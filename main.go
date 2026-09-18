// Command sshspike is a minimal prototype that validates three things before
// the full system is built:
//
//  1. SSH certificate authentication sourced entirely from ssh-agent.
//  2. Persistent SSH connections reused across many commands.
//  3. A single-page HTML console that drives the SSH client.
//
// It is a development spike, not a product. The console accepts a free-form
// command, so it must only ever be bound to loopback against test machines.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

func main() {
	var (
		listen       = flag.String("listen", "127.0.0.1:8080", "console listen address")
		knownHosts   = flag.String("known-hosts", defaultKnownHosts(), "known_hosts file used to verify target host keys")
		insecureHost = flag.Bool("insecure-host-key", false, "DANGER: skip host key verification (lab use only)")
		defaultUser  = flag.String("user", os.Getenv("USER"), "default SSH username shown in the console")
		maxOutput    = flag.Int64("max-output", 1<<20, "maximum bytes captured per stream")
	)
	flag.Parse()

	verifier, err := newHostKeyVerifier(*knownHosts, *insecureHost)
	if err != nil {
		log.Fatalf("host key setup: %v", err)
	}
	if *insecureHost {
		log.Println("WARNING: host key verification is disabled; use this only against throwaway lab hosts")
	}

	pool := &Pool{verify: verifier, maxOutput: *maxOutput}
	defer pool.CloseAll()

	srv := &Server{pool: pool, defaultUser: *defaultUser}

	httpSrv := &http.Server{
		Addr:              *listen,
		Handler:           srv.routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("console on http://%s (ssh-agent: %s)", *listen, agentStatus())
	if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func defaultKnownHosts() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return home + "/.ssh/known_hosts"
}

// ---------------------------------------------------------------- credentials

// Identity is the non-sensitive description of one key held by ssh-agent.
type Identity struct {
	Fingerprint string `json:"fingerprint"`
	Type        string `json:"type"`
	Comment     string `json:"comment,omitempty"`
	IsCert      bool   `json:"is_certificate"`
	KeyID       string `json:"key_id,omitempty"`
	ValidBefore string `json:"valid_before,omitempty"`
	Expired     bool   `json:"expired,omitempty"`
}

// agentConn dials ssh-agent. The private key never enters this process: every
// signature is delegated over the agent socket.
func agentConn() (agent.ExtendedAgent, net.Conn, error) {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		return nil, nil, errors.New("SSH_AUTH_SOCK is not set; start ssh-agent and ssh-add your key")
	}
	c, err := net.Dial("unix", sock)
	if err != nil {
		return nil, nil, fmt.Errorf("dial ssh-agent: %w", err)
	}
	return agent.NewClient(c), c, nil
}

func agentStatus() string {
	ids, err := identities()
	if err != nil {
		return "unavailable: " + err.Error()
	}
	certs := 0
	for _, i := range ids {
		if i.IsCert {
			certs++
		}
	}
	return fmt.Sprintf("%d identities, %d certificates", len(ids), certs)
}

// identities lists what the agent holds, without exposing any private material.
func identities() ([]Identity, error) {
	ag, conn, err := agentConn()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	signers, err := ag.Signers()
	if err != nil {
		return nil, fmt.Errorf("list signers: %w", err)
	}
	keys, err := ag.List()
	if err != nil {
		return nil, fmt.Errorf("list keys: %w", err)
	}

	now := time.Now()
	out := make([]Identity, 0, len(signers))
	for i, s := range signers {
		pub := s.PublicKey()
		id := Identity{
			Fingerprint: ssh.FingerprintSHA256(pub),
			Type:        pub.Type(),
		}
		if i < len(keys) {
			id.Comment = keys[i].Comment
		}
		if cert, ok := pub.(*ssh.Certificate); ok {
			id.IsCert = true
			id.KeyID = cert.KeyId
			if cert.ValidBefore != ssh.CertTimeInfinity && cert.ValidBefore > 0 {
				exp := time.Unix(int64(cert.ValidBefore), 0)
				id.ValidBefore = exp.Format(time.RFC3339)
				id.Expired = now.After(exp)
			}
		}
		out = append(out, id)
	}
	return out, nil
}

// signers returns the agent signers, preferring certificates. A certificate is
// what the production system will use, so it is tried first here too.
func signers() ([]ssh.Signer, error) {
	ag, conn, err := agentConn()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	all, err := ag.Signers()
	if err != nil {
		return nil, fmt.Errorf("list signers: %w", err)
	}
	if len(all) == 0 {
		return nil, errors.New("ssh-agent holds no identities; run ssh-add")
	}

	now := time.Now()
	var certs, plain []ssh.Signer
	for _, s := range all {
		if cert, ok := s.PublicKey().(*ssh.Certificate); ok {
			if cert.ValidBefore != ssh.CertTimeInfinity && cert.ValidBefore > 0 &&
				now.After(time.Unix(int64(cert.ValidBefore), 0)) {
				continue // expired certificate is not worth offering
			}
			certs = append(certs, s)
			continue
		}
		plain = append(plain, s)
	}
	out := append(certs, plain...)
	if len(out) == 0 {
		return nil, errors.New("all ssh-agent certificates are expired")
	}
	return out, nil
}

// ------------------------------------------------------------------ host keys

func newHostKeyVerifier(path string, insecure bool) (ssh.HostKeyCallback, error) {
	if insecure {
		return ssh.InsecureIgnoreHostKey(), nil
	}
	if path == "" {
		return nil, errors.New("no known_hosts path; pass -known-hosts or -insecure-host-key")
	}
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("%s: %w (run ssh-keyscan, or use -insecure-host-key in a lab)", path, err)
	}
	cb, err := knownhosts.New(path)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return cb, nil
}

// ------------------------------------------------------------ connection pool

// Conn is one persistent SSH transport plus its bookkeeping.
type Conn struct {
	client   *ssh.Client
	addr     string
	user     string
	opened   time.Time
	lastUsed time.Time
	runs     int
	server   string
}

// Pool keeps one live SSH client per user@host:port. Reuse is the whole point
// of the spike: it proves a command costs one channel open, not a full
// TCP plus SSH handshake.
type Pool struct {
	verify    ssh.HostKeyCallback
	maxOutput int64

	mu    sync.Mutex
	conns map[string]*Conn
}

func key(user, host string, port int) string {
	return fmt.Sprintf("%s@%s:%d", user, host, port)
}

// get returns a live connection, dialing only when necessary.
func (p *Pool) get(ctx context.Context, user, host string, port int) (*Conn, bool, error) {
	k := key(user, host, port)

	p.mu.Lock()
	if p.conns == nil {
		p.conns = map[string]*Conn{}
	}
	if c, ok := p.conns[k]; ok {
		p.mu.Unlock()
		return c, true, nil
	}
	p.mu.Unlock()

	c, err := p.dial(ctx, user, host, port)
	if err != nil {
		return nil, false, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	// Another request may have dialled the same target concurrently.
	if existing, ok := p.conns[k]; ok {
		_ = c.client.Close()
		return existing, true, nil
	}
	p.conns[k] = c
	return c, false, nil
}

func (p *Pool) dial(ctx context.Context, user, host string, port int) (*Conn, error) {
	sigs, err := signers()
	if err != nil {
		return nil, err
	}

	addr := net.JoinHostPort(host, fmt.Sprint(port))
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(sigs...)},
		HostKeyCallback: p.verify,
		Timeout:         10 * time.Second,
	}

	d := net.Dialer{Timeout: 10 * time.Second}
	tcp, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("tcp dial: %w", err)
	}
	// The handshake needs its own deadline, otherwise a black-holed peer holds
	// the socket open indefinitely.
	_ = tcp.SetDeadline(time.Now().Add(10 * time.Second))

	sc, chans, reqs, err := ssh.NewClientConn(tcp, addr, cfg)
	if err != nil {
		_ = tcp.Close()
		return nil, fmt.Errorf("ssh handshake: %w", err)
	}
	_ = tcp.SetDeadline(time.Time{})

	now := time.Now()
	return &Conn{
		client:   ssh.NewClient(sc, chans, reqs),
		addr:     addr,
		user:     user,
		opened:   now,
		lastUsed: now,
		server:   string(sc.ServerVersion()),
	}, nil
}

func (p *Pool) drop(user, host string, port int) {
	k := key(user, host, port)
	p.mu.Lock()
	c, ok := p.conns[k]
	delete(p.conns, k)
	p.mu.Unlock()
	if ok {
		_ = c.client.Close()
	}
}

// CloseAll releases every transport on shutdown.
func (p *Pool) CloseAll() {
	p.mu.Lock()
	conns := p.conns
	p.conns = nil
	p.mu.Unlock()
	for _, c := range conns {
		_ = c.client.Close()
	}
}

// ConnView is the JSON shape shown in the console.
type ConnView struct {
	Key       string `json:"key"`
	Server    string `json:"server"`
	OpenedAgo string `json:"opened_ago"`
	LastUsed  string `json:"last_used_ago"`
	Runs      int    `json:"runs"`
}

func (p *Pool) list() []ConnView {
	p.mu.Lock()
	defer p.mu.Unlock()

	out := make([]ConnView, 0, len(p.conns))
	for k, c := range p.conns {
		out = append(out, ConnView{
			Key:       k,
			Server:    c.server,
			OpenedAgo: time.Since(c.opened).Truncate(time.Second).String(),
			LastUsed:  time.Since(c.lastUsed).Truncate(time.Second).String(),
			Runs:      c.runs,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// -------------------------------------------------------------------- execute

// Result is one command execution.
type Result struct {
	Host     string `json:"host"`
	User     string `json:"user"`
	Command  string `json:"command"`
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	Reused   bool   `json:"reused_connection"`
	DialMS   int64  `json:"dial_ms"`
	ExecMS   int64  `json:"exec_ms"`
	Server   string `json:"server_version,omitempty"`
	Error    string `json:"error,omitempty"`
	Truncate bool   `json:"truncated,omitempty"`
}

// capped bounds a stream so a runaway command cannot exhaust memory.
type capped struct {
	limit int64
	n     int64
	b     strings.Builder
	cut   bool
}

func (c *capped) Write(p []byte) (int, error) {
	if room := c.limit - c.n; room > 0 {
		if int64(len(p)) < room {
			room = int64(len(p))
		}
		c.b.Write(p[:room])
		c.n += room
	}
	if c.n >= c.limit {
		c.cut = true
	}
	return len(p), nil // always report success so the session drains cleanly
}

// run opens a fresh session on the pooled connection, executes one command and
// closes the session. The transport stays up for the next request.
func (p *Pool) run(ctx context.Context, user, host string, port int, cmd string, timeout time.Duration) Result {
	res := Result{Host: net.JoinHostPort(host, fmt.Sprint(port)), User: user, Command: cmd, ExitCode: -1}

	dialStart := time.Now()
	c, reused, err := p.get(ctx, user, host, port)
	res.DialMS = time.Since(dialStart).Milliseconds()
	res.Reused = reused
	if err != nil {
		res.Error = err.Error()
		return res
	}
	res.Server = c.server

	sess, err := c.client.NewSession()
	if err != nil {
		// A dead transport is the usual cause; drop it so the next attempt redials.
		p.drop(user, host, port)
		res.Error = fmt.Sprintf("open session: %v (connection dropped, retry)", err)
		return res
	}
	defer sess.Close()

	var stdout, stderr capped
	stdout.limit, stderr.limit = p.maxOutput, p.maxOutput
	sess.Stdout = &stdout
	sess.Stderr = &stderr

	execStart := time.Now()
	done := make(chan error, 1)
	go func() { done <- sess.Run(cmd) }()

	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	select {
	case <-runCtx.Done():
		_ = sess.Signal(ssh.SIGKILL)
		_ = sess.Close()
		res.Error = fmt.Sprintf("timeout after %s", timeout)
	case err := <-done:
		var exitErr *ssh.ExitError
		switch {
		case err == nil:
			res.ExitCode = 0
		case errors.As(err, &exitErr):
			// A non-zero exit status is a result, not a transport failure.
			res.ExitCode = exitErr.ExitStatus()
		default:
			res.Error = err.Error()
		}
	}

	res.ExecMS = time.Since(execStart).Milliseconds()
	res.Stdout = stdout.b.String()
	res.Stderr = stderr.b.String()
	res.Truncate = stdout.cut || stderr.cut

	p.mu.Lock()
	c.runs++
	c.lastUsed = time.Now()
	p.mu.Unlock()

	return res
}

// ----------------------------------------------------------------- http layer

// Server wires the console to the pool.
type Server struct {
	pool        *Pool
	defaultUser string
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.index)
	mux.HandleFunc("/api/identities", s.identities)
	mux.HandleFunc("/api/conns", s.conns)
	mux.HandleFunc("/api/run", s.run)
	mux.HandleFunc("/api/close", s.close)
	return mux
}

func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// A literal replace avoids Printf verb collisions with CSS percentages.
	_, _ = io.WriteString(w, strings.Replace(indexHTML, "{{USER}}", s.defaultUser, 1))
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func (s *Server) identities(w http.ResponseWriter, _ *http.Request) {
	ids, err := identities()
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"identities": ids})
}

func (s *Server) conns(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"connections": s.pool.list()})
}

type runRequest struct {
	Host      string `json:"host"`
	Port      int    `json:"port"`
	User      string `json:"user"`
	Command   string `json:"command"`
	TimeoutMS int    `json:"timeout_ms"`
}

func (s *Server) run(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "use POST"})
		return
	}

	var req runRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json: " + err.Error()})
		return
	}
	req.Host = strings.TrimSpace(req.Host)
	req.User = strings.TrimSpace(req.User)
	req.Command = strings.TrimSpace(req.Command)

	switch {
	case req.Host == "":
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "host is required"})
		return
	case req.Command == "":
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "command is required"})
		return
	}
	if req.Port == 0 {
		req.Port = 22
	}
	if req.User == "" {
		req.User = s.defaultUser
	}
	timeout := time.Duration(req.TimeoutMS) * time.Millisecond
	if timeout <= 0 || timeout > 5*time.Minute {
		timeout = 15 * time.Second
	}

	res := s.pool.run(r.Context(), req.User, req.Host, req.Port, req.Command, timeout)
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) close(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "use POST"})
		return
	}
	var req runRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if req.Port == 0 {
		req.Port = 22
	}
	if req.User == "" {
		req.User = s.defaultUser
	}
	s.pool.drop(req.User, req.Host, req.Port)
	writeJSON(w, http.StatusOK, map[string]string{"status": "closed"})
}
