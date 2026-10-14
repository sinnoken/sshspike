package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

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

	// healthIdle is how long a connection may sit unused before it is probed
	// with a keepalive before reuse; zero selects defaultHealthIdle.
	healthIdle time.Duration
	// ping probes a transport; nil selects keepalivePing. Tests override it.
	ping func(*ssh.Client) error

	mu    sync.Mutex
	conns map[string]*Conn
}

const (
	defaultHealthIdle = 30 * time.Second
	pingTimeout       = 5 * time.Second
)

// keepalivePing sends an OpenSSH keepalive global request. Servers reply
// (success or failure) while the transport is alive, so any error here means
// the connection is dead or unresponsive.
func keepalivePing(c *ssh.Client) error {
	errc := make(chan error, 1)
	go func() {
		_, _, err := c.SendRequest("keepalive@openssh.com", true, nil)
		errc <- err
	}()
	select {
	case err := <-errc:
		return err
	case <-time.After(pingTimeout):
		return errors.New("keepalive timed out")
	}
}

// stale reports whether a pooled connection has idled long enough to deserve a
// health check and then fails it.
func (p *Pool) stale(c *Conn, lastUsed time.Time) bool {
	idle := p.healthIdle
	if idle <= 0 {
		idle = defaultHealthIdle
	}
	if time.Since(lastUsed) < idle {
		return false
	}
	ping := p.ping
	if ping == nil {
		ping = keepalivePing
	}
	return ping(c.client) != nil
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
		lastUsed := c.lastUsed
		p.mu.Unlock()
		if !p.stale(c, lastUsed) {
			return c, true, nil
		}
		// Idle connection failed its health check: evict it and redial.
		p.evict(k, c)
	} else {
		p.mu.Unlock()
	}

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

// evict removes and closes c only if it is still the pooled entry for k.
func (p *Pool) evict(k string, c *Conn) {
	p.mu.Lock()
	if p.conns[k] == c {
		delete(p.conns, k)
	}
	p.mu.Unlock()
	if c.client != nil {
		_ = c.client.Close()
	}
}

func (p *Pool) drop(user, host string, port int) {
	k := key(user, host, port)
	p.mu.Lock()
	c, ok := p.conns[k]
	delete(p.conns, k)
	p.mu.Unlock()
	if ok && c.client != nil {
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
		if c.client == nil {
			continue
		}
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
