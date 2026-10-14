package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

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
