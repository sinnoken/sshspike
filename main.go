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
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"time"
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
