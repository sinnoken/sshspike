package main

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

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
