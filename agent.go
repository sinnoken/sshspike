package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

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
