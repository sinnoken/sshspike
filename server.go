package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

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

// validateTarget rejects malformed host and port values up front so they never
// reach the dialer.
func validateTarget(host string, port int) error {
	switch {
	case host == "":
		return errors.New("host is required")
	case len(host) > 253 || strings.HasPrefix(host, "-") || strings.ContainsAny(host, " \t\r\n/\\\x00"):
		return errors.New("host is invalid")
	case port < 1 || port > 65535:
		return errors.New("port must be between 1 and 65535")
	}
	return nil
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

	if req.Port == 0 {
		req.Port = 22
	}
	if err := validateTarget(req.Host, req.Port); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if req.Command == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "command is required"})
		return
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
	req.Host = strings.TrimSpace(req.Host)
	req.User = strings.TrimSpace(req.User)
	if req.Port == 0 {
		req.Port = 22
	}
	if err := validateTarget(req.Host, req.Port); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if req.User == "" {
		req.User = s.defaultUser
	}
	s.pool.drop(req.User, req.Host, req.Port)
	writeJSON(w, http.StatusOK, map[string]string{"status": "closed"})
}
