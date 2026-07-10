// Package console serves a LOCAL, token-gated HTTP console for the guard.
//
// It is intended to bind to 127.0.0.1 only. Every /api/* route requires a
// bearer token (constant-time compared); the static UI at / is served
// without a token so a browser can load it and prompt the operator for the
// token itself.
//
// This package depends on internal/overlay for Rule/Action, and on a locally
// defined CP interface for control-plane sync. It does NOT import cpsync or
// main: the concrete control-plane client is injected by main.go via Config.
package console

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aarvion-ai/aarvion-guard/internal/overlay"
)

// SyncStatus is a snapshot of control-plane sync state.
type SyncStatus struct {
	State   string `json:"state"`
	Pending int    `json:"pending"`
}

// CP is the control-plane client contract the console depends on. It is
// deliberately minimal and locally defined so this package need not import
// cpsync or main. main.go injects a concrete implementation.
type CP interface {
	Status(ctx context.Context) (SyncStatus, error)
	PushOverlay(ctx context.Context, rules []overlay.Rule) error
}

// Config configures a console Server.
type Config struct {
	Addr     string         // listen address, e.g. "127.0.0.1:7071"
	Token    string         // bearer token required on all /api/* routes
	FeedPath string         // path to the newline-delimited JSON decision log
	Entity   string         // entity identity, surfaced by /api/status
	Tenant   string         // tenant identity, surfaced by /api/status
	Overlay  *overlay.Store // the tighten-only overlay store
	CP       CP             // control-plane client; nil is acceptable
}

// Server is the console HTTP server.
type Server struct {
	cfg Config
	mux *http.ServeMux
}

// New builds a Server with its routes wired up.
func New(cfg Config) *Server {
	s := &Server{cfg: cfg}
	s.mux = s.routes()
	return s
}

// ListenAndServe binds cfg.Addr and serves until ctx is cancelled, at which
// point it performs a graceful shutdown (5s budget) and returns nil on a
// clean shutdown.
func (s *Server) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.Addr)
	if err != nil {
		return err
	}

	srv := &http.Server{Handler: s.mux}

	errCh := make(chan error, 1)
	go func() {
		err := srv.Serve(ln)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errCh <- err
	}()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
		// Drain Serve's result; ErrServerClosed is already normalized to nil.
		<-errCh
		return nil
	case err := <-errCh:
		return err
	}
}

func (s *Server) routes() *http.ServeMux {
	mux := http.NewServeMux()

	// API routes: all token-gated.
	mux.Handle("/api/status", s.auth(http.HandlerFunc(s.handleStatus)))
	mux.Handle("/api/feed", s.auth(http.HandlerFunc(s.handleFeed)))
	mux.Handle("/api/overlay", s.auth(http.HandlerFunc(s.handleOverlay)))
	mux.Handle("/api/sync", s.auth(http.HandlerFunc(s.handleSync)))

	// Everything else: the embedded static UI (no token).
	mux.Handle("/", s.staticHandler())

	return mux
}

// auth enforces a constant-time bearer-token check on the wrapped handler.
func (s *Server) auth(next http.Handler) http.Handler {
	want := []byte("Bearer " + s.cfg.Token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := []byte(r.Header.Get("Authorization"))
		if subtle.ConstantTimeCompare(got, want) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// handleStatus: GET /api/status
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}

	sync := map[string]any{"state": "unknown", "pending": 0}
	if s.cfg.CP != nil {
		if st, err := s.cfg.CP.Status(r.Context()); err == nil {
			sync["state"] = st.State
			sync["pending"] = st.Pending
		} else {
			sync["state"] = "error"
		}
	}

	overlayCount := 0
	if s.cfg.Overlay != nil {
		overlayCount = len(s.cfg.Overlay.Rules())
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"entity":        s.cfg.Entity,
		"tenant":        s.cfg.Tenant,
		"sync":          sync,
		"overlay_rules": overlayCount,
	})
}

// handleFeed: GET /api/feed?limit=N
func (s *Server) handleFeed(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}

	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > 1000 {
		limit = 1000
	}

	rows := tailFeed(s.cfg.FeedPath, limit)
	writeJSON(w, http.StatusOK, map[string]any{"rows": rows})
}

// handleOverlay: GET/PUT /api/overlay
func (s *Server) handleOverlay(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		var rules []overlay.Rule
		if s.cfg.Overlay != nil {
			rules = s.cfg.Overlay.Rules()
		}
		if rules == nil {
			rules = []overlay.Rule{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"rules": rules})

	case http.MethodPut:
		var body struct {
			Rules []overlay.Rule `json:"rules"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON: " + err.Error()})
			return
		}
		if s.cfg.Overlay == nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "no overlay store configured"})
			return
		}
		if err := s.cfg.Overlay.Replace(body.Rules); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		// Best-effort push to the control plane; ignore errors.
		if s.cfg.CP != nil {
			rules := s.cfg.Overlay.Rules()
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				_ = s.cfg.CP.PushOverlay(ctx, rules)
			}()
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "rules": s.cfg.Overlay.Rules()})

	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
	}
}

// handleSync: POST /api/sync
func (s *Server) handleSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}

	if s.cfg.CP == nil {
		writeJSON(w, http.StatusOK, map[string]any{"state": "unknown", "pending": 0})
		return
	}

	var rules []overlay.Rule
	if s.cfg.Overlay != nil {
		rules = s.cfg.Overlay.Rules()
	}
	if err := s.cfg.CP.PushOverlay(r.Context(), rules); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	st, err := s.cfg.CP.Status(r.Context())
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"state": st.State, "pending": st.Pending})
}

// staticHandler serves the embedded UI with an SPA fallback to index.html.
func (s *Server) staticHandler() http.Handler {
	sub, err := fs.Sub(uiFS, "ui")
	if err != nil {
		// Should never happen: uiFS is embedded at build time.
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "ui not available", http.StatusInternalServerError)
		})
	}
	fileServer := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Try to open the requested path; on miss, fall back to index.html.
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p == "" {
			p = "index.html"
		}
		if f, err := sub.Open(p); err == nil {
			_ = f.Close()
			fileServer.ServeHTTP(w, r)
			return
		}
		// SPA fallback.
		r2 := r.Clone(r.Context())
		r2.URL.Path = "/"
		fileServer.ServeHTTP(w, r2)
	})
}

// tailFeed reads the newline-delimited JSON decision log at path, keeps the
// last limit lines, parses each as a generic map, and returns them
// newest-first. A missing file yields an empty slice.
func tailFeed(path string, limit int) []map[string]any {
	rows := []map[string]any{}
	if path == "" {
		return rows
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return rows
		}
		return rows
	}

	lines := strings.Split(string(data), "\n")
	// Drop trailing empties.
	end := len(lines)
	for end > 0 && strings.TrimSpace(lines[end-1]) == "" {
		end--
	}
	lines = lines[:end]

	start := 0
	if len(lines) > limit {
		start = len(lines) - limit
	}
	tail := lines[start:]

	// Walk newest-first.
	for i := len(tail) - 1; i >= 0; i-- {
		line := strings.TrimSpace(tail[i])
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			continue
		}
		rows = append(rows, m)
	}
	return rows
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
