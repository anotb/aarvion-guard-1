package cpsync

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aarvion-ai/aarvion-guard/internal/overlay"
)

func sampleRules() []overlay.Rule {
	return []overlay.Rule{
		{
			ID:      "r1",
			Match:   overlay.Match{Tools: []string{"bash"}},
			Verdict: overlay.VerdictDeny,
			Enabled: true,
		},
	}
}

func TestPushOverlaySuccess(t *testing.T) {
	var gotBody struct {
		Rules []overlay.Rule `json:"rules"`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if got, want := r.URL.Path, "/api/v1/entities/acme/entity-1/overlay"; got != want {
			t.Errorf("path = %s, want %s", got, want)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer tok-123" {
			t.Errorf("Authorization = %q, want Bearer tok-123", got)
		}
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("decode body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := New(srv.URL, "acme", "entity-1", "tok-123")
	if err := c.PushOverlay(context.Background(), sampleRules()); err != nil {
		t.Fatalf("PushOverlay: unexpected error: %v", err)
	}
	if len(gotBody.Rules) != 1 || gotBody.Rules[0].ID != "r1" {
		t.Fatalf("server received rules = %+v, want one rule id r1", gotBody.Rules)
	}
}

func TestPushOverlayUnsupported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := New(srv.URL, "acme", "entity-1", "tok-123")
	err := c.PushOverlay(context.Background(), sampleRules())
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("PushOverlay on 404: err = %v, want ErrUnsupported", err)
	}
}

func TestPushOverlayMethodNotAllowed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusMethodNotAllowed)
	}))
	defer srv.Close()

	c := New(srv.URL, "acme", "entity-1", "tok-123")
	err := c.PushOverlay(context.Background(), sampleRules())
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("PushOverlay on 405: err = %v, want ErrUnsupported", err)
	}
}

func TestPushOverlayServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := New(srv.URL, "acme", "entity-1", "tok-123")
	err := c.PushOverlay(context.Background(), sampleRules())
	if err == nil || errors.Is(err, ErrUnsupported) {
		t.Fatalf("PushOverlay on 500: err = %v, want a non-ErrUnsupported error", err)
	}
}

func TestStatusMapsBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.URL.Path, "/api/v1/entities/acme/entity-1/overlay/status"; got != want {
			t.Errorf("path = %s, want %s", got, want)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer tok-123" {
			t.Errorf("Authorization = %q, want Bearer tok-123", got)
		}
		_, _ = io.WriteString(w, `{"state":"local_ahead","pending":3}`)
	}))
	defer srv.Close()

	c := New(srv.URL, "acme", "entity-1", "tok-123")
	st, err := c.Status(context.Background())
	if err != nil {
		t.Fatalf("Status: unexpected error: %v", err)
	}
	if st.State != "local_ahead" || st.Pending != 3 {
		t.Fatalf("Status = %+v, want {local_ahead 3}", st)
	}
}

func TestStatusUnknownOn404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := New(srv.URL, "acme", "entity-1", "tok-123")
	st, err := c.Status(context.Background())
	if err != nil {
		t.Fatalf("Status on 404: unexpected error: %v", err)
	}
	if st.State != "unknown" {
		t.Fatalf("Status on 404: State = %q, want unknown", st.State)
	}
}

func TestStatusUnknownOnBadState(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"state":"wat","pending":0}`)
	}))
	defer srv.Close()

	c := New(srv.URL, "acme", "entity-1", "tok-123")
	st, err := c.Status(context.Background())
	if err != nil {
		t.Fatalf("Status: unexpected error: %v", err)
	}
	if st.State != "unknown" {
		t.Fatalf("Status with bad state: State = %q, want unknown", st.State)
	}
}

func TestDeviceLoginUnsupported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := New(srv.URL, "acme", "entity-1", "tok-123")
	_, _, err := c.DeviceLogin(context.Background())
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("DeviceLogin on 404: err = %v, want ErrUnsupported", err)
	}
}
