package proxy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aarvion-ai/aarvion-guard/internal/decisions"
	"github.com/aarvion-ai/aarvion-guard/internal/policy"
)

// fakeOPA denies POST, allows everything else — the shape the real bundle uses.
func fakeOPA(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Input struct {
				Attributes struct {
					Request struct {
						HTTP struct {
							Method string `json:"method"`
						} `json:"http"`
					} `json:"request"`
				} `json:"attributes"`
			} `json:"input"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		allowed := req.Input.Attributes.Request.HTTP.Method != "POST"
		resp := map[string]any{"result": map[string]any{"allowed": allowed}}
		if !allowed {
			resp["result"].(map[string]any)["http_status"] = 403
			resp["result"].(map[string]any)["headers"] = map[string]string{
				"x-policy-violated": "test", "x-policy-reason": "denied",
			}
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

func TestForwardProxyGoverns(t *testing.T) {
	opa := fakeOPA(t)
	defer opa.Close()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "upstream-ok")
	}))
	defer upstream.Close()

	pol := policy.New(strings.TrimPrefix(opa.URL, "http://"))
	rec := decisions.New("http://cp.invalid", "t", "e", "tok", "dp")
	srv := New("127.0.0.1:18899", pol, rec, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.ListenAndServe(ctx) }()
	waitListening(t, "127.0.0.1:18899")

	proxyURL, _ := url.Parse("http://127.0.0.1:18899")
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	// Allowed GET is forwarded to upstream.
	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "upstream-ok" {
		t.Fatalf("allowed GET: got %d %q", resp.StatusCode, body)
	}

	// Denied POST is blocked at the guard, never reaches upstream.
	resp2, err := client.Post(upstream.URL, "text/plain", strings.NewReader("x"))
	if err != nil {
		t.Fatalf("POST through proxy: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != 403 {
		t.Fatalf("denied POST: got %d, want 403", resp2.StatusCode)
	}

	total, denies, _ := rec.Stats()
	if total < 2 || denies < 1 {
		t.Fatalf("decisions not recorded: total=%d denies=%d", total, denies)
	}
}

func waitListening(t *testing.T, addr string) {
	t.Helper()
	for i := 0; i < 50; i++ {
		c, err := (&http.Client{Timeout: 100 * time.Millisecond}).Get("http://" + addr)
		if err == nil {
			c.Body.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}
