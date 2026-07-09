package mitm

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aarvion-ai/aarvion-guard/internal/decisions"
	"github.com/aarvion-ai/aarvion-guard/internal/policy"
	"github.com/aarvion-ai/aarvion-guard/internal/ratelimit"
)

func TestPeekBodyReturnsFullBodyAndRestores(t *testing.T) {
	const payload = `{"query":"mutation { closeIssue(input: {issueId: \"x\"}) { clientMutationId } }"}`
	r := httptest.NewRequest("POST", "https://api.github.com/graphql", strings.NewReader(payload))

	if got := PeekBody(r); got != payload {
		t.Fatalf("PeekBody = %q, want full body", got)
	}
	rest, _ := io.ReadAll(r.Body)
	if string(rest) != payload {
		t.Fatalf("restored body = %q, want %q", rest, payload)
	}
}

func TestPeekBodyOversizedSkipsInspectionButStreams(t *testing.T) {
	big := strings.Repeat("a", maxBodyPeek+1024)
	r := httptest.NewRequest("POST", "https://github.com/o/r.git/git-receive-pack", strings.NewReader(big))

	if got := PeekBody(r); got != "" {
		t.Fatalf("PeekBody on oversized body = %q, want empty", got)
	}
	rest, _ := io.ReadAll(r.Body)
	if len(rest) != len(big) {
		t.Fatalf("restored body len = %d, want %d", len(rest), len(big))
	}
}

func TestPeekBodyNil(t *testing.T) {
	r := httptest.NewRequest("GET", "https://api.github.com/repos/o/r/issues", nil)
	r.Body = nil
	if got := PeekBody(r); got != "" {
		t.Fatalf("PeekBody(nil) = %q, want empty", got)
	}
}

func TestEssentialsExactMatch(t *testing.T) {
	set := Essentials([]string{"api.anthropic.com", "chatgpt.com"})
	if !set.Has("api.anthropic.com") {
		t.Fatal("exact host should match")
	}
	if !set.Has("API.Anthropic.COM") {
		t.Fatal("match should be case-insensitive")
	}
	// A plain entry must not leak into subdomains or siblings.
	if set.Has("evil.api.anthropic.com") {
		t.Fatal("exact entry must not match a subdomain")
	}
	if set.Has("api.openai.com") {
		t.Fatal("non-listed host should not match")
	}
}

func TestEssentialsSuffixMatch(t *testing.T) {
	set := Essentials([]string{".openai.azure.com"})
	if !set.Has("myresource.openai.azure.com") {
		t.Fatal("suffix entry should match a subdomain")
	}
	if !set.Has("openai.azure.com") {
		t.Fatal("suffix entry should match the bare domain too")
	}
	// A host merely containing the suffix as a substring must not match.
	if set.Has("notopenai.azure.com.evil.com") {
		t.Fatal("suffix entry must anchor at the end of the host")
	}
	if set.Has("api.anthropic.com") {
		t.Fatal("suffix entry should reject a non-match")
	}
}

func TestEssentialsConfigOverridesDefaults(t *testing.T) {
	// A config-driven set is exactly what's passed in — nothing implicit.
	set := Essentials([]string{"models.internal.example"})
	if !set.Has("models.internal.example") {
		t.Fatal("config-driven host should match")
	}
	if set.Has("api.anthropic.com") {
		t.Fatal("config-driven set must not carry over any defaults")
	}
}

func TestBindTLSHost(t *testing.T) {
	cases := []struct {
		name           string
		authority, sni string
		wantHost       string
		wantDeny       bool
		wantRefuse     bool
	}{
		{"hostname authority + matching SNI", "api.github.com", "api.github.com", "api.github.com", true, false},
		{"hostname authority + no SNI", "api.github.com", "", "api.github.com", true, false},
		{"hostname authority + mismatched SNI is refused", "api.github.com", "evil.example", "", false, true},
		{"IP authority governs on the SNI hostname", "140.82.112.3", "api.github.com", "api.github.com", true, false},
		{"IP authority + no SNI governs on the IP", "140.82.112.3", "", "140.82.112.3", false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h, deny, refuse := bindTLSHost(c.authority, c.sni)
			if h != c.wantHost || deny != c.wantDeny || refuse != c.wantRefuse {
				t.Fatalf("bindTLSHost(%q,%q) = (%q,%v,%v); want (%q,%v,%v)",
					c.authority, c.sni, h, deny, refuse, c.wantHost, c.wantDeny, c.wantRefuse)
			}
		})
	}
}

// Regression for the transparent-mode break: cleartext arrives with an IP dial
// authority (from SO_ORIGINAL_DST) and a hostname Host header. It must be
// governed on the hostname, never refused as host_mismatch against the IP.
func TestServePlainIPAuthorityGovernsInnerHost(t *testing.T) {
	opa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"result": map[string]any{"allowed": true}})
	}))
	defer opa.Close()
	d := Deps{
		Pol: policy.New(strings.TrimPrefix(opa.URL, "http://")),
		Rec: decisions.New("http://cp.invalid", "t", "e", "tok", "dp", ""),
	}
	client, server := net.Pipe()
	defer client.Close()
	go d.ServePlain(server, "127.0.0.1:1") // IP authority; port 1 refuses instantly
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := client.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden && strings.Contains(string(body), "host_mismatch") {
		t.Fatal("transparent cleartext to an IP authority was wrongly refused as host_mismatch")
	}
	// Governed + allowed → upstream dial to 127.0.0.1:1 is refused → 502.
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("got %d %q; want 502 (governed on inner Host, upstream dial fails)", resp.StatusCode, body)
	}
}

// allowAllOPA is an OPA stub that allows every request, so a deny in these tests
// can only come from the in-guard rate limiter, never from policy.
func allowAllOPA(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"result": map[string]any{"allowed": true}})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// A host over its rate ceiling is short-circuited to a rate_limited 429 deny
// BEFORE OPA runs, while an under-limit host is governed normally (allowed here,
// since OPA allows everything). This is the runaway guardrail on the decision
// path, keyed on host so it works in every inspect mode.
func TestDecideRateLimitedOverCeiling(t *testing.T) {
	opa := allowAllOPA(t)
	d := Deps{
		Pol:     policy.New(strings.TrimPrefix(opa.URL, "http://")),
		Rec:     decisions.New("http://cp.invalid", "t", "e", "tok", "dp", ""),
		Limiter: ratelimit.New(2, time.Minute, nil),
	}

	// First two to the runaway host are under the ceiling → allowed by OPA.
	for i := 0; i < 2; i++ {
		dec := d.Decide("GET", "runaway.example", "/", "", nil)
		if !dec.Allowed {
			t.Fatalf("request %d to runaway.example should be allowed (under ceiling): %+v", i+1, dec)
		}
	}
	// Third crosses the ceiling → rate_limited 429 deny, short-circuiting OPA.
	dec := d.Decide("GET", "runaway.example", "/", "", nil)
	if dec.Allowed {
		t.Fatal("over-ceiling request should be denied")
	}
	if dec.HTTPStatus != http.StatusTooManyRequests {
		t.Fatalf("over-ceiling status = %d, want 429", dec.HTTPStatus)
	}
	if dec.Reason != "rate_limited" || dec.PolicyID != "guard" || !dec.Enforced {
		t.Fatalf("over-ceiling decision = %+v, want reason=rate_limited policy_id=guard enforced=true", dec)
	}

	// A different, under-limit host is unaffected — governed normally.
	if dec := d.Decide("GET", "calm.example", "/", "", nil); !dec.Allowed {
		t.Fatalf("under-limit host should be governed normally (allowed): %+v", dec)
	}
}

// A nil limiter must not change the decision path at all: every request is
// governed by OPA exactly as before the feature.
func TestDecideNilLimiterUnchanged(t *testing.T) {
	opa := allowAllOPA(t)
	d := Deps{
		Pol:     policy.New(strings.TrimPrefix(opa.URL, "http://")),
		Rec:     decisions.New("http://cp.invalid", "t", "e", "tok", "dp", ""),
		Limiter: nil,
	}
	// Far more requests than any small ceiling — with no limiter, all are allowed.
	for i := 0; i < 25; i++ {
		dec := d.Decide("GET", "any.example", "/", "", nil)
		if !dec.Allowed {
			t.Fatalf("nil limiter must leave OPA-allowed request allowed (req %d): %+v", i+1, dec)
		}
		if dec.Reason == "rate_limited" {
			t.Fatal("nil limiter must never produce a rate_limited decision")
		}
	}
}

// End-to-end over ServePlain: a rate-limited request must surface as a 429 to
// the client and be recorded as a deny with reason rate_limited (which is what
// flows to the CP push / observability sinks / denies_total).
func TestServePlainRateLimitedRecordsDeny(t *testing.T) {
	opa := allowAllOPA(t)
	rec := decisions.New("http://cp.invalid", "t", "e", "tok", "dp", "")
	d := Deps{
		Pol:     policy.New(strings.TrimPrefix(opa.URL, "http://")),
		Rec:     rec,
		Limiter: ratelimit.New(1, time.Minute, nil),
	}

	// The limiter keys on the governed host; a hostname dial authority binds it,
	// so both requests here hit the same "example.com" key.
	do := func() *http.Response {
		client, server := net.Pipe()
		defer client.Close()
		go d.ServePlain(server, "example.com:80")
		_ = client.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := client.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")); err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(client), nil)
		if err != nil {
			t.Fatalf("read response: %v", err)
		}
		return resp
	}

	// First request is under the ceiling → allowed, then the upstream dial to a
	// real example.com is what determines the final status; either way it is not
	// a 429 rate-limit.
	resp1 := do()
	body1, _ := io.ReadAll(resp1.Body)
	resp1.Body.Close()
	if resp1.StatusCode == http.StatusTooManyRequests {
		t.Fatalf("first (under-limit) request wrongly rate-limited: %q", body1)
	}

	// Second request crosses the ceiling → 429 with the rate_limited reason.
	resp2 := do()
	body2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second (over-limit) request: got %d %q, want 429", resp2.StatusCode, body2)
	}
	if !strings.Contains(string(body2), "rate_limited") {
		t.Fatalf("over-limit body = %q, want rate_limited reason", body2)
	}

	// The over-limit request must be recorded as a deny (feeds denies_total etc.).
	if _, denies, _, _ := rec.Stats(); denies < 1 {
		t.Fatalf("rate-limited deny not recorded: denies=%d", denies)
	}
}

// denyAllOPA is an OPA stub that denies every request with a 403 and a fixed
// reason, so observe-mode tests can prove an OPA deny keeps OPA's reason rather
// than being overwritten by the novel-host marker.
func denyAllOPA(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"result": map[string]any{
			"allowed":     false,
			"http_status": 403,
			"headers":     map[string]string{"x-policy-violated": "opa_pol", "x-policy-reason": "opa_denied"},
		}})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// Enforce mode denies a novel host outright with not_allowlisted (403) and never
// calls OPA, while an allowlisted host and an essential host both proceed to OPA
// and are allowed. This is the default-deny egress posture.
func TestDecideAllowlistEnforce(t *testing.T) {
	opa := allowAllOPA(t)
	d := Deps{
		Pol:       policy.New(strings.TrimPrefix(opa.URL, "http://")),
		Rec:       decisions.New("http://cp.invalid", "t", "e", "tok", "dp", ""),
		Essential: Essentials([]string{"api.anthropic.com"}),
		Allowlist: Allowlist{Mode: AllowlistEnforce, Hosts: Essentials([]string{"api.github.com"})},
	}

	// A novel host (neither allowlisted nor essential) is denied without OPA.
	dec := d.Decide("GET", "evil.example", "/", "", nil)
	if dec.Allowed {
		t.Fatal("novel host must be denied in enforce mode")
	}
	if dec.HTTPStatus != http.StatusForbidden || dec.Reason != "not_allowlisted" || dec.PolicyID != "guard" || !dec.Enforced {
		t.Fatalf("novel-host deny = %+v, want 403 not_allowlisted policy_id=guard enforced=true", dec)
	}

	// An allowlisted host proceeds to OPA and is allowed (OPA allows everything).
	if dec := d.Decide("GET", "api.github.com", "/", "", nil); !dec.Allowed || dec.Reason == "not_allowlisted" {
		t.Fatalf("allowlisted host should be allowed via OPA: %+v", dec)
	}

	// An essential host is implicitly allowed through the gate (model keeps working).
	if dec := d.Decide("GET", "api.anthropic.com", "/", "", nil); !dec.Allowed || dec.Reason == "not_allowlisted" {
		t.Fatalf("essential host should pass the gate and be allowed via OPA: %+v", dec)
	}
}

// Enforce mode honors "."-suffix allowlist entries: a subdomain of an allowed
// domain proceeds to OPA, while an unrelated host is denied.
func TestDecideAllowlistEnforceSuffixMatch(t *testing.T) {
	opa := allowAllOPA(t)
	d := Deps{
		Pol:       policy.New(strings.TrimPrefix(opa.URL, "http://")),
		Rec:       decisions.New("http://cp.invalid", "t", "e", "tok", "dp", ""),
		Allowlist: Allowlist{Mode: AllowlistEnforce, Hosts: Essentials([]string{".corp.example"})},
	}
	if dec := d.Decide("GET", "api.corp.example", "/", "", nil); !dec.Allowed {
		t.Fatalf("suffix-matched subdomain should be allowed: %+v", dec)
	}
	if dec := d.Decide("GET", "corp.example", "/", "", nil); !dec.Allowed {
		t.Fatalf("suffix entry should match the bare apex too: %+v", dec)
	}
	if dec := d.Decide("GET", "other.example", "/", "", nil); dec.Allowed || dec.Reason != "not_allowlisted" {
		t.Fatalf("non-suffix host should be denied not_allowlisted: %+v", dec)
	}
}

// Observe mode never denies on novelty: a novel host proceeds to OPA and, when
// OPA allows it, the decision is flagged novel_host_observed so the operator sees
// what enforce mode WOULD block. An allowlisted host allowed by OPA keeps a
// normal (empty) reason — the marker is for novel hosts only.
func TestDecideAllowlistObserveMarksNovel(t *testing.T) {
	opa := allowAllOPA(t)
	d := Deps{
		Pol:       policy.New(strings.TrimPrefix(opa.URL, "http://")),
		Rec:       decisions.New("http://cp.invalid", "t", "e", "tok", "dp", ""),
		Allowlist: Allowlist{Mode: AllowlistObserve, Hosts: Essentials([]string{"api.github.com"})},
	}

	// Novel host: allowed (observe never blocks) but flagged.
	dec := d.Decide("GET", "novel.example", "/", "", nil)
	if !dec.Allowed {
		t.Fatalf("observe mode must not deny a novel host: %+v", dec)
	}
	if dec.Reason != "novel_host_observed" {
		t.Fatalf("novel host in observe mode = %+v, want reason novel_host_observed", dec)
	}

	// Allowlisted host: allowed with a normal (empty) reason — not flagged.
	if dec := d.Decide("GET", "api.github.com", "/", "", nil); !dec.Allowed || dec.Reason != "" {
		t.Fatalf("allowlisted host in observe mode = %+v, want allowed with empty reason", dec)
	}
}

// In observe mode, if OPA itself denies a novel host the OPA reason is kept — the
// novel-host marker only overrides the reason on an OPA allow.
func TestDecideAllowlistObserveKeepsOPADeny(t *testing.T) {
	opa := denyAllOPA(t)
	d := Deps{
		Pol:       policy.New(strings.TrimPrefix(opa.URL, "http://")),
		Rec:       decisions.New("http://cp.invalid", "t", "e", "tok", "dp", ""),
		Allowlist: Allowlist{Mode: AllowlistObserve},
	}
	dec := d.Decide("POST", "novel.example", "/", "", nil)
	if dec.Allowed {
		t.Fatal("OPA denied, so the decision must be a deny")
	}
	if dec.Reason == "novel_host_observed" {
		t.Fatalf("OPA deny reason must be kept, not overwritten by the observe marker: %+v", dec)
	}
}

// A disabled (off / empty-mode) allowlist must not change the decision path at
// all: a host that would be novel under a gate is governed by OPA exactly as
// before the feature.
func TestDecideAllowlistDisabledUnchanged(t *testing.T) {
	opa := allowAllOPA(t)
	for _, mode := range []string{"", AllowlistOff} {
		d := Deps{
			Pol:       policy.New(strings.TrimPrefix(opa.URL, "http://")),
			Rec:       decisions.New("http://cp.invalid", "t", "e", "tok", "dp", ""),
			Allowlist: Allowlist{Mode: mode},
		}
		dec := d.Decide("GET", "anything.example", "/", "", nil)
		if !dec.Allowed {
			t.Fatalf("disabled allowlist (mode=%q) must leave an OPA-allowed request allowed: %+v", mode, dec)
		}
		if dec.Reason == "not_allowlisted" || dec.Reason == "novel_host_observed" {
			t.Fatalf("disabled allowlist (mode=%q) must not add any allowlist marker: %+v", mode, dec)
		}
	}
}

// captureSink records every finalized decision row so a test can assert on the
// audit fields (reason etc.) that flow to the JSONL / webhook / CP sinks.
type captureSink struct {
	mu   sync.Mutex
	rows []decisions.Record
}

func (c *captureSink) Record(r decisions.Record) {
	c.mu.Lock()
	c.rows = append(c.rows, r)
	c.mu.Unlock()
}

func (c *captureSink) reasonFor(host string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, r := range c.rows {
		if r.Host == host {
			return r.Reason, true
		}
	}
	return "", false
}

// End-to-end over ServePlain with a capturing sink: observe mode lets a novel
// host through but the recorded ALLOW row carries reason novel_host_observed (the
// single change that surfaces the marker in the JSONL/webhook/CP audit), while an
// allowlisted host's allow row keeps an empty reason (normal allow rows are
// unchanged). Both requests are allowed by OPA; the upstream dial then fails (502),
// but the allow is recorded first, which is what we assert on.
func TestServePlainObserveMarksNovelInAudit(t *testing.T) {
	opa := allowAllOPA(t)
	sink := &captureSink{}
	rec := decisions.New("http://cp.invalid", "t", "e", "tok", "dp", "")
	rec.SetSink(sink)
	d := Deps{
		Pol:       policy.New(strings.TrimPrefix(opa.URL, "http://")),
		Rec:       rec,
		Allowlist: Allowlist{Mode: AllowlistObserve, Hosts: Essentials([]string{"good.example"})},
	}

	// Drive one governed request whose dial authority (a hostname) binds the host.
	do := func(host string) {
		client, server := net.Pipe()
		defer client.Close()
		go d.ServePlain(server, host+":80") // hostname authority → port 80 dial fails after the allow
		_ = client.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := client.Write([]byte("GET / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n")); err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(client), nil)
		if err != nil {
			t.Fatalf("read response for %s: %v", host, err)
		}
		_, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
	}

	do("novel.example") // not allowlisted → observed
	do("good.example")  // allowlisted → normal allow

	// The novel host's allow row is flagged so an operator sees what enforce would
	// block; this is exactly what reaches the observability sinks and the CP.
	if reason, ok := sink.reasonFor("novel.example"); !ok || reason != "novel_host_observed" {
		t.Fatalf("novel.example allow row reason = %q (found=%v), want novel_host_observed", reason, ok)
	}
	// A normal allowed row is untouched: empty reason.
	if reason, ok := sink.reasonFor("good.example"); !ok || reason != "" {
		t.Fatalf("good.example allow row reason = %q (found=%v), want empty", reason, ok)
	}
}

func TestHeaderMapLowercasesAndJoins(t *testing.T) {
	r := httptest.NewRequest("POST", "https://api/x", nil)
	r.Header.Set("X-Amz-Target", "DynamoDB_20120810.DeleteTable")
	r.Header.Add("X-Multi", "a")
	r.Header.Add("X-Multi", "b")
	m := HeaderMap(r)
	if m["x-amz-target"] != "DynamoDB_20120810.DeleteTable" {
		t.Fatalf("x-amz-target = %q", m["x-amz-target"])
	}
	if m["x-multi"] != "a,b" {
		t.Fatalf("x-multi = %q, want a,b", m["x-multi"])
	}
}
