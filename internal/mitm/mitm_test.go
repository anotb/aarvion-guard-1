package mitm

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aarvion-ai/aarvion-guard/internal/decisions"
	"github.com/aarvion-ai/aarvion-guard/internal/policy"
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
