package mitm

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"
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
