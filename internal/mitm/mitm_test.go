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
