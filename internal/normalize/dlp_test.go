package normalize

import (
	"reflect"
	"strings"
	"testing"
)

func TestScanDLP(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{
			name: "github token",
			in:   "token ghp_" + strings.Repeat("a", 36),
			want: []string{"secret:ghp"},
		},
		{
			name: "anthropic key",
			in:   "key sk-ant-api03-" + strings.Repeat("A", 40),
			want: []string{"secret:anthropic"},
		},
		{
			name: "openai generic sk key",
			in:   "OPENAI_API_KEY=sk-" + strings.Repeat("A", 40),
			want: []string{"secret:openai"},
		},
		{
			name: "aws access key id",
			in:   "AKIA" + strings.Repeat("A", 16),
			want: []string{"secret:aws"},
		},
		{
			name: "1password ref",
			in:   "op://vault/item/field",
			want: []string{"secret:1password"},
		},
		{
			name: "1password literal word",
			in:   "stored in 1Password vault",
			want: []string{"secret:1password"},
		},
		{
			name: "email pii",
			in:   "me@x.com",
			want: []string{"pii:email"},
		},
		{
			name: "phone pii",
			in:   "call +1 415 555 0132",
			want: []string{"pii:phone"},
		},
		{
			name: "benign text has no findings",
			in:   "hello",
			want: nil,
		},
		{
			name: "empty string",
			in:   "",
			want: nil,
		},
		{
			name: "anthropic is not double-counted as openai",
			in:   "sk-ant-api03-" + strings.Repeat("A", 40),
			want: []string{"secret:anthropic"},
		},
		{
			name: "multiple findings sorted and unique",
			in:   "mail me@x.com and here is ghp_" + strings.Repeat("z", 36) + " and me@x.com again",
			want: []string{"pii:email", "secret:ghp"},
		},
		{
			name: "short ghp-like token does not trip",
			in:   "ghp_short",
			want: nil,
		},
		{
			name: "bare sk- without length does not trip openai",
			in:   "sk-abc",
			want: nil,
		},
		{
			name: "email inside a url path is not a false phone",
			in:   "https://example.com/users/42",
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ScanDLP(tt.in)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("ScanDLP(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestScanDLPResultIsSortedAndUnique(t *testing.T) {
	in := "AKIA" + strings.Repeat("B", 16) + " op://v/i me@x.com ghp_" + strings.Repeat("c", 36)
	got := ScanDLP(in)
	// verify sorted
	for i := 1; i < len(got); i++ {
		if got[i-1] > got[i] {
			t.Fatalf("ScanDLP result not sorted: %v", got)
		}
	}
	// verify unique
	seen := map[string]bool{}
	for _, l := range got {
		if seen[l] {
			t.Fatalf("ScanDLP result has duplicate %q: %v", l, got)
		}
		seen[l] = true
	}
}
