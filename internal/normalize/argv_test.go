package normalize

import (
	"reflect"
	"testing"
)

func TestSplitArgs(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{
			name: "quotes and mixed quoting",
			in:   `gog gmail send --to "a b@x.com" --body 'hi'`,
			want: []string{"gog", "gmail", "send", "--to", "a b@x.com", "--body", "hi"},
		},
		{
			name: "plain words",
			in:   "git push --force",
			want: []string{"git", "push", "--force"},
		},
		{
			name: "empty",
			in:   "",
			want: nil,
		},
		{
			name: "leading and trailing whitespace collapsed",
			in:   "   bird   tweet   hello   ",
			want: []string{"bird", "tweet", "hello"},
		},
		{
			name: "backslash escape of space",
			in:   `echo a\ b`,
			want: []string{"echo", "a b"},
		},
		{
			name: "backslash escape of quote",
			in:   `echo \"quoted\"`,
			want: []string{"echo", `"quoted"`},
		},
		{
			name: "adjacent quoted and bare concatenate",
			in:   `curl -X'DELETE' url`,
			want: []string{"curl", "-XDELETE", "url"},
		},
		{
			name: "double quotes preserve single quote",
			in:   `echo "it's fine"`,
			want: []string{"echo", "it's fine"},
		},
		{
			name: "single quotes are literal (no escape inside)",
			in:   `echo 'a\b'`,
			want: []string{"echo", `a\b`},
		},
		{
			name: "unbalanced double quote is best-effort",
			in:   `echo "unterminated`,
			want: []string{"echo", "unterminated"},
		},
		{
			name: "unbalanced single quote is best-effort",
			in:   `echo 'unterminated`,
			want: []string{"echo", "unterminated"},
		},
		{
			name: "empty quoted string yields empty token",
			in:   `gog gmail send --body ""`,
			want: []string{"gog", "gmail", "send", "--body", ""},
		},
		{
			name: "tabs treated as whitespace",
			in:   "gog\tdrive\tdelete",
			want: []string{"gog", "drive", "delete"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitArgs(tt.in)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("splitArgs(%q) = %#v, want %#v", tt.in, got, tt.want)
			}
		})
	}
}
