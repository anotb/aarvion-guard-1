package normalize

import (
	"reflect"
	"strings"
	"testing"
)

func TestClassifyNativeTools(t *testing.T) {
	ghp := "ghp_" + strings.Repeat("a", 36)

	tests := []struct {
		name    string
		tool    string
		args    any
		surface string
		want    Action
	}{
		{
			name:    "web_fetch DELETE to api host",
			tool:    "web_fetch",
			args:    map[string]any{"url": "https://api.x.com/v2/DELETE", "method": "DELETE"},
			surface: "egress",
			want: Action{
				Surface: "api",
				Verb:    "delete",
				Host:    "api.x.com",
				Targets: []string{"api.x.com"},
				Flags:   map[string]bool{"delete_verb": true},
				Raw:     "https://api.x.com/v2/DELETE",
			},
		},
		{
			name:    "web_fetch GET is read",
			tool:    "web_fetch",
			args:    map[string]any{"url": "https://api.x.com/v2/status", "method": "GET"},
			surface: "egress",
			want: Action{
				Surface: "api",
				Verb:    "read",
				Host:    "api.x.com",
				Targets: []string{"api.x.com"},
				Raw:     "https://api.x.com/v2/status",
			},
		},
		{
			name:    "web_fetch defaults to GET when no method",
			tool:    "web_fetch",
			args:    map[string]any{"url": "https://example.com/page"},
			surface: "egress",
			want: Action{
				Surface: "api",
				Verb:    "read",
				Host:    "example.com",
				Targets: []string{"example.com"},
				Raw:     "https://example.com/page",
			},
		},
		{
			name:    "message to telegram carries channel, target, dlp finding",
			tool:    "message",
			args:    map[string]any{"channel": "telegram", "to": "mum", "text": "hi " + ghp},
			surface: "send",
			want: Action{
				Surface:  "comms",
				Verb:     "send",
				Channel:  "telegram",
				Targets:  []string{"mum"},
				Findings: []string{"secret:ghp"},
				Raw:      "hi " + ghp,
			},
		},
		{
			name:    "sessions_send maps like a comms send",
			tool:    "sessions_send",
			args:    map[string]any{"channel": "discord", "to": "friend", "body": "yo"},
			surface: "send",
			want: Action{
				Surface: "comms",
				Verb:    "send",
				Channel: "discord",
				Targets: []string{"friend"},
				Raw:     "yo",
			},
		},
		{
			name:    "read tool is read-only",
			tool:    "read",
			args:    "some file contents",
			surface: "tool",
			want: Action{
				Surface: "unknown",
				Verb:    "read",
			},
		},
		{
			name:    "unknown native tool with map args is unknown",
			tool:    "some_future_tool",
			args:    map[string]any{"foo": "bar"},
			surface: "tool",
			want: Action{
				Surface: "unknown",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Classify(tt.tool, tt.args, tt.surface)
			assertAction(t, got, tt.want)
		})
	}
}

func TestClassifyEmailRecipients(t *testing.T) {
	// message with multiple recipients captured as targets, email finding present
	got := Classify("message", map[string]any{
		"channel": "telegram",
		"to":      []any{"a", "b"},
		"text":    "reach me@x.com",
	}, "send")
	if !reflect.DeepEqual(got.Targets, []string{"a", "b"}) {
		t.Fatalf("targets = %v, want [a b]", got.Targets)
	}
	if !containsLabel(got.Findings, "pii:email") {
		t.Fatalf("findings = %v, want pii:email", got.Findings)
	}
}

func TestClassifyRawBounded(t *testing.T) {
	big := strings.Repeat("x", 32*1024)
	got := Classify("message", map[string]any{"channel": "telegram", "to": "x", "text": big}, "send")
	if len(got.Raw) > 16*1024 {
		t.Fatalf("Raw not bounded: len=%d want <=%d", len(got.Raw), 16*1024)
	}
}

// assertAction compares the fields we assert on, tolerating nil-vs-empty for
// maps/slices so tests stay readable.
func assertAction(t *testing.T, got, want Action) {
	t.Helper()
	if got.Surface != want.Surface {
		t.Errorf("Surface = %q, want %q", got.Surface, want.Surface)
	}
	if got.Verb != want.Verb {
		t.Errorf("Verb = %q, want %q", got.Verb, want.Verb)
	}
	if got.Binary != want.Binary {
		t.Errorf("Binary = %q, want %q", got.Binary, want.Binary)
	}
	if got.Channel != want.Channel {
		t.Errorf("Channel = %q, want %q", got.Channel, want.Channel)
	}
	if got.Host != want.Host {
		t.Errorf("Host = %q, want %q", got.Host, want.Host)
	}
	if !eqStrings(got.Targets, want.Targets) {
		t.Errorf("Targets = %v, want %v", got.Targets, want.Targets)
	}
	if !eqStrings(got.Findings, want.Findings) {
		t.Errorf("Findings = %v, want %v", got.Findings, want.Findings)
	}
	if !eqFlags(got.Flags, want.Flags) {
		t.Errorf("Flags = %v, want %v", got.Flags, want.Flags)
	}
	if want.Raw != "" && got.Raw != want.Raw {
		t.Errorf("Raw = %q, want %q", got.Raw, want.Raw)
	}
}

func eqStrings(a, b []string) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	return reflect.DeepEqual(a, b)
}

func eqFlags(a, b map[string]bool) bool {
	// only compare true flags; missing == false
	ta := trueKeys(a)
	tb := trueKeys(b)
	return reflect.DeepEqual(ta, tb)
}

func trueKeys(m map[string]bool) map[string]bool {
	out := map[string]bool{}
	for k, v := range m {
		if v {
			out[k] = true
		}
	}
	return out
}

func containsLabel(labels []string, want string) bool {
	for _, l := range labels {
		if l == want {
			return true
		}
	}
	return false
}
