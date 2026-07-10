// Package normalize turns a raw OpenClaw tool call into a typed semantic
// Action: what surface it touches (email, twitter, github, ...), what verb it
// performs (send, delete, post, ...), which targets it names, and any DLP
// findings in its payload. Policy then judges the semantic Action rather than
// fragile substrings of a raw command.
//
// This package imports the standard library only. It has no dependencies on
// other guard packages, so the normalizer stays authoritative and cheap to
// call on the PDP hot path.
package normalize

import (
	"net/url"
	"sort"
	"strings"
)

// maxRaw bounds Action.Raw so a huge payload cannot bloat the decision record
// or audit row.
const maxRaw = 16 * 1024

// Action is the typed, semantic view of a tool call. Zero values mean "not
// applicable": an empty Verb, nil Targets, and a nil Flags map are all valid.
type Action struct {
	Surface  string          // email|file|calendar|doc|sheet|twitter|comms|github|api|exec|infra|unknown
	Verb     string          // send|read|delete|share|post|reply|dm|follow|like|push|force_push|repo_delete|call|run|...
	Binary   string          // gog|bird|gh|git|curl|wget|docker|systemctl|launchctl|"" (non-shell)
	Account  string          // account/handle the action runs as, when known
	Channel  string          // telegram|discord|whatsapp|reddit|imessage|""
	Targets  []string        // recipients / repo / file id / url
	Host     string          // egress host for url/api verbs
	Flags    map[string]bool // force|external_recipient|public_share|destructive|delete_verb|...
	Findings []string        // DLP labels from ScanDLP over the payload
	Raw      string          // bounded raw command/payload for forensics (<=16KiB)
}

// setFlag lazily allocates a.Flags and sets key true.
func (a *Action) setFlag(key string) {
	if a.Flags == nil {
		a.Flags = map[string]bool{}
	}
	a.Flags[key] = true
}

// shellTools are the OpenClaw tool names whose args are a raw shell command
// string, dispatched to the per-binary matchers. Any other tool with a string
// arg is treated as a native tool (so a native "read" with a string body is
// read-only, not parsed as a command).
var shellTools = map[string]bool{
	"exec":    true,
	"shell":   true,
	"bash":    true,
	"sh":      true,
	"command": true,
	"run":     true,
	"zsh":     true,
}

// Classify maps a tool call to a semantic Action. tool is the OpenClaw tool
// name; args is the raw args (a string command for shell tools, or a
// map[string]any of params for native tools); surface is the PEP's coarse tag.
//
// Shell tools carry their command as a string and dispatch to the per-binary
// matchers; everything else is treated as a native tool with structured params.
func Classify(tool string, args any, surface string) Action {
	if cmd, ok := args.(string); ok && shellTools[tool] {
		return classifyShell(tool, cmd, surface)
	}
	params, _ := args.(map[string]any)
	return classifyNative(tool, params, surface)
}

// classifyShell handles shell tools whose args are a raw command string. It
// splits the command into argv and dispatches to a per-binary matcher keyed by
// the basename of argv[0]. An unknown or empty binary falls back to a generic
// {exec, run} action. The full command is scanned for DLP findings.
func classifyShell(_tool, cmd, _surface string) Action {
	argv := splitArgs(cmd)
	a := dispatchBinary(argv)
	a.Raw = bound(cmd)
	if f := ScanDLP(cmd); len(f) > 0 {
		a.Findings = mergeFindings(a.Findings, f)
	}
	return a
}

// mergeFindings unions two DLP label lists into a sorted, unique slice.
func mergeFindings(a, b []string) []string {
	if len(a) == 0 {
		return b
	}
	if len(b) == 0 {
		return a
	}
	set := make(map[string]struct{}, len(a)+len(b))
	for _, l := range a {
		set[l] = struct{}{}
	}
	for _, l := range b {
		set[l] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for l := range set {
		out = append(out, l)
	}
	sort.Strings(out)
	return out
}

// classifyNative handles the structured, non-shell tools OpenClaw exposes:
// web_fetch (api/egress), message and sessions_send (comms), read (read-only),
// and anything else which falls through to unknown.
func classifyNative(tool string, p map[string]any, surface string) Action {
	switch tool {
	case "web_fetch", "http", "fetch":
		return classifyWebFetch(p)
	case "message", "sessions_send", "send_message":
		return classifyComms(p)
	case "read", "read_file", "list", "search", "glob", "grep":
		// Read-only native tools: no target world-effect.
		return Action{Surface: "unknown", Verb: "read"}
	default:
		return Action{Surface: "unknown"}
	}
}

// classifyWebFetch maps an HTTP/API call to {api, <verb>} with the host and a
// delete_verb flag for destructive methods.
func classifyWebFetch(p map[string]any) Action {
	rawURL := firstString(p, "url", "uri", "endpoint")
	method := strings.ToUpper(strings.TrimSpace(firstString(p, "method", "verb")))
	if method == "" {
		method = "GET"
	}

	a := Action{Surface: "api", Verb: verbForMethod(method)}
	if rawURL != "" {
		a.Targets = []string{rawURL}
		a.Host = hostOf(rawURL)
		a.Raw = bound(rawURL)
	}
	if isDestructiveMethod(method) {
		a.setFlag("delete_verb")
	}
	// Scan any body/payload for secrets.
	if body := firstString(p, "body", "data", "payload"); body != "" {
		a.Findings = ScanDLP(body)
	}
	return a
}

// classifyComms maps a message/DM send to {comms, send} with channel, targets,
// and DLP over the text body.
func classifyComms(p map[string]any) Action {
	a := Action{Surface: "comms", Verb: "send"}
	a.Channel = strings.ToLower(strings.TrimSpace(firstString(p, "channel", "platform", "network")))
	a.Targets = stringList(p, "to", "recipient", "recipients", "chat_id")
	text := firstString(p, "text", "body", "message", "content")
	if text != "" {
		a.Raw = bound(text)
		a.Findings = ScanDLP(text)
	}
	return a
}

// verbForMethod maps an HTTP method to a semantic verb.
func verbForMethod(method string) string {
	switch method {
	case "GET", "HEAD", "OPTIONS":
		return "read"
	case "DELETE":
		return "delete"
	default:
		// POST/PUT/PATCH and anything unusual are treated as a call/write.
		return "call"
	}
}

// isDestructiveMethod reports whether an HTTP method mutates or deletes state
// in a way policy may want to gate.
func isDestructiveMethod(method string) bool {
	switch method {
	case "DELETE", "PUT", "PATCH":
		return true
	default:
		return false
	}
}

// hostOf extracts the host from a URL, tolerating a scheme-less input.
func hostOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err == nil && u.Host != "" {
		return u.Hostname()
	}
	// Fallback: no scheme (e.g. "api.x.com/path").
	u2, err2 := url.Parse("//" + rawURL)
	if err2 == nil && u2.Host != "" {
		return u2.Hostname()
	}
	return ""
}

// firstString returns the first key in keys present in p whose value is a
// non-empty string.
func firstString(p map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := p[k]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}

// stringList collects string targets from the first present key, accepting a
// bare string, a []string, or a []any of strings.
func stringList(p map[string]any, keys ...string) []string {
	for _, k := range keys {
		v, ok := p[k]
		if !ok {
			continue
		}
		switch t := v.(type) {
		case string:
			if t != "" {
				return []string{t}
			}
		case []string:
			if len(t) > 0 {
				return append([]string(nil), t...)
			}
		case []any:
			out := make([]string, 0, len(t))
			for _, e := range t {
				if s, ok := e.(string); ok && s != "" {
					out = append(out, s)
				}
			}
			if len(out) > 0 {
				return out
			}
		}
	}
	return nil
}

// bound truncates s to maxRaw bytes for forensic storage.
func bound(s string) string {
	if len(s) <= maxRaw {
		return s
	}
	return s[:maxRaw]
}
