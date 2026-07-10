package normalize

import "strings"

// splitArgs is a POSIX-ish shlex: it splits cmd into argv, honouring
// single-quote, double-quote, and backslash escaping. It is deliberately
// forgiving of malformed input (unbalanced quotes emit the token collected so
// far rather than erroring), because it runs on untrusted command strings and
// must always return a best-effort argv for the binary matchers.
//
// Rules:
//   - Whitespace (space/tab/newline) outside quotes separates tokens.
//   - Single quotes are literal: no escapes are interpreted inside them.
//   - Double quotes group, but a backslash still escapes the next char.
//   - Outside quotes, a backslash escapes the next char (so `a\ b` is one token).
//   - Adjacent quoted/bare runs concatenate into a single token (`-X'DELETE'`).
//   - A quote that opens but never closes still contributes its content.
func splitArgs(cmd string) []string {
	var (
		args     []string
		cur      strings.Builder
		hasTok   bool // a token is in progress (even if empty, e.g. "")
		inSingle bool
		inDouble bool
		escaped  bool
	)

	flush := func() {
		if hasTok {
			args = append(args, cur.String())
			cur.Reset()
			hasTok = false
		}
	}

	for i := 0; i < len(cmd); i++ {
		c := cmd[i]

		if escaped {
			cur.WriteByte(c)
			hasTok = true
			escaped = false
			continue
		}

		switch {
		case inSingle:
			if c == '\'' {
				inSingle = false
			} else {
				cur.WriteByte(c)
			}
			hasTok = true

		case inDouble:
			switch c {
			case '\\':
				escaped = true
			case '"':
				inDouble = false
			default:
				cur.WriteByte(c)
			}
			hasTok = true

		default: // unquoted
			switch c {
			case '\\':
				escaped = true
			case '\'':
				inSingle = true
				hasTok = true
			case '"':
				inDouble = true
				hasTok = true
			case ' ', '\t', '\n', '\r':
				flush()
			default:
				cur.WriteByte(c)
				hasTok = true
			}
		}
	}

	// Best-effort on a trailing escape: emit a literal backslash content is
	// dropped (POSIX would line-continue); we simply flush what we have.
	flush()
	return args
}
