package normalize

import (
	"regexp"
	"sort"
)

// DLP labels emitted by ScanDLP. Secret markers are anchored to recognisable
// prefixes with plausible lengths; PII classes use conservative patterns. The
// goal is a low false-positive signal for "don't send this outbound", not a
// exhaustive scanner.
const (
	labelGHP       = "secret:ghp"
	labelAnthropic = "secret:anthropic"
	labelOpenAI    = "secret:openai"
	labelAWS       = "secret:aws"
	label1Password = "secret:1password"
	labelEmail     = "pii:email"
	labelPhone     = "pii:phone"
)

var (
	// GitHub personal access tokens: ghp_ followed by 36 base62 chars. The
	// classic format is exactly ghp_ + 36, but newer fine-grained tokens are
	// longer, so allow 36 or more.
	reGHP = regexp.MustCompile(`ghp_[A-Za-z0-9]{36,}`)

	// Anthropic keys start sk-ant-. Checked before the generic openai marker so
	// an Anthropic key is not double-labelled.
	reAnthropic = regexp.MustCompile(`sk-ant-[A-Za-z0-9_-]{16,}`)

	// OpenAI-style keys: sk- followed by 20+ base62 chars, but NOT sk-ant-
	// (that is Anthropic). The negative lookahead is emulated below by stripping
	// Anthropic matches before testing.
	reOpenAI = regexp.MustCompile(`sk-[A-Za-z0-9]{20,}`)

	// AWS access key IDs: AKIA + 16 uppercase alphanumeric.
	reAWS = regexp.MustCompile(`AKIA[A-Z0-9]{16}`)

	// 1Password secret references (op://...) or the literal product name.
	re1PasswordRef  = regexp.MustCompile(`op://[A-Za-z0-9._~-]+`)
	re1PasswordWord = regexp.MustCompile(`(?i)1password`)

	// Conservative email: local@domain.tld with a real TLD-ish suffix.
	reEmail = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)

	// Phone: an explicit +country prefix followed by digit groups, e.g.
	// "+1 415 555 0132". Requires the leading + and at least three groups so a
	// bare number or a URL path segment does not trip it.
	rePhone = regexp.MustCompile(`\+\d{1,3}(?:[ .-]\d{2,4}){2,}`)
)

// ScanDLP returns the sorted, unique DLP labels found in s. An input with no
// matches returns nil. Patterns are compiled once at package load.
func ScanDLP(s string) []string {
	if s == "" {
		return nil
	}

	set := make(map[string]struct{}, 4)

	if reGHP.MatchString(s) {
		set[labelGHP] = struct{}{}
	}

	// Anthropic before OpenAI: strip Anthropic matches so a sk-ant- key is not
	// also reported as a generic openai sk- key.
	anthropic := reAnthropic.MatchString(s)
	if anthropic {
		set[labelAnthropic] = struct{}{}
	}
	if reOpenAI.MatchString(stripAnthropic(s, anthropic)) {
		set[labelOpenAI] = struct{}{}
	}

	if reAWS.MatchString(s) {
		set[labelAWS] = struct{}{}
	}
	if re1PasswordRef.MatchString(s) || re1PasswordWord.MatchString(s) {
		set[label1Password] = struct{}{}
	}
	if reEmail.MatchString(s) {
		set[labelEmail] = struct{}{}
	}
	if rePhone.MatchString(s) {
		set[labelPhone] = struct{}{}
	}

	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for l := range set {
		out = append(out, l)
	}
	sort.Strings(out)
	return out
}

// stripAnthropic removes sk-ant-... substrings before the generic openai test
// so an Anthropic key does not also register as an openai key. It is a no-op
// when no Anthropic marker was present.
func stripAnthropic(s string, present bool) string {
	if !present {
		return s
	}
	return reAnthropic.ReplaceAllString(s, "")
}
