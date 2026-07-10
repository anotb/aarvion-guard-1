package normalize

import (
	"path/filepath"
	"strings"
)

// dispatchBinary identifies the binary by the basename of argv[0] and routes to
// its matcher. It never inspects DLP or Raw (the caller does). An empty argv or
// an unrecognised binary yields the generic {exec, run} action.
func dispatchBinary(argv []string) Action {
	if len(argv) == 0 {
		return Action{Surface: "exec", Verb: "run"}
	}
	bin := filepath.Base(argv[0])
	rest := argv[1:]

	switch bin {
	case "gog":
		return matchGog(rest)
	case "bird":
		return matchBird(rest)
	case "gh":
		return matchGh(rest)
	case "git":
		return matchGit(rest)
	case "curl":
		return matchCurl(rest, "curl")
	case "wget":
		return matchCurl(rest, "wget")
	case "docker":
		return matchDocker(rest)
	case "systemctl":
		return matchServiceCtl(rest, "systemctl")
	case "launchctl":
		return matchServiceCtl(rest, "launchctl")
	default:
		return Action{Surface: "exec", Verb: "run"}
	}
}

// --- gog (Google: gmail / drive / docs / sheets / calendar) ---

// matchGog handles `gog <service> <verb> [args...]`.
func matchGog(a []string) Action {
	act := Action{Binary: "gog", Surface: "unknown", Verb: "run"}
	if len(a) == 0 {
		return act
	}
	service := strings.ToLower(a[0])
	var verb string
	rest := a[1:]
	if len(rest) > 0 {
		verb = strings.ToLower(rest[0])
	}

	switch service {
	case "gmail", "mail":
		act.Surface = "email"
	case "drive":
		act.Surface = "file"
	case "docs":
		act.Surface = "doc"
	case "sheets":
		act.Surface = "sheet"
	case "calendar", "cal":
		act.Surface = "calendar"
	}

	act.Verb = googleVerb(verb)

	// Targets: recipients (--to) and positional ids.
	act.Targets = collectTargets(rest)

	// Flags.
	forced := hasFlag(rest, "--force", "-f")
	if forced {
		act.setFlag("force")
		act.setFlag("destructive")
	}
	if act.Verb == "delete" {
		act.setFlag("destructive")
	}
	if act.Verb == "share" && sharesPublicly(rest) {
		act.setFlag("public_share")
	}
	return act
}

// googleVerb maps a gog subcommand verb into a semantic verb.
func googleVerb(v string) string {
	switch v {
	case "send":
		return "send"
	case "delete", "rm", "trash", "empty-trash":
		return "delete"
	case "share":
		return "share"
	case "list", "get", "read", "show", "view", "search", "":
		return "read"
	default:
		return v
	}
}

// sharesPublicly reports whether a share command opens access to anyone.
func sharesPublicly(a []string) bool {
	role := flagValue(a, "--role")
	if strings.EqualFold(role, "anyone") {
		return true
	}
	return hasFlag(a, "--anyone", "--public")
}

// --- bird (X/Twitter) ---

// matchBird handles `bird <verb> [args...]`.
func matchBird(a []string) Action {
	act := Action{Binary: "bird", Surface: "twitter", Verb: "read"}
	if len(a) == 0 {
		return act
	}
	switch strings.ToLower(a[0]) {
	case "tweet", "post":
		act.Verb = "post"
	case "reply":
		act.Verb = "reply"
	case "dm", "message":
		act.Verb = "dm"
	case "follow":
		act.Verb = "follow"
	case "like", "favorite", "fav":
		act.Verb = "like"
	case "search", "whoami", "timeline", "read", "get", "show", "list":
		act.Verb = "read"
	default:
		act.Verb = "read"
	}
	return act
}

// --- gh (GitHub CLI) ---

// matchGh handles `gh <noun> <verb> [args...]`.
func matchGh(a []string) Action {
	act := Action{Binary: "gh", Surface: "github", Verb: "run"}
	if len(a) == 0 {
		return act
	}
	noun := strings.ToLower(a[0])
	var verb string
	if len(a) > 1 {
		verb = strings.ToLower(a[1])
	}

	switch {
	case (noun == "repo" || noun == "branch") && verb == "delete":
		act.Verb = "repo_delete"
		act.setFlag("destructive")
	case verb == "delete":
		act.Verb = "delete"
		act.setFlag("destructive")
	case verb == "create":
		act.Verb = "create"
	case verb == "list" || verb == "view" || verb == "":
		act.Verb = "read"
	default:
		act.Verb = verb
	}
	return act
}

// --- git ---

// matchGit handles `git <verb> [args...]`, with push/force-push the key cases.
func matchGit(a []string) Action {
	act := Action{Binary: "git", Surface: "github", Verb: "run"}
	if len(a) == 0 {
		return act
	}
	switch strings.ToLower(a[0]) {
	case "push":
		if hasForcePush(a) {
			act.Verb = "force_push"
			act.setFlag("force")
		} else {
			act.Verb = "push"
		}
	case "clone", "fetch", "pull", "log", "status", "diff", "show":
		act.Verb = "read"
	default:
		act.Verb = strings.ToLower(a[0])
	}
	return act
}

// hasForcePush reports whether a git push carries a force flag. It covers the
// bare forms (--force, -f, --force-with-lease, --force-if-includes) AND the
// valued forms (--force-with-lease=<ref>, --force-with-lease=<ref>:<expect>),
// which git accepts and which would otherwise slip past an exact-token match and
// be misclassified as a plain push.
func hasForcePush(a []string) bool {
	if hasFlag(a, "--force", "-f", "--force-with-lease", "--force-if-includes") {
		return true
	}
	for _, tok := range a {
		if strings.HasPrefix(tok, "--force-with-lease=") {
			return true
		}
	}
	return false
}

// --- curl / wget ---

// matchCurl handles `curl`/`wget`, extracting the method (-X) and URL/host.
func matchCurl(a []string, bin string) Action {
	act := Action{Binary: bin, Surface: "api", Verb: "read"}
	method := strings.ToUpper(flagValue(a, "-X", "--request"))
	if method == "" {
		method = "GET"
	}
	act.Verb = verbForMethod(method)
	if isDestructiveMethod(method) {
		act.setFlag("delete_verb")
	}
	if u := firstURL(a); u != "" {
		act.Targets = []string{u}
		act.Host = hostOf(u)
		act.Account = ""
	}
	return act
}

// --- docker ---

// matchDocker handles `docker <cmd...>`, flagging destructive operations.
func matchDocker(a []string) Action {
	act := Action{Binary: "docker", Surface: "infra", Verb: "run"}
	for _, tok := range a {
		switch strings.ToLower(tok) {
		case "prune", "rm", "rmi", "kill", "stop", "down":
			act.setFlag("destructive")
		}
	}
	if hasFlag(a, "-f", "--force") {
		act.setFlag("destructive")
	}
	return act
}

// --- systemctl / launchctl ---

// matchServiceCtl handles service managers; state-changing verbs are marked
// destructive so infra-guard can gate them.
func matchServiceCtl(a []string, bin string) Action {
	act := Action{Binary: bin, Surface: "infra", Verb: "run"}
	if len(a) == 0 {
		return act
	}
	verb := strings.ToLower(a[0])
	switch verb {
	case "stop", "disable", "kill", "unload", "remove", "mask", "restart":
		act.setFlag("destructive")
	}
	act.Verb = verb
	return act
}

// --- shared helpers ---

// collectTargets gathers recipient/positional-id targets from a subcommand's
// args: --to values and bare positional tokens (non-flags, non-flag-values).
func collectTargets(a []string) []string {
	var out []string
	for i := 0; i < len(a); i++ {
		tok := a[i]
		if tok == "--to" || tok == "--recipient" {
			if i+1 < len(a) {
				out = append(out, a[i+1])
				i++
			}
			continue
		}
		if strings.HasPrefix(tok, "--to=") {
			out = append(out, strings.TrimPrefix(tok, "--to="))
			continue
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// hasFlag reports whether any of names appears as a token in a.
func hasFlag(a []string, names ...string) bool {
	for _, tok := range a {
		for _, n := range names {
			if tok == n {
				return true
			}
			// support --role=anyone style for value flags handled elsewhere.
		}
	}
	return false
}

// flagValue returns the value following the first of names (space-separated) or
// the value in a --name=value token.
func flagValue(a []string, names ...string) string {
	for i := 0; i < len(a); i++ {
		tok := a[i]
		for _, n := range names {
			if tok == n && i+1 < len(a) {
				return a[i+1]
			}
			if strings.HasPrefix(tok, n+"=") {
				return strings.TrimPrefix(tok, n+"=")
			}
		}
	}
	return ""
}

// firstURL returns the first http(s) URL token in a.
func firstURL(a []string) string {
	for _, tok := range a {
		if strings.HasPrefix(tok, "http://") || strings.HasPrefix(tok, "https://") {
			return tok
		}
	}
	return ""
}
