package normalize

import (
	"testing"
)

// classifyCmd is a helper that runs a shell command through Classify as the
// PEP would, with tool="exec" and surface="exec".
func classifyCmd(cmd string) Action {
	return Classify("exec", cmd, "exec")
}

func TestClassifyShellBinaries(t *testing.T) {
	tests := []struct {
		name       string
		cmd        string
		wantSurf   string
		wantVerb   string
		wantBinary string
		wantFlags  []string // flags that must be true
		wantTgts   []string // exact targets (nil = don't check)
		wantHost   string   // "" = don't check
	}{
		// gog / google
		{
			name:       "gog gmail send",
			cmd:        "gog gmail send --to a@x.com",
			wantSurf:   "email",
			wantVerb:   "send",
			wantBinary: "gog",
			wantTgts:   []string{"a@x.com"},
		},
		{
			name:       "gog drive delete --force",
			cmd:        "gog drive delete 123 --force",
			wantSurf:   "file",
			wantVerb:   "delete",
			wantBinary: "gog",
			wantFlags:  []string{"force", "destructive"},
		},
		{
			name:       "gog drive share anyone",
			cmd:        "gog drive share 123 --role anyone",
			wantSurf:   "file",
			wantVerb:   "share",
			wantBinary: "gog",
			wantFlags:  []string{"public_share"},
		},
		{
			name:       "gog docs share anyone is a doc share",
			cmd:        "gog docs share 999 --role anyone",
			wantSurf:   "doc",
			wantVerb:   "share",
			wantBinary: "gog",
			wantFlags:  []string{"public_share"},
		},
		{
			name:       "gog calendar list is read",
			cmd:        "gog calendar list",
			wantSurf:   "calendar",
			wantVerb:   "read",
			wantBinary: "gog",
		},

		// bird / twitter
		{
			name:       "bird tweet posts",
			cmd:        `bird tweet "hello"`,
			wantSurf:   "twitter",
			wantVerb:   "post",
			wantBinary: "bird",
		},
		{
			name:       "bird reply",
			cmd:        `bird reply 123 "hi"`,
			wantSurf:   "twitter",
			wantVerb:   "reply",
			wantBinary: "bird",
		},
		{
			name:       "bird follow",
			cmd:        "bird follow someuser",
			wantSurf:   "twitter",
			wantVerb:   "follow",
			wantBinary: "bird",
		},
		{
			name:       "bird search is read",
			cmd:        "bird search golang",
			wantSurf:   "twitter",
			wantVerb:   "read",
			wantBinary: "bird",
		},
		{
			name:       "bird whoami is read",
			cmd:        "bird whoami",
			wantSurf:   "twitter",
			wantVerb:   "read",
			wantBinary: "bird",
		},
		{
			name:       "bird dm",
			cmd:        `bird dm someuser "hey"`,
			wantSurf:   "twitter",
			wantVerb:   "dm",
			wantBinary: "bird",
		},
		{
			name:       "bird like",
			cmd:        "bird like 123",
			wantSurf:   "twitter",
			wantVerb:   "like",
			wantBinary: "bird",
		},

		// gh / git / github
		{
			name:       "gh repo delete",
			cmd:        "gh repo delete o/r --yes",
			wantSurf:   "github",
			wantVerb:   "repo_delete",
			wantBinary: "gh",
			wantFlags:  []string{"destructive"},
		},
		{
			name:       "git push --force is force_push",
			cmd:        "git push --force",
			wantSurf:   "github",
			wantVerb:   "force_push",
			wantBinary: "git",
			wantFlags:  []string{"force"},
		},
		{
			name:       "git push is push",
			cmd:        "git push",
			wantSurf:   "github",
			wantVerb:   "push",
			wantBinary: "git",
		},
		{
			name:       "git push -f is force_push",
			cmd:        "git push -f origin main",
			wantSurf:   "github",
			wantVerb:   "force_push",
			wantBinary: "git",
			wantFlags:  []string{"force"},
		},
		{
			name:       "git push --force-with-lease=ref is force_push",
			cmd:        "git push --force-with-lease=origin/main origin main",
			wantSurf:   "github",
			wantVerb:   "force_push",
			wantBinary: "git",
			wantFlags:  []string{"force"},
		},
		{
			name:       "git push --force-if-includes is force_push",
			cmd:        "git push --force-if-includes origin main",
			wantSurf:   "github",
			wantVerb:   "force_push",
			wantBinary: "git",
			wantFlags:  []string{"force"},
		},

		// curl / api
		{
			name:       "curl DELETE",
			cmd:        "curl -X DELETE https://api.x/thing",
			wantSurf:   "api",
			wantVerb:   "delete",
			wantBinary: "curl",
			wantFlags:  []string{"delete_verb"},
			wantHost:   "api.x",
		},
		{
			name:       "curl GET is read",
			cmd:        "curl https://api.x/status",
			wantSurf:   "api",
			wantVerb:   "read",
			wantBinary: "curl",
			wantHost:   "api.x",
		},
		{
			name:       "wget is api read",
			cmd:        "wget https://example.com/file.tar",
			wantSurf:   "api",
			wantVerb:   "read",
			wantBinary: "wget",
			wantHost:   "example.com",
		},

		// docker / infra
		{
			name:       "docker system prune -f is destructive infra",
			cmd:        "docker system prune -f",
			wantSurf:   "infra",
			wantVerb:   "run",
			wantBinary: "docker",
			wantFlags:  []string{"destructive"},
		},
		{
			name:       "systemctl stop is infra",
			cmd:        "systemctl stop nginx",
			wantSurf:   "infra",
			wantBinary: "systemctl",
			wantFlags:  []string{"destructive"},
		},
		{
			name:       "launchctl unload is infra",
			cmd:        "launchctl unload com.foo.bar",
			wantSurf:   "infra",
			wantBinary: "launchctl",
			wantFlags:  []string{"destructive"},
		},

		// unknown binary falls back to exec/run
		{
			name:       "unknown binary is exec run",
			cmd:        "somebin --do-thing",
			wantSurf:   "exec",
			wantVerb:   "run",
			wantBinary: "",
		},
		{
			name:       "path-qualified binary uses basename",
			cmd:        "/usr/bin/git push",
			wantSurf:   "github",
			wantVerb:   "push",
			wantBinary: "git",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyCmd(tt.cmd)
			if got.Surface != tt.wantSurf {
				t.Errorf("Surface = %q, want %q", got.Surface, tt.wantSurf)
			}
			if tt.wantVerb != "" && got.Verb != tt.wantVerb {
				t.Errorf("Verb = %q, want %q", got.Verb, tt.wantVerb)
			}
			if got.Binary != tt.wantBinary {
				t.Errorf("Binary = %q, want %q", got.Binary, tt.wantBinary)
			}
			for _, f := range tt.wantFlags {
				if !got.Flags[f] {
					t.Errorf("Flags[%q] = false, want true (flags=%v)", f, got.Flags)
				}
			}
			if tt.wantTgts != nil && !eqStrings(got.Targets, tt.wantTgts) {
				t.Errorf("Targets = %v, want %v", got.Targets, tt.wantTgts)
			}
			if tt.wantHost != "" && got.Host != tt.wantHost {
				t.Errorf("Host = %q, want %q", got.Host, tt.wantHost)
			}
		})
	}
}

func TestClassifyShellDLPOverCommand(t *testing.T) {
	// A secret pasted into a shell command is picked up regardless of binary.
	cmd := "curl -X POST https://api.x/thing -d token=ghp_" + repeat("a", 36)
	got := classifyCmd(cmd)
	if !containsLabel(got.Findings, "secret:ghp") {
		t.Fatalf("findings = %v, want secret:ghp", got.Findings)
	}
}

func TestClassifyShellRawBounded(t *testing.T) {
	cmd := "echo " + repeat("x", 32*1024)
	got := classifyCmd(cmd)
	if len(got.Raw) > 16*1024 {
		t.Fatalf("Raw not bounded: %d", len(got.Raw))
	}
}

func repeat(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}
