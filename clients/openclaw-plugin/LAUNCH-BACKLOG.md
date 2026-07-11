# Launch backlog — @aarvion/openclaw-guard (ProductHunt)

The plugin is built, proven live on a stock OpenClaw (block + ask + per-agent
trust), documented, and consolidated into one PR. Two things remain before a
public launch. **These are handed off to a separate agent/session.**

---

## Task 1 — Publish the package so `openclaw plugins install` works from a registry

**Why:** the README tells users to run
`openclaw plugins install @aarvion/openclaw-guard`, but the package isn't
published yet — today only the local dev path works
(`openclaw plugins install ./clients/openclaw-plugin --link`). This is the #1
launch blocker: a visitor's one-line install must actually resolve.

**Current state:**
- `package.json` already declares the install specs:
  `openclaw.install = { npmSpec: "@aarvion/openclaw-guard", clawhubSpec: ... (add), localPath: ".", defaultChoice: "npm" }`.
- The package is self-contained (zero `openclaw` runtime imports; only Node
  built-ins) and builds with `npm run build` → `dist/`. `files` ships
  `dist`, `openclaw.plugin.json`, `README.md`.

**Do:**
1. Create/claim the `@aarvion` npm org; decide public vs private (public for a
   PH launch).
2. From `clients/openclaw-plugin/`: `npm ci && npm run build`, verify
   `dist/index.js` + `dist/src/*.js` exist and the manifest is included, then
   `npm publish --access public`.
3. (Optional but ideal for OpenClaw) publish to **ClawHub** too so
   `clawhub:@aarvion/openclaw-guard` resolves; add `clawhubSpec` to package.json.
4. Verify end-to-end: on a clean machine with stock OpenClaw,
   `openclaw plugins install @aarvion/openclaw-guard` → `openclaw plugins enable
   aarvion-guard` → set `OPENCLAW_GUARD_*` env → a governed action is blocked.
5. Consider a scoped release workflow (`.github/workflows`) that publishes on a
   plugin `v*` tag, mirroring the guard's release job.

**Acceptance:** a fresh OpenClaw installs the plugin from a public registry with
one command, no local checkout.

---

## Task 3 — A 30–60s demo clip (the PH hero asset)

**Why:** the pitch *is* the live moments — prose won't carry the PH post.

**The three beats to capture (all reproducible on the Mac Mini harness):**
1. **Block:** an agent tries `git push --force` → OpenClaw refuses:
   `Command blocked by PreToolUse hook: Aarvion guard: blocked: git force-push`.
2. **Ask:** an agent hits an `ask`-marked action → OpenClaw pauses for approval
   (with the gateway up, this is a prompt on the owner's phone/chat; approve →
   proceeds, deny/timeout → blocked).
3. **Per-agent trust:** the *same* `git push` allowed for `main`, denied for an
   untrusted agent — governance keyed on who's asking.

**Harness (from this session, for reproducibility):**
- Guard side: run a standalone `opa run --server --addr 127.0.0.1:8181 <dir with
  examples/govern.rego>`; run the guard with a `govern.socket` block in
  `~/.aarvion/guard.json` (path/token/`peer_uid = id -u`). The guard's own OPA
  fails to bind 8181 (harmless) and uses the standalone one, so the example
  policy is what decides.
- Plugin: `openclaw plugins install ~/aarvion-plugin --link` + `enable`; env
  `OPENCLAW_GUARD_ENABLED=1 OPENCLAW_GUARD_SOCKET=... OPENCLAW_GUARD_TOKEN=...
  OPENCLAW_GUARD_FAIL_MODE=closed OPENCLAW_GUARD_TOOLS=actions`.
- Trigger a turn: `openclaw agent --local --agent main --session-key
  agent:main:demo -m 'Use the exec/bash tool to run exactly this one shell
  command, then report verbatim what the tool returned: <cmd>'`. (That exact
  phrasing reliably makes the agent call exec; looser phrasing sometimes doesn't.
  `main` disallows `--model` overrides, so use its default model.)
- For a full **approve → proceeds** capture, run the OpenClaw **gateway** (not
  just `--local`) so an approver channel exists.

**Deliverable:** an asciinema/GIF embedded in `README.md` and the PH post.

**Reminder for launch copy:** the tamper-proof guarantee needs guard + agent on
**separate uids**; same-uid governs the decision path but isn't a hard boundary.

---

## Backlog: show the actual content being approved

Today a Telegram/console approval shows `agent: llm-twitter · action: twitter post
· reason: social_guard:write`. It should also show **what** is being approved — the
actual tweet text, the email recipient + subject, the shell command, the message
body — so the owner decides on substance, not just surface+verb.

- Guard: thread the concrete content into the approval. `govern.ApprovalRequest`
  already has the semantic action; add a bounded, redacted `Content` string
  (the normalized command / `sem.Raw` / comms body, secret-scrubbed) →
  `approve.Pending.Content` → `notifyText` and the console inbox row.
- Redact secrets/PII in the shown content (reuse `normalize.ScanDLP` to mask
  `ghp_…`/keys before display) so the approval prompt itself isn't a leak.
- Bound to Telegram's 4096-char message cap (already have `boundText`).
- Small change; deferred so it doesn't hold up the launch.
