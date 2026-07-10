# Policy packs — the consumer catalog

A **pack** is a named, per-surface guardrail you toggle on or off instead of
hand-authoring rego or overlay rules. Each pack knows about a real set of tools
(the `gog`/`bird`/`gh` CLIs, the native messaging channels, curl, docker) and
gates them by *intent* — send vs read, delete vs list, external vs internal
recipient — not by substring-matching the raw command.

You get seven built-in packs, four modes each (`off`/`observe`/`ask`/`enforce`),
per-pack params (allowlists, quiet hours), and per-agent overrides. The same pack
definition drives two enforcement points: the **local console** (compiled to
tighten-only overlay rules, in-process) and **beta.aarvion.ai** (compiled to
CP-signed rego). One schema, two compilers.

> **Honest scope.** In the single-box deployment the guard and OpenClaw share a
> uid, so a pack proves the governance *path* — it turns a soft prompt
> instruction ("never post as me") into an audited, human-approvable gate — but
> it is **not a tamper-proof boundary**. A same-uid compromise can still unset
> the plugin's env or kill the guard; real enforcement wants uid separation or a
> system extension. And packs gate tool *actions*, not the model's streamed
> response. Don't read "enforce" as "unbypassable".

---

## The three modes (plus off)

Every pack sits at one of four modes. This is the whole knob:

| Mode | What it does | Verdict emitted |
|---|---|---|
| **off** | Pack contributes nothing. | — |
| **observe** | Evaluated, but recorded-only. The action **proceeds**; the would-be verdict is written to the decision as `would_be` and fed to the behaviour profile. This is the first-run learn posture. | recorded, not enforced |
| **ask** | Every match escalates to a human. | `ask` |
| **enforce** | Hard/destructive matches → `deny`; softer sensitive matches → `ask`. | `deny` or `ask` |

Each built-in rule carries an intrinsic risk (hard or soft). The mode→verdict
transform reads it: in `enforce`, hard→deny and soft→ask; in `ask`,
everything→ask; in `observe`, the same verdicts are computed but tagged
non-enforcing so you can see what enforcement *would* have done before you flip
it on.

### The learn → promote flow

Every pack ships at **observe** (see `internal/packs/catalog.go`). Nothing is
blocked on day one — the guard just watches. The learn sink accumulates a
**behaviour profile** keyed by `{principal, surface, verb}` (target sets, counts,
time-of-day) at `~/.aarvion/behaviour-profile.json`.

When you've seen enough, the console **Learning** panel renders the profile plus
a generated proposal, and **Protect me now** promotes it (`ProposeFromProfile`).
The proposal is deliberately opinionated:

- **dlp-guard → enforce, always.** Leaking a secret is never something an agent
  should have been doing, so there's nothing to learn — it's on from the start.
- **A principal that only ever *read* a surface gets locked read-only** for that
  surface (`PerAgent: enforce`). Observed read-only usage becomes an enforced
  read-only contract. This is how the `twitter-x` skill's "STRICT READ-ONLY"
  prompt text finally gets teeth.
- **A principal that did a sensitive verb** (send/post/dm/follow/delete/share)
  puts that pack at `ask` globally. If the targets it hit are a small, stable set
  (≤10), they seed the pack's allowlist so routine recipients don't re-prompt.
- **Surfaces never observed** stay at their catalog default — the proposal
  doesn't fabricate rules for tools you've never touched.

So the default journey is: ship in observe → let it watch → one informed click to
an ask-heavy enforce that matches how your agents actually behave.

---

## Local vs beta.aarvion.ai — same pack, two compilers

The pack schema (`internal/packs`) is shared; a `Set` of packs compiles two ways:

- **Local (`CompileOverlay`)** — emits **tighten-only** overlay rules
  (`deny`/`ask` only). The console writes these to `~/.aarvion/overlay.json`; the
  guard evaluates them **after** the CP-signed base decision and **only when it
  already ALLOWED**. A local pack can therefore only *add* a deny or ask — it can
  never loosen a signed decision. That's a structural guarantee, not a
  convention, which is exactly the right safety posture for consumer toggles.
- **CP / rego (`EmitRego`)** — emits full-strength rego + a `data.json` for the
  CP-signed bundle on beta.aarvion.ai, so the *same* pack (same "Twitter
  read-only", same "no Drive deletes") is enable-able against the live entity and
  pulled down signed. Shipped as `examples/packs/governance.rego` +
  `examples/packs/data.json`. Because it's the authoritative bundle, the rego
  form *can* deny outright; the local overlay can only tighten.

Consequence of tighten-only: a per-agent override is only applied locally when it
is **stricter** than the pack's own mode. A per-agent *looser* override is dropped
by the overlay compiler (you loosen in the cloud bundle, not on the box).

---

## The seven packs

Ids and titles are stable (`internal/packs/catalog.go`). Verbs below are the
normalizer's semantic verbs (`internal/normalize`), not raw subcommands, so flag
reordering and quoting don't matter.

### 1. `social-guard` — Social media (Twitter/X) guardrails

**Protects:** posting or interacting *as you* on X/Twitter via the `bird` CLI.

| Gated (write) | Allowed (read) |
|---|---|
| `bird tweet …` / `bird post …` → `post` | `bird search …` |
| `bird reply …` → `reply` | `bird timeline` |
| `bird dm …` / `bird message …` → `dm` | `bird whoami` |
| `bird follow …` → `follow` | `bird read`/`get`/`show`/`list` |
| `bird like …` → `like` | |

The read verb is deliberately excluded, so reads always pass. Only the write
verbs (`post`/`reply`/`dm`/`follow`/`like`) are gated — all `riskHard`, so in
enforce they **deny**.

- **Default mode:** observe.
- **Params:** `accounts` (per-account scoping, list), `allow_read` (bool, true).
- **PerAgent example:** set `llm-twitter: enforce` while the pack itself stays at
  `observe` or `ask`. The `llm-twitter` agent is then locked read-only (writes
  denied) while `main` only gets asked. This is the canonical case: the read-only
  skill instruction becomes a hard, per-agent gate.

### 2. `google-guard` — Google / Gmail / Drive guardrails

**Protects:** destructive and sharing actions across `gog` (Gmail, Drive, Docs,
Sheets, Calendar).

Concrete gates:

- **Drive delete** — `gog drive delete <id>` / `trash` / `empty-trash` → `delete`
  on the `file` surface. `riskHard` → deny in enforce.
- **Force delete** — any `--force`/`-f` delete (skips trash) → deny.
- **Public share** — `gog docs share --role anyone …` (or `--anyone`/`--public`)
  → `share` with the `public_share` flag → deny. "Anyone with the link" is the
  thing you don't want an agent doing silently.
- **Email send** — `gog gmail send --to <addr> …` → `send` on the `email`
  surface. `riskSoft` → **ask** in enforce.
  - With a `contact_allowlist` configured, only sends to **non-contacts** are
    gated (the allowlisted recipients pass without a prompt). Without one, every
    send is gated.

- **Default mode:** observe.
- **Params:** `contact_allowlist` (list; gate only non-contacts when set),
  `allow_calendar_read` (bool, true — read-only calendar for others).
- **PerAgent:** e.g. a shell agent that only ever read Drive gets locked to
  enforce read-only by learn-mode; `main` stays at ask for sends.

### 3. `comms-guard` — Messaging guardrails (Telegram / Discord / WhatsApp / Reddit)

**Protects:** native messaging sends via `message` / `sessions_send` (mapped to
the `comms` surface, `send` verb).

Concrete gates:

- **Non-allowlisted recipient** — when `recipient_allowlist` is set, a `send` to
  anyone **not** on it is gated (`riskSoft` → ask). Without an allowlist there's
  no unconditioned send rule (an always-ask-on-every-message pack would just be
  noise), so the allowlist inversion is the trigger.
- **Quiet hours** — a `send` whose local time falls inside the `quiet_hours`
  window is gated. Matched by the overlay time-window facet, so it's a real
  wall-clock check, not a substring.

- **Default mode:** observe.
- **Params:** `recipient_allowlist` (list), `quiet_hours` (`{start,end,days}`,
  default `23:00`–`07:00`), `channels` (list, per-channel scoping).
- **PerAgent:** lock a read-only reddit-digest agent to enforce; leave the main
  agent at ask for outbound DMs.

### 4. `dlp-guard` — Secret & PII leak prevention

**Protects:** every outbound body — a tweet, an email, a message, an API payload.
Driven by the normalizer's `Findings` (a DLP scan over the payload), so it's
surface-agnostic: it fires wherever a secret or PII marker shows up.

Concrete gates:

- **Secrets → deny (hard).** Markers: GitHub PATs (`ghp_…`), Anthropic keys
  (`sk-ant-…`), OpenAI-style keys (`sk-…`), AWS access keys (`AKIA…`), 1Password
  references (`op://…` or the literal word). Any of these in an outbound body →
  `secret:*` finding → deny.
- **PII → ask (soft).** Emails (`pii:email`) and phone numbers (`pii:phone`) →
  ask, when `ask_on_pii` is set.

The scanner is tuned for a low false-positive "don't send this outbound" signal,
not exhaustive coverage.

- **Default mode:** observe (but **promote sets it to enforce unconditionally** —
  see the learn flow above).
- **Params:** `block_secrets` (bool, true), `ask_on_pii` (bool, true).

### 5. `api-guard` — API / web egress guardrails

**Protects:** arbitrary HTTP egress via `curl` / `wget` (the `api` surface).

Concrete gates:

- **Destructive HTTP method** — `curl -X DELETE …` (also PUT/PATCH) sets the
  `delete_verb` flag → `riskHard` → deny in enforce. `curl` / `curl -X GET` (read)
  passes.
- **Host allowlist** — when `host_allowlist` is set, egress to a host **not** on
  it is gated (`riskSoft` → ask).

- **Default mode:** observe.
- **Params:** `host_allowlist` (list), `block_destructive` (bool, true).

> **Honest caveat on the host allowlist.** The overlay's `NotTargets` inversion
> only fires when the action has targets and *none* is allowlisted; a targetless
> action is never blocked. The normalizer populates `Targets` with the extracted
> **host** for curl/wget (`internal/normalize` `matchCurl`), so the host-allowlist
> rule does match on that path — but a code comment in `compile_overlay.go`
> (written when targets held the full URL) still warns it "will NOT fire." Treat
> the *destructive-verb* gate as the solid one; verify the host-allowlist path for
> your exact tool before relying on it, and prefer the CP rego's `host` facet for
> egress allowlisting on beta.

### 6. `github-guard` — GitHub / git guardrails

**Protects:** irreversible repo operations via `gh` and `git`.

Concrete gates (all on the `github` surface unless noted):

- **Force-push** — `git push --force` / `-f` / `--force-with-lease[=ref]` /
  `--force-if-includes` → `force_push` → deny (hard). Plain `git push` → `push`
  (asked, not denied, in the CP rego).
- **Repo / branch delete** — `gh repo delete …` / `gh branch delete …` →
  `repo_delete` → deny.
- **Actions / repo secret set** — `gh secret set …` → `secret_set` → deny.
- **CI workflow edit** — a command touching `.github/workflows` → `riskSoft` →
  ask. (This one is still a command-substring match; the rest are semantic verbs.)

- **Default mode:** observe.
- **Params:** none.

### 7. `infra-guard` — Infrastructure guardrails (docker / systemctl / launchctl / truenas)

**Protects:** destructive infrastructure and service-control ops.

Concrete gates:

- **Destructive flag** — `docker rm`/`rmi`/`kill`/`stop`/`prune`/`down`, or any
  `--force`/`-f`, sets the `destructive` flag; `systemctl`/`launchctl`
  `stop`/`disable`/`kill`/`unload`/`mask`/`restart` likewise. Flag present →
  `riskHard` → deny in enforce.
- **Dangerous commands** — a substring guard on the classics:
  `docker system prune`, `systemctl stop`, `systemctl disable`, `shutdown`,
  `reboot` (the CP rego extends this with `docker volume rm`, `docker rm -f`,
  `launchctl unload`, `kill -9 1`, `halt`).

- **Default mode:** observe.
- **Params:** none.

---

## Where things live

| Thing | Path |
|---|---|
| Pack schema + persistence | `internal/packs/packs.go` (`~/.aarvion/packs.json`, 0600) |
| Built-in catalog (ids, titles, default params) | `internal/packs/catalog.go` |
| Local compiler (tighten-only overlay) | `internal/packs/compile_overlay.go` |
| CP compiler (full-strength rego) | `internal/packs/compile_rego.go` |
| Learn-mode proposal | `internal/packs/propose.go` |
| Semantic normalizer + DLP | `internal/normalize/` |
| Example CP bundle | `examples/packs/governance.rego`, `examples/packs/data.json` |

Open the local console with `aarvion-guard dashboard` — the **Packs** board
toggles mode and per-agent overrides, the **Learning** panel promotes a profile,
and the **Approvals** inbox resolves any `ask` (mirrored to a Telegram DM when a
bot is configured; timeout → deny, fail-safe).

Status: designed and tested (unit + integration). The live single-box proof is
tracked separately.
