# aarvion-guard — Roadmap & Backlog

> Working backlog for turning aarvion-guard from a network egress filter into a real **OpenClaw governance product**.
> Produced 2026-07-08 from: a full source review (31-agent adversarial pass, live e2e against the real v0.2.6 binary) + a 10-agent product-thinking pass grounded in a live recon of the mac-mini OpenClaw instance.
> Companion review page: https://claude.ai/code/artifact/b4150757-5061-4e0c-a764-607a4410ee46

---

## The thesis (read this first)

Today aarvion-guard is a **network egress filter**: it allows/denies by method + host + path + body, request-only, one nameless egress identity per box.

The real OpenClaw it governs is a **personal agent platform**: ~7 agents (one posts to X *as the user*, one reads Reddit, others run shell), ~41 action skills (Home Assistant locks/alarms/cameras, 1Password vault, Twitter/Discord/Telegram/Gmail sends, TrueNAS, Dockge/Docker control), ~30 homelab + SaaS integrations, ~40 plaintext secrets on the box, and **unattended** cron + Gmail-hook runs firing all night on attacker-influencable input.

So the product isn't "GitHub read-only." It's an **agent-action firewall**. And almost everything that makes it one hangs on a single missing seam:

> ### 🔑 THE KEYSTONE: caller identity
> The guard cannot see *which* of the 7 agents / *what* session / *how-trusted* a context made a call. The decision schema already **reserves** `caller_principal_id / caller_session_id / caller_source` and always writes `nil`. About **two-thirds of every item below is unenforceable until this lands.** Build it first.
> - **P0 · capability** — Propagate an agent/session/trust triple from OpenClaw into each egress request and thread it into OPA input + the hash chain.
> - **P0 · capability** — Identity *source* on macOS forward-proxy (no Linux group-match here): give each agent its own local proxy listener port, or a per-agent proxy-auth credential the guard reads. Cheapest viable binding.
> - Needs an OpenClaw-side contribution (stamp identity per outbound call) + guard-side plumbing. This is a joint gateway↔guard change; scope it with the moltbot team.

---

## Part 1 — Product roadmap (three waves, gated on the keystone)

### Wave 0 — unblock + honesty
The advisory-proxy-guarding-exfilable-secrets-on-the-same-box problem. Ship these before any fancy policy.
- [ ] **Caller identity** (the keystone above) — per-agent listener ports on macOS + populate `caller_*` into OPA input and decisions.
- [ ] **Bypass DETECTION** (not just prevention) — an out-of-band egress reconciler (launchd/eBPF-ish sampler + a heartbeat field) that flags traffic leaving the box *outside* the proxy. Every policy is advisory until macOS transparent mode ships; make "is governance actually on?" an observable signal instead of an assumption. *(critic-flagged, missing from the domain passes)*
- [ ] **Guard-as-target hardening** — the guard holds a machine-trusted CA key (mints a leaf for ANY host) + `guard.json` enrollment creds on the same box the agent can read. Lock `ca.key` + `guard.json` down from the agent principal (keychain/keyring, not a flat 0600 file), and threat-model the new inbound control channel *before* adding kill-switch/HITL. *(critic-flagged)*

### Wave 1 — cheap, high-leverage, mostly pure Rego once identity lands
- [ ] **Flip to default-deny allowlist**, seeded from the CP's existing decision corpus, behind a **2-week observe/learn flag** (log `would_deny`, `enforced=false`) so unattended cron/Gmail runs don't get black-holed cold. `Record.Enforced` already exists.
- [ ] **IP-literal-to-public-IP = deny + alert** (`CONNECT 185.x.x.x:443` with no allowlisted SNI is the canonical exfil shape; `192.168.1.x` literals stay fine).
- [ ] **Home Assistant fail-CLOSED classifier** — path/body rules for `lock.unlock` / `alarm_control_panel.disarm`; **never** put `192.168.1.10` on the fail-open essential list. (Honestly scope the WebSocket dependency — HA's real interface is WS `call_service`, not just REST.)
- [ ] **Deny-by-default on the Docker/host control plane** — Dockge + Crafty have no legitimate unattended use and the highest homelab blast radius.
- [ ] **Close the two silent bypasses that make body policy fake**: (1) actually strip/block on redaction instead of just relaying OPA's `x-aarvion-redactions`; (2) fail-CLOSED on oversized bodies for write/delete methods (today `maxBodyPeek` hard-*allows* a >1MB body past inspection).
- [ ] **In-guard rate + daily-USD budget accumulator that works when OPA is down** — closes the essential-host fail-OPEN "untethered spend" hole; persist like `chain.json`.

### Wave 2 — the one genuinely new capability everything ambitious needs
- [ ] **"ask" as a first-class third OPA verdict** (allow / deny / **ask**) — the guard must be able to **park** an in-flight request, fan an approval prompt to the owner over their *own* Telegram (id `6575353438`) / Discord / dashboard, and resume-or-timeout on the reply. This turns "deny" into "ask me," and is the load-bearing capability under every HITL item in every domain.
- [ ] **Response inspection** — today `serve()` `io.Copy`s the response straight back. Needed for: spend metering (read token counts out of LLM responses), secret-egress correlation (read-here-ship-there taint), DLP on inbound content, and HA state-awareness rules.
- [ ] **Bidirectional control channel** — the heartbeat is fire-and-forget; make its response carry signed commands (kill-switch / freeze-one-agent / budget-lift / break-glass token).

---

## Part 2 — Governance policy packs for *this* instance
The "what else needs governing" catalog. Each is a shippable policy pack keyed to the real hosts/agents. Most are pure Rego *once identity + the Wave-1 primitives land*.

### Egress reachability
- [ ] Three tiers with different handling: **known-homelab** (`192.168.1.0/24` on observed ports → allow silent, sampled) · **known-SaaS** (`api.x.com`, `api.anthropic.com`, `generativelanguage.googleapis.com`, `gmail.googleapis.com`, `discord.com`, `maps.googleapis.com`, `api.minimax.chat` → allow but scope method/path) · **novel** (first-seen anything → deny + immediate un-sampled owner push).
- [ ] Scope homelab allows to CIDR **+ port** (needs the CONNECT port in OPA input; `StripPort` drops it today) so a novel port on `192.168.1.10` isn't trusted just for being "internal."
- [ ] Make the fail-open essential list a **governed bundle value**, not a hardcoded Go slice, and add Bedrock/Vertex/Azure-OpenAI/Mistral/self-hosted wildcards.

### Destructive / state-changing actions (per homelab service)
- [ ] Separate read / write / delete per service: **n8n** (freeze workflow-mutation + execution-trigger endpoints) · **NocoDB / TrueNAS** (split row-write from schema-destroy / dataset-destroy) · **Karakeep / Maintainerr** (protect bulk-delete + rule-purge) · **Metube / Lazylibrarian / book-downloader** (allow enqueue, gate delete/purge).
- [ ] **Approval-pending** verdict for high-blast-radius writes (rides the "ask" capability + the existing `HTTPStatus` channel).

### Outbound comms & "acting as you"
- [ ] **Approve-before-send** for identity-visible posts (X, Gmail, DMs) — draft-and-confirm as the default send UX.
- [ ] **Per-agent send-capability allowlist** (least privilege across 41 skills: `reddit-digest` never sends; `llm-twitter` posts only to X `POST /2/tweets`-shaped paths).
- [ ] **Recipient allowlist** for DMs/email; **rate + burst caps** per channel per agent; **quiet hours** for autonomous sends; content/injection-signature policy on send bodies.

### Secrets & DLP
- [ ] **Secret-pattern detector** as a guard-native prefilter (exact-value hash set built from the service-env + regex classes) — don't make OPA regex bodies.
- [ ] **1Password egress governance** — which agent, which vault item, how often.
- [ ] **Secret-to-novel-host correlation** (read here, ship there) — needs response inspection + per-session taint.
- [ ] **Per-secret-class destination scoping** — homelab creds never leave `192.168.1.x`.
- [ ] Keep MITM inspection ON for OpenAI/Anthropic bodies (decouple "fail-closed essential" from "inspection-exempt").

### Physical / home safety
- [ ] Deny lock-unlock / alarm-disarm on **unattended** (cron + gmail-hook) runs; never-disarm-while-armed-away irreversibility floor; time-of-day rules; camera-feed egress kept on-LAN; per-agent HA scoping (twitter/reddit agents have no business touching locks).

### Spend & rate
- [ ] Sliding-window request-rate ceilings per billed host; token-usage metering from LLM response bodies; hard daily/monthly USD cap with fail-closed kill-switch; per-provider ceilings; loop/repetition anomaly detector (reuse `decisions.sampled[]` as a frequency signal); proactive spend alerts to the owner's channels.

### Autonomy & trust context
- [ ] Trust-level tag per inbound origin (owner-DM vs group vs cron vs gmail-hook) threaded into OPA input; stricter posture for unattended runs (no actuator writes, no secret egress); per-agent capability scoping keyed on `caller_principal_id`; session-scoped anomaly braking.

---

## Part 3 — UX & functionality
- [ ] **Observe/Learn mode** → after N days, auto-propose an allowlist + write-endpoint map from recorded decisions (the corpus already exists in `decisions.Recorder` + CP). This is the adoption unlock for a single-owner box with no staging.
- [ ] **Inline approval** over Telegram/Discord/dashboard: allow / deny / and-reason, with unattended-timeout handling.
- [ ] **Policy template catalog**: read-only-github, no-social-without-approval, HA-safety-lock, secret-exfil-block, LLM-spend-cap — authored against this instance's real hosts.
- [ ] **Natural-language → Rego** authoring with a dry-run preview (use the owner's own Anthropic key CP-side) + a Rego linter.
- [ ] **Dry-run / simulation**: "what would this policy have denied last week" against stored decision rows.
- [ ] **Dashboard**: live decision feed filterable by agent/service/decision (denies pinned); "morning check" summary; new-destination + deny-spike alerts; incident timeline reconstruction from the hash chain; guard-health/bypass panel ("is governance actually on?").
- [ ] **SIEM / webhook / syslog export** of the decision stream (CP-side fan-out, no guard change).
- [ ] **Kill-switch / break-glass** from the dashboard (freeze all egress or one agent).

---

## Part 4 — Missing domains the critic flagged (don't skip)
- [ ] **Guard-as-target** — the guard's CA key + creds are a prize on the box they protect. (See Wave 0.)
- [ ] **Bypass detection as a standing signal** — stop deferring the whole trust story to the unshipped macOS system extension. (See Wave 0.)
- [ ] **WebSocket / long-lived-stream governance** — HA's and n8n's real programmatic surface is WS, not REST; the physical-safety + lateral-movement paths run over frames the guard doesn't parse today.
- [ ] **DNS-layer governance** — the whole allowlist stands on a resolver/hosts trust root the guard never validates.
- [ ] **Cross-agent confused-deputy chaining** — once identity exists, the read-then-write pivot *across* agents/skills is sharper than the per-session taint item covers.
- [ ] **HITL under alert fatigue / asleep owner** — six domains converge on "ask the owner over Telegram"; scope what happens when that channel is saturated, spoofed, or unanswered (safe-default on timeout, dedupe, escalation).

---

## Part 5 — Code-correctness & security backlog (from the source review)
23 confirmed defects (adversarially verified, severity-corrected). Full detail + repro in the review artifact.

### High
- [ ] **Host-spoof** (`mitm.go:96`) — policy keyed on the agent-controlled inner `Host`, not SNI/dial target. Split SNI-from-Host defeats domain allowlisting and falsifies the audit chain. Plain-HTTP path has no upstream cert check at all. *(the headline security bug; several Part-1 items assume this is fixed)*
- [ ] **Transparent mode redirects only TCP 80/443** (`intercept/linux.go:51`) — QUIC/UDP/alt-port TCP escape; no default-deny.
- [ ] **Unauthenticated proxy + poisonable `block`/`learn` maps** (`proxy.go:72`) — any local process can DoS allowed hosts or force-downgrade an essential host to a raw uninspected tunnel.
- [ ] **Essential fail-open keyed on spoofable Host during OPA outage** (`mitm.go:79`) — self-masking exfil; agent can induce the outage.
- [ ] **Unbounded decision queue → OOM** on CP outage (`decisions.go:242`).
- [ ] **`flush` treats non-2xx as success** (`decisions.go:246`) — drops decisions + permanently corrupts the persisted hash-chain cursor across restarts.
- [ ] **`update` installs an unverified downloaded binary as the boot service** (`main.go:433`).

### Medium
- [ ] 5-year system-trusted CA with no NameConstraints (`ca.go:64`) · unbounded leaf cache (`ca.go:146`) · OPA binary downloaded+run with no checksum pin by default (`opa.go:116`) · npm shim checks content-length not sha256 (`aarvion-guard.js:62`) · `curl|sh` verifies nothing (`install.sh:31`) · Linux releases unsigned, checksum manifest unsigned (`release.yml:31`) · WebSocket over plain-HTTP forward path dies after 101 (`proxy.go:185`) · SNI-less/IP-literal TLS silently dropped in transparent mode (`ca.go:116`).

### Low
- [ ] Hop-by-hop headers forwarded on plain-HTTP path (`proxy.go:185`) · MITM http/1.1-only breaks h2-only endpoints (`mitm.go:51`) · collapsed-allow counts discarded, audit undercounts allow volume (`decisions.go:152`) · OPA supervisor no restart cap / no health in heartbeat (`opa.go:158`) · transparent loopback carve-out escape (`linux.go:45`) · Homebrew formula placeholders + v0.1.0 (`aarvion-guard.rb:14`) · fixed `.tmp` download race (`opa.go:97`).

### Found while testing (not in the static review)
- [ ] **🔴 SHIP-BLOCKER: OPA can't self-provision on Apple Silicon** (`opa.go` `downloadURL`) — for `darwin/arm64` the guard requests `opa_darwin_arm64`, which **404s**; the real asset is `opa_darwin_arm64_static`. Confirmed live on the mini: a fresh `run` dies with `opa download ... 404 Not Found`. macOS is forward-proxy-only and the primary target, so the default install is broken for every M-series Mac until a manual OPA is dropped in. Fix the asset name (and bake in the checksum while you're there).
- [ ] **OPA version skew** — `Binary()` prefers any `opa` on `PATH` over the pinned 0.68.0; my box ran brew's 1.18.1. Guard evaluates policy on a different engine than the bundle was validated against. Pin/verify the managed copy and prefer it.
- [ ] **Onboarding doc is wrong** — step 1 is documented as `npx @aarvionai/guard run`, but `run` needs an existing paired config. Real first step is `init <code>`.
- [ ] **`NODE_EXTRA_CA_CERTS` clobber** — `InjectProxy` overwrites it; the mac-mini gateway already sets it to `/etc/ssl/cert.pem`. Merge, don't overwrite (drops custom roots otherwise).

---

## Live real-traffic test (2026-07-08, real `openclaw agent` turns through the guard)
Paired the mini (`--no-inspect`, entity `agt_KpaiaIFJbsBSHr5r6DPsPQ`), enabled OPA decision logs, and ran real embedded-agent turns. The guard governed **96 real egress requests, 0 denied**: `chatgpt.com` ×89 (the model), `github.com` ×5, Home Assistant `GET 192.168.1.10/api/states`, Karakeep `GET 192.168.1.4/api/v1/bookmarks`.

- ✅ **Proxy-honoring works** — moltbot routes its egress through the injected proxy. The forward-proxy premise holds for OpenClaw.
- [ ] **🔴🔴 CRUX BUG: inspect (MITM) mode BREAKS OpenClaw — proven live.** Flipped the mini to `inspect=true`; both real agent turns died with `stream disconnected before completion: error sending request for url (https://chatgpt.com...)`. Guard log: `chatgpt.com rejected inspection (EOF); BLOCKING` and `github.com rejected inspection (remote error: tls: unknown certificate authority); BLOCKING`. **OpenClaw's own HTTP clients reject the guard's MITM cert.** A standalone Node `fetch` trusted the merged CA bundle fine, but the agent's *model* client (the `error sending request for url` / `stream disconnected` phrasing is Rust `reqwest`/`rustls`) uses a **bundled trust store that ignores `NODE_EXTRA_CA_CERTS` and the OS keychain** — you cannot make it trust a MITM CA via env vars. The guard then fail-closes rejected-inspection non-essential hosts → blocks → agent dead. This is the product's central dilemma, demonstrated: **no-inspect = catalog inert for HTTPS; inspect = agent breaks.** Fixes to explore: OpenClaw-side CA config for every embedded client (rustls needs an explicit root, not env), per-client transparent interception, or accept passthrough for native-client hosts (and lose inspection there). Until resolved, the vendor catalog cannot govern OpenClaw's HTTPS traffic without killing it.
- [ ] Related: on rejected inspection the guard **blocks** non-essential hosts, converting "client doesn't trust our CA" into "agent is dead." That failure mode is too blunt — at minimum it should be observable and the model/tool hosts auto-passthrough'd rather than hard-blocked.
- [ ] `sudo security add-trusted-cert` to the System keychain **fails over SSH/headless** ("no user interaction possible"), so `init --inspect` can't self-install CA trust on a headless mac-mini server anyway.
- [ ] **🔴 No-inspect macOS forward mode is host-level-blind for HTTPS → the entire method/path policy catalog is inert.** Real HTTPS traffic reaches OPA as `CONNECT <host> /` (method+path hidden in TLS). All 5 real `github.com` hits were `CONNECT`, so the *enabled* GitHub-read-only rule (which keys on method+path) can never fire on real traffic — it only "worked" in my probe because I hand-fed `method=DELETE`. Every vendor pack (M365 mail.send, Stripe, AWS, Slack…) is silently unenforceable without MITM `inspect`, which on macOS needs the CA install (sudo + the NODE_EXTRA_CA_CERTS clobber). Only cleartext http (the homelab: HA, Karakeep on 192.168.1.x) surfaced method/path. **This is the single biggest "it looks governed but isn't" gap.**
- [ ] **Model endpoint is `chatgpt.com` (OAuth auth-profile), not `api.openai.com`** → not in the hardcoded essential-hosts, so an OPA outage would fail-closed this agent's actual brain. Confirms the "essential hosts must be configurable + match reality" item.
- [ ] **Policy catalog is broad but enterprise-SaaS-shaped, and mostly disabled for this instance.** 27 packs ship (`policy/starter/*`): GitHub, M365, Google Workspace, AWS, Cloudflare, Stripe, Slack, Discord, Telegram, WhatsApp, Reddit, email/ESP + cross-cutting (secrets-exfil, pii-at-llm-boundary, egress-allowlist, prod-blast-radius, rate-cap, owasp-llm-top10) + compliance (eu-ai-act, gdpr, irdai, bfsi). But **only GitHub-read-only is enabled**, and there is **no Home Assistant / Hue / Sonos / homelab / 1Password / iMessage pack at all** — exactly the surface that dominates this instance. Live probes: `POST 192.168.1.10/api/services/lock/unlock` → allowed, `POST api.x.com/2/tweets` → allowed, `pastebin.com`/`evil-exfil.example.com` → allowed. The catalog needs a **personal-agent-platform pack family** (home/IoT, homelab, secrets, acting-as-you) and the egress-allowlist pack turned on.

## Appendix — evidence & status
- **Live e2e (passed):** real v0.2.6 binary in forward+inspect governed real GitHub — `GET /zen` → 200 allow, `DELETE` → 403 deny *inside* the TLS tunnel; fail-closed proven by SIGSTOP-ing OPA (non-essential → 503, essential Anthropic → reached); 5 decisions pushed to a stand-in CP with an intact hash chain (`prev_hash` == prior `row_hash`). `go vet` clean, `go test -race` passes.
- **Test coverage gap:** only `decisions`, `mitm`, `proxy` have tests; `ca`, `policy`, `opa`, `wiring`, `intercept`, `tproxy`, `svc`, `trust`, `pair`, `heartbeat` have none.
- **Live pairing on the mini (DONE — verified against the real beta backend):** paired entity `agt_EZI66GrMg5Wy4MGI9gBRJg` (tenant `aarvion-ai`, cp `cp-beta.aarvion.ai`) in `--no-inspect` mode; hit the OPA-arm64 404 above, dropped in the correct pinned OPA, guard pulled the org's signed bundle (host-level), drove 6 synthetic requests → **fleet dashboard showed the DP ONLINE 1/1, 6 decisions forwarded, 0 denies, 0 errors.** Then fully torn down: `~/.aarvion` removed, gateway env restored (0 aarvion lines), no residual process. Entity + 6 decisions persist in the dashboard as a record. Observed: current org policy is permissive (allowed `pastebin.com`, `httpbin.org`, etc. at host level) — the live case for the default-deny + novel-host P0 items. `moltbot` gateway (`~/Projects/openclaw/moltbot`, `:18789`) was never wired or restarted.
