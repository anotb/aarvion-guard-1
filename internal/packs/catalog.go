package packs

// Catalog returns the seven built-in guardrail packs with stable ids, human
// titles, and their default Params. Every pack defaults to ModeObserve: the
// first run is a learn posture that records what enforcement would do without
// changing outcomes, so an operator sees behaviour before turning gates on.
//
// The returned Set of packs is freshly allocated on each call; callers may
// mutate it freely.
func Catalog() []Pack {
	return []Pack{
		{
			ID:    "social-guard",
			Title: "Social media (Twitter/X) guardrails",
			Mode:  ModeObserve,
			Params: map[string]any{
				"accounts":   []any{},
				"allow_read": true,
			},
		},
		{
			ID:    "google-guard",
			Title: "Google / Gmail / Drive guardrails",
			Mode:  ModeObserve,
			Params: map[string]any{
				"contact_allowlist":   []any{},
				"allow_calendar_read": true,
			},
		},
		{
			ID:    "comms-guard",
			Title: "Messaging guardrails (Telegram/Discord/WhatsApp/Reddit)",
			Mode:  ModeObserve,
			Params: map[string]any{
				"recipient_allowlist": []any{},
				"quiet_hours": map[string]any{
					"start": "23:00",
					"end":   "07:00",
					"days":  []any{},
				},
				"channels": []any{},
			},
		},
		{
			ID:    "dlp-guard",
			Title: "Secret & PII leak prevention",
			Mode:  ModeObserve,
			Params: map[string]any{
				"block_secrets": true,
				"ask_on_pii":    true,
			},
		},
		{
			ID:    "api-guard",
			Title: "API / web egress guardrails",
			Mode:  ModeObserve,
			Params: map[string]any{
				"host_allowlist":    []any{},
				"block_destructive": true,
			},
		},
		{
			ID:     "github-guard",
			Title:  "GitHub / git guardrails",
			Mode:   ModeObserve,
			Params: map[string]any{},
		},
		{
			ID:     "infra-guard",
			Title:  "Infrastructure guardrails (docker/systemctl/truenas)",
			Mode:   ModeObserve,
			Params: map[string]any{},
		},
	}
}
