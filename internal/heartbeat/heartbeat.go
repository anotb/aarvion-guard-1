package heartbeat

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// StatSource yields the running decision counters for each beat.
type StatSource interface {
	Stats() (total, denies, errors, dropped int)
}

type Sender struct {
	cpURL    string
	tenant   string
	entityID string
	token    string
	dpID     string
	mode     string
	stats    StatSource
}

func New(cpURL, tenant, entityID, token, dpID, mode string, stats StatSource) *Sender {
	return &Sender{cpURL: cpURL, tenant: tenant, entityID: entityID, token: token, dpID: dpID, mode: mode, stats: stats}
}

// Run beats on an interval until ctx ends. The first beat is what flips the
// entity to online in the dashboard.
func (s *Sender) Run(ctx context.Context, interval time.Duration) {
	s.beat(ctx)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.beat(ctx)
		}
	}
}

func (s *Sender) beat(ctx context.Context) {
	total, denies, errs, dropped := s.stats.Stats()
	payload := map[string]any{
		"tenant":          s.tenant,
		"agent_id":        s.entityID,
		"dp_id":           s.dpID,
		"decisions_total": total,
		"denies_total":    denies,
		"errors_total":    errs,
		"dropped_total":   dropped,
		"metadata":        map[string]any{"role": "guard", "mode": s.mode},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cpURL+"/api/v1/fleet/heartbeat", bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.token)

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		fmt.Printf("[heartbeat] %v\n", err)
		return
	}
	resp.Body.Close()
}
