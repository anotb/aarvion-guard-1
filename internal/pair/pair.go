package pair

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Creds is the pairing result the backend returns from /api/openclaw/pair/claim.
type Creds struct {
	Tenant          string `json:"tenant"`
	EntityID        string `json:"entity_id"`
	CPUrl           string `json:"cp_url"`
	EnrollmentToken string `json:"enrollment_token"`
	SigningSecret   string `json:"signing_secret"`
	BundleURL       string `json:"bundle_url"`
}

type claimReq struct {
	Code       string `json:"code"`
	DeviceName string `json:"device_name,omitempty"`
}

// Claim exchanges a one-time pairing code for enrollment credentials. apiURL is
// the Aarvion backend base (e.g. https://api.aarvion.ai), not the control plane.
func Claim(ctx context.Context, apiURL, code, deviceName string) (*Creds, error) {
	body, err := json.Marshal(claimReq{Code: code, DeviceName: deviceName})
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL+"/api/openclaw/pair/claim", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pairing failed (%d): %s", resp.StatusCode, string(raw))
	}

	var creds Creds
	if err := json.Unmarshal(raw, &creds); err != nil {
		return nil, fmt.Errorf("unreadable pairing response: %w", err)
	}
	if creds.EntityID == "" || creds.EnrollmentToken == "" {
		return nil, fmt.Errorf("pairing response missing credentials")
	}
	return &creds, nil
}
