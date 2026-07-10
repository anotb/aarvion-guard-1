// Package cpsync is a best-effort client to the aarvion Control Plane for the
// local console. It is intentionally forgiving: the Control Plane may be
// unreachable, unauthenticated, or an older build that lacks the endpoints
// used here. Callers treat cpsync as an optional convenience, never a
// dependency, so most failures degrade to a benign "unknown" or ErrUnsupported
// rather than propagating.
//
// The package imports the standard library only (net/http, encoding/json) plus
// internal/overlay for the Rule type. It never panics and every request is
// bounded by a timeout.
package cpsync

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/aarvion-ai/aarvion-guard/internal/overlay"
)

// ErrUnsupported reports that the Control Plane does not expose the requested
// endpoint (typically a 404 or 405). It is a sentinel callers can test with
// errors.Is to distinguish "old/absent Control Plane" from a real failure.
var ErrUnsupported = errors.New("cpsync: endpoint not available")

// requestTimeout bounds every outbound Control Plane request.
const requestTimeout = 5 * time.Second

// Status describes how the local overlay relates to the Control Plane copy.
type Status struct {
	// State is one of: in_sync, local_ahead, cloud_ahead, unknown.
	State string `json:"state"`
	// Pending is the number of changes not yet reconciled.
	Pending int `json:"pending"`
}

// Client is a best-effort Control Plane client. The zero value is not usable;
// construct one with New.
type Client struct {
	cpURL           string
	tenant          string
	entityID        string
	enrollmentToken string
	http            *http.Client
}

// New returns a Client targeting the given Control Plane base URL for the
// (tenant, entityID) pair, authenticating with enrollmentToken. The trailing
// slash on cpURL, if any, is trimmed. New never fails and never panics.
func New(cpURL, tenant, entityID, enrollmentToken string) *Client {
	return &Client{
		cpURL:           strings.TrimRight(cpURL, "/"),
		tenant:          tenant,
		entityID:        entityID,
		enrollmentToken: enrollmentToken,
		http:            &http.Client{Timeout: requestTimeout},
	}
}

// overlayPath is the base path for this entity's overlay resource.
func (c *Client) overlayPath() string {
	return fmt.Sprintf("%s/api/v1/entities/%s/%s/overlay", c.cpURL, c.tenant, c.entityID)
}

// PushOverlay uploads the local overlay rules to the Control Plane.
//
// It POSTs {"rules":[...]} to /api/v1/entities/{tenant}/{entityID}/overlay with
// a bearer token. A 2xx response returns nil. A 404 or 405 returns
// ErrUnsupported (the Control Plane is too old or lacks the endpoint). Any
// other status, or a transport/encoding error, returns a descriptive error.
func (c *Client) PushOverlay(ctx context.Context, rules []overlay.Rule) error {
	if rules == nil {
		rules = []overlay.Rule{}
	}
	body, err := json.Marshal(struct {
		Rules []overlay.Rule `json:"rules"`
	}{Rules: rules})
	if err != nil {
		return fmt.Errorf("cpsync: marshal overlay: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.overlayPath(), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("cpsync: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.enrollmentToken)

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("cpsync: push overlay: %w", err)
	}
	defer drainClose(resp.Body)

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed:
		return ErrUnsupported
	default:
		return fmt.Errorf("cpsync: push overlay: unexpected status %d", resp.StatusCode)
	}
}

// Status queries the Control Plane for the overlay sync state.
//
// It GETs /api/v1/entities/{tenant}/{entityID}/overlay/status. Any failure
// (transport error, non-2xx status including 404, or an undecodable body)
// degrades to Status{State:"unknown"} with a nil error: sync state is
// advisory, so the caller never has to handle an error here. A decoded state
// outside the known set is normalized to "unknown".
func (c *Client) Status(ctx context.Context) (Status, error) {
	unknown := Status{State: "unknown"}

	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.overlayPath()+"/status", nil)
	if err != nil {
		return unknown, nil
	}
	req.Header.Set("Authorization", "Bearer "+c.enrollmentToken)

	resp, err := c.http.Do(req)
	if err != nil {
		return unknown, nil
	}
	defer drainClose(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return unknown, nil
	}

	var s Status
	if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
		return unknown, nil
	}
	if !validState(s.State) {
		s.State = "unknown"
	}
	return s, nil
}

// DeviceLogin performs a forward-looking OAuth-style device authorization
// against the OpenClaw endpoint. It POSTs to /api/openclaw/device/code to
// obtain a device/user code, then polls the token endpoint until the user
// approves.
//
// This targets an endpoint that current Control Plane builds may not expose; if
// the initial request 404s/405s (or the endpoint is otherwise absent), it
// returns ErrUnsupported. The implementation is deliberately minimal: it is a
// placeholder for a flow that will be fleshed out once the server side lands.
func (c *Client) DeviceLogin(ctx context.Context) (token, verificationURL string, err error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cpURL+"/api/openclaw/device/code", nil)
	if err != nil {
		return "", "", fmt.Errorf("cpsync: build device request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.enrollmentToken)

	resp, err := c.http.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("cpsync: device login: %w", err)
	}
	defer drainClose(resp.Body)

	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed {
		return "", "", ErrUnsupported
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", "", fmt.Errorf("cpsync: device login: unexpected status %d", resp.StatusCode)
	}

	var dc struct {
		DeviceCode      string `json:"device_code"`
		VerificationURL string `json:"verification_uri"`
		AccessToken     string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&dc); err != nil {
		return "", "", fmt.Errorf("cpsync: decode device response: %w", err)
	}
	// If the server short-circuits and returns a token immediately, use it.
	// Otherwise return the verification URL so the caller can direct the user;
	// full polling is left for when the server contract is finalized.
	return dc.AccessToken, dc.VerificationURL, nil
}

// validState reports whether s is a recognized Status.State value.
func validState(s string) bool {
	switch s {
	case "in_sync", "local_ahead", "cloud_ahead", "unknown":
		return true
	default:
		return false
	}
}

// drainClose drains and closes a response body so the underlying connection can
// be reused. Errors are ignored: this is best-effort cleanup.
func drainClose(body io.ReadCloser) {
	_, _ = io.Copy(io.Discard, body)
	_ = body.Close()
}
