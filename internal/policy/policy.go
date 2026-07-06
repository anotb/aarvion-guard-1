package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const entrypoint = "/v1/data/envoy/authz/allow"

// Decision is the guard's read of an OPA verdict for one egress request.
type Decision struct {
	Allowed    bool
	HTTPStatus int
	PolicyID   string
	Reason     string
	Redactions string
	Enforced   bool
}

type Client struct {
	base string
	http *http.Client
}

func New(opaAddr string) *Client {
	return &Client{
		base: "http://" + opaAddr,
		http: &http.Client{Timeout: 5 * time.Second},
	}
}

// Eval asks OPA whether an egress request is allowed. The input mirrors the
// Envoy ext_authz shape the production data plane uses, so the same bundle
// evaluates unchanged.
func (c *Client) Eval(ctx context.Context, method, host, path, body string, headers map[string]string) (*Decision, error) {
	input := map[string]any{
		"input": map[string]any{
			"attributes": map[string]any{
				"request": map[string]any{
					"http": map[string]any{
						"method":  method,
						"host":    host,
						"path":    path,
						"body":    body,
						"headers": headers,
					},
				},
			},
		},
	}
	payload, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+entrypoint, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("opa returned %d", resp.StatusCode)
	}

	var out struct {
		Result struct {
			Allowed    bool              `json:"allowed"`
			HTTPStatus int               `json:"http_status"`
			Headers    map[string]string `json:"headers"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}

	d := &Decision{
		Allowed:    out.Result.Allowed,
		HTTPStatus: out.Result.HTTPStatus,
		PolicyID:   out.Result.Headers["x-policy-violated"],
		Reason:     out.Result.Headers["x-policy-reason"],
		Redactions: out.Result.Headers["x-aarvion-redactions"],
		Enforced:   out.Result.Headers["x-aarvion-enforced"] != "false",
	}
	if d.HTTPStatus == 0 {
		if d.Allowed {
			d.HTTPStatus = http.StatusOK
		} else {
			d.HTTPStatus = http.StatusForbidden
		}
	}
	return d, nil
}

// Healthy reports whether OPA is up and answering.
func (c *Client) Healthy(ctx context.Context) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/health", nil)
	if err != nil {
		return false
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}
