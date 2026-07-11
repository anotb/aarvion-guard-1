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
	// Verdict is an optional policy-supplied override ("ask"|"redact") carried in
	// the x-aarvion-verdict header. Empty means the verdict follows Allowed
	// (allow/deny). Only the govern PDP path acts on it.
	Verdict string
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
			"attributes": httpAttributes(method, host, path, body, headers),
		},
	}
	return c.eval(ctx, input)
}

// GovernEval asks OPA to decide a runtime PDP request. It POSTs the full extended
// input (ctx/caller/action plus the same attributes.request.http block Eval
// sends) to the same entrypoint. OPA ignores unknown input fields, so existing
// packs keep matching on the http block while caller/action become available for
// future packs. The verdict maps allowed->allow, else deny.
func (c *Client) GovernEval(ctx context.Context, input GovernInput) (*Decision, error) {
	return c.eval(ctx, map[string]any{"input": input})
}

// GovernInput is the extended PDP evaluation input. The govern server builds it
// from the incoming request; only attributes.request.http is consumed by today's
// packs, the rest is forward-looking context.
type GovernInput struct {
	ContractVersion string         `json:"contract_version,omitempty"`
	Ctx             map[string]any `json:"ctx,omitempty"`
	Action          map[string]any `json:"action,omitempty"`
	Attributes      map[string]any `json:"attributes,omitempty"`
	// Mcp is the normalized mcp-norm/v1 block the control plane's rule-builder
	// conditions (mcp_tool/mcp_side_effects/mcp_caller_source/...) evaluate, so a
	// CP-authored policy governs the guard's PDP actions, not just egress.
	Mcp map[string]any `json:"mcp,omitempty"`
}

// HTTPAttributes builds the attributes.request.http block shared by Eval and
// GovernEval, so both paths present OPA an identical http shape.
func HTTPAttributes(method, host, path, body string, headers map[string]string) map[string]any {
	return httpAttributes(method, host, path, body, headers)
}

func httpAttributes(method, host, path, body string, headers map[string]string) map[string]any {
	return map[string]any{
		"request": map[string]any{
			"http": map[string]any{
				"method":  method,
				"host":    host,
				"path":    path,
				"body":    body,
				"headers": headers,
			},
		},
	}
}

// eval marshals input, POSTs it to the shared entrypoint, and decodes the common
// result.{allowed,http_status,headers} shape into a Decision.
func (c *Client) eval(ctx context.Context, input map[string]any) (*Decision, error) {
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
		Verdict:    out.Result.Headers["x-aarvion-verdict"],
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
