package govern

// Verdicts the PDP can return. This phase enforces only allow/deny; redact and
// ask may be returned by policy and are plumbed through the response, but the
// server does not itself enforce them.
const (
	VerdictAllow  = "allow"
	VerdictDeny   = "deny"
	VerdictRedact = "redact"
	VerdictAsk    = "ask"
)

// Request is the contract_version "1" decision request a PEP sends over the
// socket. Only attributes.request.http is consumed by today's OPA packs; the
// ctx/action context is forward-looking and passed through to OPA unchanged.
type Request struct {
	ContractVersion string     `json:"contract_version"`
	Nonce           string     `json:"nonce"`
	Ctx             Ctx        `json:"ctx"`
	Action          Action     `json:"action"`
	Attributes      Attributes `json:"attributes"`
}

// Ctx is the calling context: which surface/phase the action is on and who is
// asking.
type Ctx struct {
	Surface string `json:"surface"` // exec|tool|mcp|egress|send|response
	Phase   string `json:"phase"`   // pre|post
	Caller  Caller `json:"caller"`
}

// Caller identifies the principal and session behind the request.
type Caller struct {
	PrincipalID string `json:"principal_id"`
	SessionID   string `json:"session_id"`
	Source      string `json:"source"`
	Trust       string `json:"trust"`
	RunID       string `json:"run_id"`
	Tool        string `json:"tool"`
}

// Action describes the concrete operation being requested.
type Action struct {
	Tool       string `json:"tool"`
	Operation  string `json:"operation"`
	Args       any    `json:"args"`
	ArgsDigest string `json:"args_digest"`
}

// Attributes carries the request attributes, mirroring the Envoy ext_authz shape
// so the same OPA packs match on attributes.request.http.
type Attributes struct {
	Request AttributesRequest `json:"request"`
}

type AttributesRequest struct {
	HTTP HTTP `json:"http"`
}

// HTTP is the request line + headers/body the policy inspects.
type HTTP struct {
	Method  string            `json:"method"`
	Host    string            `json:"host"`
	Path    string            `json:"path"`
	Body    string            `json:"body"`
	Headers map[string]string `json:"headers"`
}

// Response is the PDP verdict returned to the PEP. The nonce is echoed so the
// PEP can correlate. redactions/obligations/ask are plumbed but not enforced in
// this phase.
type Response struct {
	DecisionID  string   `json:"decision_id"`
	Nonce       string   `json:"nonce"`
	Verdict     string   `json:"verdict"`
	HTTPStatus  int      `json:"http_status"`
	PolicyID    string   `json:"policy_id,omitempty"`
	Reason      string   `json:"reason,omitempty"`
	Redactions  string   `json:"redactions,omitempty"`
	Obligations []string `json:"obligations,omitempty"`
	Ask         *Ask     `json:"ask,omitempty"`
	TTLMs       int      `json:"ttl_ms,omitempty"`
}

// Ask carries a human-in-the-loop prompt when policy returns the "ask" verdict.
// Reserved for a later phase; the server never populates it today.
type Ask struct {
	Prompt string `json:"prompt,omitempty"`
}

// Approver is the human-in-the-loop hook behind an "ask" verdict. When the PDP's
// final verdict is ask and an Approver is configured, decide() mints the
// decision_id, calls Open with it (so the owner is notified over Telegram and the
// pending shows in the console inbox), and returns ask + that id to the PEP
// immediately - it never blocks on the human. The PEP then polls
// GET /v1/approvals/{id}, whose handler answers from Status. A nil Approver keeps
// today's behaviour: ask is returned but no pending is opened. See
// internal/approve.Manager for the concrete implementation.
type Approver interface {
	// Open registers a pending approval for req.DecisionID. It must not block.
	Open(req ApprovalRequest)
	// Status reports the current verdict for id ("pending"|"allow"|"deny") and
	// whether the id is known. An unknown id returns ("", false).
	Status(id string) (verdict string, ok bool)
}

// ApprovalRequest describes an action awaiting owner approval. DecisionID is the
// PDP-minted id the PEP polls on; the rest is the semantic summary the owner sees
// (which agent, what surface/verb, and why the policy escalated).
type ApprovalRequest struct {
	DecisionID string
	Principal  string
	Surface    string
	Verb       string
	Reason     string
}
