package approve

import (
	"time"

	"github.com/aarvion-ai/aarvion-guard/internal/govern"
)

// defaultTTL bounds how long a pending stays open before the reaper denies it
// (fail-safe) when the caller supplies no positive TTL. Human approval should
// arrive well inside two minutes; past it, the safe answer is deny.
const defaultTTL = 120 * time.Second

// Manager is the single approval hub wired into both the PDP and the console. It
// wraps the pending Store and an optional Telegram client so:
//
//   - it satisfies govern.Approver (Open + Status): the PDP opens a pending on an
//     `ask` verdict and the GET /v1/approvals/{id} route reads Status;
//   - it satisfies the console's approvals surface (List + Resolve): the inbox
//     lists pendings and resolving one flips the same Store the PEP polls.
//
// On Open it registers the pending and, when Telegram is configured, notifies the
// owner off the decision path (a goroutine) so the PDP returns `ask` immediately
// even if the Bot API is slow. A resolution from EITHER channel (a Telegram tap
// via Telegram.Poll → Resolve, or a console POST → Resolve) is the same Store
// write, so both surfaces stay consistent and exactly one resolution wins.
type Manager struct {
	store    *Store
	telegram *Telegram
	ttl      time.Duration
}

// NewManager builds a Manager over store, notifying tg on Open when non-nil.
// ttl is the pending lifetime stamped on each opened Pending; a non-positive ttl
// falls back to defaultTTL. store must be non-nil.
func NewManager(store *Store, tg *Telegram, ttl time.Duration) *Manager {
	if ttl <= 0 {
		ttl = defaultTTL
	}
	return &Manager{store: store, telegram: tg, ttl: ttl}
}

// Open implements govern.Approver: it turns the PDP's ApprovalRequest into a
// Pending (stamped now + the Manager's TTL), registers it, and notifies Telegram
// off the hot path. It never blocks the caller.
func (m *Manager) Open(req govern.ApprovalRequest) {
	p := Pending{
		DecisionID: req.DecisionID,
		Principal:  req.Principal,
		Surface:    req.Surface,
		Verb:       req.Verb,
		Reason:     req.Reason,
		Created:    time.Now(),
		TTL:        m.ttl,
	}
	m.store.Open(p)

	if m.telegram != nil {
		// Notify off the decision path: the Bot API can be slow, and the PDP must
		// return `ask` without waiting on it. A failure just means the owner uses
		// the console inbox instead.
		go func() { _ = m.telegram.Notify(p) }()
	}
}

// Status implements govern.Approver: the current verdict for id
// ("pending"|"allow"|"deny") and whether the id is known.
func (m *Manager) Status(id string) (string, bool) {
	return m.store.Status(id)
}

// List implements the console approvals surface: the still-pending inbox.
func (m *Manager) List() []Pending {
	return m.store.List()
}

// Resolve implements the console approvals surface: resolve a pending as if the
// owner tapped it. Idempotent and race-safe (exactly one resolution wins),
// delegating to the same Store the Telegram poller and the PEP poll observe.
func (m *Manager) Resolve(id, verdict, who string) bool {
	return m.store.Resolve(id, verdict, who)
}
