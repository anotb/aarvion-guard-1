package sinks

import (
	"sort"
	"strings"
	"sync"
)

// defaultMaxMeteredHosts caps how many distinct destination hosts get their own
// labelled metric series. A looping or hijacked agent hammering thousands of
// hosts must not blow up Prometheus label cardinality, so unconfigured hosts
// beyond the cap are folded into a single "other" bucket.
const defaultMaxMeteredHosts = 200

// overflowHost is the bucket unconfigured hosts collapse into once the
// cardinality cap is reached.
const overflowHost = "other"

// hostCounter is the running per-host tally the metrics endpoint exposes.
type hostCounter struct {
	allow, deny int
	spendUSD    float64
}

// HostMeter keeps per-host request counts (split by decision) and an estimated
// USD spend (allowed requests times a configured per-request cost). It feeds the
// /metrics endpoint with per-host series so an operator can see, per destination,
// how much traffic and rough spend each agent is driving - the money-facing
// companion to the aggregate counters.
//
// It is driven by the Recorder's meter hook (Count), which fires on every
// decision BEFORE allow-collapse, so repeated identical allows - the runaway
// case - are counted in full rather than deduped away. Count runs on the
// decision hot path (under the Recorder lock), so it only touches an in-memory
// map behind its own mutex; Snapshot is read off the hot path by the metrics
// handler.
type HostMeter struct {
	mu       sync.Mutex
	hosts    map[string]*hostCounter
	exact    map[string]float64 // host          -> USD per allowed request
	suffix   map[string]float64 // ".suffix" zone -> USD per allowed request
	maxHosts int
}

// NewHostMeter builds a meter. spendPerRequest maps a host (exact) or a
// ".suffix" domain to the USD cost of one allowed request there; a host with no
// entry still gets request counts but contributes zero spend. maxHosts <= 0 uses
// the default cardinality cap.
func NewHostMeter(spendPerRequest map[string]float64, maxHosts int) *HostMeter {
	if maxHosts <= 0 {
		maxHosts = defaultMaxMeteredHosts
	}
	hm := &HostMeter{
		hosts:    map[string]*hostCounter{},
		exact:    map[string]float64{},
		suffix:   map[string]float64{},
		maxHosts: maxHosts,
	}
	for k, v := range spendPerRequest {
		k = strings.ToLower(k)
		if strings.HasPrefix(k, ".") {
			hm.suffix[k] = v
		} else {
			hm.exact[k] = v
		}
	}
	return hm
}

// costFor returns the configured per-request USD cost for host: an exact match
// wins, else the longest matching ".suffix" entry (".openai.com" matches both
// "api.openai.com" and the bare "openai.com"), else 0.
func (h *HostMeter) costFor(host string) float64 {
	if c, ok := h.exact[host]; ok {
		return c
	}
	best, bestLen := 0.0, -1
	for suf, c := range h.suffix {
		bare := suf[1:]
		if (host == bare || strings.HasSuffix(host, suf)) && len(suf) > bestLen {
			best, bestLen = c, len(suf)
		}
	}
	return best
}

// Count tallies one decision for host. A brand-new unconfigured host arriving
// after the cardinality cap is folded into the "other" bucket; a host with a
// configured cost is always metered individually (it's the one an operator
// watches spend on), so it is never collapsed. Matches the Recorder's meter-hook
// signature (func(host, decision string)).
func (h *HostMeter) Count(host, decision string) {
	host = strings.ToLower(host)
	if host == "" {
		host = "unknown"
	}
	h.mu.Lock()
	defer h.mu.Unlock()

	hc, ok := h.hosts[host]
	if !ok {
		if len(h.hosts) >= h.maxHosts && h.costFor(host) == 0 {
			host = overflowHost
			hc, ok = h.hosts[host]
		}
		if !ok {
			hc = &hostCounter{}
			h.hosts[host] = hc
		}
	}
	switch decision {
	case "deny":
		hc.deny++
	default: // "allow" (and any non-deny) is an allowed request
		hc.allow++
		hc.spendUSD += h.costFor(host)
	}
}

// HostSample is one host's exported tally.
type HostSample struct {
	Host        string
	Allow, Deny int
	SpendUSD    float64
}

// Snapshot returns the per-host tallies sorted by host, for stable metric output.
func (h *HostMeter) Snapshot() []HostSample {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]HostSample, 0, len(h.hosts))
	for host, hc := range h.hosts {
		out = append(out, HostSample{Host: host, Allow: hc.allow, Deny: hc.deny, SpendUSD: hc.spendUSD})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out
}
