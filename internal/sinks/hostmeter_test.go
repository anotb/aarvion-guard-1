package sinks

import (
	"bytes"
	"strings"
	"testing"
)

// snapshotFor returns the sample for a given host, or a zero sample if absent.
func snapshotFor(hm *HostMeter, host string) HostSample {
	for _, s := range hm.Snapshot() {
		if s.Host == host {
			return s
		}
	}
	return HostSample{}
}

// Per-host counts split by decision, and estimated spend accrues only on allowed
// requests, using the configured per-request cost.
func TestHostMeterCountsAndSpend(t *testing.T) {
	hm := NewHostMeter(map[string]float64{"api.openai.com": 0.01}, 0)
	for i := 0; i < 3; i++ {
		hm.Count("api.openai.com", "allow")
	}
	hm.Count("api.openai.com", "deny")
	hm.Count("example.com", "allow") // no configured cost

	oai := snapshotFor(hm, "api.openai.com")
	if oai.Allow != 3 || oai.Deny != 1 {
		t.Fatalf("openai counts = allow:%d deny:%d, want 3/1", oai.Allow, oai.Deny)
	}
	if oai.SpendUSD < 0.0299 || oai.SpendUSD > 0.0301 {
		t.Fatalf("openai spend = %.6f, want ~0.03 (3 allows x 0.01)", oai.SpendUSD)
	}
	// A denied request must not accrue spend.
	ex := snapshotFor(hm, "example.com")
	if ex.Allow != 1 || ex.SpendUSD != 0 {
		t.Fatalf("example.com = allow:%d spend:%.6f, want 1/0 (no configured cost)", ex.Allow, ex.SpendUSD)
	}
}

// A ".suffix" cost entry applies to subdomains and the bare domain; the case of
// the incoming Host doesn't matter.
func TestHostMeterSuffixCost(t *testing.T) {
	hm := NewHostMeter(map[string]float64{".openai.com": 0.02}, 0)
	hm.Count("API.OpenAI.com", "allow") // subdomain, mixed case
	hm.Count("openai.com", "allow")     // bare domain

	sub := snapshotFor(hm, "api.openai.com")
	bare := snapshotFor(hm, "openai.com")
	if sub.SpendUSD < 0.0199 || bare.SpendUSD < 0.0199 {
		t.Fatalf("suffix cost not applied: sub=%.6f bare=%.6f, want ~0.02 each", sub.SpendUSD, bare.SpendUSD)
	}
}

// Unconfigured hosts beyond the cardinality cap fold into the "other" bucket, but
// a cost-configured host is always metered individually even past the cap.
func TestHostMeterCardinalityCap(t *testing.T) {
	hm := NewHostMeter(map[string]float64{"paid.example": 0.05}, 2)
	// Fill the cap with two distinct unconfigured hosts.
	hm.Count("h1.example", "allow")
	hm.Count("h2.example", "allow")
	// A third unconfigured host overflows to "other".
	hm.Count("h3.example", "allow")
	hm.Count("h4.example", "deny")
	// A cost-configured host is metered even though the cap is exceeded.
	hm.Count("paid.example", "allow")

	if s := snapshotFor(hm, "h3.example"); s.Allow != 0 {
		t.Fatalf("overflow host h3 should not have its own series, got %+v", s)
	}
	other := snapshotFor(hm, overflowHost)
	if other.Allow != 1 || other.Deny != 1 {
		t.Fatalf("other bucket = allow:%d deny:%d, want 1/1 (h3 allow + h4 deny)", other.Allow, other.Deny)
	}
	paid := snapshotFor(hm, "paid.example")
	if paid.Allow != 1 || paid.SpendUSD < 0.0499 {
		t.Fatalf("cost host must be metered past the cap: %+v", paid)
	}
}

// The rendered exposition text carries both per-host series with the right label
// shape, and a hostile Host value is escaped rather than breaking the output.
func TestWriteHostMetricsFormat(t *testing.T) {
	samples := []HostSample{
		{Host: "api.openai.com", Allow: 3, Deny: 1, SpendUSD: 0.03},
		{Host: `ev"il`, Allow: 1, Deny: 0, SpendUSD: 0},
	}
	var buf bytes.Buffer
	writeHostMetrics(&buf, samples)
	out := buf.String()

	for _, want := range []string{
		`aarvion_guard_host_requests_total{host="api.openai.com",decision="allow"} 3`,
		`aarvion_guard_host_requests_total{host="api.openai.com",decision="deny"} 1`,
		`aarvion_guard_host_estimated_spend_usd{host="api.openai.com"} 0.030000`,
		`# TYPE aarvion_guard_host_requests_total counter`,
		`# TYPE aarvion_guard_host_estimated_spend_usd gauge`,
		`host="ev\"il"`, // escaped quote
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("exposition missing %q\n---\n%s", want, out)
		}
	}
}

// An empty snapshot emits nothing (no dangling HELP/TYPE headers).
func TestWriteHostMetricsEmpty(t *testing.T) {
	var buf bytes.Buffer
	writeHostMetrics(&buf, nil)
	if buf.Len() != 0 {
		t.Fatalf("empty snapshot should emit nothing, got %q", buf.String())
	}
}
