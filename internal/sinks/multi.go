package sinks

import "github.com/aarvion-ai/aarvion-guard/internal/decisions"

// Multi fans one decision row out to several sinks. The Recorder holds a single
// decisions.Sink, so this lets the JSONL + webhook sinks (and any future ones)
// share the single hook. Record is non-blocking as long as each member is, which
// the sinks in this package guarantee (they buffer and hand off).
type Multi struct {
	members []decisions.Sink
}

// NewMulti builds a fanout over the given sinks. nil members are skipped, so
// callers can pass optionally-constructed sinks directly.
func NewMulti(members ...decisions.Sink) *Multi {
	m := &Multi{}
	for _, s := range members {
		if s != nil {
			m.members = append(m.members, s)
		}
	}
	return m
}

// Len reports how many live sinks the fanout holds. Zero means nothing is
// configured and the caller can skip attaching it.
func (m *Multi) Len() int { return len(m.members) }

// Record forwards the row to every member.
func (m *Multi) Record(rec decisions.Record) {
	for _, s := range m.members {
		s.Record(rec)
	}
}
