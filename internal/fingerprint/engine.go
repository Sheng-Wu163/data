// Package fingerprint implements the identification engine. It is a thin,
// pure layer on top of the data-driven rule set: given an input banner it
// returns the first (highest-priority) matching rule's verdict, or an
// "unknown" result. It never panics on malformed input.
package fingerprint

import (
	"github.com/Sheng-Wu163/data/internal/model"
	"github.com/Sheng-Wu163/data/internal/normalize"
	"github.com/Sheng-Wu163/data/rules"
)

// Engine evaluates banners against a compiled rule set.
type Engine struct {
	set *rules.Set
}

// New builds an engine from a loaded rule set.
func New(set *rules.Set) *Engine {
	return &Engine{set: set}
}

// RuleCount returns the number of loaded rules (useful for health output).
func (e *Engine) RuleCount() int {
	return len(e.set.Rules)
}

// IdentifyAll runs Identify over a batch and preserves input order.
func (e *Engine) IdentifyAll(items []model.Input) []model.Result {
	out := make([]model.Result, 0, len(items))
	for _, in := range items {
		out = append(out, e.Identify(in))
	}
	return out
}

// Identify returns the fingerprint for a single input. Any panic raised while
// matching is recovered and converted into an "unknown" result so a single
// hostile banner can never take the service down.
func (e *Engine) Identify(in model.Input) (res model.Result) {
	res = e.unknown(in)
	defer func() {
		if recover() != nil {
			res = e.unknown(in)
		}
	}()

	banner := normalize.Banner(in.Banner)
	for i := range e.set.Rules {
		r := &e.set.Rules[i]
		if !r.Matches(banner) {
			continue
		}
		res.Protocol = r.Protocol
		res.Product = r.ExtractProduct(banner)
		res.Version = r.ExtractVersion(banner)
		res.OSHint = r.ExtractOS(banner)
		res.Confidence = r.Confidence
		return res
	}
	return res
}

func (e *Engine) unknown(in model.Input) model.Result {
	return model.Result{
		IP:         in.IP,
		Port:       in.Port,
		Protocol:   "unknown",
		Confidence: e.set.UnknownConfidence,
	}
}
