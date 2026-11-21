package pca

import (
	"fmt"
	"math"
)

// L4 information-flow taint and the enforce.taint gate: a port of the reference taint gate. The agent's own label is never read: every
// declared provenance ref is re-classified from facts the SERVER holds (its trusted-input registry, or its own committed resource graph);
// a ref it cannot vouch for is `agent`, the worst case. Pure and deterministic; malformed or absent provenance and any internal error
// fail closed. Rank scale: trusted 0, first_party 1, tool 2, web 3, agent 4; taint = rank/4.

var taintRanks = map[string]int{"trusted": 0, "first_party": 1, "tool": 2, "web": 3, "agent": 4}

const taintMaxRank = 4

// TrustedInputRegistry is the server's registry: content digest -> the level name (trusted, first_party, tool, web) it vouches, "" when it
// does not know the digest. A level name outside the five is treated as unvouched.
type TrustedInputRegistry interface {
	Lookup(digest string) string
}

// ResourceGraph is the server's committed resource graph: a ref that is a node of it is first_party when the registry does not vouch.
type ResourceGraph interface {
	Node(ref string) bool
}

// MapTrustedInputRegistry is the in-memory registry (digest -> level name).
type MapTrustedInputRegistry map[string]string

func (m MapTrustedInputRegistry) Lookup(digest string) string { return m[digest] }

// TaintGate configures enforce.taint (check `taint_gate`): MaxTaint is the largest taint the policy accepts (0..1; a negative or
// non-finite bound is a misconfiguration and never passes).
type TaintGate struct {
	Registry TrustedInputRegistry
	Graph    ResourceGraph
	MaxTaint float64
}

func classifyTaintRef(ref string, g *TaintGate) (rank int) {
	defer func() {
		if recover() != nil {
			rank = taintMaxRank
		}
	}()
	if lv := g.Registry.Lookup(ref); lv != "" {
		if r, ok := taintRanks[lv]; ok {
			return r
		}
	}
	if g.Graph != nil {
		if g.Graph.Node(ref) { // a graph fault panics to the deferred recover: the worst case
			return 1
		}
		return taintMaxRank
	}
	return taintMaxRank
}

// taintGateReason is "" when the gate passes, else the refusal reason.
func taintGateReason(g *TaintGate, provenance any) (why string) {
	defer func() {
		if r := recover(); r != nil {
			why = fmt.Sprintf("taint gate error (fail closed): %v", r)
		}
	}()
	if g.Registry == nil {
		return "taint: no trusted-input registry"
	}
	prov, ok := provenance.(map[string]any)
	if !ok {
		return "taint: provenance is absent or malformed"
	}
	var refs []string
	if raw, has := prov["trusted_refs"]; has {
		l, isList := raw.([]any)
		if !isList {
			return "taint: trusted_refs must be an array"
		}
		for _, x := range l {
			s, isStr := x.(string)
			if !isStr || s == "" {
				return "taint: trusted_refs must be non-empty strings"
			}
			refs = append(refs, s)
		}
	}
	rank := 0
	if len(refs) == 0 {
		rank = taintMaxRank // "no verifiable trusted input" is not "trusted"
	}
	for _, r := range refs {
		if c := classifyTaintRef(r, g); c > rank {
			rank = c
		}
	}
	if math.IsNaN(g.MaxTaint) || math.IsInf(g.MaxTaint, 0) || g.MaxTaint < 0 {
		return "taint gate misconfigured: maxTaint must be a non-negative number (fail closed)"
	}
	allowed := -1
	for r := 0; r <= taintMaxRank; r++ {
		if float64(r)/taintMaxRank <= g.MaxTaint {
			allowed = r
		}
	}
	if rank <= allowed {
		return ""
	}
	return fmt.Sprintf("information-flow taint %s exceeds policy max %s", jsNumString(float64(rank)/taintMaxRank), jsNumString(g.MaxTaint))
}
