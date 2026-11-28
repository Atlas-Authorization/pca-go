package pca

// Deterministic exports of the invariant harness: Ed25519 key pairs from seeds, the legal-chain builder (a signed, attenuating
// delegation chain from a model), the risk "worsen" helper and the registry constants. The property generators and the property
// runner of the reference rest on a property-testing library whose generators and shrinking are not reproduced here.

import (
	"errors"
	"fmt"
	"math"
)

// Defaults of the invariant runner.
const (
	InvariantsDefaultSeed    = 20260108
	InvariantsDefaultNumRuns = 1000
)

// InvariantNames are the registered invariants, in run order.
var InvariantNames = []string{"attenuation-monotonicity", "risk-wellformed-and-monotone", "admission-soundness", "cumulative-budget-bound",
	"fail-closed:undecidable-leaf", "fail-closed:undecidable-groups", "fail-closed:member-of-cycle-safe", "fail-closed:unknown-caveat-type",
	"fail-closed:forged-chain-rejected", "fail-closed:garbage-chain-rejected", "forbid-monotone", "determinism"}

// InvariantKeyPair is a key pair derived from a 32-byte seed (any 32 bytes is a valid Ed25519 secret).
type InvariantKeyPair struct {
	SecretKey, PublicKey []byte
	Pub                  string
	Signer               *KeyPair
}

// InvariantKeyPairFromSeed derives the key pair of a seed; a seed that is not 32 bytes is refused.
func InvariantKeyPairFromSeed(seed []byte) (*InvariantKeyPair, error) {
	kp, err := KeyPairFromSeed(seed)
	if err != nil {
		return nil, err
	}
	pk, ok := DecodeB64uStrict(kp.Public, 32)
	if !ok {
		return nil, errors.New("invariants: public key is not canonical base64url")
	}
	return &InvariantKeyPair{SecretKey: append([]byte(nil), seed...), PublicKey: pk, Pub: kp.Public, Signer: kp}, nil
}

// InvariantHop is one delegation of a chain model: the new holder's seed and the caveat specs appended at that hop.
type InvariantHop struct {
	HolderSeed []byte
	AddedSpecs []map[string]any
}

// InvariantChainModel is {principal seed, first holder seed, root caveat specs, hops, predicates}.
type InvariantChainModel struct {
	PrincipalSeed, Holder0Seed []byte
	RootSpecs                  []map[string]any
	Hops                       []InvariantHop
	Predicates                 any
}

// InvariantChain is a built chain: the signed capabilities (root first), the predicates, the root issuer and each hop's holder.
type InvariantChain struct {
	Caps       []map[string]any
	Predicates any
	RootIssuer string
	Holders    []string
}

const invBudgetAllocBase = 1_000_000

func invSpecToCaveat(spec map[string]any, running *float64) (any, error) {
	k, _ := spec["k"].(string)
	switch k {
	case "expires", "not_before":
		return map[string]any{"type": k, "at": spec["at"]}, nil
	case "rate":
		return map[string]any{"type": "rate", "max": spec["max"], "per_secs": spec["per_secs"]}, nil
	case "max_blast_radius":
		return map[string]any{"type": "max_blast_radius", "max": spec["max"]}, nil
	case "reversibility_max":
		return map[string]any{"type": "reversibility_max", "class": spec["cls"]}, nil
	case "delegation_depth":
		return map[string]any{"type": "delegation_depth", "max": spec["max"]}, nil
	case "budget_frac":
		base := *running
		if math.IsInf(base, 0) || math.IsNaN(base) {
			base = invBudgetAllocBase
		}
		frac, ok := jsNum(spec["frac"])
		if !ok {
			return nil, errors.New("invariants: budget_frac without a number")
		}
		// frac in [0,1] and base a non-negative integer: an integer <= the previous allocation (monotone, canonical-wire-safe)
		limit := math.Floor(base * frac)
		*running = limit
		return map[string]any{"type": "budget_alloc", "limit": jsNumber(limit)}, nil
	}
	return nil, fmt.Errorf("unknown caveat spec %q", k)
}

func invCaveats(specs []map[string]any, running *float64) ([]any, error) {
	out := make([]any, 0, len(specs))
	for _, s := range specs {
		c, err := invSpecToCaveat(s, running)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// InvariantBuildChain builds a signed, legally attenuating chain from a model.
func InvariantBuildChain(m InvariantChainModel) (*InvariantChain, error) {
	running := math.Inf(1)
	principal, err := InvariantKeyPairFromSeed(m.PrincipalSeed)
	if err != nil {
		return nil, err
	}
	holder0, err := InvariantKeyPairFromSeed(m.Holder0Seed)
	if err != nil {
		return nil, err
	}
	rc, err := invCaveats(m.RootSpecs, &running)
	if err != nil {
		return nil, err
	}
	root, err := MintRoot(principal.Signer, holder0.Pub, rc, "", nil)
	if err != nil {
		return nil, err
	}
	chain := &InvariantChain{Caps: []map[string]any{root}, Predicates: m.Predicates, RootIssuer: principal.Pub, Holders: []string{holder0.Pub}}
	prev, signer := root, holder0.Signer // the next hop is signed by the key the parent is bound to
	for _, hop := range m.Hops {
		to, err := InvariantKeyPairFromSeed(hop.HolderSeed)
		if err != nil {
			return nil, err
		}
		ac, err := invCaveats(hop.AddedSpecs, &running)
		if err != nil {
			return nil, err
		}
		c, err := Delegate(prev, signer, to.Pub, ac, "", nil)
		if err != nil {
			return nil, err
		}
		chain.Caps = append(chain.Caps, c)
		chain.Holders = append(chain.Holders, to.Pub)
		prev, signer = c, to.Signer
	}
	return chain, nil
}

func invClamp01(x float64) float64 {
	if x < 0 {
		return 0
	}
	if x > 1 {
		return 1
	}
	return x
}

// InvariantWorsen is a risk input that is >= base in every risk-increasing axis and <= in every protective axis (all six clamped).
func InvariantWorsen(base, d map[string]any) (map[string]any, error) {
	get := func(m map[string]any, k string) (float64, error) {
		f, ok := jsNum(m[k])
		if !ok {
			return 0, fmt.Errorf("invariants: %s is not a number", k)
		}
		return f, nil
	}
	var err error
	val := func(m map[string]any, k string) float64 {
		f, e := get(m, k)
		if e != nil && err == nil {
			err = e
		}
		return f
	}
	out := map[string]any{
		"semanticDistance": jsNumber(invClamp01(val(base, "semanticDistance") + val(d, "dSem"))),
		"blastRadius":      jsNumber(invClamp01(val(base, "blastRadius") + val(d, "dBlast"))),
		"taint":            jsNumber(invClamp01(val(base, "taint") + val(d, "dTaint"))),
		"age":              jsNumber(invClamp01(val(base, "age") + val(d, "dAge"))),
		"reversibility":    jsNumber(invClamp01(val(base, "reversibility") - val(d, "dRev"))),
		"confidence":       jsNumber(invClamp01(val(base, "confidence") - val(d, "dConf"))),
	}
	if err != nil {
		return nil, err
	}
	return out, nil
}
