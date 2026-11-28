package pca

// Replays the invariant harness reference corpus: key pairs from seeds, the legal-chain builder (signatures are deterministic, so
// the chains compare byte for byte), the risk worsen helper and the registry constants.

import (
	"encoding/base64"
	"testing"
)

func invTestBytes(v any) []byte {
	if m, ok := v.(map[string]any); ok {
		if s, ok := m["$bytes"].(string); ok {
			if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
				return b
			}
		}
	}
	return nil
}

func invTestSpecs(v any) []map[string]any {
	l, _ := v.([]any)
	out := make([]map[string]any, len(l))
	for i, x := range l {
		out[i], _ = x.(map[string]any)
		if out[i] == nil {
			out[i] = map[string]any{}
		}
	}
	return out
}

func TestInvariantsReferenceVectors(t *testing.T) {
	siemReplaySeeded(t, "ref-invariants.json.gz", map[string]vecFn{
		"keyPairFromSeed": func(args []any) (any, error) {
			seed, _ := vecArg(args, 0).(map[string]any)
			p, err := InvariantKeyPairFromSeed(invTestBytes(seed))
			if err != nil {
				return nil, err
			}
			enc := func(b []byte) any { return map[string]any{"$bytes": base64.RawURLEncoding.EncodeToString(b)} }
			return map[string]any{"secretKey": enc(p.SecretKey), "publicKey": enc(p.PublicKey), "pub": p.Pub}, nil
		},
		"buildChain": func(args []any) (any, error) {
			m := vecObj(vecArg(args, 0))
			model := InvariantChainModel{PrincipalSeed: invTestBytes(m["principalSeed"]), Holder0Seed: invTestBytes(m["holder0Seed"]),
				RootSpecs: invTestSpecs(m["rootSpecs"]), Predicates: m["predicates"]}
			hops, _ := m["hops"].([]any)
			for _, h := range hops {
				hm := vecObj(h)
				model.Hops = append(model.Hops, InvariantHop{HolderSeed: invTestBytes(hm["holderSeed"]), AddedSpecs: invTestSpecs(hm["addedSpecs"])})
			}
			c, err := InvariantBuildChain(model)
			if err != nil {
				return nil, err
			}
			caps := make([]any, len(c.Caps))
			for i, x := range c.Caps {
				caps[i] = x
			}
			holders := make([]any, len(c.Holders))
			for i, x := range c.Holders {
				holders[i] = x
			}
			return map[string]any{"caps": caps, "predicates": c.Predicates, "rootIssuer": c.RootIssuer, "holders": holders}, nil
		},
		"worsen": func(args []any) (any, error) {
			return InvariantWorsen(vecObj(vecArg(args, 0)), vecObj(vecArg(args, 1)))
		},
		"consts": func(args []any) (any, error) {
			names := make([]any, len(InvariantNames))
			for i, n := range InvariantNames {
				names[i] = n
			}
			return map[string]any{"DEFAULT_SEED": jsonNumberOf(InvariantsDefaultSeed), "DEFAULT_NUM_RUNS": jsonNumberOf(InvariantsDefaultNumRuns),
				"INVARIANT_NAMES": names}, nil
		},
	})
}
