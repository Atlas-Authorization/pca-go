package pca

// Replays the PQ threshold step-up corpora: the signed group descriptor, the ML-DSA-65 quorum and the hybrid verdict, then the
// hybrid signer, the step-up fold, the core threshold hook and the full step-up verification. Bytes cross as {"$bytes": b64u}.
// stepUp compares the verdict (allow) and the quorum result: the native core names and orders its own checks.

import (
	"crypto/ed25519"
	"errors"
	"sort"
	"testing"
)

// pqtRevive replaces every {"$bytes": ...} member of a decoded argument by its bytes.
func pqtRevive(v any) any {
	if b := baseBytes(v); b != nil {
		return b
	}
	switch t := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(t))
		for k, x := range t {
			m[k] = pqtRevive(x)
		}
		recordKeyOrder(m, jsKeys(t))
		return m
	case []any:
		l := make([]any, len(t))
		for i, x := range t {
			l[i] = pqtRevive(x)
		}
		return l
	}
	return v
}

func pqtArgs(a []any) []any {
	out := make([]any, len(a))
	for i, x := range a {
		out[i] = pqtRevive(x)
	}
	return out
}

func pqtBytesOrNil(v any) []byte { b, _ := v.([]byte); return b }

func pqtObj(v any) map[string]any { m, _ := v.(map[string]any); return m }

func pqtSigners(seeds []any, idx []any) ([]PqSigner, error) {
	var out []PqSigner
	for _, i := range idx {
		n, err := frostI(i)
		if err != nil || n < 0 || int(n) >= len(seeds) {
			return nil, errors.New("pq signer index out of range")
		}
		s, err := NewMlDsa65Signer(pqtBytesOrNil(seeds[n]))
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

func pqtHybridSign(a map[string]any) (any, error) {
	kg, err := frostKeygenIn(map[string]any{"t": a["t"], "n": a["n"], "secret": a["secret"], "coefficients": a["coefficients"]})
	if err != nil {
		return nil, err
	}
	by := map[int64]FrostParticipantShare{}
	for _, p := range kg.ParticipantShares {
		by[p.Identifier] = p
	}
	var quorum []FrostParticipantShare
	ql, _ := a["quorum"].([]any)
	for _, q := range ql {
		id, err := frostI(q)
		if err != nil {
			return nil, err
		}
		p, ok := by[id]
		if !ok {
			return nil, errors.New("unknown quorum member")
		}
		quorum = append(quorum, p)
	}
	seeds, _ := a["pqSeeds"].([]any)
	idx, _ := a["pq"].([]any)
	signers, err := pqtSigners(seeds, idx)
	if err != nil {
		return nil, err
	}
	t, err := frostI(a["t"])
	if err != nil {
		return nil, err
	}
	signT := t
	if a["signT"] != nil {
		if signT, err = frostI(a["signT"]); err != nil {
			return nil, err
		}
	}
	var gpk any = kg.GroupPublicKey
	if a["groupAsString"] == true {
		gpk = b64.EncodeToString(kg.GroupPublicKey)
	}
	pqT, err := frostOptInt(a["pqT"])
	if err != nil {
		return nil, err
	}
	action := pqtObj(a["action"])
	art, err := HybridThresholdSign(action, HybridFrost{GroupPublicKey: gpk, Quorum: quorum, T: int(signT)}, signers, pqT)
	if err != nil {
		return nil, err
	}
	parts := []any{}
	for _, p := range kg.ParticipantShares {
		parts = append(parts, map[string]any{"identifier": pqtIntNum(int(p.Identifier)), "publicKey": b64.EncodeToString(p.PublicKey)})
	}
	authSeed := pqtBytesOrNil(a["authSeed"])
	desc, err := IssueGroupDescriptor(authSeed, b64.EncodeToString(kg.GroupPublicKey), a["t"], parts)
	if err != nil {
		return nil, err
	}
	var pool []any
	for _, s := range signers {
		pool = append(pool, b64.EncodeToString(s.Public()))
	}
	var vt any = pqtIntNum(len(idx))
	if a["pqT"] != nil {
		vt = a["pqT"]
	}
	verdict := VerifyHybridThreshold(action, art, map[string]any{
		"groupKey": b64.EncodeToString(kg.GroupPublicKey), "pqPublicKeys": pool, "t": a["t"], "pqT": vt, "groupDescriptor": desc,
		"trustedAuthorities": []any{b64.EncodeToString(ed25519.NewKeyFromSeed(authSeed).Public().(ed25519.PublicKey))},
	})
	frost := map[string]any{}
	for k, v := range art["frost"].(map[string]any) {
		if k != "sig" {
			frost[k] = v
		}
	}
	frost["sigLen"] = pqtIntNum(len(art["frost"].(map[string]any)["sig"].(string)))
	outArt := map[string]any{}
	for k, v := range art {
		outArt[k] = v
	}
	outArt["frost"] = frost
	return map[string]any{"artifact": outArt, "verdict": verdict}, nil
}

func pqtOut(b []byte) any { return frostOut(b) }

func TestPqThresholdVectors(t *testing.T) {
	arg := func(a []any, i int) any { return pqtRevive(vecArg(a, i)) }
	replayVectors(t, "ref-pq-threshold.json.gz", map[string]vecFn{
		"signerSetCommitment": func(a []any) (any, error) { return SignerSetCommitment(arg(a, 0)) },
		"issueGroupDescriptor": func(a []any) (any, error) {
			o := pqtObj(arg(a, 0))
			return IssueGroupDescriptor(pqtBytesOrNil(o["authoritySeed"]), o["groupPublicKey"], o["t"], o["participants"])
		},
		"verifyGroupDescriptor": func(a []any) (any, error) { return VerifyGroupDescriptor(arg(a, 0), arg(a, 1)), nil },
		"normalizePqQuorumPool": func(a []any) (any, error) {
			pool, err := NormalizePqQuorumPool(arg(a, 0))
			keys := make([]string, 0, len(pool))
			for k := range pool {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			return keys, err
		},
		"pqQuorumRepresentative": func(a []any) (any, error) {
			b, ok := arg(a, 0).([]byte)
			if !ok {
				return nil, errors.New("expected bytes")
			}
			return pqtOut(PqQuorumRepresentative(b)), nil
		},
		"verifyPqQuorum": func(a []any) (any, error) {
			msg, ok := arg(a, 1).([]byte)
			if !ok {
				return nil, errors.New("expected bytes")
			}
			pool, err := NormalizePqQuorumPool(arg(a, 2))
			if err != nil {
				return nil, err
			}
			return VerifyPqQuorum(arg(a, 0), msg, pool, arg(a, 3)), nil
		},
		"verifyHybridThreshold": func(a []any) (any, error) { return VerifyHybridThreshold(arg(a, 0), arg(a, 1), arg(a, 2)), nil },
	})

	replayVectorsCmp(t, "ref-pq-threshold-java-extra.json.gz", map[string]vecFn{
		"fold": func(a []any) (any, error) { return FoldHybridStepUp(pqtObj(vecArg(a, 0)), vecArg(a, 1)) },
		"hook": func(a []any) (any, error) {
			h, err := CreateHybridThresholdVerifier(pqtObj(pqtRevive(vecArg(a, 0)))) // key members may be {"$bytes"}
			if err != nil {
				return nil, err
			}
			return h(pqtObj(pqtRevive(vecArg(a, 1))))
		},
		"stepUp": func(a []any) (any, error) {
			opts := pqtObj(vecArg(a, 1))
			if _, ok := opts["audience"].(string); !ok {
				return nil, vecSkip("no audience string: the native core always enforces the audience")
			}
			r, err := VerifyHybridStepUp(pqtObj(vecArg(a, 0)), opts)
			if err != nil {
				return nil, err
			}
			return map[string]any{"allow": r["allow"], "pq": r["pq"]}, nil
		},
		"hybridSign": func(a []any) (any, error) { return pqtHybridSign(pqtObj(pqtRevive(vecArg(a, 0)))) },
	}, map[string]func(want, got any) bool{
		"stepUp": func(want, got any) bool {
			w, g := vecObj(want), vecObj(got)
			return baseCanon(w["allow"]) == baseCanon(g["allow"]) && baseCanon(w["pq"]) == baseCanon(g["pq"])
		},
	})
}
