package pca

// Replays the core FROST(Ed25519, SHA-512) corpus (RFC 9591 vectors plus hostile inputs). Bytes cross as {"$bytes": b64u}.

import (
	"errors"
	"math"
	"testing"
)

func frostOut(b []byte) any { return map[string]any{"$bytes": b64.EncodeToString(b)} }

func frostB(v any) ([]byte, error) {
	if raw, ok := v.([]byte); ok { // already revived by a caller that decoded the corpus bytes
		return raw, nil
	}
	b := baseBytes(v)
	if b == nil {
		return nil, errors.New("expected bytes")
	}
	return b, nil
}

// frostOptB reads an optional bytes member: null / absent is nil.
func frostOptB(v any) ([]byte, error) {
	if v == nil {
		return nil, nil
	}
	return frostB(v)
}

func frostI(v any) (int64, error) {
	f, ok := jsNum(v)
	if !ok || f != math.Trunc(f) || math.Abs(f) > 9007199254740991 {
		return 0, errors.New("expected integer")
	}
	return int64(f), nil
}

func frostOptInt(v any) (*int, error) {
	if v == nil {
		return nil, nil
	}
	i, err := frostI(v)
	if err != nil {
		return nil, err
	}
	n := int(i)
	return &n, nil
}

func frostCommitmentIn(v any) (FrostCommitment, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return FrostCommitment{}, errors.New("malformed commitment")
	}
	id, err := frostI(m["identifier"])
	if err != nil {
		return FrostCommitment{}, err
	}
	h, err := frostOptB(m["hiding"])
	if err != nil {
		return FrostCommitment{}, err
	}
	b, err := frostOptB(m["binding"])
	if err != nil {
		return FrostCommitment{}, err
	}
	return FrostCommitment{Identifier: id, Hiding: h, Binding: b}, nil
}

func frostCommitmentsIn(v any) ([]FrostCommitment, error) {
	l, ok := v.([]any)
	if !ok {
		return nil, errors.New("commitments must be a list")
	}
	out := make([]FrostCommitment, 0, len(l))
	for _, x := range l {
		c, err := frostCommitmentIn(x)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

func frostSigSharesIn(v any) ([]FrostSigShare, error) {
	l, ok := v.([]any)
	if !ok {
		return nil, errors.New("signature shares must be a list")
	}
	out := make([]FrostSigShare, 0, len(l))
	for _, x := range l {
		s, err := frostSigShareIn(x)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

func frostSigShareIn(v any) (FrostSigShare, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return FrostSigShare{}, errors.New("malformed signature share")
	}
	id, err := frostI(m["identifier"])
	if err != nil {
		return FrostSigShare{}, err
	}
	b, err := frostOptB(m["sigShare"])
	return FrostSigShare{Identifier: id, SigShare: b}, err
}

// frostVSIn: null is absent (nil slice); a list is present even when empty.
func frostVSIn(v any) ([]FrostVerificationShare, error) {
	if v == nil {
		return nil, nil
	}
	l, ok := v.([]any)
	if !ok {
		return nil, errors.New("verificationShares must be a list")
	}
	out := make([]FrostVerificationShare, 0, len(l))
	for _, x := range l {
		m, ok := x.(map[string]any)
		if !ok {
			return nil, errors.New("malformed verification share")
		}
		id, err := frostI(m["identifier"])
		if err != nil {
			return nil, err
		}
		pk, err := frostOptB(m["publicKey"])
		if err != nil {
			return nil, err
		}
		out = append(out, FrostVerificationShare{Identifier: id, PublicKey: pk})
	}
	return out, nil
}

func frostShareIn(v any) (FrostParticipantShare, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return FrostParticipantShare{}, errors.New("malformed participant share")
	}
	id, err := frostI(m["identifier"])
	if err != nil {
		return FrostParticipantShare{}, err
	}
	sh, err := frostOptB(m["share"])
	if err != nil {
		return FrostParticipantShare{}, err
	}
	pk, err := frostOptB(m["publicKey"])
	return FrostParticipantShare{Identifier: id, Share: sh, PublicKey: pk}, err
}

func frostCommitmentOut(c FrostCommitment) any {
	return map[string]any{"identifier": c.Identifier, "hiding": frostOut(c.Hiding), "binding": frostOut(c.Binding)}
}

func frostKeygenIn(o map[string]any) (*FrostKeyShares, error) {
	t, err := frostI(o["t"])
	if err != nil {
		return nil, err
	}
	n, err := frostI(o["n"])
	if err != nil {
		return nil, err
	}
	secret, err := frostOptB(o["secret"])
	if err != nil {
		return nil, err
	}
	var coeffs [][]byte
	if l, ok := o["coefficients"].([]any); ok {
		for _, x := range l {
			b, err := frostOptB(x)
			if err != nil {
				return nil, err
			}
			coeffs = append(coeffs, b)
		}
	}
	var ids []int64
	if l, ok := o["identifiers"].([]any); ok {
		ids = []int64{}
		for _, x := range l {
			i, err := frostI(x)
			if err != nil {
				return nil, err
			}
			ids = append(ids, i)
		}
	}
	return FrostTrustedDealerKeygen(int(t), int(n), secret, coeffs, ids)
}

func frostKeysOut(kg *FrostKeyShares) map[string]any {
	ps := make([]any, 0, len(kg.ParticipantShares))
	for _, p := range kg.ParticipantShares {
		ps = append(ps, map[string]any{"identifier": p.Identifier, "share": frostOut(p.Share), "publicKey": frostOut(p.PublicKey)})
	}
	gc := make([]any, 0, len(kg.GroupCommitment))
	for _, c := range kg.GroupCommitment {
		gc = append(gc, frostOut(c))
	}
	return map[string]any{"groupPublicKey": frostOut(kg.GroupPublicKey), "participantShares": ps, "groupCommitment": gc}
}

func frostFlow(o map[string]any) (any, error) {
	kg, err := frostKeygenIn(o)
	if err != nil {
		return nil, err
	}
	msg, err := frostB(o["message"])
	if err != nil {
		return nil, err
	}
	thr, err := frostOptInt(o["threshold"])
	if err != nil {
		return nil, err
	}
	signers, _ := o["signers"].([]any)
	rnd, _ := o["randomness"].([]any)
	by := map[int64]FrostParticipantShare{}
	for _, p := range kg.ParticipantShares {
		by[p.Identifier] = p
	}
	var commits []*FrostCommitResult
	var comms []FrostCommitment
	var vss []FrostVerificationShare
	var ids []int64
	for k, s := range signers {
		id, err := frostI(s)
		if err != nil {
			return nil, err
		}
		r, _ := rnd[k].(map[string]any)
		hr, err := frostB(r["hr"])
		if err != nil {
			return nil, err
		}
		br, err := frostB(r["br"])
		if err != nil {
			return nil, err
		}
		c, err := FrostCommit(by[id], hr, br)
		if err != nil {
			return nil, err
		}
		commits, comms, ids = append(commits, c), append(comms, c.Commitment), append(ids, id)
		vss = append(vss, FrostVerificationShare{Identifier: id, PublicKey: by[id].PublicKey})
	}
	var shares []FrostSigShare
	for k, id := range ids {
		s, err := FrostSign(id, by[id].Share, kg.GroupPublicKey, FrostNonces{Hiding: commits[k].HidingNonce, Binding: commits[k].BindingNonce}, msg, comms,
			FrostSignOpts{Threshold: thr, VerificationShare: by[id].PublicKey, VerificationShares: vss})
		if err != nil {
			return nil, err
		}
		shares = append(shares, *s)
	}
	agg, err := FrostAggregate(msg, comms, shares, kg.GroupPublicKey, vss, thr)
	if err != nil {
		return nil, err
	}
	out := frostKeysOut(kg)
	cs, ss := []any{}, []any{}
	for _, c := range comms {
		cs = append(cs, frostCommitmentOut(c))
	}
	for _, s := range shares {
		ss = append(ss, map[string]any{"identifier": s.Identifier, "sigShare": frostOut(s.SigShare)})
	}
	out["commitments"], out["sigShares"], out["aggregate"] = cs, ss, frostOut(agg)
	return out, nil
}

func TestFrostVectors(t *testing.T) {
	// flow records its argument object bare (baseCase.Args is nil for it), so the loop below hands it over as the only argument. The
	// reference one-shot nonce registry is process-wide, so cases replay strictly in file order.
	fns := map[string]vecFn{
		"flow": func(args []any) (any, error) {
			o, _ := vecArg(args, 0).(map[string]any)
			return frostFlow(o)
		},
		"scalar": func(a []any) (any, error) {
			b, err := frostB(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			s, err := FrostScalar(b)
			return frostOut(s), err
		},
		"isCanonicalScalar": func(a []any) (any, error) { return FrostIsCanonicalScalar(baseBytes(vecArg(a, 0))), nil },
		"hash": func(a []any) (any, error) {
			w, _ := vecArg(a, 0).(string)
			b, err := frostB(vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			h, err := FrostHash(w, b)
			return frostOut(h), err
		},
		"decodeSafePoint": func(a []any) (any, error) {
			b, err := frostB(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			p, err := FrostDecodeSafePoint(b)
			return frostOut(p), err
		},
		"keygen": func(a []any) (any, error) {
			o, _ := vecArg(a, 0).(map[string]any)
			kg, err := frostKeygenIn(o)
			if err != nil {
				return nil, err
			}
			return frostKeysOut(kg), nil
		},
		"verifyingShare": func(a []any) (any, error) {
			b, err := frostB(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			p, err := FrostVerifyingShare(b)
			return frostOut(p), err
		},
		"commit": func(a []any) (any, error) {
			id, err := frostI(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			sh, err := frostB(vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			hr, err := frostOptB(vecArg(a, 2))
			if err != nil {
				return nil, err
			}
			br, err := frostOptB(vecArg(a, 3))
			if err != nil {
				return nil, err
			}
			r, err := FrostCommit(FrostParticipantShare{Identifier: id, Share: sh}, hr, br)
			if err != nil {
				return nil, err
			}
			return map[string]any{"hidingNonce": frostOut(r.HidingNonce), "bindingNonce": frostOut(r.BindingNonce), "commitment": frostCommitmentOut(r.Commitment)}, nil
		},
		"sign": func(a []any) (any, error) {
			id, err := frostI(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			share, err := frostB(vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			gpk, err := frostOptB(vecArg(a, 2))
			if err != nil {
				return nil, err
			}
			nm, ok := vecArg(a, 3).(map[string]any)
			if !ok {
				return nil, errors.New("nonces must be an object")
			}
			hn, err := frostB(nm["hiding"])
			if err != nil {
				return nil, err
			}
			bn, err := frostB(nm["binding"])
			if err != nil {
				return nil, err
			}
			msg, err := frostB(vecArg(a, 4))
			if err != nil {
				return nil, err
			}
			comms, err := frostCommitmentsIn(vecArg(a, 5))
			if err != nil {
				return nil, err
			}
			o, _ := vecArg(a, 6).(map[string]any)
			var so FrostSignOpts
			if so.Threshold, err = frostOptInt(o["threshold"]); err != nil {
				return nil, err
			}
			if so.VerificationShare, err = frostOptB(o["verificationShare"]); err != nil {
				return nil, err
			}
			if so.VerificationShares, err = frostVSIn(o["verificationShares"]); err != nil {
				return nil, err
			}
			s, err := FrostSign(id, share, gpk, FrostNonces{Hiding: hn, Binding: bn}, msg, comms, so)
			if err != nil {
				return nil, err
			}
			return map[string]any{"identifier": s.Identifier, "sigShare": frostOut(s.SigShare)}, nil
		},
		"aggregate": func(a []any) (any, error) {
			msg, err := frostB(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			comms, err := frostCommitmentsIn(vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			shares, err := frostSigSharesIn(vecArg(a, 2))
			if err != nil {
				return nil, err
			}
			gpk, err := frostOptB(vecArg(a, 3))
			if err != nil {
				return nil, err
			}
			o, _ := vecArg(a, 4).(map[string]any)
			vs, err := frostVSIn(o["verificationShares"])
			if err != nil {
				return nil, err
			}
			thr, err := frostOptInt(o["threshold"])
			if err != nil {
				return nil, err
			}
			sig, err := FrostAggregate(msg, comms, shares, gpk, vs, thr)
			return frostOut(sig), err
		},
		"verifySigShare": func(a []any) (any, error) {
			o, _ := vecArg(a, 0).(map[string]any)
			id, err := frostI(o["identifier"])
			if err != nil {
				return false, nil
			}
			pk, e1 := frostOptB(o["publicKey"])
			com, e2 := frostCommitmentIn(o["commitment"])
			ss, e3 := frostSigShareIn(o["sigShare"])
			sc, e4 := frostCommitmentsIn(o["signingCommitments"])
			g, e5 := frostOptB(o["groupPublicKey"])
			m, e6 := frostOptB(o["message"])
			if err := errors.Join(e1, e2, e3, e4, e5, e6); err != nil {
				return false, nil
			}
			return FrostVerifySigShare(id, pk, com, ss, sc, g, m), nil
		},
		"cosign": func(a []any) (any, error) {
			gpk, err := frostB(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			l, ok := vecArg(a, 1).([]any)
			if !ok {
				return nil, errors.New("quorum must be a list")
			}
			var q []FrostParticipantShare
			for _, x := range l {
				p, err := frostShareIn(x)
				if err != nil {
					return nil, err
				}
				q = append(q, p)
			}
			msg, err := frostB(vecArg(a, 2))
			if err != nil {
				return nil, err
			}
			o, _ := vecArg(a, 3).(map[string]any)
			thr, err := frostOptInt(o["threshold"])
			if err != nil {
				return nil, err
			}
			sig, err := FrostCosign(gpk, q, msg, thr)
			if err != nil {
				return nil, err
			}
			return VerifyStrict(gpk, msg, sig), nil
		},
	}
	replay := func(t *testing.T, file string) int {
		return baseEach(t, file, func(c *baseCase) {
			f, ok := fns[c.Fn]
			if !ok {
				t.Errorf("%s: no Go entry point", c.Name)
				return
			}
			args := c.Args
			if c.Fn == "flow" {
				args = []any{c.C["args"]}
			}
			var got any
			var err error
			if p := baseCall(func() { got, err = f(args) }); p != "" {
				t.Errorf("%s: panic: %s", c.Name, p)
				return
			}
			if throws, _ := baseThrows(c.Out); throws {
				if err == nil && !(vecEngineCrash(c.Out) && vecRefusalValue(vecJSON(got))) {
					t.Errorf("%s: reference refuses, Go returned %s", c.Name, baseCanon(vecJSON(got)))
				}
				return
			}
			if err != nil {
				t.Errorf("%s: Go refuses (%v)", c.Name, err)
				return
			}
			if w, g := baseCanon(c.Out), baseCanon(vecJSON(got)); w != g {
				t.Errorf("%s: want %s got %s", c.Name, w, g)
			}
		})
	}
	n := replay(t, "ref-core-frost-java.json.gz")
	if n != 170 { // the 111 cases that carry private keys live in ref-core-frost-java-gen.json.gz (CI-generated): 281 in all
		t.Fatalf("corpus has %d cases, want 170", n)
	}
	replaySecretGen(t, "ref-core-frost-java.json.gz", func(t *testing.T, p string) {
		if n := replay(t, p); n != 111 {
			t.Fatalf("secret corpus has %d cases, want 111", n)
		}
	})
}
