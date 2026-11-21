package pca

import (
	"errors"
	"math"
	"strings"
	"sync"
	"testing"
)

// Replay of networked FROST against the reference (ref-frost-net), every case (634): the action digest, allow tokens, signer
// proofs of possession, enrolment, the equivocation guard, the wire decoders, the nonce store and its contract, the signer service, the
// coordinator over scripted transports, the post-quantum group registry, the hybrid co-sign and the post-quantum quorum. A refusal compares its error class and fields
// exactly (PoPError, EquivocationError); the message is informative, and the open tail of a verification error is not compared.
// Randomness is scripted: a case's trailing {$rng} lists the 32-byte draws the reference made, in order.

// frostDecode applies the corpus conventions to an argument: {"$bytes"} is bytes, {"$share"} the dealer share of one participant,
// {"$num"} a non-finite double; everything else is kept.
func frostDecode(v any) any {
	switch t := v.(type) {
	case map[string]any:
		if len(t) == 1 {
			if b, ok := qvBytes(t); ok {
				return b
			}
			if d, ok := t["$share"].(map[string]any); ok {
				return frostDealerShare(d)
			}
		}
		if _, ok := t["$num"].(string); ok && len(t) == 1 {
			return scDecode(t)
		}
		m := make(map[string]any, len(t))
		for k, x := range t {
			m[k] = frostDecode(x)
		}
		recordKeyOrder(m, jsKeys(t)) // a wire body keeps the member order of the corpus
		return m
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = frostDecode(x)
		}
		return out
	}
	return v
}

// frostDealerShare runs the dealer on the descriptor's seeds and returns the share of its participant.
func frostDealerShare(d map[string]any) []byte {
	dd := frostDecode(d["secret"])
	secret, _ := dd.([]byte)
	var coefs [][]byte
	for _, c := range rsList(d["coefficients"]) {
		b, _ := frostDecode(c).([]byte)
		coefs = append(coefs, b)
	}
	var ids []int64
	for _, x := range rsList(d["identifiers"]) {
		f, _ := jsNum(x)
		ids = append(ids, int64(f))
	}
	t, _ := jsNum(d["t"])
	n, _ := jsNum(d["n"])
	id, _ := jsNum(d["id"])
	kg, err := FrostTrustedDealerKeygen(int(t), int(n), secret, coefs, ids)
	if err != nil {
		panic(err)
	}
	for _, p := range kg.ParticipantShares {
		if p.Identifier == int64(id) {
			return p.Share
		}
	}
	panic("no such participant")
}

// frostCall wraps a handler: the trailing {$rng} is removed and scripted into the random seam for the call, and the arguments are
// decoded with the corpus conventions.
func frostCall(f func(a []any) (any, error)) vecFn {
	return func(a []any) (any, error) {
		var draws [][]byte
		if n := len(a); n > 0 {
			if m, ok := a[n-1].(map[string]any); ok && len(m) == 1 {
				if l, isList := m["$rng"].([]any); isList {
					for _, x := range l {
						b, _ := frostDecode(x).([]byte)
						draws = append(draws, b)
					}
					a = a[:n-1]
				}
			}
		}
		old := frostNetRand
		frostNetRand = func() ([]byte, error) {
			if len(draws) == 0 {
				return nil, errors.New("a draw past the script")
			}
			b := draws[0]
			draws = draws[1:]
			return b, nil
		}
		defer func() { frostNetRand = old }()
		return f(frostDecode(a).([]any))
	}
}

// frostErrOut is a refusal as an element of a result list, with its class and fields.
func frostErrOut(err error) map[string]any {
	out := map[string]any{"$throws": err.Error()}
	var pe *PoPError
	var ee *EquivocationError
	var te *CoordinatorTimeoutError
	var ce *CoordinatorError
	var de *DkgChannelError
	refusalsOut := func(rs []CoordinatorRefusal) []any {
		out := []any{}
		for _, r := range rs {
			out = append(out, map[string]any{"identifier": r.Identifier, "reason": r.Reason})
		}
		return out
	}
	switch {
	case errors.As(err, &de):
		out["class"], out["code"], out["peer"] = "DkgChannelError", de.Code, nil
		if de.HasPeer {
			out["peer"] = jsNumber(float64(de.Peer))
		}
	case errors.As(err, &te):
		out["class"], out["refusals"], out["timeoutMs"] = "CoordinatorTimeoutError", refusalsOut(te.Refusals), jsNumber(te.TimeoutMs)
	case errors.As(err, &ce):
		out["class"], out["refusals"] = "CoordinatorError", refusalsOut(ce.Refusals)
	case errors.As(err, &pe):
		out["class"] = "PoPError"
		if pe.HasIdentifier {
			out["identifier"] = jsNumber(float64(pe.Identifier))
		}
	case errors.As(err, &ee):
		out["class"], out["session_id"], out["round"], out["identifier"] = "EquivocationError", ee.SessionID, jsNumber(float64(ee.Round)), jsNumber(float64(ee.Identifier))
		out["previousDigest"], out["offendingDigest"] = ee.PreviousDigest, ee.OffendingDigest
	}
	return out
}

// frostNorm drops the informative message of every refusal element, deeply.
func frostNorm(v any) any {
	switch t := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(t))
		for k, x := range t {
			m[k] = frostNorm(x)
		}
		if _, ok := m["$throws"]; ok {
			m["$throws"] = true
		}
		recordKeyOrder(m, jsKeys(t))
		return m
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = frostNorm(x)
		}
		return out
	}
	return v
}

// frostOpen applies the corpus rule for open reasons to a pair of normalized results: where the reference marks a reason open, a
// reason with a "(fail closed)" tail compares up to and including that marker, any other is not compared at all.
func frostOpen(w, g any) {
	switch wt := w.(type) {
	case map[string]any:
		gt, _ := g.(map[string]any)
		if wt["reasonOpen"] == true {
			wr, _ := wt["reason"].(string)
			gr, _ := gt["reason"].(string)
			if i := strings.Index(wr, "(fail closed)"); i >= 0 {
				wt["reason"] = wr[:i+len("(fail closed)")]
				if j := strings.Index(gr, "(fail closed)"); j >= 0 {
					gt["reason"] = gr[:j+len("(fail closed)")]
				}
			} else {
				delete(wt, "reason")
				delete(gt, "reason")
			}
		}
		delete(wt, "reasonOpen")
		for k, x := range wt {
			if gt != nil {
				frostOpen(x, gt[k])
			}
		}
	case []any:
		gt, _ := g.([]any)
		for i, x := range wt {
			if i < len(gt) {
				frostOpen(x, gt[i])
			}
		}
	}
}

// frostReplay replays the cases of a corpus whose function a handler exists for: the total of the replayed ones is returned with the
// names of the functions without a handler (a partial replay, to be closed by the rest of the module).
func frostReplay(t *testing.T, file string, fns map[string]vecFn, exact map[string]bool) (replayed int, unhandled map[string]int) {
	t.Helper()
	unhandled = map[string]int{}
	var k baseTally
	baseEachOrdered(t, file, func(c *baseCase) {
		f, ok := fns[c.Fn]
		if !ok {
			unhandled[c.Fn]++
			return
		}
		replayed++
		k.run(c.Fn)
		var got any
		var err error
		if p := baseCall(func() { got, err = f(c.Args) }); p != "" {
			k.fail(c, "panic: %s", p)
			return
		}
		if throws, _ := baseThrows(c.Out); throws {
			if err == nil {
				if !(vecEngineCrash(c.Out) && vecRefusalValue(vecJSON(got))) {
					k.fail(c, "reference refuses (%v), Go returned %s", c.Out, baseCanon(vecJSON(got)))
				}
				return
			}
			if want, _ := vecObj(c.Out)["$throws"].(string); exact[c.Fn] && err.Error() != want {
				k.fail(c, "reference refuses with %q, Go with %q", want, err.Error())
			}
			if cls, _ := vecObj(c.Out)["class"].(string); cls != "" {
				w, g := baseCanon(frostNorm(normalizeJSON(c.Out))), baseCanon(frostNorm(frostErrOut(err)))
				if frostErrOut(err)["class"] != cls {
					k.fail(c, "reference refuses with %s, Go with %v", cls, err)
				} else if w != g {
					k.fail(c, "refusal fields: want %s got %s", w, g)
				}
			}
			return
		}
		if err != nil {
			k.fail(c, "Go refuses (%v), reference returned %s", err, baseCanon(c.Out))
			return
		}
		wn, gn := frostNorm(normalizeJSON(c.Out)), frostNorm(vecJSON(got))
		frostOpen(wn, gn)
		if w, g := baseCanon(wn), baseCanon(gn); w != g {
			k.fail(c, "want %s got %s", w, g)
		}
	})
	k.finish(t)
	return replayed, unhandled
}

func frostBytes(v any) []byte { b, _ := v.([]byte); return b }

// frostIDList reads a list of participant identifiers; an entry that is no positive safe integer becomes 0, which the digest refuses.
func frostIDList(v any) []int64 {
	out := []int64{}
	for _, x := range rsList(v) {
		id, _ := frostIDOf(x)
		out = append(out, id)
	}
	return out
}

func TestFrostNetBuildingBlocksMatchTheReference(t *testing.T) {
	fns := map[string]vecFn{
		"constants": frostCall(func([]any) (any, error) {
			return map[string]any{"ALLOW_TOKEN_TYP": AllowTokenTyp, "SIGNER_POP_DST": SignerPopDst, "MAX_FROST_SIGNING_SET": jsNumber(MaxFrostSigningSet),
				"DEFAULT_FROST_GROUP_ALG": DefaultFrostGroupAlg, "PQ_QUORUM_VERSION": jsNumber(PqQuorumVersion), "PQ_QUORUM_ALG": PqQuorumAlg,
				"MAX_PQ_QUORUM_ENTRIES": jsNumber(MaxPqQuorumEntries)}, nil
		}),
		"frostActionDigest": frostCall(func(a []any) (any, error) {
			b, ok := vecArg(a, 0).([]byte)
			if !ok {
				return nil, errors.New("frostActionDigest: message must be bytes")
			}
			return FrostActionDigest(b), nil
		}),
		"issueAllowToken": frostCall(func(a []any) (any, error) {
			o := vecObj(vecArg(a, 1))
			if _, isBytes := o["groupPublicKey"].([]byte); !isBytes { // the reference encodes the key: a non-bytes value throws
				return nil, errors.New("radix2.encode input should be Uint8Array")
			}
			opts := IssueAllowOptions{GroupPublicKey: frostBytes(o["groupPublicKey"])}
			if m, ok := o["message"].([]byte); ok {
				opts.Message = m
			}
			if s, ok := o["frostActionDigest"].(string); ok {
				opts.FrostActionDigest = &s
			}
			if s, ok := o["nonce"].(string); ok {
				opts.Nonce = &s
			}
			if f, ok := jsNum(o["notBefore"]); ok {
				opts.NotBefore = &f
			}
			if f, ok := jsNum(o["expiresAt"]); ok {
				opts.ExpiresAt = &f
			}
			return IssueAllowToken(frostBytes(vecArg(a, 0)), opts)
		}),
		"verifyAllowToken": frostCall(func(a []any) (any, error) {
			e := vecObj(vecArg(a, 1))
			now := math.NaN()
			if f, ok := jsNum(e["now"]); ok {
				now = f
			}
			ok, why := VerifyAllowToken(vecArg(a, 0), frostBytes(e["policyAuthorityPublicKey"]), frostBytes(e["groupPublicKey"]), frostBytes(e["message"]), now)
			if ok {
				return map[string]any{"ok": true}, nil
			}
			return map[string]any{"ok": false, "reason": why}, nil
		}),
		"createSignerPoP": frostCall(func(a []any) (any, error) {
			id, isID := frostIDOf(vecArg(a, 0))
			if !isID {
				id = 0
			}
			o := vecObj(vecArg(a, 2))
			return CreateSignerPoP(id, frostBytes(vecArg(a, 1)), frostBytes(o["groupPublicKey"]), frostBytes(o["nonce"]))
		}),
		"verifySignerPoP": frostCall(func(a []any) (any, error) {
			return VerifySignerPoP(vecArg(a, 0), frostBytes(vecObj(vecArg(a, 1))["groupPublicKey"])), nil
		}),
		"enrollVerificationShares": frostCall(func(a []any) (any, error) {
			l, _ := vecArg(a, 0).([]any)
			out, err := EnrollVerificationShares(l, frostBytes(vecObj(vecArg(a, 1))["groupPublicKey"]))
			if err != nil {
				return nil, err
			}
			res := []any{}
			for _, v := range out {
				res = append(res, map[string]any{"identifier": jsNumber(float64(v.Identifier)), "publicKey": vecBytesOut(v.PublicKey)})
			}
			return res, nil
		}),
		"equivocationGuard": frostCall(func(a []any) (any, error) {
			g := NewEquivocationGuard()
			out := []any{}
			for _, o := range rsList(vecArg(a, 0)) {
				op := vecObj(o)
				switch op["op"] {
				case "forget":
					g.Forget(rsStr(op["session_id"]))
					out = append(out, map[string]any{"ok": true})
				default:
					round, ok1 := attSafeInt(op["round"])
					id, ok2 := attSafeInt(op["identifier"])
					sid, isStr := op["session_id"].(string)
					if !isStr {
						sid = ""
					}
					if !ok1 {
						round = 0
					}
					if !ok2 {
						id = 0
					}
					if err := g.Observe(sid, int64(round), int64(id), op["message"]); err != nil {
						out = append(out, frostErrOut(err))
					} else {
						out = append(out, map[string]any{"ok": true})
					}
				}
			}
			return out, nil
		}),
		"decodeCommitment": frostCall(func(a []any) (any, error) {
			c, err := DecodeCommitment(frostEncodeWire(vecArg(a, 0)))
			if err != nil {
				return nil, err
			}
			return frostNetCommitmentOut(c), nil
		}),
		"decodeCommitments": frostCall(func(a []any) (any, error) {
			l, err := DecodeCommitments(frostEncodeWire(vecArg(a, 0)))
			if err != nil {
				return nil, err
			}
			out := []any{}
			for _, c := range l {
				out = append(out, frostNetCommitmentOut(c))
			}
			return out, nil
		}),
		"resolveFrostGroupAlg": frostCall(func(a []any) (any, error) {
			alg, ok := ResolveFrostGroupAlg(vecArg(a, 0), len(a) > 0)
			if !ok {
				return nil, nil
			}
			return alg, nil
		}),
		"frostSignerSetDigest": frostCall(func(a []any) (any, error) {
			d, err := FrostSignerSetDigest(frostIDList(vecArg(a, 0)))
			if err != nil {
				return nil, err
			}
			return vecBytesOut(d), nil
		}),
		"frostCosignRepresentative": frostCall(func(a []any) (any, error) {
			gpk, isStr := vecArg(a, 0).(string)
			msg, isBytes := vecArg(a, 1).([]byte)
			if !isStr {
				return nil, errors.New("frostCosignRepresentative: groupPublicKey must be a 32-byte base64url point")
			}
			alg := "undefined"
			if len(a) > 3 {
				alg = jsValueString(a[3])
			}
			if !isBytes {
				return nil, errors.New("Uint8Array expected")
			}
			r, err := FrostCosignRepresentative(gpk, msg, frostIDList(vecArg(a, 2)), alg)
			if err != nil {
				return nil, err
			}
			return vecBytesOut(r), nil
		}),
		"signHybridFrostCosign": frostCall(func(a []any) (any, error) {
			gpk := frostBytes(vecArg(a, 0))
			var quorum []FrostParticipantShare
			for _, x := range rsList(vecArg(a, 1)) {
				m := vecObj(x)
				id, _ := frostIDOf(m["identifier"])
				quorum = append(quorum, FrostParticipantShare{Identifier: id, Share: frostBytes(m["share"]), PublicKey: frostBytes(m["publicKey"])})
			}
			o := vecObj(vecArg(a, 3))
			opts := HybridFrostCosignOptions{GroupAlg: rsStr(o["groupAlg"])}
			if seed, ok := o["guardianMlDsaSeed"].([]byte); ok {
				kp, err := GeneratePqKeyPairFromSeed("ML-DSA-65", seed)
				if err != nil {
					return nil, err
				}
				opts.GuardianMlDsa = kp
			}
			if f, ok := attSafeInt(o["threshold"]); ok {
				n := int(f)
				opts.Threshold = &n
			}
			res, err := SignHybridFrostCosign(gpk, quorum, frostBytes(vecArg(a, 2)), opts)
			if err != nil {
				return nil, err
			}
			sig, _ := res["sig"].(string)
			raw, _ := DecodeB64uStrict(sig, -1)
			out := map[string]any{"sigVerifies": VerifyB64u(b64.EncodeToString(gpk), frostBytes(vecArg(a, 2)), sig), "sigLength": jsNumber(float64(len(raw)))}
			for _, k := range []string{"groupAlg", "pq_sig", "pq_pk"} {
				if v, ok := res[k]; ok {
					out[k] = v
				}
			}
			return out, nil
		}),
		"verifyHybridFrostCosign": frostCall(func(a []any) (any, error) {
			o := vecObj(vecArg(a, 4))
			opts := VerifyHybridFrostOptions{GuardianPqPublicKey: o["guardianPqPublicKey"]}
			if v, has := o["expectGroupAlg"]; has {
				opts.ExpectGroupAlg, opts.HasExpectGroupAlg = v, true
			}
			v := VerifyHybridFrostCosign(vecArg(a, 0), frostBytes(vecArg(a, 1)), vecArg(a, 2), frostIDList(vecArg(a, 3)), opts)
			out := map[string]any{"ok": v.OK, "edOk": v.EdOK, "pqOk": v.PqOK}
			if v.GroupAlg != "" {
				out["groupAlg"] = v.GroupAlg
			}
			if v.Reason != "" {
				out["reason"] = v.Reason
			}
			return out, nil
		}),
		"pqQuorumRepresentative": frostCall(func(a []any) (any, error) {
			b, ok := vecArg(a, 0).([]byte)
			if !ok {
				return nil, errors.New("Uint8Array expected")
			}
			return vecBytesOut(PqQuorumRepresentative(b)), nil
		}),
		"signPqQuorum": frostCall(func(a []any) (any, error) {
			var keys []PqSigner
			for _, x := range rsList(vecArg(a, 1)) {
				k, err := NewMlDsa65Signer(frostBytes(x))
				if err != nil {
					return nil, err
				}
				keys = append(keys, k)
			}
			var t *int
			if f, ok := attSafeInt(vecArg(a, 2)); ok {
				n := int(f)
				t = &n
			}
			return SignPqQuorum(frostBytes(vecArg(a, 0)), keys, t)
		}),
		"normalizePqQuorumPool": frostCall(func(a []any) (any, error) {
			pool, err := NormalizePqQuorumPool(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			out := []any{} // a Set iterates in insertion order: the first occurrence of each kept key
			seen := map[string]bool{}
			items, _ := vecArg(a, 0).([]any)
			for _, p := range items {
				if k, ok := pqtB64(p).(string); ok && pool[k] && !seen[k] {
					seen[k] = true
					out = append(out, k)
				}
			}
			return out, nil
		}),
		"verifyPqQuorum": frostCall(func(a []any) (any, error) {
			pool, err := NormalizePqQuorumPool(vecArg(a, 2))
			if err != nil {
				return nil, err
			}
			return VerifyPqQuorum(vecArg(a, 0), frostBytes(vecArg(a, 1)), pool, vecArg(a, 3)), nil
		}),
		"nonceStore": frostCall(func(a []any) (any, error) {
			st := NewMemoryFrostNonceStore()
			recOf := func(v any) FrostNonceRecord {
				m := vecObj(v)
				f, _ := jsNum(m["createdAt"])
				return FrostNonceRecord{Hiding: frostBytes(m["hiding"]), Binding: frostBytes(m["binding"]), HidingCommitment: frostBytes(m["hidingCommitment"]),
					BindingCommitment: frostBytes(m["bindingCommitment"]), CreatedAt: f}
			}
			recOut := func(r *FrostNonceRecord) any {
				if r == nil {
					return nil
				}
				return map[string]any{"hiding": vecBytesOut(r.Hiding), "binding": vecBytesOut(r.Binding), "hidingCommitment": vecBytesOut(r.HidingCommitment),
					"bindingCommitment": vecBytesOut(r.BindingCommitment), "createdAt": jsNumber(r.CreatedAt)}
			}
			out := []any{}
			for _, o := range rsList(vecArg(a, 0)) {
				op := vecObj(o)
				sid, _ := op["sid"].(string)
				var err error
				switch op["op"] {
				case "create":
					r := recOf(op["rec"])
					err = st.Create(sid, r)
					if op["mutateInputAfter"] == true {
						for i := range r.Hiding {
							r.Hiding[i] ^= 0xff
						}
					}
				case "load":
					r, _ := st.Load(sid)
					rec := recOut(r) // recorded as loaded, before the caller scribbles on its copy
					if op["mutate"] == true && r != nil {
						for i := range r.Hiding {
							r.Hiding[i] ^= 0xff
						}
					}
					out = append(out, map[string]any{"value": rec})
					continue
				case "spend":
					err = st.Spend(sid)
				case "drop":
					err = st.Drop(sid)
				case "isSpent":
					b, _ := st.IsSpent(sid)
					out = append(out, map[string]any{"value": b})
					continue
				}
				if err != nil {
					out = append(out, frostErrOut(err))
				} else {
					out = append(out, map[string]any{"ok": true})
				}
			}
			return out, nil
		}),
		"assertNonceStoreContract": frostCall(func(a []any) (any, error) {
			which, _ := vecObj(vecArg(a, 0))["store"].(string)
			var err error
			if which == "memory" {
				err = AssertFrostNonceStoreContract(func() FrostNonceStore { return NewMemoryFrostNonceStore() }, nil)
			} else {
				b := &brokenFrostStore{kind: strings.TrimPrefix(which, "broken:"), live: map[string]FrostNonceRecord{}, spent: map[string]bool{}}
				err = AssertFrostNonceStoreContract(func() FrostNonceStore { return b }, b.reopen)
			}
			return nil, err
		}),
		"signerService": frostCall(func(a []any) (any, error) {
			cfg := vecObj(vecArg(a, 0))
			id, _ := frostIDOf(cfg["identifier"])
			th := 0
			if f, ok := attSafeInt(cfg["threshold"]); ok && f >= 1 && f < 1<<31 {
				th = int(f)
			}
			var ttl *float64
			if v, has := cfg["sessionTtlMs"]; has {
				f := math.NaN()
				if x, ok := jsNum(v); ok {
					f = x
				}
				ttl = &f
			}
			clock := 1000000.0
			var store FrostNonceStore
			switch kind, _ := cfg["store"].(string); {
			case kind == "memory":
				store = NewMemoryFrostNonceStore()
			case strings.HasPrefix(kind, "fail-"):
				store = &frostFaultyStore{FrostNonceStore: NewMemoryFrostNonceStore(), fail: strings.TrimPrefix(kind, "fail-")}
			case kind == "invalid-no-spend": // a store object without `spend` cannot be typed here: the reference's constructor refusal
				return map[string]any{"ctor": map[string]any{"$throws": "GuardianSignerService: nonceStore.spend must be a function"}, "steps": []any{}}, nil
			}
			mk := func() (*GuardianSignerService, error) {
				return NewGuardianSignerService(GuardianSignerOptions{Identifier: id, Share: frostBytes(cfg["share"]), GroupPublicKey: frostBytes(cfg["groupPublicKey"]), Threshold: th,
					PolicyAuthorityPublicKey: frostBytes(cfg["policyAuthorityPublicKey"]), SessionTtlMs: ttl, Now: func() float64 { return clock }, NonceStore: store})
			}
			svc, err := mk()
			if err != nil {
				return map[string]any{"ctor": map[string]any{"$throws": err.Error()}, "steps": []any{}}, nil
			}
			en := svc.Enrollment()
			ctor := map[string]any{"verificationShare": vecBytesOut(svc.VerificationShare()), "pop": svc.ProofOfPossession(),
				"enrollment": map[string]any{"identifier": en["identifier"], "publicKey": vecBytesOut(svc.VerificationShare()), "pop": en["pop"]}}
			steps := []any{}
			for _, o := range rsList(vecArg(a, 1)) {
				st := vecObj(o)
				switch st["op"] {
				case "round1":
					steps = append(steps, svc.Round1(st["req"]))
				case "round2":
					steps = append(steps, svc.Round2(st["req"]))
				case "clock":
					f, _ := jsNum(st["ms"])
					clock = 1000000 + f
					steps = append(steps, map[string]any{"clock": jsNumber(clock)})
				case "restart":
					ns, err := mk()
					if err != nil {
						return nil, err
					}
					svc = ns
					steps = append(steps, map[string]any{"restarted": true, "pop": svc.ProofOfPossession()})
				case "storeLoad":
					r, _ := store.Load(rsStr(st["sid"]))
					steps = append(steps, map[string]any{"live": r != nil})
				case "storeIsSpent":
					b, _ := store.IsSpent(rsStr(st["sid"]))
					steps = append(steps, map[string]any{"spent": b})
				}
			}
			return map[string]any{"ctor": ctor, "steps": steps}, nil
		}),
		"coordinator": frostCall(func(a []any) (any, error) {
			cfg := vecObj(vecArg(a, 0))
			out := map[string]any{"calls": []any{}}
			var transports []SignerTransport
			clock := newFrostFakeClock()
			defer clock.release()
			for _, x := range rsList(cfg["signers"]) {
				transports = append(transports, newFrostTestTransport(vecObj(x), clock))
			}
			sids := attStrings(cfg["sessionIds"])
			o := NetworkCoordinatorOptions{GroupPublicKey: frostBytes(cfg["groupPublicKey"]), Signers: transports, NewTimer: clock.newTimer,
				NewSessionID: func() (string, error) {
					if len(sids) == 0 {
						return "", errors.New("no more scripted session ids")
					}
					id := sids[0]
					sids = sids[1:]
					return id, nil
				}}
			if f, ok := attSafeInt(cfg["threshold"]); ok && f >= 1 && f < 1<<31 {
				o.Threshold = int(f)
			}
			if v, has := cfg["timeoutMs"]; has && v != nil {
				f := math.NaN()
				if x, ok := jsNum(v); ok {
					f = x
				}
				o.TimeoutMs = &f
			}
			if l, has := cfg["verificationShares"]; has {
				o.VerificationShares = []FrostVerificationShare{}
				for _, x := range rsList(l) {
					m := vecObj(x)
					id, _ := frostIDOf(m["identifier"])
					o.VerificationShares = append(o.VerificationShares, FrostVerificationShare{Identifier: id, PublicKey: frostBytes(m["publicKey"])})
				}
			}
			if l, has := cfg["enroll"]; has {
				o.Enroll = rsList(l)
				if o.Enroll == nil {
					o.Enroll = []any{}
				}
			}
			coord, err := NewNetworkCoordinator(o)
			if err != nil {
				out["ctor"] = frostErrOut(err)
				return out, nil
			}
			calls := []any{}
			for _, c := range rsList(cfg["calls"]) {
				m := vecObj(c)
				var ids []int64
				if l, ok := m["signerIds"].([]any); ok {
					ids = []int64{}
					for _, x := range l {
						id, _ := frostIDOf(x)
						ids = append(ids, id)
					}
				}
				var tm *float64
				if v := m["timeoutMs"]; v != nil {
					f := math.NaN()
					if x, ok := jsNum(v); ok {
						f = x
					}
					tm = &f
				}
				res, err := coord.Sign(frostBytes(m["message"]), m["allow"], ids, tm)
				if err != nil {
					calls = append(calls, frostErrOut(err))
					continue
				}
				signers := []any{}
				for _, id := range res.Signers {
					signers = append(signers, jsNumber(float64(id)))
				}
				calls = append(calls, map[string]any{"signature": vecBytesOut(res.Signature), "sessionId": res.SessionID, "signers": signers})
			}
			out["calls"] = calls
			return out, nil
		}),
		"decodeVerificationShares": frostCall(func(a []any) (any, error) {
			l, err := DecodeVerificationShares(frostEncodeWire(vecArg(a, 0)))
			if err != nil {
				return nil, err
			}
			out := []any{}
			for _, v := range l {
				out = append(out, map[string]any{"identifier": jsNumber(float64(v.Identifier)), "publicKey": vecBytesOut(v.PublicKey)})
			}
			return out, nil
		}),
	}
	replayed, unhandled := frostReplay(t, "ref-frost-net.json.gz", vecSeeded(fns), map[string]bool{"assertNonceStoreContract": true})
	if len(unhandled) > 0 {
		t.Fatalf("functions of the corpus without a Go entry point: %v", unhandled)
	}
	if replayed != 634 {
		t.Fatalf("the corpus holds %d cases, 634 are expected", replayed)
	}
}

func frostNetCommitmentOut(c FrostCommitment) map[string]any {
	return map[string]any{"identifier": jsNumber(float64(c.Identifier)), "hiding": vecBytesOut(c.Hiding), "binding": vecBytesOut(c.Binding)}
}

// frostEncodeWire is the identity: the wire decoders take the JSON the corpus carries (frostDecode would turn strings into bytes only
// for {"$bytes"} members, which wire values never have).
func frostEncodeWire(v any) any { return v }

// brokenFrostStore is a nonce store with exactly one defect, named by kind (the reference's broken stores).
type brokenFrostStore struct {
	kind  string
	live  map[string]FrostNonceRecord
	spent map[string]bool
}

func (b *brokenFrostStore) Create(id string, r FrostNonceRecord) error {
	if _, has := b.live[id]; has && b.kind != "create-overwrites" {
		return errors.New("exists")
	}
	if b.spent[id] && b.kind != "create-over-spent" {
		return errors.New("spent")
	}
	if b.kind == "create-aliases-input" {
		b.live[id] = r
	} else {
		b.live[id] = r.clone()
	}
	return nil
}

func (b *brokenFrostStore) Load(id string) (*FrostNonceRecord, error) {
	r, ok := b.live[id]
	if !ok {
		return nil, nil
	}
	if b.kind != "load-aliases" {
		r = r.clone()
	}
	return &r, nil
}

func (b *brokenFrostStore) Spend(id string) error {
	if _, has := b.live[id]; !has {
		if b.kind == "spend-unknown-ok" || (b.kind == "spend-twice-ok" && b.spent[id]) {
			return nil
		}
		return errors.New("not live")
	}
	delete(b.live, id)
	b.spent[id] = true
	return nil
}

func (b *brokenFrostStore) Drop(id string) error {
	delete(b.live, id)
	if b.kind == "drop-marks-spent" {
		b.spent[id] = true
	}
	return nil
}

func (b *brokenFrostStore) IsSpent(id string) (bool, error) {
	return b.kind == "unknown-reports-spent" || b.spent[id], nil
}

func (b *brokenFrostStore) reopen(s FrostNonceStore) FrostNonceStore {
	if b.kind == "spent-forgotten-on-restart" {
		clear(b.spent)
	}
	if b.kind == "live-lost-on-restart" {
		clear(b.live)
	}
	return s
}

// frostFaultyStore is a memory store whose one method fails with "store down".
type frostFaultyStore struct {
	FrostNonceStore
	fail string
}

func (f *frostFaultyStore) down(m string) error {
	if f.fail == m {
		return errors.New("store down")
	}
	return nil
}

func (f *frostFaultyStore) Create(id string, r FrostNonceRecord) error {
	if err := f.down("create"); err != nil {
		return err
	}
	return f.FrostNonceStore.Create(id, r)
}

func (f *frostFaultyStore) Load(id string) (*FrostNonceRecord, error) {
	if err := f.down("load"); err != nil {
		return nil, err
	}
	return f.FrostNonceStore.Load(id)
}

func (f *frostFaultyStore) Spend(id string) error {
	if err := f.down("spend"); err != nil {
		return err
	}
	return f.FrostNonceStore.Spend(id)
}

func (f *frostFaultyStore) Drop(id string) error {
	if err := f.down("drop"); err != nil {
		return err
	}
	return f.FrostNonceStore.Drop(id)
}

func (f *frostFaultyStore) IsSpent(id string) (bool, error) {
	if err := f.down("isSpent"); err != nil {
		return false, err
	}
	return f.FrostNonceStore.IsSpent(id)
}

// frostTestTransport is a signer behind a scripted transport: its service draws from the signer's own random script, and the transport
// may delay, fail, replay canned responses or rewrite the responses of a round (a hostile network).
type frostTestTransport struct {
	id       int64
	svc      *GuardianSignerService
	canned   map[string]any
	edits    []any
	delay    map[string]any
	throws   map[string]any
	mu       sync.Mutex
	r1Calls  int
	r2Calls  int
	initFail error
	clock    *frostFakeClock
}

func newFrostTestTransport(s map[string]any, clock *frostFakeClock) *frostTestTransport {
	id, _ := frostIDOf(s["identifier"])
	t := &frostTestTransport{clock: clock, id: id, canned: vecObj(s["canned"]), edits: rsList(s["edits"]), delay: vecObj(s["delay"]), throws: vecObj(s["throws"])}
	if t.canned == nil {
		var draws [][]byte
		for _, x := range rsList(s["rng"]) {
			draws = append(draws, frostBytes(x))
		}
		var store FrostNonceStore
		if s["store"] == "memory" {
			store = NewMemoryFrostNonceStore()
		}
		var ttl *float64
		if f, ok := jsNum(s["sessionTtlMs"]); ok {
			ttl = &f
		}
		th, _ := attSafeInt(s["threshold"])
		t.svc, t.initFail = NewGuardianSignerService(GuardianSignerOptions{Identifier: id, Share: frostBytes(s["share"]), GroupPublicKey: frostBytes(s["groupPublicKey"]), Threshold: int(th),
			PolicyAuthorityPublicKey: frostBytes(s["policyAuthorityPublicKey"]), SessionTtlMs: ttl, Now: func() float64 { return 1000000 }, NonceStore: store,
			Rand: func() ([]byte, error) {
				if len(draws) == 0 {
					return nil, errors.New("a draw past the script")
				}
				b := draws[0]
				draws = draws[1:]
				return b, nil
			}})
	}
	return t
}

func (t *frostTestTransport) Identifier() int64 { return t.id }

func (t *frostTestTransport) respond(round int, req map[string]any) (map[string]any, error) {
	key, name := "r1", "round1"
	t.mu.Lock()
	var n int
	if round == 2 {
		key, name = "r2", "round2"
		n = t.r2Calls
		t.r2Calls++
	} else {
		n = t.r1Calls
		t.r1Calls++
	}
	t.mu.Unlock()
	if ms, ok := jsNum(t.delay[key]); ok && ms > 0 {
		t.clock.sleep(ms)
	}
	if t.throws[key] == true {
		return nil, errors.New("unreachable")
	}
	var resp map[string]any
	if t.canned != nil {
		l := rsList(t.canned[name])
		if n >= len(l) || l[n] == "throw" {
			return nil, errors.New("unreachable")
		}
		resp, _ = vecJSON(l[n]).(map[string]any)
	} else {
		if t.initFail != nil {
			return nil, t.initFail
		}
		if round == 1 {
			resp, _ = vecJSON(t.svc.Round1(req)).(map[string]any)
		} else {
			resp, _ = vecJSON(t.svc.Round2(req)).(map[string]any)
		}
	}
	for _, e := range t.edits {
		em := vecObj(e)
		if r, _ := jsNum(em["round"]); int(r) != round {
			continue
		}
		path := rsList(em["path"])
		if len(path) == 0 {
			continue
		}
		var parent any = resp
		for _, k := range path[:len(path)-1] {
			m, ok := parent.(map[string]any)
			if !ok {
				parent = nil
				break
			}
			parent = m[rsStr(k)]
		}
		pm, ok := parent.(map[string]any)
		if !ok {
			continue
		}
		last := rsStr(path[len(path)-1])
		switch em["op"] {
		case "set":
			pm[last] = em["value"]
		case "delete":
			delete(pm, last)
		case "flip":
			str, _ := pm[last].(string)
			if raw, ok := DecodeB64uStrict(str, -1); ok && len(raw) > 0 {
				raw[0] ^= 1
				pm[last] = b64.EncodeToString(raw)
			}
		}
	}
	return resp, nil
}

func (t *frostTestTransport) Round1(req map[string]any) (map[string]any, error) {
	return t.respond(1, req)
}
func (t *frostTestTransport) Round2(req map[string]any) (map[string]any, error) {
	return t.respond(2, req)
}

// frostFakeClock is the virtual time of a coordinator replay: no case waits on the wall clock. A session deadline and a transport delay
// are both started at virtual time 0, so a delay longer than the deadline lets the deadline fire first (the delayed transport then
// stays blocked until the case ends) and any other delay finishes before it. The deadline is registered before any transport runs.
type frostFakeClock struct {
	mu       sync.Mutex
	deadline float64
	has      bool
	fired    chan struct{}
	once     sync.Once
	end      chan struct{}
}

func newFrostFakeClock() *frostFakeClock {
	return &frostFakeClock{fired: make(chan struct{}), end: make(chan struct{})}
}

func (c *frostFakeClock) newTimer(ms float64) (<-chan struct{}, func()) {
	c.mu.Lock()
	c.deadline, c.has = ms, true
	c.mu.Unlock()
	return c.fired, func() {}
}

// sleep returns at once when its delay ends before the deadline, else fires the deadline and blocks until the case is over.
func (c *frostFakeClock) sleep(ms float64) {
	c.mu.Lock()
	late := c.has && ms > c.deadline
	c.mu.Unlock()
	if late {
		c.once.Do(func() { close(c.fired) })
		<-c.end
	}
}

func (c *frostFakeClock) release() { close(c.end) }
