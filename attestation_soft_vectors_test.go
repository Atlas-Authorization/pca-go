package pca

import (
	"errors"
	"math"
	"strconv"
	"strings"
	"testing"
)

// Replay of the software attestation layer against the reference (ref-attestation-soft), every case: the binding value, the dev
// attestor and its documents, the registry, the single-use nonce store and its entropy gate, the agent-binding match, the verifier
// and its hook, the multi-root verifier, the evidence digest and its anchoring.
//
// The reference's legacy option that accepts an unpinned post-quantum key (allowUnboundPq) is NOT ported: the two cases the reference
// accepts only through it are asserted REFUSED here, with the count asserted. The typed Go API cannot hold a value of the wrong JS
// type, so the cases that pass one are mapped before the call to the closest typed value that is refused with the reference's text
// (a non-string holder becomes the empty one, a non-number epoch NaN, ...); a clock that is no safe integer is refused before the
// store is asked, as the reference's clock check does.

type attConstStore bool

func (c attConstStore) Consume(string) bool { return bool(c) }

// attLedger is the anchoring ledger of the cases: a Merkle log with a principal.
type attLedger struct {
	log       *MerkleLog
	principal string
}

func (l attLedger) Head() (int64, string) { return int64(l.log.Size()), l.log.Root() }
func (l attLedger) AppendCommitment(c string) (int64, error) {
	i, err := l.log.AppendCommitment(c)
	return int64(i), err
}
func (l attLedger) Principal() string { return l.principal }

func attTruthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case string:
		return t != ""
	}
	if f, ok := jsNum(v); ok {
		return f != 0 && !math.IsNaN(f)
	}
	return true
}

func attSafeInt(v any) (float64, bool) {
	f, ok := jsNum(v)
	return f, ok && f == math.Trunc(f) && math.Abs(f) <= maxSafeInt
}

func attStrings(v any) []string {
	var out []string
	for _, x := range rsList(v) {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// attExpected is the server-side binding of a corpus object; a member of the wrong type becomes the value Go refuses with the
// reference's text.
func attExpected(v any) ExpectedAttestationBinding {
	m := vecObj(v)
	e := ExpectedAttestationBinding{Epoch: math.NaN()}
	if m == nil {
		return e
	}
	e.HolderPub, _ = m["holderPub"].(string)
	e.GrantRef, _ = m["grantRef"].(string)
	e.Nonce, _ = m["nonce"].(string)
	if f, ok := jsNum(m["epoch"]); ok {
		e.Epoch = f
	}
	if f, ok := jsNum(m["nonceIssuedAt"]); ok {
		e.NonceIssuedAt = &f
	}
	return e
}

// attHW is the constant hardware verifier of a corpus spec ({result} or {throws}); nil when there is none.
func attHW(v any) AttestationHardwareVerifier {
	m := vecObj(v)
	if m == nil {
		return nil
	}
	if msg, ok := m["throws"].(string); ok {
		return AttestationHardwareFunc(func(_, _ map[string]any, _ int64, _ ExpectedAttestationBinding) HardwareResult { panic(msg) })
	}
	var hr HardwareResult
	if res := vecObj(m["result"]); res != nil {
		hr.OK, hr.Bound = res["ok"] == true, res["bound"] == true
		hr.Reason, _ = res["reason"].(string)
		hr.Measured = vecObj(res["measured"])
		if ha := vecObj(res["hostAsserted"]); ha != nil {
			hr.HostAsserted = map[string]string{}
			for k, x := range ha {
				hr.HostAsserted[k], _ = x.(string)
			}
		}
	}
	return AttestationHardwareFunc(func(_, _ map[string]any, _ int64, _ ExpectedAttestationBinding) HardwareResult { return hr })
}

func attSuite(v any) (*SuiteOpts, error) {
	sm := vecObj(v)
	if sm == nil {
		return nil, nil
	}
	s := &SuiteOpts{Alg: rsStr(sm["alg"])}
	if seed, ok := qvBytes(sm["pqSeed"]); ok && s.Alg != "ed25519" {
		pq, err := GeneratePqKeyPairFromSeed("ML-DSA-65", seed)
		if err != nil {
			return nil, err
		}
		s.Pq = pq
	}
	return s, nil
}

func attAttestor(secret, suite any) (*DevAttestor, error) {
	seed, ok := qvBytes(secret)
	if !ok {
		return nil, errors.New("the secret is bytes")
	}
	su, err := attSuite(suite)
	if err != nil {
		return nil, err
	}
	return CreateDevAttestor(seed, su)
}

func attIdentityOut(id *MeasuredIdentity) any {
	if id == nil {
		return nil
	}
	m := id.Map()
	if m["weights_measured"] == false { // the reference carries the member only when the source had it
		delete(m, "weights_measured")
	}
	return m
}

func attVerdictOut(v AttestationVerdict) map[string]any {
	out := map[string]any{"ok": v.OK, "present": v.Present, "bound": v.Bound}
	if v.Reason != "" {
		out["reason"] = v.Reason
	}
	if v.Identity != nil {
		out["identity"] = attIdentityOut(v.Identity)
	}
	return out
}

func attDocOf(v any) map[string]any {
	switch t := v.(type) {
	case map[string]any:
		return t
	case []any: // a present, but empty, document
		return map[string]any{}
	}
	return nil
}

func attNowOf(v any) float64 {
	if f, ok := jsNum(v); ok {
		return f
	}
	return math.NaN()
}

func attOptNum(v any) *float64 {
	if f, ok := jsNum(v); ok {
		return &f
	}
	return nil
}

func attPins(v any) map[string]string {
	m := vecObj(v)
	if m == nil {
		return nil
	}
	out := map[string]string{}
	for k, x := range m {
		out[k], _ = x.(string)
	}
	return out
}

func TestSoftwareAttestationMatchesTheReference(t *testing.T) {
	unbound := 0
	fns := map[string]vecFn{
		"constants": func([]any) (any, error) {
			return map[string]any{"ATTEST_ANCHOR_DOMAIN": AttestAnchorDomain, "ATTEST_BIND_DOMAIN": AttestBindDomain,
				"DEFAULT_NONCE_RETENTION_MS": jsNumber(float64(DefaultNonceRetentionMs)), "MAX_ATTESTATION_AGE_MS": jsNumber(float64(MaxAttestationAgeMs)),
				"MIN_ATTESTATION_NONCE_BYTES": jsNumber(float64(MinAttestationNonceBytes))}, nil
		},
		"attestationBinding": func(a []any) (any, error) {
			b, err := AttestationBindingBytes(attExpected(scDecode(vecArg(a, 0))))
			if err != nil {
				return nil, err
			}
			return vecBytesOut(b), nil
		},
		"attestationBindingB64u": func(a []any) (any, error) {
			return AttestationBindingB64u(attExpected(scDecode(vecArg(a, 0))))
		},
		"attestorPublicKey": func(a []any) (any, error) {
			att, err := attAttestor(vecArg(a, 0), vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			return att.PublicKey, nil
		},
		"attest": func(a []any) (any, error) {
			att, err := attAttestor(vecArg(a, 0), vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			cl := vecObj(scDecode(vecArg(a, 2)))
			for _, k := range []string{"model_id", "weights_digest", "runtime_measurement", "operator", "nonce", "issued_at", "expires_at"} {
				if _, ok := cl[k]; !ok { // an absent member cannot be canonicalized
					return nil, errors.New("canonicalize: unsupported type undefined")
				}
			}
			typed := true
			for _, k := range []string{"model_id", "weights_digest", "runtime_measurement", "operator", "nonce"} {
				if _, ok := cl[k].(string); !ok {
					typed = false
				}
			}
			iat, ok1 := attSafeInt(cl["issued_at"])
			exp, ok2 := attSafeInt(cl["expires_at"])
			if !typed || !ok1 || !ok2 { // a null member, a non-finite time: the same body, signed as the reference signs it
				body := map[string]any{"model_id": cl["model_id"], "weights_digest": cl["weights_digest"], "runtime_measurement": cl["runtime_measurement"],
					"operator": cl["operator"], "nonce": cl["nonce"], "issued_at": cl["issued_at"], "expires_at": cl["expires_at"], "attestor": att.PublicKey, "mode": "software"}
				return att.signBody(body)
			}
			c := AttestationClaims{ModelID: rsStr(cl["model_id"]), WeightsDigest: rsStr(cl["weights_digest"]), RuntimeMeasurement: rsStr(cl["runtime_measurement"]),
				Operator: rsStr(cl["operator"]), Nonce: rsStr(cl["nonce"]), IssuedAt: int64(iat), ExpiresAt: int64(exp)}
			if s, ok := cl["system_prompt_digest"].(string); ok {
				c.SystemPromptDigest = &s
			}
			if s, ok := cl["tool_manifest_digest"].(string); ok {
				c.ToolManifestDigest = &s
			}
			_, hasH := cl["holder_pub"]
			_, hasG := cl["grant_ref"]
			_, hasE := cl["epoch"]
			if hasH && hasG && hasE {
				h, g := rsStr(cl["holder_pub"]), rsStr(cl["grant_ref"])
				ep, ok := attSafeInt(cl["epoch"])
				if !ok {
					return nil, errors.New("binding: epoch must be a non-negative safe integer")
				}
				e := int64(ep)
				c.HolderPub, c.GrantRef, c.Epoch = &h, &g, &e
			}
			return att.Attest(c)
		},
		"attestationDigest": func(a []any) (any, error) {
			d := vecObj(scDecode(vecArg(a, 0)))
			if d == nil {
				return nil, errors.New("not a document")
			}
			return AttestationDigest(d)
		},
		"registry": func(a []any) (any, error) {
			var docs []map[string]any
			for _, x := range rsList(vecArg(a, 0)) {
				if m := vecObj(x); m != nil {
					docs = append(docs, m)
				}
			}
			resolve := AttestationRegistry(docs)
			out := []any{}
			for _, q := range rsList(vecArg(a, 1)) {
				d := resolve(map[string]any{"pcactn": map[string]any{"attestation": map[string]any{"quote_digest": q}}})
				if d == nil {
					out = append(out, nil)
				} else {
					out = append(out, d)
				}
			}
			return out, nil
		},
		"nonceStore": func(a []any) (any, error) {
			a = scDecode(a).([]any)
			max := 100000
			if m := vecArg(a, 0); m != nil {
				f, ok := attSafeInt(m)
				if !ok || f < 1 {
					return nil, errors.New("memoryNonceStore: max must be a positive integer (a store that retains nothing gives no replay protection)")
				}
				max = int(f)
			}
			var ret int64
			if o := vecObj(vecArg(a, 1)); o != nil && o["retentionMs"] != nil {
				f, ok := attSafeInt(o["retentionMs"])
				if !ok || f <= 0 {
					return nil, errors.New("memoryNonceStore: retentionMs must be a positive integer (ms)")
				}
				ret = int64(f)
			}
			var clock any = float64(0)
			store, err := NewMemoryNonceStore(max, MemoryNonceStoreOptions{RetentionMs: ret, Now: func() int64 { f, _ := attSafeInt(clock); return int64(f) }})
			if err != nil {
				return nil, err
			}
			out := []any{}
			for _, op := range rsList(vecArg(a, 2)) {
				o := rsList(op)
				if rsStr(vecArg(o, 0)) == "clock" {
					clock = vecArg(o, 1)
					out = append(out, nil)
					continue
				}
				n, isStr := vecArg(o, 1).(string)
				if _, ok := attSafeInt(clock); !isStr || !ok {
					out = append(out, false)
					continue
				}
				out = append(out, store.Consume(n))
			}
			return out, nil
		},
		"nonceEntropyOk": func(a []any) (any, error) {
			a = scDecode(a).([]any)
			min := 0
			switch m := vecArg(a, 1).(type) {
			case string: // Math.max coerces a numeric string
				if f, err := strconv.ParseFloat(strings.TrimSpace(m), 64); err == nil && !math.IsNaN(f) {
					min = int(math.Max(math.Min(f, 1<<30), 0))
				}
			case nil:
			default:
				if f, ok := jsNum(m); ok && !math.IsNaN(f) {
					min = int(math.Max(math.Min(f, 1<<30), 0))
				}
			}
			return NonceEntropyOk(vecArg(a, 0), min), nil
		},
		"requiresAttestation": func(a []any) (any, error) { return RequiresAttestation(scDecode(vecArg(a, 0))), nil },
		"nonceBinds": func(a []any) (any, error) {
			return NonceBinds(vecObj(scDecode(vecArg(a, 0))), vecObj(scDecode(vecArg(a, 1)))), nil
		},
		"matchAgentBinding": func(a []any) (any, error) {
			idm := vecObj(scDecode(vecArg(a, 0)))
			if idm == nil {
				return nil, errors.New("Cannot read properties of null (reading 'runtime_measurement')")
			}
			if r := MatchAgentBinding(MeasuredIdentityFromMap(idm), vecObj(scDecode(vecArg(a, 1)))); r != "" {
				return r, nil
			}
			return nil, nil
		},
		"verifyAttestation": func(a []any) (any, error) {
			in := vecObj(scDecode(vecArg(a, 0)))
			vi := VerifyAttestationInput{Document: attDocOf(in["document"]), Ctx: vecObj(in["ctx"]), Expected: attExpected(in["expected"]), NowMs: attNowOf(in["nowMs"]),
				TrustedAttestorKeys: attStrings(in["trustedAttestorKeys"]), PqPins: attPins(in["pqPins"]), HardwareVerifier: attHW(in["hardware"]),
				MaxNonceAgeMs: attOptNum(in["maxNonceAgeMs"]), ClockSkewMs: attOptNum(in["clockSkewMs"])}
			v := VerifyAttestation(vi)
			if in["allowUnboundPq"] == true && !v.OK && v.Reason == "attestation signature does not verify" {
				unbound++
				return map[string]any{"unboundRefused": true}, nil
			}
			return attVerdictOut(v), nil
		},
		"attestationHook": func(a []any) (any, error) {
			a = scDecode(a).([]any)
			o := vecObj(vecArg(a, 0))
			nowF, _ := jsNum(o["now"])
			now := int64(nowF)
			opts := AttestationVerifierOpts{TrustedAttestorKeys: attStrings(o["trustedAttestorKeys"]), PqPins: attPins(o["pqPins"]), HardwareVerifier: attHW(o["hardware"]),
				InsecureSelfDeclaredNonce: o["insecure_selfDeclaredNonce"] == true, MaxNonceAgeMs: attOptNum(o["maxNonceAgeMs"]), ClockSkewMs: attOptNum(o["clockSkewMs"]),
				Now: func() int64 { return now }}
			if f, ok := jsNum(o["minNonceBytes"]); ok && !math.IsNaN(f) {
				opts.MinNonceBytes = int(math.Max(math.Min(f, 1<<30), 0))
			}
			var docs []map[string]any
			for _, x := range rsList(o["docs"]) {
				if m := vecObj(x); m != nil {
					docs = append(docs, m)
				}
			}
			opts.ResolveDocument = AttestationRegistry(docs)
			switch b := o["binding"].(type) {
			case string: // "throws"
				opts.ExpectedBinding = func(map[string]any) *ExpectedAttestationBinding { panic(errors.New("boom")) }
			case map[string]any:
				by := vecObj(b["byNonce"])
				opts.ExpectedBinding = func(ctx map[string]any) *ExpectedAttestationBinding {
					q, _ := ctxMap(ctxMap(ctx, "pcactn"), "attestation")["quote_digest"].(string)
					if e, ok := by[q].(map[string]any); ok {
						x := attExpected(e)
						return &x
					}
					return nil
				}
			}
			if sc, ok := o["storeConsume"].(bool); ok {
				opts.NonceStore = attConstStore(sc)
			} else if so := vecObj(o["store"]); so != nil {
				max := 100000
				if f, ok := attSafeInt(so["max"]); ok {
					max = int(f)
				}
				var ret int64
				if f, ok := attSafeInt(so["retentionMs"]); ok {
					ret = int64(f)
				}
				st, err := NewMemoryNonceStore(max, MemoryNonceStoreOptions{RetentionMs: ret, Now: func() int64 { return now }})
				if err != nil {
					return nil, err
				}
				opts.NonceStore = st
			}
			hook := CreateAttestationVerifier(opts)
			var out []any
			for _, c := range rsList(vecArg(a, 1)) {
				r := hook.Verify(vecObj(c))
				m := map[string]any{"enforced": r.Enforced, "ok": r.OK, "present": r.Present, "bound": r.Bound}
				if r.Reason != "" {
					m["reason"] = r.Reason
				}
				out = append(out, m)
			}
			return out, nil
		},
		"multiRoot": func(a []any) (any, error) {
			a = scDecode(a).([]any)
			pol := vecObj(vecArg(a, 0))
			th := -1 // a threshold that is no integer is refused with the reference's text
			if f, ok := jsNum(pol["threshold"]); ok && f == math.Trunc(f) && math.Abs(f) < 1<<30 {
				th = int(f)
			}
			var roots []MultiRootAttestationRoot
			for _, x := range rsList(pol["roots"]) {
				r := vecObj(x)
				roots = append(roots, MultiRootAttestationRoot{ID: rsStr(r["id"]), Verifier: attHW(r["hw"]), Required: attTruthy(r["required"]), Suite: rsStr(r["suite"])})
			}
			m, err := CreateMultiRootVerifier(roots, th)
			if err != nil {
				return nil, err
			}
			in := vecObj(vecArg(a, 1))
			if in == nil {
				return map[string]any{"built": true}, nil
			}
			res := m.VerifyHardware(attDocOf(in["document"]), vecObj(in["ctx"]), int64(attNowOf(in["nowMs"])), attExpected(in["expected"]))
			return res.Wire(), nil
		},
		"attestationEvidenceDigest": func(a []any) (any, error) {
			ev, err := attEvidence(scDecode(vecArg(a, 0)))
			if err != nil {
				return nil, err
			}
			return AttestationEvidenceDigest(ev)
		},
		"anchorEvidence": func(a []any) (any, error) {
			a = scDecode(a).([]any)
			ev, err := attEvidence(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			op := vecObj(vecArg(a, 1))
			ao := AttestationAnchorOptions{InstanceID: rsStr(op["instanceId"]), Required: op["required"] == true}
			if op["ledger"] == "ok" {
				l := attLedger{log: NewMerkleLog(), principal: rsStr(op["principal"])}
				n, _ := attSafeInt(op["preload"])
				for i := 0; i < int(n); i++ {
					if _, err := l.AppendCommitment("c" + strconv.Itoa(i)); err != nil {
						return nil, err
					}
				}
				ao.Ledger = l
			}
			if seed, ok := qvBytes(op["guardianSeed"]); ok {
				ao.GuardianSeed = seed
			}
			if f, ok := jsNum(op["now"]); ok {
				if math.IsNaN(f) || math.IsInf(f, 0) { // a head over a non-finite time does not sign
					ao.SignTreeHead = func([]byte, map[string]any, *SuiteOpts) (map[string]any, error) {
						return nil, errors.New("signTreeHead: the timestamp is not a safe integer")
					}
				} else {
					ao.Now = func() int64 { return int64(f) }
				}
			}
			r, err := AnchorAttestationEvidence(ev, ao)
			if err != nil {
				return nil, err
			}
			out := map[string]any{"index": jsNumber(float64(r.Index)), "commit": r.Commit}
			if r.Sth != nil {
				out["sth"] = r.Sth
			}
			return out, nil
		},
	}
	cmp := map[string]func(want, got any) bool{
		"verifyAttestation": func(want, got any) bool {
			if vecObj(got)["unboundRefused"] == true {
				return vecObj(want)["ok"] == true // accepted by the reference only through the legacy option
			}
			return baseCanon(want) == baseCanon(got)
		},
	}
	text := map[string]bool{"attestationBinding": true, "attestationBindingB64u": true, "attestorPublicKey": true, "nonceStore": true, "multiRoot": true, "anchorEvidence": true}
	replayAll(t, "ref-attestation-soft.json.gz", 512, vecSeeded(fns), cmp, text)
	if unbound != 2 {
		t.Fatalf("%d unpinned-key cases were refused, 2 are expected", unbound)
	}
}

// attEvidence reads the evidence of a corpus object; a verification time that is no finite number cannot be canonicalized.
func attEvidence(v any) (VerifiedAttestationEvidence, error) {
	m := vecObj(v)
	f, ok := jsNum(m["verifiedAt"])
	if !ok || math.IsNaN(f) || math.IsInf(f, 0) {
		return VerifiedAttestationEvidence{}, errors.New("canonicalize: non-finite number")
	}
	return VerifiedAttestationEvidence{Identity: MeasuredIdentityFromMap(vecObj(m["identity"])), Binding: attExpected(m["binding"]),
		RootIDs: attStrings(m["rootIds"]), Suite: rsStr(m["suite"]), VerifiedAt: int64(f)}, nil
}
