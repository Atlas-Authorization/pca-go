package pca

import (
	"errors"
	"fmt"
	"math"
	"testing"
)

// Replay of the intent leftovers against the reference (ref-intent-misc2), every case: the shared strict-artifact helpers, the
// signed "ask the principal" question and its problem response, the classifier verdicts, policy and decision, the signing and digest
// half of the accumulator receipts and sequencer key sets, and admission and settlement through a session store. A reference refusal
// requires a refusal. Non-finite numbers travel in the corpus form {"$num": ...}.
//
// The reference's legacy option that accepts an unpinned post-quantum key (allowUnboundPq) is NOT ported: the one corpus case the
// reference accepts only through it is asserted REFUSED here, with the count asserted.

// imSafe turns a panic of a Go twin that mirrors a reference throw into a refusal.
func imSafe(f func(a []any) (any, error)) vecFn {
	return func(a []any) (res any, err error) {
		defer func() {
			if p := recover(); p != nil {
				res, err = nil, fmt.Errorf("refused: %v", p)
			}
		}()
		return f(scDecode(a).([]any))
	}
}

func imKey(v any) (*KeyPair, error) {
	b, ok := qvBytes(v)
	if !ok {
		return nil, errors.New("secret is bytes")
	}
	return KeyPairFromSeed(b)
}

// imSuite is the suite of a corpus spec {alg, pqSeed}: nil for none, an ML-DSA-65 key pair from the seed for a post-quantum suite.
func imSuite(v any) (*SuiteOpts, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, nil
	}
	alg, _ := m["alg"].(string)
	s := &SuiteOpts{Alg: alg}
	if seed, ok := qvBytes(m["pqSeed"]); ok && alg != "ed25519" {
		pq, err := GeneratePqKeyPairFromSeed("ML-DSA-65", seed)
		if err != nil {
			return nil, err
		}
		s.Pq = pq
	}
	return s, nil
}

func imNullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func imMap(v any) map[string]any { m, _ := v.(map[string]any); return m }

func imStrs(v any) []string {
	l, _ := v.([]any)
	out := make([]string, 0, len(l))
	for _, x := range l {
		s, _ := x.(string)
		out = append(out, s)
	}
	return out
}

func imPins(v any) map[string]string {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	out := map[string]string{}
	for k, x := range m {
		out[k], _ = x.(string)
	}
	return out
}

// imStore is the in-memory session store of the corpus.
type imStore struct {
	durable bool
	ev      map[string][]map[string]any
}

type imTx struct {
	s       *imStore
	session string
}

func (s *imStore) Durable() bool { return s.durable }
func (s *imStore) WithSession(session string, fn func(tx SessionTx) error) error {
	return fn(imTx{s, session})
}

func (t imTx) Events() ([]any, error) {
	out := []any{}
	for _, e := range t.s.ev[t.session] {
		out = append(out, ixCopyMap(e))
	}
	return out, nil
}

func (t imTx) Append(e map[string]any) error {
	t.s.ev[t.session] = append(t.s.ev[t.session], ixCopyMap(e))
	return nil
}

func (t imTx) SetStatus(id, status string) (bool, error) {
	for _, e := range t.s.ev[t.session] {
		if e["id"] == any(id) {
			e["status"] = status
			return true, nil
		}
	}
	return false, nil
}

func imAdmit(a []any) (any, error) {
	st := &imStore{durable: true, ev: map[string][]map[string]any{}}
	out := []any{}
	ops, _ := a[0].([]any)
	for _, o := range ops {
		op := o.([]any)
		switch op[0] {
		case "store":
			d := imMap(op[1])["durable"]
			st = &imStore{durable: d != "absent" && d != false, ev: map[string][]map[string]any{}}
			out = append(out, nil)
		case "admit":
			am := imMap(op[1])
			session, _ := am["session"].(string)
			adm := IntentAdmission{Session: session, Root: imMap(am["root"]), Event: imMap(am["event"]), AllowVolatile: am["requireDurable"] == false}
			if sc, has := am["schema"]; has && sc != nil {
				adm.Schema, adm.HaveSchema = sc, true
			}
			adm.Verify = func(acc map[string]any) (bool, any, error) {
				if am["verifyAs"] == "throws" {
					return false, nil, errors.New("verify boom")
				}
				out = append(out, map[string]any{"acc": acc})
				allow := imMap(am["verifyAs"])["allow"] == true
				return allow, allow, nil
			}
			v, err := AdmitIntentAction(st, adm)
			if err != nil {
				out = append(out, map[string]any{"$err": true})
			} else {
				out = append(out, map[string]any{"allow": v})
			}
		case "settle":
			s1, _ := op[1].(string)
			id, _ := op[2].(string)
			status, _ := op[3].(string)
			ok, err := SettleIntentEvent(st, s1, id, status)
			if err != nil {
				out = append(out, map[string]any{"$err": true})
			} else {
				out = append(out, ok)
			}
		case "events":
			s1, _ := op[1].(string)
			l := []any{}
			for _, e := range st.ev[s1] {
				l = append(l, ixCopyMap(e))
			}
			out = append(out, l)
		default:
			out = append(out, map[string]any{"$err": "op"})
		}
	}
	return out, nil
}

func imConstants() map[string]any {
	n := func(f float64) any { return jsNumber(f) }
	rx := func(s string) any { return map[string]any{"$regex": s} }
	return map[string]any{
		"DATA_CLASS_RE": rx(DataClassRe.String()), "INTENT_NAME_RE": rx(IntentNameRe.String()), "PARAM_SEGMENT_RE": rx(ParamSegmentRe.String()),
		"SUITE_MEMBERS": objStringsAny(suiteMembers), "FRICTIONS": objStringsAny(Frictions), "INTENT_ACTION_DOMAIN": walletActionDomain,
		"INTENT_PROBLEM_KINDS": objStringsAny(IntentProblemKinds), "INTENT_REQUIRED_DOMAIN": intentRequiredDomain, "PROBLEM_BASE": ProblemBase,
		"INTENT_CLASSIFIER_DOMAIN": IntentClassifierDomain, "INTENT_CLASSIFIER_REF_DOMAIN": IntentClassifierRefDomain,
		"MAX_CLASSIFIER_LABELS": n(maxClassifierLabels), "MAX_COMMITTED_CLASSES": n(maxCommittedClasses),
		"ACC_AGGS": objStringsAny(accAggs), "ACC_ID_RE": rx(AccIDRe.String()), "ACC_RECEIPT_CORE_DOMAIN": AccReceiptCoreDomain,
		"ACC_RECEIPT_DOMAIN": accReceiptDomain, "ACC_RECEIPT_REF_DOMAIN": accReceiptRefDomain, "ACC_RESERVE_DOMAIN": accReserveDomain,
		"ACC_SCOPES": objStringsAny(AccScopes), "DEFAULT_MAX_KEYSET_AGE_MS": n(defaultMaxKeySetAgeMs), "DEFAULT_MAX_RECEIPT_AGE_MS": n(defaultMaxReceiptAgeMs),
		"KID_RE": rx(KidRe.String()), "MAX_MONITOR_WITHIN": n(maxMonitorWithin), "MAX_RECEIPT_LIFETIME_MS": n(maxReceiptLifetimeMs),
		"MAX_SESSION_ACCUMULATORS": n(maxSessionAccumulators), "MAX_SESSION_MONITORS": n(maxSessionMonitors), "MONITOR_KINDS": objStringsAny(monitorKinds),
		"RECEIPT_SKEW_MS": n(receiptSkewMs), "SEQUENCER_KEYS_DOMAIN": sequencerKeysDomain, "SEQUENCER_KEYS_REF_DOMAIN": sequencerKeysRefDomain,
		"COUNTED_STATUSES": objStringsAny(CountedStatuses), "EVENT_STATUSES": objStringsAny(EventStatuses),
	}
}

func TestIntentMisc2MatchesTheReference(t *testing.T) {
	str := func(s string, ok bool) (any, error) {
		if !ok {
			return nil, errors.New("no stable encoding")
		}
		return s, nil
	}
	nilIfEmpty := func(s string) (any, error) { return imNullable(s), nil }
	unbound := 0
	lastUnbound := false
	fns := map[string]vecFn{
		"constants": func([]any) (any, error) { return imConstants(), nil },
		// ---- intent-artifacts
		"isPathSegment": imSafe(func(a []any) (any, error) { return IsPathSegment(jsValueString(a[0])), nil }), // the reference tests String(v)
		"isPlainObject": imSafe(func(a []any) (any, error) { return IsPlainObject(a[0]), nil }),
		"isSafeInt":     imSafe(func(a []any) (any, error) { return IsSafeInt(a[0]), nil }),
		"isScalar":      imSafe(func(a []any) (any, error) { return IsScalar(a[0]), nil }),
		"isClock":       imSafe(func(a []any) (any, error) { return IsClock(a[0]), nil }),
		"scalarEq":      imSafe(func(a []any) (any, error) { return ScalarEq(a[0], a[1]), nil }),
		"utf8Len": imSafe(func(a []any) (any, error) {
			s, _ := a[0].(string)
			return Utf8Len(s), nil
		}),
		"isBoundedString": imSafe(func(a []any) (any, error) {
			m := jsF(a[1])
			if math.IsNaN(m) {
				return false, nil
			}
			return IsBoundedString(a[0], int(math.Max(math.Min(m, 1e9), -1e9))), nil
		}),
		"isDigest": imSafe(func(a []any) (any, error) { return IsDigest(a[0]), nil }),
		"closedMembers": imSafe(func(a []any) (any, error) {
			where := "object"
			if w, ok := a[3].(string); ok {
				where = w
			}
			return nilIfEmpty(closedMembersMsg(imMap(a[0]), where, imStrs(a[1]), imStrs(a[2])...))
		}),
		"pinPqOk": imSafe(func(a []any) (any, error) { return PinPqOk(map[string]any{"pq_pk": a[0]}), nil }),
		"artifactSuiteError": imSafe(func(a []any) (any, error) {
			m, ok := a[0].(map[string]any)
			if !ok {
				return "artifact must be an object", nil
			}
			return nilIfEmpty(ArtifactSuiteError(m))
		}),
		"artifactMessage": imSafe(func(a []any) (any, error) {
			d, _ := a[0].(string)
			b, ok := ArtifactMessage(d, imMap(a[1]))
			if !ok {
				return nil, errors.New("non-canonical body")
			}
			return vecBytesOut(b), nil
		}),
		"signArtifact": imSafe(func(a []any) (any, error) {
			key, err := imKey(a[2])
			if err != nil {
				return nil, err
			}
			su, err := imSuite(a[3])
			if err != nil {
				return nil, err
			}
			d, _ := a[0].(string)
			return SignArtifact(d, imMap(a[1]), key, su)
		}),
		"verifyArtifactSig": imSafe(func(a []any) (any, error) {
			d, _ := a[0].(string)
			art, ok := a[1].(map[string]any)
			if !ok {
				return false, nil
			}
			switch p := a[2].(type) {
			case string:
				return VerifyArtifactSig(d, art, p, nil), nil
			case map[string]any:
				return VerifyArtifactSig(d, art, p["pk"], p["pq_pk"]), nil
			}
			return false, nil
		}),
		"artifactRef": imSafe(func(a []any) (any, error) {
			d, _ := a[0].(string)
			s, _ := a[1].(string)
			return str(ArtifactRef(d, s, a[2]))
		}),
		"publicKeyB64u": imSafe(func(a []any) (any, error) {
			k, err := imKey(a[0])
			if err != nil {
				return nil, err
			}
			return PublicKeyB64u(k), nil
		}),
		"resolveParamPath": imSafe(func(a []any) (any, error) {
			v, found := ResolveParamPath(a[0], a[1])
			if !found {
				return map[string]any{"found": false}, nil
			}
			return map[string]any{"found": true, "value": v}, nil
		}),
		"isParamPath": imSafe(func(a []any) (any, error) { return IsParamPath(a[0]), nil }),
		"setNested": imSafe(func(a []any) (any, error) {
			m := imMap(a[0])
			root := imMap(m["root"])
			path, _ := m["path"].(string)
			ok := SetNested(root, path, m["value"])
			return map[string]any{"ok": ok, "root": root}, nil
		}),
		"ownGet": imSafe(func(a []any) (any, error) {
			v, _ := OwnGet(imMap(a[0]), jsValueString(a[1]))
			return v, nil
		}),
		"nullRecord": imSafe(func([]any) (any, error) { return NullRecord(), nil }),
		// ---- intent-required
		"intentActionDigest": imSafe(func(a []any) (any, error) {
			m, ok := a[0].(map[string]any)
			if !ok {
				return nil, errors.New("Cannot read properties of null (reading 'verb')")
			}
			return IntentActionDigest(m), nil
		}),
		"cellCoordsError": imSafe(func(a []any) (any, error) { return nilIfEmpty(CellCoordsError(a[0])) }),
		"intentRequiredShapeError": imSafe(func(a []any) (any, error) {
			if imMap(a[1])["signed"] == false {
				return nilIfEmpty(IntentRequiredShapeError(a[0]))
			}
			return nilIfEmpty(walletIRShapeError(a[0]))
		}),
		"signIntentRequired": imSafe(func(a []any) (any, error) {
			key, err := imKey(a[2])
			if err != nil {
				return nil, err
			}
			su, err := imSuite(a[3])
			if err != nil {
				return nil, err
			}
			kid, _ := a[1].(string)
			return SignIntentRequired(imMap(a[0]), kid, key, su)
		}),
		"verifyIntentRequired":   imSafe(func(a []any) (any, error) { return VerifyIntentRequired(a[0], a[1], a[2]), nil }),
		"verifyIntentRequiredAt": imSafe(func(a []any) (any, error) { return VerifyIntentRequiredAt(a[0], a[1], a[2]), nil }),
		"intentProblem": imSafe(func(a []any) (any, error) {
			kind := jsValueString(a[0])
			var detail *string
			o := imMap(a[1])
			if d, has := o["detail"]; has {
				s := jsValueString(d)
				detail = &s
			}
			return IntentProblem(kind, detail, imMap(o["body"]))
		}),
		// ---- intent-classifier
		"classifierContentDigest": imSafe(func(a []any) (any, error) { s, err := ClassifierContentDigest(a[0]); return s, err }),
		"signClassifierVerdict": imSafe(func(a []any) (any, error) {
			key, err := imKey(a[1])
			if err != nil {
				return nil, err
			}
			su, err := imSuite(a[2])
			if err != nil {
				return nil, err
			}
			return SignClassifierVerdict(imMap(a[0]), key, su)
		}),
		"validateClassifierVerdictWire": imSafe(func(a []any) (any, error) { return nilIfEmpty(ValidateClassifierVerdictWire(a[0])) }),
		"classifierVerdictRef":          imSafe(func(a []any) (any, error) { return str(ClassifierVerdictRef(a[0])) }),
		"validateClassifierPolicy":      imSafe(func(a []any) (any, error) { return nilIfEmpty(ValidateClassifierPolicy(a[0])) }),
		"classifierCheckActive": imSafe(func(a []any) (any, error) {
			m, ok := a[0].(map[string]any)
			if !ok {
				return false, nil
			}
			return ClassifierCheckActive(m["committed"], progMember(m["policy"], "classifiers")), nil
		}),
		"decideClassifierDimensions": imSafe(func(a []any) (any, error) { return DecideClassifierDimensions(a[0]), nil }),
		"verifyClassifierAttestation": imSafe(func(a []any) (any, error) {
			var att *HardwareResult
			if m, ok := a[1].(map[string]any); ok {
				att = &HardwareResult{OK: m["ok"] == true, Bound: m["bound"] == true, Measured: imMap(m["measured"])}
				att.Reason, _ = m["reason"].(string)
			}
			return VerifyClassifierAttestation(imMap(a[0]), att, imMap(a[2])), nil
		}),
		// ---- intent-acc leftovers
		"monitorStates": imSafe(func(a []any) (any, error) {
			if r := MonitorStates(imMap(a[0])); r != nil { // an unknown kind is JS undefined, not an empty list
				return r, nil
			}
			return nil, nil
		}),
		"monitorInitialState": imSafe(func(a []any) (any, error) { return MonitorInitialState(imMap(a[0])), nil }),
		"distinctKey": imSafe(func(a []any) (any, error) {
			s, ok := DistinctKey(a[0])
			if !ok {
				return nil, nil
			}
			return s, nil
		}),
		"sortedDistinct": imSafe(func(a []any) (any, error) { return SortedDistinct(imStrs(a[0])), nil }),
		"signAccReceipt": imSafe(func(a []any) (any, error) {
			key, err := imKey(a[1])
			if err != nil {
				return nil, err
			}
			su, err := imSuite(a[2])
			if err != nil {
				return nil, err
			}
			return SignAccReceipt(imMap(a[0]), key, su)
		}),
		"accReceiptDigest":     imSafe(func(a []any) (any, error) { return str(AccReceiptDigest(a[0])) }),
		"accReceiptCoreDigest": imSafe(func(a []any) (any, error) { s, err := AccReceiptCoreDigest(imMap(a[0])); return s, err }),
		"verifyReceiptSignature": imSafe(func(a []any) (any, error) {
			signer, _ := a[1].(string)
			pin := imMap(a[2])
			ok := VerifyAccReceiptSignature(imMap(a[0]), signer, imPins(pin["pqPins"]))
			lastUnbound = pin["allowUnboundPq"] == true
			return ok, nil
		}),
		"signSequencerKeySet": imSafe(func(a []any) (any, error) {
			key, err := imKey(a[1])
			if err != nil {
				return nil, err
			}
			su, err := imSuite(a[2])
			if err != nil {
				return nil, err
			}
			return SignSequencerKeySet(imMap(a[0]), key, su)
		}),
		"sequencerKeySetDigest": imSafe(func(a []any) (any, error) { return str(SequencerKeySetDigest(a[0])) }),
		"verifyKeySet": imSafe(func(a []any) (any, error) {
			pq, has := a[2].(string)
			return VerifySequencerKeySet(a[0], a[1], pq, has), nil
		}),
		// ---- intent-history leftovers
		"accContextFor": imSafe(func(a []any) (any, error) {
			cand := imMap(a[2])
			hist, _ := a[1].([]any)
			sc, has := a[3], a[3] != nil
			return AccContextFor(imMap(a[0]), hist, imMap(cand["params"]), cand["t"], sc, has)
		}),
		"admit": imSafe(func(a []any) (any, error) { return imAdmit(a) }),
	}
	cmp := map[string]func(want, got any) bool{
		"verifyReceiptSignature": func(want, got any) bool {
			if lastUnbound && want == true {
				unbound++
				return got == false // accepted by the reference only through the unpinned-key opt-out: refused here
			}
			return baseCanon(want) == baseCanon(got)
		},
	}
	replayAll(t, "ref-intent-misc2.json.gz", 770, vecSeeded(fns), cmp, nil)
	if unbound != 1 {
		t.Fatalf("expected the 1 corpus case accepted only through the unpinned post-quantum key opt-out, saw %d", unbound)
	}
}
