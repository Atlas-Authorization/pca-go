package pca

import (
	"errors"
	"strings"
	"testing"
)

// Replay of the agent passport against the reference (ref-passport), every case: fingerprint, issuing, the binding match with its
// reasons, the registry, the trust score, the evidence binding, signing under three suites, verification with every reason and
// detail (revocation and hardware callbacks built from the corpus specs) and the assurance label. A reference throw requires a
// refusal.
//
// The reference's legacy option that accepts an unpinned post-quantum key (allowUnboundPq) is NOT ported: the case that the
// reference accepts only through it is asserted REFUSED here, with the count asserted. SignPassport takes its times as integers:
// the cases whose times are no safe integers (all refused by the reference) are refused here before the call.

type passportLabeled struct{ l AssuranceLabel }

func (p passportLabeled) Assurance() AssuranceLabel { return p.l }

func TestPassportMatchesTheReference(t *testing.T) {
	unbound := 0
	asMaps := func(v any) []map[string]any {
		var out []map[string]any
		for _, x := range rsList(v) {
			out = append(out, vecObj(x))
		}
		return out
	}
	fns := map[string]vecFn{
		"constants": func([]any) (any, error) {
			return map[string]any{"PASSPORT_SIG_DOMAIN": passportSigDomain, "PASSPORT_VERSION": jsNumber(1), "DEFAULT_PASSPORT_EVIDENCE_AGE_MS": jsNumber(float64(DefaultPassportEvidenceAgeMs))}, nil
		},
		"passportFingerprint": func(a []any) (any, error) {
			m, err := passportIdentity(scDecode(vecArg(a, 0)))
			if err != nil {
				return nil, err
			}
			return PassportFingerprint(m)
		},
		"issuePassport": func(a []any) (any, error) {
			m, err := passportIdentity(scDecode(vecArg(a, 0)))
			if err != nil {
				return nil, err
			}
			return IssuePassport(m)
		},
		"matchesBinding": func(a []any) (any, error) {
			p, b := vecObj(vecArg(a, 0)), vecObj(vecArg(a, 1))
			if p == nil || b == nil {
				return nil, errors.New("Cannot read properties of null")
			}
			ok, reasons := MatchesBinding(p, b)
			return map[string]any{"ok": ok, "reasons": rsStringsOut(reasons)}, nil
		},
		"registry": func(a []any) (any, error) {
			r := BuildRegistry(asMaps(vecArg(a, 0)))
			ops := rsList(vecArg(a, 1))
			out := make([]any, len(ops))
			for i, o := range ops {
				op := rsList(o)
				id, _ := vecArg(op, 1).(string)
				switch name, _ := vecArg(op, 0).(string); name {
				case "get":
					if p := r.Get(id); p != nil {
						out[i] = p
					}
				case "has":
					out[i] = r.Has(id)
				case "all":
					all := []any{}
					for _, p := range r.All() {
						all = append(all, p)
					}
					out[i] = all
				default:
					return nil, errors.New("unknown registry op " + name)
				}
			}
			return out, nil
		},
		"trustScore": func(a []any) (any, error) {
			if vecArg(a, 0) == nil {
				return nil, errors.New("Cannot read properties of null (reading 'hardware_rooted')")
			}
			var known []string
			if o := vecObj(vecArg(a, 1)); o != nil {
				for _, x := range rsList(o["knownOperators"]) {
					known = append(known, rsStr(x))
				}
				// JS knownOperators.includes(op) on a string is a substring test
				if ks, isStr := o["knownOperators"].(string); isStr {
					if op, _ := vecObj(vecArg(a, 0))["operator"].(string); strings.Contains(ks, op) {
						known = append(known, op)
					}
				}
			}
			return jsNumber(TrustScore(vecObj(vecArg(a, 0)), known)), nil
		},
		"passportEvidenceBinding": func(a []any) (any, error) {
			_, s0 := vecArg(a, 0).(string)
			_, s1 := vecArg(a, 1).(string)
			_, s2 := vecArg(a, 2).(string)
			if !s0 || !s1 || !s2 { // the reference builds the object from whatever it is given
				return map[string]any{"holderPub": vecArg(a, 1), "grantRef": "passport:" + jsValueString(vecArg(a, 0)), "epoch": jsNumber(0), "nonce": vecArg(a, 2)}, nil
			}
			b := PassportEvidenceBinding(rsStr(vecArg(a, 0)), rsStr(vecArg(a, 1)), rsStr(vecArg(a, 2)))
			return map[string]any{"holderPub": b.HolderPub, "grantRef": b.GrantRef, "epoch": jsNumber(float64(b.Epoch)), "nonce": b.Nonce}, nil
		},
		"signPassport": func(a []any) (any, error) {
			a = scDecode(vecResolveSeeds(a)).([]any)
			o := vecObj(vecArg(a, 1))
			secret, ok := qvBytes(o["issuerSecret"])
			if !ok {
				return nil, errors.New("issuerSecret is bytes")
			}
			key, err := KeyPairFromSeed(secret)
			if err != nil {
				return nil, err
			}
			times := map[string]*int64{}
			for _, k := range []string{"iat", "nbf", "exp"} {
				v, has := o[k]
				if !has {
					if k == "exp" {
						return nil, errors.New("iat/nbf/exp must be safe integers with exp after nbf")
					}
					continue
				}
				if !jsIsSafeInteger(v) {
					return nil, errors.New("iat/nbf/exp must be safe integers with exp after nbf")
				}
				f, _ := jsNum(v)
				n := int64(f)
				times[k] = &n
			}
			var suite *SuiteOpts
			if sm := vecObj(o["suite"]); sm != nil {
				suite = &SuiteOpts{Alg: rsStr(sm["alg"])}
				if seed, ok := qvBytes(sm["pqSeed"]); ok {
					if suite.Pq, err = GeneratePqKeyPairFromSeed("ML-DSA-65", seed); err != nil {
						return nil, err
					}
				}
			}
			return SignPassportAt(vecObj(vecArg(a, 0)), key, rsStr(o["subject"]), times["iat"], times["nbf"], *times["exp"], vecObj(o["evidence"]), suite)
		},
		"verifyPassport": func(a []any) (any, error) {
			a = scDecode(a).([]any)
			o := vecObj(vecArg(a, 1))
			var h PassportValueHooks
			switch r := o["revocation"].(type) {
			case map[string]any:
				if ids, has := r["revokedIds"]; has {
					h.Revocation = func(id, _, _ string) (any, error) {
						for _, x := range rsList(ids) {
							if x == id {
								return true, nil
							}
						}
						return false, nil
					}
				} else {
					h.Revocation = func(_, _, _ string) (any, error) { return r["revoked"], nil }
				}
			case string:
				if r == "throws" {
					h.Revocation = func(_, _, _ string) (any, error) { return nil, errors.New("revocation down") }
				}
			}
			if hw := vecObj(o["hardware"]); hw != nil {
				if msg, has := hw["throws"]; has {
					h.Attest = func(map[string]any, PassportBinding) (map[string]any, error) { return nil, errors.New(rsStr(msg)) }
				} else {
					res := vecObj(hw["result"])
					h.Attest = func(map[string]any, PassportBinding) (map[string]any, error) { return res, nil }
				}
			}
			v := VerifyPassportValue(vecArg(a, 0), o, h)
			if o["allowUnboundPq"] == true && v["ok"] != true && v["reason"] == "bad_signature" {
				unbound++
				return map[string]any{"unboundRefused": true}, nil
			}
			return v, nil
		},
		"passportAssurance": func(a []any) (any, error) {
			verdict := vecObj(vecArg(a, 0))
			var verifier any
			switch l := vecArg(a, 1).(type) {
			case map[string]any:
				verifier = passportLabeled{AssuranceLabel{Level: rsStr(l["level"]), Vendor: rsStr(l["vendor"])}}
			case nil: // the verifier carries no label
				verifier = passportLabeled{}
			}
			l := PassportAssurance(verdict["hardware_verified"] == true, verifier)
			out := map[string]any{"level": l.Level}
			if l.Vendor != "" {
				out["vendor"] = l.Vendor
			}
			return out, nil
		},
	}
	cmp := map[string]func(want, got any) bool{
		"verifyPassport": func(want, got any) bool {
			if vecObj(got)["unboundRefused"] == true {
				return vecObj(want)["ok"] == true // accepted by the reference only through the legacy option
			}
			return baseCanon(want) == baseCanon(got)
		},
	}
	replayAll(t, "ref-passport.json.gz", 516, fns, cmp, nil)
	if unbound != 1 {
		t.Fatalf("%d unpinned-key cases were refused, 1 is expected", unbound)
	}
}

// passportIdentity is the identity object of a passport as the reference reads it: an object whose model_id, operator and
// hardware_rooted members must exist (an undefined member has no canonical form).
func passportIdentity(v any) (map[string]any, error) {
	m := vecObj(v)
	if m == nil {
		return nil, errors.New("Cannot read properties of null (reading 'model_id')")
	}
	for _, k := range []string{"model_id", "operator", "hardware_rooted"} {
		if _, has := m[k]; !has {
			return nil, errors.New("canonicalize: unsupported type undefined")
		}
	}
	return m, nil
}
