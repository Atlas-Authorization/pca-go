package pca

// base differential oracle: the caveat language v2 (caveat_lang.go) and the K1 request headers (PresentedK1) against the
// TypeScript reference caveat-lang.ts / require-pca.ts presentedK1 (testdata/base-caveatlang.json.gz,
// tools/pca-audit/oracles-base/caveatlang-oracle.mts). Typed bindings (DischargeBinding, NarrowBinding, DeriveInput, K1Input,
// K1Context) are built from the JSON arguments; a member Go cannot represent is skipped and counted.

import (
	"net/http"
	"testing"
)

func baseCLStrs(v any) ([]string, bool) {
	xs, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		s, ok := x.(string)
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

func baseCLPins(v any) ([]DischargePin, bool) {
	if v == nil {
		return nil, true
	}
	list, ok := v.([]any)
	if !ok {
		return nil, false
	}
	var pins []DischargePin
	for _, x := range list {
		p, ok := x.(map[string]any)
		if !ok {
			return nil, false
		}
		pk, ok1 := p["pk"].(string)
		label, ok2 := p["label"].(string)
		class, ok3 := p["class"].(string)
		if !ok1 || !ok2 || !ok3 {
			return nil, false
		}
		pin := DischargePin{PinnedSigner: PinnedSigner{PK: pk}, Label: label, Class: class}
		pin.PQPK, _ = p["pq_pk"].(string)
		pin.SpiffeID, _ = p["spiffe_id"].(string)
		pins = append(pins, pin)
	}
	return pins, true
}

// baseCLK1 is nil for a k1 that is not an object (no K1 input); ok false when a member is not representable.
func baseCLK1(raw any) (*K1Input, bool) {
	k, isObj := raw.(map[string]any)
	if !isObj {
		return nil, true
	}
	var in K1Input
	var ok bool
	if in.Pins, ok = baseCLPins(k["pins"]); !ok {
		return nil, false
	}
	if d, has := k["discharges"]; has {
		if in.Discharges, ok = d.([]any); !ok {
			return nil, false
		}
	}
	in.Narrow, in.HasNarrow = k["narrow"]
	in.ActionDigest, _ = k["action_digest"].(string)
	if rv, has := k["revoked_discharges"]; has {
		if in.RevokedDischarges, ok = baseCLStrs(rv); !ok {
			return nil, false
		}
	}
	in.SpiffeID, _ = k["spiffe_id"].(string)
	if h, has := k["history"]; has {
		if in.History, ok = h.([]any); !ok {
			return nil, false
		}
	}
	return &in, true
}

func baseCLStrList(xs []string) []any {
	out := make([]any, len(xs))
	for i, x := range xs {
		out[i] = x
	}
	return out
}

func baseCLBound(bs []BoundCaveat) []any {
	out := make([]any, len(bs))
	for i, b := range bs {
		out[i] = map[string]any{"caveat": b.Caveat, "hop": int64(b.Hop), "cap_hash": b.CapHash}
	}
	return out
}

func TestBaseCaveatLang(t *testing.T) {
	var k baseTally
	eq := func(c *baseCase, got any) {
		if g := baseCanon(normalizeJSON(got)); g != baseCanon(c.Out) {
			k.fail(c, "want %s, got %s", baseCanon(c.Out), g)
		}
	}
	strOrNull := func(c *baseCase, got string) {
		if want, _ := c.Out.(string); got != want {
			k.fail(c, "want %v, got %q", c.Out, got)
		}
	}
	baseEach(t, "base-caveatlang.json.gz", func(c *baseCase) {
		a := c.Args
		switch c.Fn {
		case "spiffeIdError":
			k.run(c.Fn)
			strOrNull(c, SpiffeIDError(a[0]))
		case "needsDischargeError":
			k.run(c.Fn)
			strOrNull(c, NeedsDischargeError(a[0]))
		case "dischargeShapeError":
			k.run(c.Fn)
			strOrNull(c, DischargeShapeError(a[0]))
		case "narrowShapeError":
			k.run(c.Fn)
			strOrNull(c, NarrowShapeError(a[0]))
		case "maxUsesError":
			k.run(c.Fn)
			strOrNull(c, MaxUsesError(a[0]))
		case "spiffeBoundError":
			k.run(c.Fn)
			strOrNull(c, SpiffeBoundError(a[0]))
		case "deriveError":
			k.run(c.Fn)
			strOrNull(c, DeriveError(a[0]))
		case "maxUsesSlotKey":
			cp, ok1 := a[0].(string)
			id, ok2 := a[1].(string)
			i, ok3 := baseUndoInt(a[2])
			if !ok1 || !ok2 || !ok3 {
				k.skip(c.Fn, "typed port: (string, string, int) arguments only")
				return
			}
			k.run(c.Fn)
			if got := MaxUsesSlotKey(cp, id, int(i)); got != c.Out {
				k.fail(c, "want %v, got %q", c.Out, got)
			}
		case "evaluateDerive":
			cv, ok := a[0].(map[string]any)
			in, ok2 := a[1].(map[string]any)
			now, ok3 := jsNum(in["now"])
			if !ok || !ok2 || !ok3 {
				k.skip(c.Fn, "typed port: caveat / input not representable")
				return
			}
			inp := DeriveInput{Now: now}
			inp.Action, _ = in["action"].(map[string]any)
			inp.History, _ = in["history"].([]any) // not an array = no history, as the reference
			if cl, has := in["claims"].(map[string]any); has {
				inp.Claims = map[string]map[string]any{}
				for id, x := range cl {
					m, isObj := x.(map[string]any)
					if !isObj {
						ok = false
					}
					inp.Claims[id] = m
				}
			}
			if !ok {
				k.skip(c.Fn, "typed port: a claims entry is not an object")
				return
			}
			k.run(c.Fn)
			res, known := EvaluateDerive(cv, inp)
			var got any
			if known {
				got = res
			}
			if got != c.Out {
				k.fail(c, "want %v, got %v", c.Out, got)
			}
		case "verifyDischarge":
			b, ok := a[2].(map[string]any)
			var bind DischargeBinding
			var ok2, ok3 bool
			if ok {
				bind.Pins, ok2 = baseCLPins(b["pins"])
				if _, isArr := b["pins"].([]any); !isArr {
					ok2 = false // Go's Pins slice has no "not an array" (the reference's 'no issuer is pinned'); both refuse
				}
				bind.Now, ok3 = jsNum(b["now"])
				bind.CapHash, _ = b["cap_hash"].(string)
				bind.ActionDigest, _ = b["action_digest"].(string)
				if rv, has := b["revoked"]; has {
					var okR bool
					if bind.Revoked, okR = baseCLStrs(rv); !okR {
						ok = false
					}
				}
			}
			if !ok || !ok2 || !ok3 {
				k.skip(c.Fn, "typed port: binding not representable (e.g. revoked as a string)")
				return
			}
			k.run(c.Fn)
			r := VerifyDischarge(a[0], a[1], bind)
			got := map[string]any{"ok": r.OK}
			if r.OK {
				got["digest"], got["claims"] = r.Digest, r.Claims
			} else {
				got["reason"] = r.Reason
			}
			eq(c, got)
		case "verifyNarrow":
			b, ok := a[3].(map[string]any)
			now, ok2 := jsNum(b["now"])
			if !ok || !ok2 {
				k.skip(c.Fn, "typed port: binding not representable")
				return
			}
			ad, _ := b["action_digest"].(string)
			k.run(c.Fn)
			r := VerifyNarrow(a[0], a[1], a[2], NarrowBinding{Now: now, ActionDigest: ad})
			got := map[string]any{"ok": r.OK}
			if r.OK {
				got["caveats"] = r.Caveats
			} else {
				got["reason"] = r.Reason
			}
			eq(c, got)
		case "boundCaveats":
			k.run(c.Fn)
			var chain any
			if len(a) > 1 {
				chain = a[1]
			}
			bs, ok := BoundCaveats(a[0], chain)
			var got any
			if ok {
				got = baseCLBound(bs)
			}
			eq(c, got)
		case "dischargeRequests":
			k.run(c.Fn)
			var chain any
			if len(a) > 1 {
				chain = a[1]
			}
			digest := ""
			if len(a) > 2 {
				digest, _ = a[2].(string)
			}
			rs := DischargeRequests(a[0], chain, digest)
			out := make([]any, len(rs))
			for i, r := range rs {
				out[i] = r
			}
			eq(c, out)
		case "evaluateK1", "evaluateCaveatsK1":
			k1, ok := baseCLK1(a[2])
			if !ok {
				k.skip(c.Fn, "typed port: k1 member not representable")
				return
			}
			k.run(c.Fn)
			ctx, _ := a[3].(map[string]any)
			if c.Fn == "evaluateCaveatsK1" {
				allow, failed := EvaluateCaveatsK1(a[0], a[1], k1, ctx)
				eq(c, map[string]any{"allow": allow, "failed": baseCLStrList(failed)})
				return
			}
			now := 0.5 // no numeric clock: not a safe integer, refused as the reference
			if f, isNum := jsNum(ctx["now"]); isNum {
				now = f
			}
			action, _ := ctx["action"].(map[string]any)
			r := EvaluateK1(a[0], a[1], k1, K1Context{Now: now, Action: action})
			plain := r.Plain
			if plain == nil {
				plain = []any{}
			}
			eq(c, map[string]any{"ok": r.OK, "failed": baseCLStrList(r.Failed), "reasons": baseCLStrList(r.Reasons), "plain": plain, "bound": baseCLBound(r.Bound)})
		case "presentedK1":
			hm, ok := a[0].(map[string]any)
			if !ok {
				k.skip(c.Fn, "typed port: headers not an object")
				return
			}
			canon := map[string]bool{}
			for name := range hm {
				if canon[http.CanonicalHeaderKey(name)] {
					// a plain object can hold PCA-Discharges and pca-discharges (the reference reads the lowercase one); an
					// http.Header folds them into ONE header sent twice, which Go refuses
					k.skip(c.Fn, "typed port: two spellings of one header are one repeated header in http.Header (refused)")
					return
				}
				canon[http.CanonicalHeaderKey(name)] = true
			}
			h := http.Header{}
			for name, x := range hm {
				s, isStr := x.(string)
				if !isStr {
					ok = false
				}
				h.Add(name, s)
			}
			if !ok {
				k.skip(c.Fn, "typed port: a header value is not a string")
				return
			}
			k.run(c.Fn)
			in, err := PresentedK1(h)
			got := map[string]any{"ok": err == nil}
			if err == nil {
				v := map[string]any{}
				if in.Discharges != nil {
					v["discharges"] = in.Discharges
				}
				if in.HasNarrow {
					v["narrow"] = in.Narrow
				}
				got["value"] = v
			}
			eq(c, got)
		default:
			k.fail(c, "unknown fn %s", c.Fn)
		}
	})
	k.finish(t)
}
