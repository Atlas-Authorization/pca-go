package pca

// base differential oracle: undo windows, the pure layer (undo.go) against the TypeScript reference undo.ts
// (testdata/base-undo.json.gz, tools/pca-audit/oracles-base/undo-oracle.mts; comparison rules per fn in its header).
// The Go API is typed (UndoTokenRecord, UndoReceiptBody, UndoCompensation, UndoChainRecord, int64 clocks): a case whose
// argument cannot be represented in those types (a retyped / deleted member, a non-integer clock) is skipped and counted.

import (
	"testing"
)

func baseUndoStr(m map[string]any, k string, opt bool) (string, bool) {
	v, has := m[k]
	if !has {
		return "", opt
	}
	s, ok := v.(string)
	return s, ok
}

// baseUndoInt: a safe integer as int64 (-0 has no int64 form: such a case is skipped).
func baseUndoInt(v any) (int64, bool) {
	if !jsIsInt(v) {
		return 0, false
	}
	f, _ := jsNum(v)
	return int64(f), true
}

// baseUndoStrs reads the required string members (ok false when any is absent or not a string).
func baseUndoStrs(m map[string]any, keys ...string) ([]string, bool) {
	out := make([]string, len(keys))
	for i, k := range keys {
		s, ok := baseUndoStr(m, k, false)
		if !ok {
			return nil, false
		}
		out[i] = s
	}
	return out, true
}

func baseUndoTokenRec(v any) (UndoTokenRecord, bool) {
	m, ok := v.(map[string]any)
	if !ok {
		return UndoTokenRecord{}, false
	}
	s, ok := baseUndoStrs(m, "id", "aud", "principal", "compensation_digest")
	if !ok {
		return UndoTokenRecord{}, false
	}
	rd, ok := baseUndoStr(m, "render_digest", true)
	if v, has := m["render_digest"]; has && v == nil {
		rd, ok = "", true // `rec.render_digest ?? ''`: null is no render digest, as Go's ""
	}
	if !ok {
		return UndoTokenRecord{}, false
	}
	we, ok := baseUndoInt(m["window_end"])
	if !ok {
		return UndoTokenRecord{}, false
	}
	return UndoTokenRecord{ID: s[0], Aud: s[1], Principal: s[2], CompensationDigest: s[3], RenderDigest: rd, WindowEnd: we}, true
}

func TestBaseUndo(t *testing.T) {
	var k baseTally
	keys := map[string]*KeyPair{}
	keyOf := func(v any) (*KeyPair, bool) {
		s, ok := v.(string)
		if !ok {
			return nil, false
		}
		if kp, has := keys[s]; has {
			return kp, true
		}
		kp, err := KeyPairFromSeedB64u(s)
		if err != nil {
			kp = nil // the reference refuses a key that is not a 32-byte seed: Go's nil key is the same refusal
		}
		keys[s] = kp
		return kp, true
	}
	// sameErr compares a (value, error) result with a reference string result or throw
	sameStr := func(c *baseCase, got string, err error) {
		if th, _ := baseThrows(c.Out); th {
			if err == nil {
				k.fail(c, "want a throw, got %q", got)
			}
			return
		}
		if err != nil || got != c.Out {
			k.fail(c, "want %v, got %q (%v)", c.Out, got, err)
		}
	}
	sameObj := func(c *baseCase, got map[string]any, err error) {
		if th, code := baseThrows(c.Out); th {
			if err == nil {
				k.fail(c, "want a throw (%s), got %v", code, got)
			} else if code != "" && !baseHasCode(err.Error(), code) {
				k.fail(c, "want code %s, got %v", code, err)
			}
			return
		}
		if err != nil || baseCanon(got) != baseCanon(c.Out) {
			k.fail(c, "want %s, got %s (%v)", baseCanon(c.Out), baseCanon(got), err)
		}
	}
	baseEachSeeded(t, "base-undo.json.gz", func(c *baseCase) {
		a := c.Args
		switch c.Fn {
		case "compensationDigest":
			m, ok := a[0].(map[string]any)
			if !ok {
				k.skip(c.Fn, "typed port: the compensation is not an object")
				return
			}
			s, ok := baseUndoStrs(m, "verb", "resource", "undo_of", "def_digest")
			tp, tpOK := baseUndoStr(m, "target_param", true)
			params, pOK := m["params"].(map[string]any)
			if !ok || !tpOK || !pOK {
				k.skip(c.Fn, "typed port: a member is absent or not of its Go type")
				return
			}
			if v, has := m["target_param"]; has && v == "" {
				k.skip(c.Fn, "typed port: TargetParam \"\" is Go's absent target_param")
				return
			}
			k.run(c.Fn)
			got, err := CompensationDigest(UndoCompensation{Verb: s[0], Resource: s[1], Params: params, UndoOf: s[2], DefDigest: s[3], TargetParam: tp})
			sameStr(c, got, err)
		case "signUndoToken":
			rec, ok := baseUndoTokenRec(a[0])
			kp, kOK := keyOf(a[1])
			if !ok || !kOK {
				k.skip(c.Fn, "typed port: the record or key is not representable")
				return
			}
			k.run(c.Fn)
			got, err := SignUndoToken(rec, kp)
			sameObj(c, got, err)
		case "undoTokenCheck":
			rec, ok := baseUndoTokenRec(a[2])
			signer, sOK := a[1].(string)
			now, nOK := baseUndoInt(a[3])
			if !ok || !sOK || !nOK {
				k.skip(c.Fn, "typed port: record / signer / clock not representable")
				return
			}
			k.run(c.Fn)
			if got := UndoTokenCheck(a[0], signer, rec, now); got != c.Out {
				k.fail(c, "want %v, got %s", c.Out, got)
			}
		case "encodeUndoToken", "undoTokenDigest":
			m, ok := a[0].(map[string]any)
			if !ok {
				k.skip(c.Fn, "typed port: the token is not an object")
				return
			}
			k.run(c.Fn)
			if c.Fn == "encodeUndoToken" {
				got, err := EncodeUndoToken(m)
				sameStr(c, got, err)
			} else {
				got, err := UndoTokenDigest(m)
				sameStr(c, got, err)
			}
		case "decodeUndoToken":
			s, ok := a[0].(string)
			if !ok {
				k.skip(c.Fn, "typed port: the argument is not a string")
				return
			}
			k.run(c.Fn)
			got := DecodeUndoToken(s)
			if c.Out == nil || got == nil {
				if (c.Out == nil) != (got == nil) {
					k.fail(c, "want %v, got %v", c.Out, got)
				}
				return
			}
			if want := baseCanon(c.Out); want != baseCanon(got) {
				k.fail(c, "want %s, got %s", want, baseCanon(got))
			}
		case "signUndoReceipt":
			m, ok := a[0].(map[string]any)
			kp, kOK := keyOf(a[1])
			if !ok || !kOK {
				k.skip(c.Fn, "typed port: the body or key is not representable")
				return
			}
			s, sOK := baseUndoStrs(m, "record", "event", "state", "compensation_digest", "prev", "note")
			at, aOK := baseUndoInt(m["at"])
			if !sOK || !aOK {
				k.skip(c.Fn, "typed port: a body member is absent or not of its Go type")
				return
			}
			k.run(c.Fn)
			got, err := SignUndoReceipt(UndoReceiptBody{Record: s[0], Event: s[1], State: s[2], At: at, CompensationDigest: s[3], Prev: s[4], Note: s[5]}, kp)
			sameObj(c, got, err)
		case "undoReceiptDigest":
			m, ok := a[0].(map[string]any)
			if !ok {
				k.skip(c.Fn, "typed port: the receipt is not an object")
				return
			}
			k.run(c.Fn)
			got, err := UndoReceiptDigest(m)
			sameStr(c, got, err)
		case "verifyUndoReceipt":
			signer, ok := a[1].(string)
			if !ok {
				k.skip(c.Fn, "typed port: the signer is not a string")
				return
			}
			k.run(c.Fn)
			if got := VerifyUndoReceipt(a[0], signer); got != c.Out {
				k.fail(c, "want %v, got %v", c.Out, got)
			}
		case "undoReceiptChainError":
			m, ok := a[0].(map[string]any)
			signer, sOK := a[1].(string)
			var s []string
			if ok {
				s, ok = baseUndoStrs(m, "id", "compensation_digest", "state")
			}
			if !ok || !sOK {
				k.skip(c.Fn, "typed port: the record / signer is not representable")
				return
			}
			rs, _ := m["receipts"].([]any) // not an array = no receipts, as the reference
			k.run(c.Fn)
			got := UndoReceiptChainError(UndoChainRecord{ID: s[0], CompensationDigest: s[1], State: s[2], Receipts: rs}, signer)
			want, _ := c.Out.(string)
			if got != want {
				k.fail(c, "want %v, got %q", c.Out, got)
			}
		case "undoTransition":
			now, ok := jsNum(a[2])
			if !ok {
				k.skip(c.Fn, "typed port: the clock is not a number")
				return
			}
			k.run(c.Fn)
			got := UndoTransition(a[0], a[1], now)
			o := c.Out.(map[string]any)
			if got.Outcome != o["outcome"] {
				k.fail(c, "want %v, got %+v", o, got)
				return
			}
			switch got.Outcome {
			case "refused":
				if got.Code != o["code"] || got.Reason != o["reason"] {
					k.fail(c, "want %v %v, got %s %q", o["code"], o["reason"], got.Code, got.Reason)
				}
			case "applied":
				r, _ := o["receipt"].(map[string]any)
				if baseCanon(got.Record) != baseCanon(o["record"]) || got.Event != r["event"] || got.Note != r["note"] {
					k.fail(c, "want %s %v, got %s %s %q", baseCanon(o["record"]), r, baseCanon(got.Record), got.Event, got.Note)
				}
			case "replayed":
				if baseCanon(got.Record) != baseCanon(o["record"]) {
					k.fail(c, "want %s, got %s", baseCanon(o["record"]), baseCanon(got.Record))
				}
			}
		case "resolveUndoWindow":
			var req *float64
			if f, ok := jsNum(a[0]); ok {
				req = &f // a non-number request is absent, as the reference's typeof check
			}
			p, ok := a[1].(map[string]any)
			want, wOK := baseUndoInt(c.Out)
			if !ok || !wOK {
				k.skip(c.Fn, "typed port: the policy is not an object / the reference result is not an integer")
				return
			}
			var pol UndoWindowPolicy
			for _, x := range []struct {
				key string
				dst **float64
			}{{"minMs", &pol.MinMs}, {"maxMs", &pol.MaxMs}, {"defaultMs", &pol.DefaultMs}} {
				v, has := p[x.key]
				if !has || v == nil {
					continue
				}
				f, isNum := jsNum(v)
				if !isNum {
					ok = false
				}
				*x.dst = &f
			}
			if !ok {
				k.skip(c.Fn, "typed port: a policy member is not a number")
				return
			}
			k.run(c.Fn)
			if got := ResolveUndoWindow(req, pol); got != want {
				k.fail(c, "want %d, got %d", want, got)
			}
		default:
			k.fail(c, "unknown fn %s", c.Fn)
		}
	})
	k.finish(t)
}

// baseHasCode: Go errors carry the reference code as their "code: message" prefix.
func baseHasCode(msg, code string) bool {
	return len(msg) >= len(code) && msg[:len(code)] == code
}
