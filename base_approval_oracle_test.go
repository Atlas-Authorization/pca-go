package pca

// base differential oracle: the canonical approval render (approval.go) against the TypeScript reference approval-render.ts
// (testdata/base-approval.json.gz, tools/pca-audit/oracles-base/approval-oracle.mts; comparison rules per fn in its header).
// spcExpectation / cibaApprovalDetails: Go has no Secure Payment Confirmation / CIBA profile helpers (skipped, counted).

import (
	"testing"
)

func TestBaseApproval(t *testing.T) {
	var k baseTally
	str := func(c *baseCase, got string, err error) {
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
	obj := func(c *baseCase, got map[string]any, err error, panicked string) {
		if panicked != "" {
			k.fail(c, "panicked: %s (reference %v)", panicked, baseCanon(c.Out))
			return
		}
		if th, code := baseThrows(c.Out); th {
			if err == nil {
				k.fail(c, "want a throw (%s), got %s", code, baseCanon(got))
			} else if code != "" && !baseHasCode(err.Error(), code) {
				k.fail(c, "want code %s, got %v", code, err)
			}
			return
		}
		want := c.Out
		if m, ok := want.(map[string]any); ok {
			if b := baseBytes(m["challenge"]); b != nil { // the batch challenge: Go returns it as base64url
				cp := map[string]any{}
				for kk, v := range m {
					cp[kk] = v
				}
				cp["challenge"] = b64.EncodeToString(b)
				want = cp
			}
		}
		if err != nil || baseCanon(got) != baseCanon(want) {
			k.fail(c, "want %s, got %s (%v)", baseCanon(want), baseCanon(got), err)
		}
	}
	baseEachSeeded(t, "base-approval.json.gz", func(c *baseCase) {
		a := c.Args
		switch c.Fn {
		case "approvalRenderShapeError":
			k.run(c.Fn)
			want, _ := c.Out.(string)
			if got := ApprovalRenderShapeError(a[0]); got != want {
				k.fail(c, "want %v, got %q", c.Out, got)
			}
		case "approvalRenderDigest":
			k.run(c.Fn)
			got, err := ApprovalRenderDigest(a[0])
			str(c, got, err)
		case "approvalChallengeB64u", "bindingWords":
			s0, ok := a[0].(string)
			s1 := ""
			if c.Fn == "approvalChallengeB64u" {
				var ok1 bool
				s1, ok1 = a[1].(string)
				ok = ok && ok1
			}
			if !ok {
				k.skip(c.Fn, "typed port: a digest argument is not a string")
				return
			}
			k.run(c.Fn)
			if c.Fn == "bindingWords" {
				got, err := BindingWords(s0)
				str(c, got, err)
			} else {
				got, err := ApprovalChallenge(s0, s1)
				str(c, got, err)
			}
		case "validateDef":
			k.run(c.Fn)
			want, _ := c.Out.(string)
			if got := validateDef(a[0]); got != want {
				k.fail(c, "want %v, got %q", c.Out, got)
			}
		case "renderApproval":
			def, ok := a[0].(map[string]any)
			if !ok {
				k.skip(c.Fn, "typed port: the def is not an object")
				return
			}
			k.run(c.Fn)
			var got map[string]any
			var err error
			p := baseCall(func() { got, err = RenderApproval(def, a[1], false) })
			obj(c, got, err, p)
		case "psd2Linking":
			r, ok := a[0].(map[string]any)
			if !ok {
				k.skip(c.Fn, "typed port: the render is not an object")
				return
			}
			k.run(c.Fn)
			var got map[string]any
			var err error
			p := baseCall(func() { got, err = Psd2Linking(r) })
			obj(c, got, err, p)
		case "minorToDecimal":
			m, ok1 := baseI64(a[0])
			e, ok2 := baseI64(a[1])
			if !ok1 || !ok2 {
				k.skip(c.Fn, "typed (int64, int64) port: an argument is not a JSON integer (the reference refuses them all)")
				return
			}
			k.run(c.Fn)
			got, err := MinorToDecimal(m, e)
			str(c, got, err)
		case "approvalBatch":
			items, ok := a[0].([]any)
			if !ok {
				k.skip(c.Fn, "typed port: the items are not an array")
				return
			}
			k.run(c.Fn)
			var got map[string]any
			var err error
			p := baseCall(func() { got, err = ApprovalBatch(items) })
			obj(c, got, err, p)
		case "spcExpectation", "cibaApprovalDetails":
			k.skip(c.Fn, "Go has no SPC / CIBA approval profile helpers")
		default:
			k.fail(c, "unknown fn %s", c.Fn)
		}
	})
	k.finish(t)
}
