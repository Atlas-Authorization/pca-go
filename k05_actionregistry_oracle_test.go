package pca

// k05 differential oracle: the action-kit registry layer (actions_registry.go: evolution records, registry signatures,
// re-approvals, action pins, packs, the pack tracker, rule 22, pack proofs) against the TypeScript reference action-pin.ts +
// pca-actions pack/registry/rule22 (testdata/k05-actionregistry.json.gz, ~170 MB inflated, streamed;
// tools/pca-audit/k05-oracles/actionregistry-oracle.mts). A case with `textPrefix` carries an engine-specific message tail:
// the decision must match and the message must START WITH the prefix. packTracker compares each step exactly (reason included); its keys are the reference ALLKEYS, read from the `verifyRegistrySig/ml ok` case.

import (
	"strings"
	"testing"
)

// k05RegWithout drops member k (the free-text reason a textPrefix case compares by prefix only).
func k05RegWithout(v any, k string) any {
	m, ok := v.(map[string]any)
	if !ok {
		return v
	}
	out := map[string]any{}
	for kk, x := range m {
		if kk != k {
			out[kk] = x
		}
	}
	return out
}

func TestK05ActionRegistry(t *testing.T) {
	var k k05Tally
	var allKeys any
	// msg compares a message (string | null) exactly, or by textPrefix
	msg := func(c *k05Case, got string) {
		want, _ := c.Out.(string)
		if p, ok := c.C["textPrefix"].(string); ok {
			if !strings.HasPrefix(got, p) {
				k.fail(c, "want prefix %q, got %q", p, got)
			}
			return
		}
		if got != want && !k05SameUnknown(want, got) {
			k.fail(c, "want %v, got %q", c.Out, got)
		}
	}
	// obj compares a result object; with textPrefix its reason by prefix
	obj := func(c *k05Case, got map[string]any) {
		want := c.Out
		if p, ok := c.C["textPrefix"].(string); ok {
			r, _ := got["reason"].(string)
			if !strings.HasPrefix(r, p) {
				k.fail(c, "want reason prefix %q, got %q", p, r)
			}
			want, got = k05RegWithout(want, "reason"), k05RegWithout(got, "reason").(map[string]any)
		}
		if g := k05Canon(normalizeJSON(got)); g != k05Canon(want) {
			k.fail(c, "want %s, got %s", k05Canon(want), g)
		}
	}
	throwsOr := func(c *k05Case, got any, err error) {
		if th, code := k05Throws(c.Out); th {
			if err == nil {
				k.fail(c, "want a throw (%s), got %s", code, k05Canon(normalizeJSON(got)))
			} else if p, ok := c.C["textPrefix"].(string); ok && !strings.HasPrefix(err.Error(), p) {
				k.fail(c, "want message prefix %q, got %v", p, err)
			} else if code != "" && !k05HasCode(err.Error(), code) {
				k.fail(c, "want code %s, got %v", code, err)
			}
			return
		}
		if err != nil {
			k.fail(c, "want %s, got error %v", k05Canon(c.Out), err)
			return
		}
		if g := k05Canon(normalizeJSON(got)); g != k05Canon(c.Out) {
			k.fail(c, "want %s, got %s", k05Canon(c.Out), g)
		}
	}
	verbsOf := func(defs []any) []any {
		out := make([]any, len(defs))
		for i, d := range defs {
			out[i] = d.(map[string]any)["verb"]
		}
		return out
	}
	k05Each(t, "k05-actionregistry.json.gz", func(c *k05Case) {
		a := c.Args
		switch c.Fn {
		case "compareVersions":
			k.run(c.Fn)
			n, err := compareVersions(a[0].(string), a[1].(string))
			sign := int64(0)
			if n < 0 {
				sign = -1
			} else if n > 0 {
				sign = 1
			}
			throwsOr(c, sign, err)
		case "packDefs":
			p, ok := a[0].(map[string]any)
			if !ok {
				k.skip(c.Fn, "typed port: the pack is not an object")
				return
			}
			k.run(c.Fn)
			sh, _ := a[1].(map[string]any)
			var defs []any
			var err error
			if pn := k05Call(func() { defs, err = packDefs(p, sh) }); pn != "" {
				k.fail(c, "panicked: %s", pn)
				return
			}
			var got any
			if err == nil {
				got = verbsOf(defs)
			}
			throwsOr(c, got, err)
		case "evolutionRecordError":
			k.run(c.Fn)
			msg(c, evolutionRecordError(a[0], a[1] == true))
		case "evolutionDiffDigest":
			r, ok := a[0].(map[string]any)
			if !ok {
				k.skip(c.Fn, "typed port: the record is not an object")
				return
			}
			k.run(c.Fn)
			d, ok := evolutionDiffDigest(r)
			if !ok || d != c.Out {
				k.fail(c, "want %v, got %q (%v)", c.Out, d, ok)
			}
		case "verifyRegistrySig":
			if c.Name == "verifyRegistrySig/ml ok" {
				allKeys = a[3]
			}
			dom, ok1 := a[0].(string)
			sig, ok2 := a[2].(map[string]any)
			if !ok1 || !ok2 {
				k.skip(c.Fn, "typed port: domain / sig not representable")
				return
			}
			k.run(c.Fn)
			msg(c, verifyRegistrySig(dom, a[1], sig, a[3]))
		case "verifyEvolutionRecord":
			k.run(c.Fn)
			msg(c, verifyEvolutionRecord(a[0], a[1]))
		case "reapprovalValid":
			k.run(c.Fn)
			if got := reapprovalValid(a[0], a[1], a[2], a[3], a[4]); got != c.Out {
				k.fail(c, "want %v, got %v", c.Out, got)
			}
		case "actionPinError":
			k.run(c.Fn)
			msg(c, actionPinError(a[0]))
		case "decidePin":
			k.run(c.Fn)
			obj(c, decidePin(a[0].(map[string]any)))
		case "packShapeError":
			k.run(c.Fn)
			msg(c, packShapeError(a[0], a[1] == true))
		case "verifyPack":
			k.run(c.Fn)
			sh, _ := a[2].(map[string]any)
			digest, _, reason := verifyPack(a[0], a[1], sh)
			got := map[string]any{"ok": reason == ""}
			if reason == "" {
				defs, _ := packDefs(a[0].(map[string]any), sh)
				got["digest"], got["verbs"] = digest, verbsOf(defs)
			} else {
				got["reason"] = reason
			}
			obj(c, got)
		case "packTracker":
			if allKeys == nil {
				k.fail(c, "the verifyRegistrySig/ml ok case (ALLKEYS) was not seen first")
				return
			}
			k.run(c.Fn)
			tr := newPackTracker(allKeys)
			want := c.Out.([]any)
			for i, sv := range a[0].([]any) {
				s := sv.([]any)
				sh, _ := s[1].(map[string]any)
				got := tr.accept(s[0], sh)
				w := want[i]
				if k05Canon(normalizeJSON(got)) != k05Canon(w) {
					k.fail(c, "step %d: want %s, got %s", i, k05Canon(w), k05Canon(normalizeJSON(got)))
				}
			}
		case "rule22Decide":
			doc, ok1 := a[0].(map[string]any)
			verb, ok2 := a[1].(string)
			if !ok1 || !ok2 {
				k.skip(c.Fn, "typed port: doc / verb not representable")
				return
			}
			g, _ := a[2].(map[string]any)
			ctx, ok3 := a[3].([]any)
			if !ok3 {
				k.skip(c.Fn, "typed port: context is a []any (a non-list context cannot be passed)")
				return
			}
			k.run(c.Fn)
			msg(c, rule22Decide(doc, verb, g, ctx))
		case "verifyPackProof":
			root, ok1 := a[0].(string)
			d, ok2 := a[2].(string)
			if !ok1 || !ok2 {
				k.skip(c.Fn, "typed port: root / digest not a string")
				return
			}
			pf, _ := a[1].(map[string]any)
			k.run(c.Fn)
			if got := verifyPackProof(root, pf, d); got != c.Out {
				k.fail(c, "want %v, got %v", c.Out, got)
			}
		default:
			k.fail(c, "unknown fn %s", c.Fn)
		}
	})
	k.finish(t)
}
