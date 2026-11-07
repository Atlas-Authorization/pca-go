package pca

// k05 differential oracle: the cross-domain agent mesh (mesh.go) and the Merkle primitives under it (VerifyLedgerConsistency,
// VerifyNonMembership) against the TypeScript reference mesh.ts / ledger.ts / revocation.ts (testdata/k05-mesh.json.gz,
// tools/pca-audit/k05-oracles/mesh-oracle.mts). Reasons are compared exactly.

import (
	"testing"
)

func k05MeshAuthority(e meshAuthority) map[string]any {
	strs := func(xs []string) []any {
		out := make([]any, len(xs))
		for i, x := range xs {
			out[i] = x
		}
		return out
	}
	m := map[string]any{"prefixes": strs(e.prefixes)}
	if e.hasAct {
		m["actions"] = strs(e.actions)
	}
	if e.hasAmount {
		m["maxAmount"] = e.maxAmount
	}
	if e.hasExp {
		m["expiresAt"] = e.expiresAt
	}
	if e.hasAud {
		m["audience"] = strs(e.audience)
	}
	if e.hasHops {
		m["maxHops"] = e.maxHops
	}
	return m
}

func TestK05Mesh(t *testing.T) {
	var k k05Tally
	eq := func(c *k05Case, got any) {
		if g := k05Canon(normalizeJSON(got)); g != k05Canon(c.Out) {
			k.fail(c, "want %s, got %s", k05Canon(c.Out), g)
		}
	}
	k05Each(t, "k05-mesh.json.gz", func(c *k05Case) {
		a := c.Args
		switch c.Fn {
		case "verifyMeshProof":
			k.run(c.Fn)
			v := VerifyMeshProof(a[0], a[1])
			got := map[string]any{"ok": v.OK}
			if !v.OK {
				got["reason"] = v.Reason
				if v.Hop >= 0 {
					got["hop"] = int64(v.Hop)
				}
			}
			eq(c, got)
		case "checkHeadAdvance":
			k.run(c.Fn)
			var proof any
			if len(a) > 2 {
				proof = a[2]
			}
			got := meshCheckHeadAdvance(a[0], a[1], proof)
			if want, _ := c.Out.(string); got != want {
				k.fail(c, "want %v, got %q", c.Out, got)
			}
		case "verifyLedgerConsistency":
			k.run(c.Fn)
			if got := VerifyLedgerConsistency(a[0], a[1], a[2]); got != c.Out {
				k.fail(c, "want %v, got %v", c.Out, got)
			}
		case "verifyNonMembership":
			root, ok1 := a[0].(string)
			id, ok2 := a[2].(string)
			if !ok1 || !ok2 {
				k.skip(c.Fn, "typed port: root / id not a string")
				return
			}
			k.run(c.Fn)
			if got := VerifyNonMembership(root, a[1], id); got != c.Out {
				k.fail(c, "want %v, got %v", c.Out, got)
			}
		case "effectiveAuthority":
			k.run(c.Fn)
			e, errText := meshEffective(a[0])
			if errText != "" {
				eq(c, map[string]any{"error": errText})
			} else {
				eq(c, k05MeshAuthority(e))
			}
		default:
			k.fail(c, "unknown fn %s", c.Fn)
		}
	})
	k.finish(t)
}
