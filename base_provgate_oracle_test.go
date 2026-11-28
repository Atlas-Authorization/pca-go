package pca

// base differential oracle: build provenance as a K1 discharge (provenance_gate.go) against the TypeScript reference
// provenance-gate.ts (testdata/base-provgate.json.gz, tools/pca-audit/oracles-base/provgate-oracle.mts).

import (
	"bytes"
	"testing"
)

func basePGBytes(v any) []byte {
	s, _ := v.(string)
	b, err := b64.DecodeString(s)
	if err != nil {
		panic("base provgate: bad base64url fixture " + s)
	}
	return b
}

func TestBaseProvGate(t *testing.T) {
	var k baseTally
	baseEach(t, "base-provgate.json.gz", func(c *baseCase) {
		a := c.Args
		k.run(c.Fn)
		switch c.Fn {
		case "provenanceFactsError", "provenancePolicyError":
			got := ProvenanceFactsError(a[0])
			if c.Fn == "provenancePolicyError" {
				got = ProvenancePolicyError(a[0])
			}
			if want, _ := c.Out.(string); got != want {
				k.fail(c, "want %v, got %q", c.Out, got)
			}
		case "provenanceGate":
			r := ProvenanceGate(a[0])
			got := map[string]any{"ok": r.OK}
			if r.OK {
				got["level"] = r.Level
				got["claims"] = r.Claims
			} else {
				got["code"] = r.Code
			}
			if baseCanon(normalizeJSON(got)) != baseCanon(c.Out) {
				k.fail(c, "want %s, got %s", baseCanon(c.Out), baseCanon(normalizeJSON(got)))
			}
		case "verifyRfc9162Inclusion":
			idx, ok1 := baseI64(a[1])
			size, ok2 := baseI64(a[2])
			if !ok1 || !ok2 {
				k.fail(c, "fixture index/size not integers")
				return
			}
			var proof [][]byte
			for _, p := range a[3].([]any) {
				proof = append(proof, basePGBytes(p))
			}
			if got := VerifyRFC9162Inclusion(basePGBytes(a[0]), idx, size, proof, basePGBytes(a[4])); got != c.Out {
				k.fail(c, "want %v, got %v", c.Out, got)
			}
		case "rfc9162LeafHash":
			if got := RFC9162LeafHash(basePGBytes(a[0])); !bytes.Equal(got, baseBytes(c.Out)) {
				k.fail(c, "want %v, got %s", c.Out, b64.EncodeToString(got))
			}
		case "provenanceCaveat":
			m := a[0].(map[string]any)
			s := func(key string) string { x, _ := m[key].(string); return x }
			o := ProvenanceCaveatOptions{ID: s("id"), Issuer: s("issuer"), SourceRepo: s("source_repo"), OIDCIssuer: s("oidc_issuer"), Bind: s("bind")}
			o.MinLevel, _ = baseUndoInt(m["min_level"])
			o.TTLMs, _ = baseUndoInt(m["ttl_ms"])
			if ids, ok := m["builder_ids"].([]any); ok {
				o.BuilderIDs = []string{}
				for _, x := range ids {
					o.BuilderIDs = append(o.BuilderIDs, x.(string))
				}
			}
			o.NoRuntime = m["require_runtime"] == false
			if got := normalizeJSON(ProvenanceCaveat(o)); baseCanon(got) != baseCanon(c.Out) {
				k.fail(c, "want %s, got %s", baseCanon(c.Out), baseCanon(got))
			}
		default:
			k.fail(c, "unknown fn %s", c.Fn)
		}
	})
	k.finish(t)
}
