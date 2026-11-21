package pca

import (
	"crypto/ed25519"
	"crypto/sha256"
	"testing"
)

// Replays the reference's full evidence verification over the chargeback walkthrough bundle and its tampered, withheld and
// re-trusted variants: the whole findings report, report_digest included, is compared. Every `verifiers` member of the trust inputs
// is a constant {ok, reason?} verdict that overrides the core default of its artifact.
func TestEvidenceVerifyBundleVectors(t *testing.T) {
	fns := map[string]vecFn{
		"verifyEvidenceBundle": func(a []any) (any, error) {
			trust, _ := vecArg(a, 1).(map[string]any)
			return VerifyEvidenceBundle(vecArg(a, 0), trust), nil
		},
	}
	replayVectors(t, "ref-evidence-bundle-py.json.gz", fns)
}

// Replays the signed statement over the bundle reference: Ed25519 only, so the statement bytes are deterministic. The signing key
// is derived from a seed label, never stored.
func TestEvidenceSignedStatementVectors(t *testing.T) {
	fns := map[string]vecFn{
		"evidenceSignedStatement": func(a []any) (any, error) {
			spec := vecObj(vecArg(a, 1))
			h := sha256.Sum256([]byte("atlas-pca-conformance/" + vecStr(spec, "label")))
			o := ScittSignStatementOpts{Alg: vecStr(spec, "alg"), Key: ed25519.NewKeyFromSeed(h[:]), Issuer: vecStr(spec, "issuer")}
			if s, ok := spec["subject"].(string); ok {
				o.Subject = &s
			}
			b, err := EvidenceSignedStatement(vecArg(a, 0), o)
			if err != nil {
				return nil, err
			}
			return scTB(b), nil
		},
	}
	replayVectors(t, "ref-evidence-statement.json.gz", fns)
}
