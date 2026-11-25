package pca

// Replays the evidence reference corpus: shape validation, normal form, commitments-only form, digest, bundle reference, anchor leaves,
// the grant cap reader and the trust-input validators. The full replay is evidence_verify_vectors_test.go.

import "testing"

func evidNilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func TestEvidenceVectors(t *testing.T) {
	str := func(a []any, i int) string { s, _ := vecArg(a, i).(string); return s }
	fns := map[string]vecFn{
		"bundleShapeError":    func(a []any) (any, error) { return evidNilIfEmpty(EvidenceBundleShapeError(vecArg(a, 0))), nil },
		"normalizeBundle":     func(a []any) (any, error) { return NormalizeEvidenceBundle(vecArg(a, 0)) },
		"buildEvidenceBundle": func(a []any) (any, error) { return BuildEvidenceBundle(vecArg(a, 0)) },
		"commitmentForm":      func(a []any) (any, error) { return EvidenceCommitmentForm(vecArg(a, 0)) },
		"evidenceDigest":      func(a []any) (any, error) { return EvidenceBundleDigest(vecArg(a, 0)) },
		"evidenceRef": func(a []any) (any, error) {
			r, err := EvidenceRef(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			return r, nil
		},
		"evidenceAnchorCommit": func(a []any) (any, error) { return EvidenceAnchorCommit(str(a, 0)) },
		"anchorCommit":         func(a []any) (any, error) { return EvidenceAnchorCommitOf(str(a, 0), str(a, 1)) },
		"capOf":                func(a []any) (any, error) { return EvidenceCapOf(vecArg(a, 0), str(a, 1), str(a, 2)) },
		"principalsTrustError": func(a []any) (any, error) {
			return evidNilIfEmpty(EvidencePrincipalsTrustError(vecArg(a, 0), len(a) > 0)), nil
		},
		"accTrustError": func(a []any) (any, error) {
			return evidNilIfEmpty(EvidenceAccTrustError(vecArg(a, 0), len(a) > 0)), nil
		},
		"consts": func(a []any) (any, error) {
			return map[string]any{"EVIDENCE_DOMAIN": EvidenceDomain, "EVIDENCE_REPORT_DOMAIN": EvidenceReportDomain, "EVIDENCE_CONTENT_TYPE": EvidenceContentType}, nil
		},
	}
	replayVectors(t, "ref-evidence.json.gz", fns)
}
