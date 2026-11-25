package pca

import (
	"errors"
	"math"
	"testing"
)

// Replay of the approval half of natural-language policy authoring against the reference (ref-nl-approval), every case: the catalog
// digest, the draft binding and digests, policyFromNL and draftPolicyFromNL over a fixed completion, approval v2 and the legacy v1,
// loadApprovedPolicy with every rejection code, and the agent minted from an approved draft (only the deterministic envelope
// members are compared: the grant's goal salt is random). A reference refusal requires a refusal; an agent refusal carries the
// same text.

func nlCompletion(raw string) NLCompletion {
	return func(string) (string, error) {
		if raw == "THROWS" {
			return "", errors.New("llm down")
		}
		return raw, nil
	}
}

func nlModel(v any) *string {
	if s, ok := v.(string); ok {
		return &s
	}
	return nil
}

func nlApprovalOpts(v any) NLApprovalOptions {
	var o NLApprovalOptions
	m, _ := scDecode(v).(map[string]any)
	// Number.isFinite does not coerce: a present value that is not a number is not finite (null is `?? default`)
	num := func(x any) *float64 {
		f := math.NaN()
		if v, ok := jsNum(x); ok {
			f = v
		}
		return &f
	}
	if x, has := m["now"]; has && x != nil {
		o.Now = num(x)
	}
	if x, has := m["ttlMs"]; has && x != nil {
		o.TtlMs = num(x)
	}
	return o
}

func nlLoadOpts(v any) LoadApprovedOptions {
	var o LoadApprovedOptions
	m, _ := v.(map[string]any)
	if l, ok := m["reviewers"].([]any); ok {
		for _, r := range l {
			s, _ := r.(string)
			o.Reviewers = append(o.Reviewers, s)
		}
	}
	if x, has := m["extras"]; has && x != nil {
		o.Catalog = ixNlCatalogOf(x)
	}
	if x, has := m["now"]; has {
		f := objToNumber(scDecode(x))
		o.Now = &f
	}
	return o
}

func nlKeyOfLabel(label any) (*KeyPair, error) {
	s, _ := label.(string)
	k, _ := vecSeedValue(map[string]any{"$seed": s})
	return KeyPairFromSeed(progSeedKey(k))
}

func TestNLApprovalMatchesTheReference(t *testing.T) {
	fns := map[string]vecFn{
		"constants": func([]any) (any, error) {
			return map[string]any{"NL_APPROVAL_DOMAIN": NLApprovalDomain, "NL_APPROVAL_DOMAIN_V2": NLApprovalDomainV2,
				"MAX_NL_OUTPUT_BYTES": jsNumber(MaxNLOutputBytes), "MAX_NL_APPROVAL_TTL_MS": jsNumber(MaxNLApprovalTTLMs)}, nil
		},
		"catalogDigest": func(a []any) (any, error) {
			s, err := NLCatalogDigest(ixNlCatalogOf(vecArg(a, 0)))
			return s, err
		},
		"draftBinding": func(a []any) (any, error) {
			s, _ := vecArg(a, 0).(string)
			return NLDraftBinding(s, ixNlCatalogOf(vecArg(a, 1)), nlModel(vecArg(a, 2)))
		},
		"draftDigestV2": func(a []any) (any, error) {
			return NLDraftDigestV2(vecArg(a, 0), vecArg(a, 1), vecArg(a, 2), vecArg(a, 3))
		},
		"draftDigest": func(a []any) (any, error) { return NLDraftDigest(vecArg(a, 0), vecArg(a, 1), vecArg(a, 2)) },
		"policyFromNL": func(a []any) (any, error) {
			s, _ := vecArg(a, 0).(string)
			raw, _ := vecArg(a, 1).(string)
			return PolicyFromNL(PolicyFromNLRequest{Instruction: s, Complete: nlCompletion(raw), Catalog: ixNlCatalogOf(vecArg(a, 2)), Model: nlModel(vecArg(a, 3))})
		},
		"draftPolicyFromNL": func(a []any) (any, error) {
			s, _ := vecArg(a, 0).(string)
			raw, _ := vecArg(a, 1).(string)
			return DraftPolicyFromNL(PolicyFromNLRequest{Instruction: s, Complete: nlCompletion(raw), Catalog: ixNlCatalogOf(vecArg(a, 2)), Model: nlModel(vecArg(a, 3))})
		},
		"approveDraft": func(a []any) (any, error) {
			m, _ := vecArg(a, 1).(map[string]any)
			return ApproveNLDraft(vecArg(a, 0), progSeedKey(m["$bytes"]), nlApprovalOpts(vecArg(a, 2)))
		},
		"approveDraftLegacy": func(a []any) (any, error) {
			m, _ := vecArg(a, 1).(map[string]any)
			return ApproveNLDraftLegacyV1(vecArg(a, 0), progSeedKey(m["$bytes"]), nlApprovalOpts(vecArg(a, 2)))
		},
		"loadApproved": func(a []any) (any, error) {
			return LoadApprovedPolicy(vecArg(a, 0), vecArg(a, 1), nlLoadOpts(vecArg(a, 2))), nil
		},
		"agentFromApproved": func(a []any) (any, error) {
			r, _ := vecArg(a, 0).(map[string]any)
			principal, err := nlKeyOfLabel(r["principalSeed"])
			if err != nil {
				return nil, err
			}
			req := AgentFromApprovedNLRequest{LoadApprovedOptions: nlLoadOpts(r["opts"]), Draft: r["draft"], Approval: r["approval"], Principal: principal}
			req.Goal, _ = r["goal"].(string)
			req.Aud, _ = r["aud"].(string)
			if hs, ok := r["holderSeed"]; ok {
				if req.Holder, err = nlKeyOfLabel(hs); err != nil {
					return nil, err
				}
			}
			out, err := AgentFromApprovedNL(req)
			if err != nil {
				return nil, err
			}
			env := ReadEnvelope(out.Agent.Grant)
			return map[string]any{"reviewer": out.Reviewer, "legacy_unbound_instruction": out.LegacyUnboundInstruction,
				"envelope": map[string]any{"predicates": env["predicates"], "caveats": env["caveats"], "risk_policy": env["risk_policy"], "agent_binding": env["agent_binding"]}}, nil
		},
	}
	replayAll(t, "ref-nl-approval.json.gz", 206, vecSeeded(fns), nil, map[string]bool{"agentFromApproved": true})
}
