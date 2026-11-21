package pca

import (
	"errors"
	"testing"
)

// Replay of the action pin signing half against the reference (ref-action-pin), every case: the constants, registry document signing
// under ed25519, ml-dsa-65 and the hybrid, evolution records, registry key entries, re-approvals and the verification of what they sign.
func TestActionPinMatchesTheReference(t *testing.T) {
	keyOf := func(v any) (*KeyPair, error) {
		b, ok := qvBytes(v)
		if !ok {
			return nil, errors.New("the secret is bytes")
		}
		return KeyPairFromSeed(b)
	}
	suiteOf := func(v any) (*SuiteOpts, error) {
		sm := vecObj(v)
		if sm == nil {
			return nil, nil
		}
		s := &SuiteOpts{Alg: rsStr(sm["alg"])}
		if seed, ok := qvBytes(sm["pqSeed"]); ok {
			pq, err := GeneratePqKeyPairFromSeed("ML-DSA-65", seed)
			if err != nil {
				return nil, err
			}
			s.Pq = pq
		}
		return s, nil
	}
	fns := map[string]vecFn{
		"constants": func([]any) (any, error) {
			return map[string]any{"ACTION_PIN_ON_NEW": rsStringsOut(ActionPinOnNew), "EVOLUTION_CLASSES": rsStringsOut(EvolutionClasses),
				"EVOLUTION_DIFF_DOMAIN": EvolutionDiffDomain, "EVOLUTION_DOMAIN": EvolutionDomain, "EVOLUTION_RECORD_KIND": EvolutionRecordKind,
				"MAX_ESC_TIER": jsNumber(MaxEscTier), "MAX_EVOLUTION_STEPS": jsNumber(MaxEvolutionSteps), "REAPPROVAL_DOMAIN": ReapprovalDomain,
				"REAPPROVAL_KIND": ReapprovalKind}, nil
		},
		"signRegistryDoc": func(a []any) (any, error) {
			key, err := keyOf(vecArg(a, 3))
			if err != nil {
				return nil, err
			}
			suite, err := suiteOf(vecArg(a, 4))
			if err != nil {
				return nil, err
			}
			return SignRegistryDoc(rsStr(vecArg(a, 0)), scDecode(vecArg(a, 1)), rsStr(vecArg(a, 2)), key, suite)
		},
		"signEvolutionRecord": func(a []any) (any, error) {
			key, err := keyOf(vecArg(a, 2))
			if err != nil {
				return nil, err
			}
			suite, err := suiteOf(vecArg(a, 3))
			if err != nil {
				return nil, err
			}
			return SignEvolutionRecord(vecObj(vecArg(a, 0)), rsStr(vecArg(a, 1)), key, suite)
		},
		"registryKeyOf": func(a []any) (any, error) {
			key, err := keyOf(vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			suite, err := suiteOf(vecArg(a, 2))
			if err != nil {
				return nil, err
			}
			return RegistryKeyOf(rsStr(vecArg(a, 0)), key, suite)
		},
		"signReapproval": func(a []any) (any, error) {
			o := vecObj(vecArg(a, 0))
			key, err := keyOf(o["principalSecret"])
			if err != nil {
				return nil, err
			}
			return SignReapproval(rsStr(o["grantId"]), vecObj(o["record"]), key)
		},
		"verifyRegistrySig": func(a []any) (any, error) {
			return VerifyRegistrySig(rsStr(vecArg(a, 0)), vecArg(a, 1), vecObj(vecArg(a, 2)), vecArg(a, 3)), nil
		},
		"verifyEvolutionRecord": func(a []any) (any, error) { return VerifyEvolutionRecord(vecArg(a, 0), vecArg(a, 1)), nil },
		"reapprovalValid": func(a []any) (any, error) {
			return ReapprovalValid(vecArg(a, 0), vecArg(a, 1), vecArg(a, 2), vecArg(a, 3), vecArg(a, 4)), nil
		},
	}
	replayAll(t, "ref-action-pin.json.gz", 111, vecSeeded(fns), nil, nil)
}
