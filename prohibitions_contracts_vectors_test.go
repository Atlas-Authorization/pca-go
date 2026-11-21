package pca

import (
	"errors"
	"testing"
)

// Replays of the prohibition engine and the behavioural contracts against the reference, every case of three corpora:
// base-prohibitions (constitution and state validation, the monitor grids, advance, evidence, signed evidence, check-and-advance),
// ref-prohibitions (the constants, triggers, constitution signing, the non-strict advance, evidence digests, composition) and
// ref-contracts (clauses, ids, signing, check, advance, check-and-advance). Verdicts and reasons compare as JSON values. An
// argument the typed signatures cannot carry (a seed that is no seed, a signer that is no string, evidence that is no object) is
// refused here, as the reference refuses it.

func pcvList(l []string) any { return append([]string{}, l...) }

func pcvSeed(v any) ([]byte, error) {
	s, _ := v.(string)
	seed, ok := DecodeB64uStrict(s, 32)
	if !ok {
		return nil, errors.New("not an Ed25519 seed")
	}
	return seed, nil
}

func pcvOpts(a []any, i int) map[string]any {
	if i < len(a) {
		if m, ok := a[i].(map[string]any); ok {
			return m
		}
	}
	return nil
}

func TestProhibitionEngineMatchesTheReference(t *testing.T) {
	replayAll(t, "base-prohibitions.json.gz", 21781, vecSeeded(map[string]vecFn{
		"validateInvariant":    func(a []any) (any, error) { return pcvList(ValidateInvariant(a[0])), nil },
		"validateConstitution": func(a []any) (any, error) { return pcvList(ValidateConstitution(a[0])), nil },
		"stateProblem":         func(a []any) (any, error) { return killReason(StateProblem(a[0])), nil },
		"canonicalState": func(a []any) (any, error) {
			s, ok := CanonicalState(a[0])
			if !ok {
				return nil, errors.New("no canonical state")
			}
			return s, nil
		},
		"stateDigest":       func(a []any) (any, error) { return StateDigest(a[0]) },
		"tickState":         func(a []any) (any, error) { return TickState(a[0], a[1]), nil },
		"emptyState":        func(a []any) (any, error) { return EmptyMonitorState(a[0]), nil },
		"checkProhibitions": func(a []any) (any, error) { return CheckProhibitions(a[0], a[1], a[2]), nil },
		"advanceStateStrict": func(a []any) (any, error) {
			if len(a) > 3 {
				return AdvanceStateStrictAt(a[0], a[1], a[2], a[3]), nil
			}
			return AdvanceStateStrict(a[0], a[1], a[2]), nil
		},
		"proveSafety":          func(a []any) (any, error) { return ProveSafety(a[0], a[1], a[2]), nil },
		"verifySafetyEvidence": func(a []any) (any, error) { return VerifySafetyEvidence(a[0], a[1], a[2], a[3]), nil },
		"safetyBindingId": func(a []any) (any, error) {
			ev, isObj := a[0].(map[string]any)
			signer, isStr := a[1].(string)
			if !isObj || !isStr {
				return nil, errors.New("the evidence is an object and the signer a string")
			}
			return SafetyBindingID(ev, signer)
		},
		"signSafetyEvidence": func(a []any) (any, error) {
			seed, err := pcvSeed(a[1])
			if err != nil {
				return nil, err
			}
			signer, isStr := a[2].(string)
			if !isStr {
				return nil, errors.New("signSafetyEvidence: signer missing")
			}
			return SignSafetyEvidence(a[0], seed, signer)
		},
		"verifySignedSafetyEvidence": func(a []any) (any, error) { return VerifySignedSafetyEvidence(a[0], a[1]), nil },
		"checkAndAdvance": func(a []any) (any, error) {
			return CheckAndAdvance(a[0], a[1], a[2], a[3], pcvOpts(a, 4)), nil
		},
		"verifyConstitution": func(a []any) (any, error) {
			var pin *string
			if len(a) > 1 { // a given pin of any type must equal the principal: a value that is not a string never does
				s := "\xff not a string pin"
				if str, ok := a[1].(string); ok {
					s = str
				}
				pin = &s
			}
			return VerifyConstitution(a[0], pin), nil
		},
		"constitutionId":  func(a []any) (any, error) { return ConstitutionID(a[0]) },
		"whenAffirmative": func(a []any) (any, error) { return WhenAffirmative(a[0], a[1]), nil },
	}), nil, nil)
}

func TestProhibitionsMatchTheReference(t *testing.T) {
	replayAll(t, "ref-prohibitions.json.gz", 1637, vecSeeded(map[string]vecFn{
		"constants": func([]any) (any, error) {
			return map[string]any{"CONSTITUTION_VERSION": ConstitutionVersion, "CONSTITUTION_SIG_DOMAIN": ConstitutionSigDomain, "EVIDENCE_VERSION": EvidenceVersion,
				"SAFETY_EVIDENCE_SIG_DOMAIN": SafetyEvidenceSigDomain, "STATE_DIGEST_DOMAIN": StateDigestDomain, "STATE_CHAIN_DOMAIN": StateChainDomain,
				"MAX_LEDGER": MaxLedger, "MAX_INVARIANTS": MaxInvariants, "MAX_DEADLINE": MaxDeadline}, nil
		},
		// the label is text here: a caller formats what it has, as the reference does in its message
		"validateWhen": func(a []any) (any, error) { return killReason(ValidateWhen(a[0], jsValueString(a[1]))), nil },
		"whenMatches":  func(a []any) (any, error) { return WhenMatches(a[0], a[1]), nil },
		"signConstitution": func(a []any) (any, error) {
			seed, err := pcvSeed(a[1])
			if err != nil {
				return nil, err
			}
			return SignConstitution(a[0], seed)
		},
		"advanceState": func(a []any) (any, error) {
			if len(a) > 3 {
				return AdvanceStateAt(a[0], a[1], a[2], a[3]), nil
			}
			return AdvanceState(a[0], a[1], a[2]), nil
		},
		"evidenceDigest":   func(a []any) (any, error) { return EvidenceDigest(a[0]) },
		"composeAuthority": func(a []any) (any, error) { return ComposeAuthority(a[0], a[1], a[2], a[3]), nil },
	}), nil, nil)
}

func TestContractsMatchTheReference(t *testing.T) {
	// the two lifts take an object: null is refused (the reference throws), any other value has no members
	lift := func(f func(map[string]any) map[string]any) vecFn {
		return func(a []any) (any, error) {
			if a[0] == nil {
				return nil, errors.New("null has no members")
			}
			return f(vecObj(a[0])), nil
		}
	}
	nullOpts := 0
	replayAll(t, "ref-contracts.json.gz", 1269, vecSeeded(map[string]vecFn{
		"constants": func([]any) (any, error) {
			return map[string]any{"CONTRACT_VERSION": ContractVersion, "CONTRACT_SIG_DOMAIN": ContractSigDomain, "MAX_CLAUSES": ContractMaxClauses,
				"MAX_CLAUSE_DEPTH": ContractMaxClauseDeep}, nil
		},
		"validateClause": func(a []any) (any, error) {
			seen := map[string]bool{}
			for _, id := range vecStrs(map[string]any{"ids": a[1]}, "ids") {
				seen[id] = true
			}
			return pcvList(ValidateClause(a[0], seen, int(jsF(a[2])))), nil
		},
		"contractId": func(a []any) (any, error) { return ContractID(a[0]) },
		"signContract": func(a []any) (any, error) {
			seed, err := pcvSeed(a[1])
			if err != nil {
				return nil, err
			}
			return SignContract(a[0], seed)
		},
		"embeddedConstitution":     lift(EmbeddedConstitution),
		"contractFromConstitution": lift(ContractFromConstitution),
		"checkContract":            func(a []any) (any, error) { return CheckContract(a[0], a[1], a[2]), nil },
		"advanceContract": func(a []any) (any, error) {
			if len(a) > 3 && a[3] == nil {
				nullOpts++
				return map[string]any{"typed": "options given as null have no typed form"}, nil
			}
			return AdvanceContract(a[0], a[1], a[2], pcvOpts(a, 3)), nil
		},
		"checkAndAdvanceContract": func(a []any) (any, error) {
			return CheckAndAdvanceContract(a[0], a[1], a[2], a[3], pcvOpts(a, 4)), nil
		},
	}), map[string]func(want, got any) bool{
		// one case passes null for the options (the reference fails closed reading it): absent is the only typed "no options"
		"advanceContract": func(want, got any) bool {
			if _, gap := vecObj(got)["typed"]; gap {
				return baseCanon(vecObj(want)["violated"]) == `["<state>"]`
			}
			return baseCanon(want) == baseCanon(got)
		},
	}, nil)
	if nullOpts != 1 {
		t.Fatalf("%d cases pass null options, 1 is expected", nullOpts)
	}
}
