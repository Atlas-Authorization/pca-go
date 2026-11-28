package pca

// Replay of the reference corpus for the agent-native primitives (ref-agent-native.json.gz, 1632 cases): caution claims, rationale
// binding, the tool-schema firewall, capability introspection and leases. Keys are the seed labels of the corpus ("$seed"), so the
// signed claims and heartbeats the corpus feeds to the verifiers are verified here for real; describeEnvelope chains are verified
// with the package's own chain verifier. A case whose fn has no entry point here fails.

import (
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"
)

// anTestRevive turns {"$num": "NaN" | "Infinity" | "-Infinity"} into the matching number lexeme.
func anTestRevive(v any) any {
	switch t := v.(type) {
	case map[string]any:
		if s, ok := t["$num"].(string); ok && len(t) == 1 {
			return json.Number(s)
		}
		for k, x := range t {
			t[k] = anTestRevive(x)
		}
	case []any:
		for i, x := range t {
			t[i] = anTestRevive(x)
		}
	}
	return v
}

func anTestNum(v any) *float64 {
	f, ok := jsNum(v)
	if !ok {
		return nil
	}
	return &f
}

func anTestFloat(v any) float64 {
	f, ok := jsNum(v)
	if !ok {
		return math.NaN()
	}
	return f
}

func anTestStr(v any) *string {
	s, ok := v.(string)
	if !ok {
		return nil
	}
	return &s
}

// anTestPin is an expected value as the reference reads it: absent is no pin (an undefined argument crosses the corpus as null), any
// other value (a number, an empty string, ...) is a pin that only an equal string meets.
func anTestPin(a []any, i int) *string {
	if i >= len(a) || a[i] == nil {
		return nil
	}
	s, ok := a[i].(string)
	if !ok {
		s = "\xff not a string pin"
	}
	return &s
}

func anTestObjOrNil(v any) map[string]any { m, _ := v.(map[string]any); return m }

func anTestKey(v any) (*KeyPair, error) {
	b := baseBytes(v)
	if b == nil {
		return nil, errors.New("no secret key")
	}
	return KeyPairFromSeed(b)
}

func anTestFirewall(ok bool, reason string) any {
	if ok {
		return map[string]any{"ok": true}
	}
	return map[string]any{"ok": false, "reason": reason}
}

func anTestJudge(spec string) RationaleJudge {
	return func(rationale string, action any) (bool, error) {
		switch {
		case spec == "true":
			return true, nil
		case spec == "false", spec == "truthy": // "truthy" returns the string "yes", which is not === true
			return false, nil
		case spec == "throw":
			return false, errors.New("judge threw")
		case strings.HasPrefix(spec, "contains:"):
			return strings.Contains(rationale, spec[len("contains:"):]), nil
		case strings.HasPrefix(spec, "action-verb:"):
			a, _ := action.(map[string]any)
			v, _ := a["verb"].(string)
			return v == spec[len("action-verb:"):], nil
		}
		return false, errors.New("unknown judge spec " + spec)
	}
}

func agentNativeTestFns() map[string]vecFn {
	fns := map[string]vecFn{
		"constants": func([]any) (any, error) {
			return map[string]any{
				"CAVEAT_ENVELOPE": CaveatEnvelope, "CAVEAT_EXPIRES": CaveatExpires, "CAVEAT_NOT_BEFORE": CaveatNotBefore, "CAVEAT_RATE": CaveatRate,
				"CAVEAT_MAX_BLAST_RADIUS": CaveatMaxBlastRadius, "CAVEAT_REVERSIBILITY_MAX": CaveatReversibilityMax,
				"CAVEAT_DELEGATION_DEPTH": CaveatDelegationDepth, "CAVEAT_PREDICATES": CaveatPredicates, "CAVEAT_TOOL_SCHEMA": CaveatToolSchema,
				"CAVEAT_MAX_SPEND": CaveatMaxSpend, "MAX_CAUTION_REASON_LEN": MaxCautionReasonLen, "MIN_SALT_BYTES": MinSaltBytes,
				"MIN_SALT_DISTINCT_BYTES": MinSaltDistinctBytes, "MAX_RATIONALE_LEN": MaxRationaleLen, "MAX_SCHEMA_DEPTH": MaxSchemaDepth,
				"MAX_SCHEMA_NODES": MaxSchemaNodes, "MAX_OBJECT_PROPS": MaxObjectProps, "MAX_ENUM_VALUES": MaxEnumValues,
				"DEFAULT_MAX_ARRAY_ITEMS": DefaultMaxArrayItems, "ABSOLUTE_MAX_ARRAY_ITEMS": AbsoluteMaxArrayItems,
				"DEFAULT_MAX_STRING_LEN": DefaultMaxStringLen, "ABSOLUTE_MAX_STRING_LEN": AbsoluteMaxStringLen, "MAX_VALUE_NODES": MaxValueNodes,
				"HEARTBEAT_SKEW_MS": HeartbeatSkewMs, "MAX_LEASE_TTL_MS": MaxLeaseTtlMs,
			}, nil
		},
		"signCaution": func(a []any) (any, error) {
			kp, err := anTestKey(vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			return SignCaution(kp, anTestObjOrNil(vecArg(a, 0)))
		},
		"signHeartbeat": func(a []any) (any, error) {
			kp, err := anTestKey(vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			return SignHeartbeat(kp, anTestObjOrNil(vecArg(a, 0)))
		},
		"verifyCaution": func(a []any) (any, error) {
			return VerifyCaution(vecArg(a, 0), anTestPin(a, 1), anTestPin(a, 2)), nil
		},
		"combineCaution": func(a []any) (any, error) {
			return jsNumber(CombineCaution(anTestNum(vecArg(a, 0)), anTestFloat(vecArg(a, 1)))), nil
		},
		"combineSignedCaution": func(a []any) (any, error) {
			d, _ := vecArg(a, 1).(string)
			return CombineSignedCaution(vecArg(a, 0), d, anTestFloat(vecArg(a, 2)), anTestPin(a, 3)), nil
		},
		"checkCautionMonotone": func(a []any) (any, error) {
			grid := []float64{}
			l, _ := vecArg(a, 0).([]any)
			for _, x := range l {
				if f, ok := jsNum(x); ok {
					grid = append(grid, f)
				}
			}
			return CheckCautionMonotone(grid), nil
		},
		"isStrongSalt": func(a []any) (any, error) { return IsStrongSalt(vecArg(a, 0)), nil },
		"bindRationale": func(a []any) (any, error) {
			text, ok := vecArg(a, 1).(string)
			if !ok {
				return nil, errors.New("rationale must be a string")
			}
			salt, isStr := vecArg(a, 2).(string)
			if !isStr {
				salt = "" // any non-string salt is below the floor
			}
			c, r, err := BindRationale(vecArg(a, 0), text, &salt)
			if err != nil {
				return nil, err
			}
			return map[string]any{"commitment": c, "reveal": r}, nil
		},
		"verifyRationale": func(a []any) (any, error) {
			if len(a) > 2 {
				return VerifyRationale(vecArg(a, 0), vecArg(a, 1), vecArg(a, 2)), nil
			}
			return VerifyRationale(vecArg(a, 0), vecArg(a, 1)), nil
		},
		"auditRationale": func(a []any) (any, error) {
			spec, _ := vecArg(a, 3).(string)
			return AuditRationale(vecArg(a, 0), vecArg(a, 1), vecArg(a, 2), anTestJudge(spec)), nil
		},
		"validateArgSchema": func(a []any) (any, error) {
			if e := ValidateArgSchema(vecArg(a, 0)); e != "" {
				return e, nil
			}
			return nil, nil
		},
		"toolSchemaCaveat": func(a []any) (any, error) { return ToolSchemaCaveat(vecArg(a, 0), vecArg(a, 1)) },
		"evaluateToolSchema": func(a []any) (any, error) {
			return anTestFirewall(EvaluateToolSchemaCall(vecArg(a, 0), vecArg(a, 1))), nil
		},
		"toolSchemaEvaluator": func(a []any) (any, error) { return ToolSchemaEvaluator(vecArg(a, 0), vecArg(a, 1)), nil },
		"predicatesCaveat":    func(a []any) (any, error) { return PredicatesCaveat(vecArg(a, 0)) },
		"actionSpendUsd": func(a []any) (any, error) {
			if f, ok := ActionSpendUsd(vecArg(a, 0)); ok {
				return jsNumber(f), nil
			}
			return nil, nil
		},
		"agentNativeCaveatEvaluator": func(a []any) (any, error) { return AgentNativeCaveatEvaluator(vecArg(a, 0), vecArg(a, 1)), nil },
		"describeEnvelope": func(a []any) (any, error) {
			return DescribeEnvelope(vecArg(a, 0), anTestNum(vecArg(a, 1)), anTestStr(vecArg(a, 2)), vecArg(a, 3)), nil
		},
		"envelopePermits": func(a []any) (any, error) {
			verb, _ := vecArg(a, 1).(string)
			res, _ := vecArg(a, 2).(string)
			return EnvelopePermits(vecArg(a, 0), verb, res, anTestNum(vecArg(a, 3)), anTestObjOrNil(vecArg(a, 4))), nil
		},
		"envelopePermitsToolCall": func(a []any) (any, error) {
			return anTestFirewall(EnvelopePermitsToolCall(vecArg(a, 0), vecArg(a, 1))), nil
		},
		"grantLease": func(a []any) (any, error) { return GrantLease(vecArg(a, 0)) },
		"leaseState": func(a []any) (any, error) { return LeaseState(vecArg(a, 0), anTestFloat(vecArg(a, 1))), nil },
		"renewLease": func(a []any) (any, error) {
			return RenewCapabilityLease(vecArg(a, 0), vecArg(a, 1), anTestFloat(vecArg(a, 2))), nil
		},
	}
	out := make(map[string]vecFn, len(fns))
	for n, f := range fns {
		f := f
		out[n] = func(a []any) (any, error) { return f(anTestRevive(vecResolveSeeds(a)).([]any)) }
	}
	return out
}

func TestAgentNativeReferenceVectors(t *testing.T) {
	replayVectors(t, "ref-agent-native.json.gz", agentNativeTestFns())
}
