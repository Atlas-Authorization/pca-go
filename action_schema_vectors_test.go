package pca

import (
	"errors"
	"strings"
	"testing"
)

// Replay of the action schema against the reference (ref-action-schema), every case: the exported constants, value-dependent
// reversibility, wallet floors, the verb lookup, signing under three suites, the key entry, the digest, verification and the
// drafting importers (MCP tool lists and OpenAPI documents). A reference throw requires a refusal.
func TestActionSchemaMatchesTheReference(t *testing.T) {
	list := func(v any) []any {
		switch t := v.(type) {
		case []string:
			return rsStringsOut(t)
		case []any:
			return t
		}
		return nil
	}
	regex := func(source string) any { return map[string]any{"$regex": source} }
	fns := map[string]vecFn{
		"constants": func([]any) (any, error) {
			return map[string]any{
				"ACTION_SCHEMA_DOMAIN": ActionSchemaDomain, "ACTION_SCHEMA_KIND": ActionSchemaKind, "ACTION_SCHEMA_REF_DOMAIN": ActionSchemaRefDomain,
				"DEFAULT_MAX_ITEMS": jsNumber(DefaultMaxItems), "DEFAULT_MAX_LEN": jsNumber(DefaultMaxLen), "MAX_SCHEMA_PARAMS": jsNumber(MaxSchemaParams),
				"MAX_SCHEMA_VALUES": jsNumber(MaxSchemaValues), "MAX_SCHEMA_VERBS": jsNumber(MaxSchemaVerbs),
				"PARAM_PATH_RE": regex(ParamPathRe.String()), "PARAM_PATH_RE_V2": regex(ParamPathReV2.String()), "UNIT_ID_RE": regex(UnitIDRe.String()),
				"PARAM_TYPES": list(ParamTypes), "PARAM_TYPES_V2": list(ParamTypesV2), "SCHEMA_REVERSIBILITY": list(SchemaReversibility),
				"SCHEMA_V2_CAVEATS": list(SchemaV2Caveats), "SCHEMA_V2_CONTEXT": list(SchemaV2Context), "SCHEMA_V2_EFFECTS": list(SchemaV2Effects),
				"SCHEMA_V2_PROVENANCE": list(SchemaV2Provenance), "SCHEMA_V2_PRULES": list(SchemaV2Prules), "SCHEMA_V2_TAGS": list(SchemaV2Tags),
				"SENSITIVITIES": list(Sensitivities), "WALLET_FLOOR_EXACT": list(WalletFloorExact), "WALLET_FLOOR_PREFIXES": list(WalletFloorPrefixes),
				"WELL_KNOWN_PCA_ACTIONS_PATH": WellKnownPcaActionsPath,
			}, nil
		},
		"reversibilityOf": func(a []any) (any, error) { return ReversibilityOf(vecObj(vecArg(a, 0)), vecObj(vecArg(a, 1))), nil },
		"floorApplies": func(a []any) (any, error) {
			s, _ := vecArg(a, 0).(string)
			return FloorApplies(s, vecObj(vecArg(a, 1))), nil
		},
		"schemaVerb": func(a []any) (any, error) {
			verb, _ := vecArg(a, 1).(string)
			v, throws := SchemaVerb(vecArg(a, 0), verb)
			if throws {
				return nil, errors.New("schemaVerb: the document has no verbs list")
			}
			if v == nil {
				return nil, nil
			}
			return v, nil
		},
		"signActionSchema": func(a []any) (any, error) {
			secret, ok := qvBytes(vecArg(a, 2))
			if !ok {
				return nil, errors.New("the secret is bytes")
			}
			key, err := KeyPairFromSeed(secret)
			if err != nil {
				return nil, err
			}
			var suite *SuiteOpts
			if sm := vecObj(vecArg(a, 3)); sm != nil {
				suite = &SuiteOpts{Alg: rsStr(sm["alg"])}
				if seed, ok := qvBytes(sm["pqSeed"]); ok {
					if suite.Pq, err = GeneratePqKeyPairFromSeed("ML-DSA-65", seed); err != nil {
						return nil, err
					}
				}
			}
			return SignActionSchema(vecObj(vecArg(a, 0)), rsStr(vecArg(a, 1)), key, suite)
		},
		"actionSchemaKeyOf": func(a []any) (any, error) {
			secret, ok := qvBytes(vecArg(a, 1))
			if !ok {
				return nil, errors.New("the secret is bytes")
			}
			key, err := KeyPairFromSeed(secret)
			if err != nil {
				return nil, err
			}
			var suite *SuiteOpts
			if sm := vecObj(vecArg(a, 2)); sm != nil {
				suite = &SuiteOpts{Alg: rsStr(sm["alg"])}
				if seed, ok := qvBytes(sm["pqSeed"]); ok {
					if suite.Pq, err = GeneratePqKeyPairFromSeed("ML-DSA-65", seed); err != nil {
						return nil, err
					}
				}
			}
			return ActionSchemaKeyOf(rsStr(vecArg(a, 0)), key, suite)
		},
		"actionSchemaDigest": func(a []any) (any, error) {
			d, ok := ActionSchemaDigest(vecArg(a, 0))
			if !ok {
				return nil, errors.New("the schema has no digest")
			}
			return d, nil
		},
		"verifyActionSchema":        func(a []any) (any, error) { return VerifyActionSchema(vecArg(a, 0), vecArg(a, 1)), nil },
		"reversibilityFromMcpHints": func(a []any) (any, error) { return ReversibilityFromMcpHints(vecArg(a, 0)), nil },
		"draftSchemaFromMcpTools":   func(a []any) (any, error) { return DraftSchemaFromMcpTools(vecArg(a, 0), vecArg(a, 1)) },
		"draftSchemaFromOpenApi":    func(a []any) (any, error) { return DraftSchemaFromOpenApi(vecArg(a, 0), vecArg(a, 1)) },
	}
	cmp := map[string]func(want, got any) bool{
		// reasons compare exactly except the two families that carry the reference's own exception text: by prefix
		"verifyActionSchema": func(want, got any) bool {
			w, g := vecObj(want), vecObj(got)
			wr, _ := w["reason"].(string)
			gr, _ := g["reason"].(string)
			for _, p := range []string{"schema verification error:", "malformed schema:"} {
				if strings.HasPrefix(wr, p) {
					return w["ok"] == g["ok"] && strings.HasPrefix(gr, p)
				}
			}
			return baseCanon(want) == baseCanon(got)
		},
	}
	replayAll(t, "ref-action-schema.json.gz", 173, vecSeeded(fns), cmp, nil)
}
