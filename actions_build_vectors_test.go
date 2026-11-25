package pca

// Replays the reference corpus for `pca actions build` (the core trait registry, attestations never verified). Registry seeds are
// labels ({"$bytes": {"$seed": label}}): the key is sha256("atlas-pca-conformance/" + label).

import "testing"

func TestActionBuildVectors(t *testing.T) {
	list := func(v any) []any { l, _ := v.([]any); return l }
	replayVectors(t, "ref-actions-build.json.gz", vecSeeded(map[string]vecFn{
		"buildArtifacts": func(a []any) (any, error) {
			return ActionBuildArtifacts(list(vecArg(a, 0)), vecObj(vecArg(a, 1)), coreRegistry, nil)
		},
		"generateTypes": func(a []any) (any, error) { return ActionGenerateTypes(list(vecArg(a, 0))), nil },
		"toolAction": func(a []any) (any, error) {
			tool, _ := vecArg(a, 1).(string)
			return ActionToolAction(list(vecArg(a, 0)), tool, vecObj(vecArg(a, 2))), nil
		},
		"packConsistencyError": func(a []any) (any, error) {
			if r := ActionPackConsistencyError(vecArg(a, 0), coreRegistry); r != "" {
				return r, nil
			}
			return nil, nil
		},
		"signPack": func(a []any) (any, error) {
			seed, err := packTestSeed(vecArg(a, 2))
			if err != nil {
				return nil, err
			}
			kid, _ := vecArg(a, 1).(string)
			return ActionSignPack(vecObj(vecArg(a, 0)), kid, seed, coreRegistry)
		},
		"packKeyOf": func(a []any) (any, error) {
			seed, err := packTestSeed(vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			kid, _ := vecArg(a, 0).(string)
			return ActionPackKeyOf(kid, seed)
		},
		"verifyPack": func(a []any) (any, error) {
			return ActionBuildVerifyPack(vecArg(a, 0), list(vecArg(a, 1)), coreRegistry), nil
		},
	}))
}
