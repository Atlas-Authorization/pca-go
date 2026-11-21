package pca

// Replays the reference corpus for pack building and upgrade verification. The registry signing seeds are labels
// ({"$bytes": {"$seed": label}}): the key is sha256("atlas-pca-conformance/" + label).

import (
	"errors"
	"testing"
)

// packTestSeed reads a signing seed the replay already resolved ({"$bytes": b64u}).
func packTestSeed(v any) ([]byte, error) {
	b, ok := oprfB(v)
	if !ok || len(b) == 0 {
		return nil, errors.New("no signing seed")
	}
	return b, nil
}

func TestActionPackBuildVectors(t *testing.T) {
	replayVectors(t, "ref-actions-pack.json.gz", vecSeeded(map[string]vecFn{
		"buildPack": func(a []any) (any, error) {
			seed, err := packTestSeed(vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			pack, shards, err := ActionBuildPack(ActionPackBuild{Args: vecObj(vecArg(a, 0)), Seed: seed})
			if err != nil {
				return nil, err
			}
			return map[string]any{"pack": pack, "shards": shards}, nil
		},
		"shardDefs": func(a []any) (any, error) {
			defs, _ := vecArg(a, 0).([]any)
			var max *float64
			if m := vecArg(a, 1); m != nil {
				f := jsF(m)
				max = &f
			}
			return ActionShardDefs(defs, max)
		},
		"verifyUpgrade": func(a []any) (any, error) {
			ps, _ := vecArg(a, 3).(map[string]any)
			ns, _ := vecArg(a, 4).(map[string]any)
			if r := ActionVerifyUpgrade(vecObj(vecArg(a, 0)), vecObj(vecArg(a, 1)), vecArg(a, 2), ps, ns, nil); r != "" {
				return map[string]any{"ok": false, "reason": r}, nil
			}
			return map[string]any{"ok": true}, nil
		},
		"packStatementPayload": func(a []any) (any, error) { return ActionPackStatementPayload(vecObj(vecArg(a, 0))) },
	}))
}
