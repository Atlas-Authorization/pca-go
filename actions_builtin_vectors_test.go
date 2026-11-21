package pca

// Replays the reference corpus for the built-in defs and their release signing. A reviewer seed is a label: the key is
// sha256("atlas-pca-conformance/" + label).

import (
	"crypto/sha256"
	"testing"
)

func TestActionBuiltinVectors(t *testing.T) {
	replayVectors(t, "ref-signbuiltins-go.json.gz", map[string]vecFn{
		"builtinDefs": func([]any) (any, error) { return ActionBuiltinDefs(), nil },
		"signBuiltins": func(a []any) (any, error) {
			o := vecObj(vecArg(a, 0))
			label, _ := o["seed"].(string)
			seed := sha256.Sum256([]byte("atlas-pca-conformance/" + label))
			return ActionSignBuiltins(vecStr(o, "kid"), seed[:], o["ts"], nil, nil)
		},
	})
}
