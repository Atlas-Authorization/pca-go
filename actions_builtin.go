package pca

// The built-in connector actions as hand-reviewed defs (embedded JSON) and the release step that signs them with the release
// reviewer key. Without that step the built-ins are unconfirmed and their effective traits are the top of the registry.

import (
	_ "embed"
)

//go:embed actions_builtin_defs.json
var actionBuiltinDefsJSON []byte

// ActionBuiltinDefs returns a fresh copy of the built-in defs.
func ActionBuiltinDefs() []map[string]any {
	v, err := ParseJSONLenient(actionBuiltinDefsJSON)
	list, ok := v.([]any)
	if err != nil || !ok {
		anlFail("actions_builtin_defs.json is unreadable")
	}
	out := make([]map[string]any, 0, len(list))
	for _, x := range list {
		out = append(out, aisMap(x))
	}
	return out
}

// ActionSignBuiltins is the release step: it confirms every def (the final traits are the def's own, sorted and deduplicated) under
// the reviewer key (kid and Ed25519 seed). The seed is supplied by the caller and never stored. A nil registry means the core one.
func ActionSignBuiltins(kid string, seed []byte, ts any, reg Registry, defs []map[string]any) ([]map[string]any, error) {
	if reg == nil {
		reg = coreRegistry
	}
	if defs == nil {
		defs = ActionBuiltinDefs()
	}
	out := make([]map[string]any, 0, len(defs))
	for _, d := range defs {
		c, err := ActionConfirmDef(d, ActionConfirmOpts{Registry: reg, ReviewerKID: kid, ReviewerSeed: seed, FinalTraits: aisSortUniq(aisStrList(d["traits"])), TS: ts})
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}
