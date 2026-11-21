package pca

// Replays the reference corpus for the import pipeline, the importer registry, the JSON Lines forms, the suggestion evaluation and the
// review flow. A signing seed is a label: the key is sha256("atlas-pca-conformance/" + label).

import (
	"crypto/sha256"
	"errors"
	"sort"
	"testing"
)

func aevTestSuggestOpts(v any) ActionSuggestOptions {
	m := vecObj(v)
	o := ActionSuggestOptions{Mode: vecStr(m, "mode")}
	if m["rules"] == "default" {
		r := aisShallow(ActionDefaultRules())
		r["rules"] = aisList(r["rules"])[:20]
		o.Rules = r
	} else if m["rules"] != nil {
		o.Rules = m["rules"]
	}
	if m["models"] != nil {
		o.Models = aisTestAdapters(m["models"])
	}
	return o
}

func aevTestDefs(v any) []map[string]any {
	out := []map[string]any{}
	for _, x := range aisList(v) {
		out = append(out, vecObj(x))
	}
	return out
}

var aevTestTraitOrder = []string{"money_moving", "destructive", "external_communication", "privilege_change", "code_execution", "public_exposure", "financial_data_read", "scheduled"}

// aevTestFloorList reads a floor table in the order of the recorded floors (a Go map keeps no insertion order).
func aevTestFloorList(recall, minPos map[string]any) []ActionEvalFloor {
	keys := []string{}
	for _, t := range aevTestTraitOrder {
		if _, ok := recall[t]; ok {
			keys = append(keys, t)
		}
	}
	var rest []string
	for t := range recall {
		if !contains(aevTestTraitOrder, t) {
			rest = append(rest, t)
		}
	}
	sort.Strings(rest)
	out := []ActionEvalFloor{}
	for _, t := range append(keys, rest...) {
		out = append(out, ActionEvalFloor{Trait: t, RecallLower: jsF(recall[t]), MinPositives: jsF(minPos[t])})
	}
	return out
}

func aevTestFloors(v any) ActionEvalFloors {
	m := vecObj(v)
	real, reg := vecObj(m["real"]), vecObj(m["regression"])
	return ActionEvalFloors{RealMinEntries: jsF(real["min_entries"]), Real: aevTestFloorList(vecObj(real["recall_lower"]), vecObj(real["min_positives"])),
		Regression: aevTestFloorList(vecObj(reg["recall_lower"]), nil)}
}

func TestActionImportReviewVectors(t *testing.T) {
	replayVectors(t, "ref-actions-import-review.json.gz", map[string]vecFn{
		"parseHandTsv": func(a []any) (any, error) { s, _ := vecArg(a, 0).(string); return ActionEvalParseHandTSV(s) },
		"parseCorpusJsonl": func(a []any) (any, error) {
			s, _ := vecArg(a, 0).(string)
			return ActionEvalParseCorpusJSONL(s)
		},
		"realSplit":    func(a []any) (any, error) { return ActionEvalRealSplit(vecArg(a, 0)), nil },
		"importCorpus": func(a []any) (any, error) { return ActionEvalImportCorpus(aisList(vecArg(a, 0))) },
		"evalSuggest": func(a []any) (any, error) {
			var rules any
			if r := vecArg(a, 1); r != nil && r != "default" {
				rules = r
			}
			var alpha *float64
			if v := vecArg(a, 2); v != nil {
				f := jsF(v)
				alpha = &f
			}
			return ActionEvalSuggest(aisList(vecArg(a, 0)), rules, nil, alpha)
		},
		"renderEvalMarkdown": func(a []any) (any, error) { return ActionEvalRenderMarkdown(vecObj(vecArg(a, 0))), nil },
		"floorFailures": func(a []any) (any, error) {
			return ActionEvalFloorFailures(vecObj(vecArg(a, 0)), aevTestFloors(vecArg(a, 1))), nil
		},
		"importActions": func(a []any) (any, error) {
			kind, _ := vecArg(a, 0).(string)
			return aimTestReport(ActionImport(kind, vecArg(a, 1), aimTestOpts(vecArg(a, 2))))
		},
		"IMPORTERS": func(a []any) (any, error) {
			kind, _ := vecArg(a, 0).(string)
			imp, ok := ActionImporters[kind]
			if !ok {
				return nil, errors.New("no importer for " + kind)
			}
			defs, todo, err := imp(vecArg(a, 1), aimTestOpts(vecArg(a, 2)))
			if err != nil {
				return nil, err
			}
			return map[string]any{"defs": defs, "todo": todo}, nil
		},
		"importAndSuggest": func(a []any) (any, error) {
			kind, _ := vecArg(a, 0).(string)
			return ActionImportAndSuggest(kind, vecArg(a, 1), aimTestOpts(vecArg(a, 2)), aevTestSuggestOpts(vecArg(a, 3)))
		},
		"suggestDefs": func(a []any) (any, error) {
			defs, errs, err := ActionSuggestDefs(aevTestDefs(vecArg(a, 0)), aevTestSuggestOpts(vecArg(a, 1)))
			if err != nil {
				return nil, err
			}
			return map[string]any{"defs": defs, "errors": errs}, nil
		},
		"defsToJsonl": func(a []any) (any, error) { return ActionDefsToJSONL(aevTestDefs(vecArg(a, 0))) },
		"jsonlToDefs": func(a []any) (any, error) { s, _ := vecArg(a, 0).(string); return ActionJSONLToDefs(s) },

		"confirmDef": func(a []any) (any, error) {
			oo := vecObj(vecArg(a, 1))
			label, _ := oo["seed"].(string)
			seed := sha256.Sum256([]byte("atlas-pca-conformance/" + label))
			return ActionConfirmDef(vecObj(vecArg(a, 0)), ActionConfirmOpts{Registry: coreRegistry, ReviewerKID: vecStr(oo, "kid"), ReviewerSeed: seed[:], Pins: oo["pins"],
				FinalTraits: aisStrList(oo["finalTraits"]), Dismissed: aisList(oo["dismissed"]), TS: oo["ts"]})
		},
		"verifyAttestation": func(a []any) (any, error) {
			return ActionVerifyAttestation(vecArg(a, 0), coreRegistry, vecArg(a, 1)), nil
		},
		"reviewStatus": func(a []any) (any, error) {
			return ActionReviewStatus(vecObj(vecArg(a, 0)), coreRegistry, vecArg(a, 1))
		},
		"revertStale": func(a []any) (any, error) {
			return ActionRevertStale(vecObj(vecArg(a, 0)), coreRegistry, vecArg(a, 1))
		},
		"reviewPriority": func(a []any) (any, error) {
			p, err := ActionReviewPriority(vecObj(vecArg(a, 0)), coreRegistry)
			return p, err
		},
		"reviewQueueOrder": func(a []any) (any, error) {
			return ActionReviewQueueOrder(aevTestDefs(vecArg(a, 0)), coreRegistry)
		},
		"prepareReview": func(a []any) (any, error) {
			return ActionPrepareReview(vecObj(vecArg(a, 0)), coreRegistry, vecObj(vecArg(a, 1)))
		},
	})
}
