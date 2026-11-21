package pca

// Replays the natural-language facade corpus: the grounding prompt, the strict policy parser, the facade compiler and its run
// inside a panel.

import (
	"errors"
	"math"
	"testing"
)

func ixNlCatalogOf(extras any) *IntentNLCatalog {
	var extra []CatalogAction
	for _, ev := range ixL(extras) {
		e := ixM(ev)
		a := CatalogAction{Connector: ixS(e["connector"]), Action: ixS(e["action"]), Verb: ixS(e["connector"]) + "." + ixS(e["action"]),
			Reversibility: ixS(e["reversibility"]), BlastRadius: ixFOr(e["blastRadius"], math.NaN()), AmountField: ixS(e["amountField"]), Description: ixS(e["description"])}
		for _, al := range ixL(e["aliases"]) {
			a.Aliases = append(a.Aliases, ixS(al))
		}
		extra = append(extra, a)
	}
	return NewIntentNLCatalog(extra)
}

func TestIntentNLReferenceVectors(t *testing.T) {
	replayVectors(t, "ref-intent-nl-java.json.gz", map[string]vecFn{
		"nlPrompt":      ixWrap(func(a []any) any { return IntentNLPrompt(ixS(a[0]), ixNlCatalogOf(ixArg(a, 1))) }),
		"parseNLPolicy": ixWrap(func(a []any) any { return IntentParseNLPolicy(ixS(a[0]), ixNlCatalogOf(ixArg(a, 1))) }),
		"nlCompile": ixWrap(func(a []any) any {
			cat := ixNlCatalogOf(ixArg(a, 2))
			c := IntentNLFacadeCompiler("nl", "fam", cat, func(string) (string, error) { return ixS(a[1]), nil })
			out, err := c.Compile(map[string]any{"text": a[0]})
			if err != nil {
				panic(err)
			}
			return map[string]any{"prompt": IntentNLPrompt(ixS(a[0]), cat), "output": out}
		}),
		"nlRun": ixWrap(func(a []any) any {
			cat := ixNlCatalogOf(ixArg(a, 2))
			raw := ixS(a[1])
			c := IntentNLFacadeCompiler("nl", "fam", cat, func(string) (string, error) {
				if raw == "THROWS" {
					return "", errors.New("llm down")
				}
				return raw, nil
			})
			return IntentRunCompilers(map[string]any{"text": a[0]}, []IntentCompiler{c})
		}),
	})
}
