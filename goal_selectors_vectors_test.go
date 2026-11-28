package pca

// Replay of the reference corpora for goal selectors: the verbs of a class selector, role resolution, expansion of a selector goal
// against the pinned catalog, selector typing, role keys, the policy card and the carrier form. The first corpus carries the catalog and
// ontology of a shipped domain by name; the second a hand-written catalog with confirmed verbs, the selector typing refusals and the
// catalog of a pack of defs.

import "testing"

func goalSelTest(f func(a []any) any) vecFn {
	return func(a []any) (any, error) { return anlTry(func() any { return f(a) }) }
}

// goalSelDomainOnt is the IR ontology of a shipped domain.
func goalSelDomainOnt(dom any) any { return goalToIrOntology(goalShippedOntology(dom), nil) }

func TestGoalSelectorsVectors(t *testing.T) {
	replayVectors(t, "ref-goal-selectors.json.gz", map[string]vecFn{
		"selCatalogOfDomain": goalSelTest(func(a []any) any { return goalSelCatalogOfDomain(vecArg(a, 0)) }),
		"selCatalogDigest":   goalSelTest(func(a []any) any { return goalSelCatalogDigest(vecArg(a, 0)) }),
		"selGoalDigest":      goalSelTest(func(a []any) any { return goalSelGoalDigest(vecArg(a, 0)) }),
		"classVerbs":         goalSelTest(func(a []any) any { return goalClassVerbs(vecArg(a, 0), vecArg(a, 1), vecArg(a, 2)) }),
		"allowClassVerbs":    goalSelTest(func(a []any) any { return goalAllowClassVerbs(vecArg(a, 0), vecArg(a, 1), vecArg(a, 2)) }),
		"floatClassVerbs":    goalSelTest(func(a []any) any { return goalFloatClassVerbs(vecArg(a, 0), vecArg(a, 1), vecArg(a, 2)) }),
		"resolveRole": goalSelTest(func(a []any) any {
			return goalResolveRole(goalSelDomainOnt(vecArg(a, 0)), vecArg(a, 1), vecArg(a, 2), vecArg(a, 3))
		}),
		"expandSelGoal": goalSelTest(func(a []any) any {
			return goalExpandSelGoal(vecArg(a, 0), goalSelDomainOnt(vecArg(a, 1)), vecArg(a, 2))
		}),
		"selReasons":       goalSelTest(func(a []any) any { return goalSelReasons(vecArg(a, 0), goalSelDomainOnt(vecArg(a, 1)), vecArg(a, 2)) }),
		"withRoleParams":   goalSelTest(func(a []any) any { return goalWithRoleParams(vecArg(a, 0), vecArg(a, 1)) }),
		"selCarrier":       goalSelTest(func(a []any) any { return goalSelCarrier(vecArg(a, 0)) }),
		"encodeSelCatalog": goalSelTest(func(a []any) any { return goalEncodeSelCatalog(vecArg(a, 0)) }),
		"renderSelCard": goalSelTest(func(a []any) any {
			return goalRenderSelCard(vecArg(a, 0), goalSelDomainOnt(vecArg(a, 1)), vecArg(a, 2), nil)
		}),
		"traitClosure": goalSelTest(func(a []any) any { return goalTraitClosure(vecArg(a, 0), nil) }),
	})
}

// goalSelRefOnt is a shipped domain's IR ontology when x names one, else x itself.
func goalSelRefOnt(x any) any {
	if o := goalShippedOntology(x); o != nil {
		return goalToIrOntology(o, nil)
	}
	return x
}

// goalSelRefCat is a shipped domain's catalog when x names one, else x itself.
func goalSelRefCat(x any) any {
	if c := goalShippedCatalog(x); c != nil {
		return c
	}
	return x
}

func TestGoalSelectorsReferenceCorpus(t *testing.T) {
	replayVectors(t, "ref-goal-selectors-java.json.gz", map[string]vecFn{
		"selCatalogDigest": goalSelTest(func(a []any) any { return goalSelCatalogDigest(goalSelRefCat(vecArg(a, 0))) }),
		"selGoalDigest":    goalSelTest(func(a []any) any { return goalSelGoalDigest(vecArg(a, 0)) }),
		"classVerbs": goalSelTest(func(a []any) any {
			return goalClassVerbs(goalSelRefCat(vecArg(a, 0)), vecArg(a, 1), vecArg(a, 2))
		}),
		"allowClassVerbs": goalSelTest(func(a []any) any {
			return goalAllowClassVerbs(goalSelRefCat(vecArg(a, 0)), vecArg(a, 1), vecArg(a, 2))
		}),
		"floatClassVerbs": goalSelTest(func(a []any) any {
			return goalFloatClassVerbs(goalSelRefCat(vecArg(a, 0)), vecArg(a, 1), vecArg(a, 2))
		}),
		"resolveRole": goalSelTest(func(a []any) any {
			return goalResolveRole(goalSelRefOnt(vecArg(a, 0)), goalSelRefCat(vecArg(a, 1)), vecArg(a, 2), vecArg(a, 3))
		}),
		"expandSelGoal": goalSelTest(func(a []any) any {
			return goalExpandSelGoal(vecArg(a, 0), goalSelRefOnt(vecArg(a, 1)), goalSelRefCat(vecArg(a, 2)))
		}),
		"selReasons": goalSelTest(func(a []any) any {
			return goalSelReasons(vecArg(a, 0), goalSelRefOnt(vecArg(a, 1)), goalSelRefCat(vecArg(a, 2)))
		}),
		"compileSelGoal": goalSelTest(func(a []any) any {
			return goalCompileSelGoal(vecArg(a, 0), goalSelRefOnt(vecArg(a, 1)), goalSelRefCat(vecArg(a, 2)), nil)
		}),
		"withRoleParams": goalSelTest(func(a []any) any { return goalWithRoleParams(vecArg(a, 0), goalSelRefCat(vecArg(a, 1))) }),
		"renderSelCard": goalSelTest(func(a []any) any {
			return goalRenderSelCard(vecArg(a, 0), goalSelRefOnt(vecArg(a, 1)), goalSelRefCat(vecArg(a, 2)), nil)
		}),
		"selCarrier":       goalSelTest(func(a []any) any { return goalSelCarrier(vecArg(a, 0)) }),
		"encodeSelCatalog": goalSelTest(func(a []any) any { return goalEncodeSelCatalog(goalSelRefCat(vecArg(a, 0))) }),
		"traitClosure":     goalSelTest(func(a []any) any { return goalTraitClosure(vecArg(a, 0), nil) }),
		"catalogOfDomain":  goalSelTest(func(a []any) any { return goalSelCatalogOfDomain(vecArg(a, 0)) }),
		"catalogOfDefs":    goalSelTest(func(a []any) any { return goalSelCatalogOfDefs(vecArg(a, 0), nil, nil) }),
	})
}
