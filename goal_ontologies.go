package pca

// The shipped intent ontologies and the selector catalog of each domain (the TypeScript reference is @atlasauth/pca-goal
// `ontologies`). Derived reference data: they read the action definitions, so the port ships the reference output as JSON
// (goal_ontologies.json, embedded) instead of re-deriving it.

import (
	_ "embed"
)

//go:embed goal_ontologies.json
var goalOntologiesJSON []byte

// GoalOntologyNames lists the shipped domains.
var GoalOntologyNames = []string{"calendar_travel", "code_repos", "data_access", "email", "payments"}

// goalOntologiesData parses the embedded data afresh, so every caller owns its copy.
func goalOntologiesData() map[string]any {
	v, err := ParseJSONLenient(goalOntologiesJSON)
	m, ok := v.(map[string]any)
	if err != nil || !ok {
		anlFail("goal_ontologies.json is unreadable")
	}
	return m
}

func goalOntologiesPick(section string, name any) any {
	n, ok := name.(string)
	if !ok {
		return nil
	}
	sec, _ := goalOntologiesData()[section].(map[string]any)
	if v, has := sec[n]; has {
		return v
	}
	return nil
}

// goalShippedOntology is the intent ontology of a shipped domain (a fresh copy), or nil for an unknown name.
func goalShippedOntology(name any) any { return goalOntologiesPick("ontologies", name) }

// goalShippedCatalog is the selector catalog {known, verbs} of a shipped domain (a fresh copy), or nil for an unknown name.
func goalShippedCatalog(name any) any { return goalOntologiesPick("catalogs", name) }

// GoalShippedOntology is goalShippedOntology (nil for an unknown name).
func GoalShippedOntology(name string) any { return goalShippedOntology(name) }

// GoalShippedCatalog is goalShippedCatalog (nil for an unknown name).
func GoalShippedCatalog(name string) any { return goalShippedCatalog(name) }

// GoalAllOntologies is every shipped intent ontology by domain name.
func GoalAllOntologies() map[string]any {
	out := map[string]any{}
	for _, n := range GoalOntologyNames {
		out[n] = goalShippedOntology(n)
	}
	return out
}
