package pca

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

// Replay of the seeded provider catalog against the reference (ref-connectors-providers), every case: each provider manifest with its
// digest and validity, the structural invariants every built-in holds, the built-in order with the catalog digest, and the ids that
// are not in the catalog (case, whitespace, prototype names) and are never found.

func TestConnectorProvidersMatchTheReference(t *testing.T) {
	byID := func(id string) map[string]any {
		for _, m := range BuiltinManifests() {
			if m["id"] == id {
				return m
			}
		}
		return nil
	}
	strs := func(v any) []string { return attStrings(v) }
	fns := map[string]vecFn{
		"provider": func(a []any) (any, error) {
			m := byID(rsStr(vecArg(a, 0)))
			if m == nil {
				return nil, errors.New("not a built-in provider")
			}
			d, err := ManifestDigest(m)
			if err != nil {
				return nil, err
			}
			_, issues := ValidateManifest(m)
			return map[string]any{"manifest": m, "digest": d, "valid": len(issues) == 0}, nil
		},
		"invariants": func(a []any) (any, error) {
			id := rsStr(vecArg(a, 0))
			m := byID(id)
			if m == nil {
				return nil, errors.New("not a built-in provider")
			}
			avail, def := strs(m["scopesAvailable"]), strs(m["defaultScopes"])
			subset := true
			for _, s := range def {
				if !slices.Contains(avail, s) {
					subset = false
				}
			}
			uniq := map[string]bool{}
			for _, s := range avail {
				uniq[s] = true
			}
			https := strings.HasPrefix(rsStr(m["authorizeUrl"]), "https://") && strings.HasPrefix(rsStr(m["tokenUrl"]), "https://")
			return map[string]any{"defaultScopesSubset": subset, "scopesUnique": len(uniq) == len(avail), "idMatchesKey": m["id"] == id, "httpsEndpoints": https}, nil
		},
		"builtinManifests": func([]any) (any, error) {
			ids, digests := []any{}, []any{}
			for _, m := range BuiltinManifests() {
				d, err := ManifestDigest(m)
				if err != nil {
					return nil, err
				}
				ids, digests = append(ids, m["id"]), append(digests, d)
			}
			cd, err := CatalogDigest(nil)
			return map[string]any{"ids": ids, "digests": digests, "catalogDigest": cd}, err
		},
		"unknownProvider": func(a []any) (any, error) {
			id := rsStr(vecArg(a, 0))
			return map[string]any{"found": CreateDefaultRegistry().Get(id) != nil}, nil
		},
	}
	replayAll(t, "ref-connectors-providers.json.gz", 40, fns, nil, nil)
}
