package pca

// The signed per-definition changes between two versions of a pack (spec section 7.1, EvolutionRecord). A grant that pinned a
// definition digest follows a record chain only through steps the registry signed as `equal` or `narrow`; everything else needs
// the principal. Records are produced here from the semantic diff, signed as the registry, and checked against the change they
// claim to describe.

import (
	"errors"
	"fmt"
)

func evolveByVerb(defs []any) (map[string]map[string]any, error) {
	m := map[string]map[string]any{}
	for _, x := range defs {
		d, _ := x.(map[string]any)
		v, _ := d["verb"].(string)
		if _, dup := m[v]; dup {
			return nil, &CodedError{Code: "duplicate_def", Msg: fmt.Sprintf("verb '%s' appears twice", v)}
		}
		m[v] = d
	}
	return m, nil
}

// ActionEvolutionRecords are the unsigned records that take prev to next, sorted by verb. A verb rename is `removed` + `added`
// (grants on the old verb do not follow).
func ActionEvolutionRecords(ns string, prev, next []any, reg Registry, confirmed ActionDiffConfirmed) ([]any, error) {
	a, err := evolveByVerb(prev)
	if err != nil {
		return nil, err
	}
	b, err := evolveByVerb(next)
	if err != nil {
		return nil, err
	}
	verbs := make([]string, 0, len(a)+len(b))
	for v := range a {
		verbs = append(verbs, v)
	}
	for v := range b {
		if _, in := a[v]; !in {
			verbs = append(verbs, v)
		}
	}
	adSortU16(verbs)
	out := []any{}
	for _, verb := range verbs {
		o, n := a[verb], b[verb]
		base := func(from, to any, class string, reasons []any) map[string]any {
			return map[string]any{"v": jsNumber(1), "kind": evolutionRecordKind, "ns": ns, "verb": verb, "from": from, "to": to, "class": class, "reasons": reasons}
		}
		switch {
		case o == nil:
			to, err := defDigest(n)
			if err != nil {
				return nil, err
			}
			out = append(out, base(nil, to, "added", []any{}))
		case n == nil:
			from, err := defDigest(o)
			if err != nil {
				return nil, err
			}
			out = append(out, base(from, nil, "removed", []any{}))
		default:
			from, err := defDigest(o)
			if err != nil {
				return nil, err
			}
			to, err := defDigest(n)
			if err != nil {
				return nil, err
			}
			if from == to {
				continue
			}
			d, err := ActionDiffDefs(o, n, reg, confirmed)
			if err != nil {
				return nil, err
			}
			out = append(out, base(from, to, d["class"].(string), d["reasons"].([]any)))
		}
	}
	return out, nil
}

// ActionSignEvolution signs the records as the registry (an Ed25519 seed; kid names the pinned registry key entry). A record that
// is not a well-formed unsigned record is an error.
func ActionSignEvolution(records []any, kid string, seed []byte) ([]any, error) {
	kp, err := KeyPairFromSeed(seed)
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(records))
	for _, rv := range records {
		if bad := evolutionRecordError(rv, false); bad != "" {
			return nil, errors.New("signEvolutionRecord: " + bad)
		}
		r := rv.(map[string]any)
		sig, err := signBody(kp, evolutionDomain, r)
		if err != nil {
			return nil, err
		}
		signed := map[string]any{}
		for k, v := range r {
			signed[k] = v
		}
		signed["sig"] = map[string]any{"alg": "ed25519", "kid": kid, "value": sig}
		out = append(out, signed)
	}
	return out, nil
}

func evolveKey(r map[string]any) string {
	dd, _ := evolutionDiffDigest(r)
	show := func(v any) string {
		if v == nil {
			return "null"
		}
		return jsAnyString(v)
	}
	return jsAnyString(r["verb"]) + "|" + show(r["from"]) + "|" + show(r["to"]) + "|" + jsAnyString(r["class"]) + "|" + dd
}

// ActionEvolutionError says whether records EXACTLY describe the change from prev to next: every record verifies under the pinned
// registry keys and names ns; none is missing and none is extra; the class of each is the one the diff computes (a registry cannot
// sign `narrow` for a widening). "" = consistent, else the reason.
func ActionEvolutionError(ns string, prev, next []any, records []any, keys any, reg Registry, confirmed ActionDiffConfirmed) (reason string) {
	defer func() {
		if p := recover(); p != nil {
			reason = fmt.Sprint("evolution error: ", p)
		}
	}()
	for _, rv := range records {
		if bad := verifyEvolutionRecord(rv, keys); bad != "" {
			return "evolution record: " + bad
		}
		if r := rv.(map[string]any); r["ns"] != ns {
			return fmt.Sprintf("evolution record names namespace '%s', not '%s'", jsAnyString(r["ns"]), ns)
		}
	}
	recs, err := ActionEvolutionRecords(ns, prev, next, reg, confirmed)
	if err != nil {
		return "evolution error: " + err.Error()
	}
	var want, have []string
	for _, r := range recs {
		want = append(want, evolveKey(r.(map[string]any)))
	}
	for _, rv := range records {
		u := map[string]any{}
		for k, v := range rv.(map[string]any) {
			if k != "sig" {
				u[k] = v
			}
		}
		have = append(have, evolveKey(u))
	}
	adSortU16(want)
	adSortU16(have)
	if len(want) != len(have) {
		return fmt.Sprintf("evolution has %d records, the change needs %d", len(have), len(want))
	}
	for i := range want {
		if want[i] != have[i] {
			return "evolution records do not match the computed change (a missing, extra or mis-classified record)"
		}
	}
	return ""
}
