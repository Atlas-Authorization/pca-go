package pca

// Re-importing a source: how the freshly imported defs differ from the ones a registry holds (added, changed, unchanged, removed),
// with the lock that remembers each operation's digest between syncs. Changed and added defs come back unreviewed.

import (
	"fmt"
	"strings"
)

// ActionSyncArgs are the inputs of ActionSyncSource: current and imported defs, the spec digest, the previous lock (nil = none),
// the clock (epoch ms) and the attestation check used when diffing (nil = never).
type ActionSyncArgs struct {
	Current, Imported []any
	SpecDigest        string
	Lock              map[string]any
	Now               any
	Confirmed         ActionDiffConfirmed
}

// ActionSyncSource compares imported defs with the current ones. The result is {defs, entries, deprecated, lock, needsReview}.
func ActionSyncSource(a ActionSyncArgs) (map[string]any, error) {
	cur := map[string]map[string]any{}
	for _, x := range a.Current {
		d, _ := x.(map[string]any)
		cur[jsAnyString(d["verb"])] = d
	}
	imp := map[string]map[string]any{}
	for _, x := range a.Imported {
		d, _ := x.(map[string]any)
		if rv, _ := d["review"].(map[string]any); rv["state"] == "confirmed" { // an imported def is never confirmed
			c := map[string]any{}
			for k, v := range d {
				c[k] = v
			}
			c["review"] = map[string]any{"state": "unreviewed"}
			d = c
		}
		imp[jsAnyString(d["verb"])] = d
	}
	var lockOps map[string]any
	if a.Lock != nil {
		lockOps, _ = a.Lock["ops"].(map[string]any)
	}
	verbs := make([]string, 0, len(imp))
	for v := range imp {
		verbs = append(verbs, v)
	}
	adSortU16(verbs)
	ops := map[string]any{}
	entries := []any{}
	defs := []any{}
	for _, verb := range verbs {
		d := imp[verb]
		dg, err := defDigest(d)
		if err != nil {
			return nil, err
		}
		ops[verb] = dg
		old, hasOld := cur[verb]
		locked, hasLocked := lockOps[verb]
		switch {
		case !hasOld:
			entries = append(entries, map[string]any{"verb": verb, "change": "added"})
			defs = append(defs, d)
			continue
		}
		oldDg, err := defDigest(old)
		if err != nil {
			return nil, err
		}
		if (hasLocked && locked == dg) || (!hasLocked && oldDg == dg) {
			entries = append(entries, map[string]any{"verb": verb, "change": "unchanged"})
			defs = append(defs, old)
			continue
		}
		diff, derr := ActionDiffDefs(old, d, coreRegistry, a.Confirmed)
		if derr != nil {
			diff = map[string]any{"class": "incomparable", "reasons": []any{derr.Error()}}
		}
		entries = append(entries, map[string]any{"verb": verb, "change": "changed", "diff": diff})
		defs = append(defs, d)
	}
	deprecated := []string{}
	for v := range lockOps {
		if _, in := imp[v]; !in {
			deprecated = append(deprecated, v)
		}
	}
	adSortU16(deprecated)
	for _, v := range deprecated {
		entries = append(entries, map[string]any{"verb": v, "change": "removed"})
	}
	needs := false
	for _, e := range entries {
		if c := e.(map[string]any)["change"]; c == "added" || c == "changed" {
			needs = true
		}
	}
	return map[string]any{"defs": defs, "entries": entries, "deprecated": anyStrs(deprecated),
		"lock":        map[string]any{"spec_digest": a.SpecDigest, "ops": ops, "synced_at": a.Now},
		"needsReview": needs}, nil
}

// ActionSyncText renders a sync result: one line per changed entry and a summary.
func ActionSyncText(r map[string]any) string {
	entries, _ := r["entries"].([]any)
	var lines []string
	count := map[string]int{}
	for _, x := range entries {
		e := x.(map[string]any)
		c := jsAnyString(e["change"])
		count[c]++
		if c == "unchanged" {
			continue
		}
		line := fmt.Sprintf("%-9s %s", c, jsAnyString(e["verb"]))
		if diff, ok := e["diff"].(map[string]any); ok {
			line += "  (" + jsAnyString(diff["class"])
			if rs, _ := strsOf(diff["reasons"]); len(rs) > 0 {
				line += ": " + strings.Join(rs, ", ")
			}
			line += ")"
		}
		lines = append(lines, line)
	}
	tail := ""
	if r["needsReview"] == true {
		tail = "; added and changed actions are unreviewed (strict) until a reviewer confirms them"
	}
	lines = append(lines, fmt.Sprintf("%d added, %d changed, %d removed (deprecated), %d unchanged%s", count["added"], count["changed"], count["removed"], count["unchanged"], tail))
	return strings.Join(lines, "\n")
}
