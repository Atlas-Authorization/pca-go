package pca

import (
	"encoding/json"
	"sort"
	"unicode/utf16"
)

// Forbid-wins certificate check (security contract C-241): a port of `certificateConsistent` in
// packages/pca/src/forbid-certificate.ts (the TypeScript is authoritative).
//
// A certificate lists, per policy clause, whether it matched (true / unknown / false). The decision, the winner and the shadowed
// list follow from that table alone: any matched forbid denies (the most authoritative signer is named, ties by id); otherwise
// no matched permit denies; otherwise a matched escalate clause escalates; otherwise allow. No predicate evaluator is needed.
// Total: any malformed certificate is not consistent.

type certRow struct {
	id, kind, value string
	signer          *string
}

// ForbidCertificateConsistent reports whether the certificate's own table entails its decision, winner and shadowed list.
// `precedence` lists signers from most to least authoritative.
func ForbidCertificateConsistent(cert any, precedence []string) bool {
	c, ok := cert.(map[string]any)
	if !ok || c["v"] != jsonOne() || c["kind"] != "forbid-wins" {
		return false
	}
	raw, ok := c["clauses"].([]any)
	winner, wok := c["winner"].(map[string]any)
	shadowed, sok := c["shadowed"].([]any)
	if !ok || !wok || !sok {
		return false
	}
	if winner["kind"] == "malformed" {
		return len(raw) == 0 && c["decision"] == "deny" && winner["id"] == nil && len(shadowed) == 0
	}
	rows := make([]certRow, 0, len(raw))
	for _, x := range raw {
		m, ok := x.(map[string]any)
		if !ok {
			return false
		}
		id, ok1 := m["id"].(string)
		kind, ok2 := m["kind"].(string)
		value, ok3 := m["value"].(string)
		if !ok1 || !ok2 || !ok3 || (kind != "permit" && kind != "forbid" && kind != "escalate") || (value != "true" && value != "false" && value != "unknown") {
			return false
		}
		r := certRow{id: id, kind: kind, value: value}
		if s, ok := m["signer"].(string); ok {
			r.signer = &s
		}
		rows = append(rows, r)
	}
	rank := func(r certRow) int {
		if r.signer != nil {
			for i, p := range precedence {
				if p == *r.signer {
					return i
				}
			}
		}
		return len(precedence) // an unlisted (or absent) signer ranks last
	}
	hit := func(kind string) []certRow {
		var out []certRow
		for _, r := range rows {
			if r.kind == kind && r.value != "false" {
				out = append(out, r)
			}
		}
		return out
	}
	forbids, permits, escalates := hit("forbid"), hit("permit"), hit("escalate")
	sort.SliceStable(forbids, func(i, j int) bool {
		a, b := rank(forbids[i]), rank(forbids[j])
		if a != b {
			return a < b
		}
		return utf16Less(forbids[i].id, forbids[j].id)
	})
	var win *certRow
	decision, kind := "deny", "none"
	switch {
	case len(forbids) > 0:
		win, kind = &forbids[0], "forbid"
	case len(permits) == 0:
	case len(escalates) > 0:
		win, decision, kind = &escalates[0], "escalate", "escalate"
	default:
		win, decision, kind = &permits[0], "allow", "permit"
	}
	others := []any{}
	for _, group := range [][]certRow{forbids, permits, escalates} {
		for i := range group {
			if win == nil || group[i].id != win.id || group[i].kind != win.kind {
				others = append(others, group[i].id)
			}
		}
	}
	var wantID any
	if win != nil {
		wantID = win.id
	}
	if c["decision"] != decision || winner["kind"] != kind || winner["id"] != wantID || len(shadowed) != len(others) {
		return false
	}
	for i := range others {
		if shadowed[i] != others[i] {
			return false
		}
	}
	return true
}

func jsonOne() any { return json.Number("1") }

// utf16Less orders strings by UTF-16 code unit like JavaScript's `<` (the reference orders ids that way).
func utf16Less(a, b string) bool {
	x, y := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(x) && i < len(y); i++ {
		if x[i] != y[i] {
			return x[i] < y[i]
		}
	}
	return len(x) < len(y)
}
