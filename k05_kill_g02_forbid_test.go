package pca

import (
	"encoding/json"
	"testing"
)

// Forbid-wins certificate (forbid_certificate.go): the ranking, the tie-break, the shadowed list and utf16Less, pinned by
// certificates whose consistency each depends on exactly one rule.

func g02cert(decision, winnerKind string, winnerID any, shadowed []any, clauses ...map[string]any) map[string]any {
	raw := []any{}
	for _, c := range clauses {
		raw = append(raw, c)
	}
	w := map[string]any{"kind": winnerKind}
	if winnerID != nil {
		w["id"] = winnerID
	}
	return map[string]any{"v": json.Number("1"), "kind": "forbid-wins", "clauses": raw, "winner": w, "shadowed": shadowed, "decision": decision}
}

func g02clause(id, kind, value, signer string) map[string]any {
	m := map[string]any{"id": id, "kind": kind, "value": value}
	if signer != "" {
		m["signer"] = signer
	}
	return m
}

func TestG02ForbidCertificateRules(t *testing.T) {
	rows := []struct {
		name string
		cert any
		prec []string
		want bool
	}{
		{"no clauses member", map[string]any{"v": json.Number("1"), "kind": "forbid-wins", "winner": map[string]any{"kind": "malformed"}, "shadowed": []any{}, "decision": "deny"}, nil, false},
		{"clause without an id", g02cert("deny", "forbid", "", []any{}, map[string]any{"kind": "forbid", "value": "true"}), nil, false},
		{"empty clauses deny with no winner", g02cert("deny", "none", nil, []any{}), nil, true},
		{"most authoritative forbid wins", g02cert("deny", "forbid", "b", []any{"a"}, g02clause("a", "forbid", "true", "low"), g02clause("b", "forbid", "true", "high")), []string{"high", "low"}, true},
		{"signed forbid outranks unsigned", g02cert("deny", "forbid", "b", []any{"a"}, g02clause("a", "forbid", "true", ""), g02clause("b", "forbid", "true", "high")), []string{"high"}, true},
		{"equal ranks tie by id", g02cert("deny", "forbid", "a", []any{"b"}, g02clause("b", "forbid", "true", ""), g02clause("a", "forbid", "true", "")), nil, true},
		{"one forbid beats a permit", g02cert("deny", "forbid", "f", []any{"p"}, g02clause("f", "forbid", "true", ""), g02clause("p", "permit", "true", "")), nil, true},
		{"shadowed must name the others", g02cert("deny", "forbid", "f", []any{"x"}, g02clause("f", "forbid", "true", ""), g02clause("p", "permit", "true", "")), nil, false},
	}
	for _, r := range rows {
		if got := ForbidCertificateConsistent(r.cert, r.prec); got != r.want {
			t.Errorf("%s: consistent = %v, want %v", r.name, got, r.want)
		}
	}
}

func TestG02Utf16Less(t *testing.T) {
	for _, r := range []struct {
		a, b string
		want bool
	}{
		{"ab", "bb", true},
		{"bb", "ab", false},
		{"ab", "ac", true},
		{"a", "ab", true},
		{"ab", "a", false},
		{"a", "a", false},
		{"", "a", true},
	} {
		if got := utf16Less(r.a, r.b); got != r.want {
			t.Errorf("utf16Less(%q, %q) = %v, want %v", r.a, r.b, got, r.want)
		}
	}
}
