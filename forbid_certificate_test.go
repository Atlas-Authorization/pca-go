package pca

import "testing"

// Shared vectors for the forbid-wins certificate: packages/pca/conformance/forbid-certificate-vectors.json (`table`).
func TestForbidCertificateTableVectors(t *testing.T) {
	table := load(t, "forbid-certificate-vectors.json")["table"].([]any)
	if len(table) < 19 {
		t.Fatalf("only %d table vectors", len(table))
	}
	for _, x := range table {
		v := x.(map[string]any)
		t.Run(v["name"].(string), func(t *testing.T) {
			var prec []string
			if o, ok := v["options"].(map[string]any); ok {
				for _, p := range o["precedence"].([]any) {
					prec = append(prec, p.(string))
				}
			}
			want := v["expect"].(map[string]any)["consistent"].(bool)
			if got := ForbidCertificateConsistent(v["certificate"], prec); got != want {
				t.Fatalf("consistent = %v, want %v", got, want)
			}
		})
	}
}

func TestForbidCertificateGarbageIsNotConsistent(t *testing.T) {
	for _, bad := range []any{nil, 5, []any{}, map[string]any{}, map[string]any{"v": jsonOne(), "kind": "forbid-wins", "clauses": "x"},
		map[string]any{"v": jsonOne(), "kind": "forbid-wins", "clauses": []any{nil}, "winner": map[string]any{}, "shadowed": []any{}}} {
		if ForbidCertificateConsistent(bad, nil) {
			t.Fatalf("%v accepted", bad)
		}
	}
}
