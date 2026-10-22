package pca

// Differential kill test for intent_session.go (rule 13: the intent_session wire member, the grant caveat, the signed session
// root) and intent_revocation.go (rule 13 step 7) against the TypeScript reference: testdata/k042-sessrevoc-cases.json comes
// from tools/pca-audit/java-mutate/k042-sessrevoc-oracle.mts (shared with the Java suite). The verdict (refused or not) must
// agree on every case; the reason text is compared exactly and counted where Go words it differently.

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

type k042SRStats struct {
	n  int
	td textDiffs
}

func k042SRCheck(t *testing.T, bad *[]string, st *k042SRStats, label string, want any, got string) {
	st.n++
	if (want == nil) != (got == "") {
		*bad = append(*bad, fmt.Sprintf("%s: want %v got <%s>", label, want, got))
		return
	}
	if want != nil {
		w := want.(string)
		if strings.HasSuffix(w, "(fail closed): ") {
			if !strings.HasPrefix(got, w) {
				st.td.add(w, got)
			}
		} else if w != got {
			st.td.add(w, got)
		}
	}
}

func TestK042SessionAndRevocationCorpus(t *testing.T) {
	b, err := os.ReadFile("testdata/k042-sessrevoc-cases.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := ParseJSONLenient(b)
	if err != nil {
		t.Fatal(err)
	}
	g := doc.(map[string]any)
	list := func(k string, min int) []map[string]any {
		var out []map[string]any
		for _, c := range g[k].([]any) {
			out = append(out, c.(map[string]any))
		}
		if len(out) < min {
			t.Fatalf("%s: only %d cases", k, len(out))
		}
		return out
	}
	parse := func(text any) any {
		v, err := ParseJSONLenient([]byte(text.(string)))
		if err != nil {
			t.Fatal(err)
		}
		return normalizeJSON(v)
	}
	var bad []string
	var st k042SRStats
	for _, c := range list("wire", 60) {
		k042SRCheck(t, &bad, &st, "wire "+c["name"].(string), c["reason"], validateIntentSessionWire(parse(c["v"])))
	}
	for _, c := range list("caveat", 17) {
		k042SRCheck(t, &bad, &st, "caveat "+c["name"].(string), c["reason"], intentSessionCaveatError(parse(c["c"])))
	}
	for _, c := range list("root", 150) {
		n := c["name"].(string)
		s := parse(c["s"])
		k042SRCheck(t, &bad, &st, "shape "+n, c["shape"], sessionRootShape(s))
		var pins any
		if p, has := c["pq_pins"]; has && p != nil {
			pins = parse(p)
		}
		k042SRCheck(t, &bad, &st, "verify "+n, c["verify"], verifySessionRoot(s, pins))
	}
	for _, c := range list("rev", 100) {
		if c["scope"] != nil {
			continue // Go has no custom-scope parameter: the session scope is always derived from the session id
		}
		var ev, ids, last any
		if c["ev"] != nil {
			ev = parse(c["ev"])
		}
		if c["ids"] != nil {
			ids = parse(c["ids"])
		}
		lastP := c["last"] != nil
		if lastP {
			last = parse(c["last"])
		}
		k042SRCheck(t, &bad, &st, "rev "+c["name"].(string), c["reason"],
			checkSessionRevocation(ev, c["session"], parse(c["authority"]), ids, c["now"], c["maxAge"], last, lastP, nil))
	}
	for _, c := range list("prim", 27) {
		in, err := ParseJSONLenient([]byte(c["text"].(string)))
		if err != nil {
			t.Fatal(err)
		}
		want := c["reason"] == nil
		if got := IntentRevocationPrimitive(in); got != want {
			bad = append(bad, fmt.Sprintf("prim %s: want ok=%v got %v (%v)", c["name"], want, got, c["reason"]))
		}
	}
	t.Logf("%d checks", st.n)
	st.td.finish(t)
	if len(bad) > 0 {
		if len(bad) > 40 {
			bad = bad[:40]
		}
		t.Fatalf("%d mismatches:\n%s", len(bad), strings.Join(bad, "\n"))
	}
}
