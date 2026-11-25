package pca

import (
	"compress/gzip"
	"io"
	"os"
	"testing"
)

// Differential replay of the intent session surface against the reference (testdata/killSession.json.gz): the `intent_session`
// wire member, the grant caveat and its lookup, the session root shape and its signature. Every case carries the reference's
// reason (null = accepted). A case that the reference and this verifier both refuse, with different words, is a text difference
// (reported by textDiffs); accepting where the reference refuses, or the reverse, fails.
func TestIntentSessionKillCorpus(t *testing.T) {
	f, err := os.Open("testdata/killSession.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	v, err := ParseJSONLenient(raw)
	if err != nil {
		t.Fatal(err)
	}
	doc := vecObj(v)
	var td textDiffs
	defer td.finish(t)
	total := 0
	check := func(section, member string, got func(c map[string]any) string) {
		cases, _ := doc[section].([]any)
		if len(cases) == 0 {
			t.Fatalf("no %s cases", section)
		}
		for _, cv := range cases {
			c := vecObj(cv)
			want, _ := c[member].(string) // null = accepted
			g := got(c)
			total++
			switch {
			case (want == "") != (g == ""):
				t.Errorf("%s/%s (%s): want %q got %q", section, vecStr(c, "name"), member, want, g)
			case want != g:
				td.add(want, g)
			}
		}
	}
	check("wire", "ts", func(c map[string]any) string { return ValidateIntentSessionWire(c["arg"]) })
	check("caveat", "ts", func(c map[string]any) string { return IntentSessionCaveatError(c["arg"]) })
	check("root", "shape", func(c map[string]any) string { return SessionRootShapeError(normalizeJSON(c["arg"])) })
	check("root", "verify", func(c map[string]any) string {
		var pins any
		if p, has := c["pins"]; has {
			pins = normalizeJSON(p)
		}
		r := VerifySessionRoot(normalizeJSON(c["arg"]), pins)
		reason, _ := r["reason"].(string)
		if r["ok"] != true && reason == "" {
			reason = "refused"
		}
		return reason
	})
	grants, _ := doc["grant"].([]any)
	for _, cv := range grants {
		c := vecObj(cv)
		total++
		got, found := GrantSessionCaveat(c["arg"])
		idx, wantFound := jsNum(c["want_index"])
		if found != wantFound {
			t.Errorf("grant/%s: found %v, the reference %v", vecStr(c, "name"), found, wantFound)
			continue
		}
		if found {
			list, _ := vecObj(c["arg"])["caveats"].([]any)
			if baseCanon(list[int(idx)]) != baseCanon(got) {
				t.Errorf("grant/%s: not the caveat at index %d", vecStr(c, "name"), int(idx))
			}
		}
	}
	if total != 123+29+207+207+11 {
		t.Fatalf("replayed %d checks", total)
	}
}
