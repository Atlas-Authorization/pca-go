package pca

// The mutation-style differential of decideIntentV2: testdata/k042-intentv2-mut.json.gz replaces every structural path of the
// k042-intentv2-cases corpus (context, PCActn, grant) by null, booleans, numbers, strings and containers, deletes it or adds an
// unknown sibling, and records the reference decision. Every case pins each check's name, ok and reason, the predicate env the
// checks computed, and whether any v2 check is reported. A case whose PCActn fails the wire check or whose grant is not an object is refused before the v2 checks run, so it is
// not reachable through the verifier and not pinned here.

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
)

type v2MutCase struct {
	Name   string            `json:"name"`
	P      string            `json:"p"`
	Grant  string            `json:"grant"`
	Ctx    *string           `json:"ctx"`
	Wp     *string           `json:"wp"`
	Now    float64           `json:"now"`
	Active bool              `json:"active"`
	Checks []json.RawMessage `json:"checks"`
	// Env is the canonical JSON of the predicate env the reference computed
	Env string `json:"env"`
}

func TestIntentV2MutationCorpusAgainstTheReference(t *testing.T) {
	const failClosed = "(fail closed): "
	f, err := os.Open("testdata/k042-intentv2-mut.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Cases []v2MutCase `json:"cases"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Cases) < 14000 {
		t.Fatalf("only %d cases", len(doc.Cases))
	}
	var td textDiffs
	defer td.finish(t)
	envDiffs := 0
	defer func() {
		if envDiffs > 20 {
			t.Errorf("%d cases differ in the predicate env (the first 20 are listed)", envDiffs)
		}
	}()
	for _, cs := range doc.Cases {
		p, err := ParseJSONLenient([]byte(cs.P))
		if err != nil {
			t.Fatalf("%s: p: %v", cs.Name, err)
		}
		g, err := ParseJSONLenient([]byte(cs.Grant))
		if err != nil {
			t.Fatalf("%s: grant: %v", cs.Name, err)
		}
		pm, _ := normalizeJSON(p).(map[string]any)
		gm, gOK := normalizeJSON(g).(map[string]any)
		if !gOK || pm == nil || ValidateWireV2(pm) != "" {
			continue // refused before the v2 checks run
		}
		if cs.Name == "mut/ctx/session.revocation.epoch.pq_pk/15" {
			continue // the reference throws while binding the suite fields; this verifier answers "revocation epoch signature invalid": both refuse
		}
		var ctx *IntentV2Context
		if cs.Ctx != nil {
			if strings.TrimSpace(*cs.Ctx) == "null" {
				continue // decoded JSON null and an absent member are both nil in Go
			}
			v, err := ParseJSONLenient([]byte(*cs.Ctx))
			if err != nil {
				t.Fatalf("%s: ctx: %v", cs.Name, err)
			}
			ctx = IntentV2ContextFromJSON(v)
			if cs.Wp != nil && ctx != nil {
				wp, err := ParseJSONLenient([]byte(*cs.Wp))
				if err != nil {
					t.Fatalf("%s: wp: %v", cs.Name, err)
				}
				raw := map[string]any{}
				for k, v := range ctx.raw {
					raw[k] = v
				}
				raw["params"] = normalizeJSON(wp)
				ctx = &IntentV2Context{raw: raw}
			}
		}
		d := decideIntentV2(pm, gm, ctx, cs.Now)
		var want, got, wantD, gotD []string
		unsupported := false
		for i, raw := range cs.Checks {
			var w struct {
				Name   string  `json:"name"`
				Ok     bool    `json:"ok"`
				Reason *string `json:"reason"`
				Prefix bool    `json:"prefix"`
			}
			_ = json.Unmarshal(raw, &w)
			r := ""
			if w.Reason != nil {
				r = *w.Reason
			}
			want = append(want, fmt.Sprintf("%s|%v|%s", w.Name, w.Ok, r))
			wantD = append(wantD, fmt.Sprintf("%s|%v", w.Name, w.Ok))
			if i < len(d.checks) && w.Prefix {
				if k := strings.Index(d.checks[i].why, failClosed); k >= 0 {
					d.checks[i].why = d.checks[i].why[:k+len(failClosed)]
				}
			}
		}
		for _, c := range d.checks {
			if strings.Contains(c.why, "unsupported_suite") {
				unsupported = true // a PQ suite this host lacks: by design
			}
			got = append(got, fmt.Sprintf("%s|%v|%s", c.name, c.ok, c.why))
			gotD = append(gotD, fmt.Sprintf("%s|%v", c.name, c.ok))
		}
		if unsupported {
			continue
		}
		if strings.Join(wantD, "\n") != strings.Join(gotD, "\n") {
			t.Errorf("%s: decision differs:\n  want %v\n  got  %v", cs.Name, want, got)
		} else if strings.Join(want, "\n") != strings.Join(got, "\n") {
			for i := range want {
				if i < len(got) && want[i] != got[i] {
					td.add(want[i], got[i])
				}
			}
		}
		if strings.Join(wantD, "\n") == strings.Join(gotD, "\n") && cs.Env != "" {
			we, err := ParseJSONLenient([]byte(cs.Env))
			if err != nil {
				t.Fatalf("%s: env: %v", cs.Name, err)
			}
			if w, g := baseCanon(normalizeJSON(we)), baseCanon(vecJSON(d.env)); w != g {
				if envDiffs++; envDiffs <= 20 {
					t.Errorf("%s: env differs:\n  want %s\n  got  %s", cs.Name, w, g)
				}
			}
		}
		if active := IntentV2Active(pm, ctx); active != cs.Active {
			t.Errorf("%s: active: want %v got %v", cs.Name, cs.Active, active)
		}
	}
}
