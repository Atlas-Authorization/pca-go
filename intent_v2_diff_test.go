package pca

// Intent Layer v2 differential test: decideIntentV2 against the TS reference decideIntentV2. testdata/k042-intentv2-cases.json.gz
// is the shared oracle (tools/pca-audit/java-mutate/k042-intentv2-oracle.mts; the Java, Kotlin, Python, PHP, .NET and Ruby
// suites run the same file): every case pins the EXACT decision (each check's name and ok, in order) AND the exact reason text
// (a reference reason that ends in "(fail closed): " carries a JavaScript error message, so only that prefix is compared).
// A JSON-null context has no Go spelling (nil = absent) and is skipped.

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
)

type v2DiffCase struct {
	Name   string            `json:"name"`
	P      string            `json:"p"`
	Grant  string            `json:"grant"`
	Ctx    *string           `json:"ctx"`
	Wp     *string           `json:"wp"`
	Now    float64           `json:"now"`
	Checks []json.RawMessage `json:"checks"`
}

func loadV2Diff(t *testing.T) []v2DiffCase {
	f, err := os.Open("testdata/k042-intentv2-cases.json.gz")
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
		Cases []v2DiffCase `json:"cases"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Cases
}

func TestIntentV2DifferentialAgainstTheReference(t *testing.T) {
	const failClosed = "(fail closed): "
	cases := loadV2Diff(t)
	if len(cases) < 1000 {
		t.Fatalf("only %d cases", len(cases))
	}
	var td textDiffs
	defer td.finish(t)
	for _, cs := range cases {
		p, err := ParseJSONLenient([]byte(cs.P))
		if err != nil {
			t.Fatalf("%s: p: %v", cs.Name, err)
		}
		g, err := ParseJSONLenient([]byte(cs.Grant))
		if err != nil {
			t.Fatalf("%s: grant: %v", cs.Name, err)
		}
		var ctx *IntentV2Context
		if cs.Ctx != nil && strings.TrimSpace(*cs.Ctx) == "null" {
			continue // decoded JSON null and an absent member are both nil in Go: documented "no context"
		}
		if cs.Ctx != nil {
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
		pm, _ := normalizeJSON(p).(map[string]any)
		gm, _ := normalizeJSON(g).(map[string]any)
		d := decideIntentV2(pm, gm, ctx, cs.Now)
		var want, got, wantD, gotD []string
		skip := false
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
				skip = true // a PQ suite this host lacks: by design
			}
			got = append(got, fmt.Sprintf("%s|%v|%s", c.name, c.ok, c.why))
			gotD = append(gotD, fmt.Sprintf("%s|%v", c.name, c.ok))
		}
		if skip {
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
	}
}
