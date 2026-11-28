package pcasigstore

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"

	pca "github.com/Atlas-Authorization/pca-go"
)

// Replays packages/pca/conformance/sigstore-vectors.json (track K9): ok must match, and on ok the whole core.
func loadVectors(t *testing.T) map[string]any {
	t.Helper()
	for _, p := range []string{"../conformance/sigstore-vectors.json", "../conformance/sigstore-vectors.json"} {
		if b, err := os.ReadFile(p); err == nil {
			var v map[string]any
			if err := json.Unmarshal(b, &v); err != nil {
				t.Fatal(err)
			}
			return v
		}
	}
	t.Fatal("sigstore-vectors.json is missing")
	return nil
}

func TestSigstoreVectors(t *testing.T) {
	d := loadVectors(t)
	roots := d["roots"].(map[string]any)
	cases := d["cases"].([]any)
	if len(cases) < 30 {
		t.Fatalf("only %d cases", len(cases))
	}
	facts := 0
	defer func() { t.Logf("%d cases replayed, %d produced gate-valid SLSA facts", len(cases), facts) }()
	for _, x := range cases {
		c := x.(map[string]any)
		name := c["name"].(string)
		rj, _ := json.Marshal(roots[c["roots"].(string)])
		tr, err := ParseTrustedRoot(rj)
		if err != nil {
			t.Fatalf("%s: root: %v", name, err)
		}
		bj, _ := json.Marshal(c["bundle"])
		r := VerifySigstoreBundleCore(bj, tr)
		exp := c["expect"].(map[string]any)
		if r.OK != exp["ok"].(bool) {
			t.Errorf("%s: ok=%v (%s: %s), want %v (%v)", name, r.OK, r.Code, r.Detail, exp["ok"], exp["code"])
			continue
		}
		if !r.OK {
			continue
		}
		got, _ := json.Marshal(r.Core)
		var g any
		_ = json.Unmarshal(got, &g)
		if !reflect.DeepEqual(g, exp["core"]) {
			want, _ := json.Marshal(exp["core"])
			t.Errorf("%s: core\n got %s\nwant %s", name, got, want)
		}
		if f := VerifySigstoreBundle(bj, tr); f.OK {
			if e := pca.ProvenanceFactsError(f.Facts); e != "" {
				t.Errorf("%s: facts rejected by the gate: %s", name, e)
			}
			facts++
		}
	}
}

func TestSigstoreHostile(t *testing.T) {
	d := loadVectors(t)
	var tr = func() []byte { b, _ := json.Marshal(d["roots"].(map[string]any)["public-good-844a1c6d"]); return b }()
	root, err := ParseTrustedRoot(tr)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range []string{``, `null`, `[]`, `{}`, `{"verificationMaterial":{}}`, `{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json","verificationMaterial":{"certificate":{"rawBytes":"AA=="}},"dsseEnvelope":{"payloadType":"application/vnd.in-toto+json","signatures":[{"sig":""}]}}`} {
		if r := VerifySigstoreBundleCore([]byte(b), root); r.OK {
			t.Errorf("%q accepted", b)
		}
	}
	if r := VerifySigstoreBundleCore([]byte(`{}`), nil); r.OK {
		t.Error("nil root accepted")
	}
}
