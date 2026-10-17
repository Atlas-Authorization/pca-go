//go:build less && cgo

package pca

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// The LESS known answers (packages/pca/conformance/less-vectors.json, gen-less.mjs) through the suite wire rule and the
// ONE suite dispatch, in a `less` (cgo) build.
func TestLessKnownAnswers(t *testing.T) {
	var doc struct {
		Keys map[string]struct {
			PqPk  string `json:"pq_pk"`
			EdPub string `json:"ed_pub"`
		} `json:"keys"`
		Vectors []map[string]any `json:"vectors"`
	}
	if err := json.Unmarshal(mustRead(t, dir+"less-vectors.json"), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Vectors) < 20 {
		t.Fatalf("only %d vectors", len(doc.Vectors))
	}
	for _, v := range doc.Vectors {
		name, _ := v["name"].(string)
		key := doc.Keys[v["key"].(string)]
		art := map[string]any{"alg": v["alg"], "sig": v["sig"], "pq_pk": key.PqPk}
		if ov, ok := v["pq_pk_override"]; ok {
			art["pq_pk"] = ov
		}
		if ps, ok := v["pq_sig"]; ok {
			art["pq_sig"] = ps
		}
		exp := v["expect"].(map[string]any)
		wireOK := validateSignatureWire(art) == ""
		msg, ok := DecodeB64uStrict(v["message"].(string), -1)
		if !ok {
			t.Fatalf("%s: message", name)
		}
		verify := verifyLeafSuite(art["alg"], true, key.EdPub, callerVouchedPqKey(art["pq_pk"]), msg, art["sig"], art["pq_sig"])
		if wireOK != exp["wire_ok"].(bool) || (wireOK && verify) != exp["allow"].(bool) {
			t.Errorf("%s: wire %v verify %v, want %v", name, wireOK, verify, exp)
		}
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// lessc/ must be byte-identical to the canonical sdks/pca-less-c (in the repository; skipped in a published module).
func TestLessCopyMatchesCanonical(t *testing.T) {
	canon := "../pca-less-c"
	if _, err := os.Stat(filepath.Join(canon, "atlas_less.c")); err != nil {
		t.Skip("canonical sdks/pca-less-c not present")
	}
	n := 0
	err := filepath.WalkDir("lessc", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel("lessc", p)
		if !bytes.Equal(mustRead(t, p), mustRead(t, filepath.Join(canon, rel))) {
			t.Errorf("lessc/%s differs from sdks/pca-less-c (run sdks/pca-less-c/sync-copies.sh)", rel)
		}
		n++
		return nil
	})
	if err != nil || n < 31 {
		t.Fatalf("walked %d files: %v", n, err)
	}
}
