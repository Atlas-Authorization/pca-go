package blstkit

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	pca "github.com/Atlas-Authorization/pca-go"
)

// Replay of reference corpora (testdata/*.json.gz): {"cases":[{"fn","name","args","out"}...]}. Bytes are
// {"$bytes": base64url}; secret keys are seed labels {"$seed": label} derived from sha256("atlas-pca-conformance/"+label).

type vecCase struct {
	Fn, Name string
	Args     []any
	Out      any
}

func loadCorpus(t *testing.T, file string) []vecCase {
	t.Helper()
	path := file
	if !filepath.IsAbs(file) {
		path = "testdata/" + file
	}
	fh, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	zr, err := gzip.NewReader(fh)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	// the lenient fixture parser keeps lone surrogate escapes (as WTF-8) and number lexemes (json.Number)
	doc, err := pca.ParseJSONLenient(raw)
	if err != nil {
		t.Fatal(err)
	}
	list, _ := doc.(map[string]any)["cases"].([]any)
	out := make([]vecCase, len(list))
	for i, c := range list {
		m := c.(map[string]any)
		out[i] = vecCase{Fn: m["fn"].(string), Name: m["name"].(string), Args: vecList(m["args"]), Out: m["out"]}
	}
	return out
}

func vecObj(v any) map[string]any { m, _ := v.(map[string]any); return m }

func vecList(v any) []any { l, _ := v.([]any); return l }

// vecBytes decodes {"$bytes": b64url}; nil for anything else.
func vecBytes(v any) []byte {
	s, ok := vecObj(v)["$bytes"].(string)
	if !ok {
		return nil
	}
	b, err := b64u.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func vecByteList(v any) [][]byte {
	l := vecList(v)
	out := make([][]byte, len(l))
	for i, x := range l {
		out[i] = vecBytes(x)
	}
	return out
}

func seedBytes(label string) []byte {
	d := sha256.Sum256([]byte("atlas-pca-conformance/" + label))
	return d[:]
}

// vecSecret resolves a secret scalar argument: a {"$seed": label} (sha256(seed) reduced into 1..r-1) or {"$bytes"}.
func vecSecret(v any) []byte {
	if label, ok := vecObj(v)["$seed"].(string); ok {
		r, _ := new(big.Int).SetString("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16)
		d := sha256.Sum256(seedBytes(label))
		n := new(big.Int).SetBytes(d[:])
		n.Mod(n, new(big.Int).Sub(r, big.NewInt(1))).Add(n, big.NewInt(1))
		return n.FillBytes(make([]byte, 32))
	}
	return vecBytes(v)
}

// vecNorm turns a native result into the corpus JSON shape ([]byte -> {"$bytes"}).
func vecNorm(v any) any {
	switch x := v.(type) {
	case []byte:
		return map[string]any{"$bytes": b64u.EncodeToString(x)}
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = vecNorm(e)
		}
		return out
	case [][]byte:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = vecNorm(e)
		}
		return out
	case []string:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = e
		}
		return out
	case map[string]any:
		if x == nil {
			return nil
		}
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = vecNorm(e)
		}
		return out
	case int:
		return json.Number(fmt.Sprint(x))
	}
	return v
}

func vecCanon(v any) string {
	b, err := json.Marshal(vecNorm(v))
	if err != nil {
		return fmt.Sprintf("<unmarshalable %T>", v)
	}
	return string(b)
}

type vecFn func(args []any) (any, error)

// replay runs every case through its entry point; prep (optional) may rewrite a case (e.g. resolve seed labels) first.
func replay(t *testing.T, file string, fns map[string]vecFn, prep ...func(*vecCase)) {
	t.Helper()
	cases := loadCorpus(t, file)
	for i := range cases {
		for _, p := range prep {
			p(&cases[i])
		}
	}
	ran := map[string]int{}
	fails := 0
	fail := func(c vecCase, f string, a ...any) {
		fails++
		if fails <= 40 {
			t.Errorf("%s: %s", c.Name, fmt.Sprintf(f, a...))
		}
	}
	for _, c := range cases {
		f, ok := fns[c.Fn]
		if !ok {
			fail(c, "no entry point for %s", c.Fn)
			continue
		}
		ran[c.Fn]++
		var got any
		var err error
		func() {
			defer func() {
				if p := recover(); p != nil {
					err = fmt.Errorf("panic: %v", p)
				}
			}()
			got, err = f(c.Args)
		}()
		if _, throws := vecObj(c.Out)["$throws"]; throws {
			if err == nil {
				fail(c, "reference refuses, got %s", vecCanon(got))
			}
			continue
		}
		if err != nil {
			fail(c, "refused (%v), want %s", err, vecCanon(c.Out))
			continue
		}
		if w, g := vecCanon(c.Out), vecCanon(got); w != g {
			fail(c, "want %s got %s", w, g)
		}
	}
	names := make([]string, 0, len(ran))
	for k := range ran {
		names = append(names, k)
	}
	sort.Strings(names)
	t.Logf("%s: %d cases, %d failures; %v", file, len(cases), fails, ran)
	if fails > 0 {
		t.Fatalf("%d of %d cases diverge", fails, len(cases))
	}
}

// replaySecretGen replays ref-<name>-gen.json.gz (the cases that carry private keys; CI generates it with gen-secret-corpus.sh, never
// committed) in a subtest: next to the main corpus unless PCA_SECRET_CORPUS_DIR is set; missing fails under CI ("true"/"1"), else skips.
func replaySecretGen(t *testing.T, file string, run func(t *testing.T, path string)) {
	t.Helper()
	t.Run("gen", func(t *testing.T) {
		dir := os.Getenv("PCA_SECRET_CORPUS_DIR")
		if dir == "" {
			dir = "testdata"
		}
		path, _ := filepath.Abs(filepath.Join(dir, strings.TrimSuffix(file, ".json.gz")+"-gen.json.gz"))
		if _, err := os.Stat(path); err != nil {
			if ci := os.Getenv("CI"); ci == "true" || ci == "1" {
				t.Fatalf("secret corpus missing (%s): CI must generate it with gen-secret-corpus.sh", path)
			}
			t.Skipf("secret corpus missing (%s): run gen-secret-corpus.sh", path)
		}
		run(t, path)
	})
}
