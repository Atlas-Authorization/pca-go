package pca

// Generic replay of a reference-oracle corpus whose cases compare by JSON value: each fn maps to a Go entry point that takes the
// case args and returns (value, error). A reference throw requires an error; otherwise the value must equal the reference output
// (both sides canonicalized; Go slices / structs are round-tripped through encoding/json first). A reference throw that carries a
// stable `code` requires a *CodedError with that code (a JS-runtime ERR_* code only requires the refusal). A panic is a divergence.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// replayRec records, across every replay of the package, the functions that ran (by name) and those a replay skipped (per corpus),
// so that a final test can demand that no skipped function is replayed nowhere.
var replayRec = struct {
	sync.Mutex
	ran     map[string]int
	skipped map[string]map[string]bool
}{ran: map[string]int{}, skipped: map[string]map[string]bool{}}

func replayRan(fn string) {
	replayRec.Lock()
	replayRec.ran[fn]++
	replayRec.Unlock()
}

func replaySkipped(file, fn string) {
	replayRec.Lock()
	if replayRec.skipped[file] == nil {
		replayRec.skipped[file] = map[string]bool{}
	}
	replayRec.skipped[file][fn] = true
	replayRec.Unlock()
}

type vecFn func(args []any) (any, error)

// vecSkip, returned by a vecFn, records the case as not comparable (with the reason) instead of comparing it.
type vecSkip string

func (s vecSkip) Error() string { return string(s) }

// vecEngineCrashRE is the shared definition of a raw JS-engine crash text in a corpus: such a case passes iff the native refuses
// (an error, or a refusal decision), never when it returns a value; the message is not compared.
var vecEngineCrashRE = regexp.MustCompile(`Cannot read propert(y|ies) of (null|undefined)|is not a function|is not iterable|Cannot convert undefined or null to object|Cannot destructure|Cannot use 'in' operator|Cannot create property|Reduce of empty array|is not an object|Cannot mix BigInt|Do not know how to serialize a BigInt|Converting circular structure|Invalid array length|Maximum call stack`)

// vecEngineCrash reports whether out is a throw with an engine-crash text (and no Node error code).
func vecEngineCrash(out any) bool {
	m := vecObj(out)
	msg, ok := m["$throws"].(string)
	if !ok {
		return false
	}
	if code, _ := m["code"].(string); strings.HasPrefix(code, "ERR_") {
		return false
	}
	return vecEngineCrashRE.MatchString(msg)
}

// vecRefusalValue reports whether a returned value is a refusal decision (ok / valid / admit / allow false, decision deny or
// escalate, or an error / refused member).
func vecRefusalValue(v any) bool {
	m, ok := v.(map[string]any)
	if !ok {
		return false
	}
	for _, k := range []string{"ok", "valid", "admit", "allow", "allowed", "verified", "accepted"} {
		if b, isB := m[k].(bool); isB && !b {
			return true
		}
	}
	if d, _ := m["decision"].(string); d == "deny" || d == "escalate" || d == "refuse" || d == "refused" {
		return true
	}
	for _, k := range []string{"error", "refused", "$throws"} {
		if x, has := m[k]; has && x != nil && x != false {
			return true
		}
	}
	return false
}

func vecJSON(v any) any {
	b, err := json.Marshal(vecWTFMask(v))
	if err != nil {
		return fmt.Sprintf("<unmarshalable %T: %v>", v, err)
	}
	x, err := ParseJSONLenient(b)
	if err != nil {
		return fmt.Sprintf("<unparsable %s>", b)
	}
	return normalizeJSON(vecWTFUnmask(x))
}

// encoding/json turns the WTF-8 bytes of a lone surrogate into U+FFFD, so a result string that carries one is masked as
// U+F8FF + four hex digits of the code unit before the round trip and restored after it (plain maps, slices and strings only).
func vecWTFMask(v any) any {
	switch t := v.(type) {
	case string:
		if !strings.Contains(t, "\xed") {
			return t
		}
		var sb strings.Builder
		for i := 0; i < len(t); i++ {
			if t[i] == 0xED && i+2 < len(t) && t[i+1] >= 0xA0 && t[i+1] <= 0xBF {
				fmt.Fprintf(&sb, "\uf8ff%04x", 0xD000|int(t[i+1]&0x3f)<<6|int(t[i+2]&0x3f))
				i += 2
				continue
			}
			sb.WriteByte(t[i])
		}
		return sb.String()
	case map[string]any:
		if t == nil { // a nil map is JS null/undefined, not {}
			return t
		}
		m := make(map[string]any, len(t))
		for k, x := range t {
			m[vecWTFMask(k).(string)] = vecWTFMask(x)
		}
		recordKeyOrder(m, jsKeys(t))
		return m
	case []any:
		a := make([]any, len(t))
		for i, x := range t {
			a[i] = vecWTFMask(x)
		}
		return a
	case []string:
		a := make([]string, len(t))
		for i, x := range t {
			a[i] = vecWTFMask(x).(string)
		}
		return a
	case map[string]string:
		if t == nil {
			return t
		}
		m := make(map[string]string, len(t))
		for k, x := range t {
			m[vecWTFMask(k).(string)] = vecWTFMask(x).(string)
		}
		return m
	}
	if v == nil {
		return v
	}
	return vecWTFMaskReflect(reflect.ValueOf(v)).Interface()
}

// vecWTFMaskReflect is vecWTFMask for typed results (named slices, structs with exported fields, pointers): a deep copy with every
// string masked. Structs with unexported fields are returned as they are.
func vecWTFMaskReflect(rv reflect.Value) reflect.Value {
	switch rv.Kind() {
	case reflect.String:
		out := reflect.New(rv.Type()).Elem()
		out.SetString(vecWTFMask(rv.String()).(string))
		return out
	case reflect.Slice:
		if rv.IsNil() || rv.Type().Elem().Kind() == reflect.Uint8 {
			return rv
		}
		out := reflect.MakeSlice(rv.Type(), rv.Len(), rv.Len())
		for i := 0; i < rv.Len(); i++ {
			out.Index(i).Set(vecWTFMaskReflect(rv.Index(i)))
		}
		return out
	case reflect.Array:
		out := reflect.New(rv.Type()).Elem()
		for i := 0; i < rv.Len(); i++ {
			out.Index(i).Set(vecWTFMaskReflect(rv.Index(i)))
		}
		return out
	case reflect.Map:
		if rv.IsNil() {
			return rv
		}
		out := reflect.MakeMapWithSize(rv.Type(), rv.Len())
		it := rv.MapRange()
		for it.Next() {
			out.SetMapIndex(vecWTFMaskReflect(it.Key()), vecWTFMaskReflect(it.Value()))
		}
		return out
	case reflect.Ptr:
		if rv.IsNil() {
			return rv
		}
		out := reflect.New(rv.Type().Elem())
		out.Elem().Set(vecWTFMaskReflect(rv.Elem()))
		return out
	case reflect.Interface:
		if rv.IsNil() {
			return rv
		}
		out := reflect.New(rv.Type()).Elem()
		out.Set(vecWTFMaskReflect(rv.Elem()))
		return out
	case reflect.Struct:
		for i := 0; i < rv.NumField(); i++ {
			if rv.Type().Field(i).PkgPath != "" {
				return rv
			}
		}
		out := reflect.New(rv.Type()).Elem()
		for i := 0; i < rv.NumField(); i++ {
			out.Field(i).Set(vecWTFMaskReflect(rv.Field(i)))
		}
		return out
	}
	return rv
}

func vecWTFUnmask(v any) any {
	const mark = "\uf8ff"
	switch t := v.(type) {
	case string:
		for {
			i := strings.Index(t, mark)
			if i < 0 || i+len(mark)+4 > len(t) {
				return t
			}
			var cu int
			if _, err := fmt.Sscanf(t[i+len(mark):i+len(mark)+4], "%04x", &cu); err != nil {
				return t
			}
			t = t[:i] + string([]byte{0xED, byte(0x80 | cu>>6&0x3f), byte(0x80 | cu&0x3f)}) + t[i+len(mark)+4:]
		}
	case map[string]any:
		m := make(map[string]any, len(t))
		for k, x := range t {
			m[vecWTFUnmask(k).(string)] = vecWTFUnmask(x)
		}
		recordKeyOrder(m, jsKeys(t))
		return m
	case []any:
		for i, x := range t {
			t[i] = vecWTFUnmask(x)
		}
	}
	return v
}

func replayVectors(t *testing.T, file string, fns map[string]vecFn) {
	t.Helper()
	replayVectorsCmp(t, file, fns, nil)
}

// replayVectorsCmp is replayVectors with per-fn comparators (want, got as canonical-JSON values) for outputs only partly defined.
func replayVectorsCmp(t *testing.T, file string, fns map[string]vecFn, cmp map[string]func(want, got any) bool) {
	t.Helper()
	var k baseTally
	baseEachOrdered(t, file, func(c *baseCase) {
		f, ok := fns[c.Fn]
		if !ok {
			k.fail(c, "no Go entry point for %s", c.Fn)
			return
		}
		k.run(c.Fn)
		var got any
		var err error
		if p := baseCall(func() { got, err = f(c.Args) }); p != "" {
			k.fail(c, "panic: %s", p)
			return
		}
		var skip vecSkip
		if errors.As(err, &skip) {
			replaySkipped(file, c.Fn)
			k.skip(c.Fn, string(skip))
			return
		}
		replayRan(c.Fn)
		if throws, code := baseThrows(c.Out); throws {
			switch {
			case err == nil && vecEngineCrash(c.Out) && vecRefusalValue(vecJSON(got)):
			case err == nil:
				k.fail(c, "reference refuses (%v), Go returned %s", c.Out, baseCanon(vecJSON(got)))
			case code != "" && !strings.HasPrefix(code, "ERR_") && !vecErrHasCode(err, code): // ERR_* are JS-runtime codes
				k.fail(c, "reference refuses with code %s, Go with %v", code, err)
			}
			return
		}
		if err != nil {
			k.fail(c, "Go refuses (%v), reference returned %s", err, baseCanon(c.Out))
			return
		}
		if f := cmp[c.Fn]; f != nil {
			if !f(normalizeJSON(c.Out), vecJSON(got)) {
				k.fail(c, "%s", vecDiff(baseCanon(c.Out), baseCanon(vecJSON(got))))
			}
			return
		}
		if w, g := baseCanon(c.Out), baseCanon(vecJSON(got)); w != g {
			k.fail(c, "%s", vecDiff(w, g))
		}
	})
	k.finish(t)
}

// vecErrHasCode: the error carries the stable code: a *CodedError, an error struct with a Code field, the sentinel or typed errors that
// stand for one code, or a message that leads with "<code>: ".
func vecErrHasCode(err error, code string) bool {
	var ce *CodedError
	if errors.As(err, &ce) && ce.Code == code {
		return true
	}
	var a2a *A2AAuthorityError
	if code == "authority_required" && errors.As(err, &a2a) {
		return true
	}
	if code == "invalid_pca_header" && errors.Is(err, ErrPCAHeader) {
		return true
	}
	for e := err; e != nil; e = errors.Unwrap(e) {
		if v := reflect.Indirect(reflect.ValueOf(e)); v.Kind() == reflect.Struct {
			if f := v.FieldByName("Code"); f.IsValid() && f.Kind() == reflect.String && f.String() == code {
				return true
			}
		}
	}
	return strings.HasPrefix(err.Error(), code+":")
}

// vecArg returns args[i], or nil past the end (an omitted trailing argument).
func vecArg(args []any, i int) any {
	if i < len(args) {
		return args[i]
	}
	return nil
}

func vecObj(v any) map[string]any { m, _ := v.(map[string]any); return m }

func vecStr(m map[string]any, k string) string { s, _ := m[k].(string); return s }

// vecStrs reads a JSON string array member; nil when absent (so "absent" and "empty" stay distinct).
func vecStrs(m map[string]any, k string) []string {
	l, ok := m[k].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(l))
	for _, x := range l {
		s, _ := x.(string)
		out = append(out, s)
	}
	return out
}

// vecSeedValue derives the key of a {"$seed": label[, "es256": true | "ec": "P-384"|"P-521" | "ed448": true]} object (ok=false for
// any other shape): SHA-256("atlas-pca-conformance/" + label) (top bit of byte 0 cleared when es256); ec: the first 48 / 66 bytes of
// SHA256(P+L)||SHA256(P+L+"/2")||SHA256(P+L+"/3") with byte0 &= 0x7F / 0x01; ed448: SHA256(P+L) || SHA256(P+L+"/2")[:25].
func vecSeedValue(t map[string]any) (string, bool) {
	label, ok := t["$seed"].(string)
	if !ok {
		return "", false
	}
	for k := range t {
		if k != "$seed" && k != "es256" && k != "ec" && k != "ed448" {
			return "", false
		}
	}
	h := func(s string) []byte { d := sha256.Sum256([]byte("atlas-pca-conformance/" + label + s)); return d[:] }
	raw := h("")
	if es, _ := t["es256"].(bool); es {
		raw[0] &= 0x7F
	}
	switch ec, _ := t["ec"].(string); ec {
	case "P-384", "P-521":
		raw = append(append(h(""), h("/2")...), h("/3")...)
		if ec == "P-384" {
			raw = raw[:48]
			raw[0] &= 0x7F
		} else {
			raw = raw[:66]
			raw[0] &= 0x01
		}
	}
	if ed, _ := t["ed448"].(bool); ed {
		raw = append(h(""), h("/2")[:25]...)
	}
	return base64.RawURLEncoding.EncodeToString(raw), true
}

// vecResolveSeeds replaces, in place, every seed object (see vecSeedValue) by its derived base64url key. Other objects are left alone.
func vecResolveSeeds(v any) any {
	switch t := v.(type) {
	case map[string]any:
		if s, ok := vecSeedValue(t); ok {
			return s
		}
		for k, x := range t {
			t[k] = vecResolveSeeds(x)
		}
	case []any:
		for i, x := range t {
			t[i] = vecResolveSeeds(x)
		}
	}
	return v
}

// vecSeeded wraps each fn so its args have the corpus seed objects resolved first.
func vecSeeded(fns map[string]vecFn) map[string]vecFn {
	out := make(map[string]vecFn, len(fns))
	for n, f := range fns {
		f := f
		out[n] = func(a []any) (any, error) { return f(vecResolveSeeds(a).([]any)) }
	}
	return out
}

// replayVectorsSeeded is replayVectors with the corpus seed objects in each case's args resolved to keys (expected outputs untouched).
func replayVectorsSeeded(t *testing.T, file string, fns map[string]vecFn) {
	t.Helper()
	replayVectors(t, file, vecSeeded(fns))
}

// replaySecretGen replays ref-<name>-gen.json.gz (the oracle cases that carry private keys; CI generates it with
// gen-secret-corpus.sh, never committed) in a subtest: located next to the main corpus unless PCA_SECRET_CORPUS_DIR is set; a missing
// file fails under CI ("true"/"1"), else skips.
func replaySecretGen(t *testing.T, file string, run func(t *testing.T, path string)) {
	t.Helper()
	t.Run("gen", func(t *testing.T) {
		dir := os.Getenv("PCA_SECRET_CORPUS_DIR")
		if dir == "" {
			dir = filepath.Dir(vecCorpusPath(file))
		}
		path, _ := filepath.Abs(filepath.Join(dir, strings.TrimSuffix(filepath.Base(file), ".json.gz")+"-gen.json.gz"))
		if _, err := os.Stat(path); err != nil {
			if ci := os.Getenv("CI"); ci == "true" || ci == "1" {
				t.Fatalf("secret corpus missing (%s): CI must generate it with gen-secret-corpus.sh", path)
			}
			t.Skipf("secret corpus missing (%s): run gen-secret-corpus.sh", path)
		}
		run(t, path)
	})
}

// vecDiff reports where two canonical texts first differ, with context from each side (a whole value can be many kilobytes).
func vecDiff(w, g string) string {
	i := 0
	for i < len(w) && i < len(g) && w[i] == g[i] {
		i++
	}
	cut := func(s string) string {
		lo, hi := max(0, i-60), min(len(s), i+160)
		return s[lo:hi]
	}
	return fmt.Sprintf("differs (lengths %d / %d, first difference at byte %d)\n          want ...%s\n          got  ...%s", len(w), len(g), i, cut(w), cut(g))
}

// replayVectorsApprox is replayVectors comparing the named functions (all when none is named) with a relative tolerance of 1e-12 on
// numbers: a result that comes from the platform's libm (log, exp, pow) can differ from V8's in the last digits.
func replayVectorsApprox(t *testing.T, file string, fns map[string]vecFn, only ...string) {
	t.Helper()
	cmp := map[string]func(want, got any) bool{}
	if len(only) == 0 {
		for name := range fns {
			cmp[name] = goalVxApprox
		}
	}
	for _, name := range only {
		cmp[name] = goalVxApprox
	}
	replayVectorsCmp(t, file, fns, cmp)
}
