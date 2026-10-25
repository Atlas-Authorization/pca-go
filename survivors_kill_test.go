package pca

// Kill tests for the survivors the first honest go-mutate run left after the shared oracles (0.4.2): refusal texts,
// iteration-order determinism, boundary inputs of the helper parsers and the PQ raw verifier's refusals.

import (
	"strings"
	"testing"
)

// ---- saferegex.go ------------------------------------------------------------------------------------------------

func TestSurvivorBraceQuantRequiresBraceAndStaysInBounds(t *testing.T) {
	for _, c := range []struct {
		name         string
		src          string
		i, win, maxD int
	}{
		// the opening character must be '{' itself: a digit run right after any other character is not a quantifier
		{"x-then-digit", "x2}", 0, -1, -1},
		{"x-then-range", "x2,3}", 0, -1, -1},
		{"x-then-digit-win", "x2}", 0, 16, 4},
		// i at the end of the source: nothing to read (must not index past it)
		{"at-end", "{1}", 3, -1, -1},
		{"at-end-win", "{1}", 3, 16, 4},
		{"past-empty", "", 0, -1, -1},
		{"past-empty-win", "", 0, 16, 4},
		// a window larger than the remaining source never reads past the source
		{"unterminated-lo-win", "{2", 0, 16, 4},
		{"unterminated-comma-win", "{2,", 0, 16, 4},
		{"unterminated-hi-win", "{2,3", 0, 16, 4},
		{"brace-only-win", "{", 0, 16, 4},
	} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s: braceQuant panicked: %v", c.name, r)
				}
			}()
			if _, _, _, _, _, ok := braceQuant(u16s(c.src), c.i, c.win, c.maxD); ok {
				t.Errorf("%s: %q at %d accepted", c.name, c.src, c.i)
			}
		}()
	}
}

func TestSurvivorLetterAndDigitIdentityEscapesAreRefused(t *testing.T) {
	allowed := "dDwWsStnvfrxucb0"
	for c := 'A'; c <= 'z'; c++ {
		isLetter := c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z'
		if !isLetter {
			continue
		}
		special := strings.ContainsRune(allowed, c)
		if special {
			continue
		}
		if compiles(`\`+string(c)) || compiles(`[\`+string(c)+`]`) {
			t.Errorf(`\%c compiled (identity escape of a letter)`, c)
		}
	}
	for c := '1'; c <= '9'; c++ {
		if compiles(`\`+string(c)) || compiles(`[\`+string(c)+`]`) {
			t.Errorf(`\%c compiled`, c)
		}
	}
	if compiles(`\_`) || compiles(`[\_]`) {
		t.Error(`\_ compiled`)
	}
	// the neighbours of the letter / digit ranges are ordinary identity escapes
	for _, s := range []string{`\@`, `\[`, "\\`", `\{`, `\/`, `\:`, `\-`} {
		if !compiles(s) {
			t.Errorf("%s refused", s)
		}
	}
}

func TestSurvivorEscapesNeverReadPastTheSource(t *testing.T) {
	// the hex digits that would complete the escape sit in the spare capacity of the same slice
	u := u16s(`\u12ab`)
	if compileSafeRegex(u[:4]) != nil {
		t.Error(`\u12 (cut) compiled using the units beyond the slice`)
	}
	if compileSafeRegex(u[:5]) != nil {
		t.Error(`\u12a (cut) compiled using the units beyond the slice`)
	}
	if compileSafeRegex(u) == nil {
		t.Error(`\u12ab refused`)
	}
	x := u16s(`\x12`)
	if compileSafeRegex(x[:3]) != nil {
		t.Error(`\x1 (cut) compiled using the unit beyond the slice`)
	}
	if compileSafeRegex(x[:2]) != nil || compileSafeRegex(x[:1]) != nil {
		t.Error("a cut escape compiled")
	}
	if compileSafeRegex(x) == nil {
		t.Error(`\x12 refused`)
	}
}

func TestSurvivorComplementReachesTheLastCodeUnit(t *testing.T) {
	got := complementRanges([]charRange{{0, 0xfffe}})
	if len(got) != 1 || got[0] != (charRange{0xffff, 0xffff}) {
		t.Errorf("complement of [0, fffe] = %v", got)
	}
	if got := complementRanges([]charRange{{0, 0xffff}}); len(got) != 0 {
		t.Errorf("complement of everything = %v", got)
	}
	if got := complementRanges([]charRange{{5, 9}}); len(got) != 2 || got[0] != (charRange{0, 4}) || got[1] != (charRange{10, 0xffff}) {
		t.Errorf("complement of [5, 9] = %v", got)
	}
	// ... and through a regex: [^\x00-￾] matches exactly U+FFFF
	if !fullMatch(t, `[^\x00-￾]`, "￿") || safeMatchOK(`[^\x00-￾]`, "a") {
		t.Error(`[^\x00-￾]`)
	}
	if !fullMatch(t, `\W`, "￿") || !fullMatch(t, `[\D]`, "￿") || !fullMatch(t, `[\S]`, "￿") {
		t.Error("negated class escapes must include U+FFFF")
	}
}

func safeMatchOK(pat, subj string) bool {
	m, ok := safeRegexFullMatch(u16s(pat), u16s(subj))
	return ok && m
}

func TestSurvivorGuardSkipsAnEscapedBracketInAClass(t *testing.T) {
	for src, want := range map[string]bool{
		`[\](]b`:    true, // the escaped ] does not close the class, so the ( is class data
		`[\]]*`:     true,
		`[^\](]b`:   true,
		`([\])]a)*`: true,
		`[\]`:       false, // unterminated
		`[\](`:      false,
		`[\](]b)`:   false,
		`[\](]b(`:   false,
	} {
		if got := isSafeRegexSource(u16s(src)); got != want {
			t.Errorf("isSafeRegexSource(%q) = %v, want %v", src, got, want)
		}
	}
}

// ---- pq.go -------------------------------------------------------------------------------------------------------

func TestSurvivorPqRawRefusesWhatItCannotParse(t *testing.T) {
	msg := []byte("m")
	for _, p := range []pqPrim{pqMlDsa65, pqMlDsa87, pqSlh128f, pqSlh256s, pqLessCat1, pqNone, pqPrim(99)} {
		pkLen, sgLen := p.lens()
		if p == pqLessCat1 {
			sgLen = lessSignatureMinBytes
		}
		for _, pk := range [][]byte{nil, {1}, make([]byte, pkLen+1), make([]byte, pkLen)} {
			if pqVerifyRaw(p, pk, msg, make([]byte, sgLen)) {
				t.Errorf("prim %d accepted a zero signature under a %d-byte key", p, len(pk))
			}
		}
	}
	// ML-DSA-87 and SLH-DSA public keys of the wrong size are refused before any verification
	if pqVerifyRaw(pqMlDsa87, []byte{1, 2, 3}, msg, make([]byte, mlDsa87SignatureBytes)) {
		t.Error("ml-dsa-87 accepted a 3-byte key")
	}
	if pqVerifyRaw(pqSlh128f, []byte{1, 2, 3}, msg, make([]byte, slh128fSignatureBytes)) {
		t.Error("slh-dsa-128f accepted a 3-byte key")
	}
	if pqVerifyRaw(pqSlh256s, []byte{1, 2, 3}, msg, make([]byte, slh256sSignatureBytes)) {
		t.Error("slh-dsa-256s accepted a 3-byte key")
	}
	if pqVerifyRaw(pqNone, nil, msg, nil) || pqVerifyRaw(pqPrim(42), []byte{1}, msg, []byte{1}) {
		t.Error("an unknown primitive verified")
	}
}

func TestSurvivorIsRegisteredSuiteNeedsAString(t *testing.T) {
	for _, v := range []any{nil, 5, jnum(5), true, []any{"ed25519"}, map[string]any{}} {
		if isRegisteredSuite(v) {
			t.Errorf("isRegisteredSuite(%v) = true", v)
		}
	}
	if isRegisteredSuite("") || isRegisteredSuite("nope") {
		t.Error("an unregistered name is registered")
	}
	if !isRegisteredSuite("ed25519") {
		t.Error("ed25519 not registered")
	}
}

// ---- action_schema.go --------------------------------------------------------------------------------------------

func survivorSchemaDoc(verbParam map[string]any, units any) map[string]any {
	doc := map[string]any{
		"v": jnum(1), "kind": actionSchemaKind, "site": "https://s.example", "aud": "aud", "version": "1",
		"verbs": []any{map[string]any{"verb": "air.book", "kind": "read", "params": map[string]any{"action.params.p": verbParam}}},
	}
	if units != nil {
		doc["units"] = units
	}
	return doc
}

func TestSurvivorSchemaUnitsOnlyOnIntegerParams(t *testing.T) {
	units := map[string]any{"usd": map[string]any{"kind": "currency", "currency": "USD", "exponent": jnum(2)}}
	param := func(typ string, extra map[string]any) map[string]any {
		m := map[string]any{"type": typ, "semantic": "s", "sensitivity": "free"}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	// reference shape first: an integer param naming a declared unit is well-formed
	if e := actionSchemaShapeError(normalizeJSON(survivorSchemaDoc(param("integer", map[string]any{"unit": "usd"}), units)), false); e != "" {
		t.Fatalf("base schema refused: %q", e)
	}
	const want = "unit must name a declared unit of an integer parameter"
	for name, c := range map[string]struct {
		p     map[string]any
		units any
	}{
		"string-param-declared-unit": {param("string", map[string]any{"unit": "usd"}), units},
		"integer-undeclared-unit":    {param("integer", map[string]any{"unit": "eur"}), units},
		"integer-unit-not-string":    {param("integer", map[string]any{"unit": jnum(1)}), units},
		"integer-no-units":           {param("integer", map[string]any{"unit": "usd"}), nil},
		"set-param-declared-unit":    {param("set", map[string]any{"unit": "usd", "values": []any{"a"}}), units},
	} {
		got := actionSchemaShapeError(normalizeJSON(survivorSchemaDoc(c.p, c.units)), false)
		if !strings.HasSuffix(got, want) {
			t.Errorf("%s: got %q", name, got)
		}
	}
}

func TestSurvivorSchemaSigAlgReasons(t *testing.T) {
	doc := func(alg any, set bool) map[string]any {
		d := survivorSchemaDoc(map[string]any{"type": "string", "semantic": "s", "sensitivity": "free"}, nil)
		sig := map[string]any{"kid": "k", "value": "AAAA"}
		if set {
			sig["alg"] = alg
		}
		d["sig"] = sig
		return d
	}
	for name, c := range map[string]struct {
		alg  any
		want string
	}{
		"non-string":  {jnum(7), "sig.alg: alg must be a string"},
		"unsupported": {"rot13-dsa", "sig.alg: unsupported_suite: 'rot13-dsa'"},
		"null":        {nil, "sig.alg: alg must be a string"},
	} {
		if got := actionSchemaShapeError(normalizeJSON(doc(c.alg, true)), true); got != c.want {
			t.Errorf("%s: got %q, want %q", name, got, c.want)
		}
	}
}

func TestSurvivorSchemaArrayItemReasons(t *testing.T) {
	d := map[string]any{"type": "array", "items": "integer"}
	if r, msg := paramValueViolationReason(d, []any{jnum(1), "x"}); r != "bad_type" || msg != "array items must be safe integers" {
		t.Errorf("integer items: %q %q", r, msg)
	}
	d = map[string]any{"type": "array", "items": "string"}
	if r, msg := paramValueViolationReason(d, []any{"a", jnum(1)}); r != "bad_type" || !strings.HasPrefix(msg, "array items must be strings of at most ") {
		t.Errorf("string items: %q %q", r, msg)
	}
}

// ---- intent_map.go -----------------------------------------------------------------------------------------------

func TestSurvivorMapHeaderCellProductBound(t *testing.T) {
	cuts := make([]any, 0, 256)
	for i := 1; i <= 256; i++ {
		cuts = append(cuts, jnum(int64(i)))
	}
	dim := func(name string) any {
		return map[string]any{"kind": "num", "path": "action.params." + name, "lo": jnum(0), "hi": jnum(1000), "cuts": cuts}
	}
	h := map[string]any{"verb": "v", "first": jnum(0), "cells": jnum(1), "dims": []any{dim("a"), dim("b"), dim("c")}}
	if got := mapHeaderError(normalizeJSON(h)); got != "header: too many cells" {
		t.Errorf("three 258-cell dimensions: %q", got)
	}
	h["dims"] = []any{dim("a"), dim("b")}
	if got := mapHeaderError(normalizeJSON(h)); got != "header.cells is not the product of the dimensions' cell counts" {
		t.Errorf("two dimensions, wrong cells: %q", got)
	}
}

// ---- intent_session.go -------------------------------------------------------------------------------------------

func TestSurvivorSessionProvKeysAreReportedInSortedOrder(t *testing.T) {
	for n := 0; n < 40; n++ {
		w := map[string]any{"session": dg("s"), "root": dg("r"), "seq": jnum(0), "schema": dg("sch")}
		prov := map[string]any{}
		for _, k := range []string{"zz", "mm", "bb", "ab", "yy", "cc", "aa"} {
			prov[k] = []any{"r"}
		}
		w["prov"] = prov
		want := "'intent_session.prov' key 'aa' is not action.params.<name>"
		if got := validateIntentSessionWire(w); got != want {
			t.Fatalf("run %d: got %q, want %q", n, got, want)
		}
	}
}

func TestSurvivorFirstUnknownKeyIsTheSmallest(t *testing.T) {
	for n := 0; n < 40; n++ {
		m := map[string]any{"ok": 1}
		for _, k := range []string{"zz", "mm", "bb", "ab", "yy", "cc", "ba"} {
			m[k] = 1
		}
		if k, ok := firstUnknownKey(m, []string{"ok"}); ok || k != "ab" {
			t.Fatalf("run %d: got %q %v", n, k, ok)
		}
	}
	if k, ok := firstUnknownKey(map[string]any{"ok": 1}, []string{"ok"}); !ok || k != "" {
		t.Errorf("closed: %q %v", k, ok)
	}
}

// ---- intent_revocation.go ----------------------------------------------------------------------------------------

func TestSurvivorRevocationLastEpochWithAnUnrootableListFailsClosedAsACheckError(t *testing.T) {
	f := newV2Fx(t)
	f.withRevocation(60)
	auth := f.revAuth.id
	set := newRevSet(t, "pca-intent:session:aa", "pca-intent:session:zz")
	ev := deepM(t, f.evidence(f.revAuth, set, v2Now-1_000, v2Now+299_000))
	last := deepM(t, ev)
	last["revoked"] = []any{"\xed\xa0\x80"}
	le := last["epoch"].(map[string]any)
	le["set_size"], le["epoch"] = jnum(1), jnum(1)
	got := checkSessionRevocation(ev, f.session, auth, []any{"x"}, jnum(v2Now), jnum(60_000), last, true, nil)
	if got != revCheckError {
		t.Errorf("got %q, want %q", got, revCheckError)
	}
}

// ---- intent_wb.go ------------------------------------------------------------------------------------------------

func TestSurvivorWorldEntryAndOfferSetShapeTexts(t *testing.T) {
	for _, entry := range []any{jnum(5), "w", nil, []any{}} {
		got := validateWorldPolicyError(map[string]any{"worlds": []any{entry}})
		if got != "world entry must be an object" {
			t.Errorf("world entry %v: %q", entry, got)
		}
	}
	for _, v := range []any{nil, "x", jnum(1), []any{}} {
		if got := validateOfferSetWireError(v); got != "offer set must be an object" {
			t.Errorf("offer set %v: %q", v, got)
		}
	}
}

func TestSurvivorFlowRuleForPicksTheLongestWildcardWhateverTheMapOrder(t *testing.T) {
	for n := 0; n < 60; n++ {
		rules := map[string]any{}
		for _, k := range []string{"a.*", "a.b.*", "a.b.c.*", "a.bb.*", "z.*", "a.b.c.d.*"} {
			rules[k] = []any{"x"}
		}
		if got, ok := flowRuleFor(rules, "a.b.c.d.e"); !ok || got != "a.b.c.d.*" {
			t.Fatalf("run %d: got %q %v", n, got, ok)
		}
		if got, ok := flowRuleFor(rules, "a.b.q"); !ok || got != "a.b.*" {
			t.Fatalf("run %d: got %q %v", n, got, ok)
		}
	}
}

func TestSurvivorClassifierKeysReasons(t *testing.T) {
	ok := func() map[string]any {
		return map[string]any{
			"id": "c1", "param": "action.params.p", "labels": []any{"a", "b"}, "keys": []any{dg("k1")}, "k": jnum(1),
		}
	}
	pol := func(c map[string]any) any { return map[string]any{"classifiers": []any{c}} }
	if e := validateClassifierPolicyError(normalizeJSON(pol(ok()))); strings.Contains(e, "keys must be distinct") {
		t.Fatalf("base: %q", e)
	}
	const want = "classifier 'c1': keys must be distinct 32-byte keys"
	for name, keys := range map[string]any{"empty": []any{}, "not-array": "x", "not-digest": []any{"abc"}, "dup": []any{dg("k1"), dg("k1")}} {
		c := ok()
		c["keys"] = keys
		if got := validateClassifierPolicyError(normalizeJSON(pol(c))); got != want {
			t.Errorf("%s: got %q, want %q", name, got, want)
		}
	}
}

// ---- jsval.go ----------------------------------------------------------------------------------------------------

func TestSurvivorUtf16UnitsAndWellFormedKeepNonSurrogateED(t *testing.T) {
	// U+D7FF (ED 9F BF) is the last scalar below the surrogates: not a lone surrogate
	if got := utf16Units("퟿"); len(got) != 1 || got[0] != 0xD7FF {
		t.Errorf("utf16Units(U+D7FF) = %v", got)
	}
	if got := wellFormedUTF8("퟿"); got != "퟿" {
		t.Errorf("wellFormedUTF8(U+D7FF) = %q", got)
	}
	if got := wellFormedUTF8("a퟿b"); got != "a퟿b" {
		t.Errorf("wellFormedUTF8 = %q", got)
	}
	var sb strings.Builder
	lenientString(&sb, "퟿")
	if sb.String() != "\"퟿\"" {
		t.Errorf("lenientString(U+D7FF) = %q", sb.String())
	}
	// a lone surrogate is one code unit, well-formed replaces it with U+FFFD, the lenient form escapes it
	if got := utf16Units("\xed\xa0\x80"); len(got) != 1 || got[0] != 0xD800 {
		t.Errorf("lone high surrogate: %v", got)
	}
	if got := wellFormedUTF8("a\xed\xbf\xbfb"); got != "a�b" {
		t.Errorf("wellFormedUTF8(lone low surrogate) = %q", got)
	}
	sb.Reset()
	lenientString(&sb, "\xed\xbf\xbf")
	if sb.String() != `"\udfff"` {
		t.Errorf("lenientString(lone low surrogate) = %q", sb.String())
	}
	// ED followed by a byte that cannot continue it is not a surrogate
	if got := utf16Units("\xedAB"); len(got) != 3 || got[0] != 0xFFFD || got[1] != 'A' || got[2] != 'B' {
		t.Errorf("utf16Units(ED 41 42) = %v", got)
	}
	if got := wellFormedUTF8("\xed\xc0\x80x"); got != "\xed\xc0\x80x" {
		t.Errorf("wellFormedUTF8(ED C0 80) = %q", got)
	}
}

func TestSurvivorSessionRootPqPkMustBeAStringEqualToTheVerifierPin(t *testing.T) {
	f := newV2Fx(t)
	const want = "session root pq_pk does not match the verifier's pin for the signer"
	for name, pq := range map[string]any{"number": jnum(1), "null": nil, "absent": "\x00absent", "object": map[string]any{}} {
		S := deepM(t, f.S)
		S["alg"] = "ml-dsa-65"
		if pq != "\x00absent" {
			S["pq_pk"] = pq
		}
		S = normalizeJSON(S).(map[string]any)
		if r := sessionRootShape(S); r != "" {
			t.Fatalf("%s: shape %q", name, r)
		}
		// a pin that is the empty string must not accept a pq_pk that is not a string
		if r := verifySessionRoot(S, map[string]any{f.principal.id: ""}); r != want {
			t.Errorf("%s: got %q, want %q", name, r, want)
		}
	}
}
