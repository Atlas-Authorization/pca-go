package pca

// Kill tests for the Intent Layer v2 session / revocation / pipeline survivors of the 0.4.2 Go mutation run
// (intent_session.go, intent_revocation.go, intent_v2.go and the v2 stragglers in pca.go, caveats.go, intent.go,
// middleware.go). Each test drives ONE rule of the reference (packages/pca/src/intent-session.ts,
// intent-session-caveat.ts, intent-revocation.ts, revocation.ts, intent-v2.ts) at its boundary and asserts the exact
// verdict or refusal reason. Where the Go reason text differs from the reference's, the assertion is on the shared
// substring. Built on the natively signed v2 fixture (intent_v2_fixture_test.go).

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// ---- helpers ----------------------------------------------------------------------------------------------------

func killBCtx(t *testing.T, ctx map[string]any) *IntentV2Context {
	t.Helper()
	b, err := json.Marshal(ctx)
	if err != nil {
		t.Fatal(err)
	}
	c, err := IntentV2ContextFromJSONText(string(b))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// killBTry runs f and returns its panic value as text ("" when it did not panic).
func killBTry(f func()) (p string) {
	defer func() {
		if r := recover(); r != nil {
			p = fmt.Sprint(r)
		}
	}()
	f()
	return ""
}

func killBSess(t *testing.T, f *v2fx) (why string) {
	t.Helper()
	if p := killBTry(func() { why = sessionStep(f.p2(), deepM(t, f.grant), killBCtx(t, f.ctx), float64(f.now)) }); p != "" {
		return "PANIC: " + p
	}
	return why
}

func killBAcc(t *testing.T, f *v2fx) (env map[string]any, why string) {
	t.Helper()
	if p := killBTry(func() { env, why = accStep(f.p2(), killBCtx(t, f.ctx), float64(f.now)) }); p != "" {
		return nil, "PANIC: " + p
	}
	return env, why
}

func killBSchema(t *testing.T, f *v2fx) (why string) {
	t.Helper()
	if p := killBTry(func() { _, why = schemaStep(f.p2(), killBCtx(t, f.ctx)) }); p != "" {
		return "PANIC: " + p
	}
	return why
}

func killBWant(t *testing.T, name, got, want string) {
	t.Helper()
	if got != want {
		t.Errorf("%s: got %q, want %q", name, got, want)
	}
}

func killBWantSub(t *testing.T, name, got, sub string) {
	t.Helper()
	if sub == "" {
		if got != "" {
			t.Errorf("%s: got %q, want accepted", name, got)
		}
		return
	}
	if !strings.Contains(got, sub) {
		t.Errorf("%s: got %q, want it to contain %q", name, got, sub)
	}
}

func killBRep(s string, n int) string { return strings.Repeat(s, n) }

// ---- the session root shape (intent-session.ts sessionRootShapeError) -------------------------------------------

func TestKillBSessionRootShape(t *testing.T) {
	f := newV2Fx(t)
	base := func() map[string]any { return deepM(t, f.S) }
	if r := sessionRootShape(base()); r != "" {
		t.Fatalf("base root: %q", r)
	}
	killBWant(t, "not-object", sessionRootShape("x"), "session root is not an object")
	acc := func(id string) map[string]any { a := tripAcc(); a["id"] = id; return deepM(t, a) }
	mon := func(id string) map[string]any {
		return map[string]any{"id": id, "kind": "never", "p": map[string]any{"verb": "air.book"}}
	}
	principals := func(n int) []any {
		out := []any{map[string]any{"key": f.principal.id}}
		for i := 1; i < n; i++ {
			out = append(out, map[string]any{"key": dg(fmt.Sprint("p", i))})
		}
		return out
	}
	accs := func(n int) []any {
		out := []any{}
		for i := 0; i < n; i++ {
			out = append(out, acc(fmt.Sprint("a", i)))
		}
		return out
	}
	mons := func(n int) []any {
		out := []any{}
		for i := 0; i < n; i++ {
			out = append(out, mon(fmt.Sprint("m", i)))
		}
		return out
	}
	std := func(mut func(d map[string]any)) func(S map[string]any) {
		return func(S map[string]any) {
			d := map[string]any{"profile": "travel", "version": jnum(1), "digest": dg("std")}
			if mut != nil {
				mut(d)
			}
			S["layers"].(map[string]any)["std"] = d
		}
	}
	rev := func(mut func(r map[string]any)) func(S map[string]any) {
		return func(S map[string]any) {
			r := map[string]any{"epoch_uri": "https://atlas.example/rev", "max_age_s": jnum(60), "key": f.revAuth.id}
			if mut != nil {
				mut(r)
			}
			S["revocation"] = r
		}
	}
	const (
		badPrin  = "principals entries are {key, alg?, pq_pk?} with a 32-byte key"
		badSch   = "schema must be {aud, digest}"
		badLay   = "layers must be {org?, std?, task}"
		badTask  = "layers.task must be {map_digest}"
		badOrg   = "layers.org must be an object with a 32-byte digest"
		badStd   = "layers.std must be {profile, version >= 1, digest}"
		badQ     = "question_uri must be a non-empty string"
		badRev   = "revocation must be {epoch_uri, max_age_s, key, pq_pk?}"
		badPrins = "principals must be 1..16 keys"
	)
	for _, c := range []struct {
		name string
		mut  func(S map[string]any)
		want string // "" = well-formed; else a substring of the reason (the reference's text where they agree)
	}{
		{"unknown-member", func(S map[string]any) { S["zz"] = jnum(1) }, "session root: unknown member 'zz'"},
		{"v-2", func(S map[string]any) { S["v"] = jnum(2) }, "not a pca-intent-session v1"},
		{"kind-other", func(S map[string]any) { S["kind"] = "pca-intent-other" }, "not a pca-intent-session v1"},
		{"session-short", func(S map[string]any) { S["session"] = "abc" }, "session and intent_ref must be canonical base64url (32 bytes)"},
		{"intent_ref-short", func(S map[string]any) { S["intent_ref"] = "abc" }, "session and intent_ref must be canonical base64url (32 bytes)"},
		{"principals-missing", func(S map[string]any) { delete(S, "principals") }, badPrins},
		{"principals-object", func(S map[string]any) { S["principals"] = map[string]any{} }, badPrins},
		{"principals-empty", func(S map[string]any) { S["principals"] = []any{} }, badPrins},
		{"principals-16", func(S map[string]any) { S["principals"] = principals(16) }, ""},
		{"principals-17", func(S map[string]any) { S["principals"] = principals(17) }, badPrins},
		{"principal-not-object", func(S map[string]any) { S["principals"] = []any{"x", map[string]any{"key": f.principal.id}} }, badPrin},
		{"principal-unknown-member", func(S map[string]any) {
			S["principals"] = []any{map[string]any{"key": f.principal.id, "note": "x"}}
		}, badPrin},
		{"principal-key-short", func(S map[string]any) {
			S["principals"] = []any{map[string]any{"key": "abc"}, map[string]any{"key": f.principal.id}}
		}, badPrin},
		{"principal-alg-unknown", func(S map[string]any) {
			S["principals"] = []any{map[string]any{"key": f.principal.id, "alg": "nope-dsa"}}
		}, "principal alg: unsupported_suite"},
		{"principal-pq_pk-ok", func(S map[string]any) {
			S["principals"] = []any{map[string]any{"key": f.principal.id, "pq_pk": "AAAA"}}
		}, ""},
		{"principal-pq_pk-bad", func(S map[string]any) {
			S["principals"] = []any{map[string]any{"key": f.principal.id, "pq_pk": "AA=A"}}
		}, "principal pq_pk is not canonical base64url"},
		{"principal-dup", func(S map[string]any) {
			S["principals"] = []any{map[string]any{"key": f.principal.id}, map[string]any{"key": f.principal.id}}
		}, "principal keys must be distinct"},
		{"schema-string", func(S map[string]any) { S["schema"] = "x" }, badSch},
		{"schema-extra", func(S map[string]any) { S["schema"].(map[string]any)["x"] = jnum(1) }, badSch},
		{"schema-aud-number", func(S map[string]any) { S["schema"].(map[string]any)["aud"] = jnum(1) }, badSch},
		{"schema-aud-empty", func(S map[string]any) { S["schema"].(map[string]any)["aud"] = "" }, badSch},
		{"schema-digest-short", func(S map[string]any) { S["schema"].(map[string]any)["digest"] = "abc" }, badSch},
		{"layers-string", func(S map[string]any) { S["layers"] = "x" }, "layers"},
		{"layers-unknown", func(S map[string]any) { S["layers"].(map[string]any)["site"] = map[string]any{"digest": dg("s")} }, "layers"},
		{"task-string", func(S map[string]any) { S["layers"].(map[string]any)["task"] = "x" }, badTask},
		{"task-extra", func(S map[string]any) { S["layers"].(map[string]any)["task"].(map[string]any)["x"] = jnum(1) }, badTask},
		{"task-other-member", func(S map[string]any) { S["layers"].(map[string]any)["task"] = map[string]any{"digest": dg("m")} }, badTask},
		{"task-digest-short", func(S map[string]any) { S["layers"].(map[string]any)["task"] = map[string]any{"map_digest": "abc"} }, badTask},
		{"org-ok", func(S map[string]any) { S["layers"].(map[string]any)["org"] = map[string]any{"digest": dg("org")} }, ""},
		{"org-null", func(S map[string]any) { S["layers"].(map[string]any)["org"] = nil }, badOrg},
		{"org-digest-short", func(S map[string]any) { S["layers"].(map[string]any)["org"] = map[string]any{"digest": "abc"} }, badOrg},
		{"std-ok", std(nil), ""},
		{"std-version-2", std(func(d map[string]any) { d["version"] = jnum(2) }), ""},
		{"std-profile-128", std(func(d map[string]any) { d["profile"] = killBRep("p", 128) }), ""},
		{"std-null", func(S map[string]any) { S["layers"].(map[string]any)["std"] = nil }, badStd},
		{"std-extra", std(func(d map[string]any) { d["x"] = jnum(1) }), badStd},
		{"std-profile-number", std(func(d map[string]any) { d["profile"] = jnum(1) }), badStd},
		{"std-profile-empty", std(func(d map[string]any) { d["profile"] = "" }), badStd},
		{"std-profile-129", std(func(d map[string]any) { d["profile"] = killBRep("p", 129) }), badStd},
		{"std-version-0", std(func(d map[string]any) { d["version"] = jnum(0) }), badStd},
		{"std-version-fraction", std(func(d map[string]any) { d["version"] = json.Number("1.5") }), badStd},
		{"std-version-string", std(func(d map[string]any) { d["version"] = "1" }), badStd},
		{"std-digest-short", std(func(d map[string]any) { d["digest"] = "abc" }), badStd},
		{"accumulators-object", func(S map[string]any) { S["accumulators"] = map[string]any{} }, "accumulators must be an array of at most 16"},
		{"accumulators-16", func(S map[string]any) { S["accumulators"] = accs(16) }, ""},
		{"accumulators-17", func(S map[string]any) { S["accumulators"] = accs(17) }, "accumulators must be an array of at most 16"},
		{"accumulators-dup", func(S map[string]any) { S["accumulators"] = []any{acc("a"), acc("a")} }, "ids must be distinct"},
		{"monitors-object", func(S map[string]any) { S["monitors"] = map[string]any{} }, "monitors must be an array of at most 16"},
		{"monitors-16", func(S map[string]any) { S["monitors"] = mons(16) }, ""},
		{"monitors-17", func(S map[string]any) { S["monitors"] = mons(17) }, "monitors must be an array of at most 16"},
		{"monitors-dup", func(S map[string]any) { S["monitors"] = []any{mon("m"), mon("m")} }, "monitor ids must be distinct"},
		{"monitor-bad", func(S map[string]any) { S["monitors"] = []any{map[string]any{"id": "m"}} }, "monitor 'm': unknown kind"},
		// a valid monitor must not end the shape check: the later members are still checked
		{"monitor-then-question-empty", func(S map[string]any) { S["monitors"] = mons(1); S["question_uri"] = "" }, badQ},
		{"question-number", func(S map[string]any) { S["question_uri"] = jnum(1) }, badQ},
		{"question-empty", func(S map[string]any) { S["question_uri"] = "" }, badQ},
		{"question-2048", func(S map[string]any) { S["question_uri"] = "h" + killBRep("q", 2047) }, ""},
		{"question-2049", func(S map[string]any) { S["question_uri"] = "h" + killBRep("q", 2048) }, badQ},
		{"revocation-ok", rev(nil), ""},
		{"revocation-pq_pk-ok", rev(func(r map[string]any) { r["pq_pk"] = "AAAA" }), ""},
		{"revocation-string", func(S map[string]any) { S["revocation"] = "x" }, badRev},
		{"revocation-unknown", rev(func(r map[string]any) { r["x"] = jnum(1) }), badRev},
		{"revocation-uri-number", rev(func(r map[string]any) { r["epoch_uri"] = jnum(1) }), "revocation.epoch_uri must be a non-empty string"},
		{"revocation-uri-empty", rev(func(r map[string]any) { r["epoch_uri"] = "" }), "revocation.epoch_uri must be a non-empty string"},
		{"revocation-age-negative", rev(func(r map[string]any) { r["max_age_s"] = jnum(-1) }), "revocation.max_age_s must be a non-negative safe integer"},
		{"revocation-key-short", rev(func(r map[string]any) { r["key"] = "abc" }), "revocation.key (the dedicated revocation authority) is required"},
		{"revocation-key-principal", rev(func(r map[string]any) { r["key"] = f.principal.id }), "revocation.key must not be a session principal"},
		{"revocation-pq_pk-bad", rev(func(r map[string]any) { r["pq_pk"] = "AA=A" }), "revocation.pq_pk must be canonical base64url"},
		{"flows-ok", func(S map[string]any) { S["flows"] = map[string]any{} }, ""},
		{"flows-string", func(S map[string]any) { S["flows"] = "x" }, "flows must be an object"},
		{"expires-negative", func(S map[string]any) { S["expires_at"] = jnum(-1) }, "expires_at must be a non-negative safe integer (epoch ms)"},
		{"signer-not-principal", func(S map[string]any) { S["signer"] = dg("other") }, "signer is not one of the session principals"},
		{"alg-unknown", func(S map[string]any) { S["alg"] = "nope-dsa" }, "alg: unsupported_suite"},
		{"ed25519-pq_pk", func(S map[string]any) { S["pq_pk"] = "AAAA" }, "an ed25519 session root must not carry pq_pk / pq_sig"},
		{"ed25519-pq_sig", func(S map[string]any) { S["pq_sig"] = "AAAA" }, "an ed25519 session root must not carry pq_pk / pq_sig"},
		{"sig-number", func(S map[string]any) { S["sig"] = jnum(1) }, "sig must be a string"},
	} {
		S := base()
		c.mut(S)
		killBWantSub(t, c.name, sessionRootShape(normalizeJSON(S)), c.want)
	}
}

// verifySessionRoot: shape first, then the suite signature; a PQ signer verifies only under the VERIFIER's pin (R3-01).
func TestKillBVerifySessionRoot(t *testing.T) {
	f := newV2Fx(t)
	if verifySessionRoot(deepM(t, f.S), nil) != "" {
		t.Fatal("base root must verify")
	}
	// a member outside the signed body leaves the signature valid: only the shape check refuses it
	S := deepM(t, f.S)
	S["zz"] = jnum(1)
	if verifySessionRoot(S, nil) == "" {
		t.Error("a root with an unknown member must not verify")
	}
	// tampered after signing
	S = deepM(t, f.S)
	S["question_uri"] = "https://other.example/q"
	if verifySessionRoot(S, nil) == "" {
		t.Error("a tampered root must not verify")
	}
	// a PQ suite without the artifact pq_pk: the signed body cannot be bound (refused, never accepted)
	S = deepM(t, f.S)
	S["alg"] = "ml-dsa-65"
	if sessionRootShape(S) != "" {
		t.Fatalf("shape: %q", sessionRootShape(S))
	}
	if verifySessionRoot(S, map[string]any{f.principal.id: "AAAA"}) == "" {
		t.Error("an ml-dsa-65 root without pq_pk must not verify")
	}
	// ml-dsa-65 root signed by the SECOND principal: the PQ pin is the signer's entry, not the first principal's
	var seed [mldsa65.SeedSize]byte
	copy(seed[:], "killB-session-root-ml-dsa-65-sd")
	pk, sk := mldsa65.NewKeyFromSeed(&seed)
	pkb, _ := pk.MarshalBinary()
	pq := b64.EncodeToString(pkb)
	S = deepM(t, f.S)
	S["principals"] = []any{map[string]any{"key": dg("first")}, map[string]any{"key": f.principal.id, "alg": "ml-dsa-65", "pq_pk": pq}}
	S["signer"] = f.principal.id
	S["alg"] = "ml-dsa-65"
	S["pq_pk"] = pq
	base := sessionRootBody(S)
	base["signer"] = f.principal.id
	bound, ok := bindSuiteFields(base, "ml-dsa-65", true, pq, true)
	if !ok {
		t.Fatal("bind")
	}
	msg, ok := domainMessage(intentSessionSigDomain, bound)
	if !ok {
		t.Fatal("msg")
	}
	sig := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(sk, msg, nil, false, sig); err != nil {
		t.Fatal(err)
	}
	S["sig"] = b64.EncodeToString(sig)
	S = normalizeJSON(S).(map[string]any)
	if r := sessionRootShape(S); r != "" {
		t.Fatalf("pq root shape: %q", r)
	}
	pins := map[string]any{f.principal.id: pq}
	if r := verifySessionRoot(S, pins); r != "" {
		t.Errorf("an ml-dsa-65 root signed by the second principal, pinned by the verifier, must verify: %q", r)
	}
	// R3-01: the root's own principals entry is NOT a pin: no verifier pin, a pin for another key, a non-string pin or a
	// different key all fail closed
	const noPin = "session root suite 'ml-dsa-65' needs the signer's PQ key pinned by the verifier (pq_pins); the root's own principals entry proves nothing about who signed it"
	for name, p := range map[string]any{"nil": nil, "empty": map[string]any{}, "other-key": map[string]any{dg("first"): pq}, "non-string": map[string]any{f.principal.id: jnum(1)}, "not-object": []any{pq}} {
		if r := verifySessionRoot(S, p); r != noPin {
			t.Errorf("%s: got %q, want %q", name, r, noPin)
		}
	}
	if r := verifySessionRoot(S, map[string]any{f.principal.id: dg("other")}); r != "session root pq_pk does not match the verifier's pin for the signer" {
		t.Errorf("pin mismatch: %q", r)
	}
	// the principals list is signed: dropping the signer's declared key breaks the signature (the pin still matches)
	S2 := deepM(t, S)
	S2["principals"] = []any{map[string]any{"key": dg("first")}, map[string]any{"key": f.principal.id, "alg": "ml-dsa-65"}}
	if r := verifySessionRoot(S2, pins); r != "session root signature invalid" {
		t.Errorf("an edited principals list must not verify: %q", r)
	}
	// the signer's own entry declaring another PQ key than the one it signs under fails before the signature
	S3 := deepM(t, S)
	S3["principals"] = []any{map[string]any{"key": dg("first")}, map[string]any{"key": f.principal.id, "alg": "ml-dsa-65", "pq_pk": dg("other")}}
	if r := verifySessionRoot(S3, pins); r != "session root pq_pk does not match the signer's principals entry" {
		t.Errorf("principals entry mismatch: %q", r)
	}
	// an ed25519 root never consults the pins
	if r := verifySessionRoot(deepM(t, f.S), map[string]any{f.principal.id: pq}); r != "" {
		t.Errorf("ed25519 root with pins: %q", r)
	}
}

// ---- the session caveat and its lookup (intent-session-caveat.ts) -----------------------------------------------

func TestKillBSessionCaveat(t *testing.T) {
	ok0 := func() map[string]any {
		return map[string]any{"type": "intent_session", "session": dg("s"), "seq": jnum(0), "root": dg("r")}
	}
	killBWant(t, "valid-seq0", intentSessionCaveatError(ok0()), "")
	c := ok0()
	c["seq"], c["prev"] = jnum(maxSessionSeq), dg("p")
	killBWant(t, "valid-max-seq", intentSessionCaveatError(c), "")
	killBWant(t, "not-object", intentSessionCaveatError("x"), "not an intent_session caveat")
	c = ok0()
	c["type"] = "envelope"
	killBWant(t, "other-type", intentSessionCaveatError(c), "not an intent_session caveat")
	c = ok0()
	c["x"] = jnum(1)
	killBWant(t, "unknown-member", intentSessionCaveatError(c), "intent_session caveat: unknown member 'x'")
	const badDigest = "intent_session caveat: session and root must be canonical base64url (32 bytes)"
	c = ok0()
	c["session"] = "abc"
	killBWant(t, "session-short", intentSessionCaveatError(c), badDigest)
	c = ok0()
	c["root"] = "abc"
	killBWant(t, "root-short", intentSessionCaveatError(c), badDigest)
	const badSeq = "intent_session caveat: seq must be a safe integer in [0, 2147483647]"
	for name, s := range map[string]any{"negative": jnum(-1), "over": jnum(maxSessionSeq + 1), "string": "0", "fraction": json.Number("0.5")} {
		c = ok0()
		c["seq"] = s
		killBWant(t, "seq-"+name, intentSessionCaveatError(c), badSeq)
	}
	const badPrev = "intent_session caveat: prev is present exactly when seq > 0"
	c = ok0()
	c["prev"] = dg("p")
	killBWant(t, "seq0-with-prev", intentSessionCaveatError(c), badPrev)
	c = ok0()
	c["seq"] = jnum(1)
	killBWant(t, "seq1-no-prev", intentSessionCaveatError(c), badPrev)
	c["prev"] = "abc"
	killBWant(t, "prev-short", intentSessionCaveatError(c), "intent_session caveat: prev must be canonical base64url (32 bytes)")

	// caveat evaluation: an intent_session caveat is satisfied iff it is well-formed
	if !caveatSatisfied(ok0(), map[string]any{"now": jnum(v2Now)}) {
		t.Error("a well-formed intent_session caveat must be satisfied")
	}
	c = ok0()
	c["prev"] = dg("p")
	if caveatSatisfied(c, map[string]any{"now": jnum(v2Now)}) {
		t.Error("a malformed intent_session caveat must not be satisfied")
	}

	// grantSessionCaveat: the FIRST intent_session caveat of the grant
	if m, ok := grantSessionCaveat("x"); m != nil || ok {
		t.Error("non-object grant")
	}
	if m, ok := grantSessionCaveat(map[string]any{"caveats": "x"}); m != nil || ok {
		t.Error("caveats not an array")
	}
	if m, ok := grantSessionCaveat(map[string]any{"caveats": []any{map[string]any{"type": "envelope"}}}); m != nil || ok {
		t.Error("no session caveat")
	}
	first, second := ok0(), ok0()
	second["session"] = dg("second")
	m, ok := grantSessionCaveat(map[string]any{"caveats": []any{"x", map[string]any{"type": "envelope"}, first, second}})
	if !ok || m == nil || m["session"] != dg("s") {
		t.Errorf("first session caveat: %v %v", m, ok)
	}
}

// ---- the intent_session wire (intent-session.ts intentSessionWireError) ------------------------------------------

func TestKillBSessionWire(t *testing.T) {
	ok := func() map[string]any {
		return map[string]any{"session": dg("s"), "root": dg("r"), "seq": jnum(0), "schema": dg("sch")}
	}
	killBWant(t, "valid", validateIntentSessionWire(ok()), "")
	w := ok()
	w["facts"] = []any{dg("f1"), dg("f2")}
	killBWant(t, "facts-ok", validateIntentSessionWire(w), "")
	for name, facts := range map[string]any{"not-digest": []any{"abc"}, "digest-then-not": []any{dg("f"), "abc"}, "number": []any{jnum(1)}, "dup": []any{dg("f"), dg("f")}} {
		w = ok()
		w["facts"] = facts
		want := "'intent_session.facts' entries must be canonical base64url (32 bytes)"
		if name == "dup" {
			want = "'intent_session.facts' entries must be distinct"
		}
		killBWant(t, "facts-"+name, validateIntentSessionWire(w), want)
	}
	w = ok()
	w["acc"] = []any{jnum(5)}
	killBWant(t, "acc-not-object", validateIntentSessionWire(w), "'intent_session.acc[0]' must be an object")

	// pca.go ValidateWireV2: a well-formed intent_session does not end the wire check (later members are still checked)
	f := newV2Fx(t)
	p := f.p2()
	if r := ValidateWireV2(p); r != "" {
		t.Fatalf("base wire: %q", r)
	}
	p["prohibition_evidence"] = jnum(5)
	killBWant(t, "wire-after-session", ValidateWireV2(p), "'prohibition_evidence' must be an object or array")
}

// ---- revocation (intent-revocation.ts checkSessionRevocation, revocation.ts checkRevocationEpoch) ---------------

func TestKillBRevocation(t *testing.T) {
	f := newV2Fx(t)
	f.withRevocation(60)
	auth := f.revAuth.id
	ids := func(xs ...string) []any {
		out := []any{}
		for _, x := range xs {
			out = append(out, x)
		}
		return out
	}
	set := newRevSet(t, "pca-intent:session:aa", "pca-intent:session:zz")
	ev := func() map[string]any { return deepM(t, f.evidence(f.revAuth, set, v2Now-1_000, v2Now+299_000)) }
	run := func(e any, authority any, idList any, now any, maxAge any, last any, lastP bool) string {
		return checkSessionRevocation(e, f.session, authority, idList, now, maxAge, last, lastP, nil)
	}
	now, age := jnum(v2Now), jnum(60_000)
	killBWant(t, "base", run(ev(), auth, ids("x"), now, age, nil, false), "")
	killBWant(t, "max-age-negative", run(ev(), auth, ids("x"), now, jnum(-1), nil, false), "revocation max age misconfigured (fail closed)")
	killBWant(t, "clock-fraction", run(ev(), auth, ids("x"), json.Number("1800000000000.5"), age, nil, false), "the verifier clock is not a safe integer (fail closed)")
	killBWant(t, "ids-not-array", run(ev(), auth, "x", now, age, nil, false), "ids must be an array and the authority a key")
	killBWant(t, "authority-not-string", run(ev(), jnum(1), ids("x"), now, age, nil, false), "ids must be an array and the authority a key")
	killBWant(t, "evidence-not-object", run("x", auth, ids("x"), now, age, nil, false), "no session revocation epoch supplied")
	e := ev()
	e["x"] = jnum(1)
	killBWantSub(t, "evidence-extra", run(e, auth, ids("x"), now, age, nil, false), "exactly {epoch, revoked}")
	killBWant(t, "other-authority", run(ev(), f.principal.id, ids("x"), now, age, nil, false), "the revocation epoch is not signed by the session revocation authority")
	killBWantSub(t, "too-old", run(deepM(t, f.evidence(f.revAuth, set, v2Now-60_001, v2Now+299_000)), auth, ids("x"), now, age, nil, false), "older than")
	killBWantSub(t, "revoked-id", run(ev(), auth, ids("x", "pca-intent:session:zz"), now, age, nil, false), "revoked")
	// last epoch tracking: rollback is reported as such (not as a drop)
	small := newRevSet(t, "pca-intent:session:aa")
	cur := deepM(t, f.evidence(f.revAuth, small, v2Now-1_000, v2Now+299_000))
	killBWant(t, "rollback", run(cur, auth, ids("x"), now, age, ev(), true), "revocation epoch rollback (older than the last accepted)")
	other := newRevSet(t, "pca-intent:session:bb")
	killBWantSub(t, "drop", run(deepM(t, f.evidence(f.revAuth, other, v2Now-1_000, v2Now+299_000)), auth, ids("x"), now, age, cur, true), "drops 'pca-intent:session:aa'")
	killBWant(t, "extends", run(ev(), auth, ids("x"), now, age, cur, true), "")

	// the epoch shape
	ep := func() map[string]any { return deepM(t, ev()["epoch"].(map[string]any)) }
	killBWant(t, "shape-ok", revocationEpochShape(ep()), "")
	for _, k := range []string{"epoch", "set_size", "issued_at", "not_after"} {
		x := ep()
		x[k] = "1"
		killBWant(t, "shape-"+k, revocationEpochShape(x), "revocation epoch "+k+" must be a non-negative safe integer")
	}
	x := ep()
	x["guardian_epoch"] = jnum(-1)
	killBWant(t, "shape-guardian_epoch", revocationEpochShape(x), "revocation epoch guardian_epoch must be a non-negative safe integer")
	x = ep()
	x["alg"] = "nope-dsa"
	killBWant(t, "shape-alg", revocationEpochShape(x), "revocation epoch alg: unsupported_suite: 'nope-dsa'")
	x = ep()
	x["pq_sig"] = jnum(1)
	killBWant(t, "shape-pq_sig", revocationEpochShape(x), "revocation epoch pq_sig must be a string")
	// checkRevocationEpoch on its own: the pinned guardian
	killBWant(t, "epoch-ok", checkRevocationEpoch(ep(), auth, float64(v2Now), sessionRevocationScope(f.session), nil), "")
	killBWant(t, "epoch-other-guardian", checkRevocationEpoch(ep(), f.principal.id, float64(v2Now), sessionRevocationScope(f.session), nil), "revocation epoch not signed by the pinned guardian")

	// the revoked list: strictly ascending (UTF-8 bytes), distinct, exactly the signed set
	list := func(xs ...string) map[string]any {
		return map[string]any{"revoked": ids(xs...), "epoch": map[string]any{"set_size": jnum(int64(len(xs))), "epoch": jnum(int64(len(xs))), "root": ""}}
	}
	const unsorted = "revoked must be sorted by UTF-8 bytes and distinct"
	for name, l := range map[string][]string{"desc-2": {"b", "a"}, "dup-2": {"a", "a"}, "desc-at-0-of-3": {"b", "a", "c"}, "dup-at-1-of-3": {"a", "b", "b"}} {
		_, why := revokedList(list(l...))
		killBWant(t, "list-"+name, why, unsorted)
	}
	// a list the set root cannot be computed for (a lone surrogate) is never the signed set, even against root ""
	_, why := revokedList(list("\xed\xa0\x80"))
	killBWant(t, "list-lone-surrogate", why, revListThrows)

	// the primitive: a non-object input is refused; the reference input form is accepted
	if IntentRevocationPrimitive("x") {
		t.Error("primitive: non-object input accepted")
	}
	in := ev()
	in["session"], in["authority"], in["ids"], in["now"], in["max_age_ms"] = f.session, auth, ids("x"), now, age
	if !IntentRevocationPrimitive(in) {
		t.Error("primitive: valid input refused")
	}
}

// ---- rule 13 (intent-v2.ts sessionCheck) -------------------------------------------------------------------------

func killBChainFx(t *testing.T, n int) (*v2fx, []map[string]any) {
	f := newV2Fx(t)
	prior := []map[string]any{}
	prev := ""
	for i := 0; i < n; i++ {
		g := f.sessionGrant(f.principal, int64(i), prev, f.mapD, f.salt)
		prior = append(prior, g)
		prev = g["id"].(string)
	}
	f.grant = f.sessionGrant(f.principal, int64(n), prev, f.mapD, f.salt)
	f.build()
	f.is()["seq"] = jnum(int64(n))
	f.resign()
	gs := []any{}
	for _, g := range prior {
		gs = append(gs, g)
	}
	f.ctx["session"].(map[string]any)["grants"] = gs
	return f, prior
}

func killBSessCaveat(g map[string]any) map[string]any {
	for _, c := range g["caveats"].([]any) {
		if m, ok := c.(map[string]any); ok && m["type"] == "intent_session" {
			return m
		}
	}
	return nil
}

func TestKillBSessionStep(t *testing.T) {
	f := newV2Fx(t)
	killBWant(t, "base", killBSess(t, f), "")

	f = newV2Fx(t)
	f.ctx["policy"] = map[string]any{"session": map[string]any{"max_revocation_age_s": jnum(-1)}}
	killBWant(t, "policy-age-negative", killBSess(t, f), "session policy misconfigured: max_revocation_age_s must be a non-negative safe integer (fail closed)")
	f = newV2Fx(t)
	f.ctx["policy"] = map[string]any{"session": map[string]any{"max_revocation_age_s": jnum(60)}}
	killBWant(t, "policy-age-no-authority", killBSess(t, f), "revocation: the policy requires a revocation epoch but the session root names no revocation authority")

	// a root with a bad signature whose digest IS the committed one
	f = newV2Fx(t)
	f.S["question_uri"] = "https://other.example/q"
	r, _ := sessionRootDigest(deep(t, f.S))
	f.is()["root"] = r
	f.ctx["session"].(map[string]any)["root"] = f.S
	killBWant(t, "root-bad-sig", killBSess(t, f), "session root: session root signature invalid")
	f = newV2Fx(t)
	f.is()["root"] = dg("other-root")
	killBWant(t, "root-digest", killBSess(t, f), "intent_session.root is not the digest of the session root")
	f = newV2Fx(t)
	f.is()["schema"] = dg("other-schema")
	killBWant(t, "schema-digest", killBSess(t, f), "intent_session.schema is not the session schema")

	// the admitting root's caveat
	f = newV2Fx(t)
	killBSessCaveat(f.grant)["x"] = jnum(1)
	killBWant(t, "admitting-malformed", killBSess(t, f), "admitting root: intent_session caveat: unknown member 'x'")
	const otherBinding = "the admitting root is bound to another session, root or seq"
	f = newV2Fx(t)
	killBSessCaveat(f.grant)["session"] = dg("other-session")
	killBWant(t, "admitting-session", killBSess(t, f), otherBinding)
	f = newV2Fx(t)
	killBSessCaveat(f.grant)["root"] = dg("other-root")
	killBWant(t, "admitting-root", killBSess(t, f), otherBinding)
	f = newV2Fx(t)
	c := killBSessCaveat(f.grant)
	c["seq"], c["prev"] = jnum(1), dg("prev")
	killBWant(t, "admitting-seq", killBSess(t, f), otherBinding)

	// the held chain of earlier grants (seq 2: G_0, G_1 held)
	f, _ = killBChainFx(t, 2)
	killBWant(t, "chain-2", killBSess(t, f), "")
	f, _ = killBChainFx(t, 3)
	killBWant(t, "chain-3", killBSess(t, f), "")
	f, prior := killBChainFx(t, 2)
	f.ctx["session"].(map[string]any)["grants"] = []any{prior[0]}
	killBWant(t, "chain-unheld", killBSess(t, f), "the verifier does not hold the 2 earlier grants of this session")
	mutPrior := func(i int, mut func(g map[string]any)) *v2fx {
		f, prior := killBChainFx(t, 2)
		g := deepM(t, prior[i])
		mut(g)
		gs := []any{prior[0], prior[1]}
		gs[i] = g
		f.ctx["session"].(map[string]any)["grants"] = gs
		return f
	}
	killBWant(t, "prior-not-object", killBSess(t, mutPrior(1, func(g map[string]any) {
		for k := range g {
			delete(g, k)
		}
		g["id"] = jnum(1)
	})), "session grant 1 is not a capability")
	killBWant(t, "prior-id-number", killBSess(t, mutPrior(1, func(g map[string]any) { g["id"] = jnum(1) })), "session grant 1 is not a capability")
	killBWant(t, "prior-issuer-number", killBSess(t, mutPrior(1, func(g map[string]any) { g["issuer"] = jnum(1) })), "session grant 1 is not a capability")
	killBWant(t, "prior-alg", killBSess(t, mutPrior(1, func(g map[string]any) { g["alg"] = "nope-dsa" })), "session grant 1: unsupported_suite: 'nope-dsa'")
	const notBelong = "session grant 1 does not belong to this session at seq 1"
	killBWant(t, "prior-session", killBSess(t, mutPrior(1, func(g map[string]any) { killBSessCaveat(g)["session"] = dg("x") })), notBelong)
	killBWant(t, "prior-root", killBSess(t, mutPrior(1, func(g map[string]any) { killBSessCaveat(g)["root"] = dg("x") })), notBelong)
	killBWant(t, "prior-seq", killBSess(t, mutPrior(1, func(g map[string]any) { killBSessCaveat(g)["seq"] = jnum(5) })), notBelong)
	killBWant(t, "prior-malformed", killBSess(t, mutPrior(1, func(g map[string]any) { killBSessCaveat(g)["x"] = jnum(1) })), notBelong)
	killBWant(t, "prior-issuer-agent", killBSess(t, mutPrior(1, func(g map[string]any) { g["issuer"] = f.agent.id })), "session grant 1 is not signed by a session principal")
	killBWant(t, "prior-0-issuer-agent", killBSess(t, mutPrior(0, func(g map[string]any) { g["issuer"] = dg("agent") })), "session grant 0 is not signed by a session principal")
	killBWant(t, "prior-prev", killBSess(t, mutPrior(1, func(g map[string]any) { killBSessCaveat(g)["prev"] = dg("x") })), "session grant 1 does not chain to grant 0")
	f, _ = killBChainFx(t, 2)
	killBSessCaveat(f.grant)["prev"] = dg("x")
	killBWant(t, "admitting-prev", killBSess(t, f), "the admitting root does not chain to grant 1")
	f, _ = killBChainFx(t, 3)
	killBSessCaveat(f.grant)["prev"] = dg("x")
	killBWant(t, "admitting-prev-3", killBSess(t, f), "the admitting root does not chain to grant 2")
}

// ---- rule 14 (intent-v2.ts schemaCheck) --------------------------------------------------------------------------

func TestKillBSchemaStep(t *testing.T) {
	f := newV2Fx(t)
	killBWant(t, "base", killBSchema(t, f), "")
	f = newV2Fx(t)
	f.ctx["schema"].(map[string]any)["docs"] = "x"
	killBWant(t, "docs-string", killBSchema(t, f), "the schema context must be {docs: [...], keys: [...]}")
	f = newV2Fx(t)
	f.ctx["schema"].(map[string]any)["docs"] = []any{}
	killBWant(t, "docs-empty", killBSchema(t, f), "this verifier has no action schema configured")
	f = newV2Fx(t)
	delete(f.p, "intent_session")
	f.ctx["schema"].(map[string]any)["docs"] = []any{}
	killBWant(t, "docs-empty-no-session", killBSchema(t, f), "this verifier has no action schema configured")
	f = newV2Fx(t)
	f.is()["schema"] = dg("unknown")
	killBWant(t, "unknown-digest", killBSchema(t, f), "intent_session.schema names no schema this verifier accepts")
	// a forged schema (content changed after signing) whose digest the PCActn names: exactly "schema does not verify"
	f = newV2Fx(t)
	f.schema["version"] = "2026-10-02"
	d, _ := actionSchemaDigest(deep(t, f.schema))
	f.is()["schema"] = d
	f.ctx["schema"].(map[string]any)["docs"] = []any{f.schema}
	killBWant(t, "forged", killBSchema(t, f), "schema does not verify: schema signature invalid")
	f = newV2Fx(t)
	f.p["aud"] = "other.example"
	killBWant(t, "aud", killBSchema(t, f), "schema aud does not match the PCActn aud")
	f = newV2Fx(t)
	delete(f.ctx, "params")
	killBWant(t, "no-params", killBSchema(t, f), "no plaintext params to check against the schema (closed world needs them)")
	f = newV2Fx(t)
	f.ctx["params"].(map[string]any)["total"] = jnum(1)
	killBWant(t, "params-digest", killBSchema(t, f), "params do not hash to action.params_digest")
	// params that are not strictly canonical (-0) are an error of the check (fail closed), not a mismatch
	f = newV2Fx(t)
	pd := f.p2()
	ctx := killBCtx(t, f.ctx)
	ctx.raw["params"].(map[string]any)["total"] = json.Number("-0")
	p := killBTry(func() { schemaStep(pd, ctx) })
	if !strings.Contains(p, "params are not strictly canonical") {
		t.Errorf("params -0: panic %q, want the strict-canonical fail-closed error", p)
	}
	// ... and decideIntentV2 turns that error into a failed `schema` check (never a crash)
	var dec v2Decision
	if p := killBTry(func() { dec = decideIntentV2(pd, deepM(t, f.grant), ctx, float64(f.now)) }); p != "" {
		t.Fatalf("decideIntentV2 panicked: %s", p)
	}
	if len(dec.checks) == 0 || dec.checks[0].name != "schema" || dec.checks[0].ok || !strings.Contains(dec.checks[0].why, "schema error (fail closed)") {
		t.Errorf("decide with -0 params: %+v", dec.checks)
	}
}

// ---- rule 15 (intent-v2.ts accumulatorCheck) ---------------------------------------------------------------------

// killBReroot re-signs S after mut and re-binds the PCActn to it.
func killBReroot(f *v2fx, mut func(S map[string]any)) {
	mut(f.S)
	f.signRoot()
	f.rebind()
}

func killBAccDecl(id, agg string, sel map[string]any, extra map[string]any) map[string]any {
	a := map[string]any{"id": id, "agg": agg, "sel": sel, "win": map[string]any{"kind": "task"}, "key": nil, "holder": map[string]any{"kind": "site_local"}}
	for k, v := range extra {
		a[k] = v
	}
	return a
}

func TestKillBAccStep(t *testing.T) {
	f := newV2Fx(t)
	env, why := killBAcc(t, f)
	killBWant(t, "base", why, "")
	if got := fmt.Sprint(env["acc"]); got != "map[trip_spend:map[post:38900]]" {
		t.Errorf("base env.acc = %s", got)
	}
	f = newV2Fx(t)
	delete(f.ctx["session"].(map[string]any), "root")
	_, why = killBAcc(t, f)
	killBWant(t, "no-root", why, "no session root for this session")
	f = newV2Fx(t)
	f.is()["acc"] = []any{map[string]any{"id": "trip_spend", "post": jnum(38_900)}, map[string]any{"id": "nope", "post": jnum(1)}}
	_, why = killBAcc(t, f)
	killBWant(t, "claim-unknown", why, "claim 'nope' names no accumulator of the session")
	f = newV2Fx(t)
	f.is()["schema"] = dg("unknown-schema")
	_, why = killBAcc(t, f)
	killBWant(t, "no-schema", why, "accumulator 'trip_spend' selects by accumulates_into but the session schema is not available")
	f = newV2Fx(t)
	f.is()["acc"] = []any{}
	_, why = killBAcc(t, f)
	killBWant(t, "no-claim", why, "no claim for accumulator 'trip_spend' that this action feeds")
	f = newV2Fx(t)
	f.ctx["acc"].(map[string]any)["state"] = map[string]any{}
	_, why = killBAcc(t, f)
	killBWant(t, "no-state", why, "no state for site-local accumulator 'trip_spend'")

	// an accumulator this action does not feed (sel.verbs names another verb)
	other := func(f *v2fx) {
		killBReroot(f, func(S map[string]any) {
			S["accumulators"] = append(S["accumulators"].([]any), killBAccDecl("other", "sum", map[string]any{"verbs": []any{"hotel.book"}}, map[string]any{"val": "action.params.total"}))
		})
	}
	f = newV2Fx(t)
	other(f)
	f.ctx["acc"].(map[string]any)["state"].(map[string]any)["other"] = map[string]any{"sum": jnum(5)}
	env, why = killBAcc(t, f)
	killBWant(t, "unfed-with-state", why, "")
	if got := fmt.Sprint(env["acc"]); got != "map[other:map[post:5] trip_spend:map[post:38900]]" {
		t.Errorf("unfed env.acc = %s", got)
	}
	f = newV2Fx(t)
	other(f)
	env, why = killBAcc(t, f)
	killBWant(t, "unfed-no-state", why, "")
	if got := fmt.Sprint(env["acc"]); got != "map[trip_spend:map[post:38900]]" {
		t.Errorf("unfed-no-state env.acc = %s", got)
	}
	f = newV2Fx(t)
	other(f)
	f.ctx["acc"].(map[string]any)["state"].(map[string]any)["other"] = map[string]any{"sum": jnum(-1)}
	_, why = killBAcc(t, f)
	killBWant(t, "unfed-bad-state", why, "accumulator 'other': pre-state sum must be a non-negative safe integer")
	f = newV2Fx(t)
	other(f)
	f.is()["acc"] = []any{map[string]any{"id": "trip_spend", "post": jnum(38_900)}, map[string]any{"id": "other", "post": jnum(5)}}
	_, why = killBAcc(t, f)
	killBWant(t, "unfed-claimed", why, "claim 'other' for an accumulator this action does not feed")

	// keyed accumulators: the key must be a present, schema-declared identity
	keyed := func(f *v2fx, key string) {
		killBReroot(f, func(S map[string]any) {
			S["accumulators"] = []any{killBAccDecl("k", "count", map[string]any{"verbs": []any{"air.book"}}, map[string]any{"key": key})}
		})
		f.is()["acc"] = []any{map[string]any{"id": "k", "post": jnum(1)}}
		f.ctx["acc"].(map[string]any)["state"] = map[string]any{"k": map[string]any{"count": jnum(0)}}
	}
	f = newV2Fx(t)
	keyed(f, "action.params.offer_id")
	_, why = killBAcc(t, f)
	killBWant(t, "keyed-ok", why, "")
	f = newV2Fx(t)
	keyed(f, "action.params.passengers")
	_, why = killBAcc(t, f)
	killBWant(t, "keyed-missing", why, "accumulator 'k': the key parameter action.params.passengers is missing")
	const freeText = "accumulator 'k': the key must be a schema-declared identity (not free text)"
	f = newV2Fx(t)
	keyed(f, "action.params.note")
	f.ctx["params"].(map[string]any)["note"] = "hi"
	_, why = killBAcc(t, f)
	killBWant(t, "keyed-text", why, freeText)
	f = newV2Fx(t)
	keyed(f, "action.params.offer_id")
	f.ctx["schema"].(map[string]any)["docs"] = []any{}
	_, why = killBAcc(t, f)
	killBWant(t, "keyed-no-schema", why, freeText)
	// crafted (unverified) schema entries: the verb entry's declaration of the key parameter
	withDoc := func(f *v2fx, verbs []any) {
		doc := map[string]any{"verbs": verbs}
		d, ok := actionSchemaDigest(deep(t, doc))
		if !ok {
			t.Fatal("doc digest")
		}
		f.ctx["schema"].(map[string]any)["docs"] = []any{doc}
		f.is()["schema"] = d
	}
	decl := func(x any, has bool) []any {
		ps := map[string]any{}
		if has {
			ps["action.params.offer_id"] = x
		}
		return []any{map[string]any{"verb": "air.book", "params": ps}}
	}
	for _, c := range []struct {
		name  string
		verbs []any
		want  string // "" ok; "PANIC:..." prefix match; else exact reason
	}{
		{"sem-id", decl(map[string]any{"semantic": "id.offer"}, true), ""},
		{"sem-text", decl(map[string]any{"semantic": "text"}, true), ""},
		{"sem-tex", decl(map[string]any{"semantic": "tex"}, true), ""},
		{"sem-text.", decl(map[string]any{"semantic": "text."}, true), freeText},
		{"sem-text.x", decl(map[string]any{"semantic": "text.x"}, true), freeText},
		{"sem-text.long", decl(map[string]any{"semantic": "text.free_form"}, true), freeText},
		{"decl-false", decl(false, true), freeText},
		{"decl-null", decl(nil, true), freeText},
		{"decl-absent", decl(nil, false), freeText},
		{"decl-true", decl(true, true), "PANIC: unusable key declaration"},
		{"decl-number", decl(jnum(1), true), "PANIC: unusable key declaration"},
		{"decl-no-semantic", decl(map[string]any{}, true), "PANIC: unusable key declaration"},
		{"verb-absent", []any{map[string]any{"verb": "hotel.book", "params": map[string]any{}}}, freeText},
		{"verb-params-null", []any{map[string]any{"verb": "air.book", "params": nil}}, "PANIC: unusable schema entry"},
		{"verb-params-absent", []any{map[string]any{"verb": "air.book"}}, "PANIC: unusable schema entry"},
		{"verb-entry-null", []any{nil, map[string]any{"verb": "air.book", "params": map[string]any{}}}, "PANIC: unusable schema entry"},
	} {
		f = newV2Fx(t)
		keyed(f, "action.params.offer_id")
		withDoc(f, c.verbs)
		_, why = killBAcc(t, f)
		if strings.HasPrefix(c.want, "PANIC:") {
			killBWantSub(t, "keyed-"+c.name, why, c.want)
		} else {
			killBWant(t, "keyed-"+c.name, why, c.want)
		}
	}
	// an unusable (null) verb entry where the accumulator selects by accumulates_into / reads its value from the schema
	f = newV2Fx(t)
	withDoc(f, []any{nil})
	_, why = killBAcc(t, f)
	killBWantSub(t, "select-null-entry", why, "PANIC: unusable schema entry")
	f = newV2Fx(t)
	killBReroot(f, func(S map[string]any) {
		S["accumulators"] = []any{killBAccDecl("s", "sum", map[string]any{"verbs": []any{"air.book"}, "accumulates_into": "spend.usd_cents"}, nil)}
	})
	f.is()["acc"] = []any{map[string]any{"id": "s", "post": jnum(38_900)}}
	f.ctx["acc"].(map[string]any)["state"] = map[string]any{"s": map[string]any{"sum": jnum(0)}}
	_, why = killBAcc(t, f)
	killBWant(t, "value-from-schema", why, "")
	withDoc(f, []any{nil})
	_, why = killBAcc(t, f)
	killBWantSub(t, "value-null-entry", why, "PANIC: unusable schema entry")
}

// sequenced accumulators: the receipt lookup and the reservation binding
func TestKillBAccReceipts(t *testing.T) {
	setup := func() (*v2fx, map[string]any, []any) {
		f := newV2Fx(t)
		f.useSequenced()
		r := f.receipt(f.seqKey, "s2", nil)
		ks := []any{f.keySet(f.seqRoot, keyEntry("s2", f.seqKey, 0, nil))}
		return f, r, ks
	}
	f, r, ks := setup()
	f.claimReceipt(r, 48_900, ks, r)
	_, why := killBAcc(t, f)
	killBWant(t, "base", why, "")
	// another receipt listed first: the claimed one is found by digest
	f, r, ks = setup()
	r0 := f.receipt(f.seqKey, "s2", func(x map[string]any) { x["acc"] = "other_acc" })
	f.claimReceipt(r, 48_900, ks, r0, r)
	_, why = killBAcc(t, f)
	killBWant(t, "second-receipt", why, "")
	// the claimed digest names nothing presented
	f, r, ks = setup()
	f.claimReceipt(r, 48_900, ks)
	_, why = killBAcc(t, f)
	killBWant(t, "not-presented", why, "the reservation receipt for 'trip_spend' was not presented")
	// a digest-matching non-object is presented: refused by the receipt check, not "not presented"
	f, r, ks = setup()
	f.claimReceipt(r, 48_900, ks, r)
	d, _ := accReceiptDigest("x")
	f.is()["acc"] = []any{map[string]any{"id": "trip_spend", "post": jnum(48_900), "receipt": d}}
	f.ctx["acc"].(map[string]any)["receipts"] = []any{"x"}
	_, why = killBAcc(t, f)
	killBWant(t, "non-object", why, "the reservation receipt for 'trip_spend' is not signed by a key the session sequencer's root-signed key set lists for its issue time")
	// a receipt for another action
	f, _, ks = setup()
	r = f.receipt(f.seqKey, "s2", func(x map[string]any) { x["pcactn_digest"] = dg("other-action") })
	f.claimReceipt(r, 48_900, ks, r)
	_, why = killBAcc(t, f)
	killBWant(t, "other-action", why, "the reservation receipt for 'trip_spend' is for another action")
	// a PCActn that is not strictly canonical: the reservation digest is an error (fail closed)
	f, r, ks = setup()
	f.claimReceipt(r, 48_900, ks, r)
	p := f.p2()
	p["zz"] = json.Number("-0")
	ctx := killBCtx(t, f.ctx)
	pn := killBTry(func() { accStep(p, ctx, float64(f.now)) })
	if !strings.Contains(pn, "PCActn is not strictly canonical") {
		t.Errorf("non-canonical PCActn: panic %q", pn)
	}
	// max_keyset_age_s is in seconds: an age of exactly the policy passes
	for _, c := range []struct {
		age  int64
		pass bool
	}{{2_000, true}, {2_001, false}} {
		f, r, _ = setup()
		ks0 := []any{map[string]any{"kid": "s2", "pk": f.seqKey.id, "not_before": jnum(0)}}
		body := map[string]any{"v": jnum(1), "kind": "pca-sequencer-keys", "sequencer": f.seqRoot.id, "version": jnum(1), "issued_at": jnum(v2Now - c.age), "keys": ks0}
		set := withoutKeys(body)
		set["sig"] = signDomain(t, f.seqRoot, sequencerKeysDomain, body)
		f.claimReceipt(r, 48_900, []any{set}, r)
		f.ctx["policy"] = map[string]any{"acc": map[string]any{"max_keyset_age_s": jnum(2)}}
		_, why = killBAcc(t, f)
		if (why == "") != c.pass {
			t.Errorf("keyset age %d ms under max_keyset_age_s 2: why %q", c.age, why)
		}
	}
}

// ---- V5 layers, context plumbing, policy text, middleware --------------------------------------------------------

func TestKillBLayersMalformed(t *testing.T) {
	actx := map[string]any{"action": map[string]any{"verb": "air.book", "resource": "r", "params": map[string]any{}}, "env": map[string]any{}}
	const bad = "layers: the org ceiling is malformed (null or not {predicates: [...]})"
	killBWant(t, "predicates-string", decideLayerCeilings(map[string]any{"org": map[string]any{"predicates": "x"}}, actx), bad)
	killBWant(t, "predicates-extra", decideLayerCeilings(map[string]any{"org": map[string]any{"predicates": []any{map[string]any{"verb": "air.book"}}, "x": jnum(1)}}, actx), bad)
	killBWant(t, "predicates-missing", decideLayerCeilings(map[string]any{"org": map[string]any{}}, actx), bad)
	killBWant(t, "ok", decideLayerCeilings(map[string]any{"org": map[string]any{"predicates": []any{map[string]any{"verb": "air.book"}}}}, actx), "")
}

func TestKillBContextPlumbing(t *testing.T) {
	if _, err := IntentV2ContextFromJSONText("{"); err == nil || strings.Contains(err.Error(), "not a JSON object") {
		t.Errorf("unparseable text: err %v, want the parse error", err)
	}
	if c, err := IntentV2ContextFromJSONText("[1]"); err == nil || c != nil {
		t.Errorf("non-object text: %v %v", c, err)
	}
	if c, err := IntentV2ContextFromJSONText(`{"a":1}`); err != nil || c == nil {
		t.Errorf("object text: %v %v", c, err)
	}
	o := map[string]any{"a": jnum(5), "n": nil, "m": map[string]any{"b": "x"}}
	if v, ok := memberPath(o); !ok || v == nil {
		t.Errorf("empty path: %v %v", v, ok)
	}
	if v, ok := memberPath(o, "m", "b"); !ok || v != "x" {
		t.Errorf("m.b: %v %v", v, ok)
	}
	if v, ok := memberPath(o, "a", "b"); ok || v != nil {
		t.Errorf("through a number: %v %v", v, ok)
	}
	if v, ok := memberPath(o, "n", "b"); ok || v != nil {
		t.Errorf("through null: %v %v", v, ok)
	}
	if v, ok := member(jnum(1), "a"); ok || v != nil {
		t.Errorf("member of a number: %v %v", v, ok)
	}
	var nc *IntentV2Context
	if v, ok := nc.get("a"); ok || v != nil {
		t.Errorf("nil context get: %v %v", v, ok)
	}
	// IntentPolicyFromJSONText: an unparseable text reports the parse error
	if _, err := IntentPolicyFromJSONText("{"); err == nil || strings.Contains(err.Error(), "not a JSON object") {
		t.Errorf("policy text: err %v, want the parse error", err)
	}
}

// RequirePCA hands the IntentV2 callback's state to the verifier (a session action needs it to pass).
func TestKillBMiddlewareIntentV2(t *testing.T) {
	f := newV2Fx(t)
	if v := f.verify(); !v.Allow {
		t.Fatalf("fixture not allowed: %s", v.Reason)
	}
	ctx := killBCtx(t, f.ctx)
	grant := deepM(t, f.grant)
	ref := f.p["grant_ref"].(string)
	called := false
	h := RequirePCA(RequirePCAOptions{
		Audience: v2Aud,
		Now:      func() int64 { return f.now },
		ResolveGrant: func(r string) (map[string]any, error) {
			if r == ref {
				return grant, nil
			}
			return nil, fmt.Errorf("unknown grant")
		},
		IntentV2: func(*http.Request, map[string]any) *IntentV2Context { return ctx },
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodPost, "/do", nil)
	req.Header.Set(PCAHeader, headerFor(t, f.p2()))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if !called || rec.Code != http.StatusNoContent {
		t.Fatalf("status %d (%s), called %v", rec.Code, rec.Body.String(), called)
	}
}

// env.canon exists for the layers ceilings only when `schema` PASSED (intent-v2.ts: `...(out.env?.canon ? {canon} : {})`),
// and a W-B error fails `facts` (fail closed) instead of escaping the decision.
func TestKillBDecidePipeline(t *testing.T) {
	f := newV2Fx(t)
	f.ctx["params"].(map[string]any)["total"] = jnum(1) // schema fails: params do not hash to params_digest
	f.ctx["layers"] = map[string]any{"org": map[string]any{"predicates": []any{map[string]any{"verb": "air.book", "resource": "*",
		"where": []any{map[string]any{"field": "env.canon", "op": "exists", "value": false}}}}}}
	var dec v2Decision
	if p := killBTry(func() { dec = decideIntentV2(f.p2(), deepM(t, f.grant), killBCtx(t, f.ctx), float64(f.now)) }); p != "" {
		t.Fatalf("panic: %s", p)
	}
	got := map[string]v2Check{}
	for _, c := range dec.checks {
		got[c.name] = c
	}
	if got["schema"].ok || got["schema"].why != "params do not hash to action.params_digest" {
		t.Errorf("schema: %+v", got["schema"])
	}
	if c, has := got["layers"]; !has || !c.ok {
		t.Errorf("layers (no env.canon after a failed schema): %+v (present %v)", c, has)
	}

	f = newV2Fx(t)
	f.is()["session"] = jnum(5)
	if p := killBTry(func() { dec = decideIntentV2(f.p2(), deepM(t, f.grant), killBCtx(t, f.ctx), float64(f.now)) }); p != "" {
		t.Fatalf("a W-B error escaped decideIntentV2: %s", p)
	}
	got = map[string]v2Check{}
	for _, c := range dec.checks {
		got[c.name] = c
	}
	if c := got["facts"]; c.ok || !strings.HasPrefix(c.why, "W-B error (fail closed)") {
		t.Errorf("facts after a W-B error: %+v", c)
	}
}
