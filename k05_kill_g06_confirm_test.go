package pca

// k05 mutation kills (group g06): signed reviewer confirmations (actions_confirm.go), agent blueprints (blueprint.go) and
// the verdict fold of pca.go. Self-contained: every key, record and attestation is generated here.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
)

type g06acSigner struct {
	priv ed25519.PrivateKey
	kid  string
	pins map[string]any
}

func g06acNew(t *testing.T) *g06acSigner {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s := &g06acSigner{priv: priv, kid: "rev-1"}
	s.pins = map[string]any{"keys": []any{map[string]any{"kid": s.kid, "pk": b64.EncodeToString(pub), "roles": []any{"reviewer"}}}}
	return s
}

// sign signs the review message exactly as confirmationError rebuilds it (dl: the dismissals in signed order).
func (s *g06acSigner) sign(t *testing.T, want, td, fd string, final []string, dl []any) string {
	t.Helper()
	msg, ok := domainMessage(reviewDomain, map[string]any{"def_digest": want, "traits_digest": td, "facts_digest": fd, "final_traits": anyStrs(sortUniqS(final)),
		"dismissed": dl, "reviewer_kid": s.kid, "ts": json.Number("100")})
	if !ok {
		t.Fatal("review message")
	}
	return b64.EncodeToString(ed25519.Sign(s.priv, msg))
}

func g06dism(trait, reason string) map[string]any {
	return map[string]any{"trait": trait, "reason": reason}
}

// attest is a signed attestation of `want` (facts digest "fd") with final traits [a] and the given dismissals; signedDl is the
// dismissal list the signature covers (nil: the same list).
func (s *g06acSigner) attest(t *testing.T, want string, dis, signedDl []any) map[string]any {
	t.Helper()
	td, err := traitsDigest(coreRegistry)
	if err != nil {
		t.Fatal(err)
	}
	if signedDl == nil {
		signedDl = dis
	}
	return map[string]any{"def_digest": want, "traits_digest": td, "facts_digest": "fd", "final_traits": []any{"a"}, "dismissed": dis,
		"reviewer_kid": s.kid, "ts": json.Number("100"), "sig": s.sign(t, want, td, "fd", []string{"a"}, signedDl)}
}

func g06yes([]string) bool { return true }

func TestK05G06ConfirmationSignedDismissalOrder(t *testing.T) {
	s := g06acNew(t)
	// the signature covers the dismissals sorted by trait, a stable sort (equal traits keep their order)
	unsorted := []any{g06dism("b", "rb"), g06dism("x", "r1"), g06dism("c", "rc"), g06dism("x", "r2")}
	sorted := []any{g06dism("b", "rb"), g06dism("c", "rc"), g06dism("x", "r1"), g06dism("x", "r2")}
	if got := confirmationError(s.attest(t, "w", unsorted, sorted), "w", nil, coreRegistry, s.pins, g06yes); got != "" {
		t.Fatalf("sorted dismissals: %q", got)
	}
	if got := confirmationError(s.attest(t, "w", unsorted, unsorted), "w", nil, coreRegistry, s.pins, g06yes); got != "the confirmation signature is invalid" {
		t.Fatalf("signature over the unsorted list: %q", got)
	}
}

func TestK05G06ConfirmationRefusals(t *testing.T) {
	s := g06acNew(t)
	base := func() map[string]any { return s.attest(t, "w", []any{}, nil) }
	if got := confirmationError(base(), "w", nil, coreRegistry, s.pins, g06yes); got != "" {
		t.Fatalf("control: %q", got)
	}
	run := func(av any, want string) string {
		return confirmationError(av, want, nil, coreRegistry, s.pins, g06yes)
	}
	if got := run("x", "w"); got != "no confirmation" {
		t.Fatalf("not an object: %q", got)
	}
	if got := run(map[string]any{"def_digest": "w"}, "w"); got != "the confirmation is unsigned" {
		t.Fatalf("unsigned: %q", got)
	}
	if got := run(map[string]any{"sig": "x", "def_digest": ""}, ""); got != "the confirmation covers a different def digest" {
		t.Fatalf("empty def digest: %q", got)
	}

	// a def-level attestation (no wanted facts) without facts_digest, signed over an empty facts digest: not accepted
	td, _ := traitsDigest(coreRegistry)
	noFd := base()
	delete(noFd, "facts_digest")
	noFd["sig"] = s.sign(t, "w", td, "", []string{"a"}, []any{})
	if got := run(noFd, "w"); got != "the confirmation signature is invalid" {
		t.Fatalf("no facts_digest: %q", got)
	}

	for _, field := range []string{"final_traits", "dismissed", "reviewer_kid"} {
		a := base()
		delete(a, field)
		if got := run(a, "w"); got != "malformed confirmation" {
			t.Fatalf("no %s: %q", field, got)
		}
	}
	badTs := base()
	badTs["ts"] = "x"
	if got := run(badTs, "w"); got != "malformed confirmation" {
		t.Fatalf("ts: %q", got)
	}
	if got := confirmationError(base(), "w", nil, coreRegistry, s.pins, func([]string) bool { return false }); got != "malformed confirmation" {
		t.Fatalf("final traits refused: %q", got)
	}

	for i, d := range []any{map[string]any{"reason": "r"}, map[string]any{"trait": "q"}, g06dism("a", "r"), g06dism("q", "\x1f ")} {
		a := s.attest(t, "w", []any{d}, nil)
		if got := run(a, "w"); got != "a dismissed trait is also final, or has no reason" {
			t.Fatalf("dismissal %d: %q", i, got)
		}
	}

	if got := verbConfirmationError(map[string]any{}, coreRegistry, nil); got != "no reviewer keys are pinned" {
		t.Fatalf("no pins: %q", got)
	}
	if !blankReason("\x1f") || !blankReason("\x1c \t") || blankReason("\x1fa") {
		t.Fatal("blankReason")
	}
}

func TestK05G06DefConfirmed(t *testing.T) {
	s := g06acNew(t)
	// no resource: normalizeDef panics; the panic is a refusal
	if defConfirmed(map[string]any{"review": map[string]any{"state": "confirmed"}}, coreRegistry, s.pins) {
		t.Fatal("a def that cannot be normalized is confirmed")
	}
	// a float64 member cannot be canonicalized: no def digest, not confirmed
	if defConfirmed(map[string]any{"review": map[string]any{"state": "confirmed"}, "resource": map[string]any{"scope": "x"}, "params": map[string]any{}, "description": 1.5}, coreRegistry, s.pins) {
		t.Fatal("a def without a digest is confirmed")
	}

	d := map[string]any{"resource": map[string]any{"scope": "x"}, "params": map[string]any{}, "traits": []any{"a", "b"}}
	dg, err := defDigest(d)
	if err != nil {
		t.Fatal(err)
	}
	td, _ := traitsDigest(coreRegistry)
	att := func(final ...string) map[string]any {
		return map[string]any{"def_digest": dg, "traits_digest": td, "facts_digest": "fd", "final_traits": anyStrs(final), "dismissed": []any{},
			"reviewer_kid": s.kid, "ts": json.Number("100"), "sig": s.sign(t, dg, td, "fd", final, []any{})}
	}
	d["review"] = map[string]any{"state": "confirmed", "attestation": att("a", "b")}
	if !defConfirmed(d, coreRegistry, s.pins) {
		t.Fatal("control: final == declared is not confirmed")
	}
	// same length, different trait
	d["review"] = map[string]any{"state": "confirmed", "attestation": att("a", "c")}
	if defConfirmed(d, coreRegistry, s.pins) {
		t.Fatal("final traits other than the declared ones confirmed")
	}
}

// ───────────────────────────────────────────────────────────── blueprints

func g06bp(fields map[string]any) map[string]any {
	b := map[string]any{"v": json.Number("1"), "id": "bp-1", "key": "k", "ceiling": []any{}, "epoch": json.Number("1"), "status": "active",
		"issued_at": json.Number("1"), "operator": "op"}
	for k, v := range fields {
		if v == nil {
			delete(b, k)
		} else {
			b[k] = v
		}
	}
	return b
}

func g06bpSigned(t *testing.T, priv ed25519.PrivateKey, fields map[string]any) map[string]any {
	t.Helper()
	b := g06bp(fields)
	body := map[string]any{}
	for _, k := range blueprintBodyKeys {
		if x, has := b[k]; has {
			body[k] = x
		}
	}
	c, err := canonBytes(body)
	if err != nil {
		t.Fatal(err)
	}
	b["sig"] = b64.EncodeToString(ed25519.Sign(priv, append([]byte(agentBlueprintDomain), c...)))
	return b
}

func TestK05G06BlueprintWellFormed(t *testing.T) {
	s128, s129 := strings.Repeat("a", 128), strings.Repeat("a", 129)
	ceiling := func(n int) []any {
		out := make([]any, n)
		for i := range out {
			out[i] = map[string]any{"type": "t"}
		}
		return out
	}
	for _, c := range []struct {
		name   string
		v      any
		wantOK bool
	}{
		{"valid", g06bp(nil), true},
		{"not an object", "x", false},
		{"v 2", g06bp(map[string]any{"v": json.Number("2")}), false},
		{"id 128", g06bp(map[string]any{"id": s128}), true},
		{"id 129", g06bp(map[string]any{"id": s129}), false},
		{"key 128", g06bp(map[string]any{"key": s128}), true},
		{"key 129", g06bp(map[string]any{"key": s129}), false},
		{"operator 128", g06bp(map[string]any{"operator": s128}), true},
		{"operator 129", g06bp(map[string]any{"operator": s129}), false},
		{"no id", g06bp(map[string]any{"id": nil}), false},
		{"no key", g06bp(map[string]any{"key": nil}), false},
		{"no operator", g06bp(map[string]any{"operator": nil}), false},
		{"epoch not an integer", g06bp(map[string]any{"epoch": "x"}), false},
		{"issued_at not an integer", g06bp(map[string]any{"issued_at": "x"}), false},
		{"status", g06bp(map[string]any{"status": "x"}), false},
		{"max_depth 0", g06bp(map[string]any{"max_depth": json.Number("0")}), false},
		{"max_depth 1", g06bp(map[string]any{"max_depth": json.Number("1")}), true},
		{"expires_at not an integer", g06bp(map[string]any{"expires_at": "x"}), false},
		{"no ceiling", g06bp(map[string]any{"ceiling": nil}), false},
		{"ceiling 32", g06bp(map[string]any{"ceiling": ceiling(32)}), true},
		{"ceiling 33", g06bp(map[string]any{"ceiling": ceiling(33)}), false},
		{"ceiling entry not an object", g06bp(map[string]any{"ceiling": []any{"x"}}), false},
		{"ceiling entry without type", g06bp(map[string]any{"ceiling": []any{map[string]any{}}}), false},
	} {
		b, ok := blueprintWellFormed(c.v)
		if ok != c.wantOK || (ok && b == nil) || (!ok && b != nil) {
			t.Fatalf("%s: %v %v, want %v", c.name, b, ok, c.wantOK)
		}
	}
	if VerifyBlueprint(map[string]any{}) {
		t.Fatal("an empty record verified")
	}
}

func TestK05G06BlueprintRegistry(t *testing.T) {
	pa, ka, _ := ed25519.GenerateKey(rand.Reader)
	pb, kb, _ := ed25519.GenerateKey(rand.Reader)
	opA, opB := b64.EncodeToString(pa), b64.EncodeToString(pb)
	r := NewBlueprintRegistry([]string{opA, opB}, MemoryBlueprintKv())
	accept := func(v any, code string, replaced bool) {
		t.Helper()
		if c, rep := r.Accept(v); c != code || rep != replaced {
			t.Fatalf("accept: %q %v, want %q %v", c, rep, code, replaced)
		}
	}
	first := g06bpSigned(t, ka, map[string]any{"operator": opA})
	accept("x", "bad_record", false)
	_, kc, _ := ed25519.GenerateKey(rand.Reader)
	accept(g06bpSigned(t, kc, map[string]any{"operator": b64.EncodeToString(kc.Public().(ed25519.PublicKey))}), "unknown_operator", false)
	accept(first, "", true)
	accept(g06bpSigned(t, kb, map[string]any{"operator": opB, "epoch": json.Number("2")}), "operator_changed", false)
	accept(g06bpSigned(t, ka, map[string]any{"operator": opA, "epoch": json.Number("0")}), "stale_epoch", false)
	accept(g06bpSigned(t, ka, map[string]any{"operator": opA, "issued_at": json.Number("2")}), "epoch_fork", false)
	accept(first, "", false)
	accept(g06bpSigned(t, ka, map[string]any{"operator": opA, "key": "k2", "id": "bp-2", "epoch": json.Number("7")}), "", true)
	// the highest epoch, whatever the store's iteration order
	for i := 0; i < 64; i++ {
		if e := r.Epoch(); e != 7 {
			t.Fatalf("Epoch() = %d, want 7", e)
		}
	}
}

func TestK05G06CheckBlueprintsHops(t *testing.T) {
	r := NewBlueprintRegistry(nil, MemoryBlueprintKv())
	s128, s129 := strings.Repeat("h", 128), strings.Repeat("h", 129)
	for _, c := range []struct {
		name, issuer, holder, want string
	}{
		{"issuer 128", s128, "x", "allow"},
		{"holder 128", "x", s128, "allow"},
		{"issuer 129", s129, "x", "deny"},
		{"holder 129", "x", s129, "deny"},
		{"empty issuer", "", "x", "deny"},
		{"empty holder", "x", "", "deny"},
	} {
		got := CheckBlueprints([]any{map[string]any{"issuer": c.issuer, "holder": c.holder}}, r, json.Number("1"), "any", nil)
		if got.Decision != c.want || (c.want == "deny" && got.Code != "bad_input") {
			t.Fatalf("%s: %+v", c.name, got)
		}
	}
}

// ───────────────────────────────────────────────────────────── pca.go: the verdict fold and the fresh_at member

func TestK05G06VerdictReasonsFold(t *testing.T) {
	r := newFaRig(t, false)
	v, err := VerifyPCActnCoreWith(r.f.p, r.f.grant, r.f.now, r.f.aud, VerifyOptions{InsecureSkipPlanRootCheck: true})
	if err != nil || !v.Allow || v.Reasons != nil {
		t.Fatalf("allowed verdict: %+v %v", v, err)
	}

	// fresh_at carried with no policy fails; with an earlier failure (audience) the fresh_at reason is folded in after it
	m := newFaRig(t, true)
	v, err = VerifyPCActnCoreWith(m.f.p, m.f.grant, m.f.now, "other-aud", VerifyOptions{InsecureSkipPlanRootCheck: true})
	want := []string{"audience: aud does not match this resource server / instance", "fresh_at: the PCActn carries fresh_at but this verifier has no fresh_at policy (fail closed)"}
	if err != nil || v.Allow || len(v.Reasons) != 2 || v.Reasons[0] != want[0] || v.Reasons[1] != want[1] {
		t.Fatalf("folded reasons: %q %v", v.Reasons, err)
	}

	// a wire-valid fresh_at does not end the wire validation: a malformed later member is still refused
	p := deepCopy(m.f.p).(map[string]any)
	p["prohibition_evidence"] = "x"
	if got := ValidateWireV2(p); got != "'prohibition_evidence' must be an object or array" {
		t.Fatalf("wire: %q", got)
	}
}
