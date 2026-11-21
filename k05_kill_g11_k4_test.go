package pca

import (
	"crypto/ed25519"
	"encoding/json"
	"reflect"
	"testing"
)

func g11K4Key() (ed25519.PrivateKey, string) {
	seed := make([]byte, 32)
	seed[0] = 44
	priv := ed25519.NewKeyFromSeed(seed)
	return priv, b64.EncodeToString(priv.Public().(ed25519.PublicKey))
}

// g11K4Sign signs m (without its sig) the k4 way and stores the signature in m["sig"].
func g11K4Sign(priv ed25519.PrivateKey, kind string, m map[string]any) map[string]any {
	body := map[string]any{}
	for k, v := range m {
		if k != "sig" {
			body[k] = v
		}
	}
	h, err := HashCanonical(map[string]any{"kind": kind, "body": body})
	if err != nil {
		panic(err)
	}
	m["sig"] = b64.EncodeToString(ed25519.Sign(priv, []byte(h)))
	return m
}

// g11K4Cfg is a signed pricing config, with the named members removed and the given ones set before signing.
func g11K4Cfg(drop string, set map[string]any) map[string]any {
	priv, pub := g11K4Key()
	m := map[string]any{"v": json.Number("1"), "principal": pub, "currency": "USD", "interruptionCost": json.Number("5"),
		"maxInterruptionCost": json.Number("10"), "hardCeilingLoss": json.Number("1000"), "epoch": json.Number("1"), "tightenStepPpm": json.Number("100000")}
	for k, v := range set {
		m[k] = v
	}
	delete(m, drop)
	return g11K4Sign(priv, "pca.escalation_pricing", m)
}

func g11K4Answer(drop string, set map[string]any) map[string]any {
	priv, pub := g11K4Key()
	m := map[string]any{"v": json.Number("1"), "principal": pub, "nonce": "nonce-0001", "action_digest": "ad1", "answer": "approve"}
	for k, v := range set {
		m[k] = v
	}
	delete(m, drop)
	return g11K4Sign(priv, "pca.escalation_answer", m)
}

func TestG11K4NumberReaders(t *testing.T) {
	for _, v := range []any{"5", json.Number("-1"), json.Number("1.5"), nil} {
		if n, ok := k4Minor(v); ok || n != 0 {
			t.Errorf("k4Minor(%v) = %d %v", v, n, ok)
		}
	}
	for _, v := range []any{"5", json.Number("1.5"), json.Number("-0"), nil} {
		if n, ok := k4SafeInt(v); ok || n != 0 {
			t.Errorf("k4SafeInt(%v) = %d %v", v, n, ok)
		}
	}
	if n, ok := k4SafeInt(json.Number("-7")); !ok || n != -7 {
		t.Fatal(n, ok)
	}
}

func TestG11K4Sig(t *testing.T) {
	priv, pub := g11K4Key()
	good := g11K4Sign(priv, "k", map[string]any{"a": "b"})
	if ok, dec := k4Sig(pub, "k", good); !ok || !dec {
		t.Fatal("control", ok, dec)
	}
	for name, tc := range map[string]struct {
		pub any
		obj map[string]any
	}{
		"pub not a string":      {5, good},
		"sig not a string":      {pub, map[string]any{"a": "b", "sig": 5}},
		"pub does not decode":   {"!!", good},
		"sig does not decode":   {pub, map[string]any{"a": "b", "sig": "!!"}},
		"body not canonical":    {pub, map[string]any{"a": 1.5, "sig": good["sig"]}},
		"pub missing, sig fine": {nil, good},
	} {
		if ok, dec := k4Sig(tc.pub, "k", tc.obj); ok || dec {
			t.Errorf("%s: %v %v", name, ok, dec)
		}
	}
	// decodes but does not verify
	if ok, dec := k4Sig(pub, "other", good); ok || !dec {
		t.Fatal("wrong kind", ok, dec)
	}
}

func TestG11K4Luhn(t *testing.T) {
	for d, want := range map[string]bool{"59": true, "58": false, "4111111111111111": true, "4111111111111112": false, "79927398713": true} {
		if k4Luhn(d) != want {
			t.Errorf("k4Luhn(%s) != %v", d, want)
		}
	}
	for s, want := range map[string]bool{
		"411111111117":         false, // 12 digits
		"4111111111119":        true,  // 13
		"4111111111111111110":  true,  // 19
		"41111111111111111115": false, // 20
		"ab 4111-1111-1111-9":  true,  // 13 once spaces and hyphens go
	} {
		if !k4Luhn(stripNonDigitsG11(s)) {
			t.Fatalf("fixture %s must pass Luhn", s)
		}
		if LooksLikePan(s) != want {
			t.Errorf("LooksLikePan(%s) != %v", s, want)
		}
	}
}

func stripNonDigitsG11(s string) string {
	out := []byte{}
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			out = append(out, s[i])
		}
	}
	return string(out)
}

func TestG11K4BindingMalformedKeys(t *testing.T) {
	grant := map[string]any{"g": "1"}
	gd, _ := HashCanonical(grant)
	b := map[string]any{"kind": networkTokenBindKind, "token_ref": "tok_abcdefgh", "provider": "visa", "grant_digest": gd,
		"holder": "!!", "issuer_nonce": "n1", "binding_proof": "AAAA"}
	if got := VerifyNetworkTokenBinding(b, grant, "!!", "n1", ""); got != "binding_malformed" {
		t.Fatal(got)
	}
}

func TestG11K4PricingConfig(t *testing.T) {
	if got := PricingConfigError(g11K4Cfg("", nil)); got != "" {
		t.Fatal("control", got)
	}
	for _, tc := range []struct {
		drop string
		set  map[string]any
		want string
	}{
		{"currency", nil, "config_malformed"},
		{"interruptionCost", nil, "config_amounts_invalid"},
		{"maxInterruptionCost", nil, "config_amounts_invalid"},
		{"hardCeilingLoss", nil, "config_amounts_invalid"},
		{"epoch", nil, "config_amounts_invalid"},
		{"", map[string]any{"interruptionCost": json.Number("10")}, ""},
		{"", map[string]any{"interruptionCost": json.Number("11")}, "config_cost_above_max"},
		{"", map[string]any{"tightenStepPpm": json.Number("0")}, ""},
		{"", map[string]any{"tightenStepPpm": json.Number("-1")}, "config_step_invalid"},
		{"tightenStepPpm", nil, "config_step_invalid"},
	} {
		if got := PricingConfigError(g11K4Cfg(tc.drop, tc.set)); got != tc.want {
			t.Errorf("drop %q set %v: %q want %q", tc.drop, tc.set, got, tc.want)
		}
	}
}

func TestG11K4DecideEscalation(t *testing.T) {
	cal := map[string]any{"multiplierPpm": json.Number("1000000")}
	bad := g11K4Cfg("", nil)
	bad["epoch"] = json.Number("2")
	if got := DecideEscalation(bad, cal, map[string]any{"currency": "USD", "loss": json.Number("1"), "pBadUpperPpm": json.Number("1")}); got != (EscalationDecision{true, "config_signature_invalid"}) {
		t.Fatal(got)
	}
	cfg := g11K4Cfg("", nil)
	for _, r := range []map[string]any{
		{"currency": "USD", "loss": "x", "pBadUpperPpm": json.Number("1000")},
		{"currency": "USD", "loss": json.Number("1")},
	} {
		if got := DecideEscalation(cfg, cal, r); got != (EscalationDecision{true, "risk_input_invalid"}) {
			t.Errorf("%v: %+v", r, got)
		}
	}
	// p*mult = 2e12 is capped at 1e12: 1e12*3 <= 5e12 (uncapped it would be 6e12)
	if got := DecideEscalation(cfg, map[string]any{"multiplierPpm": json.Number("2000000")},
		map[string]any{"currency": "USD", "loss": json.Number("3"), "pBadUpperPpm": json.Number("1000000")}); got != (EscalationDecision{false, "expected_loss_within_interruption_cost"}) {
		t.Fatal(got)
	}
}

func TestG11K4AnswerOK(t *testing.T) {
	_, pub := g11K4Key()
	if !k4AnswerOK(g11K4Answer("", nil), pub) {
		t.Fatal("control")
	}
	if !k4AnswerOK(g11K4Answer("", map[string]any{"nonce": "abcdefgh"}), pub) {
		t.Fatal("an 8-unit nonce is enough")
	}
	for name, a := range map[string]any{
		"not an object":    "x",
		"no v":             g11K4Answer("v", nil),
		"v 2":              g11K4Answer("", map[string]any{"v": json.Number("2")}),
		"other principal":  g11K4Answer("", map[string]any{"principal": "someone"}),
		"7-unit nonce":     g11K4Answer("", map[string]any{"nonce": "abcdefg"}),
		"no action digest": g11K4Answer("action_digest", nil),
		"answer maybe":     g11K4Answer("", map[string]any{"answer": "maybe"}),
	} {
		if k4AnswerOK(a, pub) {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestG11K4UpdateCalibration(t *testing.T) {
	cfg := g11K4Cfg("", nil)
	// only string nonces of the start state are carried over
	mult, order := UpdateCalibration(cfg, map[string]any{"multiplierPpm": json.Number("1000000"), "seen": []any{"n-aaaaaaaa", json.Number("5")}}, nil, nil)
	if mult != 1_000_000 || !reflect.DeepEqual(order, []string{"n-aaaaaaaa"}) {
		t.Fatal(mult, order)
	}
	// an answer whose nonce was already seen is skipped
	deny := g11K4Answer("", map[string]any{"answer": "deny"})
	risks := map[string]any{"ad1": map[string]any{"currency": "USD", "loss": json.Number("1"), "pBadUpperPpm": json.Number("1")}}
	mult, order = UpdateCalibration(cfg, map[string]any{"multiplierPpm": json.Number("1000000"), "seen": []any{"nonce-0001"}}, []any{deny}, risks)
	if mult != 1_000_000 || !reflect.DeepEqual(order, []string{"nonce-0001"}) {
		t.Fatal(mult, order)
	}
	// control: unseen, the deny of a not-asked action tightens by one step
	mult, order = UpdateCalibration(cfg, map[string]any{"multiplierPpm": json.Number("1000000")}, []any{deny}, risks)
	if mult != 1_100_000 || !reflect.DeepEqual(order, []string{"nonce-0001"}) {
		t.Fatal(mult, order)
	}
	// an invalid config changes nothing (and must not be read)
	mult, order = UpdateCalibration(nil, map[string]any{"multiplierPpm": json.Number("1000000"), "seen": []any{"x"}}, []any{deny}, risks)
	if mult != 1_000_000 || !reflect.DeepEqual(order, []string{"x"}) {
		t.Fatal(mult, order)
	}
}

const g11Mgr = "0x1111111111111111111111111111111111111111"

func g11Perm(from any, hasFrom bool) (g, sent, got map[string]any) {
	g = map[string]any{"grantDigest": "gd", "expiresAtSec": json.Number("2000")}
	sent = map[string]any{"chainId": "0x1", "to": "0xTo",
		"permission": map[string]any{"type": "native-token-allowance", "data": map[string]any{"allowance": "0x10"}, "isAdjustmentAllowed": false}}
	if hasFrom {
		sent["from"] = from
	}
	got = map[string]any{
		"permission":        map[string]any{"type": "native-token-allowance", "data": map[string]any{"allowance": "0x10"}, "isAdjustmentAllowed": false},
		"context":           "0xabc",
		"delegationManager": g11Mgr,
		"chainId":           "0x1",
		"to":                "0xto",
		"from":              "0xBB",
		"rules":             []any{map[string]any{"type": "expiry", "data": map[string]any{"timestamp": json.Number("1000")}}},
	}
	return
}

func TestG11K4GrantedPermission(t *testing.T) {
	allowed := []string{g11Mgr}
	check := func(name string, g, sent, got map[string]any, mgrs []string, want string) {
		t.Helper()
		if r := VerifyGrantedPermission(g, sent, got, mgrs, nil); r != want {
			t.Errorf("%s: %q want %q", name, r, want)
		}
	}
	g, s, r := g11Perm(nil, false)
	check("control, no from sent", g, s, r, allowed, "")
	g, s, r = g11Perm(nil, true)
	check("from sent as null", g, s, r, allowed, "")
	g, s, r = g11Perm("0xbb", true)
	check("same from, other case", g, s, r, allowed, "")
	g, s, r = g11Perm("0xAA", true)
	check("other from", g, s, r, allowed, "from_mismatch")

	g, s, r = g11Perm(nil, false)
	delete(r, "permission")
	check("no permission", g, s, r, allowed, "response_malformed")

	g, s, r = g11Perm(nil, false)
	r["delegationManager"] = "zzz"
	check("allowed but not an address", g, s, r, []string{"zzz"}, "delegation_manager_not_allowed")

	g, s, r = g11Perm(nil, false)
	r["permission"].(map[string]any)["data"] = "x"
	check("data not an object", g, s, r, allowed, "response_malformed")

	g, s, r = g11Perm(nil, false)
	r["rules"] = []any{map[string]any{"type": "expiry", "data": map[string]any{"timestamp": "x"}}}
	check("expiry timestamp malformed", g, s, r, allowed, "expiry_malformed")
}
