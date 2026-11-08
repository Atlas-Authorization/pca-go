package pca

import (
	"crypto/ed25519"
	"strings"
	"testing"
)

// g10faTok is a fresh_at token whose fields mut may change, then signed by k over exactly its (nine) fields.
func g10faTok(t *testing.T, k fxKey, mut func(map[string]any)) map[string]any {
	t.Helper()
	tok := map[string]any{"v": jnum(1), "scope": "inst_1", "revocation_epoch": jnum(1), "ledger_tree_size": jnum(2),
		"budget_version": jnum(3), "policy_revision": jnum(4), "policy_digest": "pd", "issued_at": jnum(5), "signer": k.id}
	if mut != nil {
		mut(tok)
	}
	c, err := canonBytes(tok)
	if err != nil {
		t.Fatal(err)
	}
	tok["sig"] = b64.EncodeToString(ed25519.Sign(k.priv, append([]byte(freshAtDomain), c...)))
	return tok
}

func TestG10VerifyFreshAtShape(t *testing.T) {
	k, other := newKey(t), newKey(t)
	set := func(key string, v any) func(map[string]any) { return func(m map[string]any) { m[key] = v } }
	for _, c := range []struct {
		name string
		mut  func(map[string]any)
		want bool
	}{
		{"valid", nil, true},
		{"v 2", set("v", jnum(2)), false},
		{"signer field names another key", set("signer", other.id), false},
		{"empty scope", set("scope", ""), false},
		{"scope 256", set("scope", strings.Repeat("s", 256)), true},
		{"scope 257", set("scope", strings.Repeat("s", 257)), false},
		{"policy_digest 128", set("policy_digest", strings.Repeat("p", 128)), true},
		{"policy_digest 129", set("policy_digest", strings.Repeat("p", 129)), false},
		{"negative counter", set("revocation_epoch", jnum(-1)), false},
	} {
		if got := VerifyFreshAt(g10faTok(t, k, c.mut), k.id); got != c.want {
			t.Errorf("%s: VerifyFreshAt = %v, want %v", c.name, got, c.want)
		}
	}
	if VerifyFreshAt("not an object", k.id) || VerifyFreshAt(nil, k.id) {
		t.Fatal("a non-object token must not verify")
	}
}

func TestG10FreshAtWireShape(t *testing.T) {
	base := func() map[string]any {
		return map[string]any{"v": jnum(1), "scope": "s", "revocation_epoch": jnum(0), "ledger_tree_size": jnum(0),
			"budget_version": jnum(0), "policy_revision": jnum(0), "policy_digest": "pd", "issued_at": jnum(0),
			"signer": b64.EncodeToString(make([]byte, 32)), "sig": b64.EncodeToString(make([]byte, 64))}
	}
	const strMsg = "'fresh_at' scope and policy_digest must be non-empty strings"
	for _, c := range []struct {
		key  string
		v    any
		want string
	}{
		{"", nil, ""},
		{"v", jnum(2), "'fresh_at.v' must be 1"},
		{"scope", "", strMsg},
		{"scope", strings.Repeat("s", 256), ""},
		{"scope", strings.Repeat("s", 257), strMsg},
		{"policy_digest", strings.Repeat("p", 128), ""},
		{"policy_digest", strings.Repeat("p", 129), strMsg},
		{"signer", "not base64url!", "'fresh_at.signer' is not canonical base64url (32 bytes)"},
	} {
		m := base()
		if c.key != "" {
			m[c.key] = c.v
		}
		if got := validateFreshAtWire(m); got != c.want {
			t.Errorf("%s=%v: %q, want %q", c.key, c.v, got, c.want)
		}
	}
}
