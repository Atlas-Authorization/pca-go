package pca

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"testing"
)

// JSON.parse keeps the LAST repeated member while only the first is what a different parser sees as signed. These sites refuse a
// repeated member and leave numbers as written (8.0 and 1e3 stay accepted). Every signed fixture uses a key generated in the test.

func TestDuplicateKeyJSON(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{`{"a":1,"a":2}`, `"a"`},
		{`{"a":1,"\u0061":2}`, `"a"`},
		{`{"x":["s",{"k":1,"k":2}]}`, `"k"`},
		{`{"a":{"b":1},"c":{"b":2}}`, ""},
		{`[{"a":1},{"a":2}]`, ""},
		{`{"a":[1,2],"b":{"a":3}}`, ""},
		{`{"n":1e3,"m":8.0,"n2":1.50}`, ""},
		{`{"p":"a\"b","p":1}`, `"p"`},
		{`{"k":1,"k":2,"j":3,"j":4}`, `"k"`},
		{`{"a":"x,\"b\":1","b":1,"b":2}`, `"b"`},
	} {
		got, dup := DuplicateKeyJSON(c.in)
		if (c.want == "") == dup || got != c.want {
			t.Errorf("DuplicateKeyJSON(%s) = %q, %v; want %q", c.in, got, dup, c.want)
		}
	}
	if _, err := ParseNoDuplicates(`{"a":1,"a":2}`); err == nil || err.Error() != `duplicate key "a"` {
		t.Errorf("ParseNoDuplicates: %v", err)
	}
	if _, err := ParseNoDuplicates(`{"a":1e3}`); err != nil {
		t.Errorf("a number written 1e3 stays accepted: %v", err)
	}
}

func TestVCDisclosureRefusesARepeatedMember(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b64u := base64.RawURLEncoding.EncodeToString
	vcWith := func(disclosureText string) string {
		d := b64u([]byte(disclosureText))
		header := b64u([]byte(`{"alg":"EdDSA","typ":"vc+sd-jwt"}`))
		payload := b64u([]byte(fmt.Sprintf(`{"vc":{"@context":["%s","%s"],"type":["VerifiableCredential","%s"],"credentialSubject":{"id":"did:example:s","passport_id":"p","model_id":"m","operator":"o","hardware_rooted":true,"issued_at":1,"_sd":["%s"]}},"_sd_alg":"sha-256","iss":"did:example:i","sub":"did:example:s"}`,
			VCContext, AgentPassportContext, AgentPassportVCType, vcSha(d))))
		return header + "." + payload + "." + b64u(ed25519.Sign(priv, []byte(header+"."+payload))) + "~" + d + "~"
	}
	for _, ok := range []string{`[8.0,"weights_digest","dd"]`, `[1e3,"weights_digest","dd"]`} {
		r, err := VerifyPassportVC(vcWith(ok), pub, VerifyPassportVCOptions{})
		if err != nil || r["passport"].(map[string]any)["weights_digest"] != "dd" {
			t.Fatalf("%s must verify (the fixture is signed correctly): %v", ok, err)
		}
	}
	if _, err := VerifyPassportVC(vcWith(`["s","weights_digest",{"a":1,"a":2}]`), pub, VerifyPassportVCOptions{}); err == nil || err.Error() != "pca-vc: malformed disclosure" {
		t.Fatalf("a repeated member in a disclosure: %v", err)
	}
}
