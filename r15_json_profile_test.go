package pca

import (
	"encoding/base64"
	"strings"
	"testing"
)

// A clientDataJSON with a repeated member is refused as invalid JSON (JSON.parse would keep the last, the authenticator signed over the
// whole text); the rest of the JSON.parse grammar (an exponent, a trailing-zero fraction) is still read.
func TestVerifyAssertionRefusesARepeatedClientDataMember(t *testing.T) {
	zero := float64(0)
	run := func(clientData string) string {
		return VerifyAssertion(Assertion{AuthenticatorData: []byte{0}, ClientDataJSON: []byte(clientData), Signature: []byte{0}},
			WebAuthnExpectations{ExpectedChallenge: "x", RPID: "example.com", Origins: []string{"https://example.com"}, StoredSignCount: &zero}).Reason
	}
	for name, text := range map[string]string{
		"top level":  `{"type":"webauthn.get","type":"webauthn.create"}`,
		"nested":     `{"type":"webauthn.get","payment":{"a":1,"a":2}}`,
		"last empty": `{"type":"webauthn.get","challenge":"x","challenge":""}`,
	} {
		if got := run(text); got != "clientDataJSON is not valid JSON" {
			t.Errorf("%s: reason %q", name, got)
		}
	}
	if got := run(`{"type":"webauthn.get","n":1e3,"m":1.0}`); got == "clientDataJSON is not valid JSON" {
		t.Errorf("the JSON.parse number grammar must still be read, got %q", got)
	}
}

// A key directory with a repeated member is refused, not read with the last one.
func TestWebBotAuthKeyDirectoryRefusesARepeatedMember(t *testing.T) {
	text := `{"keys":[{"kty":"OKP","crv":"Ed25519","x":"nyhMxDazvaOFgheJPwoXUUeByeYzQY0CCEXGg1KRPZg","kid":"ka"}],"keys":[]}`
	if _, err := WebBotAuthParseKeyDirectory(text); err == nil || !strings.Contains(err.Error(), `duplicate key "keys"`) {
		t.Fatalf("a repeated keys member must be refused naming it, got %v", err)
	}
}

// Buffer#toString('utf8') is the WHATWG decoder: one U+FFFD per maximal ill-formed subsequence.
func TestNodeUTF8String(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"abcé€\U0001F600", "abcé€\U0001F600"},
		{"\xff", "�"},
		{"\xe2\x82", "�"},
		{"\xe2\x28\xa1", "�(�"},
		{"\xf0\x9f", "�"},
		{"\xed\xa0\x80", "���"},
		{"a\xc0\xafb", "a��b"},
	} {
		if got := nodeUTF8String([]byte(c.in)); got != c.want {
			t.Errorf("nodeUTF8String(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// A JWS segment with bytes that are not UTF-8: the reference reads the substituted text (so a header with no alg is "header has no
// alg"); the native adds one refusal on top, so such a token never parses at all.
func TestParseJWTInvalidUTF8(t *testing.T) {
	enc := base64.RawURLEncoding.EncodeToString
	tok := func(h, p string) string { return enc([]byte(h)) + "." + enc([]byte(p)) + ".c2ln" }
	if _, err := parseJWT(tok("{\"\xff\":1}", `{"iss":"i"}`), "p"); err == nil || err.Error() != "p: header has no alg" {
		t.Errorf("no alg: %v", err)
	}
	for name, token := range map[string]string{
		"header":  tok("{\"alg\":\"ES256\",\"k\":\"\xff\"}", `{"iss":"i"}`),
		"payload": tok(`{"alg":"ES256"}`, "{\"iss\":\"\xff\"}"),
	} {
		if _, err := parseJWT(token, "p"); err == nil || err.Error() != "p: malformed JSON segment: invalid JSON" {
			t.Errorf("%s with invalid UTF-8: %v", name, err)
		}
	}
	if _, err := parseJWT(tok(`{"alg":"ES256"}`, `{"iss":"i"}`), "p"); err != nil {
		t.Errorf("the fixture without invalid bytes must parse: %v", err)
	}
}
