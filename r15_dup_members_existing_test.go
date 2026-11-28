package pca

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

// Sites that already refuse a repeated member (the stricter native profile or the lenient parser's own refusal): pinned so that a
// parser that keeps the last duplicate would fail here. Signed fixtures use a key generated in the test.

func TestStripeWebhookBodyRefusesARepeatedMember(t *testing.T) {
	h := NewStripeIssuingWebhook(StripeWebhookOptions{Secret: "whsec_test", NowSec: func() float64 { return 1700000000 }})
	call := func(body string) HTTPReply { return h(body, SignStripePayload(body, "whsec_test", 1700000000)) }
	if r := call(`{"type":"other"}`); r.Status != 200 {
		t.Fatalf("the signed fixture must be accepted: %+v", r)
	}
	if r := call(`{"type":"issuing_authorization.request","type":"other"}`); r.Status != 400 || r.Body != `{"error":"bad_json"}` {
		t.Fatalf("a repeated member: %+v", r)
	}
}

func TestSdJwtPresentRefusesARepeatedIssuerPayloadMember(t *testing.T) {
	b64u := base64.RawURLEncoding.EncodeToString
	sd := func(payload string) string { return b64u([]byte(`{"alg":"EdDSA"}`)) + "." + b64u([]byte(payload)) + ".c2ln~" }
	if _, err := PresentSdJwt(sd(`{"_sd":["x"]}`), nil, nil); err != nil {
		t.Fatalf("the fixture must be readable: %v", err)
	}
	if _, err := PresentSdJwt(sd(`{"_sd":[],"_sd":["x"]}`), nil, nil); err == nil {
		t.Fatal("a repeated _sd member in the issuer payload must be refused")
	}
}

func TestEatRefusesARepeatedHeaderOrPayloadMember(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b64u := base64.RawURLEncoding.EncodeToString
	key := &JOSEKey{Kty: "OKP", Crv: "Ed25519", Ed25519: pub}
	eat := func(header, payload string) string {
		h, p := b64u([]byte(header)), b64u([]byte(payload))
		return h + "." + p + "." + b64u(ed25519.Sign(priv, []byte(h+"."+p)))
	}
	if _, err := EatVerify(eat(`{"alg":"EdDSA","typ":"eat+jwt"}`, `{"iss":"a","iat":1}`), key, nil); err != nil {
		t.Fatalf("the signed fixture must verify: %v", err)
	}
	if _, err := EatVerify(eat(`{"alg":"EdDSA","typ":"eat+jwt"}`, `{"iss":"a","iss":"b","iat":1}`), key, nil); err == nil {
		t.Error("a repeated payload member must be refused")
	}
	if _, err := EatVerify(eat(`{"alg":"EdDSA","alg":"none","typ":"eat+jwt"}`, `{"iss":"a","iat":1}`), key, nil); err == nil {
		t.Error("a repeated header member must be refused")
	}
}
