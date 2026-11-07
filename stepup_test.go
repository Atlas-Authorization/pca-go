package pca

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newStepupKey(t *testing.T) (*PrincipalDeviceKey, string) {
	t.Helper()
	k := NewPrincipalDeviceKey(&MemorySecretStore{})
	pub, err := k.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return k, pub
}

func verifyDeviceSig(t *testing.T, pubB64 string, msg []byte, sigB64 string) bool {
	t.Helper()
	pub, ok := DecodeB64uStrict(pubB64, ed25519.PublicKeySize)
	sig, ok2 := DecodeB64uStrict(sigB64, ed25519.SignatureSize)
	return ok && ok2 && ed25519.Verify(pub, msg, sig)
}

func TestPrincipalDeviceKeyGenerateExportImportSign(t *testing.T) {
	k := NewPrincipalDeviceKey(&MemorySecretStore{})
	if k.Exists() {
		t.Fatal("empty store")
	}
	pub, _ := k.Generate()
	if !k.Exists() {
		t.Fatal("generated")
	}
	secret, _ := k.ExportSecret()
	k2 := NewPrincipalDeviceKey(&MemorySecretStore{})
	if got, err := k2.ImportSecret(secret); err != nil || got != pub {
		t.Fatalf("import: %q %v", got, err)
	}
	msg := []byte("hello")
	sig, _ := k2.Sign(msg)
	if !verifyDeviceSig(t, pub, msg, sig) {
		t.Fatal("signature must verify under the registered public key")
	}
	if _, err := k2.ImportSecret("AAAA"); !IsStepUpKind(err, StepUpInvalidSecret) {
		t.Fatalf("short secret: %v", err)
	}
	if _, err := NewPrincipalDeviceKey(&MemorySecretStore{}).Sign(msg); !IsStepUpKind(err, StepUpNoDeviceKey) {
		t.Fatalf("no key: %v", err)
	}
	if err := k.Delete(); err != nil || k.Exists() {
		t.Fatal("delete")
	}
}

// RFC 8032 test vector 1 (empty message): the signature matches the Ed25519 the server verifies with.
func TestPrincipalDeviceKeyRFC8032Vector1(t *testing.T) {
	seed, _ := hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	k := NewPrincipalDeviceKey(&MemorySecretStore{})
	pub, err := k.ImportSecret(b64.EncodeToString(seed))
	if err != nil {
		t.Fatal(err)
	}
	pk, _ := DecodeB64uStrict(pub, 32)
	if hex.EncodeToString(pk) != "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a" {
		t.Fatalf("public key %x", pk)
	}
	sig, _ := k.Sign(nil)
	sb, _ := DecodeB64uStrict(sig, 64)
	if hex.EncodeToString(sb) != "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b" {
		t.Fatalf("signature %x", sb)
	}
}

func isoMs(ms int64) string { return time.UnixMilli(ms).UTC().Format("2006-01-02T15:04:05.000Z") }

func stepUpClient(t *testing.T, dash, inst *httptest.Server, key *PrincipalDeviceKey) *StepUpClient {
	t.Helper()
	c, err := NewStepUpClient(StepUpClientOptions{DashboardURL: dash.URL, InstanceURL: inst.URL, AccountID: "acc", InstanceID: "ins", Key: key,
		Token: func(context.Context) (string, error) { return "dsk_x", nil }, Now: func() int64 { return 1_800_000_000_000 }})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestStepUpListApproveDeny(t *testing.T) {
	key, pub := newStepupKey(t)
	msg := []byte{1, 2, 3, 250, 251}
	future := isoMs(1_800_000_600_000)
	var listReq, cosignReq, denyReq *http.Request
	var cosignBody, denyBody []byte
	dash := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if strings.HasSuffix(r.URL.Path, "/deny") {
			denyReq, denyBody = r, b
			_, _ = w.Write([]byte("{}"))
			return
		}
		listReq = r
		_, _ = w.Write([]byte(`{"stepups":[{"id":"su_1","grant_ref":"g1","action":{"verb":"pay","resource":"order/1"},"required_t":3,"threshold_message":"` +
			b64.EncodeToString(msg) + `","created_at":"x","expires_at":"` + future + `","status":"pending"},` +
			`{"id":"old","grant_ref":"g","action":{"verb":"v","resource":"r"},"required_t":3,"threshold_message":"AA","created_at":"x","expires_at":"2001-01-01T00:00:00.000Z","status":"pending"}]}`))
	}))
	defer dash.Close()
	inst := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cosignReq = r
		cosignBody, _ = io.ReadAll(r.Body)
		_, _ = w.Write([]byte(`{"status":"approved","allow":true}`))
	}))
	defer inst.Close()
	c := stepUpClient(t, dash, inst, key)

	items, err := c.Pending(context.Background())
	if err != nil || len(items) != 1 || items[0].ID != "su_1" || items[0].ActionVerb != "pay" || items[0].Summary() != "pay on order/1" {
		t.Fatalf("pending: %+v %v", items, err)
	}
	if listReq.Header.Get("Authorization") != "Bearer dsk_x" || listReq.URL.Path != "/v1/dashboard/accounts/acc/instances/ins/pca/stepups" || listReq.URL.Query().Get("status") != "pending" {
		t.Fatalf("list request: %v %v", listReq.Header, listReq.URL)
	}

	res, err := c.Approve(context.Background(), items[0])
	if err != nil || !res.Anchored || res.Status != "approved" || res.HTTPStatus != 200 {
		t.Fatalf("approve: %+v %v", res, err)
	}
	if cosignReq.URL.Path != "/v1/pca/stepups/su_1/cosign" || cosignReq.Header.Get("Authorization") != "" {
		t.Fatalf("cosign request: %v", cosignReq.URL)
	}
	var body map[string]string
	_ = json.Unmarshal(cosignBody, &body)
	if body["role"] != "principal" || body["publicKey"] != pub || !verifyDeviceSig(t, pub, msg, body["sig"]) {
		t.Fatalf("the cosign body must carry the device signature over the exact message: %v", body)
	}

	if err := c.Deny(context.Background(), items[0], "no"); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(denyReq.URL.Path, "/su_1/deny") || string(denyBody) != `{"reason":"no"}` {
		t.Fatalf("deny: %v %s", denyReq.URL, denyBody)
	}
}

func TestStepUpPrincipalMismatchSurfacesGuidance(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		_, _ = w.Write([]byte(`{"errors":[{"code":"forbidden","message":"The share is not from this grant's principal key."}]}`))
	}))
	defer srv.Close()
	key, _ := newStepupKey(t)
	c := stepUpClient(t, srv, srv, key)
	_, err := c.Approve(context.Background(), PendingStepUp{ID: "s", ThresholdMessageB64u: "AAEC"})
	if !IsStepUpKind(err, StepUpPrincipalMismatch) || !strings.Contains(err.Error(), "principal key") {
		t.Fatalf("%v", err)
	}
}

func TestStepUpOtherErrorsAndFailClosed(t *testing.T) {
	status := 409
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`not json`))
	}))
	defer srv.Close()
	key, _ := newStepupKey(t)
	c := stepUpClient(t, srv, srv, key)
	su := PendingStepUp{ID: "s", ThresholdMessageB64u: "AAEC"}
	if _, err := c.Approve(context.Background(), su); !IsStepUpKind(err, StepUpAPI) || err.Error() != "HTTP 409: The request failed." {
		t.Fatalf("%v", err)
	}
	// a threshold message that is not canonical base64url is never signed
	if _, err := c.Approve(context.Background(), PendingStepUp{ID: "s", ThresholdMessageB64u: "a"}); !IsStepUpKind(err, StepUpInvalidThresholdMessage) {
		t.Fatalf("%v", err)
	}
	// an id that could rewrite the request path is refused before any request
	if _, err := c.Approve(context.Background(), PendingStepUp{ID: "../x", ThresholdMessageB64u: "AAEC"}); !IsStepUpKind(err, StepUpInvalidStepUp) {
		t.Fatalf("%v", err)
	}
	if err := c.Deny(context.Background(), PendingStepUp{ID: "a/b"}, ""); !IsStepUpKind(err, StepUpInvalidStepUp) {
		t.Fatalf("%v", err)
	}
	// an unreadable list is a transport error, never an empty list
	status = 200
	if _, err := c.Pending(context.Background()); !IsStepUpKind(err, StepUpTransport) {
		t.Fatalf("%v", err)
	}
	// no key stored: nothing is sent
	empty := NewPrincipalDeviceKey(&MemorySecretStore{})
	c2 := stepUpClient(t, srv, srv, empty)
	if _, err := c2.Approve(context.Background(), su); !IsStepUpKind(err, StepUpNoDeviceKey) {
		t.Fatalf("%v", err)
	}
	// a closed server is a transport error
	srv.Close()
	if _, err := c.Pending(context.Background()); !IsStepUpKind(err, StepUpTransport) {
		t.Fatalf("%v", err)
	}
	if _, err := NewStepUpClient(StepUpClientOptions{DashboardURL: "ftp://x", InstanceURL: "http://x", AccountID: "a", InstanceID: "i", Key: key,
		Token: func(context.Context) (string, error) { return "", nil }}); err == nil {
		t.Fatal("a non-http URL must be refused")
	}
}
