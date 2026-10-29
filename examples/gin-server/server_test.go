package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	pca "github.com/Atlas-Authorization/pca-go"
	"github.com/gin-gonic/gin"
)

// A genuinely valid proof from the shared authorize fixtures: signed for payments.send on payments/acme with
// {"amount":50,"currency":"usd"}, audience payments-rs.
func fixture(t *testing.T) (grant, proof map[string]any, aud string, now int64) {
	t.Helper()
	b, err := os.ReadFile("../../testdata/authorize-fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	d, err := pca.ParseJSON(b)
	if err != nil {
		t.Fatal(err)
	}
	c := d["cases"].([]any)[0].(map[string]any)
	step := c["steps"].([]any)[0].(map[string]any)
	n, _ := d["now"].(interface{ Int64() (int64, error) }).Int64()
	return c["grant"].(map[string]any), step["pcactn"].(map[string]any), d["audience"].(string), n
}

// agentHarness is the client half of provenance by default: the agent harness records where the action came from (here
// straight from the user, principalDirectProvenance) and presents the bundle in the PCA-Provenance header. The server pins
// the harness key (Pin) in ProtectOptions.Authorize.ArgProvenance.
func agentHarness(t *testing.T) (pin pca.ProvMediatorPin, header string) {
	t.Helper()
	rec, err := pca.NewProvenanceRecorder(pca.ProvenanceRecorderOptions{Mediator: "refund-ui", Kid: "k1"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := pca.PrincipalDirectProvenance(rec, pca.Operation{Verb: "payments.send", Resource: "payments/acme", Params: map[string]any{"amount": 50, "currency": "usd"}})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return rec.Pin, base64.RawURLEncoding.EncodeToString(raw)
}

func protect(t *testing.T) (*pca.Protected, map[string]any, string) {
	t.Helper()
	grant, proof, aud, now := fixture(t)
	pin, header := agentHarness(t)
	p := pca.Protect(pca.ProtectOptions{Audience: aud, Grants: []map[string]any{grant}, Operation: operationFor, Now: func() int64 { return now },
		Authorize: &pca.AuthorizeOptions{ArgProvenance: &pca.ArgProvenanceOptions{Mediators: []pca.ProvMediatorPin{pin}}}})
	return p, proof, header
}

func call(t *testing.T, r http.Handler, proof map[string]any, body, provenance string) (int, map[string]any) {
	t.Helper()
	raw, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/refunds", strings.NewReader(body))
	req.Header.Set(pca.PCAHeader, base64.RawURLEncoding.EncodeToString(raw))
	if provenance != "" {
		req.Header.Set(pca.ProvenanceHeader, provenance)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("status %d, body %q: %v", rec.Code, rec.Body.String(), err)
	}
	return rec.Code, out
}

func TestRefundAllowedThenReplayRefusedWithDoc(t *testing.T) {
	gin.SetMode(gin.TestMode)
	p, proof, prov := protect(t)
	r := newRouter(p)
	const body = `{"amount":50,"currency":"usd"}`

	if code, out := call(t, r, proof, body, prov); code != 200 || out["status"] != "done" {
		t.Fatalf("allow: %d %v", code, out)
	}
	code, out := call(t, r, proof, body, prov) // the same proof again
	doc, _ := out["doc"].(string)
	if code != 403 || !strings.HasPrefix(doc, "https://") || !strings.Contains(doc, "refusals.md#replay") {
		t.Fatalf("replay: %d %v", code, out)
	}
}

func TestRefundWithOtherAmountRefused(t *testing.T) {
	gin.SetMode(gin.TestMode)
	p, proof, prov := protect(t)
	r := newRouter(p)
	code, out := call(t, r, proof, `{"amount":5000,"currency":"usd"}`, prov) // the proof was signed for 50
	if _, has := out["doc"].(string); code != 403 || !has {
		t.Fatalf("%d %v", code, out)
	}
}

// Provenance by default: without a bundle the payment is an unlabelled sensitive call, so it escalates (the principal must
// confirm) instead of running.
func TestRefundWithoutProvenanceEscalates(t *testing.T) {
	gin.SetMode(gin.TestMode)
	p, proof, _ := protect(t)
	code, out := call(t, newRouter(p), proof, `{"amount":50,"currency":"usd"}`, "")
	if code != 403 || out["decision"] != "escalate" {
		t.Fatalf("%d %v", code, out)
	}
}
