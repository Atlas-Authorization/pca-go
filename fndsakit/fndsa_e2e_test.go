package fndsakit

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	pca "github.com/Atlas-Authorization/pca-go"
)

// requireLib gates the real-library tests: ATLAS_PCA_LIBFNDSA unset skips, unless ATLAS_PCA_LIBFNDSA_REQUIRED=1 (then it fails).
func requireLib(t *testing.T) {
	t.Helper()
	if os.Getenv("ATLAS_PCA_LIBFNDSA") == "" {
		if os.Getenv("ATLAS_PCA_LIBFNDSA_REQUIRED") == "1" {
			t.Fatal("ATLAS_PCA_LIBFNDSA is not set but ATLAS_PCA_LIBFNDSA_REQUIRED=1")
		}
		t.Skip("ATLAS_PCA_LIBFNDSA not set")
	}
}

// useBackend registers b for this test only and restores the PREVIOUS backend state afterwards (nil registers nothing: no backend).
func useBackend(t *testing.T, b *pca.FalconBackend) {
	t.Helper()
	prev := pca.GetFalconBackend()
	pca.ResetFalconBackend()
	if b != nil {
		if err := pca.SetFalconBackend(b); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _ = pca.SetFalconBackend(prev) })
}

// labelSeed is seed32 = sha256("atlas-pca-conformance/" + label).
func labelSeed(label string) []byte {
	h := sha256.Sum256([]byte("atlas-pca-conformance/" + label))
	return h[:]
}

type pcactnCase struct {
	Name, Alg, Audience string
	Pcactn, Grant, Body map[string]any
	ExpectAllow         bool
	NowEpoch            int64
	KeyLabels           map[string]string
}

func loadPcactnCases(t *testing.T) []pcactnCase {
	t.Helper()
	raw, err := os.ReadFile("testdata/ref-fndsa-pcactn.json")
	if err != nil {
		t.Fatal(err)
	}
	v, err := pca.ParseJSONLenient(raw)
	if err != nil {
		t.Fatal(err)
	}
	var out []pcactnCase
	for _, c := range v.(map[string]any)["cases"].([]any) {
		m := c.(map[string]any)
		pc := pcactnCase{Name: m["name"].(string), Alg: m["alg"].(string), Audience: m["audience"].(string), ExpectAllow: m["expect_allow"].(bool)}
		pc.Pcactn, _ = m["pcactn"].(map[string]any)
		pc.Grant, _ = m["grant"].(map[string]any)
		pc.Body, _ = m["body"].(map[string]any)
		now, err := m["now_epoch"].(json.Number).Int64()
		if err != nil {
			t.Fatal(err)
		}
		pc.NowEpoch = now
		if kl, ok := m["key_labels"].(map[string]any); ok {
			pc.KeyLabels = map[string]string{}
			for k, x := range kl {
				pc.KeyLabels[k] = x.(string)
			}
		}
		out = append(out, pc)
	}
	if len(out) != 12 {
		t.Fatalf("expected 12 fixture cases, got %d", len(out))
	}
	return out
}

func verifyCase(t *testing.T, c pcactnCase) pca.Verdict {
	t.Helper()
	v, err := pca.VerifyPCActnCoreWith(c.Pcactn, c.Grant, c.NowEpoch, c.Audience, pca.VerifyOptions{InsecureSkipPlanRootCheck: true})
	if err != nil {
		t.Fatalf("%s: %v", c.Name, err)
	}
	return v
}

// (a) the agent-side public sign path reproduces the reference's PCActn byte for byte; (b) every fixture case verifies as the reference says.
func TestFnDsaPcactnE2E(t *testing.T) {
	requireLib(t)
	useBackend(t, NewBackend())
	for _, c := range loadPcactnCases(t) {
		if c.Body != nil {
			ed, err := pca.KeyPairFromSeedB64u(base64.RawURLEncoding.EncodeToString(labelSeed(c.KeyLabels["agent_ed25519"])))
			if err != nil {
				t.Fatal(err)
			}
			pq, err := pca.FnDsaKeyPairFromSeed(c.Alg, labelSeed(c.KeyLabels["fndsa_keygen"]), labelSeed(c.KeyLabels["fndsa_sign_seed"]))
			if err != nil {
				t.Fatalf("%s: %v", c.Name, err)
			}
			got, err := pca.SignPCActn(c.Body, ed, &pca.SuiteOpts{Alg: c.Alg, Pq: pq})
			if err != nil {
				t.Fatalf("%s: %v", c.Name, err)
			}
			g, _ := pca.NormalizeJSON(got)
			w, _ := pca.NormalizeJSON(c.Pcactn)
			if !reflect.DeepEqual(g, w) {
				t.Errorf("%s: signed PCActn differs from the reference", c.Name)
			}
		}
		if v := verifyCase(t, c); v.Allow != c.ExpectAllow {
			t.Errorf("%s: allow=%v want %v (%s)", c.Name, v.Allow, c.ExpectAllow, v.Reason)
		}
	}
}

// (c) with no backend registered nothing allows, the valid case says unsupported_suite, and the signer refuses.
func TestFnDsaPcactnNoBackendDenies(t *testing.T) {
	useBackend(t, nil)
	for _, c := range loadPcactnCases(t) {
		v := verifyCase(t, c)
		if v.Allow {
			t.Errorf("%s: allowed with no FN-DSA backend", c.Name)
		}
		if strings.HasSuffix(c.Name, "/valid") && !strings.Contains(v.Reason, pca.UnsupportedSuite) {
			t.Errorf("%s: reason %q is not %s", c.Name, v.Reason, pca.UnsupportedSuite)
		}
		if _, err := pca.FnDsaKeyPairFromSeed(c.Alg, make([]byte, 32), nil); err == nil {
			t.Errorf("%s: a key pair was built with no backend", c.Name)
		}
	}
}

// The fn-dsa cases of the shared producer vectors (keygen, suite_sign, mint_root, delegate, PCActn, escalation answer, revocation epoch).
func TestProducerPqVectorsFnDsa(t *testing.T) {
	requireLib(t)
	useBackend(t, NewBackend())
	raw, err := os.ReadFile("../conformance/producer-pq-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	v, err := pca.ParseJSONLenient(raw)
	if err != nil {
		t.Fatal(err)
	}
	doc := v.(map[string]any)
	ran := 0
	for _, c := range doc["cases"].([]any) {
		cm := c.(map[string]any)
		name := cm["name"].(string)
		if !strings.Contains(name, "fn-dsa") {
			continue
		}
		got, err := pca.ProduceVector(cm["op"].(string), cm["args"].(map[string]any), doc["ed_keys"].(map[string]any), doc["pq_keys"].(map[string]any))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		g, err1 := pca.NormalizeJSON(got)
		w, err2 := pca.NormalizeJSON(cm["expect"])
		if err1 != nil || err2 != nil || !reflect.DeepEqual(g, w) {
			t.Errorf("%s: producer output differs from the reference", name)
		}
		ran++
	}
	if ran < 16 {
		t.Fatalf("only %d fn-dsa producer cases replayed", ran)
	}
	// without a backend the same ops refuse with unsupported_suite
	useBackend(t, nil)
	_, err = pca.ProduceVector("pq_keygen", map[string]any{"family": "fn-dsa-512", "seed": "V7DytJELEwPg9-MysjqYSj9Z9rK5Xk3AH07ng6aI-Do"}, nil, nil)
	if err == nil || !strings.Contains(err.Error(), pca.UnsupportedSuite) {
		t.Fatalf("pq_keygen without a backend: %v", err)
	}
}
