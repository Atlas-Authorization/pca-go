package zkkit

import (
	"compress/gzip"
	"encoding/json"
	"os"
	"strings"
	"testing"

	pca "github.com/Atlas-Authorization/pca-go"
)

// Replay of the verification cases of the shared reference corpus (verifyPolicyVmProof on BN254 and BLS12-381). The corpus holds
// the reference's end-to-end verdicts, which include checks made before the pairing (envelope shape, circuit and system tags,
// context pins and the proof's own protocol and curve tags, which the library does not read); the cases those checks alone decide are not this library's question and are left out (gateOnly). Every other case
// must agree: in the default mode with the reference, in strict mode with the reference except the quirk-* cases, which the
// reference accepts and strict mode refuses.

var gateOnly = []string{"expect-now-wrong", "expect-thunk-throws", "expectRiskHash", "circuit-", "system-", "extra-key", "proof-extra-key", "protocol-plonk", "proof-curve-wrong"}

type zkCase struct {
	Name string            `json:"name"`
	Args []json.RawMessage `json:"args"`
	Out  json.RawMessage   `json:"out"`
}

func corpus(t *testing.T) []zkCase {
	t.Helper()
	f, err := os.Open("../testdata/ref-zk.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Cases []zkCase `json:"cases"`
	}
	if err := json.NewDecoder(z).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	return doc.Cases
}

type zkEnvelope struct {
	Proof         json.RawMessage `json:"proof"`
	PublicSignals json.RawMessage `json:"publicSignals"`
}

type zkOpts struct {
	VerificationKey json.RawMessage `json:"verificationKey"`
}

func present(r json.RawMessage) bool { return len(r) > 0 && string(r) != "null" }

func TestVerifyMatchesTheReference(t *testing.T) {
	if Version() == "" {
		t.Fatal("no library version")
	}
	cases := corpus(t)
	checked := 0
	for prefix, curve := range map[string]string{"verifyPolicyVmProof/bn/": pca.Groth16CurveBn254, "verifyPolicyVmProof/bls/": pca.Groth16CurveBls12381} {
		var defaultKey json.RawMessage
		for _, c := range cases {
			if c.Name == prefix+"valid" && len(c.Args) > 1 {
				var o zkOpts
				if err := json.Unmarshal(c.Args[1], &o); err != nil {
					t.Fatal(err)
				}
				defaultKey = o.VerificationKey
			}
		}
		if !present(defaultKey) {
			t.Fatalf("%svalid carries no verification key", prefix)
		}
		for _, c := range cases {
			if !strings.HasPrefix(c.Name, prefix) || len(c.Args) < 2 {
				continue
			}
			stem := c.Name[len(prefix):]
			var env zkEnvelope
			var o zkOpts
			_ = json.Unmarshal(c.Args[0], &env) // an envelope that is not an object is decided by the gates
			_ = json.Unmarshal(c.Args[1], &o)
			gated := false
			for _, g := range gateOnly {
				gated = gated || strings.HasPrefix(stem, g)
			}
			want := string(c.Out) == "true"
			if !present(env.Proof) || !present(env.PublicSignals) {
				if want {
					t.Fatalf("%s: the reference accepts an envelope without a proof", c.Name)
				}
				continue
			}
			vk := o.VerificationKey
			if !present(vk) {
				vk = defaultKey
			}
			compat, _, errC := Verify(curve, false, vk, env.Proof, env.PublicSignals)
			strict, _, errS := Verify(curve, true, vk, env.Proof, env.PublicSignals)
			if errC != nil || errS != nil {
				t.Fatalf("%s: the library failed instead of deciding: %v %v", c.Name, errC, errS)
			}
			switch {
			case want:
				if !compat {
					t.Fatalf("%s: the reference accepts", c.Name)
				}
				if strict == strings.HasPrefix(stem, "quirk") {
					t.Fatalf("%s: strict mode answered %v", c.Name, strict)
				}
			case gated:
				continue
			default:
				if compat || strict {
					t.Fatalf("%s: must be refused in both modes (compat %v, strict %v)", c.Name, compat, strict)
				}
			}
			checked++
		}
	}
	if checked <= 120 {
		t.Fatalf("only %d cases replayed", checked)
	}
}

func TestRefusalsAndTheCoreSeam(t *testing.T) {
	if _, _, err := Verify("p-256", false, []byte("{}"), []byte("{}"), []byte("[]")); err == nil {
		t.Fatal("an unknown curve must be an error")
	}
	if _, _, err := Verify(pca.Groth16CurveBn254, false, nil, []byte("{}"), []byte("[]")); err == nil {
		t.Fatal("a missing key must be an error")
	}
	if ok, reason, err := Verify(pca.Groth16CurveBn254, false, []byte("not json"), []byte("{}"), []byte("[]")); ok || reason == "" || err != nil {
		t.Fatalf("garbage is invalid with a reason: %v %q %v", ok, reason, err)
	}
	if _, err := Prove(pca.Groth16CurveBn254, []byte{0}, []byte{0}, []byte("{}"), []byte{1, 2, 3}); err == nil {
		t.Fatal("a short seed must be refused")
	}
	if _, err := Prove(pca.Groth16CurveBn254, []byte("not wasm"), []byte("not a zkey"), []byte("{}"), nil); err == nil {
		t.Fatal("garbage artifacts must not prove")
	}
	if err := Register(); err != nil || !pca.IsGroth16BackendActive() {
		t.Fatalf("register: %v", err)
	}
	for _, c := range corpus(t) {
		if c.Name != "verifyPolicyVmProof/bn/valid" {
			continue
		}
		var env, key map[string]any
		if json.Unmarshal(c.Args[0], &env) != nil || json.Unmarshal(c.Args[1], &key) != nil {
			t.Fatal("the valid case does not parse")
		}
		ok, _, err := pca.Groth16Verify(pca.Groth16CurveBn254, key["verificationKey"], env["proof"], env["publicSignals"], false)
		if !ok || err != nil {
			t.Fatalf("the valid proof through the core seam: %v %v", ok, err)
		}
		signals := env["publicSignals"].([]any)
		signals[0] = "2"
		if ok, reason, err := pca.Groth16Verify(pca.Groth16CurveBn254, key["verificationKey"], env["proof"], signals, false); ok || reason == "" || err != nil {
			t.Fatalf("a changed public signal must not verify: %v %q %v", ok, reason, err)
		}
		return
	}
	t.Fatal("the corpus has no valid BN254 case")
}
