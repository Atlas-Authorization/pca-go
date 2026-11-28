package zkkit

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	pca "github.com/Atlas-Authorization/pca-go"
)

// The core's zk compliance functions with this module as their Groth16 backend: every case of the shared reference corpus whose
// outcome can rest on the pairing (VerifyPolicyVmProof, the four SNARK backends, the verifier hook in SNARK mode) is replayed
// through the public API on the real library and must equal the reference, verdict and assurance label. The core's own test
// replays the whole corpus with the reference's recorded verdicts in place of the library.

func parse(t *testing.T, raw json.RawMessage) any {
	t.Helper()
	if len(raw) == 0 {
		return nil
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func obj(v any) map[string]any { m, _ := v.(map[string]any); return m }

// optsOf reads an options object of the corpus: {"$expectThunk": X} is a function returning X ("throw": one that panics).
func optsOf(raw any) map[string]any {
	m := obj(raw)
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	if x, has := obj(m["expect"])["$expectThunk"]; has {
		out["expect"] = func() any {
			if x == any("throw") {
				panic("thunk")
			}
			return x
		}
	}
	return out
}

func labelOf(target any) any {
	l, ok := pca.AssuranceLabelOf(target)
	if !ok {
		return nil
	}
	out := map[string]any{"level": l.Level}
	if l.Vendor != "" {
		out["vendor"] = l.Vendor
	}
	if l.Ceremony != "" {
		out["ceremony"] = l.Ceremony
	}
	return out
}

var snarkBackends = map[string]func(map[string]any) pca.ZkSnarkBackend{
	"createGroth16SnarkBackend": pca.CreateGroth16SnarkBackend, "createPolicyVmSnarkBackend": pca.CreatePolicyVmSnarkBackend,
	"createPolicyVmSnarkBackendBls12381": pca.CreatePolicyVmSnarkBackendBls12381, "createPolicyVmBoundSnarkBackend": pca.CreatePolicyVmBoundSnarkBackend,
}

var snarkKinds = map[string]string{"groth16": "createGroth16SnarkBackend", "policyvm": "createPolicyVmSnarkBackend",
	"policyvm-bls": "createPolicyVmSnarkBackendBls12381", "policyvm-bound": "createPolicyVmBoundSnarkBackend"}

func TestThePublicApiOnTheRealLibraryMatchesTheReference(t *testing.T) {
	if err := Register(); err != nil {
		t.Fatal(err)
	}
	replayed := map[string]int{}
	for _, c := range corpus(t) {
		fn, _, _ := strings.Cut(c.Name, "/")
		arg := func(i int) any {
			if i < len(c.Args) {
				return parse(t, c.Args[i])
			}
			return nil
		}
		var got any
		var err error
		switch {
		case fn == "verifyPolicyVmProof":
			got, err = pca.VerifyPolicyVmProof(arg(0), optsOf(arg(1)))
		case snarkBackends[fn] != nil:
			b := snarkBackends[fn](optsOf(arg(0)))
			in := obj(arg(1))
			commit := func(k string) string { s, _ := obj(in["publicInputs"])[k].(string); return s }
			var ok bool
			ok, err = b.VerifySnark(pca.ZkSnarkInput{Proof: in["proof"], ActionCommit: commit("action_commit"), PolicyCommit: commit("policy_commit"),
				PlanCommit: commit("plan_commit"), Ctx: obj(in["ctx"])})
			got = map[string]any{"verified": ok, "label": labelOf(b)}
		case fn == "createZkVerifier" && strings.Contains(c.Name, "/snark/"):
			spec := obj(arg(0))
			snark := obj(spec["snark"])
			kind, _ := snark["kind"].(string)
			now, _ := spec["nowMs"].(json.Number)
			nowMs, _ := now.Int64()
			hook, herr := pca.CreateZkVerifier(pca.ZkVerifierOpts{SnarkBackend: snarkBackends[snarkKinds[kind]](obj(snark["opts"])), Now: func() int64 { return nowMs }})
			if herr != nil {
				t.Fatalf("%s: %v", c.Name, herr)
			}
			r := hook.Verify(obj(arg(1)))
			res := map[string]any{"enforced": r.Enforced, "ok": r.OK}
			if r.Reason != "" {
				res["reason"] = r.Reason
			}
			got = map[string]any{"result": res, "label": labelOf(hook)}
		default:
			continue
		}
		replayed[fn]++
		want := parse(t, c.Out)
		if _, throws := obj(want)["$throws"]; throws {
			if err == nil {
				t.Fatalf("%s: the reference refuses, got %v", c.Name, got)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		w, _ := json.Marshal(want)
		g, _ := json.Marshal(got)
		if string(w) != string(g) {
			t.Fatalf("%s: want %s got %s", c.Name, w, g)
		}
	}
	for fn, n := range map[string]int{"verifyPolicyVmProof": 169, "createPolicyVmSnarkBackend": 20, "createPolicyVmSnarkBackendBls12381": 15,
		"createGroth16SnarkBackend": 14, "createPolicyVmBoundSnarkBackend": 7, "createZkVerifier": 8} {
		if replayed[fn] != n {
			t.Fatalf("%s: %d cases replayed, the corpus has %d", fn, replayed[fn], n)
		}
	}
}

// Proving needs the circuit build (the witness program and the proving key, which are large and not in the repository): with
// PCA_ZK_POLICYVM_WASM and PCA_ZK_POLICYVM_ZKEY set, the committed sample witness must prove to exactly the recorded public signals
// and the proof must verify under the bundled key.
func TestProvingTheSampleWitness(t *testing.T) {
	wasm, zkey := os.Getenv("PCA_ZK_POLICYVM_WASM"), os.Getenv("PCA_ZK_POLICYVM_ZKEY")
	if wasm == "" || zkey == "" {
		t.Skip("set PCA_ZK_POLICYVM_WASM and PCA_ZK_POLICYVM_ZKEY to the circuit build")
	}
	if err := Register(); err != nil {
		t.Fatal(err)
	}
	for _, c := range corpus(t) {
		if c.Name != "provePolicyVmCompliance/roundtrip" || len(c.Args) != 1 {
			continue
		}
		env, err := pca.ProvePolicyVmCompliance(obj(parse(t, c.Args[0])), map[string]any{"wasmPath": wasm, "zkeyPath": zkey})
		if err != nil {
			t.Fatal(err)
		}
		w, _ := json.Marshal(obj(parse(t, c.Out))["publicSignals"])
		g, _ := json.Marshal(env["publicSignals"])
		if string(w) != string(g) || env["circuit"] != any("pca-policyvm-v1") {
			t.Fatalf("public signals: want %s got %s", w, g)
		}
		if ok, err := pca.VerifyPolicyVmProof(env, nil); !ok || err != nil {
			t.Fatalf("the proof does not verify under the bundled key: %v %v", ok, err)
		}
		return
	}
	t.Fatal("the corpus has no prover contract case")
}

// Under the reference's rules the library takes the curve the key names, read as snarkjs reads it; the core passes
// pca.Groth16CurveFromKey and maps no names itself. Strict mode needs an explicit curve.
func TestTheCurveIsReadFromTheKey(t *testing.T) {
	if err := Register(); err != nil {
		t.Fatal(err)
	}
	for _, c := range corpus(t) {
		if c.Name != "verifyPolicyVmProof/bn/valid" {
			continue
		}
		env, key := obj(parse(t, c.Args[0])), obj(obj(parse(t, c.Args[1]))["verificationKey"])
		vk, _ := json.Marshal(key)
		proof, _ := json.Marshal(env["proof"])
		signals, _ := json.Marshal(env["publicSignals"])
		if ok, _, err := Verify(pca.Groth16CurveFromKey, false, vk, proof, signals); !ok || err != nil {
			t.Fatalf("the curve from the key: %v %v", ok, err)
		}
		if ok, _, err := Verify(pca.Groth16CurveFromKey, true, vk, proof, signals); ok || err == nil {
			t.Fatalf("strict mode has no curve from the key: %v %v", ok, err)
		}
		if _, err := Prove(pca.Groth16CurveFromKey, []byte{0}, []byte{0}, []byte("{}"), nil); err == nil {
			t.Fatal("proving needs an explicit curve")
		}
		for name, want := range map[string]bool{"BN254": true, "alt_bn128": true, "bn-128": true, "bls12381": false, "bn255": false, "": false} {
			key["curve"] = name
			if ok, err := pca.VerifyPolicyVmProof(env, map[string]any{"verificationKey": key}); ok != want || err != nil {
				t.Fatalf("a key naming its curve %q: %v %v, want %v", name, ok, err, want)
			}
		}
		delete(key, "curve")
		if ok, err := pca.VerifyPolicyVmProof(env, map[string]any{"verificationKey": key}); ok || err != nil {
			t.Fatalf("a key naming no curve: %v %v", ok, err)
		}
		key["curve"] = "BN254" // strict takes the exact snarkjs names only
		if ok, err := pca.VerifyPolicyVmProof(env, map[string]any{"verificationKey": key, "strict": true}); ok || err != nil {
			t.Fatalf("strict with another spelling: %v %v", ok, err)
		}
		return
	}
	t.Fatal("the corpus has no valid BN254 case")
}
