package pca

// The zk compliance module against the shared reference corpus (ref-zk.json.gz, 1429 cases): every function, every case, by JSON
// value. The pairing itself lives behind the Groth16 backend seam (the zkkit module replays the pairing cases on the real
// library), so here the backend is a recording of the reference: for each case it answers with the verdict the corpus records for
// that case, and notes that it was asked. Every outcome must then equal the corpus; a proof the reference accepts must have asked
// the backend, and a case the reference refuses in front of the pairing must be refused without asking it. A backend that says
// yes to everything cannot pass.

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const zkCorpus = "ref-zk.json.gz"

// zkRecorded answers the pairing question with the reference's verdict of the case being replayed.
type zkRecorded struct {
	reached, verdict bool
	proved           map[string]string // the circuit input the prover was handed
	proof            any
	signals          any
}

func (s *zkRecorded) backend() *Groth16Backend {
	return &Groth16Backend{
		Verify: func(curve string, strict bool, vkey, proof, signals []byte) (bool, string, error) {
			s.reached = true
			if s.verdict {
				return true, "", nil
			}
			return false, "pairing_failed", nil
		},
		Prove: func(curve string, wasm, zkey, input, seed []byte) ([]byte, error) {
			if curve != Groth16CurveBn254 || string(wasm) != "wasm" || string(zkey) != "zkey" || seed != nil {
				return nil, errors.New("unexpected prover call")
			}
			s.proved = nil
			if err := json.Unmarshal(input, &s.proved); err != nil {
				return nil, err
			}
			return json.Marshal(map[string]any{"proof": s.proof, "publicSignals": s.signals})
		},
	}
}

// zkUseBackend installs b (nil: none) for the test and restores the previous backend afterwards.
func zkUseBackend(t *testing.T, b *Groth16Backend) {
	t.Helper()
	prev := GetGroth16Backend()
	set := func(x *Groth16Backend) {
		groth16Mu.Lock()
		groth16Current = x
		groth16Mu.Unlock()
	}
	set(b)
	t.Cleanup(func() { set(prev) })
}

// zkRevive applies the corpus conventions: {"$bigint"} is that integer, {"$num"} that double, {"$bytes": {"$seed": label}} the
// 32-byte key sha256("atlas-pca-conformance/" + label).
func zkRevive(v any) any {
	switch t := v.(type) {
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = zkRevive(x)
		}
		return out
	case map[string]any:
		if len(t) == 1 {
			if s, ok := t["$bigint"].(string); ok {
				b, _ := new(big.Int).SetString(s, 10)
				return b
			}
			switch s, _ := t["$num"].(string); s {
			case "NaN":
				return math.NaN()
			case "Infinity":
				return math.Inf(1)
			case "-Infinity":
				return math.Inf(-1)
			}
			if label, ok := vecObj(t["$bytes"])["$seed"].(string); ok {
				d := sha256.Sum256([]byte("atlas-pca-conformance/" + label))
				return d[:]
			}
		}
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[k] = zkRevive(x)
		}
		recordKeyOrder(out, jsKeys(t))
		return out
	}
	return v
}

// zkExpectOf: {"$expectThunk": X} is a function returning X as written ("throw": one that panics); anything else is the pins.
func zkExpectOf(e any, revive bool) any {
	if x, has := vecObj(e)["$expectThunk"]; has {
		if x == any("throw") {
			return func() any { panic("thunk") }
		}
		return func() any { return x }
	}
	if revive {
		return zkRevive(e)
	}
	return e
}

// zkOptsOf revives an options object; null options are no options.
func zkOptsOf(raw any) map[string]any {
	m := vecObj(raw)
	if m == nil {
		return nil
	}
	o, _ := zkRevive(m).(map[string]any)
	if e, has := m["expect"]; has {
		o["expect"] = zkExpectOf(e, true)
	}
	return o
}

// zkQuantArgs is the options argument of a quantizer case: not given when the case has none, else the options as written, where
// null options are an explicit nil (which the reference, and so the API, refuses).
func zkQuantArgs(a []any) []map[string]any {
	if len(a) < 2 {
		return nil
	}
	o, _ := zkRevive(a[1]).(map[string]any)
	return []map[string]any{o}
}

// zkBigs is the corpus form of quantized fields: {"$bigint": decimal} each.
func zkBigs(xs []uint64) []any {
	out := make([]any, len(xs))
	for i, x := range xs {
		out[i] = map[string]any{"$bigint": strconv.FormatUint(x, 10)}
	}
	return out
}

func zkLabelJSON(target any) any {
	l, ok := AssuranceLabelOf(target)
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

func zkBackendCase(mk func(map[string]any) ZkSnarkBackend, a []any) (any, error) {
	b := mk(zkOptsOf(vecArg(a, 0)))
	in := vecObj(vecArg(a, 1))
	pi := vecObj(in["publicInputs"])
	ok, err := b.VerifySnark(ZkSnarkInput{Proof: in["proof"], ActionCommit: vecStr(pi, "action_commit"), PolicyCommit: vecStr(pi, "policy_commit"),
		PlanCommit: vecStr(pi, "plan_commit"), Ctx: vecObj(in["ctx"])})
	if err != nil {
		return nil, err
	}
	return map[string]any{"verified": ok, "label": zkLabelJSON(b)}, nil
}

var zkSnarkKinds = map[string]func(map[string]any) ZkSnarkBackend{"groth16": CreateGroth16SnarkBackend, "policyvm": CreatePolicyVmSnarkBackend,
	"policyvm-bls": CreatePolicyVmSnarkBackendBls12381, "policyvm-bound": CreatePolicyVmBoundSnarkBackend}

func zkVerifierCase(a []any) (any, error) {
	s, _ := zkRevive(vecArg(a, 0)).(map[string]any)
	o := ZkVerifierOpts{TrustedProverKeys: vecStrs(s, "trustedProverKeys"), PolicyCommitments: vecStrs(s, "policyCommitments"),
		RevokedProverKeys: vecStrs(s, "revokedProverKeys")}
	o.ClockSkewMs, _ = jsNum(s["clockSkewMs"])
	now, _ := baseI64(s["nowMs"])
	o.Now = func() int64 { return now }
	if sn := vecObj(s["snark"]); sn != nil {
		o.SnarkBackend = zkSnarkKinds[vecStr(sn, "kind")](vecObj(sn["opts"]))
	}
	hook, err := CreateZkVerifier(o)
	if err != nil {
		return nil, err
	}
	r := hook.Verify(vecObj(vecArg(a, 1)))
	res := map[string]any{"enforced": r.Enforced, "ok": r.OK}
	if r.Reason != "" {
		// the text after the fail-closed prefix is the engine's own and is not compared
		const p = "zk verification error (fail closed)"
		if i := strings.Index(r.Reason, p+": "); i >= 0 {
			r.Reason = r.Reason[:i+len(p)]
		}
		res["reason"] = r.Reason
	}
	return map[string]any{"result": res, "label": zkLabelJSON(hook)}, nil
}

func zkConstants() map[string]any {
	return map[string]any{
		"ZK_PROVER_BINDING_REF": ZkProverBindingRef, "POLICYVM_PUBLIC_SIGNAL": PolicyVmPublicSignal, "POLICYVM_PUBLIC_SIGNAL_COUNT": PolicyVmPublicSignalCount,
		"POLICYVM_BOUND_PUBLIC_SIGNAL": PolicyVmBoundPublicSignal, "POLICYVM_BOUND_PUBLIC_SIGNAL_COUNT": PolicyVmBoundPublicSignalCount,
		"POLICYVM_BOUND_RISK_FIELDS": PolicyVmBoundRiskFields, "POLICYVM_REVERSIBILITY_ORDER": PolicyVmReversibilityOrder,
		"paths": map[string]any{"DEFAULT_VKEY_PATH": ZkDefaultVkeyPath, "DEFAULT_WASM_PATH": ZkDefaultWasmPath, "DEFAULT_ZKEY_PATH": ZkDefaultZkeyPath,
			"POLICYVM_VKEY_PATH": PolicyVmVkeyPath, "POLICYVM_SAMPLE_PROOF_PATH": PolicyVmSampleProofPath, "POLICYVM_WASM_PATH": PolicyVmWasmPath,
			"POLICYVM_ZKEY_PATH": PolicyVmZkeyPath, "POLICYVM_BLS12381_VKEY_PATH": PolicyVmBls12381VkeyPath,
			"POLICYVM_BLS12381_SAMPLE_PROOF_PATH": PolicyVmBls12381SampleProofPath, "POLICYVM_BOUND_VKEY_PATH": PolicyVmBoundVkeyPath,
			"POLICYVM_BOUND_SAMPLE_PROOF_PATH": PolicyVmBoundSampleProofPath, "POLICYVM_BOUND_WASM_PATH": PolicyVmBoundWasmPath,
			"POLICYVM_BOUND_ZKEY_PATH": PolicyVmBoundZkeyPath},
	}
}

// zkEmpty turns the "" of a check that found nothing into the reference's null.
func zkEmpty(s string, err error) (any, error) {
	if s == "" || err != nil {
		return nil, err
	}
	return s, nil
}

// zkPureFns are the functions that never ask the pairing question.
func zkPureFns() map[string]vecFn {
	str := func(a []any, i int) (string, error) {
		s, ok := vecArg(a, i).(string)
		if !ok {
			return "", errors.New("not a string")
		}
		return s, nil
	}
	quant := func(f func(any, ...map[string]any) ([]uint64, error)) vecFn {
		return func(a []any) (any, error) {
			q, err := f(zkRevive(vecArg(a, 0)), zkQuantArgs(a)...)
			return zkBigs(q), err
		}
	}
	return map[string]vecFn{
		"constants": func(a []any) (any, error) { return zkConstants(), nil },
		"commitmentField": func(a []any) (any, error) {
			s, err := str(a, 0)
			if err != nil {
				return nil, err
			}
			return CommitmentField(s)
		},
		"policyCommitment":       func(a []any) (any, error) { return PolicyCommitment(vecArg(a, 0)) },
		"pinnedPolicyCommitment": func(a []any) (any, error) { return PinnedPolicyCommitment(vecArg(a, 0)) },
		"actionCommitment":       func(a []any) (any, error) { return ActionCommitment(vecArg(a, 0)) },
		"proverKeyBinding": func(a []any) (any, error) {
			pub, _ := str(a, 0)
			nonce, _ := str(a, 2)
			b := ProverKeyBinding(pub, jsF(vecArg(a, 1)), nonce)
			return map[string]any{"holderPub": b.HolderPub, "grantRef": b.GrantRef, "epoch": jsNumber(b.Epoch), "nonce": b.Nonce}, nil
		},
		"policyVmStructHash":   func(a []any) (any, error) { return PolicyVmStructHash(zkRevive(vecArg(a, 0))) },
		"policyVmRiskHash":     func(a []any) (any, error) { return PolicyVmRiskHash(zkRevive(vecArg(a, 0))) },
		"quantizeActionStruct": quant(QuantizeActionStruct),
		"quantizePlanStruct":   quant(QuantizePlanStruct),
		"quantizePolicyStruct": quant(QuantizePolicyStruct),
		"policyVmCommitmentFromAction": func(a []any) (any, error) {
			return PolicyVmCommitmentFromAction(zkRevive(vecArg(a, 0)), zkQuantArgs(a)...)
		},
		"quantizePolicyVmInputs": func(a []any) (any, error) {
			q, err := QuantizePolicyVmInputs(zkRevive(vecArg(a, 0)), zkQuantArgs(a)...)
			if err != nil {
				return nil, err
			}
			out := map[string]any{"action": zkBigs(q.Action)}
			if q.Plan != nil {
				out["plan"] = zkBigs(q.Plan)
			}
			if q.Policy != nil {
				out["policy"] = zkBigs(q.Policy)
			}
			return out, nil
		},
		"decodePolicyVmPublic":      func(a []any) (any, error) { return DecodePolicyVmPublic(vecArg(a, 0)) },
		"decodePolicyVmBoundPublic": func(a []any) (any, error) { return DecodePolicyVmBoundPublic(vecArg(a, 0)) },
		"policyVmContextMatches": func(a []any) (any, error) { // this function's cases carry their pins as written
			bound := vecArg(a, 2) == any("bound")
			if vecArg(a, 1) == any("$absent") {
				return PolicyVmContextMatches(vecArg(a, 0), bound)
			}
			return PolicyVmContextMatches(vecArg(a, 0), bound, zkExpectOf(vecArg(a, 1), false))
		},
		"isCanonicalGroth16Envelope": func(a []any) (any, error) {
			curve, _ := vecArg(a, 1).(string)
			return IsCanonicalGroth16Envelope(vecArg(a, 0), curve), nil
		},
		"circuitVersion": func(a []any) (any, error) {
			id, err := str(a, 0)
			if err != nil {
				return nil, err
			}
			return CircuitVersion(id)
		},
		"vkId":              func(a []any) (any, error) { return VkID(vecArg(a, 0)) },
		"circuitProvenance": func(a []any) (any, error) { return CircuitProvenance(vecObj(vecArg(a, 0))) },
		"checkCircuitProvenance": func(a []any) (any, error) {
			return zkEmpty(CheckCircuitProvenance(vecArg(a, 0), vecObj(vecArg(a, 1))))
		},
		"transcriptSha256": func(a []any) (any, error) { return TranscriptSha256(vecArg(a, 0)) },
		"checkTranscript":  func(a []any) (any, error) { return zkEmpty(CheckTranscript(vecArg(a, 0), vecObj(vecArg(a, 1))), nil) },
		"ceremonyOf":       func(a []any) (any, error) { return CeremonyOf(vecArg(a, 0), vecArg(a, 1)), nil },
		"createAttestedComplianceProver": func(a []any) (any, error) {
			seed, _ := zkRevive(vecArg(a, 0)).([]byte)
			p, err := CreateAttestedComplianceProver(seed)
			if err != nil {
				return nil, err
			}
			o := vecObj(vecArg(a, 1))
			issued, _ := baseI64(o["issued_at"])
			expires, _ := baseI64(o["expires_at"])
			st, err := p.Prove(ZkProveOpts{PCActn: vecObj(o["pcactn"]), DecideInput: vecObj(o["decideInput"]), IssuedAt: issued, ExpiresAt: expires})
			if err != nil {
				return nil, err
			}
			return map[string]any{"publicKey": p.PublicKey, "statement": st}, nil
		},
	}
}

// zkEngineFns are the functions whose accepted outcome rests on the pairing; each maps a reference result to its verdict.
var zkEngineFns = map[string]func(out any) bool{
	"verifyPolicyVmProof":                func(out any) bool { return out == any(true) },
	"createPolicyVmSnarkBackend":         func(out any) bool { return vecObj(out)["verified"] == any(true) },
	"createPolicyVmSnarkBackendBls12381": func(out any) bool { return vecObj(out)["verified"] == any(true) },
	"createGroth16SnarkBackend":          func(out any) bool { return vecObj(out)["verified"] == any(true) },
	"createPolicyVmBoundSnarkBackend":    func(out any) bool { return vecObj(out)["verified"] == any(true) },
	"createZkVerifier":                   func(out any) bool { return vecObj(vecObj(out)["result"])["ok"] == any(true) },
}

// zkGateOnly: cases the reference refuses in front of the pairing, by the stem of the case name.
var zkGateOnly = []string{"expect-now-wrong", "expect-thunk-throws", "expectRiskHash", "circuit-", "system-", "extra-key", "proof-extra-key", "signal-count-",
	"allow-0", "signal-noncanonical", "signal-plus-order", "pi_a.x-hex", "pi_a.x+p", "pi_a.x-leading-zero", "pi_a.z-0", "pi_a-infinity", "pi_a-affine-2", "pi_b-short",
	"proof-null", "proof-missing", "proof-string", "protocol-plonk", "proof-curve-wrong", "shape-", "risk-hash-mismatch", "risk-hash-half", "bls-not-allowed",
	"15-signals", "now-out-of-range", "context-pin", "action-hash-wrong", "policy-hash-wrong", "plan-hash-wrong", "other-circuit", "signals-not-array",
	"policy-tag-mismatch", "plan-tag-mismatch", "action-tag-mismatch", "wrong-system", "wrong-circuit", "signals-6", "signals-8", "null", "noncanonical-signal",
	"risk-wrong", "action-wrong", "v1-circuit", "signals-missing", "no-proof", "groth16-compliance-garbage"}

func zkIsGateOnly(name string) bool {
	stem := name[strings.LastIndex(name, "/")+1:]
	for _, g := range zkGateOnly {
		if strings.HasPrefix(stem, g) {
			return true
		}
	}
	return false
}

func TestZkMatchesTheReference(t *testing.T) {
	stub := &zkRecorded{}
	zkUseBackend(t, stub.backend())
	dir := t.TempDir()
	wasm, zkey := filepath.Join(dir, "c.wasm"), filepath.Join(dir, "c.zkey")
	if os.WriteFile(wasm, []byte("wasm"), 0o600) != nil || os.WriteFile(zkey, []byte("zkey"), 0o600) != nil {
		t.Fatal("cannot write the stand-in prover artifacts")
	}
	var cur *baseCase
	var sample map[string]any // the committed BN254 sample proof, from its verification case

	fns := zkPureFns()
	fns["verifyPolicyVmProof"] = func(a []any) (any, error) { return VerifyPolicyVmProof(vecArg(a, 0), zkOptsOf(vecArg(a, 1))) }
	fns["createPolicyVmSnarkBackend"] = func(a []any) (any, error) { return zkBackendCase(CreatePolicyVmSnarkBackend, a) }
	fns["createPolicyVmSnarkBackendBls12381"] = func(a []any) (any, error) { return zkBackendCase(CreatePolicyVmSnarkBackendBls12381, a) }
	fns["createGroth16SnarkBackend"] = func(a []any) (any, error) { return zkBackendCase(CreateGroth16SnarkBackend, a) }
	fns["createPolicyVmBoundSnarkBackend"] = func(a []any) (any, error) { return zkBackendCase(CreatePolicyVmBoundSnarkBackend, a) }
	fns["createZkVerifier"] = zkVerifierCase
	// The one prover case is a contract, not an output (a proof carries fresh randomness and the proving key is not in the
	// repository): proving the committed sample witness must hand the circuit exactly that witness as decimal strings, wrap the
	// prover's result in the v1 envelope with the recorded public signals, and the result must verify under the bundled key.
	fns["provePolicyVmCompliance"] = func(a []any) (any, error) {
		witness := vecObj(vecArg(a, 0))
		if sample == nil || len(witness) == 0 {
			return nil, errors.New("the sample proof or the sample witness is missing from the corpus")
		}
		stub.proof, stub.signals = sample["proof"], vecObj(cur.Out)["publicSignals"]
		env, err := ProvePolicyVmCompliance(witness, map[string]any{"wasmPath": wasm, "zkeyPath": zkey})
		if err != nil {
			return nil, err
		}
		if len(stub.proved) != len(witness) {
			return nil, errors.New("the circuit input is not the witness")
		}
		for k, v := range witness {
			if stub.proved[k] != jsValueString(v) {
				return nil, errors.New("witness member " + k + " reached the circuit as " + stub.proved[k])
			}
		}
		out := map[string]any{"publicSignals": env["publicSignals"], "sampleProofCircuit": env["circuit"]}
		stub.verdict = true
		if ok, err := VerifyPolicyVmProof(env, nil); ok && err == nil && stub.reached && zkIs(env["system"], "groth16-bn254") {
			out["verifiesUnder"] = "VK_BN"
		}
		return out, nil
	}

	var k baseTally
	refusedByPairing := 0
	n := baseEachOrdered(t, zkCorpus, func(c *baseCase) {
		f, ok := fns[c.Fn]
		if !ok {
			k.fail(c, "no Go entry point for %s", c.Fn)
			return
		}
		k.run(c.Fn)
		if c.Name == "verifyPolicyVmProof/bn/valid" {
			sample = vecObj(vecArg(c.Args, 0))
		}
		throws, _ := baseThrows(c.Out)
		verdictOf, engine := zkEngineFns[c.Fn]
		accepted := engine && !throws && verdictOf(c.Out)
		cur, stub.reached, stub.verdict = c, false, accepted
		var got any
		var err error
		if p := baseCall(func() { got, err = f(c.Args) }); p != "" {
			k.fail(c, "panic: %s", p)
			return
		}
		switch {
		case throws && err == nil:
			k.fail(c, "reference refuses (%v), Go returned %s", c.Out, baseCanon(vecJSON(got)))
			return
		case throws:
			return
		case err != nil:
			k.fail(c, "Go refuses (%v), reference returned %s", err, baseCanon(c.Out))
			return
		}
		if w, g := baseCanon(c.Out), baseCanon(vecJSON(got)); w != g {
			k.fail(c, "want %s got %s (pairing reached: %v)", w, g, stub.reached)
			return
		}
		if !engine {
			return
		}
		// an attested-VM statement is accepted without any proof system; every other acceptance must have asked the backend
		proofCase := c.Fn != "createZkVerifier" || strings.Contains(c.Name, "/snark/")
		if proofCase && accepted && !stub.reached {
			k.fail(c, "accepted without a pairing check")
		}
		if !accepted && stub.reached {
			if zkIsGateOnly(c.Name) {
				k.fail(c, "the reference refuses this in front of the pairing, here the pairing was reached")
			}
			refusedByPairing++
		}
	})
	k.finish(t)
	if n != 1429 {
		t.Fatalf("%d cases replayed, the corpus has 1429", n)
	}
	if refusedByPairing <= 40 {
		t.Fatalf("only %d refusals came from the pairing", refusedByPairing)
	}
}

// zkVerifyCases calls f for every verifyPolicyVmProof case.
func zkVerifyCases(t *testing.T, f func(c *baseCase)) {
	t.Helper()
	baseEachOrdered(t, zkCorpus, func(c *baseCase) {
		if c.Fn == "verifyPolicyVmProof" {
			f(c)
		}
	})
}

func TestZkABackendThatAcceptsEverythingDoesNotChangeARefusalInFrontOfThePairing(t *testing.T) {
	asked := 0
	zkUseBackend(t, &Groth16Backend{Verify: func(string, bool, []byte, []byte, []byte) (bool, string, error) { asked++; return true, "", nil }})
	refused := 0
	zkVerifyCases(t, func(c *baseCase) {
		if !zkIsGateOnly(c.Name) || c.Out != any(false) {
			return
		}
		if ok, err := VerifyPolicyVmProof(vecArg(c.Args, 0), zkOptsOf(vecArg(c.Args, 1))); ok || err != nil {
			t.Fatalf("%s: %v %v", c.Name, ok, err)
		}
		refused++
	})
	if refused <= 40 || asked != 0 {
		t.Fatalf("%d gate refusals replayed, the backend was asked %d times", refused, asked)
	}
}

func TestZkWithoutABackendNothingIsReportedValidOrInvalid(t *testing.T) {
	zkUseBackend(t, nil)
	seen := false
	zkVerifyCases(t, func(c *baseCase) {
		if c.Name != "verifyPolicyVmProof/bn/valid" {
			return
		}
		seen = true
		env := vecObj(vecArg(c.Args, 0))
		if ok, err := VerifyPolicyVmProof(env, zkOptsOf(vecArg(c.Args, 1))); ok || !errors.Is(err, ErrGroth16BackendMissing) {
			t.Fatalf("a valid proof without a backend: %v %v", ok, err)
		}
		b := CreatePolicyVmSnarkBackend(nil)
		if ok, err := b.VerifySnark(ZkSnarkInput{Proof: env}); ok || !errors.Is(err, ErrGroth16BackendMissing) {
			t.Fatalf("the backend without an engine: %v %v", ok, err)
		}
		// through the hook the fault is a denial that says so, never an acceptance
		hook, err := CreateZkVerifier(ZkVerifierOpts{SnarkBackend: b})
		if err != nil {
			t.Fatal(err)
		}
		r := hook.Verify(map[string]any{"pcactn": map[string]any{"zk_compliance": env}})
		if r.OK || !r.Enforced || !strings.HasPrefix(r.Reason, "zk verification error (fail closed): ") {
			t.Fatalf("the hook without an engine: %+v", r)
		}
		if _, err := ProvePolicyVmCompliance(map[string]any{"a": "1"}, nil); !errors.Is(err, ErrGroth16BackendMissing) {
			t.Fatalf("proving without a backend: %v", err)
		}
	})
	if !seen {
		t.Fatal("the corpus has no valid BN254 case")
	}
	// a refusal in front of the pairing needs no backend
	if ok, err := VerifyPolicyVmProof(map[string]any{}, nil); ok || err != nil {
		t.Fatalf("an empty envelope: %v %v", ok, err)
	}
}

// zkHardware is a hardware attestation verifier with a label, answering with a fixed result.
type zkHardware struct {
	label AssuranceLabel
	res   HardwareResult
	doc   map[string]any
	now   int64
	bind  ExpectedAttestationBinding
}

func (h *zkHardware) Assurance() AssuranceLabel { return h.label }

func (h *zkHardware) VerifyHardware(doc, ctx map[string]any, nowMs int64, expected ExpectedAttestationBinding) HardwareResult {
	h.doc, h.now, h.bind = doc, nowMs, expected
	return h.res
}

func TestZkProverKeyBoundToHardware(t *testing.T) {
	seed := sha256.Sum256([]byte("zk hardware-bound prover"))
	prover, err := CreateAttestedComplianceProver(seed[:])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CreateAttestedComplianceProver(seed[:31]); err == nil {
		t.Fatal("a short secret must be refused")
	}
	// a statement signed by the prover key for a fixed action, built by hand (the Policy VM is exercised by the corpus replay)
	pcactn := map[string]any{"action": map[string]any{"verb": "read", "resource": "doc:1"}, "plan": map[string]any{"root": "plan-root"}}
	grant := map[string]any{"id": "grant-1"}
	actionCommit, _ := ActionCommitment(pcactn)
	st := map[string]any{"v": json.Number("1"), "mode": "attested-vm", "action_commit": actionCommit, "policy_commit": "grant-1", "plan_commit": "plan-root",
		"released": true, "r": json.Number("0"), "issued_at": json.Number("1000"), "expires_at": json.Number("2000"), "prover": prover.PublicKey}
	msg, err := zkStatementMessage(st)
	if err != nil {
		t.Fatal(err)
	}
	st["sig"] = B64u(prover.key.Sign(msg))
	pcactn["zk_compliance"] = st
	ctx := map[string]any{"pcactn": pcactn, "grant": grant}

	good := HardwareResult{OK: true, Bound: true, Measured: map[string]any{"runtime_measurement": "image-1"}}
	hw := &zkHardware{label: AssuranceLabel{Level: "hardware", Vendor: "amd-sev-snp"}, res: good}
	binding := func(pub string) (ExpectedAttestationBinding, error) { return ProverKeyBinding(pub, 7, "nonce-1"), nil }
	opts := func() ZkVerifierOpts {
		return ZkVerifierOpts{TrustedProverKeys: []string{prover.PublicKey}, Now: func() int64 { return 1500 },
			ProverAttestation: &ZkProverAttestationOpts{HardwareVerifier: hw, ExpectedBinding: binding, Measurements: []string{"image-1"}}}
	}

	// construction: the hardware verifier must be labelled hardware or multi_root, the allowlist non-empty, the binding given
	for name, edit := range map[string]func(pa *ZkProverAttestationOpts){
		"software verifier": func(pa *ZkProverAttestationOpts) {
			pa.HardwareVerifier = &zkHardware{label: AssuranceLabel{Level: "software"}}
		},
		"unlabelled verifier": func(pa *ZkProverAttestationOpts) { pa.HardwareVerifier = AttestationHardwareFunc(hw.VerifyHardware) },
		"no measurements":     func(pa *ZkProverAttestationOpts) { pa.Measurements = nil },
		"empty measurement":   func(pa *ZkProverAttestationOpts) { pa.Measurements = []string{"image-1", ""} },
		"no binding":          func(pa *ZkProverAttestationOpts) { pa.ExpectedBinding = nil },
	} {
		o := opts()
		edit(o.ProverAttestation)
		if v, err := CreateZkVerifier(o); err == nil || v != nil {
			t.Fatalf("%s: must be refused at construction", name)
		}
	}
	multi := opts()
	multi.ProverAttestation.HardwareVerifier = &zkHardware{label: AssuranceLabel{Level: "multi_root"}, res: good}
	if v, err := CreateZkVerifier(multi); err != nil || v.Assurance() != (AssuranceLabel{Level: "attested_vm_hw", Vendor: "hardware-bound:multi_root"}) {
		t.Fatalf("a multi-root verifier without a vendor is labelled by its level: %v", err)
	}

	o := opts()
	v, err := CreateZkVerifier(o)
	if err != nil {
		t.Fatal(err)
	}
	if v.Assurance() != (AssuranceLabel{Level: "attested_vm_hw", Vendor: "hardware-bound:amd-sev-snp"}) {
		t.Fatalf("label: %+v", v.Assurance())
	}
	// the configuration is a snapshot: later edits by the caller change nothing
	o.TrustedProverKeys[0], o.ProverAttestation.Measurements[0] = "other", "other"
	if r := v.Verify(ctx); !r.OK || !r.Enforced || r.Reason != "" {
		t.Fatalf("a bound, measured, allowlisted prover: %+v", r)
	}
	if hw.now != 1500 || hw.bind != ProverKeyBinding(prover.PublicKey, 7, "nonce-1") || hw.bind.GrantRef != ZkProverBindingRef ||
		hw.doc["attestor"] != any(prover.PublicKey) || hw.doc["mode"] != any("hardware") {
		t.Fatalf("the hardware verifier was asked with %v %v %+v", hw.doc, hw.now, hw.bind)
	}
	for want, res := range map[string]HardwareResult{
		"prover hardware evidence invalid: quote expired":        {Reason: "quote expired", Bound: true, Measured: good.Measured},
		"prover hardware evidence invalid: no reason given":      {Bound: true, Measured: good.Measured},
		"prover hardware evidence does not bind the prover key":  {OK: true, Measured: good.Measured},
		"prover hardware evidence carries no measured identity":  {OK: true, Bound: true},
		"prover hardware evidence carries no measured identity ": {OK: true, Bound: true, Measured: map[string]any{"runtime_measurement": json.Number("5")}},
		"prover VM measurement is not allowlisted":               {OK: true, Bound: true, Measured: map[string]any{"runtime_measurement": "image-2"}},
		"prover VM measurement is not allowlisted ":              {OK: true, Bound: true, Measured: map[string]any{"runtime_measurement": "other"}},
	} {
		hw.res = res
		if r := v.Verify(ctx); r.OK || !r.Enforced || r.Reason != strings.TrimSpace(want) {
			t.Fatalf("want %q, got %+v", want, r)
		}
	}
	hw.res = good

	// a binding that cannot be produced, and a verifier that panics, deny
	failing := opts()
	failing.ProverAttestation.ExpectedBinding = func(string) (ExpectedAttestationBinding, error) {
		return ExpectedAttestationBinding{}, errors.New("no nonce")
	}
	fv, _ := CreateZkVerifier(failing)
	if r := fv.Verify(ctx); r.OK || r.Reason != "zk verification error (fail closed): no nonce" {
		t.Fatalf("a failing binding: %+v", r)
	}
	panicking := opts()
	panicking.ProverAttestation.ExpectedBinding = func(string) (ExpectedAttestationBinding, error) { panic("boom") }
	pv, _ := CreateZkVerifier(panicking)
	if r := pv.Verify(ctx); r.OK || !r.Enforced || r.Reason != "zk verification error (fail closed): boom" {
		t.Fatalf("a panicking binding: %+v", r)
	}

	// the hardware check is last: a statement that fails earlier never reaches the verifier, and SNARK mode ignores it
	hw.doc = nil
	late := opts()
	late.Now = func() int64 { return 2001 }
	lv, _ := CreateZkVerifier(late)
	if r := lv.Verify(ctx); r.Reason != "compliance statement expired" || hw.doc != nil {
		t.Fatalf("an expired statement: %+v, hardware asked: %v", r, hw.doc != nil)
	}
	malformed := map[string]any{}
	for k, x := range st {
		malformed[k] = x
	}
	malformed["expires_at"] = json.Number("999")
	delete(malformed, "sig")
	m2, _ := zkStatementMessage(malformed)
	malformed["sig"] = B64u(prover.key.Sign(m2))
	if r := lv.Verify(map[string]any{"pcactn": map[string]any{"action": pcactn["action"], "plan": pcactn["plan"], "zk_compliance": malformed}, "grant": grant}); r.Reason != "malformed statement validity window" {
		t.Fatalf("a window that ends before it starts: %+v", r)
	}
	snark := opts()
	snark.SnarkBackend = ZkSnarkBackendFunc(func(in ZkSnarkInput) (bool, error) {
		return in.ActionCommit == actionCommit && in.PolicyCommit == "grant-1" && in.PlanCommit == "plan-root" && in.Proof != nil && in.Ctx != nil, nil
	})
	sv, err := CreateZkVerifier(snark)
	if err != nil || sv.Assurance() != (AssuranceLabel{Level: "unknown"}) {
		t.Fatalf("an unlabelled backend is unknown: %+v %v", sv, err)
	}
	if r := sv.Verify(ctx); !r.OK || hw.doc != nil {
		t.Fatalf("SNARK mode: %+v, hardware asked: %v", r, hw.doc != nil)
	}
	// one pinned commitment is the backend's policy input; with none or several it is the grant's
	for pins, want := range map[string]string{"pinned": "pinned", "a,b": "grant-1", "": "grant-1"} {
		var got string
		snark.SnarkBackend = ZkSnarkBackendFunc(func(in ZkSnarkInput) (bool, error) { got = in.PolicyCommit; return false, nil })
		snark.PolicyCommitments = strings.FieldsFunc(pins, func(r rune) bool { return r == ',' })
		if pins == "" {
			snark.PolicyCommitments = []string{}
		}
		pv, _ := CreateZkVerifier(snark)
		if r := pv.Verify(ctx); r.OK || r.Reason != "snark backend rejected the proof" || got != want {
			t.Fatalf("pins %q: backend saw %q, %+v", pins, got, r)
		}
	}
	snark.SnarkBackend = ZkSnarkBackendFunc(func(ZkSnarkInput) (bool, error) { return true, errors.New("engine fault") })
	ev, _ := CreateZkVerifier(snark)
	if r := ev.Verify(ctx); r.OK || r.Reason != "zk verification error (fail closed): engine fault" {
		t.Fatalf("a backend fault is a denial even when it says yes: %+v", r)
	}
	// the default clock is the wall clock: a statement from 1970 is expired
	wall := opts()
	wall.Now = nil
	wv, _ := CreateZkVerifier(wall)
	if r := wv.Verify(ctx); r.Reason != "compliance statement expired" {
		t.Fatalf("the wall clock: %+v", r)
	}
}

// The Go-typed forms of the inputs (Go integers, *big.Int, ZkDigestHalves, clock functions) and the options the corpus cannot
// carry (key files, strict mode).
func TestZkGoTypedInputsAndKeyFiles(t *testing.T) {
	// integers: a uint64, an int, an int64 and a *big.Int are exact; the same fields as numbers hash identically
	top := new(big.Int).SetUint64(math.MaxUint64)
	a, err := PolicyVmStructHash([]uint64{7, 42, 0, math.MaxUint64})
	b, err2 := PolicyVmStructHash([]any{7, int64(42), json.Number("0"), top})
	if err != nil || err2 != nil || a != b || a.Hi == "" || a.Lo == "" {
		t.Fatalf("typed fields: %v %v %v %v", a, b, err, err2)
	}
	if _, err := PolicyVmStructHash([]any{-1}); err == nil {
		t.Fatal("a negative int must be refused")
	}
	if _, err := PolicyVmStructHash([]any{(*big.Int)(nil)}); err == nil {
		t.Fatal("a nil integer must be refused")
	}
	if _, err := PolicyVmStructHash([]any{new(big.Int).Add(top, big.NewInt(1))}); err == nil {
		t.Fatal("2^64 must be refused")
	}
	if _, err := PolicyVmStructHash("x"); err == nil {
		t.Fatal("fields that are not a list must be refused")
	}
	if h, err := PolicyVmRiskHash([]uint64{1, 2, 3, 4, 5}); err != nil || h.Hi != "103793097291623275381652350277434258226" || h.Lo != "278376649621675728137615250140217347045" {
		t.Fatalf("risk hash of typed fields: %v %v", h, err)
	}
	if _, err := PolicyVmRiskHash([]uint64{1, 2, 3, 4}); err == nil {
		t.Fatal("four risk fields must be refused")
	}
	for lit, want := range map[string]int64{"0x1F": 31, "0o17": 15, "0b101": 5, " 12 ": 12, "-7": -7, "+7": 7, "012": 12, "0XfF": 255} {
		if got, err := zkStringToBigInt(lit); err != nil || got.Int64() != want {
			t.Fatalf("integer literal %q: %v %v", lit, got, err)
		}
	}
	for _, lit := range []string{"0x", "0b2", "0o8", "0xg", "-0x1", "1_0", "1e3", "-", "+", "1.0", "७"} {
		if got, err := zkStringToBigInt(lit); err == nil {
			t.Fatalf("integer literal %q must be refused, got %v", lit, got)
		}
	}
	codes := map[string]any{"verbCodes": map[string]any{"read": uint64(7)}, "resourceCodes": map[string]any{"doc:1": 42}, "paramScalarField": "amount"}
	for _, amount := range []any{uint64(100), 100, int64(100), big.NewInt(100), json.Number("100"), "100", float64(100)} {
		q, err := QuantizeActionStruct(map[string]any{"verb": "read", "resource": "doc:1", "params": map[string]any{"amount": amount}}, codes)
		if err != nil || len(q) != 4 || q[0] != 7 || q[1] != 42 || q[2] != 0 || q[3] != 100 {
			t.Fatalf("amount %T: %v %v", amount, q, err)
		}
	}
	for _, amount := range []any{-1, int64(-1), big.NewInt(-1), []any{}, map[string]any{}, false} {
		if q, err := QuantizeActionStruct(map[string]any{"verb": "read", "resource": "doc:1", "params": map[string]any{"amount": amount}}, codes); err == nil {
			t.Fatalf("amount %T %v must be refused, got %v", amount, amount, q)
		}
	}
	if _, err := QuantizeActionStruct(map[string]any{"verb": "read", "resource": "doc:1", "params": []any{json.Number("1")}}, codes); err == nil {
		t.Fatal("params that are not an object must be refused when a scalar is read from them")
	}
	// options: not given is none; an explicit nil is the reference's null options and is refused by every quantizer
	plain := map[string]any{"verb": "read", "resource": "doc:1"}
	var none map[string]any
	if q, err := QuantizeActionStruct(plain); err != nil || len(q) != 4 {
		t.Fatalf("no options: %v %v", q, err)
	}
	if h, err := PolicyVmCommitmentFromAction(plain); err != nil || h.Hi == "" {
		t.Fatalf("no options: %v %v", h, err)
	}
	if q, err := QuantizePolicyVmInputs(map[string]any{"action": plain}, map[string]any{}); err != nil || len(q.Action) != 4 || q.Plan != nil {
		t.Fatalf("empty options: %v %v", q, err)
	}
	_, e1 := QuantizeActionStruct(plain, none)
	_, e2 := PolicyVmCommitmentFromAction(plain, none)
	_, e3 := QuantizePlanStruct(map[string]any{"verb": "read", "resource": "doc:1", "semanticDist": 0, "planSalt": 1}, none)
	_, e4 := QuantizePolicyVmInputs(map[string]any{"action": plain}, none)
	_, e5 := QuantizePolicyStruct(map[string]any{}, none)
	if e1 == nil || e2 == nil || e3 == nil || e4 == nil || e5 == nil {
		t.Fatalf("null options must be refused: %v %v %v %v %v", e1, e2, e3, e4, e5)
	}
	if q, err := QuantizePlanStruct(map[string]any{"verb": "read", "resource": "doc:1", "semanticDist": 0, "planSalt": 1}); err != nil || len(q) != 4 {
		t.Fatalf("a plan without options: %v %v", q, err)
	}
	for _, member := range []string{"__proto__", "valueOf", "hasOwnProperty"} {
		if _, err := QuantizeActionStruct(map[string]any{"verb": "read", "resource": "doc:1", "params": map[string]any{}}, map[string]any{"paramScalarField": member}); err == nil {
			t.Fatalf("the object member %s is not a scalar", member)
		}
	}
	// a lone surrogate in a verb hashes as the replacement character, as the reference's UTF-8 encoder writes it
	lone, _ := QuantizeActionStruct(map[string]any{"verb": "a\xed\xa0\x80\xed\xa0\x80", "resource": "r"})
	repl, _ := QuantizeActionStruct(map[string]any{"verb": "a\ufffd\ufffd", "resource": "r"})
	one, _ := QuantizeActionStruct(map[string]any{"verb": "a\ufffd", "resource": "r"})
	if lone == nil || repl == nil || one == nil || lone[0] != repl[0] || lone[0] == one[0] {
		t.Fatalf("lone surrogates: %v %v %v", lone, repl, one)
	}
	// a surrogate pair written as two escapes is the one character it encodes
	pair, _ := QuantizeActionStruct(map[string]any{"verb": "\xed\xa0\xbd\xed\xb8\x80", "resource": "r"})
	char, _ := QuantizeActionStruct(map[string]any{"verb": "\U0001F600", "resource": "r"})
	if pair == nil || char == nil || pair[0] != char[0] {
		t.Fatalf("surrogate pair: %v %v", pair, char)
	}

	// pins: Go integers and *big.Int are exact, a clock function is called at each verification, a typed nil map is no pins
	ps := []any{"1", "2", "3", "4", "5", "6", "0", "1", "1", "1", "18446744073709551615", "0", "0", "0", "500000"}
	now := new(big.Int).SetUint64(math.MaxUint64)
	for name, pin := range map[string]any{"uint64": uint64(math.MaxUint64), "big": now, "string": "18446744073709551615", "hex": "0xffffffffffffffff",
		"window": map[string]any{"min": uint64(1), "max": now}} {
		if ok, err := PolicyVmContextMatches(ps, false, map[string]any{"now": pin}); !ok || err != nil {
			t.Fatalf("pin %s: %v %v", name, ok, err)
		}
	}
	for name, pin := range map[string]any{"float above 2^53": float64(math.MaxUint64), "int": 5, "int64": int64(-1), "list": []any{"18446744073709551615"},
		"window without max": map[string]any{"min": 1}, "window null max": map[string]any{"min": 1, "max": nil}, "true": true} {
		if ok, err := PolicyVmContextMatches(ps, false, map[string]any{"now": pin}); ok || err != nil {
			t.Fatalf("pin %s must not match: %v %v", name, ok, err)
		}
	}
	if ok, err := PolicyVmContextMatches(ps, false, map[string]any{"allocChild": true}); ok || err != nil {
		t.Fatalf("true is the integer 1, not 500000: %v %v", ok, err)
	}
	if ok, err := PolicyVmContextMatches(ps, false, map[string]any{"t": true}); !ok || err != nil {
		t.Fatalf("true is the integer 1: %v %v", ok, err)
	}
	calls := 0
	clock := func() map[string]any { calls++; return map[string]any{"blast": calls - 1} }
	if ok, _ := PolicyVmContextMatches(ps, false, clock); !ok {
		t.Fatal("the first call pins blast 0")
	}
	if ok, _ := PolicyVmContextMatches(ps, false, clock); ok || calls != 2 {
		t.Fatal("the second call pins blast 1")
	}
	if ok, err := PolicyVmContextMatches(ps, false, func() map[string]any { return nil }); ok || err != nil {
		t.Fatalf("a clock that returns nothing refuses: %v %v", ok, err)
	}
	if ok, err := PolicyVmContextMatches(ps, false, func() map[string]any { panic("clock") }); ok || err != nil {
		t.Fatalf("a clock that panics refuses: %v %v", ok, err)
	}
	if _, err := PolicyVmContextMatches(nil, false); err == nil {
		t.Fatal("missing signals are an error")
	}
	if ok, err := PolicyVmContextMatches("x", false); ok || err != nil {
		t.Fatalf("signals that are not a list: %v %v", ok, err)
	}
	// r and t are not context signals: read as the reference reads them (a number by its value, a one-element list by its text)
	odd := append([]any(nil), ps...)
	odd[6], odd[7] = json.Number("1152921504606846976"), []any{"3"}
	if ok, _ := PolicyVmContextMatches(odd, false, map[string]any{"r": "1152921504606846976", "t": 3}); !ok {
		t.Fatal("a numeric signal is compared by its exact value (2^60), a one-element list by its text")
	}
	if ok, _ := PolicyVmContextMatches(odd, false, map[string]any{"r": "1152921504606847000"}); ok {
		t.Fatal("2^60 prints as 1152921504606847000, but that is not its value")
	}
	odd[6] = json.Number("12")
	if ok, _ := PolicyVmContextMatches(odd, false, map[string]any{"r": 12, "t": "3"}); !ok {
		t.Fatal("a numeric r and a one-element t match their pins")
	}
	odd[6] = json.Number("1.5")
	if ok, _ := PolicyVmContextMatches(odd, false, map[string]any{"r": 1}); ok {
		t.Fatal("a fractional signal matches nothing")
	}

	// verification options the corpus cannot carry
	var sampleBn, sampleBls map[string]any
	var refBn, refBls any // the reference's keys, which the corpus carries by value
	zkVerifyCases(t, func(c *baseCase) {
		switch c.Name {
		case "verifyPolicyVmProof/bn/valid":
			sampleBn, refBn = vecObj(vecArg(c.Args, 0)), vecObj(vecArg(c.Args, 1))["verificationKey"]
		case "verifyPolicyVmProof/bls/valid":
			sampleBls, refBls = vecObj(vecArg(c.Args, 0)), vecObj(vecArg(c.Args, 1))["verificationKey"]
		}
	})
	if sampleBn == nil || sampleBls == nil {
		t.Fatal("the corpus has no valid cases")
	}
	if baseCanon(vecJSON(PolicyVmVerificationKey())) != baseCanon(refBn) || baseCanon(vecJSON(PolicyVmBls12381VerificationKey())) != baseCanon(refBls) {
		t.Fatal("a bundled verifying key is not the reference's")
	}
	type call struct {
		curve  string
		strict bool
		vkey   string
	}
	var seen call
	zkUseBackend(t, &Groth16Backend{Verify: func(curve string, strict bool, vkey, proof, signals []byte) (bool, string, error) {
		seen = call{curve, strict, string(vkey)}
		return true, "", nil
	}})
	bnKey, _ := json.Marshal(PolicyVmVerificationKey())
	blsKey, _ := json.Marshal(PolicyVmBls12381VerificationKey())
	if id, _ := VkID(PolicyVmVerificationKey()); len(bnKey) < 1000 || len(blsKey) < 1000 || string(bnKey) == string(blsKey) || !strings.HasPrefix(id, "vk_") {
		t.Fatal("the bundled keys do not load")
	}
	if ok, err := VerifyPolicyVmProof(sampleBn, nil); !ok || err != nil || seen != (call{Groth16CurveFromKey, false, string(bnKey)}) {
		t.Fatalf("the default BN254 key, reference rules: %v %v %s %v", ok, err, seen.curve, seen.strict)
	}
	if ok, err := VerifyPolicyVmProof(sampleBls, map[string]any{"strict": true}); !ok || err != nil || seen != (call{Groth16CurveBls12381, true, string(blsKey)}) {
		t.Fatalf("the default BLS12-381 key, strict: %v %v %s %v", ok, err, seen.curve, seen.strict)
	}
	if ok, err := VerifyPolicyVmProof(sampleBn, map[string]any{"strict": "true"}); !ok || err != nil || seen.strict {
		t.Fatal("strict is the boolean true only")
	}
	for _, name := range []string{"BN254", "alt_bn128", "bn-128"} {
		key := PolicyVmVerificationKey()
		key["curve"] = name
		if ok, err := VerifyPolicyVmProof(sampleBn, map[string]any{"verificationKey": key}); !ok || err != nil || seen.curve != Groth16CurveFromKey {
			t.Fatalf("curve name %s: %v %v", name, ok, err)
		}
	}
	blsNamed := PolicyVmVerificationKey()
	blsNamed["curve"] = "BLS12-381"
	if ok, err := VerifyPolicyVmProof(sampleBn, map[string]any{"verificationKey": blsNamed}); !ok || err != nil || seen.curve != Groth16CurveFromKey {
		t.Fatalf("the curve is the one the key names, and the backend reads it: %v %v %s", ok, err, seen.curve)
	}
	// strict mode takes the two exact names; any other is refused without asking the backend
	seen = call{}
	if ok, err := VerifyPolicyVmProof(sampleBn, map[string]any{"verificationKey": blsNamed, "strict": true}); ok || err != nil || seen.curve != "" {
		t.Fatalf("strict with another spelling of the curve: %v %v %s", ok, err, seen.curve)
	}
	if ok, err := VerifyPolicyVmProof(sampleBn, map[string]any{"strict": true}); !ok || err != nil || seen != (call{Groth16CurveBn254, true, string(bnKey)}) {
		t.Fatalf("strict with the bundled BN254 key: %v %v %s", ok, err, seen.curve)
	}
	// a key file, an unreadable one, a path that is not a string
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "vkey.json")
	if err := os.WriteFile(keyFile, blsKey, 0o600); err != nil {
		t.Fatal(err)
	}
	if ok, err := VerifyPolicyVmProof(sampleBn, map[string]any{"verificationKeyPath": keyFile}); !ok || err != nil || seen.vkey != string(blsKey) {
		t.Fatalf("a key file: %v %v", ok, err)
	}
	if ok, err := VerifyPolicyVmProof(sampleBn, map[string]any{"verificationKeyPath": keyFile, "verificationKey": PolicyVmVerificationKey()}); !ok || err != nil || seen.vkey != string(bnKey) {
		t.Fatalf("an explicit key wins over a path: %v %v", ok, err)
	}
	if ok, err := VerifyPolicyVmProof(sampleBn, map[string]any{"verificationKeyPath": filepath.Join(dir, "missing.json")}); ok || err == nil {
		t.Fatal("a missing key file is an error")
	}
	if ok, err := VerifyPolicyVmProof(sampleBn, map[string]any{"verificationKeyPath": json.Number("5")}); ok || err == nil {
		t.Fatal("a path that is not a string is an error")
	}
	// the risk-bound circuit has no bundled key: without one configured the error says so; with the directory set the file is read
	psBound := append(append(append([]any(nil), sampleBn["publicSignals"].([]any)[:9]...), "11", "22"), sampleBn["publicSignals"].([]any)[9:]...)
	v2 := map[string]any{"system": "groth16-bn254", "circuit": "pca-policyvm-v2", "proof": sampleBn["proof"], "publicSignals": psBound}
	t.Setenv("ATLAS_PCA_CIRCUITS_DIR", "")
	if ok, err := VerifyPolicyVmProof(v2, nil); ok || err == nil || errors.Is(err, ErrGroth16BackendMissing) {
		t.Fatalf("v2 without a key: %v %v", ok, err)
	}
	if ok, err := VerifyPolicyVmProof(v2, map[string]any{"expectRiskHash": nil}); ok || err == nil {
		t.Fatal("a null risk pin is an error")
	}
	if ok, err := VerifyPolicyVmProof(sampleBn, map[string]any{"expectRiskHash": nil}); ok || err != nil {
		t.Fatal("a risk pin on a v1 proof refuses before the pin is read")
	}
	if err := os.MkdirAll(filepath.Join(dir, "build"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "build", "policyvm_bound_vkey.json"), bnKey, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "build", "verification_key.json"), bnKey, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ATLAS_PCA_CIRCUITS_DIR", dir)
	for name, pin := range map[string]any{"struct": ZkDigestHalves{Hi: "11", Lo: "22"}, "pointer": &ZkDigestHalves{Hi: "11", Lo: "22"}, "object": map[string]any{"hi": "11", "lo": "22"}} {
		seen = call{}
		if ok, err := VerifyPolicyVmProof(v2, map[string]any{"expectRiskHash": pin}); !ok || err != nil || seen.vkey != string(bnKey) {
			t.Fatalf("v2 with the key file and a %s pin: %v %v", name, ok, err)
		}
		b := CreatePolicyVmBoundSnarkBackend(map[string]any{"expectRiskHash": pin, "expectActionHash": ZkDigestHalves{Hi: psBound[0].(string), Lo: psBound[1].(string)}})
		if ok, err := b.VerifySnark(ZkSnarkInput{Proof: v2}); !ok || err != nil {
			t.Fatalf("the bound backend with a %s pin: %v %v", name, ok, err)
		}
	}
	for name, pin := range map[string]any{"struct": ZkDigestHalves{Hi: "11", Lo: "23"}, "nil pointer": (*ZkDigestHalves)(nil), "half": map[string]any{"hi": "11"}} {
		seen = call{}
		if ok, err := VerifyPolicyVmProof(v2, map[string]any{"expectRiskHash": pin}); ok || err != nil || seen.curve != "" {
			t.Fatalf("v2 with another %s pin: %v %v", name, ok, err)
		}
	}
	if ok, err := CreatePolicyVmBoundSnarkBackend(map[string]any{"expectRiskHash": nil}).VerifySnark(ZkSnarkInput{Proof: v2}); ok || err == nil {
		t.Fatal("a null risk pin reaches the verifier as one")
	}
	// the backends: typed hash pins, a key resolved once, the first circuit's default key file
	halves := func(i int) ZkDigestHalves {
		p := sampleBn["publicSignals"].([]any)
		return ZkDigestHalves{Hi: p[i].(string), Lo: p[i+1].(string)}
	}
	bound := CreatePolicyVmSnarkBackend(map[string]any{"expectActionHash": halves(0), "expectPolicyHash": halves(2), "expectPlanHash": halves(4), "strict": true})
	if l, _ := AssuranceLabelOf(bound); l != (AssuranceLabel{Level: "policyvm_snark", Ceremony: CeremonySingleParty}) {
		t.Fatalf("label with typed pins: %+v", l)
	}
	if ok, err := bound.VerifySnark(ZkSnarkInput{Proof: sampleBn}); !ok || err != nil || !seen.strict || seen.vkey != string(bnKey) {
		t.Fatalf("the backend with typed pins: %v %v", ok, err)
	}
	wrong := CreatePolicyVmSnarkBackend(map[string]any{"expectPlanHash": halves(2)})
	seen = call{}
	if ok, err := wrong.VerifySnark(ZkSnarkInput{Proof: sampleBn}); ok || err != nil || seen.curve != "" {
		t.Fatalf("another plan hash: %v %v", ok, err)
	}
	fileBacked := CreatePolicyVmSnarkBackend(map[string]any{"verificationKeyPath": keyFile})
	if ok, err := fileBacked.VerifySnark(ZkSnarkInput{Proof: sampleBn}); !ok || err != nil || seen.vkey != string(blsKey) {
		t.Fatalf("a backend with a key file: %v %v", ok, err)
	}
	if err := os.Remove(keyFile); err != nil {
		t.Fatal(err)
	}
	if ok, err := fileBacked.VerifySnark(ZkSnarkInput{Proof: sampleBn}); !ok || err != nil {
		t.Fatalf("the key is read once: %v %v", ok, err)
	}
	if ok, err := CreatePolicyVmSnarkBackend(map[string]any{"verificationKeyPath": keyFile}).VerifySnark(ZkSnarkInput{Proof: sampleBn}); ok || err == nil {
		t.Fatal("a backend whose key file is gone is an error")
	}
	tag := func(c string) string { s, _ := CommitmentField(c); return s }
	c1, c2, c3 := B64u(make([]byte, 32)), B64u([]byte{1}), B64u([]byte{2})
	first := map[string]any{"system": "groth16-bn254", "circuit": "pca-compliance-v1", "proof": sampleBn["proof"],
		"publicSignals": []any{"1", "2", "3", tag(c2), tag(c3), tag(c1), "1"}}
	g := CreateGroth16SnarkBackend(nil)
	if ok, err := g.VerifySnark(ZkSnarkInput{Proof: first, ActionCommit: c1, PolicyCommit: c2, PlanCommit: c3}); !ok || err != nil || seen.vkey != string(bnKey) || seen.strict {
		t.Fatalf("the first circuit with its default key file: %v %v", ok, err)
	}
	if ok, err := g.VerifySnark(ZkSnarkInput{Proof: first, ActionCommit: c2, PolicyCommit: c1, PlanCommit: c3}); ok || err != nil {
		t.Fatalf("commitments in another order: %v %v", ok, err)
	}
	// a key that names no curve: the backend reads the key under the reference's rules; strict refuses it without asking
	noCurve := PolicyVmVerificationKey()
	delete(noCurve, "curve")
	seen = call{}
	if ok, err := CreateGroth16SnarkBackend(map[string]any{"verificationKey": noCurve, "strict": true}).VerifySnark(ZkSnarkInput{Proof: first, ActionCommit: c1, PolicyCommit: c2, PlanCommit: c3}); ok || err != nil || seen.curve != "" {
		t.Fatalf("strict with a key that names no curve: %v %v", ok, err)
	}
	if ok, err := VerifyPolicyVmProof(sampleBn, map[string]any{"verificationKey": noCurve}); !ok || err != nil || seen.curve != Groth16CurveFromKey {
		t.Fatalf("a key that names no curve is the backend's to refuse: %v %v %s", ok, err, seen.curve)
	}
	// a fault of the pairing check is a refusal for VerifyPolicyVmProof, as in the reference, and an error for the first circuit's
	// backend (the reference throws there); a missing backend stays an error everywhere (see the test above)
	fault := errors.New("library fault")
	zkUseBackend(t, &Groth16Backend{Verify: func(string, bool, []byte, []byte, []byte) (bool, string, error) { return true, "", fault }})
	if ok, err := VerifyPolicyVmProof(sampleBn, nil); ok || err != nil {
		t.Fatalf("a backend fault is a refusal: %v %v", ok, err)
	}
	if ok, err := CreatePolicyVmSnarkBackend(nil).VerifySnark(ZkSnarkInput{Proof: sampleBn}); ok || err != nil {
		t.Fatalf("a backend fault through the Policy VM backend: %v %v", ok, err)
	}
	if ok, err := g.VerifySnark(ZkSnarkInput{Proof: first, ActionCommit: c1, PolicyCommit: c2, PlanCommit: c3}); ok || !errors.Is(err, fault) {
		t.Fatalf("a backend fault through the first circuit's backend: %v %v", ok, err)
	}
}

func TestZkProveWrappers(t *testing.T) {
	stub := &zkRecorded{proof: map[string]any{"pi_a": []any{"1"}}, signals: []any{"7"}}
	zkUseBackend(t, stub.backend())
	dir := t.TempDir()
	write := func(rel, body string) string {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if os.MkdirAll(filepath.Dir(p), 0o700) != nil || os.WriteFile(p, []byte(body), 0o600) != nil {
			t.Fatal("cannot write " + rel)
		}
		return p
	}
	// the default artifact locations, under the configured circuits directory
	for _, rel := range []string{"build/compliance_js/compliance.wasm", "build/policyvm_js/policyvm.wasm", "build/policyvm_bound_js/policyvm_bound.wasm"} {
		write(rel, "wasm")
	}
	for _, rel := range []string{"build/compliance_final.zkey", "build/policyvm_final.zkey", "build/policyvm_bound_final.zkey"} {
		write(rel, "zkey")
	}
	t.Setenv("ATLAS_PCA_CIRCUITS_DIR", dir)
	commit := B64u(sha256.New().Sum(nil))
	tag, _ := CommitmentField(commit)
	inp := map[string]any{"action_commit": commit, "policy_commit": commit, "plan_commit": B64u([]byte{9}), "verb": 7, "resource": uint64(42), "planVerb": "7",
		"policySalt": big.NewInt(11), "planSalt": int64(12), "actionSalt": json.Number("13"), "risk": json.Number("100"), "budget": float64(1000)}
	env, err := ProveGroth16Compliance(inp, nil)
	if err != nil || baseCanon(vecJSON(env)) != `{"circuit":"pca-compliance-v1","proof":{"pi_a":["1"]},"publicSignals":["7"],"system":"groth16-bn254"}` {
		t.Fatalf("the first circuit's envelope: %v %v", env, err)
	}
	want := map[string]string{"verb": "7", "resource": "42", "planVerb": "7", "policySalt": "11", "planSalt": "12", "actionSalt": "13", "risk": "100", "budget": "1000",
		"shaPolicy": tag, "shaPlan": "9", "shaAction": tag, "allow": "1"}
	if len(stub.proved) != len(want) {
		t.Fatalf("circuit input: %v", stub.proved)
	}
	for k, v := range want {
		if stub.proved[k] != v {
			t.Fatalf("circuit input %s: %q, want %q", k, stub.proved[k], v)
		}
	}
	for _, k := range []string{"verb", "budget", "plan_commit"} {
		bad := map[string]any{}
		for n, v := range inp {
			bad[n] = v
		}
		delete(bad, k)
		if _, err := ProveGroth16Compliance(bad, nil); err == nil {
			t.Fatalf("a witness without %s must be refused", k)
		}
	}
	bad := map[string]any{}
	for n, v := range inp {
		bad[n] = v
	}
	bad["action_commit"] = "!!"
	if _, err := ProveGroth16Compliance(bad, nil); err == nil {
		t.Fatal("a commitment that is not base64url must be refused")
	}
	bad["action_commit"], bad["risk"] = commit, nil
	if _, err := ProveGroth16Compliance(bad, nil); err == nil {
		t.Fatal("a null witness member must be refused")
	}
	for circuit, prove := range map[string]func(map[string]any, map[string]any) (map[string]any, error){"pca-policyvm-v1": ProvePolicyVmCompliance, "pca-policyvm-v2": ProvePolicyVmBoundCompliance} {
		env, err := prove(map[string]any{"a": 1, "b": "2"}, nil)
		if err != nil || env["circuit"] != any(circuit) || env["system"] != any("groth16-bn254") || len(stub.proved) != 2 || stub.proved["a"] != "1" || stub.proved["b"] != "2" {
			t.Fatalf("%s: %v %v %v", circuit, env, err, stub.proved)
		}
	}
	// explicit paths win; a missing artifact, a prover without a proof and a verify-only backend are errors
	other := write("elsewhere/x.wasm", "not the wasm")
	if _, err := ProvePolicyVmCompliance(map[string]any{"a": 1}, map[string]any{"wasmPath": other}); err == nil {
		t.Fatal("the explicit wasm path must be the one read")
	}
	if _, err := ProvePolicyVmCompliance(map[string]any{"a": 1}, map[string]any{"zkeyPath": other}); err == nil {
		t.Fatal("the explicit zkey path must be the one read")
	}
	if _, err := ProvePolicyVmCompliance(map[string]any{"a": 1}, map[string]any{"zkeyPath": filepath.Join(dir, "missing")}); err == nil {
		t.Fatal("a missing proving key is an error")
	}
	stub.proof = nil
	if _, err := ProvePolicyVmCompliance(map[string]any{"a": 1}, nil); err == nil {
		t.Fatal("a prover result without a proof is an error")
	}
	stub.proof, stub.signals = map[string]any{}, "x"
	if _, err := ProvePolicyVmCompliance(map[string]any{"a": 1}, nil); err == nil {
		t.Fatal("a prover result without public signals is an error")
	}
	t.Setenv("ATLAS_PCA_CIRCUITS_DIR", "")
	stub.signals = []any{}
	if _, err := ProvePolicyVmCompliance(map[string]any{"a": 1}, nil); err == nil || errors.Is(err, ErrGroth16BackendMissing) {
		t.Fatalf("no artifact location configured: %v", err)
	}
	zkUseBackend(t, &Groth16Backend{Verify: stub.backend().Verify})
	if _, err := ProvePolicyVmCompliance(map[string]any{"a": 1}, nil); !errors.Is(err, ErrGroth16BackendMissing) {
		t.Fatalf("a verify-only backend cannot prove: %v", err)
	}
}
