package pca

// Groth16 compliance proofs: public-input derivation, the envelope and context gates, verification and the SNARK backends.
//
// Three circuits, all proved with snarkjs / circom and carried as {system, circuit, proof, publicSignals}:
//
//   - "pca-compliance-v1" (BN254): Poseidon openings of the policy / plan / action commitments, plan membership of the verb and
//     risk <= budget. Its public binding tags are CommitmentField of the resource server's own commitments.
//   - "pca-policyvm-v1" (BN254 and BLS12-381): the Policy VM itself in fixed point, over sha256 of a fixed-layout quantized struct
//     (PolicyVmStructHash, the Quantize functions). 15 public signals. The verifying keys of both curves are bundled.
//   - "pca-policyvm-v2" (BN254): v1 plus a public commitment to the five risk magnitudes (PolicyVmRiskHash). 17 public signals.
//
// Everything here except the pairing equation is pure Go. The pairing check goes through the Groth16 backend seam
// (SetGroth16Backend, for example the zkkit module): without a backend a proof that passes every gate is neither valid nor
// invalid, the error is ErrGroth16BackendMissing. A refusal in front of the pairing needs no backend.
//
// Proofs, keys, options and pins are parsed JSON (map[string]any, []any, string, bool, nil, json.Number), read with the
// reference's rules; option objects use the reference's member names, and a nil options map is "no options". Integers may also
// be given as Go integers or *big.Int.

import (
	_ "embed"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unicode/utf16"
)

//go:embed zk_policyvm_vkey.json
var zkPolicyVmVkeyJSON []byte

//go:embed zk_policyvm_bls12381_vkey.json
var zkPolicyVmBls12381VkeyJSON []byte

//go:embed zk_circuit_versions.json
var zkCircuitVersionsJSON []byte

// Where the reference keeps the circuit artifacts, relative to its package root. Only the two Policy VM verifying keys and the
// circuit version table are bundled with this module; every other artifact is read from the directory named by the environment
// variable ATLAS_PCA_CIRCUITS_DIR (the "circuits" directory) unless a path option says otherwise.
const (
	// ZkDefaultVkeyPath is the verifying key of "pca-compliance-v1".
	ZkDefaultVkeyPath = "circuits/build/verification_key.json"
	// ZkDefaultWasmPath is the witness calculator of "pca-compliance-v1".
	ZkDefaultWasmPath = "circuits/build/compliance_js/compliance.wasm"
	// ZkDefaultZkeyPath is the proving key of "pca-compliance-v1".
	ZkDefaultZkeyPath = "circuits/build/compliance_final.zkey"
	// PolicyVmVkeyPath is the BN254 verifying key of "pca-policyvm-v1" (bundled: PolicyVmVerificationKey).
	PolicyVmVkeyPath = "circuits/policyvm_vkey.json"
	// PolicyVmSampleProofPath is the committed BN254 sample proof of "pca-policyvm-v1".
	PolicyVmSampleProofPath = "circuits/policyvm_sample_proof.json"
	// PolicyVmWasmPath is the witness calculator of "pca-policyvm-v1".
	PolicyVmWasmPath = "circuits/build/policyvm_js/policyvm.wasm"
	// PolicyVmZkeyPath is the proving key of "pca-policyvm-v1".
	PolicyVmZkeyPath = "circuits/build/policyvm_final.zkey"
	// PolicyVmBls12381VkeyPath is the BLS12-381 verifying key of "pca-policyvm-v1" (bundled: PolicyVmBls12381VerificationKey).
	PolicyVmBls12381VkeyPath = "circuits/policyvm_bls12381_vkey.json"
	// PolicyVmBls12381SampleProofPath is the committed BLS12-381 sample proof of "pca-policyvm-v1".
	PolicyVmBls12381SampleProofPath = "circuits/policyvm_bls12381_sample_proof.json"
	// PolicyVmBoundVkeyPath is the verifying key of "pca-policyvm-v2" (never bundled: a development build or a ceremony makes it).
	PolicyVmBoundVkeyPath = "circuits/build/policyvm_bound_vkey.json"
	// PolicyVmBoundSampleProofPath is the sample proof of "pca-policyvm-v2".
	PolicyVmBoundSampleProofPath = "circuits/build/policyvm_bound_sample_proof.json"
	// PolicyVmBoundWasmPath is the witness calculator of "pca-policyvm-v2".
	PolicyVmBoundWasmPath = "circuits/build/policyvm_bound_js/policyvm_bound.wasm"
	// PolicyVmBoundZkeyPath is the proving key of "pca-policyvm-v2".
	PolicyVmBoundZkeyPath = "circuits/build/policyvm_bound_final.zkey"
)

const (
	// PolicyVmPublicSignalCount is the number of public signals of "pca-policyvm-v1".
	PolicyVmPublicSignalCount = 15
	// PolicyVmBoundPublicSignalCount is the number of public signals of "pca-policyvm-v2".
	PolicyVmBoundPublicSignalCount = 17
)

var (
	// PolicyVmPublicSignal is the public-signal layout of "pca-policyvm-v1" (snarkjs order: the circuit outputs, then the public
	// inputs): the three sha256 struct-hash halves, the computed risk r, the threshold tier t, the auto-admit bit, then the
	// asserted allow bit and the decision context.
	PolicyVmPublicSignal = map[string]int{"actionHi": 0, "actionLo": 1, "policyHi": 2, "policyLo": 3, "planHi": 4, "planLo": 5,
		"r": 6, "t": 7, "admit": 8, "allow": 9, "now": 10, "blast": 11, "delegationDepth": 12, "recentCount": 13, "allocChild": 14}
	// PolicyVmBoundPublicSignal is the public-signal layout of "pca-policyvm-v2": v1 plus the risk commitment halves.
	PolicyVmBoundPublicSignal = map[string]int{"actionHi": 0, "actionLo": 1, "policyHi": 2, "policyLo": 3, "planHi": 4, "planLo": 5,
		"r": 6, "t": 7, "admit": 8, "riskHi": 9, "riskLo": 10, "allow": 11, "now": 12, "blast": 13, "delegationDepth": 14,
		"recentCount": 15, "allocChild": 16}
	// PolicyVmBoundRiskFields are the risk magnitudes the v2 circuit commits to, in struct order.
	PolicyVmBoundRiskFields = []string{"revScore", "taint", "conf", "age", "rFloorIn"}
	// PolicyVmReversibilityOrder is the reversibility-class ordering the circuit encodes: reversible = 0, rate_limited = 1,
	// irreversible = 2.
	PolicyVmReversibilityOrder = []string{"reversible", "rate_limited", "irreversible"}
)

// zkLayout holds the signal indices the gates read (the hash halves are at 0..5 in both layouts).
type zkLayout struct{ r, t, admit, riskHi, allow, now, blast, depth, recent, alloc, count int }

var (
	zkLayoutV1 = zkLayout{r: 6, t: 7, admit: 8, riskHi: -1, allow: 9, now: 10, blast: 11, depth: 12, recent: 13, alloc: 14, count: PolicyVmPublicSignalCount}
	zkLayoutV2 = zkLayout{r: 6, t: 7, admit: 8, riskHi: 9, allow: 11, now: 12, blast: 13, depth: 14, recent: 15, alloc: 16, count: PolicyVmBoundPublicSignalCount}
)

func zkLayoutOf(bound bool) zkLayout {
	if bound {
		return zkLayoutV2
	}
	return zkLayoutV1
}

func zkMustBig(s string, base int) *big.Int {
	b, ok := new(big.Int).SetString(s, base)
	if !ok {
		panic("zk: bad constant")
	}
	return b
}

var (
	// the scalar field (public signals) and the base field (point coordinates) of each curve
	zkBn254Fr    = zkMustBig("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)
	zkBn254Fq    = zkMustBig("21888242871839275222246405745257275088696311157297823662689037894645226208583", 10)
	zkBls12381Fq = zkMustBig("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab", 16)
	zkBls12381Fr = zkMustBig("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16)
	zkTwo64      = new(big.Int).Lsh(big.NewInt(1), 64)
)

// CommitmentField maps a base64url commitment (a sha256, 32 bytes; any length is reduced) to a BN254 scalar-field element, as a
// decimal string: the encoding of the "pca-compliance-v1" public binding tags. The prover and the verifier derive it identically
// from the same commitment, so the proof is tied to that exact commitment. 256 bits are reduced into the ~254-bit field: at most
// six commitments share a tag, which leaves second-preimage and collision resistance above the security of the proof system the
// tag sits in. It errors on anything that is not strict unpadded base64url.
func CommitmentField(b64uCommit string) (string, error) {
	b, err := Unb64u(b64uCommit)
	if err != nil {
		return "", err
	}
	acc := new(big.Int).SetBytes(b)
	return acc.Mod(acc, zkBn254Fr).String(), nil
}

// zkCanonDec reports a canonical decimal: "0", or digits without a leading zero.
func zkCanonDec(s string) bool {
	if s == "0" {
		return true
	}
	if s == "" || s[0] == '0' {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func zkCanonDecBelow(v any, bound *big.Int) bool {
	s, ok := v.(string)
	if !ok || len(s) > 120 || !zkCanonDec(s) {
		return false
	}
	x, _ := new(big.Int).SetString(s, 10)
	return x.Cmp(bound) < 0
}

func zkSameKeys(m map[string]any, keys ...string) bool {
	if len(m) != len(keys) {
		return false
	}
	for _, k := range keys {
		if _, has := m[k]; !has {
			return false
		}
	}
	return true
}

// IsCanonicalGroth16Envelope reports whether env is exactly the one canonical Groth16 envelope snarkjs emits for curve ("bn254";
// anything else is read as "bls12-381"): the exact member sets, every number a canonical decimal string below its field modulus
// (the scalar field for public signals, the base field for coordinates), every point affine with z = 1. A verifier that parses
// leniently accepts many encodings of one proof (x + p, leading zeros, hex, extra members); this gate accepts one.
func IsCanonicalGroth16Envelope(env any, curve string) bool {
	e, ok := env.(map[string]any)
	if !ok || !zkSameKeys(e, "system", "circuit", "proof", "publicSignals") {
		return false
	}
	fq, fr, name := zkBls12381Fq, zkBls12381Fr, "bls12381"
	if curve == "bn254" {
		fq, fr, name = zkBn254Fq, zkBn254Fr, "bn128"
	}
	ps, ok := e["publicSignals"].([]any)
	if !ok {
		return false
	}
	for _, x := range ps {
		if !zkCanonDecBelow(x, fr) {
			return false
		}
	}
	pr, ok := e["proof"].(map[string]any)
	if !ok || !zkSameKeys(pr, "pi_a", "pi_b", "pi_c", "protocol", "curve") || !zkIs(pr["protocol"], "groth16") || !zkIs(pr["curve"], name) {
		return false
	}
	g1 := func(v any) bool {
		a, ok := v.([]any)
		return ok && len(a) == 3 && zkCanonDecBelow(a[0], fq) && zkCanonDecBelow(a[1], fq) && zkIs(a[2], "1")
	}
	if !g1(pr["pi_a"]) || !g1(pr["pi_c"]) {
		return false
	}
	b, ok := pr["pi_b"].([]any)
	if !ok || len(b) != 3 {
		return false
	}
	for _, row := range b[:2] {
		r, ok := row.([]any)
		if !ok || len(r) != 2 || !zkCanonDecBelow(r[0], fq) || !zkCanonDecBelow(r[1], fq) {
			return false
		}
	}
	z, ok := b[2].([]any)
	return ok && len(z) == 2 && zkIs(z[0], "1") && zkIs(z[1], "0")
}

// ---- integers as the reference reads them -------------------------------------------------------------------------------------

func zkFloatInt(f float64) *big.Int {
	b, _ := new(big.Float).SetFloat64(f).Int(nil)
	return b
}

// zkStringToBigInt reads an integer literal as the reference's integer conversion does: surrounding white space ignored, "" is
// 0, a signed decimal, or an unsigned 0x / 0o / 0b literal.
func zkStringToBigInt(s string) (*big.Int, error) {
	t := jsTrim(s)
	if t == "" {
		return new(big.Int), nil
	}
	base, digits, neg := 10, t, false
	if len(t) > 2 && t[0] == '0' {
		switch t[1] | 0x20 {
		case 'x':
			base = 16
		case 'o':
			base = 8
		case 'b':
			base = 2
		}
		if base != 10 {
			digits = t[2:]
		}
	} else if t[0] == '+' || t[0] == '-' {
		digits, neg = t[1:], t[0] == '-'
	}
	for i := 0; i < len(digits); i++ {
		d := 99
		switch c := digits[i]; {
		case c >= '0' && c <= '9':
			d = int(c - '0')
		case c|0x20 >= 'a' && c|0x20 <= 'f':
			d = int(c|0x20-'a') + 10
		}
		if d >= base {
			digits = ""
			break
		}
	}
	b, ok := new(big.Int).SetString(digits, base)
	if digits == "" || !ok {
		return nil, fmt.Errorf("cannot convert %q to an integer", s)
	}
	if neg {
		b.Neg(b)
	}
	return b, nil
}

// zkBigInt is the reference's integer conversion of a value: an integer, an integral number, a boolean (0 / 1) or an integer
// literal in a string.
func zkBigInt(v any) (*big.Int, error) {
	switch t := v.(type) {
	case *big.Int:
		if t != nil {
			return t, nil
		}
	case bool:
		if t {
			return big.NewInt(1), nil
		}
		return new(big.Int), nil
	case uint64:
		return new(big.Int).SetUint64(t), nil
	case int:
		return big.NewInt(int64(t)), nil
	case int64:
		return big.NewInt(t), nil
	case string:
		return zkStringToBigInt(t)
	case []any:
		return zkStringToBigInt(zkString(t))
	case json.Number, float64:
		if f, ok := jsNum(t); ok && !math.IsInf(f, 0) && f == math.Trunc(f) {
			return zkFloatInt(f), nil
		}
		return nil, fmt.Errorf("the number %s is not an integer", zkString(t))
	}
	return nil, errors.New("the value cannot be converted to an integer")
}

// zkToU64 takes an explicit code or numeric field: an integer or an integral number in [0, 2^64). Anything else (a string, a
// fraction, a negative) is refused.
func zkToU64(v any, what string) (uint64, error) {
	var b *big.Int
	switch t := v.(type) {
	case uint64:
		return t, nil
	case int:
		b = big.NewInt(int64(t))
	case int64:
		b = big.NewInt(t)
	case *big.Int:
		b = t
	case json.Number, float64:
		if f, ok := jsNum(t); ok && !math.IsInf(f, 0) && f == math.Trunc(f) {
			b = zkFloatInt(f)
		}
	}
	if b == nil || !b.IsUint64() {
		return 0, fmt.Errorf("policyvm quantize: %s is not a uint64", what)
	}
	return b.Uint64(), nil
}

// ---- struct hashes ----------------------------------------------------------------------------------------------------------

// ZkDigestHalves is a sha256 digest split into the circuit's two 128-bit big-endian halves, as decimal field strings.
type ZkDigestHalves struct {
	Hi string `json:"hi"`
	Lo string `json:"lo"`
}

// zkHalvesOf reads the two halves of a pin given as ZkDigestHalves or as {hi, lo}.
func zkHalvesOf(want any) (hi, lo any) {
	switch t := want.(type) {
	case ZkDigestHalves:
		return t.Hi, t.Lo
	case *ZkDigestHalves:
		if t != nil {
			return t.Hi, t.Lo
		}
	}
	return zkProp(want, "hi"), zkProp(want, "lo")
}

// zkHalvesMatch: the halves at hiIdx, hiIdx + 1 equal the expected digest, or no expectation was set.
func zkHalvesMatch(ps []any, hiIdx int, want any) bool {
	if !zkTruthy(want) {
		return true
	}
	hi, lo := zkHalvesOf(want)
	return zkEq(zkIdx(ps, hiIdx), hi) && zkEq(zkIdx(ps, hiIdx+1), lo)
}

// PolicyVmStructHash serializes fixed-layout struct fields exactly as the circuit does (each a 64-bit unsigned big-endian integer,
// concatenated), hashes them with sha256 and splits the digest into the two 128-bit halves the circuit exposes (Hi = the top 16
// bytes). A verifier binds a proof's public hash halves to a known field layout with it. fields is a []uint64, or a []any of
// integers, integral numbers and integer strings; a field outside [0, 2^64) or not an integer is an error.
func PolicyVmStructHash(fields any) (ZkDigestHalves, error) {
	var list []any
	switch t := fields.(type) {
	case []any:
		list = t
	case []uint64:
		list = make([]any, len(t))
		for i, x := range t {
			list[i] = x
		}
	default:
		return ZkDigestHalves{}, errors.New("policyVmStructHash: the fields must be a list")
	}
	buf := make([]byte, 8*len(list))
	for i, f := range list {
		v, err := zkBigInt(f)
		if err != nil {
			return ZkDigestHalves{}, fmt.Errorf("policyVmStructHash: %w", err)
		}
		if !v.IsUint64() {
			return ZkDigestHalves{}, errors.New("policyVmStructHash: field out of uint64 range")
		}
		binary.BigEndian.PutUint64(buf[8*i:], v.Uint64())
	}
	d := sha(buf)
	return ZkDigestHalves{Hi: new(big.Int).SetBytes(d[:16]).String(), Lo: new(big.Int).SetBytes(d[16:]).String()}, nil
}

// PolicyVmRiskHash is the sha256 commitment of the v2 circuit's risk struct, as its two public halves riskHi / riskLo: exactly the
// five risk magnitudes (revScore, taint, conf, age, rFloorIn; fixed point, scale 1e6) in PolicyVmBoundRiskFields order.
func PolicyVmRiskHash(fields any) (ZkDigestHalves, error) {
	n := -1
	switch t := fields.(type) {
	case []any:
		n = len(t)
	case []uint64:
		n = len(t)
	}
	if n != len(PolicyVmBoundRiskFields) {
		return ZkDigestHalves{}, errors.New("policyVmRiskHash: need exactly 5 risk fields")
	}
	return PolicyVmStructHash(fields)
}

// ---- quantization: the live action, plan node and policy as the circuit's fixed uint64 structs ------------------------------------

// zkOptsArg reads the optional options argument of a quantizer: not given is no options; an explicit nil is the reference's null
// options, which it refuses.
func zkOptsArg(opts []map[string]any) (map[string]any, error) {
	if len(opts) == 0 {
		return nil, nil
	}
	if opts[0] == nil {
		return nil, errors.New("policyvm quantize: the options are null")
	}
	return opts[0], nil
}

// zkContentAddressU64 is the uint64 content address of a domain-tagged string: the top 8 bytes of its sha256, big-endian. The
// string is hashed as the reference's UTF-8 encoder writes it: every lone surrogate is the replacement character.
func zkContentAddressU64(domain, value string) uint64 {
	wellFormed := string(utf16.Decode(utf16Units(value)))
	return binary.BigEndian.Uint64(sha([]byte("atlas-pca/policyvm-quantize/" + domain + ":" + wellFormed)))
}

// zkCodeFor maps a verb or resource string to its circuit code: the explicit catalog, else its content address.
func zkCodeFor(domain string, value, codes any, strict bool) (uint64, error) {
	s, ok := value.(string)
	if !ok {
		return 0, fmt.Errorf("policyvm quantize: %s must be a string", domain)
	}
	if m, ok := codes.(map[string]any); ok {
		if c, has := m[s]; has {
			return zkToU64(c, domain+" code")
		}
	}
	if strict {
		return 0, fmt.Errorf("policyvm quantize: %s %q is not in the catalog (strict)", domain, s)
	}
	return zkContentAddressU64(domain, s), nil
}

// zkObjectMembers are the names every object of the reference answers to: read as a param scalar they are not an integer.
var zkObjectMembers = map[string]bool{"constructor": true, "toString": true, "toLocaleString": true, "valueOf": true, "hasOwnProperty": true,
	"isPrototypeOf": true, "propertyIsEnumerable": true, "__proto__": true, "__defineGetter__": true, "__defineSetter__": true,
	"__lookupGetter__": true, "__lookupSetter__": true}

// zkParamScalar reads the uint64 param scalar from the action params: 0 when no field is configured or the param is unset.
func zkParamScalar(params, field any) (uint64, error) {
	if !zkTruthy(field) || !zkTruthy(params) {
		return 0, nil
	}
	m, ok := params.(map[string]any)
	if !ok {
		return 0, errors.New("policyvm quantize: params is not an object")
	}
	bad := errors.New("policyvm quantize: paramScalar is not a non-negative integer")
	v, has := m[zkString(field)]
	if !has && zkObjectMembers[zkString(field)] {
		return 0, bad
	}
	switch t := v.(type) {
	case nil:
		return 0, nil
	case *big.Int, uint64, int, int64:
		return zkToU64(t, "paramScalar")
	case string:
		if t == "" || strings.Trim(t, "0123456789") != "" {
			return 0, bad
		}
		b, _ := new(big.Int).SetString(t, 10)
		return zkToU64(b, "paramScalar")
	case json.Number, float64:
		if f, _ := jsNum(t); math.Signbit(f) { // a negative, and negative zero
			return 0, bad
		}
		return zkToU64(t, "paramScalar")
	}
	return 0, bad
}

func zkReversibilityIndex(rc any, what string) (uint64, error) {
	for i, c := range PolicyVmReversibilityOrder {
		if zkIs(rc, c) {
			return uint64(i), nil
		}
	}
	return 0, fmt.Errorf("policyvm quantize: unknown %s class %q", what, zkString(rc))
}

// QuantizeActionStruct deterministically quantizes the live action {verb, resource, reversibility_class?, params?} to the
// circuit's fixed 4-field struct: verb code, resource code, reversibility-class index (an omitted class is "reversible"), param
// scalar. opts (optional) is how the verb and resource strings map to uint64 codes, and must equal the map the prover used:
// verbCodes and resourceCodes (explicit catalogs), strictCatalog (a miss is an error instead of the content address) and
// paramScalarField (the action param whose non-negative integer value is the scalar; unset = 0). It fails closed on anything
// that cannot be quantized: a verb or resource that is not a string, an unknown class, a strict-catalog miss, a scalar outside
// the uint64 range. Options that are given must not be nil (the reference refuses null options).
func QuantizeActionStruct(action any, opts ...map[string]any) ([]uint64, error) {
	o, err := zkOptsArg(opts)
	if err != nil {
		return nil, err
	}
	return zkQuantizeAction(action, o)
}

func zkQuantizeAction(action any, opts map[string]any) ([]uint64, error) {
	a, ok := action.(map[string]any)
	if !ok {
		return nil, errors.New("policyvm quantize: action is missing")
	}
	strict := opts["strictCatalog"] == any(true)
	verb, err := zkCodeFor("verb", a["verb"], opts["verbCodes"], strict)
	if err != nil {
		return nil, err
	}
	resource, err := zkCodeFor("resource", a["resource"], opts["resourceCodes"], strict)
	if err != nil {
		return nil, err
	}
	class := a["reversibility_class"]
	if class == nil {
		class = "reversible"
	}
	rev, err := zkReversibilityIndex(class, "reversibility")
	if err != nil {
		return nil, err
	}
	scalar, err := zkParamScalar(a["params"], opts["paramScalarField"])
	if err != nil {
		return nil, err
	}
	return []uint64{verb, resource, rev, scalar}, nil
}

// QuantizePlanStruct quantizes the plan node {verb, resource, semanticDist, planSalt} to the circuit's 4-field plan struct. The
// quantized distance and the hiding salt are prover-side values, so this is for provers and non-hiding deployments; a resource
// server binds the action.
func QuantizePlanStruct(plan any, opts ...map[string]any) ([]uint64, error) {
	o, err := zkOptsArg(opts)
	if err != nil {
		return nil, err
	}
	return zkQuantizePlan(plan, o)
}

func zkQuantizePlan(plan any, opts map[string]any) ([]uint64, error) {
	p, ok := plan.(map[string]any)
	if !ok {
		return nil, errors.New("policyvm quantize: plan is missing")
	}
	strict := opts["strictCatalog"] == any(true)
	out := make([]uint64, 4)
	var err error
	if out[0], err = zkCodeFor("verb", p["verb"], opts["verbCodes"], strict); err != nil {
		return nil, err
	}
	if out[1], err = zkCodeFor("resource", p["resource"], opts["resourceCodes"], strict); err != nil {
		return nil, err
	}
	if out[2], err = zkToU64(p["semanticDist"], "semanticDist"); err != nil {
		return nil, err
	}
	if out[3], err = zkToU64(p["planSalt"], "planSalt"); err != nil {
		return nil, err
	}
	return out, nil
}

// QuantizePolicyStruct quantizes the policy to the circuit's 20-field struct: weights {alpha, beta, gamma, delta, epsilon, zeta},
// theta1, theta2, kappa, budgetB, policyVerb, policyResource, policyParamBound, expiresAt, notBefore, maxBlast, maxDepth, revMax,
// rateMax, allocParent. Weights, thresholds and bounds are the policy's own quantized integers; verb and resource map through
// the code catalog and revMax through the class order.
func QuantizePolicyStruct(policy any, opts ...map[string]any) ([]uint64, error) {
	o, err := zkOptsArg(opts)
	if err != nil {
		return nil, err
	}
	return zkQuantizePolicy(policy, o)
}

func zkQuantizePolicy(policy any, opts map[string]any) ([]uint64, error) {
	p, ok := policy.(map[string]any)
	if !ok {
		return nil, errors.New("policyvm quantize: policy is missing")
	}
	w, ok := p["weights"].(map[string]any)
	if !ok {
		return nil, errors.New("policyvm quantize: policy weights are missing")
	}
	strict := opts["strictCatalog"] == any(true)
	out := make([]uint64, 0, 20)
	num := func(v any, what string) (err error) {
		var x uint64
		if x, err = zkToU64(v, what); err == nil {
			out = append(out, x)
		}
		return err
	}
	for _, k := range []string{"alpha", "beta", "gamma", "delta", "epsilon", "zeta"} {
		if err := num(w[k], "w"+strings.ToUpper(k[:1])+k[1:]); err != nil {
			return nil, err
		}
	}
	for _, k := range []string{"theta1", "theta2", "kappa", "budgetB"} {
		if err := num(p[k], k); err != nil {
			return nil, err
		}
	}
	verb, err := zkCodeFor("verb", p["policyVerb"], opts["verbCodes"], strict)
	if err != nil {
		return nil, err
	}
	resource, err := zkCodeFor("resource", p["policyResource"], opts["resourceCodes"], strict)
	if err != nil {
		return nil, err
	}
	out = append(out, verb, resource)
	for _, k := range []string{"policyParamBound", "expiresAt", "notBefore", "maxBlast", "maxDepth"} {
		if err := num(p[k], k); err != nil {
			return nil, err
		}
	}
	rev, err := zkReversibilityIndex(p["revMax"], "revMax")
	if err != nil {
		return nil, err
	}
	out = append(out, rev)
	for _, k := range []string{"rateMax", "allocParent"} {
		if err := num(p[k], k); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// PolicyVmQuantizedStructs are the quantized struct field lists, ready for PolicyVmStructHash. Plan and Policy are nil when their
// inputs were not supplied.
type PolicyVmQuantizedStructs struct {
	Action []uint64 `json:"action"`
	Plan   []uint64 `json:"plan,omitempty"`
	Policy []uint64 `json:"policy,omitempty"`
}

// QuantizePolicyVmInputs derives the circuit's fixed action struct (always) and, when inp carries them, the plan and policy
// structs: inp is {action, plan?, policy?}. Deterministic and fail-closed.
func QuantizePolicyVmInputs(inp any, opts ...map[string]any) (out PolicyVmQuantizedStructs, err error) {
	o, err := zkOptsArg(opts)
	m, ok := inp.(map[string]any)
	if !ok || err != nil {
		return out, errors.New("policyvm quantize: the inputs are missing or the options are null")
	}
	if out.Action, err = zkQuantizeAction(m["action"], o); err != nil {
		return PolicyVmQuantizedStructs{}, err
	}
	if zkTruthy(m["plan"]) {
		if out.Plan, err = zkQuantizePlan(m["plan"], o); err != nil {
			return PolicyVmQuantizedStructs{}, err
		}
	}
	if zkTruthy(m["policy"]) {
		if out.Policy, err = zkQuantizePolicy(m["policy"], o); err != nil {
			return PolicyVmQuantizedStructs{}, err
		}
	}
	return out, nil
}

// PolicyVmCommitmentFromAction is the circuit's action commitment (its public halves actionHi / actionLo) recomputed from the live
// action: PolicyVmStructHash of QuantizeActionStruct. A resource server binds a Policy VM proof to this action by requiring the
// proof's action halves to equal it (the expectActionHash option of the backends), so a proof minted for another action is
// rejected.
func PolicyVmCommitmentFromAction(action any, opts ...map[string]any) (ZkDigestHalves, error) {
	q, err := QuantizeActionStruct(action, opts...)
	if err != nil {
		return ZkDigestHalves{}, err
	}
	return PolicyVmStructHash(q)
}

// ---- public signals: decoding and the context pins ------------------------------------------------------------------------------

func zkDecodePublic(publicSignals any, bound bool) (map[string]any, error) {
	ps, ok := publicSignals.([]any)
	if !ok {
		return nil, errors.New("decodePolicyVmPublic: the public signals must be a list")
	}
	L := zkLayoutOf(bound)
	put := func(m map[string]any, k string, i int) { // a signal past the end is left out
		if i < len(ps) {
			m[k] = ps[i]
		}
	}
	halves := func(hi int) map[string]any {
		h := map[string]any{}
		put(h, "hi", hi)
		put(h, "lo", hi+1)
		return h
	}
	out := map[string]any{"actionHash": halves(0), "policyHash": halves(2), "planHash": halves(4)}
	if bound {
		out["riskHash"] = halves(L.riskHi)
	}
	for k, i := range map[string]int{"r": L.r, "t": L.t, "admit": L.admit, "allow": L.allow, "now": L.now, "blast": L.blast,
		"delegationDepth": L.depth, "recentCount": L.recent, "allocChild": L.alloc} {
		put(out, k, i)
	}
	return out, nil
}

// DecodePolicyVmPublic decodes the public signals of a "pca-policyvm-v1" proof into the proven statement: {actionHash, policyHash,
// planHash (each {hi, lo}), r, t, admit, allow, now, blast, delegationDepth, recentCount, allocChild}. A signal the list does not
// reach is left out.
func DecodePolicyVmPublic(publicSignals any) (map[string]any, error) {
	return zkDecodePublic(publicSignals, false)
}

// DecodePolicyVmBoundPublic decodes the public signals of a "pca-policyvm-v2" proof: the v1 statement plus riskHash.
func DecodePolicyVmBoundPublic(publicSignals any) (map[string]any, error) {
	return zkDecodePublic(publicSignals, true)
}

// zkSignalBig reads a public signal as the integer a pin is compared with; ok is false unless it prints as a canonical decimal.
func zkSignalBig(signal any) (*big.Int, bool) {
	switch t := signal.(type) {
	case zkUndef:
		return nil, false
	case json.Number, float64:
		f, _ := jsNum(t)
		if !zkCanonDec(zkString(t)) {
			return nil, false
		}
		return zkFloatInt(f), true
	}
	s := zkString(signal)
	if !zkCanonDec(s) {
		return nil, false
	}
	return new(big.Int).SetString(s, 10)
}

// zkPinBig reads one pin value; a number must be a safe integer (a Go integer or *big.Int is exact).
func zkPinBig(v any) (*big.Int, bool) {
	switch v.(type) {
	case json.Number, float64:
		if !jsIsSafeInteger(v) {
			return nil, false
		}
	}
	b, err := zkBigInt(v)
	return b, err == nil
}

func zkSignalMatchesPin(signal, pin any) (bool, error) {
	x, ok := zkSignalBig(signal)
	if !ok {
		return false, nil
	}
	switch p := pin.(type) {
	case nil:
		return false, errors.New("policyVmContextMatches: a pin is null")
	case []any:
		return false, nil
	case map[string]any:
		lo, okLo := zkPinBig(zkProp(p, "min"))
		hi, okHi := zkPinBig(zkProp(p, "max"))
		return okLo && okHi && lo.Cmp(hi) <= 0 && x.Cmp(lo) >= 0 && x.Cmp(hi) <= 0, nil
	}
	want, ok := zkPinBig(pin)
	return ok && x.Cmp(want) == 0, nil
}

// PolicyVmContextMatches reports whether a proof's public signals satisfy the context the verifier requires. The circuit evaluates
// its caveats (expiry, not-before, rate, blast radius, delegation depth, budget allocation) on prover-supplied public inputs:
// without a pin a valid proof only says "the gate passes for some now / recentCount / ...". bound selects the "pca-policyvm-v2"
// layout.
//
// expect is optional. Given, it is the pins {now?, blast?, delegationDepth?, recentCount?, allocChild?, r?, t?, requireAdmit?,
// requireTier1?}, or a func() any (or func() map[string]any) returning them at each verification so that `now` can follow a
// clock; one that panics refuses. A pin is an exact value (an integer, a safe-integer number or a decimal string) or an inclusive
// window {min, max}. A verifier that serves real traffic should pin at least now and recentCount and set requireAdmit and
// requireTier1.
//
// Even with no pins, a context signal that is not a canonical decimal below 2^64 is refused: the circuit's comparators run on
// public inputs that are not range-checked, so a field-negative `now` would otherwise satisfy `now < expiresAt`. The error is
// for missing signals or a null pin, never a verdict.
func PolicyVmContextMatches(publicSignals any, bound bool, expect ...any) (bool, error) {
	if publicSignals == nil {
		return false, errors.New("policyVmContextMatches: the public signals are required")
	}
	ps, _ := publicSignals.([]any)
	L := zkLayoutOf(bound)
	for _, idx := range []int{L.now, L.blast, L.depth, L.recent, L.alloc} {
		if s, ok := zkIdx(ps, idx).(string); !ok || !zkCanonDecBelow(s, zkTwo64) {
			return false, nil
		}
	}
	if len(expect) == 0 {
		return true, nil
	}
	e := expect[0]
	call := func(f func() any) (v any, ok bool) {
		defer func() {
			if recover() != nil {
				v, ok = nil, false
			}
		}()
		return f(), true
	}
	ok := true
	switch f := e.(type) {
	case func() any:
		e, ok = call(f)
	case func() map[string]any:
		e, ok = call(func() any {
			if m := f(); m != nil {
				return m
			}
			return nil
		})
	}
	if !ok {
		return false, nil
	}
	m, isMap := e.(map[string]any)
	if _, isList := e.([]any); !isMap && !isList {
		return false, nil
	}
	for _, p := range []struct {
		name string
		idx  int
	}{{"now", L.now}, {"blast", L.blast}, {"delegationDepth", L.depth}, {"recentCount", L.recent}, {"allocChild", L.alloc}, {"r", L.r}, {"t", L.t}} {
		pin, pinned := m[p.name]
		if !pinned {
			continue
		}
		if ok, err := zkSignalMatchesPin(zkIdx(ps, p.idx), pin); err != nil || !ok {
			return false, err
		}
	}
	if zkTruthy(m["requireAdmit"]) && !zkIs(zkIdx(ps, L.admit), "1") {
		return false, nil
	}
	if zkTruthy(m["requireTier1"]) && !zkIs(zkIdx(ps, L.t), "1") {
		return false, nil
	}
	return true, nil
}

// ---- verification -----------------------------------------------------------------------------------------------------------

func zkReadJSONFile(path string) (any, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseJSONLenient(b)
}

// zkCircuitsPath resolves one of the reference's artifact paths under ATLAS_PCA_CIRCUITS_DIR.
func zkCircuitsPath(rel string) (string, error) {
	dir := os.Getenv("ATLAS_PCA_CIRCUITS_DIR")
	if dir == "" {
		return "", fmt.Errorf("zk: %s is not bundled: pass it explicitly or set ATLAS_PCA_CIRCUITS_DIR", rel)
	}
	return filepath.Join(dir, filepath.FromSlash(strings.TrimPrefix(rel, "circuits/"))), nil
}

// zkKeyOf resolves the verifying key: the explicit one, else the file at verificationKeyPath, else the bundled key, else the
// default file.
func zkKeyOf(opts map[string]any, bundled []byte, defaultRel string) (any, error) {
	if k := opts["verificationKey"]; k != nil {
		return k, nil
	}
	if p := opts["verificationKeyPath"]; p != nil {
		path, ok := p.(string)
		if !ok {
			return nil, errors.New("zk: verificationKeyPath must be a string")
		}
		return zkReadJSONFile(path)
	}
	if bundled != nil {
		return ParseJSONLenient(bundled)
	}
	path, err := zkCircuitsPath(defaultRel)
	if err != nil {
		return nil, err
	}
	return zkReadJSONFile(path)
}

// PolicyVmVerificationKey is the bundled BN254 verifying key of "pca-policyvm-v1" (a fresh copy of the parsed snarkjs key).
func PolicyVmVerificationKey() map[string]any {
	k, _ := ParseJSONLenient(zkPolicyVmVkeyJSON)
	m, _ := k.(map[string]any)
	return m
}

// PolicyVmBls12381VerificationKey is the bundled BLS12-381 verifying key of "pca-policyvm-v1".
func PolicyVmBls12381VerificationKey() map[string]any {
	k, _ := ParseJSONLenient(zkPolicyVmBls12381VkeyJSON)
	m, _ := k.(map[string]any)
	return m
}

// zkGroth16Check asks the backend the pairing question. Under the reference's rules the curve is the one the key names, read by
// the backend as the reference verifier reads it (Groth16CurveFromKey); strict mode takes exactly "bn128" or "bls12381", and a
// key naming anything else is refused.
func zkGroth16Check(vkey any, ps []any, proof any, strict bool) (bool, error) {
	curve := Groth16CurveFromKey
	if strict {
		switch name, _ := zkProp(vkey, "curve").(string); name {
		case "bn128":
			curve = Groth16CurveBn254
		case "bls12381":
			curve = Groth16CurveBls12381
		default:
			return false, nil
		}
	}
	ok, _, err := Groth16Verify(curve, vkey, proof, ps, strict)
	return ok && err == nil, err
}

// VerifyPolicyVmProof verifies a Policy VM Groth16 proof offline. env is the envelope {system: "groth16-bn254" |
// "groth16-bls12-381", circuit: "pca-policyvm-v1" | "pca-policyvm-v2", proof, publicSignals}; opts (nil for none) may carry
// verificationKey (the parsed snarkjs key; default the bundled key of the proof's curve, and for v2, which has none, the file
// PolicyVmBoundVkeyPath), verificationKeyPath, expect (the context pins, see PolicyVmContextMatches; a member that is present),
// expectRiskHash (the risk commitment, v2 only: with it a v1 proof or other halves are refused) and strict (true also refuses
// what the reference verifier lets pass in a key: another protocol tag, a wrong nPublic, surplus IC entries).
//
// The gates run in this order, each refusing with false: the envelope shape, the circuit and system tags (v2 is BN254 only),
// the signal count, allow == "1", the risk-hash pin, the canonical envelope gate, the context bounds and pins, then the pairing
// check through the Groth16 backend (any fault of the check itself is a refusal). The error is never a verdict:
// ErrGroth16BackendMissing when a proof passed every gate and no backend is installed, a key that cannot be loaded, or a null pin.
func VerifyPolicyVmProof(env any, opts map[string]any) (bool, error) {
	p, ok := env.(map[string]any)
	if !ok {
		return false, nil
	}
	bound := zkIs(p["circuit"], "pca-policyvm-v2")
	if !bound && !zkIs(p["circuit"], "pca-policyvm-v1") {
		return false, nil
	}
	bls := zkIs(p["system"], "groth16-bls12-381")
	if !zkIs(p["system"], "groth16-bn254") && !(bls && !bound) {
		return false, nil
	}
	L := zkLayoutOf(bound)
	ps, ok := p["publicSignals"].([]any)
	if !ok || len(ps) != L.count || p["proof"] == nil {
		return false, nil
	}
	if !zkIs(ps[L.allow], "1") {
		return false, nil
	}
	if want, pinned := opts["expectRiskHash"]; pinned {
		if !bound {
			return false, nil
		}
		if want == nil {
			return false, errors.New("verifyPolicyVmProof: expectRiskHash is null")
		}
		if hi, lo := zkHalvesOf(want); !zkEq(ps[L.riskHi], hi) || !zkEq(ps[L.riskHi+1], lo) {
			return false, nil
		}
	}
	curve := "bn254"
	if bls {
		curve = "bls12-381"
	}
	if !IsCanonicalGroth16Envelope(p, curve) {
		return false, nil
	}
	var expect []any
	if e, pinned := opts["expect"]; pinned {
		expect = []any{e}
	}
	if ok, err := PolicyVmContextMatches(ps, bound, expect...); err != nil || !ok {
		return false, err
	}
	bundled := zkPolicyVmVkeyJSON
	if bound {
		bundled = nil
	} else if bls {
		bundled = zkPolicyVmBls12381VkeyJSON
	}
	vkey, err := zkKeyOf(opts, bundled, PolicyVmBoundVkeyPath)
	if err != nil {
		return false, err
	}
	valid, err := zkGroth16Check(vkey, ps, p["proof"], opts["strict"] == any(true))
	if err != nil && !errors.Is(err, ErrGroth16BackendMissing) { // a fault of the pairing check is a refusal, as in the reference
		return false, nil
	}
	return valid, err
}

// ---- SNARK backends ---------------------------------------------------------------------------------------------------------

type zkBackend struct {
	label  AssuranceLabel
	verify func(in ZkSnarkInput) (bool, error)
}

// VerifySnark implements ZkSnarkBackend.
func (b *zkBackend) VerifySnark(in ZkSnarkInput) (bool, error) { return b.verify(in) }

// Assurance implements AssuranceLabeler.
func (b *zkBackend) Assurance() AssuranceLabel { return b.label }

// zkLazyKey resolves the backend's verifying key on first use and keeps it.
func zkLazyKey(opts map[string]any, bundled []byte, defaultRel string) func() (any, error) {
	var mu sync.Mutex
	var cached any
	return func() (any, error) {
		mu.Lock()
		defer mu.Unlock()
		if cached == nil {
			k, err := zkKeyOf(opts, bundled, defaultRel)
			if err != nil {
				return nil, err
			}
			cached = k
		}
		return cached, nil
	}
}

// zkCeremonyLabel is "multi-party" only for an explicit verifying key backed by pinned ceremony evidence for this circuit; the
// bundled keys are single-party.
func zkCeremonyLabel(opts map[string]any, circuit string) string {
	ev, ok := opts["ceremony"].(map[string]any)
	if !ok {
		return CeremonySingleParty
	}
	e := maps.Clone(ev)
	if e == nil {
		e = map[string]any{}
	}
	e["circuit"] = circuit
	return CeremonyOf(opts["verificationKey"], e)
}

// zkVerifyOpts are the options a backend hands to VerifyPolicyVmProof: its key, and the pins it was configured with.
func zkVerifyOpts(o map[string]any, vkey any, keep ...string) map[string]any {
	out := map[string]any{"verificationKey": vkey}
	for _, k := range keep {
		if v, has := o[k]; has {
			out[k] = v
		}
	}
	return out
}

// CreateGroth16SnarkBackend is the SNARK backend of "pca-compliance-v1" (BN254). It refuses anything that is not a well-formed
// envelope of that circuit with 7 public signals, requires the released-allow signal to be 1, binds the proof to this action,
// policy and plan (the circuit's public binding tags must equal CommitmentField of the public inputs), requires the canonical
// envelope, then checks the proof against the verifying key. opts (nil for none): verificationKey, verificationKeyPath (default
// the file ZkDefaultVkeyPath: no key of this circuit is bundled) and ceremony ({transcript, sha256}: evidence that the explicit
// key came from a multi-party ceremony; without it the label says "single-party"). Label: "groth16".
func CreateGroth16SnarkBackend(opts map[string]any) ZkSnarkBackend {
	o := maps.Clone(opts)
	key := zkLazyKey(o, nil, ZkDefaultVkeyPath)
	return &zkBackend{label: AssuranceLabel{Level: "groth16", Ceremony: zkCeremonyLabel(o, "pca-compliance-v1")}, verify: func(in ZkSnarkInput) (bool, error) {
		env, ok := in.Proof.(map[string]any)
		if !ok || !zkIs(env["system"], "groth16-bn254") || !zkIs(env["circuit"], "pca-compliance-v1") {
			return false, nil
		}
		ps, ok := env["publicSignals"].([]any)
		if !ok || len(ps) != 7 || env["proof"] == nil || !zkIs(ps[6], "1") {
			return false, nil
		}
		// signals 3..5 are the binding tags of the policy, plan and action commitments
		for i, commit := range []string{in.PolicyCommit, in.PlanCommit, in.ActionCommit} {
			tag, err := CommitmentField(commit)
			if err != nil {
				return false, err
			}
			if !zkIs(ps[3+i], tag) {
				return false, nil
			}
		}
		if !IsCanonicalGroth16Envelope(env, "bn254") {
			return false, nil
		}
		vkey, err := key()
		if err != nil {
			return false, err
		}
		return zkGroth16Check(vkey, ps, env["proof"], o["strict"] == any(true))
	}}
}

func zkPolicyVmBackend(opts map[string]any, bundled []byte) ZkSnarkBackend {
	o := maps.Clone(opts)
	key := zkLazyKey(o, bundled, "")
	// bound to this action, policy and plan only with all three hashes pinned; otherwise a valid proof may be for another action
	label := AssuranceLabel{Level: "unknown", Vendor: "policyvm-unbound"}
	if zkTruthy(o["expectActionHash"]) && zkTruthy(o["expectPolicyHash"]) && zkTruthy(o["expectPlanHash"]) {
		label = AssuranceLabel{Level: "policyvm_snark"}
	}
	label.Ceremony = zkCeremonyLabel(o, "pca-policyvm-v1")
	return &zkBackend{label: label, verify: func(in ZkSnarkInput) (bool, error) {
		if !zkIs(zkProp(in.Proof, "circuit"), "pca-policyvm-v1") {
			return false, nil
		}
		if ps, ok := zkProp(in.Proof, "publicSignals").([]any); ok {
			if !zkHalvesMatch(ps, 0, o["expectActionHash"]) || !zkHalvesMatch(ps, 2, o["expectPolicyHash"]) || !zkHalvesMatch(ps, 4, o["expectPlanHash"]) {
				return false, nil
			}
		}
		vkey, err := key()
		if err != nil {
			return false, err
		}
		return VerifyPolicyVmProof(in.Proof, zkVerifyOpts(o, vkey, "expect", "strict"))
	}}
}

// CreatePolicyVmSnarkBackend is the SNARK backend of the full Policy VM circuit "pca-policyvm-v1". It verifies the Groth16 proof
// with every gate of VerifyPolicyVmProof and, when expected struct hashes are supplied, binds the proof's public hash halves to
// them. It does not bind the canonical-JSON public inputs: the circuit commits to sha256 of a fixed-layout struct, another
// preimage, so pass the hashes instead (PolicyVmCommitmentFromAction, PolicyVmStructHash). opts (nil for none): verificationKey,
// verificationKeyPath (default the bundled BN254 key), expect, strict, ceremony, expectActionHash, expectPolicyHash,
// expectPlanHash (each a ZkDigestHalves or {hi, lo}). Label: "policyvm_snark" only with all three hashes pinned, else "unknown"
// with vendor "policyvm-unbound".
func CreatePolicyVmSnarkBackend(opts map[string]any) ZkSnarkBackend {
	return zkPolicyVmBackend(opts, zkPolicyVmVkeyJSON)
}

// CreatePolicyVmSnarkBackendBls12381 is CreatePolicyVmSnarkBackend for proofs minted over BLS12-381 (128-bit security): the same
// binding and gates, with the bundled BLS12-381 key as the default.
func CreatePolicyVmSnarkBackendBls12381(opts map[string]any) ZkSnarkBackend {
	return zkPolicyVmBackend(opts, zkPolicyVmBls12381VkeyJSON)
}

// CreatePolicyVmBoundSnarkBackend is the SNARK backend of the risk-bound circuit "pca-policyvm-v2" (BN254): the checks of
// CreatePolicyVmSnarkBackend on the action, policy and plan halves, plus the risk commitment (expectRiskHash, from
// PolicyVmRiskHash over the attested risk magnitudes). Label: "policyvm_snark" only with all four commitments pinned. No key of
// this circuit is bundled: pass verificationKey or verificationKeyPath, or the file PolicyVmBoundVkeyPath is read.
func CreatePolicyVmBoundSnarkBackend(opts map[string]any) ZkSnarkBackend {
	o := maps.Clone(opts)
	key := zkLazyKey(o, nil, PolicyVmBoundVkeyPath)
	label := AssuranceLabel{Level: "unknown", Vendor: "policyvm-unbound"}
	if zkTruthy(o["expectActionHash"]) && zkTruthy(o["expectPolicyHash"]) && zkTruthy(o["expectPlanHash"]) && zkTruthy(o["expectRiskHash"]) {
		label = AssuranceLabel{Level: "policyvm_snark"}
	}
	label.Ceremony = zkCeremonyLabel(o, "pca-policyvm-v2")
	return &zkBackend{label: label, verify: func(in ZkSnarkInput) (bool, error) {
		ps, ok := zkProp(in.Proof, "publicSignals").([]any)
		if !ok || !zkIs(zkProp(in.Proof, "circuit"), "pca-policyvm-v2") {
			return false, nil
		}
		if !zkHalvesMatch(ps, 0, o["expectActionHash"]) || !zkHalvesMatch(ps, 2, o["expectPolicyHash"]) || !zkHalvesMatch(ps, 4, o["expectPlanHash"]) ||
			!zkHalvesMatch(ps, zkLayoutV2.riskHi, o["expectRiskHash"]) {
			return false, nil
		}
		vkey, err := key()
		if err != nil {
			return false, err
		}
		return VerifyPolicyVmProof(in.Proof, zkVerifyOpts(o, vkey, "expect", "strict", "expectRiskHash"))
	}}
}

// ---- circuit versions -------------------------------------------------------------------------------------------------------

// ZkCircuitVersion is the version record of one circuit: SourceSha256 is the SHA-256 over the circuit's whole source set (its own
// files, its includes, the circomlib files) plus the pinned compiler.
type ZkCircuitVersion struct {
	Circuit      string `json:"circuit"`
	SourceSha256 string `json:"sourceSha256"`
	Circom       string `json:"circom"`
	Circomlib    string `json:"circomlib"`
}

// CircuitVersion is the committed version of a circuit id ("pca-compliance-v1", "pca-policyvm-v1", "pca-policyvm-v2"), from the
// bundled version table; an unknown id is an error.
func CircuitVersion(id string) (ZkCircuitVersion, error) {
	table, err := ParseJSONLenient(zkCircuitVersionsJSON)
	if err != nil {
		return ZkCircuitVersion{}, err
	}
	src, ok := zkProp(zkProp(zkProp(table, "circuits"), id), "source_sha256").(string)
	if !ok {
		return ZkCircuitVersion{}, fmt.Errorf("circuitVersion: unknown circuit %q", id)
	}
	circom, _ := zkProp(table, "circom").(string)
	circomlib, _ := zkProp(table, "circomlib").(string)
	return ZkCircuitVersion{Circuit: id, SourceSha256: src, Circom: circom, Circomlib: circomlib}, nil
}

// ---- proving ----------------------------------------------------------------------------------------------------------------

// zkWitnessString is how a witness value is handed to the circuit: its decimal text.
func zkWitnessString(v any) string {
	switch t := v.(type) {
	case *big.Int:
		return t.String()
	case uint64, int, int64:
		return fmt.Sprint(t)
	}
	return zkString(v)
}

func zkArtifact(opts map[string]any, member, defaultRel string) ([]byte, error) {
	path, ok := opts[member].(string)
	if !ok {
		var err error
		if path, err = zkCircuitsPath(defaultRel); err != nil {
			return nil, err
		}
	}
	return os.ReadFile(path)
}

// zkProve runs the circuit's witness program and prover through the Groth16 backend and wraps the result in the envelope.
func zkProve(input map[string]string, opts map[string]any, wasmRel, zkeyRel, circuit string) (map[string]any, error) {
	if b := GetGroth16Backend(); b == nil || b.Prove == nil { // before the proving key (it is large) is read
		return nil, ErrGroth16BackendMissing
	}
	wasm, err := zkArtifact(opts, "wasmPath", wasmRel)
	if err != nil {
		return nil, err
	}
	zkey, err := zkArtifact(opts, "zkeyPath", zkeyRel)
	if err != nil {
		return nil, err
	}
	in, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	raw, err := Groth16Prove(Groth16CurveBn254, wasm, zkey, in, nil)
	if err != nil {
		return nil, err
	}
	out, err := ParseJSONLenient(raw)
	if err != nil {
		return nil, err
	}
	ps, ok := zkProp(out, "publicSignals").([]any)
	proof := zkOrNull(zkProp(out, "proof"))
	if !ok || proof == nil {
		return nil, errors.New("zk: the prover returned no proof")
	}
	return map[string]any{"system": "groth16-bn254", "circuit": circuit, "proof": proof, "publicSignals": ps}, nil
}

// ProveGroth16Compliance generates a "pca-compliance-v1" proof through the Groth16 backend. inp carries the commitments the proof
// must bind to (action_commit, policy_commit, plan_commit: base64url sha256) and the private witness: verb, resource, planVerb,
// policySalt, planSalt, actionSalt, risk, budget. opts (nil for none): wasmPath, zkeyPath (defaults: the files ZkDefaultWasmPath
// and ZkDefaultZkeyPath). A witness that is not compliant (verb mismatch, risk > budget) cannot be proven: the error is the
// prover's. The result is the envelope a PCActn carries in zk_compliance.
func ProveGroth16Compliance(inp map[string]any, opts map[string]any) (map[string]any, error) {
	input := map[string]string{"allow": "1"}
	for _, k := range []string{"verb", "resource", "planVerb", "policySalt", "planSalt", "actionSalt", "risk", "budget"} {
		v, has := inp[k]
		if !has || v == nil {
			return nil, fmt.Errorf("proveGroth16Compliance: the witness has no %s", k)
		}
		input[k] = zkWitnessString(v)
	}
	for tag, k := range map[string]string{"shaPolicy": "policy_commit", "shaPlan": "plan_commit", "shaAction": "action_commit"} {
		commit, isStr := inp[k].(string)
		f, err := CommitmentField(commit)
		if !isStr || err != nil {
			return nil, fmt.Errorf("proveGroth16Compliance: %s is not a base64url commitment", k)
		}
		input[tag] = f
	}
	return zkProve(input, opts, ZkDefaultWasmPath, ZkDefaultZkeyPath, "pca-compliance-v1")
}

func zkProveWitness(witness, opts map[string]any, wasmRel, zkeyRel, circuit string) (map[string]any, error) {
	input := make(map[string]string, len(witness))
	for k, v := range witness {
		input[k] = zkWitnessString(v)
	}
	return zkProve(input, opts, wasmRel, zkeyRel, circuit)
}

// ProvePolicyVmCompliance generates a "pca-policyvm-v1" proof (BN254) from the complete fixed-point witness: every circuit input,
// the division witnesses included. opts (nil for none): wasmPath, zkeyPath (defaults: the files PolicyVmWasmPath and
// PolicyVmZkeyPath, which the circuit setup produces; the bundled verifying key is enough to verify). A denied action cannot be
// proven.
func ProvePolicyVmCompliance(witness map[string]any, opts map[string]any) (map[string]any, error) {
	return zkProveWitness(witness, opts, PolicyVmWasmPath, PolicyVmZkeyPath, "pca-policyvm-v1")
}

// ProvePolicyVmBoundCompliance generates a risk-bound "pca-policyvm-v2" proof; same witness inputs as ProvePolicyVmCompliance
// (defaults: the files PolicyVmBoundWasmPath and PolicyVmBoundZkeyPath).
func ProvePolicyVmBoundCompliance(witness map[string]any, opts map[string]any) (map[string]any, error) {
	return zkProveWitness(witness, opts, PolicyVmBoundWasmPath, PolicyVmBoundZkeyPath, "pca-policyvm-v2")
}
