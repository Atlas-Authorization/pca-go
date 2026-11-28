// Package sealkit is the homomorphic risk gate (BFV on Microsoft SEAL) for Go, wire-compatible with the TypeScript package
// (node-seal 5.1.x bundles SEAL 4.1.x; stream headers carry major.minor only). It binds SEAL's own C export API through cgo, a
// separate module so the core stays cgo-free. A tagged release carries libsealc under lib/<os>_<arch>/ (linux and macOS, amd64 and arm64, found through an rpath; windows amd64 as sealc.dll, which must sit next to the executable or on PATH), so there is
// nothing to build; otherwise build libsealc from the pinned SEAL tag (build-libsealc.sh in the CI scripts) and point CGO_LDFLAGS at it. BFV is never reimplemented here: every lattice operation is SEAL.
package sealkit

/*
#cgo linux,amd64 LDFLAGS: -L${SRCDIR}/lib/linux_amd64 -Wl,-rpath,${SRCDIR}/lib/linux_amd64
#cgo linux,arm64 LDFLAGS: -L${SRCDIR}/lib/linux_arm64 -Wl,-rpath,${SRCDIR}/lib/linux_arm64
#cgo darwin,amd64 LDFLAGS: -L${SRCDIR}/lib/darwin_amd64 -Wl,-rpath,${SRCDIR}/lib/darwin_amd64
#cgo darwin,arm64 LDFLAGS: -L${SRCDIR}/lib/darwin_arm64 -Wl,-rpath,${SRCDIR}/lib/darwin_arm64
#cgo windows,amd64 LDFLAGS: -L${SRCDIR}/lib/windows_amd64
#cgo LDFLAGS: -lsealc
#include "sealc.h"
*/
import "C"

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"regexp"
	"unsafe"
)

const (
	PolyModulusDegree = 8192
	PlainModulusBits  = 30
	PlainModulus      = 1073692673
	SignedBound       = PlainModulus / 2
	RiskDim           = 6

	minNoiseBudgetBits = 16
	schemeBFV          = 1
	secLevelTC128      = 128
	comprNone          = 0
	comprZstd          = 2
)

// Policy is the public gate policy: fixed-point weights, kappa-weighted weights and the budget bound (scale S, budget at S^2).
type Policy struct {
	Scale              int64
	Dim                int64
	WeightsScaled      []int64
	KappaWeightsScaled []int64
	BudgetScaled       int64
	Kappa              float64
}

// Keyset is the full key material; the key holder keeps SecretKey, the evaluator gets only the public parts.
type Keyset struct{ SecretKey, PublicKey, RelinKeys, GaloisKeys string }

// EvalKeys is what an evaluator is given (no secret key).
type EvalKeys struct{ PublicKey, RelinKeys, GaloisKeys string }

// EncryptedGate is the two encrypted gate outputs (base64 SEAL streams).
type EncryptedGate struct{ EncRiskRaw, EncSlack string }

// Verdict is the opened verdict: RScaled is r at scale S^2 clamped to [0,S^2]; Admit is slack >= 0.
type Verdict struct {
	RScaled, Slack int64
	Admit          bool
}

func chk(op string, hr C.long) error {
	if hr < 0 { // SEAL's HRESULT convention: negative is failure, S_FALSE (1) is success
		return fmt.Errorf("seal %s failed: 0x%08x", op, uint32(hr))
	}
	return nil
}

// scope releases native handles in reverse order on every exit path.
type scope struct{ fns []func() }

func (s *scope) add(f func()) { s.fns = append(s.fns, f) }
func (s *scope) close() {
	for i := len(s.fns) - 1; i >= 0; i-- {
		s.fns[i]()
	}
	s.fns = nil
}

type ctx struct {
	context, encoder unsafe.Pointer
	slots            int
}

var b64Re = regexp.MustCompile(`^[A-Za-z0-9+/]*={0,2}$`)

// AssertSealBlob rejects anything that is not a well-formed SEAL stream envelope (magic, header size, compression mode, declared size
// equal to the length) before SEAL parses it, and returns the raw bytes.
func AssertSealBlob(blob, what string) ([]byte, error) {
	if len(blob) < 24 || len(blob)%4 != 0 || !b64Re.MatchString(blob) {
		return nil, fmt.Errorf("%s: not a serialized SEAL object (bad encoding)", what)
	}
	b, err := base64.StdEncoding.DecodeString(blob)
	if err != nil || len(b) < 16 || b[0] != 0x5e || b[1] != 0xa1 || b[2] != 16 || b[5] > 2 || b[6] != 0 || b[7] != 0 {
		return nil, fmt.Errorf("%s: not a serialized SEAL object (bad header)", what)
	}
	if size := binary.LittleEndian.Uint64(b[8:16]); size != uint64(len(b)) {
		return nil, fmt.Errorf("%s: truncated or padded SEAL object (declared %d bytes, got %d)", what, size, len(b))
	}
	return b, nil
}

// RequirePolicy validates a policy that crossed a trust boundary exactly as the policy builder would have produced it.
func RequirePolicy(p *Policy) error {
	if p == nil {
		return errors.New("policy must be an object")
	}
	if p.Scale <= 0 {
		return errors.New("policy.Scale must be a positive integer")
	}
	for _, v := range append(append([]int64{p.BudgetScaled}, p.WeightsScaled...), p.KappaWeightsScaled...) {
		if v <= -SignedBound || v >= SignedBound {
			return errors.New("policy coefficients must be integers with |value| < SignedBound")
		}
	}
	if p.Dim != RiskDim {
		return fmt.Errorf("policy.Dim must be %d", RiskDim)
	}
	if len(p.WeightsScaled) != RiskDim || len(p.KappaWeightsScaled) != RiskDim {
		return fmt.Errorf("policy weight vectors must have length %d", RiskDim)
	}
	return nil
}

// newCtx builds the deterministic BFV context (N=8192, BFVDefault 128-bit coefficient modulus, batching plain modulus 30 bits).
func newCtx(s *scope) (*ctx, error) {
	var parms unsafe.Pointer
	if err := chk("EncParams_Create", C.EncParams_Create1(schemeBFV, &parms)); err != nil {
		return nil, err
	}
	s.add(func() { C.EncParams_Destroy(parms) })
	if err := chk("SetPolyModulusDegree", C.EncParams_SetPolyModulusDegree(parms, PolyModulusDegree)); err != nil {
		return nil, err
	}
	var n C.uint64_t
	if err := chk("BFVDefault(length)", C.CoeffModulus_BFVDefault(PolyModulusDegree, secLevelTC128, &n, nil)); err != nil {
		return nil, err
	}
	coeffs := make([]unsafe.Pointer, n)
	if err := chk("BFVDefault", C.CoeffModulus_BFVDefault(PolyModulusDegree, secLevelTC128, &n, &coeffs[0])); err != nil {
		return nil, err
	}
	for _, m := range coeffs {
		m := m
		s.add(func() { C.Modulus_Destroy(m) })
	}
	if err := chk("SetCoeffModulus", C.EncParams_SetCoeffModulus(parms, n, &coeffs[0])); err != nil {
		return nil, err
	}
	bits := C.int(PlainModulusBits)
	var plain unsafe.Pointer
	if err := chk("PlainModulus.Batching", C.CoeffModulus_Create1(PolyModulusDegree, 1, &bits, &plain)); err != nil {
		return nil, err
	}
	s.add(func() { C.Modulus_Destroy(plain) })
	var live C.uint64_t
	if err := chk("Modulus_Value", C.Modulus_Value(plain, &live)); err != nil {
		return nil, err
	}
	if live != PlainModulus {
		return nil, fmt.Errorf("plain modulus drift: live %d != documented %d", uint64(live), uint64(PlainModulus))
	}
	if err := chk("SetPlainModulus", C.EncParams_SetPlainModulus1(parms, plain)); err != nil {
		return nil, err
	}
	c := &ctx{}
	if err := chk("SEALContext_Create", C.SEALContext_Create(parms, true, secLevelTC128, &c.context)); err != nil {
		return nil, err
	}
	s.add(func() { C.SEALContext_Destroy(c.context) })
	var ok C.bool
	if err := chk("ParametersSet", C.SEALContext_ParametersSet(c.context, &ok)); err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("SEAL rejected the BFV parameters")
	}
	if err := chk("BatchEncoder_Create", C.BatchEncoder_Create(c.context, &c.encoder)); err != nil {
		return nil, err
	}
	s.add(func() { C.BatchEncoder_Destroy(c.encoder) })
	var sc C.uint64_t
	if err := chk("SlotCount", C.BatchEncoder_GetSlotCount(c.encoder, &sc)); err != nil {
		return nil, err
	}
	c.slots = int(sc)
	return c, nil
}

func newPlain(s *scope) (unsafe.Pointer, error) {
	var p unsafe.Pointer
	if err := chk("Plaintext_Create", C.Plaintext_Create1(nil, &p)); err != nil {
		return nil, err
	}
	s.add(func() { C.Plaintext_Destroy(p) })
	return p, nil
}

func newCipher(s *scope) (unsafe.Pointer, error) {
	var p unsafe.Pointer
	if err := chk("Ciphertext_Create", C.Ciphertext_Create1(nil, &p)); err != nil {
		return nil, err
	}
	s.add(func() { C.Ciphertext_Destroy(p) })
	return p, nil
}

func copyCipher(s *scope, src unsafe.Pointer) (unsafe.Pointer, error) {
	var p unsafe.Pointer
	if err := chk("Ciphertext_Create2", C.Ciphertext_Create2(src, &p)); err != nil {
		return nil, err
	}
	s.add(func() { C.Ciphertext_Destroy(p) })
	return p, nil
}

func encode(c *ctx, s *scope, values []int64) (unsafe.Pointer, error) {
	slots := make([]int64, c.slots)
	copy(slots, values)
	pt, err := newPlain(s)
	if err != nil {
		return nil, err
	}
	if err := chk("Encode", C.BatchEncoder_Encode2(c.encoder, C.uint64_t(len(slots)), (*C.int64_t)(unsafe.Pointer(&slots[0])), pt)); err != nil {
		return nil, err
	}
	return pt, nil
}

// object kinds that share the save/load plumbing (GaloisKeys and RelinKeys are KSwitchKeys in the C API, exactly as in SEAL.NET)
type kind int

const (
	kPublic kind = iota
	kSecret
	kKeys
	kCipher
)

func newObj(s *scope, k kind) (unsafe.Pointer, error) {
	var p unsafe.Pointer
	var hr C.long
	switch k {
	case kPublic:
		hr = C.PublicKey_Create1(&p)
		s.add(func() { C.PublicKey_Destroy(p) })
	case kSecret:
		hr = C.SecretKey_Create1(&p)
		s.add(func() { C.SecretKey_Destroy(p) })
	case kKeys:
		hr = C.KSwitchKeys_Create1(&p)
		s.add(func() { C.KSwitchKeys_Destroy(p) })
	default:
		return newCipher(s)
	}
	if err := chk("create", hr); err != nil {
		return nil, err
	}
	return p, nil
}

func loadObj(c *ctx, s *scope, k kind, blob, what string) (unsafe.Pointer, error) {
	raw, err := AssertSealBlob(blob, what)
	if err != nil {
		return nil, err
	}
	p, err := newObj(s, k)
	if err != nil {
		return nil, err
	}
	in, sz := (*C.uint8_t)(unsafe.Pointer(&raw[0])), C.uint64_t(len(raw))
	var used C.int64_t
	var hr C.long
	switch k {
	case kPublic:
		hr = C.PublicKey_Load(p, c.context, in, sz, &used)
	case kSecret:
		hr = C.SecretKey_Load(p, c.context, in, sz, &used)
	case kKeys:
		hr = C.KSwitchKeys_Load(p, c.context, in, sz, &used)
	default:
		hr = C.Ciphertext_Load(p, c.context, in, sz, &used)
	}
	if err := chk("load "+what, hr); err != nil {
		return nil, err
	}
	return p, nil
}

func saveObj(k kind, p unsafe.Pointer, compr uint8) (string, error) {
	var size C.int64_t
	var hr C.long
	switch k {
	case kPublic:
		hr = C.PublicKey_SaveSize(p, C.uint8_t(compr), &size)
	case kSecret:
		hr = C.SecretKey_SaveSize(p, C.uint8_t(compr), &size)
	case kKeys:
		hr = C.KSwitchKeys_SaveSize(p, C.uint8_t(compr), &size)
	default:
		hr = C.Ciphertext_SaveSize(p, C.uint8_t(compr), &size)
	}
	if err := chk("save size", hr); err != nil {
		return "", err
	}
	buf := make([]byte, int(size))
	out, n := (*C.uint8_t)(unsafe.Pointer(&buf[0])), C.int64_t(0)
	switch k {
	case kPublic:
		hr = C.PublicKey_Save(p, out, C.uint64_t(size), C.uint8_t(compr), &n)
	case kSecret:
		hr = C.SecretKey_Save(p, out, C.uint64_t(size), C.uint8_t(compr), &n)
	case kKeys:
		hr = C.KSwitchKeys_Save(p, out, C.uint64_t(size), C.uint8_t(compr), &n)
	default:
		hr = C.Ciphertext_Save(p, out, C.uint64_t(size), C.uint8_t(compr), &n)
	}
	if err := chk("save", hr); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf[:int(n)]), nil
}

// Keygen generates the key material (the secret key stays with the policy owner).
func Keygen() (*Keyset, error) {
	s := &scope{}
	defer s.close()
	c, err := newCtx(s)
	if err != nil {
		return nil, err
	}
	var gen, sk, pk, rk, gk unsafe.Pointer
	if err := chk("KeyGenerator_Create", C.KeyGenerator_Create1(c.context, &gen)); err != nil {
		return nil, err
	}
	s.add(func() { C.KeyGenerator_Destroy(gen) })
	if err := chk("SecretKey", C.KeyGenerator_SecretKey(gen, &sk)); err != nil {
		return nil, err
	}
	s.add(func() { C.SecretKey_Destroy(sk) })
	if err := chk("CreatePublicKey", C.KeyGenerator_CreatePublicKey(gen, false, &pk)); err != nil {
		return nil, err
	}
	s.add(func() { C.PublicKey_Destroy(pk) })
	if err := chk("CreateRelinKeys", C.KeyGenerator_CreateRelinKeys(gen, false, &rk)); err != nil {
		return nil, err
	}
	s.add(func() { C.KSwitchKeys_Destroy(rk) })
	if err := chk("CreateGaloisKeys", C.KeyGenerator_CreateGaloisKeysAll(gen, false, &gk)); err != nil {
		return nil, err
	}
	s.add(func() { C.KSwitchKeys_Destroy(gk) })
	ks := &Keyset{}
	for _, it := range []struct {
		dst *string
		k   kind
		p   unsafe.Pointer
	}{{&ks.SecretKey, kSecret, sk}, {&ks.PublicKey, kPublic, pk}, {&ks.RelinKeys, kKeys, rk}, {&ks.GaloisKeys, kKeys, gk}} {
		if *it.dst, err = saveObj(it.k, it.p, comprZstd); err != nil {
			return nil, err
		}
	}
	return ks, nil
}

// EncryptRiskInputs BFV-encrypts the quantized risk-input vector (length 6, each a non-negative integer below the signed bound).
func EncryptRiskInputs(publicKey string, inputsScaled []int64) (string, error) {
	if len(inputsScaled) != RiskDim {
		return "", fmt.Errorf("inputsScaled must have length %d", RiskDim)
	}
	for _, v := range inputsScaled {
		if v < 0 || v >= SignedBound {
			return "", errors.New("each scaled input must be a non-negative integer below the signed bound")
		}
	}
	s := &scope{}
	defer s.close()
	c, err := newCtx(s)
	if err != nil {
		return "", err
	}
	pk, err := loadObj(c, s, kPublic, publicKey, "publicKey")
	if err != nil {
		return "", err
	}
	var enc unsafe.Pointer
	if err := chk("Encryptor_Create", C.Encryptor_Create(c.context, pk, nil, &enc)); err != nil {
		return "", err
	}
	s.add(func() { C.Encryptor_Destroy(enc) })
	pt, err := encode(c, s, inputsScaled)
	if err != nil {
		return "", err
	}
	ct, err := newCipher(s)
	if err != nil {
		return "", err
	}
	if err := chk("Encrypt", C.Encryptor_Encrypt(enc, pt, ct, nil)); err != nil {
		return "", err
	}
	return saveObj(kCipher, ct, comprZstd)
}

// EvalRiskGate evaluates the gate blind, with the reference's operation order: multiplyPlain, sumElements (rotateColumns+add, then
// rotateRows/rotateColumns/add for steps N/4..1), negate, addPlain. It never constructs a decryptor.
func EvalRiskGate(keys *EvalKeys, encInputs string, policy *Policy) (*EncryptedGate, error) {
	if err := RequirePolicy(policy); err != nil {
		return nil, err
	}
	if keys == nil {
		return nil, errors.New("evalKeys must be an object")
	}
	s := &scope{}
	defer s.close()
	c, err := newCtx(s)
	if err != nil {
		return nil, err
	}
	gk, err := loadObj(c, s, kKeys, keys.GaloisKeys, "galoisKeys")
	if err != nil {
		return nil, err
	}
	pk, err := loadObj(c, s, kPublic, keys.PublicKey, "publicKey")
	if err != nil {
		return nil, err
	}
	var ev, enc unsafe.Pointer
	if err := chk("Evaluator_Create", C.Evaluator_Create(c.context, &ev)); err != nil {
		return nil, err
	}
	s.add(func() { C.Evaluator_Destroy(ev) })
	if err := chk("Encryptor_Create", C.Encryptor_Create(c.context, pk, nil, &enc)); err != nil {
		return nil, err
	}
	s.add(func() { C.Encryptor_Destroy(enc) })
	x, err := loadObj(c, s, kCipher, encInputs, "encInputs")
	if err != nil {
		return nil, err
	}

	sum := func(prod unsafe.Pointer) (unsafe.Pointer, error) {
		temp, err := copyCipher(s, prod)
		if err != nil {
			return nil, err
		}
		dest, err := newCipher(s)
		if err != nil {
			return nil, err
		}
		if err := chk("RotateColumns", C.Evaluator_RotateColumns(ev, temp, gk, dest, nil)); err != nil {
			return nil, err
		}
		if err := chk("Add", C.Evaluator_Add(ev, temp, dest, temp)); err != nil {
			return nil, err
		}
		for steps := PolyModulusDegree / 4; steps >= 1; steps /= 2 {
			if err := chk("RotateRows", C.Evaluator_RotateRows(ev, temp, C.int(steps), gk, dest, nil)); err != nil {
				return nil, err
			}
			if err := chk("RotateColumns", C.Evaluator_RotateColumns(ev, dest, gk, dest, nil)); err != nil {
				return nil, err
			}
			if err := chk("Add", C.Evaluator_Add(ev, temp, dest, temp)); err != nil {
				return nil, err
			}
		}
		return temp, nil
	}
	// SEAL refuses multiplyPlain by an all-zero plaintext (transparent result); the dot product is then a fresh encryption of zero.
	dot := func(coeffs []int64) (unsafe.Pointer, error) {
		zero := true
		for _, v := range coeffs {
			zero = zero && v == 0
		}
		if zero {
			z, err := encode(c, s, nil)
			if err != nil {
				return nil, err
			}
			ct, err := newCipher(s)
			if err != nil {
				return nil, err
			}
			return ct, chk("Encrypt", C.Encryptor_Encrypt(enc, z, ct, nil))
		}
		pt, err := encode(c, s, coeffs)
		if err != nil {
			return nil, err
		}
		prod, err := newCipher(s)
		if err != nil {
			return nil, err
		}
		if err := chk("MultiplyPlain", C.Evaluator_MultiplyPlain(ev, x, pt, prod, nil)); err != nil {
			return nil, err
		}
		return sum(prod)
	}

	riskRaw, err := dot(policy.WeightsScaled)
	if err != nil {
		return nil, err
	}
	kappaRisk, err := dot(policy.KappaWeightsScaled)
	if err != nil {
		return nil, err
	}
	neg, err := newCipher(s)
	if err != nil {
		return nil, err
	}
	if err := chk("Negate", C.Evaluator_Negate(ev, kappaRisk, neg)); err != nil {
		return nil, err
	}
	budget, err := encode(c, s, []int64{policy.BudgetScaled})
	if err != nil {
		return nil, err
	}
	slack, err := newCipher(s)
	if err != nil {
		return nil, err
	}
	if err := chk("AddPlain", C.Evaluator_AddPlain(ev, neg, budget, slack)); err != nil {
		return nil, err
	}
	g := &EncryptedGate{}
	if g.EncRiskRaw, err = saveObj(kCipher, riskRaw, comprZstd); err != nil {
		return nil, err
	}
	if g.EncSlack, err = saveObj(kCipher, slack, comprZstd); err != nil {
		return nil, err
	}
	return g, nil
}

// DecryptVerdict decrypts the gate outputs and reads the verdict; it fails closed when the noise budget is exhausted (wrong key,
// corrupt or foreign ciphertext).
func DecryptVerdict(secretKey, encRiskRaw, encSlack string, policy *Policy) (*Verdict, error) {
	if err := RequirePolicy(policy); err != nil {
		return nil, err
	}
	s := &scope{}
	defer s.close()
	c, err := newCtx(s)
	if err != nil {
		return nil, err
	}
	sk, err := loadObj(c, s, kSecret, secretKey, "secretKey")
	if err != nil {
		return nil, err
	}
	var dec unsafe.Pointer
	if err := chk("Decryptor_Create", C.Decryptor_Create(c.context, sk, &dec)); err != nil {
		return nil, err
	}
	s.add(func() { C.Decryptor_Destroy(dec) })
	ctR, err := loadObj(c, s, kCipher, encRiskRaw, "encRiskRaw")
	if err != nil {
		return nil, err
	}
	ctS, err := loadObj(c, s, kCipher, encSlack, "encSlack")
	if err != nil {
		return nil, err
	}
	for _, ct := range []unsafe.Pointer{ctR, ctS} {
		var nb C.int
		if err := chk("InvariantNoiseBudget", C.Decryptor_InvariantNoiseBudget(dec, ct, &nb)); err != nil {
			return nil, err
		}
		if nb < minNoiseBudgetBits {
			return nil, errors.New("DecryptVerdict: ciphertext has no noise budget left (wrong key, corrupted, or not produced by the gate)")
		}
	}
	first := func(ct unsafe.Pointer) (int64, error) {
		pt, err := newPlain(s)
		if err != nil {
			return 0, err
		}
		if err := chk("Decrypt", C.Decryptor_Decrypt(dec, ct, pt)); err != nil {
			return 0, err
		}
		// the buffer holds every slot and count tells the encoder its size: a nil-buffer probe leaves the count at zero in this build
		out := make([]int64, c.slots)
		n := C.uint64_t(len(out))
		if err := chk("Decode", C.BatchEncoder_Decode2(c.encoder, pt, &n, (*C.int64_t)(unsafe.Pointer(&out[0])), nil)); err != nil {
			return 0, err
		}
		if n == 0 {
			return 0, errors.New("decode returned no slots")
		}
		return out[0], nil
	}
	raw, err := first(ctR)
	if err != nil {
		return nil, err
	}
	slack, err := first(ctS)
	if err != nil {
		return nil, err
	}
	cp := policy.Scale * policy.Scale
	r := raw
	if r < 0 {
		r = 0
	} else if r > cp {
		r = cp
	}
	return &Verdict{RScaled: r, Slack: slack, Admit: slack >= 0}, nil
}

// CanonicalCipher re-saves a base64 SEAL ciphertext uncompressed, for byte comparison independent of the zstd build.
func CanonicalCipher(blob string) (string, error) {
	s := &scope{}
	defer s.close()
	c, err := newCtx(s)
	if err != nil {
		return "", err
	}
	ct, err := loadObj(c, s, kCipher, blob, "ciphertext")
	if err != nil {
		return "", err
	}
	return saveObj(kCipher, ct, comprNone)
}
