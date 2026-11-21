// Package lweotkit is the post-quantum endemic (Masny-Rindal) base OT for Go, wire-compatible with the TypeScript package's MPC endemic OT.
// Every lattice operation (Kyber-768 K-PKE keygen, CPA encrypt and decrypt, the ring helpers) is the audited pqc_kyber reference, reached through
// cgo over the small C library liblweot (pca_lwe_ot.h, built from the flagship's crate with cargo build --features capi). A separate module so
// the core stays cgo-free. A tagged release carries liblweot as a static archive under lib/<os>_<arch>/ (linux, macOS and windows amd64, linux and macOS arm64), so there is nothing to build; otherwise point CGO_LDFLAGS (-L) and LD_LIBRARY_PATH at the directory holding liblweot.
package lweotkit

/*
#cgo linux,amd64 LDFLAGS: -L${SRCDIR}/lib/linux_amd64
#cgo linux,arm64 LDFLAGS: -L${SRCDIR}/lib/linux_arm64
#cgo darwin,amd64 LDFLAGS: -L${SRCDIR}/lib/darwin_amd64
#cgo darwin,arm64 LDFLAGS: -L${SRCDIR}/lib/darwin_arm64
#cgo linux LDFLAGS: -llweot -ldl -lpthread -lm
#cgo darwin LDFLAGS: -llweot -lm -liconv -framework Security -framework CoreFoundation
#cgo windows,amd64 LDFLAGS: -L${SRCDIR}/lib/windows_amd64 -llweot -lws2_32 -luserenv -lntdll -lbcrypt -ladvapi32
#cgo !linux,!darwin,!windows LDFLAGS: -llweot
#include "pca_lwe_ot.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"
)

// Kyber-768 sizes (bytes). init refuses to run against a library built with different ones.
const (
	PKBytes   = 1184
	SKBytes   = 1152
	CTBytes   = 1088
	TVecBytes = 1152
	SymBytes  = 32
	HashinCap = 4096
)

func init() {
	if int(C.lweot_len_pk()) != PKBytes || int(C.lweot_len_sk()) != SKBytes || int(C.lweot_len_ct()) != CTBytes ||
		int(C.lweot_len_tvec()) != TVecBytes || int(C.lweot_len_sym()) != SymBytes || int(C.lweot_hashin_cap()) != HashinCap {
		panic("lweotkit: liblweot reports different Kyber-768 sizes")
	}
}

func need(b []byte, n int, what string) error {
	if len(b) != n {
		return fmt.Errorf("lattice: %s must be exactly %d bytes", what, n)
	}
	return nil
}

func ptr(b []byte) *C.uint8_t {
	if len(b) == 0 {
		return nil
	}
	return (*C.uint8_t)(unsafe.Pointer(&b[0]))
}

func rc(code C.int32_t, op string) error {
	if code != 0 {
		return fmt.Errorf("lattice: %s refused (%d)", op, int(code))
	}
	return nil
}

// KPKEKeygen derives a Kyber-768 K-PKE key pair deterministically from a 32-byte seed.
func KPKEKeygen(seed []byte) (pk, sk []byte, err error) {
	if err = need(seed, SymBytes, "seed"); err != nil {
		return nil, nil, err
	}
	pk, sk = make([]byte, PKBytes), make([]byte, SKBytes)
	if err = rc(C.lweot_kpke_keygen(ptr(seed), C.size_t(len(seed)), ptr(pk), C.size_t(len(pk)), ptr(sk), C.size_t(len(sk))), "keygen"); err != nil {
		return nil, nil, err
	}
	return pk, sk, nil
}

// KPKEKeygenFips203 derives the K-PKE key pair exactly as FIPS 203 Algorithm 13 does (the derivation the endemic receiver uses).
func KPKEKeygenFips203(seed []byte) (pk, sk []byte, err error) {
	if err = need(seed, SymBytes, "seed"); err != nil {
		return nil, nil, err
	}
	pk, sk = make([]byte, PKBytes), make([]byte, SKBytes)
	if err = rc(C.lweot_kpke_keygen_fips203(ptr(seed), C.size_t(len(seed)), ptr(pk), C.size_t(len(pk)), ptr(sk), C.size_t(len(sk))), "keygen (FIPS 203)"); err != nil {
		return nil, nil, err
	}
	return pk, sk, nil
}

// KPKEEnc CPA-encrypts a 32-byte message under any 1184-byte public key with caller-supplied 32-byte coins.
func KPKEEnc(pk, msg, coins []byte) ([]byte, error) {
	for _, c := range []struct {
		b    []byte
		n    int
		what string
	}{{pk, PKBytes, "public key"}, {msg, SymBytes, "message"}, {coins, SymBytes, "coins"}} {
		if err := need(c.b, c.n, c.what); err != nil {
			return nil, err
		}
	}
	ct := make([]byte, CTBytes)
	if err := rc(C.lweot_kpke_enc(ptr(pk), C.size_t(len(pk)), ptr(msg), C.size_t(len(msg)), ptr(coins), C.size_t(len(coins)), ptr(ct), C.size_t(len(ct))), "enc"); err != nil {
		return nil, err
	}
	return ct, nil
}

// KPKEDec recovers the 32-byte message from a ciphertext under the K-PKE secret key.
func KPKEDec(sk, ct []byte) ([]byte, error) {
	if err := need(sk, SKBytes, "secret key"); err != nil {
		return nil, err
	}
	if err := need(ct, CTBytes, "ciphertext"); err != nil {
		return nil, err
	}
	msg := make([]byte, SymBytes)
	if err := rc(C.lweot_kpke_dec(ptr(sk), C.size_t(len(sk)), ptr(ct), C.size_t(len(ct)), ptr(msg), C.size_t(len(msg))), "dec"); err != nil {
		return nil, err
	}
	return msg, nil
}

func ring(a, b []byte, sub bool) ([]byte, error) {
	if err := need(a, TVecBytes, "a"); err != nil {
		return nil, err
	}
	if err := need(b, TVecBytes, "b"); err != nil {
		return nil, err
	}
	out := make([]byte, TVecBytes)
	var err error
	if sub {
		err = rc(C.lweot_ring_sub(ptr(a), C.size_t(len(a)), ptr(b), C.size_t(len(b)), ptr(out), C.size_t(len(out))), "ring sub")
	} else {
		err = rc(C.lweot_ring_add(ptr(a), C.size_t(len(a)), ptr(b), C.size_t(len(b)), ptr(out), C.size_t(len(out))), "ring add")
	}
	if err != nil {
		return nil, err
	}
	return out, nil
}

// RingAdd is (a + b) mod q over serialized ring vectors, coefficient-wise.
func RingAdd(a, b []byte) ([]byte, error) { return ring(a, b, false) }

// RingSub is (a - b) mod q over serialized ring vectors, coefficient-wise.
func RingSub(a, b []byte) ([]byte, error) { return ring(a, b, true) }

// HashToRing is SHAKE128 then the FIPS 203 SampleNTT sampler: a uniform ring vector. At most 4096 input bytes.
func HashToRing(in []byte) ([]byte, error) {
	if len(in) > HashinCap {
		return nil, errors.New("lattice: hash input must be at most 4096 bytes")
	}
	out := make([]byte, TVecBytes)
	if err := rc(C.lweot_hash_to_ring(ptr(in), C.size_t(len(in)), ptr(out), C.size_t(len(out))), "hash to ring"); err != nil {
		return nil, err
	}
	return out, nil
}
