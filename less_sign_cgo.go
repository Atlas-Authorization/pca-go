//go:build less && cgo

package pca

/*
#cgo CFLAGS: -O2 -std=c99 -DCATEGORY=252 -DTARGET=45 -I${SRCDIR}/lessc/include -I${SRCDIR}/lessc
#cgo !windows LDFLAGS: -lpthread
#include <stdint.h>
#include <stddef.h>
#include "atlas_less.h"
#include "api.h"
*/
import "C"

import (
	"errors"
	"unsafe"
)

// LessCat1Keygen derives a LESS category-1 key pair from a 32-byte seed. It returns the public key and the secret key (the seed
// the public key is expanded from). Available in a build with the `less` tag and cgo.
func LessCat1Keygen(seed []byte) (publicKey, secretKey []byte, err error) {
	if len(seed) != LessCat1SecretKeyBytes {
		return nil, nil, errors.New("lessCat1Keygen: seed must be 32 bytes")
	}
	pk := make([]byte, LessCat1PublicKeyBytes)
	sk := make([]byte, LessCat1SecretKeyBytes)
	if C.atlas_less_cat1_keygen((*C.uint8_t)(unsafe.Pointer(&pk[0])), C.size_t(len(pk)), (*C.uint8_t)(unsafe.Pointer(&sk[0])),
		C.size_t(len(sk)), (*C.uint8_t)(unsafe.Pointer(&seed[0])), C.size_t(len(seed))) != 1 {
		return nil, nil, errors.New("lessCat1Keygen: key generation failed")
	}
	return pk, sk, nil
}

// LessCat1Sign signs msg with a LESS category-1 secret key and an explicit 32-byte randomness seed (a repeated seed repeats the
// salt). The signature is detached and 1153 to 1329 bytes long. Available in a build with the `less` tag and cgo.
func LessCat1Sign(secretKey, msg, seed []byte) ([]byte, error) {
	if len(seed) != LessCat1SecretKeyBytes {
		return nil, errors.New("lessCat1Sign: seed must be 32 bytes")
	}
	if len(secretKey) != LessCat1SecretKeyBytes {
		return nil, errors.New("lessCat1Sign: secret key must be 32 bytes")
	}
	var m *C.uint8_t
	if len(msg) > 0 {
		m = (*C.uint8_t)(unsafe.Pointer(&msg[0]))
	}
	sig := make([]byte, LessCat1SignatureMaxBytes)
	var n C.size_t
	if C.atlas_less_cat1_sign((*C.uint8_t)(unsafe.Pointer(&secretKey[0])), C.size_t(len(secretKey)), m, C.size_t(len(msg)),
		(*C.uint8_t)(unsafe.Pointer(&seed[0])), C.size_t(len(seed)), (*C.uint8_t)(unsafe.Pointer(&sig[0])), C.size_t(len(sig)), &n) != 1 {
		return nil, errors.New("lessCat1Sign: signing failed")
	}
	return sig[:int(n)], nil
}

// The raw seams below call the C with no Go-side checks; they exist only for the wrapper's own tests (less_sign_wrapper_test.go).

func lessCat1KeygenRaw(pk unsafe.Pointer, pkCap uint64, sk unsafe.Pointer, skCap uint64, seed unsafe.Pointer, seedLen uint64) bool {
	return C.atlas_less_cat1_keygen((*C.uint8_t)(pk), C.size_t(pkCap), (*C.uint8_t)(sk), C.size_t(skCap), (*C.uint8_t)(seed),
		C.size_t(seedLen)) == 1
}

// lessCat1SignRaw also returns the C errno after the call (cgo clears it first): a refused length leaves it 0, an admitted one
// that then fails to allocate sets ENOMEM.
func lessCat1SignRaw(sk unsafe.Pointer, skLen uint64, msg unsafe.Pointer, msgLen uint64, seed unsafe.Pointer, seedLen uint64, sig unsafe.Pointer, sigCap uint64, sigLen *uint64) (bool, error) {
	r, err := C.atlas_less_cat1_sign((*C.uint8_t)(sk), C.size_t(skLen), (*C.uint8_t)(msg), C.size_t(msgLen), (*C.uint8_t)(seed),
		C.size_t(seedLen), (*C.uint8_t)(sig), C.size_t(sigCap), (*C.size_t)(unsafe.Pointer(sigLen)))
	return r == 1, err
}

// lessSignOverflowBound is the largest msg_len the C's overflow guard admits (SIZE_MAX - sizeof(sign_t) - 16).
func lessSignOverflowBound() uint64 { return ^uint64(0) - uint64(C.sizeof_sign_t) - 16 }
