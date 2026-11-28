//go:build less && cgo

package pca

/*
#cgo CFLAGS: -O2 -std=c99 -DCATEGORY=252 -DTARGET=45 -I${SRCDIR}/lessc/include -I${SRCDIR}/lessc
#cgo !windows LDFLAGS: -lpthread
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "atlas_less.h"
#include "api.h"

// Hooks for the C's test-only seams (atlas_less_test_set_*), used only by the wrapper's own tests (less_sign_wrapper_test.go):
// an allocator that fails its fail_at-th call (0: none) and checks on free that the temporary secret key was wiped, and a signer
// that reports success with a detached signature of lt_sign_len bytes.
static int lt_calls, lt_fail_at, lt_sk_freed, lt_sk_dirty;
static void *lt_sk_buf;
static unsigned long long lt_sign_len;
static void *lt_alloc(size_t n) {
	if (++lt_calls == lt_fail_at) return NULL;
	void *p = malloc(n);
	if (n == atlas_less_cat1_secret_key_bytes()) lt_sk_buf = p;
	return p;
}
static void lt_free(void *p) {
	if (p != NULL && p == lt_sk_buf) {
		for (size_t i = 0; i < atlas_less_cat1_secret_key_bytes(); i++) if (((unsigned char *)p)[i] != 0) lt_sk_dirty = 1;
		lt_sk_freed++;
		lt_sk_buf = NULL;
	}
	free(p);
}
static int lt_sign(unsigned char *sm, unsigned long long *smlen, const unsigned char *m, unsigned long long mlen, const unsigned char *sk) {
	(void)sm; (void)m; (void)sk;
	*smlen = mlen + lt_sign_len;
	return 0;
}
static void lt_set_allocator(int fail_at) { lt_calls = 0; lt_fail_at = fail_at; atlas_less_test_set_allocator(lt_alloc, lt_free); }
static void lt_set_signer(unsigned long long len) { lt_sign_len = len; atlas_less_test_set_sign(lt_sign); }
static void lt_reset(void) { atlas_less_test_set_allocator(NULL, NULL); atlas_less_test_set_sign(NULL); }
static void lt_wipe_reset(void) { lt_sk_freed = 0; lt_sk_dirty = 0; }
static int lt_wipe_freed(void) { return lt_sk_freed; }
static int lt_wipe_dirty(void) { return lt_sk_dirty; }
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

// lessSeamAllocator routes the C wrapper's allocations through malloc, failing the failAt-th (0: none), and records whether the
// temporary secret key was all zero when freed (lessSeamWipe); lessSeamSigner replaces the reference crypto_sign with one that
// reports success and a sigLen-byte signature; lessSeamReset restores both. For the wrapper's own tests only (not thread-safe).
func lessSeamAllocator(failAt int) { C.lt_set_allocator(C.int(failAt)) }
func lessSeamSigner(sigLen uint64) { C.lt_set_signer(C.ulonglong(sigLen)) }
func lessSeamReset() { C.lt_reset() }
func lessSeamWipeReset() { C.lt_wipe_reset() }
func lessSeamWipe() (int, bool) { return int(C.lt_wipe_freed()), C.lt_wipe_dirty() != 0 }
