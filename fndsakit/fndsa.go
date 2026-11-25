// Package fndsakit is the real FN-DSA (Falcon) primitive for Go: Pornin's fn-dsa 0.4.0 reached through cgo over the small C library
// libfndsa (pca_fndsa.h, built with cargo build --features capi from the flagship's crate). It plugs into the core module's FN-DSA
// framing and hybrid through the backend seam (NewBackend -> pca.SetFalconBackend), keeping the core cgo-free.
//
// FIPS 206 is not final: this is a draft best guess pinned in lockstep with the TypeScript reference and interoperates with it byte for
// byte. Round-3 Falcon (liboqs, circl) is a different scheme and does not interoperate. A tagged release carries libfndsa as a static archive
// under lib/<os>_<arch>/ (linux, macOS and windows amd64, linux and macOS arm64), so there is nothing to build; otherwise point CGO_LDFLAGS (-L) and
// LD_LIBRARY_PATH at the directory holding libfndsa. A missing or mismatched library fails the link or panics in init; nothing silently reports a signature valid.
package fndsakit

/*
#cgo linux,amd64 LDFLAGS: -L${SRCDIR}/lib/linux_amd64
#cgo linux,arm64 LDFLAGS: -L${SRCDIR}/lib/linux_arm64
#cgo darwin,amd64 LDFLAGS: -L${SRCDIR}/lib/darwin_amd64
#cgo darwin,arm64 LDFLAGS: -L${SRCDIR}/lib/darwin_arm64
#cgo linux LDFLAGS: -lfndsa -ldl -lpthread -lm
#cgo darwin LDFLAGS: -lfndsa -lm -liconv -framework Security -framework CoreFoundation
#cgo windows,amd64 LDFLAGS: -L${SRCDIR}/lib/windows_amd64 -lfndsa -lws2_32 -luserenv -lntdll -lbcrypt -ladvapi32
#cgo !linux,!darwin,!windows LDFLAGS: -lfndsa
#include "pca_fndsa.h"
*/
import "C"

import (
	"crypto/rand"
	"errors"
	"fmt"
	"unsafe"

	pca "github.com/Atlas-Authorization/pca-go"
)

const (
	SeedBytes  = 32
	MessageCap = 8192
)

var tags = map[string]C.int32_t{"fn-dsa-512": 512, "fn-dsa-1024": 1024}

type sizes struct{ vk, sk, sig int }

var variantSizes = map[string]sizes{}

func init() {
	for v, tag := range tags {
		s := sizes{int(C.fndsa_len_vk(tag)), int(C.fndsa_len_sk(tag)), int(C.fndsa_len_sig(tag))}
		want := map[string]sizes{"fn-dsa-512": {897, 1345, 666}, "fn-dsa-1024": {1793, 2369, 1280}}[v]
		if s != want {
			panic(fmt.Sprintf("fndsakit: libfndsa reports different %s sizes %+v", v, s))
		}
		variantSizes[v] = s
	}
	if int(C.fndsa_len_seed()) != SeedBytes || int(C.fndsa_cap_msg()) != MessageCap {
		panic("fndsakit: libfndsa reports a different seed length or message cap")
	}
}

func ptr(b []byte) *C.uint8_t {
	if len(b) == 0 {
		return nil
	}
	return (*C.uint8_t)(unsafe.Pointer(&b[0]))
}

func variantOf(v string) (C.int32_t, sizes, error) {
	tag, ok := tags[v]
	if !ok {
		return 0, sizes{}, fmt.Errorf("fndsakit: unknown FN-DSA variant %q", v)
	}
	return tag, variantSizes[v], nil
}

// Keygen derives (sk, vk) deterministically from a 32-byte seed.
func Keygen(variant string, seed []byte) (sk, vk []byte, err error) {
	tag, sz, err := variantOf(variant)
	if err != nil {
		return nil, nil, err
	}
	if len(seed) != SeedBytes {
		return nil, nil, fmt.Errorf("fndsakit: keygen seed must be %d bytes", SeedBytes)
	}
	sk, vk = make([]byte, sz.sk), make([]byte, sz.vk)
	if rc := C.fndsa_c_keygen(tag, ptr(seed), C.size_t(len(seed)), ptr(sk), C.size_t(len(sk)), ptr(vk), C.size_t(len(vk))); rc != 0 {
		return nil, nil, fmt.Errorf("fndsakit: keygen refused (%d)", int(rc))
	}
	return sk, vk, nil
}

// KeygenRandom is Keygen with a fresh CSPRNG seed.
func KeygenRandom(variant string) (sk, vk []byte, err error) {
	seed := make([]byte, SeedBytes)
	if _, err = rand.Read(seed); err != nil {
		return nil, nil, err
	}
	return Keygen(variant, seed)
}

// Sign signs msg (at most MessageCap bytes; never truncated). A nil seed draws 32 fresh CSPRNG bytes (the only mode real signing should use);
// a given seed makes the signature deterministic (known-answer tests).
func Sign(variant string, sk, msg, seed []byte) ([]byte, error) {
	tag, sz, err := variantOf(variant)
	if err != nil {
		return nil, err
	}
	if len(sk) != sz.sk {
		return nil, fmt.Errorf("fndsakit: %s secret key must be %d bytes", variant, sz.sk)
	}
	if len(msg) > MessageCap {
		return nil, fmt.Errorf("fndsakit: message over the %d-byte cap", MessageCap)
	}
	if seed == nil {
		seed = make([]byte, SeedBytes)
		if _, err = rand.Read(seed); err != nil {
			return nil, err
		}
	}
	if len(seed) != SeedBytes {
		return nil, fmt.Errorf("fndsakit: sign seed must be %d bytes", SeedBytes)
	}
	sig := make([]byte, sz.sig)
	if rc := C.fndsa_c_sign(tag, ptr(sk), C.size_t(len(sk)), ptr(msg), C.size_t(len(msg)), ptr(seed), C.size_t(len(seed)), ptr(sig), C.size_t(len(sig))); rc != 0 {
		return nil, fmt.Errorf("fndsakit: sign refused (%d)", int(rc))
	}
	return sig, nil
}

// Verify is true only when the library answers 0. Bad variant, lengths or an oversize message are false before the library is called; so is any
// nonzero answer.
func Verify(variant string, vk, msg, sig []byte) (bool, error) {
	tag, sz, err := variantOf(variant)
	if err != nil || len(vk) != sz.vk || len(sig) != sz.sig || len(msg) > MessageCap {
		return false, nil
	}
	return C.fndsa_c_verify(tag, ptr(vk), C.size_t(len(vk)), ptr(sig), C.size_t(len(sig)), ptr(msg), C.size_t(len(msg))) == 0, nil
}

func variantByVk(n int) (string, bool) {
	for v, s := range variantSizes {
		if s.vk == n {
			return v, true
		}
	}
	return "", false
}

func variantBySk(n int) (string, bool) {
	for v, s := range variantSizes {
		if s.sk == n {
			return v, true
		}
	}
	return "", false
}

// NewBackend is the seam backend for the core: pca.SetFalconBackend(fndsakit.NewBackend()). The variant follows the key length; signing uses a fresh
// CSPRNG seed per call; Keygen makes an FN-DSA-512 key pair; SignSeeded and KeygenSeeded give the deterministic paths the agent-side signer
// (pca.NewFnDsaKeyPair, pca.FnDsaKeyPairFromSeed) uses for fixed seeds.
func NewBackend() *pca.FalconBackend {
	return &pca.FalconBackend{
		Verify: func(pk, msg, sig []byte) (bool, error) {
			v, ok := variantByVk(len(pk))
			if !ok {
				return false, nil
			}
			return Verify(v, pk, msg, sig)
		},
		Sign: func(sk, msg []byte) ([]byte, error) {
			v, ok := variantBySk(len(sk))
			if !ok {
				return nil, errors.New("fndsakit: unrecognised FN-DSA secret-key length")
			}
			return Sign(v, sk, msg, nil)
		},
		Keygen: func() ([]byte, []byte, error) { return KeygenRandom("fn-dsa-512") },
		SignSeeded: func(sk, msg, seed []byte) ([]byte, error) {
			v, ok := variantBySk(len(sk))
			if !ok {
				return nil, errors.New("fndsakit: unrecognised FN-DSA secret-key length")
			}
			return Sign(v, sk, msg, seed)
		},
		KeygenSeeded: func(variant string, seed []byte) ([]byte, []byte, error) {
			sk, vk, err := Keygen(variant, seed)
			return vk, sk, err
		},
	}
}
