// Package zkkit is the Groth16 backend for Go: verification and proving for snarkjs / circom artifacts on BN254 and BLS12-381,
// reached through cgo over the small C library libpcazk (pca_zk.h; arkworks pairing arithmetic, the circom witness program run on
// an embedded interpreter). It plugs into the core module through the backend seam (Register, or pca.SetGroth16Backend(NewBackend())),
// keeping the core cgo-free.
//
// A tagged release carries libpcazk as a static archive under lib/<os>_<arch>/ (linux, macOS and windows amd64, linux and macOS
// arm64), so there is nothing to build; otherwise point CGO_LDFLAGS (-L) and LD_LIBRARY_PATH at the directory holding libpcazk. A
// missing or mismatched library fails the link or panics in init; nothing silently reports a proof valid or invalid.
package zkkit

/*
#cgo linux,amd64 LDFLAGS: -L${SRCDIR}/lib/linux_amd64
#cgo linux,arm64 LDFLAGS: -L${SRCDIR}/lib/linux_arm64
#cgo darwin,amd64 LDFLAGS: -L${SRCDIR}/lib/darwin_amd64
#cgo darwin,arm64 LDFLAGS: -L${SRCDIR}/lib/darwin_arm64
#cgo linux LDFLAGS: -lpcazk -ldl -lpthread -lm
#cgo darwin LDFLAGS: -lpcazk -lm -liconv -framework Security -framework CoreFoundation
#cgo windows,amd64 LDFLAGS: -L${SRCDIR}/lib/windows_amd64 -lpcazk -lws2_32 -luserenv -lntdll -lbcrypt -ladvapi32
#cgo !linux,!darwin,!windows LDFLAGS: -lpcazk
#include "pca_zk.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"

	pca "github.com/Atlas-Authorization/pca-go"
)

// SeedBytes is the length of the optional deterministic proving seed.
const SeedBytes = 32

var version string

func init() {
	v := C.pca_zk_version()
	if v == nil || C.GoString(v) == "" {
		panic("zkkit: libpcazk reports no version")
	}
	version = C.GoString(v)
}

// Version is the version of the linked libpcazk.
func Version() string { return version }

func ptr(b []byte) *C.uint8_t {
	if len(b) == 0 {
		return nil
	}
	return (*C.uint8_t)(unsafe.Pointer(&b[0]))
}

func curveOf(curve string) (C.int32_t, error) {
	switch curve {
	case pca.Groth16CurveBn254:
		return C.PCA_ZK_CURVE_BN254, nil
	case pca.Groth16CurveBls12381:
		return C.PCA_ZK_CURVE_BLS12_381, nil
	case pca.Groth16CurveFromKey: // the library refuses it outside reference-compatible verification
		return C.PCA_ZK_CURVE_FROM_KEY, nil
	}
	return 0, fmt.Errorf("zkkit: unknown curve %q", curve)
}

// Verify checks a snarkjs Groth16 proof: vkey is the verification key JSON object, proof the proof JSON object, signals the JSON
// array of decimal-string public signals. With strict false the verdict is the one snarkjs' groth16.verify gives (the reference's);
// strict true also requires protocol groth16, a matching nPublic and no IC entries beyond signals + 1. valid false comes with the
// library's reason (bad_json, bad_encoding, not_in_subgroup, pairing_failed, ...). An unknown curve, an empty input or a library
// fault is an error, never a verdict.
func Verify(curve string, strict bool, vkey, proof, signals []byte) (valid bool, reason string, err error) {
	c, err := curveOf(curve)
	if err != nil {
		return false, "", err
	}
	if len(vkey) == 0 || len(proof) == 0 || len(signals) == 0 {
		return false, "", errors.New("zkkit: the verification key, the proof and the public signals are required")
	}
	flags := C.uint32_t(C.PCA_ZK_FLAG_SNARKJS_COMPAT)
	if strict {
		flags = 0
	}
	var why C.int32_t
	rc := C.pca_zk_verify(c, flags, ptr(vkey), C.size_t(len(vkey)), ptr(proof), C.size_t(len(proof)), ptr(signals), C.size_t(len(signals)), &why)
	switch rc {
	case C.PCA_ZK_VALID:
		return true, "", nil
	case C.PCA_ZK_INVALID:
		return false, C.GoString(C.pca_zk_reason_text(why)), nil
	}
	return false, "", fmt.Errorf("zkkit: verify failed (%d)", int(rc))
}

// Prove runs the circom witness program (wasm, the circuit's <name>_js/<name>.wasm) over the input JSON object, reads the snarkjs
// zkey (held in memory whole) and proves with Groth16. The result is the JSON {"proof": {...}, "publicSignals": [...]}. seed must
// be nil (operating-system randomness: the only mode real proving should use) or SeedBytes bytes, which make the blinding
// deterministic for tests.
func Prove(curve string, wasm, zkey, input, seed []byte) ([]byte, error) {
	c, err := curveOf(curve)
	if err != nil {
		return nil, err
	}
	if len(wasm) == 0 || len(zkey) == 0 || len(input) == 0 {
		return nil, errors.New("zkkit: the witness wasm, the zkey and the input are required")
	}
	if seed != nil && len(seed) != SeedBytes {
		return nil, fmt.Errorf("zkkit: the seed must be %d bytes", SeedBytes)
	}
	var out *C.uint8_t
	var outLen C.size_t
	rc := C.pca_zk_prove(c, ptr(wasm), C.size_t(len(wasm)), ptr(zkey), C.size_t(len(zkey)), ptr(input), C.size_t(len(input)),
		ptr(seed), C.size_t(len(seed)), &out, &outLen)
	var text []byte
	if out != nil {
		if uint64(outLen) > 1<<30 {
			C.pca_zk_free(out, outLen)
			return nil, errors.New("zkkit: the library returned an implausible length")
		}
		text = C.GoBytes(unsafe.Pointer(out), C.int(outLen)) // the buffer is the library's: copy, then release exactly once
		C.pca_zk_free(out, outLen)
	}
	if rc != C.PCA_ZK_OK {
		return nil, fmt.Errorf("zkkit: prove failed (%d): %s", int(rc), text)
	}
	if len(text) == 0 {
		return nil, errors.New("zkkit: the library returned no proof")
	}
	return text, nil
}

// NewBackend is the seam backend for the core: pca.SetGroth16Backend(zkkit.NewBackend()).
func NewBackend() *pca.Groth16Backend {
	return &pca.Groth16Backend{Verify: Verify, Prove: Prove}
}

// Register installs this module as the core's Groth16 backend.
func Register() error { return pca.SetGroth16Backend(NewBackend()) }
