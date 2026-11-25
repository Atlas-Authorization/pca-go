package pca

import (
	"encoding/json"
	"errors"
	"sync"
)

// The Groth16 backend seam. Checking or producing a Groth16 proof needs pairing arithmetic on BN254 and BLS12-381, which this
// module does not carry (it stays free of cgo): a backend is plugged in with SetGroth16Backend, for example the zkkit module's
// (libpcazk through cgo). Without a backend every call fails with ErrGroth16BackendMissing; nothing reports a proof valid or
// invalid without having checked it.

const (
	// Groth16CurveBn254 names BN254 (snarkjs "bn128", envelope system "groth16-bn254").
	Groth16CurveBn254 = "bn254"
	// Groth16CurveBls12381 names BLS12-381 (snarkjs "bls12381", envelope system "groth16-bls12-381").
	Groth16CurveBls12381 = "bls12-381"
	// Groth16CurveFromKey asks the backend to take the curve the verification key names, read as snarkjs reads it (upper-cased,
	// only ASCII letters and digits kept: BN128, BN254 and ALTBN128 are BN254, BLS12381 is BLS12-381; any other name, or none, is
	// an invalid key). Verify only, and only with strict false: this is what the reference verifier does.
	Groth16CurveFromKey = "from-key"
)

// Groth16Backend is a Groth16 implementation for snarkjs / circom artifacts. vkey, proof, signals and input are UTF-8 JSON in the
// snarkjs encoding (decimal-string field elements; G1 [x, y, "1"]; G2 [[x0, x1], [y0, y1], ["1", "0"]]).
type Groth16Backend struct {
	// Verify decides the pairing equation. With strict false it accepts exactly what snarkjs' groth16.verify accepts (the
	// reference's behaviour: the key's protocol and nPublic are ignored, IC entries beyond signals + 1 are not read); with strict
	// true those are refused as well. In both modes every point must be on the curve and in the prime-order subgroup and every
	// number canonical and below its field modulus. valid false comes with the reason; err is a usage or backend fault, never a
	// verdict.
	Verify func(curve string, strict bool, vkey, proof, signals []byte) (valid bool, reason string, err error)
	// Prove runs the circom witness program (wasm) over the input object, reads the snarkjs zkey and returns the JSON
	// {"proof": {...}, "publicSignals": [...]}. seed (32 bytes) makes the blinding deterministic and is for tests only; nil draws
	// operating-system randomness. Optional: a verify-only backend leaves it nil.
	Prove func(curve string, wasm, zkey, input, seed []byte) ([]byte, error)
}

// ErrGroth16BackendMissing: no Groth16 backend is installed.
var ErrGroth16BackendMissing = errors.New("no Groth16 backend registered: supply one via SetGroth16Backend() (for example the zkkit module's backend)")

var (
	groth16Mu      sync.RWMutex
	groth16Current *Groth16Backend
)

// SetGroth16Backend installs the backend every Groth16 call of this package uses.
func SetGroth16Backend(b *Groth16Backend) error {
	if b == nil || b.Verify == nil {
		return errors.New("SetGroth16Backend: a backend needs a Verify function")
	}
	groth16Mu.Lock()
	groth16Current = b
	groth16Mu.Unlock()
	return nil
}

// GetGroth16Backend returns the installed backend, or nil when there is none.
func GetGroth16Backend() *Groth16Backend {
	groth16Mu.RLock()
	defer groth16Mu.RUnlock()
	return groth16Current
}

// IsGroth16BackendActive reports whether a backend is installed.
func IsGroth16BackendActive() bool { return GetGroth16Backend() != nil }

// Groth16Verify checks a snarkjs Groth16 proof through the installed backend: verificationKey and proof are the parsed JSON
// objects, publicSignals the array of decimal strings. It answers the pairing question only; the envelope, circuit and context
// gates of a compliance proof belong to the caller. Without a backend the error is ErrGroth16BackendMissing.
func Groth16Verify(curve string, verificationKey, proof, publicSignals any, strict bool) (valid bool, reason string, err error) {
	b := GetGroth16Backend()
	if b == nil {
		return false, "", ErrGroth16BackendMissing
	}
	vk, err := json.Marshal(verificationKey)
	if err != nil {
		return false, "", err
	}
	pr, err := json.Marshal(proof)
	if err != nil {
		return false, "", err
	}
	sg, err := json.Marshal(publicSignals)
	if err != nil {
		return false, "", err
	}
	return b.Verify(curve, strict, vk, pr, sg)
}

// Groth16Prove proves through the installed backend (see Groth16Backend.Prove). Without a backend, or with one that cannot prove,
// the error is ErrGroth16BackendMissing.
func Groth16Prove(curve string, wasm, zkey, input, seed []byte) ([]byte, error) {
	b := GetGroth16Backend()
	if b == nil || b.Prove == nil {
		return nil, ErrGroth16BackendMissing
	}
	return b.Prove(curve, wasm, zkey, input, seed)
}
