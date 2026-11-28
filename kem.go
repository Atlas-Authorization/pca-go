package pca

// Key encapsulation: the hybrid X25519 + ML-KEM-768 and X25519 + ML-KEM-1024 KEMs (a HKDF-SHA256 combiner that binds the transcript),
// the X-Wing KEM (draft-connolly-cfrg-xwing-kem-09: SHA3-256 combiner, byte-interoperable with other X-Wing implementations) and
// the FIPS 203 section 7.2 / 7.3 checks for imported ML-KEM keys. Each KEM establishes a 32-byte shared secret and ships no cipher:
// use the result as the key of an AEAD. Every input is length-checked and every failure refuses (returns an error).
// Primitives: circl ML-KEM (the only Go implementation that imports an expanded decapsulation key), crypto/ecdh X25519 (an all-zero
// result, i.e. a low-order peer point, is refused), crypto/hkdf and crypto/sha3. No cgo.

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
)

const (
	kemX25519Len = 32
	kemSSLen     = 32
	kemMlkem768  = 3
	kemMlkem1024 = 4
)

// Sizes and suite identifiers of the hybrid X25519 + ML-KEM-768 KEM.
const (
	// HybridPublicKeyLen is X25519 (32) || ML-KEM-768 (1184).
	HybridPublicKeyLen = 1216
	// HybridCiphertextLen is the ephemeral X25519 key (32) || the ML-KEM-768 ciphertext (1088).
	HybridCiphertextLen = 1120
	// HybridSharedSecretLen is the shared-secret size.
	HybridSharedSecretLen = 32
	// HybridKemSuite is the suite id of the ML-KEM-768 hybrid.
	HybridKemSuite = "x25519-ml-kem-768"
)

// Sizes and suite identifiers of the hybrid X25519 + ML-KEM-1024 KEM.
const (
	// Hybrid1024PublicKeyLen is X25519 (32) || ML-KEM-1024 (1568).
	Hybrid1024PublicKeyLen = 1600
	// Hybrid1024CiphertextLen is the ephemeral X25519 key (32) || the ML-KEM-1024 ciphertext (1568).
	Hybrid1024CiphertextLen = 1600
	// Hybrid1024SharedSecretLen is the shared-secret size.
	Hybrid1024SharedSecretLen = 32
	// Hybrid1024KemSuite is the suite id of the ML-KEM-1024 hybrid.
	Hybrid1024KemSuite = "x25519-ml-kem-1024"
)

// Sizes and suite identifier of X-Wing.
const (
	// XWingSuite is the suite id of X-Wing (draft-connolly-cfrg-xwing-kem-09).
	XWingSuite = "xwing"
	// XWingSeedLen is the length of the decapsulation-key seed.
	XWingSeedLen = 32
	// XWingSecretKeyLen is the secret-key length (the seed itself).
	XWingSecretKeyLen = XWingSeedLen
	// XWingPublicKeyLen is ML-KEM-768 (1184) || X25519 (32).
	XWingPublicKeyLen = 1216
	// XWingCiphertextLen is the ML-KEM-768 ciphertext (1088) || the ephemeral X25519 key (32).
	XWingCiphertextLen = 1120
	// XWingSharedSecretLen is the shared-secret size.
	XWingSharedSecretLen = 32
	// XWingESeedLen is the derandomised encapsulation seed: the ML-KEM message m (32) || the X25519 ephemeral secret (32).
	XWingESeedLen = 64
)

// XWingLabel returns a copy of the 6-byte X-Wing domain label, ASCII `\.//^\` (hex 5c2e2f2f5e5c).
func XWingLabel() []byte { return []byte{0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c} }

const (
	kemDomain768  = "atlas-pca/kem/x25519-ml-kem-768/v1\x00"
	kemDomain1024 = "atlas-pca/kem/x25519-ml-kem-1024/v1\x00"
)

// HybridKemKeyPair is a hybrid recipient key pair.
type HybridKemKeyPair struct {
	// PublicKey is the X25519 public key (32) || the ML-KEM encapsulation key.
	PublicKey []byte
	// SecretKey is the X25519 secret (32) || the expanded ML-KEM decapsulation key.
	SecretKey []byte
}

// HybridEncapsulation is the result of a hybrid encapsulation.
type HybridEncapsulation struct {
	// Ciphertext is the ephemeral X25519 public key (32) || the ML-KEM ciphertext: send it.
	Ciphertext []byte
	// SharedSecret is the 32-byte shared secret: keep it.
	SharedSecret []byte
}

// XWingKeyPair is an X-Wing key pair.
type XWingKeyPair struct {
	// SecretKey is the 32-byte seed (draft-09's decapsulation key), expanded on use.
	SecretKey []byte
	// PublicKey is the ML-KEM-768 encapsulation key (1184) || the X25519 public key (32).
	PublicKey []byte
}

// XWingEncapsulation is the result of an X-Wing encapsulation.
type XWingEncapsulation struct {
	// Ciphertext is the ML-KEM-768 ciphertext (1088) || the ephemeral X25519 public key (32): send it.
	Ciphertext []byte
	// SharedSecret is the 32-byte shared secret: keep it.
	SharedSecret []byte
}

// kemLevel is one ML-KEM parameter set behind the vetted circl implementation.
type kemLevel struct {
	k        int
	ekLen    int
	ctLen    int
	dkLen    int
	fromSeed func(seed []byte) (ek, dk []byte)
	encaps   func(ek, m []byte) (ct, ss []byte, err error)
	decaps   func(dk, ct []byte) ([]byte, error)
}

var kemLevel768 = &kemLevel{
	k: kemMlkem768, ekLen: mlkem768.PublicKeySize, ctLen: mlkem768.CiphertextSize, dkLen: mlkem768.PrivateKeySize,
	fromSeed: func(seed []byte) ([]byte, []byte) {
		pk, sk := mlkem768.NewKeyFromSeed(seed)
		ek, dk := make([]byte, mlkem768.PublicKeySize), make([]byte, mlkem768.PrivateKeySize)
		pk.Pack(ek)
		sk.Pack(dk)
		return ek, dk
	},
	encaps: func(ek, m []byte) ([]byte, []byte, error) {
		var pk mlkem768.PublicKey
		if err := pk.Unpack(ek); err != nil {
			return nil, nil, err
		}
		ct, ss := make([]byte, mlkem768.CiphertextSize), make([]byte, mlkem768.SharedKeySize)
		pk.EncapsulateTo(ct, ss, m)
		return ct, ss, nil
	},
	decaps: func(dk, ct []byte) ([]byte, error) {
		var sk mlkem768.PrivateKey
		if err := sk.Unpack(dk); err != nil {
			return nil, err
		}
		ss := make([]byte, mlkem768.SharedKeySize)
		sk.DecapsulateTo(ss, ct)
		return ss, nil
	},
}

var kemLevel1024 = &kemLevel{
	k: kemMlkem1024, ekLen: mlkem1024.PublicKeySize, ctLen: mlkem1024.CiphertextSize, dkLen: mlkem1024.PrivateKeySize,
	fromSeed: func(seed []byte) ([]byte, []byte) {
		pk, sk := mlkem1024.NewKeyFromSeed(seed)
		ek, dk := make([]byte, mlkem1024.PublicKeySize), make([]byte, mlkem1024.PrivateKeySize)
		pk.Pack(ek)
		sk.Pack(dk)
		return ek, dk
	},
	encaps: func(ek, m []byte) ([]byte, []byte, error) {
		var pk mlkem1024.PublicKey
		if err := pk.Unpack(ek); err != nil {
			return nil, nil, err
		}
		ct, ss := make([]byte, mlkem1024.CiphertextSize), make([]byte, mlkem1024.SharedKeySize)
		pk.EncapsulateTo(ct, ss, m)
		return ct, ss, nil
	},
	decaps: func(dk, ct []byte) ([]byte, error) {
		var sk mlkem1024.PrivateKey
		if err := sk.Unpack(dk); err != nil {
			return nil, err
		}
		ss := make([]byte, mlkem1024.SharedKeySize)
		sk.DecapsulateTo(ss, ct)
		return ss, nil
	},
}

func kemCat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func kemRandom(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// kemX25519Pub is X25519(secret, 9).
func kemX25519Pub(secret []byte) ([]byte, error) {
	k, err := ecdh.X25519().NewPrivateKey(secret)
	if err != nil {
		return nil, err
	}
	return k.PublicKey().Bytes(), nil
}

// kemX25519Shared is X25519(secret, peer); a low-order peer (all-zero output) is refused.
func kemX25519Shared(secret, peer []byte) ([]byte, error) {
	k, err := ecdh.X25519().NewPrivateKey(secret)
	if err != nil {
		return nil, err
	}
	p, err := ecdh.X25519().NewPublicKey(peer)
	if err != nil {
		return nil, err
	}
	ss, err := k.ECDH(p)
	if err != nil {
		return nil, err
	}
	var zero [kemX25519Len]byte
	if subtle.ConstantTimeCompare(ss, zero[:]) == 1 {
		return nil, errors.New("kem: X25519 low-order point")
	}
	return ss, nil
}

func kemCombine(domain string, ssMlkem, ssX, ephPub, recipX []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, kemCat(ssMlkem, ssX, ephPub, recipX), nil, domain, kemSSLen)
}

// kemModulusOK is the FIPS 203 section 7.2 modulus check: every 12-bit coefficient of the 384*k-byte t part is below q = 3329.
func kemModulusOK(ek []byte, k int) bool {
	for i := 0; i < 384*k; i += 3 {
		if int(ek[i])|(int(ek[i+1]&0x0f)<<8) >= 3329 {
			return false
		}
		if int(ek[i+1]>>4)|(int(ek[i+2])<<4) >= 3329 {
			return false
		}
	}
	return true
}

// kemKeygen draws x(32) || d(32) || z(32) from rng.
func kemKeygen(lv *kemLevel, rng []byte) (HybridKemKeyPair, error) {
	if len(rng) != kemX25519Len+64 {
		return HybridKemKeyPair{}, errors.New("hybridKemKeygen: need 96 random bytes")
	}
	x := rng[:kemX25519Len]
	xPub, err := kemX25519Pub(x)
	if err != nil {
		return HybridKemKeyPair{}, err
	}
	ek, dk := lv.fromSeed(rng[kemX25519Len:])
	return HybridKemKeyPair{PublicKey: kemCat(xPub, ek), SecretKey: kemCat(x, dk)}, nil
}

func kemHybridKeygen(lv *kemLevel) (HybridKemKeyPair, error) {
	rng, err := kemRandom(kemX25519Len + 64)
	if err != nil {
		return HybridKemKeyPair{}, err
	}
	return kemKeygen(lv, rng)
}

// kemEncapsulate takes rng = ephemeralX25519Secret(32) || m(32).
func kemEncapsulate(lv *kemLevel, pkLen int, domain, who string, pk, rng []byte) (HybridEncapsulation, error) {
	if len(pk) != pkLen {
		return HybridEncapsulation{}, fmt.Errorf("%s: public key must be %d bytes (got %d)", who, pkLen, len(pk))
	}
	if len(rng) != kemX25519Len+32 {
		return HybridEncapsulation{}, fmt.Errorf("%s: need 64 random bytes", who)
	}
	recipX, recipMlkem := pk[:kemX25519Len], pk[kemX25519Len:]
	eph := rng[:kemX25519Len]
	ephPub, err := kemX25519Pub(eph)
	if err != nil {
		return HybridEncapsulation{}, err
	}
	ssX, err := kemX25519Shared(eph, recipX)
	if err != nil {
		return HybridEncapsulation{}, err
	}
	if !kemModulusOK(recipMlkem, lv.k) {
		return HybridEncapsulation{}, fmt.Errorf("%s: ML-KEM encapsulation key fails the FIPS 203 modulus check", who)
	}
	ct, ssM, err := lv.encaps(recipMlkem, rng[kemX25519Len:])
	if err != nil {
		return HybridEncapsulation{}, err
	}
	ss, err := kemCombine(domain, ssM, ssX, ephPub, recipX)
	if err != nil {
		return HybridEncapsulation{}, err
	}
	return HybridEncapsulation{Ciphertext: kemCat(ephPub, ct), SharedSecret: ss}, nil
}

func kemHybridEncapsulate(lv *kemLevel, pkLen int, domain, who string, pk []byte) (HybridEncapsulation, error) {
	rng, err := kemRandom(kemX25519Len + 32)
	if err != nil {
		return HybridEncapsulation{}, err
	}
	return kemEncapsulate(lv, pkLen, domain, who, pk, rng)
}

func kemDecapsulate(lv *kemLevel, ctLen int, domain, who string, ct, sk []byte) ([]byte, error) {
	if len(ct) != ctLen {
		return nil, fmt.Errorf("%s: ciphertext must be %d bytes (got %d)", who, ctLen, len(ct))
	}
	if len(sk) <= kemX25519Len {
		return nil, fmt.Errorf("%s: malformed secret key", who)
	}
	// The ML-KEM layer needs the exact expanded size; a library that does not check lengths must not see another one.
	if len(sk) != kemX25519Len+lv.dkLen {
		return nil, fmt.Errorf("%s: secret key must be %d bytes (got %d)", who, kemX25519Len+lv.dkLen, len(sk))
	}
	ephPub := ct[:kemX25519Len]
	xPriv := sk[:kemX25519Len]
	ssX, err := kemX25519Shared(xPriv, ephPub)
	if err != nil {
		return nil, err
	}
	ssM, err := lv.decaps(sk[kemX25519Len:], ct[kemX25519Len:])
	if err != nil {
		return nil, err
	}
	recipX, err := kemX25519Pub(xPriv)
	if err != nil {
		return nil, err
	}
	return kemCombine(domain, ssM, ssX, ephPub, recipX)
}

// HybridKemKeygen generates an X25519 + ML-KEM-768 recipient key pair.
func HybridKemKeygen() (HybridKemKeyPair, error) { return kemHybridKeygen(kemLevel768) }

// HybridEncapsulate encapsulates to a hybrid X25519 + ML-KEM-768 public key (1216 bytes): send the ciphertext, keep the shared secret.
func HybridEncapsulate(recipientPublicKey []byte) (HybridEncapsulation, error) {
	return kemHybridEncapsulate(kemLevel768, HybridPublicKeyLen, kemDomain768, "HybridEncapsulate", recipientPublicKey)
}

// HybridDecapsulate recovers the shared secret from a hybrid ciphertext with the recipient secret key (2432 bytes). A tampered
// ciphertext or a wrong key yields the ML-KEM implicit-rejection secret, never an error.
func HybridDecapsulate(ciphertext, secretKey []byte) ([]byte, error) {
	return kemDecapsulate(kemLevel768, HybridCiphertextLen, kemDomain768, "HybridDecapsulate", ciphertext, secretKey)
}

// HybridKem1024Keygen generates an X25519 + ML-KEM-1024 recipient key pair.
func HybridKem1024Keygen() (HybridKemKeyPair, error) { return kemHybridKeygen(kemLevel1024) }

// HybridEncapsulate1024 encapsulates to a hybrid X25519 + ML-KEM-1024 public key (1600 bytes).
func HybridEncapsulate1024(recipientPublicKey []byte) (HybridEncapsulation, error) {
	return kemHybridEncapsulate(kemLevel1024, Hybrid1024PublicKeyLen, kemDomain1024, "HybridEncapsulate1024", recipientPublicKey)
}

// HybridDecapsulate1024 recovers the shared secret from a hybrid ML-KEM-1024 ciphertext with the recipient secret key (3200 bytes).
func HybridDecapsulate1024(ciphertext, secretKey []byte) ([]byte, error) {
	return kemDecapsulate(kemLevel1024, Hybrid1024CiphertextLen, kemDomain1024, "HybridDecapsulate1024", ciphertext, secretKey)
}

// kemXWingExpand is the draft-09 key expansion: SHAKE256(seed, 96) = d || z || skX.
func kemXWingExpand(seed []byte) (ek, dk, xSecret, xPub []byte, err error) {
	if len(seed) != XWingSeedLen {
		return nil, nil, nil, nil, fmt.Errorf("xwing: seed must be %d bytes (got %d)", XWingSeedLen, len(seed))
	}
	ex := sha3.SumSHAKE256(seed, 96)
	ek, dk = kemLevel768.fromSeed(ex[:64])
	xSecret = ex[64:]
	if xPub, err = kemX25519Pub(xSecret); err != nil {
		return nil, nil, nil, nil, err
	}
	return ek, dk, xSecret, xPub, nil
}

func kemXWingCombine(ssM, ssX, ctX, pkX []byte) []byte {
	h := sha3.Sum256(kemCat(ssM, ssX, ctX, pkX, XWingLabel()))
	return h[:]
}

// XWingKeygen generates an X-Wing key pair from a fresh 32-byte seed.
func XWingKeygen() (XWingKeyPair, error) {
	seed, err := kemRandom(XWingSeedLen)
	if err != nil {
		return XWingKeyPair{}, err
	}
	return XWingKeygenFromSeed(seed)
}

// XWingKeygenFromSeed derives the X-Wing key pair of a 32-byte seed (known-answer and deterministic keygen). The secret key is a copy of the seed.
func XWingKeygenFromSeed(seed []byte) (XWingKeyPair, error) {
	ek, _, _, xPub, err := kemXWingExpand(seed)
	if err != nil {
		return XWingKeyPair{}, err
	}
	return XWingKeyPair{SecretKey: append([]byte(nil), seed...), PublicKey: kemCat(ek, xPub)}, nil
}

// XWingEncapsulateDerand is the derandomised encapsulation of draft-09: eseed (64 bytes) = the ML-KEM message m (32) || the X25519
// ephemeral secret (32). It reproduces the draft's known-answer vectors; production code should call XWingEncapsulate.
func XWingEncapsulateDerand(recipientPublicKey, eseed []byte) (XWingEncapsulation, error) {
	if len(recipientPublicKey) != XWingPublicKeyLen {
		return XWingEncapsulation{}, fmt.Errorf("XWingEncapsulateDerand: public key must be %d bytes (got %d)", XWingPublicKeyLen, len(recipientPublicKey))
	}
	if len(eseed) != XWingESeedLen {
		return XWingEncapsulation{}, fmt.Errorf("XWingEncapsulateDerand: eseed must be %d bytes (got %d)", XWingESeedLen, len(eseed))
	}
	pkM, pkX := recipientPublicKey[:mlkem768.PublicKeySize], recipientPublicKey[mlkem768.PublicKeySize:]
	ekX := eseed[32:]
	if !kemModulusOK(pkM, kemMlkem768) {
		return XWingEncapsulation{}, errors.New("XWingEncapsulateDerand: ML-KEM encapsulation key fails the FIPS 203 modulus check")
	}
	ctM, ssM, err := kemLevel768.encaps(pkM, eseed[:32])
	if err != nil {
		return XWingEncapsulation{}, err
	}
	ctX, err := kemX25519Pub(ekX)
	if err != nil {
		return XWingEncapsulation{}, err
	}
	ssX, err := kemX25519Shared(ekX, pkX)
	if err != nil {
		return XWingEncapsulation{}, err
	}
	return XWingEncapsulation{Ciphertext: kemCat(ctM, ctX), SharedSecret: kemXWingCombine(ssM, ssX, ctX, pkX)}, nil
}

// XWingEncapsulate encapsulates to an X-Wing public key with fresh randomness.
func XWingEncapsulate(recipientPublicKey []byte) (XWingEncapsulation, error) {
	eseed, err := kemRandom(XWingESeedLen)
	if err != nil {
		return XWingEncapsulation{}, err
	}
	return XWingEncapsulateDerand(recipientPublicKey, eseed)
}

// XWingDecapsulate recovers the shared secret from an X-Wing ciphertext with the 32-byte seed secret key.
func XWingDecapsulate(ciphertext, secretKey []byte) ([]byte, error) {
	if len(ciphertext) != XWingCiphertextLen {
		return nil, fmt.Errorf("XWingDecapsulate: ciphertext must be %d bytes (got %d)", XWingCiphertextLen, len(ciphertext))
	}
	_, dk, xSecret, xPub, err := kemXWingExpand(secretKey)
	if err != nil {
		return nil, err
	}
	ctM, ctX := ciphertext[:mlkem768.CiphertextSize], ciphertext[mlkem768.CiphertextSize:]
	ssM, err := kemLevel768.decaps(dk, ctM)
	if err != nil {
		return nil, err
	}
	ssX, err := kemX25519Shared(xSecret, ctX)
	if err != nil {
		return nil, err
	}
	return kemXWingCombine(ssM, ssX, ctX, xPub), nil
}

func kemLevelOf(level int) (*kemLevel, error) {
	switch level {
	case 768:
		return kemLevel768, nil
	case 1024:
		return kemLevel1024, nil
	}
	return nil, fmt.Errorf("unknown ML-KEM level %d", level)
}

// MlKemEncapsulationKeyCheck is the FIPS 203 section 7.2 type and modulus check of an ML-KEM encapsulation key (level 768 or 1024).
// It reports false for a wrong length or a non-reduced coefficient; an unknown level is an error.
func MlKemEncapsulationKeyCheck(level int, ek []byte) (bool, error) {
	lv, err := kemLevelOf(level)
	if err != nil {
		return false, err
	}
	return len(ek) == 384*lv.k+32 && kemModulusOK(ek, lv.k), nil
}

// MlKemDecapsulationKeyCheck is the FIPS 203 section 7.3 check of an expanded ML-KEM decapsulation key (level 768 or 1024): the
// length, the embedded H(ek) and the embedded key's modulus check (dkPKE and z are not checkable). An unknown level is an error.
func MlKemDecapsulationKeyCheck(level int, dk []byte) (bool, error) {
	lv, err := kemLevelOf(level)
	if err != nil {
		return false, err
	}
	k := lv.k
	if len(dk) != 768*k+96 {
		return false, nil
	}
	ek, h := dk[384*k:768*k+32], dk[768*k+32:768*k+64]
	want := sha3.Sum256(ek)
	return subtle.ConstantTimeCompare(want[:], h) == 1 && kemModulusOK(ek, k), nil
}

func kemEncode(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// kemDecode is the strict unpadded base64url decode: no padding, no whitespace, no other alphabet, no non-zero trailing bits.
func kemDecode(s string) ([]byte, error) {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return nil, errors.New("invalid base64url")
		}
	}
	return base64.RawURLEncoding.Strict().DecodeString(s)
}

// EncodeHybridPublicKey is the unpadded base64url form of a hybrid public key.
func EncodeHybridPublicKey(k []byte) string { return kemEncode(k) }

// DecodeHybridPublicKey strictly decodes a base64url hybrid public key (the length is not checked).
func DecodeHybridPublicKey(s string) ([]byte, error) { return kemDecode(s) }

// EncodeHybridCiphertext is the unpadded base64url form of a hybrid ciphertext.
func EncodeHybridCiphertext(c []byte) string { return kemEncode(c) }

// DecodeHybridCiphertext strictly decodes a base64url hybrid ciphertext (the length is not checked).
func DecodeHybridCiphertext(s string) ([]byte, error) { return kemDecode(s) }

// EncodeXWingPublicKey is the unpadded base64url form of an X-Wing public key.
func EncodeXWingPublicKey(k []byte) string { return kemEncode(k) }

// DecodeXWingPublicKey strictly decodes a base64url X-Wing public key (the length is not checked).
func DecodeXWingPublicKey(s string) ([]byte, error) { return kemDecode(s) }

// EncodeXWingCiphertext is the unpadded base64url form of an X-Wing ciphertext.
func EncodeXWingCiphertext(c []byte) string { return kemEncode(c) }

// DecodeXWingCiphertext strictly decodes a base64url X-Wing ciphertext (the length is not checked).
func DecodeXWingCiphertext(s string) ([]byte, error) { return kemDecode(s) }
