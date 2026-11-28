package pca

// Per-run identity material for the TLS mesh: one fresh P-256 key and self-signed certificate per node, from crypto/x509 and
// crypto/ecdsa (no hand-rolled crypto, no X.509 code of our own). The key lives only on the node that generated it; only the
// PUBLIC certificates are exchanged and pinned.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"time"
)

// MpcGenerateIdentity makes a throw-away identity (valid two days) for cn. rnd nil means crypto/rand.
func MpcGenerateIdentity(cn string, rnd io.Reader) (keyPEM, certPEM string, err error) {
	if rnd == nil {
		rnd = rand.Reader
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rnd)
	if err != nil {
		return "", "", err
	}
	serial, err := rand.Int(rnd, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return "", "", err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(48 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rnd, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return "", "", err
	}
	kd, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd})),
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), nil
}

func mpcCertDER(certPEM string) ([]byte, error) {
	b, _ := pem.Decode([]byte(certPEM))
	if b == nil || b.Type != "CERTIFICATE" {
		return nil, errors.New("not a PEM certificate")
	}
	return b.Bytes, nil
}

func mpcFingerprintDER(der []byte) string {
	h := sha256.Sum256(der)
	return hex.EncodeToString(h[:])
}

// MpcFingerprintOf is the SHA-256 fingerprint (lowercase hex of the DER) of a PEM certificate.
func MpcFingerprintOf(certPEM string) (string, error) {
	der, err := mpcCertDER(certPEM)
	if err != nil {
		return "", err
	}
	return mpcFingerprintDER(der), nil
}
