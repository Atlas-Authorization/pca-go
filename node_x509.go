package pca

import "crypto"

// NodeCert is a certificate as node:crypto's X509Certificate (OpenSSL) reads it: the structure checks of the OpenSSL template
// decoder and nothing more (bytes after the certificate are not part of it). A low-level building block of the offline Sigstore
// verifier (module pca-go/sigstore), which must judge certificates exactly as the TypeScript reference does.
type NodeCert struct{ c *attCert }

// ParseNodeCert parses one DER certificate like d2i_X509.
func ParseNodeCert(der []byte) (*NodeCert, error) {
	c, err := parseCertDER(der)
	if err != nil {
		return nil, err
	}
	return &NodeCert{c}, nil
}

// Subject and Issuer are the DER Names (header included); SPKI the DER SubjectPublicKeyInfo.
func (n *NodeCert) Subject() []byte { return n.c.RawSubject }
func (n *NodeCert) Issuer() []byte  { return n.c.RawIssuer }
func (n *NodeCert) SPKI() []byte    { return n.c.RawSPKI }

// PublicKey is X509Certificate.publicKey (an error when node:crypto could not read it).
func (n *NodeCert) PublicKey() (crypto.PublicKey, error) {
	k, err := keyOfCert(n.c)
	return k.pub, err
}

// CA is X509Certificate.ca: BasicConstraints CA:TRUE, and keyCertSign when keyUsage is present.
func (n *NodeCert) CA() bool { return certIsCA(n.c) }

// CheckIssued is X509Certificate.checkIssued(up): the name link, the authority key identifier against up, keyCertSign on up, and
// no extension OpenSSL caches that fails to decode on either certificate. Stricter than Node on the rare shapes listed where
// certCheckIssued and its decoders are documented.
func (n *NodeCert) CheckIssued(up *NodeCert) bool { return certCheckIssued(n.c, up.c) }

// SignedBy is X509Certificate.verify(parent.publicKey): the signature only (no name or role checks).
func (n *NodeCert) SignedBy(parent *NodeCert) bool { return certSigOKBy(n.c, parent.c) }

// ValidAt: validFrom <= ms <= validTo (false when either bound is unreadable).
func (n *NodeCert) ValidAt(ms int64) bool { return derValidAt(n.c.Raw, ms, 0) }
