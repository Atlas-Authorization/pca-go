package pca

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"
)

func tlsDkgTestCert(t *testing.T, cn string) (keyPEM, certPEM string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kd, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd})), string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// A 2-of-3 ceremony over real mutual-TLS links: every party ends with the same group key, and a node that pins the wrong certificate for
// a peer never links to it.
func TestDkgOverMutualTlsLinks(t *testing.T) {
	ids := []int64{1, 2, 3}
	keys, certs := map[int64]string{}, map[int64]string{}
	for _, id := range ids {
		keys[id], certs[id] = tlsDkgTestCert(t, "p"+string(rune('0'+id)))
	}
	sid := bytes.Repeat([]byte{7}, 32)
	nodes := map[int64]*TlsDkgNode{}
	for _, id := range ids {
		var peers []TlsDkgPeerCert
		for _, o := range ids {
			if o != id {
				peers = append(peers, TlsDkgPeerCert{ID: o, CertPEM: certs[o]})
			}
		}
		n, err := StartTlsDkgNode(TlsDkgNodeOpts{Self: id, SessionID: sid, KeyPEM: keys[id], CertPEM: certs[id], PeerCerts: peers})
		if err != nil {
			t.Fatal(err)
		}
		nodes[id] = n
		defer n.Close()
	}
	var addrs []TlsDkgAddress
	for _, id := range ids {
		addrs = append(addrs, TlsDkgAddress{ID: id, Host: "127.0.0.1", Port: nodes[id].Port()})
	}
	var wg sync.WaitGroup
	results := make([]*RunDkgResult, len(ids))
	errs := make([]error, len(ids))
	for i, id := range ids {
		wg.Add(1)
		go func(i int, id int64) {
			defer wg.Done()
			var others []TlsDkgAddress // a node's own address is no pinned peer: the connect refuses it
			for _, ad := range addrs {
				if ad.ID != id {
					others = append(others, ad)
				}
			}
			ch, err := nodes[id].Connect(others, 10000)
			if err != nil {
				errs[i] = err
				return
			}
			tm := 10000.0
			results[i], errs[i] = RunDkgOverChannel(ch, RunDkgOpts{T: 2, Participants: ids, SessionID: sid, TimeoutMs: &tm})
		}(i, id)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("party %d: %v", ids[i], err)
		}
	}
	for _, r := range results[1:] {
		if !bytes.Equal(r.KeyPackage.GroupPublicKey, results[0].KeyPackage.GroupPublicKey) {
			t.Fatal("the parties disagree on the group key")
		}
	}

	// the dialled peer shows a certificate that is not the pinned one: the link is never made
	_, foreign := tlsDkgTestCert(t, "foreign")
	a, err := StartTlsDkgNode(TlsDkgNodeOpts{Self: 1, SessionID: sid, KeyPEM: keys[1], CertPEM: certs[1], PeerCerts: []TlsDkgPeerCert{{ID: 2, CertPEM: certs[2]}}})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := StartTlsDkgNode(TlsDkgNodeOpts{Self: 2, SessionID: sid, KeyPEM: keys[2], CertPEM: certs[2], PeerCerts: []TlsDkgPeerCert{{ID: 1, CertPEM: foreign}}})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if _, err := b.Connect([]TlsDkgAddress{{ID: 1, Host: "127.0.0.1", Port: a.Port()}}, 400); err == nil {
		t.Fatal("a link was made to a peer that is not pinned")
	}
}
