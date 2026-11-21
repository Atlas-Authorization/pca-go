package pca

import (
	"bytes"
	"strings"
	"testing"
)

// A delegated responder certificate is read from the response's own bytes: a flipped byte anywhere inside it is refused.
func TestOcspEmbeddedCertificateIsNotNormalised(t *testing.T) {
	f := g02newFx(t)
	resp := f.responder(t, nil, f.inter, f.interK)
	der := f.mod(t, func(r *g02rsp) { r.rid, r.certs, r.signer = g02byName(g02att(t, resp.Raw)), g02certs(resp.Raw), f.respK })
	verify := func(b []byte) ocspResult { return verifyNvidiaOcspResponse(b, f.leafA, f.interA, f.chain, f.nowMs) }
	if got := verify(der); !got.ok {
		t.Fatalf("untouched response: %+v", got)
	}
	at := bytes.Index(der, resp.Raw)
	if at < 0 {
		t.Fatal("certificate not found in the response")
	}
	for i := at; i < at+len(resp.Raw); i += 3 {
		bad := append([]byte(nil), der...)
		bad[i] ^= 1
		if got := verify(bad); got.ok {
			t.Fatalf("flipped byte %d inside the embedded certificate verified", i-at)
		}
	}
}

func TestBuildNvidiaOcspRequestRefusesUnknownHash(t *testing.T) {
	_, err := BuildNvidiaOcspRequest(nil, nil, NvidiaOcspRequestOptions{Hash: "md5"})
	if err == nil || !strings.Contains(err.Error(), "unsupported CertID hash") {
		t.Fatalf("md5: %v", err)
	}
}
