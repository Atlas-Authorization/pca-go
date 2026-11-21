package pca

import (
	"bytes"
	"testing"
)

// A Go string holds a lone surrogate as WTF-8 (ED A0 80); the reference TextEncoder writes U+FFFD (EF BF BD) into every hash input.
const (
	loneSurrogate = "\xed\xa0\x80"
	fffd          = "\xef\xbf\xbd"
)

func TestLoneSurrogateHashInputsAreFffd(t *testing.T) {
	if leaseShardOf("x"+loneSurrogate, 16) != leaseShardOf("x"+fffd, 16) {
		t.Fatal("lease shard hashed the WTF-8 bytes")
	}
	if !bytes.Equal(linkMessage("d", "x"+loneSurrogate), linkMessage("d", "x"+fffd)) {
		t.Fatal("link message hashed the WTF-8 bytes")
	}
	if !bytes.Equal(pDomainMessage("d", "x"+loneSurrogate), pDomainMessage("d", "x"+fffd)) {
		t.Fatal("prohibition domain message hashed the WTF-8 bytes")
	}
	if MpcGadgetCommit("s"+loneSurrogate, 1, []byte{1}) != MpcGadgetCommit("s"+fffd, 1, []byte{1}) {
		t.Fatal("gadget commit hashed the WTF-8 bytes")
	}
	if !bytes.Equal(connAAD(ConnectionKey{AgentID: "a" + loneSurrogate}, "f"), connAAD(ConnectionKey{AgentID: "a" + fffd}, "f")) {
		t.Fatal("connection aad kept the WTF-8 bytes")
	}
}

func TestCibaClientRefusesALoneSurrogateCredential(t *testing.T) {
	_, err := NewCibaClient(CibaClientConfig{
		BackchannelAuthenticationEndpoint: "https://idp.example/bc", TokenEndpoint: "https://idp.example/token",
		ClientID: "c" + loneSurrogate, ClientSecret: "s",
	})
	if err == nil {
		t.Fatal("encodeURIComponent throws on a lone surrogate; the client must refuse it")
	}
}
