package pca

import "testing"

// spdmTranscript builds a minimal request||response transcript (no measurement blocks, no opaque data) with the given versions.
func spdmTranscript(reqVersion, respVersion byte) []byte {
	b := make([]byte, spdmReqLen+8+spdmNonceLen+2+spdmSigLen)
	b[0], b[1] = reqVersion, 0xe0
	b[spdmReqLen], b[spdmReqLen+1] = respVersion, 0x60
	return b
}

func TestNvidiaSpdmVersionRule(t *testing.T) {
	for _, c := range []struct {
		req, resp byte
		want      string
	}{
		{0x11, 0x11, ""},
		{0x12, 0x12, ""},
		{0x10, 0x10, "SPDM version 0x10/0x10 is not an accepted GET_MEASUREMENTS version"},
		{0x12, 0x11, "SPDM version 0x12/0x11 is not an accepted GET_MEASUREMENTS version"},
		{0x11, 0x12, "SPDM version 0x11/0x12 is not an accepted GET_MEASUREMENTS version"},
	} {
		rep, err := parseNvidiaSpdmEvidence(spdmTranscript(c.req, c.resp))
		if err != nil {
			t.Fatal(err)
		}
		if got := spdmVersionReason(rep); got != c.want {
			t.Fatalf("%#x/%#x: got %q want %q", c.req, c.resp, got, c.want)
		}
	}
}
