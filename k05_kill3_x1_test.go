package pca

import (
	"fmt"
	"testing"
)

// x509-strict.ts strictChainError: an extension table its strict reader refuses is a failure, even when the role reader passes
// (readCertRoleInfo walks an empty Extensions SEQUENCE; parseTbsExtensions throws on it).
func TestK05Kill3X1StrictChainExtensionParseFailure(t *testing.T) {
	raw := []byte{0x30, 0x06, 0x30, 0x04, 0xa3, 0x02, 0x30, 0x00}
	if r := checkChainRoles([][]byte{raw}); r != "" {
		t.Fatalf("the role reader must pass this certificate: %q", r)
	}
	const want = "certificate extension parse failed: empty Extensions SEQUENCE"
	if got := strictChainError([]*attCert{{Raw: raw}}); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// Every SDK refuses a malformed wire allowlist at construction (the same row exists for Swift, Kotlin and .NET), so a second,
// valid allowlist does not hide it.
func TestK05Kill3X1MaaMalformedSevListRefused(t *testing.T) {
	const want = "createAzureMaaVerifier: policy.sevSnpMeasurements must be a list of strings"
	cfg := func(sev string) map[string]any {
		return parityCfg(t, `{"trustedIssuers":["https://i"],"trustAnchors":{"rootSpkiSha256":["aa"]},"policy":{"sevSnpMeasurements":`+sev+`,"tdxMrtds":["bb"]}}`)
	}
	for _, sev := range []string{`[1]`, `["aa",1]`, `"aa"`} {
		if _, err := VerifierFromConfig("azure-maa", cfg(sev)); fmt.Sprint(err) != want {
			t.Errorf("%s: %v, want %q", sev, err, want)
		}
	}
	if _, err := VerifierFromConfig("azure-maa", cfg(`null`)); err != nil {
		t.Errorf("null is no list: %v", err)
	}
}

// RFC 5280 GeneralName, as OpenSSL decodes it: [0] otherName, [5] ediPartyName and [8] registeredID are names, the neighbouring
// tags are not.
func TestK05Kill3X1SanGeneralNameTags(t *testing.T) {
	san := func(name ...byte) *attCert {
		return &attCert{exts: []lenientExt{{oid: "2.5.29.17", value: append([]byte{0x30, byte(len(name))}, name...)}}}
	}
	for _, r := range []struct {
		name string
		der  []byte
		want bool
	}{
		{"otherName", []byte{0xa0, 0x0a, 0x06, 0x03, 0x2a, 0x03, 0x04, 0xa0, 0x03, 0x0c, 0x01, 0x78}, true},
		{"ediPartyName", []byte{0xa5, 0x05, 0xa1, 0x03, 0x0c, 0x01, 0x78}, true},
		{"registeredID", []byte{0x88, 0x03, 0x2a, 0x03, 0x04}, true},
		{"after otherName", []byte{0xa1, 0x00}, false},
		{"after ediPartyName", []byte{0xa6, 0x00}, false},
		{"after registeredID", []byte{0x89, 0x00}, false},
	} {
		if got := certSanDecodes(san(r.der...)); got != r.want {
			t.Errorf("%s: %v, want %v", r.name, got, r.want)
		}
	}
}

func TestK05Kill3X1ListHelpersRefuseNonLists(t *testing.T) {
	for _, v := range []any{nil, "aa", map[string]any{}} {
		if l, ok := hexListOf(v); ok || l != nil {
			t.Errorf("hexListOf(%v) = %v, %v", v, l, ok)
		}
	}
	const want = "p: policy.k must be a list"
	list, has, err := optionalStatusList(map[string]any{"k": "UpToDate"}, "k", "p: ")
	if list != nil || has || fmt.Sprint(err) != want {
		t.Errorf("non-list: %v %v %v", list, has, err)
	}
	if list, has, err = optionalStatusList(map[string]any{"k": []any{"UpToDate"}}, "k", "p: "); len(list) != 1 || !has || err != nil {
		t.Errorf("list: %v %v %v", list, has, err)
	}
}
