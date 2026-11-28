package pca

import (
	"strings"
	"testing"
)

func TestAllowlistManifestSignVerifyProject(t *testing.T) {
	ed, _ := KeyPairFromSeedB64u(b64.EncodeToString(fill(32, 2)))
	mk := func(version int64) map[string]any {
		return map[string]any{"version": version, "issuedAt": int64(10), "notBefore": int64(10), "expiresAt": int64(1000), "entries": []any{
			map[string]any{"kind": "tdx-mrtd", "value": strings.Repeat("ab", 48), "label": "mrtd"},
			map[string]any{"kind": "nvidia-driver-version", "value": "595.71.05", "label": "drv"},
			map[string]any{"kind": "maa-signing-spki", "value": strings.Repeat("c", 64), "label": "https://x.attest.azure.net"},
			map[string]any{"kind": "gcp-image-digest", "value": "sha256:" + strings.Repeat("d", 64), "label": "img", "notAfter": int64(50)},
		}}
	}
	man, err := SignAllowlistManifest(mk(3), "op", "ed25519", ed, nil)
	if err != nil {
		t.Fatal(err)
	}
	opts := VerifyAllowlistOptions{IssuerKeys: map[string]AllowlistIssuerKey{"op": {Alg: "ed25519", EdPub: ed.Public}}, NowMs: 100}
	r := VerifyAllowlistManifest(man, opts)
	if !r.OK || r.Version != 3 || len(r.Digest) != 43 {
		t.Fatalf("verify: %+v", r)
	}
	p, err := ProjectAllowlist(r, 100)
	if err != nil || len(p.TdxMrtds) != 1 || len(p.ImageDigests) != 0 || len(p.Expired) != 1 || p.NvidiaCcDriverVersions[0] != "3539352e37312e303500000000000000" || len(p.MaaSigningSpkis["https://x.attest.azure.net"]) != 1 {
		t.Fatalf("projection: %+v %v", p, err)
	}
	rollback := int64(4)
	same := int64(3)
	other := "wrong-digest"
	cases := map[string]func(*VerifyAllowlistOptions){
		"rollback":          func(o *VerifyAllowlistOptions) { o.LastSeenVersion = &rollback },
		"conflict":          func(o *VerifyAllowlistOptions) { o.LastSeenVersion, o.LastSeenDigest = &same, &other },
		"below-min-version": func(o *VerifyAllowlistOptions) { o.MinVersion = &rollback },
		"expired":           func(o *VerifyAllowlistOptions) { o.NowMs = 5000 },
		"not-yet-valid":     func(o *VerifyAllowlistOptions) { o.NowMs = 1 },
		"unknown-issuer":    func(o *VerifyAllowlistOptions) { o.IssuerKeys = nil },
		"alg-mismatch": func(o *VerifyAllowlistOptions) {
			o.IssuerKeys = map[string]AllowlistIssuerKey{"op": {Alg: "ml-dsa-65"}}
		},
		"bad-signature": func(o *VerifyAllowlistOptions) {
			o.IssuerKeys = map[string]AllowlistIssuerKey{"op": {Alg: "ed25519", EdPub: "AAAA"}}
		},
	}
	for code, mut := range cases {
		o := opts
		mut(&o)
		if r := VerifyAllowlistManifest(man, o); r.OK || r.Code != code {
			t.Fatalf("%s: %+v", code, r)
		}
	}
	tampered := copyMap(man)
	tampered["extra"] = 1
	if r := VerifyAllowlistManifest(tampered, opts); r.OK || r.Code != "malformed" {
		t.Fatalf("unexpected member: %+v", r)
	}
	next, err := RevokeAllowlistEntry(mk(3), "tdx-mrtd", strings.Repeat("ab", 48), "", 20, 20, 2000)
	if err != nil {
		t.Fatal(err)
	}
	signed, _ := SignAllowlistManifest(next, "op", "ed25519", ed, nil)
	rv := VerifyAllowlistManifest(signed, opts)
	rp, _ := ProjectAllowlist(rv, 100)
	if !rv.OK || rv.Version != 4 || len(rp.TdxMrtds) != 0 || len(rp.Revoked) != 1 {
		t.Fatalf("revocation: %+v %+v", rv, rp)
	}
	if _, err := CreateAllowlistManifest(map[string]any{"version": 0}); err == nil {
		t.Fatal("a malformed body must be refused")
	}
	if _, err := DriverVersionSlotHex("not-a-version"); err == nil {
		t.Fatal("driver version")
	}
}
