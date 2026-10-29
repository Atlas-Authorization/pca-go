package pca

import (
	"errors"
	"os"
	"slices"
	"testing"
)

// Replays packages/pca/conformance/passport-vectors.json (signed agent passport): every signature suite this verifier
// implements (a suite it does not implement must answer unsupported_suite), and the hardware branch through a stub
// vendor verifier that answers what the vector says.
func TestPassportConformance(t *testing.T) {
	raw, err := os.ReadFile(dir + "passport-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	pv, err := ParseJSONLenient(raw) // a trusted fixture: the vendor evidence of the hardware table exceeds the signed-wire size limit
	if err != nil {
		t.Fatal(err)
	}
	vs := pv.(map[string]any)["passport_vectors"].([]any)
	if len(vs) < 74 {
		t.Fatalf("only %d vectors", len(vs))
	}
	docs := map[string]any{}
	supported := SupportedSuites()
	seenSuites := replayPassportRows(t, vs, docs, supported)
	if seenSuites < 3 {
		t.Fatalf("only %d vectors exercised a supported post-quantum suite", seenSuites)
	}

	// passport_hardware_vectors: hardware-rooted passports verified by the REAL vendor verifiers built from the vendor
	// configuration (verifier_from_config), through the default-verifier seam of VerifyPassport. The table is produced by
	// the TypeScript generator; its absence is a failure, never a skip.
	hw, ok := pv.(map[string]any)["passport_hardware_vectors"].([]any)
	if !ok {
		t.Fatal("passport-vectors.json has no passport_hardware_vectors table: regenerate it with the TypeScript reference (tsx scripts/gen-conformance-passport.ts in packages/pca)")
	}
	if len(hw) < 40 {
		t.Fatalf("only %d passport_hardware_vectors", len(hw))
	}
	replayPassportRows(t, hw, docs, supported)
}

// replayPassportRows verifies every row and returns how many exercised a supported signature suite.
func replayPassportRows(t *testing.T, vs []any, docs map[string]any, supported []string) int {
	seenSuites := 0
	for _, x := range vs {
		v := x.(map[string]any)
		name := v["name"].(string)
		signed := v["signed"]
		if ref, ok := v["signed_ref"].(string); ok {
			signed = docs[ref]
		}
		docs[name] = signed
		var issuers, revoked []string
		for _, i := range v["trustedIssuers"].([]any) {
			issuers = append(issuers, i.(string))
		}
		for _, r := range v["revoked"].([]any) {
			revoked = append(revoked, r.(string))
		}
		o := PassportOptions{TrustedIssuers: issuers, NowMs: num(v["now"]),
			Revoked: func(id, _, _ string) (bool, error) { return slices.Contains(revoked, id), nil }}
		if n, ok := v["clockSkewMs"]; ok {
			o.ClockSkewMs = ptr(num(n))
		}
		if n, ok := v["maxEvidenceAgeMs"]; ok {
			o.MaxEvidenceAgeMs = ptr(num(n))
		}
		if s, ok := v["subject"].(string); ok {
			o.Subject = &s
		}
		if pins, ok := v["pqPins"].(map[string]any); ok {
			o.PQPins = map[string]string{}
			for k, p := range pins {
				o.PQPins[k] = p.(string)
			}
		}
		var gotBinding *PassportBinding
		if h, ok := v["hardware"].(map[string]any); ok {
			o.Attest = func(_ map[string]any, b PassportBinding) (PassportAttestation, error) {
				gotBinding = &b
				if h["throws"] == true {
					return PassportAttestation{}, errors.New("verifier down")
				}
				r := PassportAttestation{OK: h["ok"] == true, Bound: h["bound"] == true}
				if m, ok := h["measured"].(map[string]any); ok {
					r.Measured = m
				}
				return r, nil
			}
		}
		if hv, ok := v["hardware_verifier"].(map[string]any); ok {
			vendor, _ := hv["vendor"].(string)
			cfg, _ := hv["config"].(map[string]any)
			ver, err := VerifierFromConfig(vendor, cfg)
			if err != nil {
				t.Errorf("%s: %v", name, err)
				continue
			}
			ev, _ := hv["evidence"].(map[string]any)
			o.DefaultHardware = &DefaultHardware{Verifier: ver, Evidence: func(map[string]any) map[string]any { return ev }}
		}
		got := VerifyPassport(signed, o)
		want := ""
		if e := v["expect"].(map[string]any); e["ok"] != true {
			want = e["reason"].(string)
		}
		sm, _ := signed.(map[string]any)
		if alg, ok := sm["alg"].(string); ok && !slices.Contains(supported, alg) {
			want = "unsupported_suite"
		} else if ok {
			seenSuites++
		}
		if got != want {
			t.Errorf("%s: got %q want %q", name, got, want)
		}
		if eb, ok := v["expectBinding"].(map[string]any); ok {
			if gotBinding == nil || gotBinding.HolderPub != eb["holderPub"] || gotBinding.GrantRef != eb["grantRef"] || gotBinding.Epoch != num(eb["epoch"]) || gotBinding.Nonce != eb["nonce"] {
				t.Errorf("%s: verifier handed %+v want %v", name, gotBinding, eb)
			}
		}
	}
	return seenSuites
}

func ptr(n int64) *int64 { return &n }
