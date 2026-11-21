package pca

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"testing"
)

// Replay of the SEV-SNP report helpers against the reference (ref-sevsnp-helpers), every case: hex, the PEM splitter, the report
// parser (every field), the P-384 key and signature helpers, the report signature, the policy gate, the default identity, the KDS
// VCEK fetch over a recording transport and the VCEK certificate helpers. A reference throw requires a refusal. Go always has a
// built-in HTTP transport, so the one case that asks for "no transport at all" is refused here before the call (counted).

func sevBig(v any) *big.Int {
	if m := vecObj(v); m != nil {
		if s, ok := m["$bigint"].(string); ok {
			if n, ok := new(big.Int).SetString(s, 10); ok {
				return n
			}
		}
	}
	return nil
}

func sevBigOut(n uint64) any { return map[string]any{"$bigint": new(big.Int).SetUint64(n).String()} }

func sevVersionOut(v SevSnpFirmwareVersion) any {
	return map[string]any{"major": jsNumber(float64(v.Major)), "minor": jsNumber(float64(v.Minor)), "build": jsNumber(float64(v.Build))}
}

func sevReportOut(r *SevSnpReport) any {
	sig := sha256.Sum256(r.Signed)
	return map[string]any{
		"version": jsNumber(float64(r.Version)), "guest_svn": jsNumber(float64(r.GuestSvn)), "policy": sevBigOut(r.Policy),
		"family_id": vecBytesOut(r.FamilyID), "image_id": vecBytesOut(r.ImageID), "vmpl": jsNumber(float64(r.Vmpl)),
		"signature_algo": jsNumber(float64(r.SignatureAlgo)), "current_tcb": sevBigOut(r.CurrentTcb), "platform_info": sevBigOut(r.PlatformInfo),
		"report_data": vecBytesOut(r.ReportData), "measurement": vecBytesOut(r.Measurement), "host_data": vecBytesOut(r.HostData),
		"id_key_digest": vecBytesOut(r.IDKeyDigest), "author_key_digest": vecBytesOut(r.AuthorKeyDigest),
		"report_id": vecBytesOut(r.ReportID), "report_id_ma": vecBytesOut(r.ReportIDMa), "reported_tcb": sevBigOut(r.ReportedTcb),
		"cpuid_fam_id": jsNumber(float64(r.CpuidFamID)), "cpuid_mod_id": jsNumber(float64(r.CpuidModID)), "cpuid_step": jsNumber(float64(r.CpuidStep)),
		"chip_id": vecBytesOut(r.ChipID), "committed_tcb": sevBigOut(r.CommittedTcb),
		"current_version": sevVersionOut(r.CurrentVersion), "committed_version": sevVersionOut(r.CommittedVersion),
		"launch_tcb": sevBigOut(r.LaunchTcb), "launch_mit_vector": sevBigOut(r.LaunchMitVector), "current_mit_vector": sevBigOut(r.CurrentMitVector),
		"signature":  map[string]any{"r": vecBytesOut(r.SignatureR), "s": vecBytesOut(r.SignatureS)},
		"signed_len": jsNumber(float64(len(r.Signed))), "signed_sha256": hex.EncodeToString(sig[:]), "raw_len": jsNumber(float64(len(r.Raw))),
	}
}

// sevPolicy is the policy of a corpus object: only a value of the type the reference reads counts (a number where a bigint is
// read is ignored, a string where a list is read gates nothing); a list element that is no string is refused as the reference does.
func sevPolicy(m map[string]any) (SevSnpPolicy, error) {
	var p SevSnpPolicy
	list := func(k string) ([]string, error) {
		l, ok := m[k].([]any)
		if !ok {
			return nil, nil
		}
		out := make([]string, 0, len(l))
		for _, x := range l {
			s, ok := x.(string)
			if !ok {
				return nil, errors.New("x.toLowerCase is not a function")
			}
			out = append(out, s)
		}
		return out, nil
	}
	var err error
	if p.Measurements, err = list("measurements"); err != nil {
		return p, err
	}
	if p.HostData, err = list("hostData"); err != nil {
		return p, err
	}
	if p.ChipIds, err = list("chipIds"); err != nil {
		return p, err
	}
	p.AllowDebug = m["allowDebug"] == true
	if b, ok := m["requireEcdsaP384"].(bool); ok {
		p.RequireEcdsaP384 = &b
	}
	if f, ok := jsNum(m["minGuestSvn"]); ok {
		p.MinGuestSvn = &f
	}
	p.MinReportedTcb, p.MinCommittedTcb, p.MinLaunchTcb = sevBig(m["minReportedTcb"]), sevBig(m["minCommittedTcb"]), sevBig(m["minLaunchTcb"])
	switch v := m["requireVmpl"].(type) {
	case nil:
	case string:
		p.RequireVmpl = v
	default:
		if f, ok := jsNum(v); ok {
			p.RequireVmpl = f
		}
	}
	return p, nil
}

func TestSevSnpHelpersMatchTheReference(t *testing.T) {
	noFetch := 0
	report := func(v any) (*SevSnpReport, error) {
		b, ok := qvBytes(v)
		if !ok {
			return nil, errors.New("the report is bytes")
		}
		return ParseSevSnpReport(b)
	}
	fns := map[string]vecFn{
		"constants": func([]any) (any, error) {
			return map[string]any{"SEV_SNP_SIG_ALGO_ECDSA_P384_SHA384": jsNumber(SevSnpSigAlgoEcdsaP384Sha384), "SEV_SNP_POLICY_DEBUG_BIT": sevBigOut(snpPolicyDebugBit),
				"AMD_MILAN_ARK_SPKI_SHA384": AmdMilanArkSpkiSha384}, nil
		},
		"toHex": func(a []any) (any, error) {
			b, ok := qvBytes(vecArg(a, 0))
			if !ok {
				return nil, errors.New("bytes expected")
			}
			return toHexLower(b), nil
		},
		"splitPemCertificates": func(a []any) (any, error) {
			s, _ := vecArg(a, 0).(string)
			return rsStringsOut(SplitPemCertificates(s)), nil
		},
		"parseReport": func(a []any) (any, error) {
			r, err := report(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			return sevReportOut(r), nil
		},
		"ecdsaP384PublicKey": func(a []any) (any, error) {
			b, _ := qvBytes(vecArg(a, 0))
			pub, err := EcdsaP384PublicKey(b)
			if err != nil {
				return nil, err
			}
			pt, err := pub.Bytes()
			return map[string]any{"point": vecBytesOut(pt)}, err
		},
		"signatureToCompact": func(a []any) (any, error) {
			m := vecObj(vecArg(a, 0))
			r, _ := qvBytes(m["r"])
			s, _ := qvBytes(m["s"])
			out, err := SevSnpSignatureToCompact(r, s)
			if err != nil {
				return nil, err
			}
			return vecBytesOut(out), nil
		},
		"verifyReportSignature": func(a []any) (any, error) {
			r, err := report(vecArg(a, 0))
			if err != nil {
				return false, nil
			}
			kb, ok := qvBytes(vecArg(a, 1))
			if !ok {
				return false, nil
			}
			pub, err := EcdsaP384PublicKey(kb)
			if err != nil {
				return false, nil
			}
			return VerifySevSnpReportSignature(r, pub), nil
		},
		"checkPolicy": func(a []any) (any, error) {
			r, err := report(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			pm := vecObj(scDecode(vecArg(a, 1)))
			if pm == nil {
				return nil, errors.New("Cannot read properties of null (reading 'requireEcdsaP384')")
			}
			pol, err := sevPolicy(pm)
			if err != nil {
				return nil, err
			}
			if why := CheckSevSnpPolicy(r, pol); why != "" {
				return why, nil
			}
			return nil, nil
		},
		"deriveIdentity": func(a []any) (any, error) {
			r, err := report(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			return MakeDefaultDeriveIdentity(vecArg(a, 1) == true)(r).Map(), nil
		},
		"fetchVcek": func(a []any) (any, error) {
			chip, _ := qvBytes(vecArg(a, 0))
			tcb := sevBig(vecArg(a, 1))
			o := vecObj(vecArg(a, 2))
			if o["noFetch"] == true {
				noFetch++
				return nil, errors.New("fetchVcekFromKds: no fetch implementation available")
			}
			body, _ := qvBytes(o["body"])
			status, _ := jsNum(o["status"])
			var url string
			ko := KdsOptions{Fetch: func(u string) (int, []byte, error) { url = u; return int(status), body, nil }}
			if s, ok := o["product"].(string); ok {
				ko.Product = &s
			}
			if s, ok := o["baseUrl"].(string); ok {
				ko.BaseURL = &s
			}
			out, err := FetchVcekFromKds(chip, tcb.Uint64(), ko)
			if err != nil {
				return nil, err
			}
			return map[string]any{"url": url, "bytes": vecBytesOut(out)}, nil
		},
		"extractTbsCertificate": func(a []any) (any, error) {
			b, _ := qvBytes(vecArg(a, 0))
			tbs, err := ExtractTbsCertificate(b)
			if err != nil {
				return nil, err
			}
			return vecBytesOut(tbs), nil
		},
		"extractVcekPublicKey": func(a []any) (any, error) {
			b, _ := qvBytes(vecArg(a, 0))
			pub, tbs, err := ExtractVcekPublicKey(b)
			if err != nil {
				return nil, err
			}
			pt, err := pub.Bytes()
			if err != nil {
				return nil, err
			}
			return map[string]any{"point": vecBytesOut(pt), "tbs": vecBytesOut(tbs)}, nil
		},
		"checkVcekReportBinding": func(a []any) (any, error) {
			tbs, _ := qvBytes(vecArg(a, 0))
			rb, _ := qvBytes(vecArg(a, 1))
			if why := CheckVcekReportBinding(tbs, rb); why != "" {
				return why, nil
			}
			return nil, nil
		},
	}
	cmp := map[string]func(want, got any) bool{
		"checkVcekReportBinding": func(want, got any) bool { // after "VCEK extensions malformed:" only the prefix is compared
			const pre = "VCEK extensions malformed:"
			if w, ok := want.(string); ok && strings.HasPrefix(w, pre) {
				g, ok := got.(string)
				return ok && strings.HasPrefix(g, pre)
			}
			return baseCanon(want) == baseCanon(got)
		},
	}
	replayAll(t, "ref-sevsnp-helpers.json.gz", 248, vecSeeded(fns), cmp, map[string]bool{"parseReport": true, "signatureToCompact": true, "fetchVcek": true})
	if noFetch != 1 {
		t.Fatalf("%d no-transport cases were refused before the call, 1 is expected", noFetch)
	}
}
