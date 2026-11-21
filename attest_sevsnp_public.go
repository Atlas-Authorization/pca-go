package pca

// The public surface of the AMD SEV-SNP report module: the report parser and signature check, the P-384 key helpers, the VCEK
// extraction, the end-to-end genuine-report verification, the acceptance policy and its default identity mapping, and the
// KDS VCEK fetch over an injectable transport. They are documented wrappers over the verifier of attest_amd.go.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"regexp"
)

const (
	// SevSnpSigAlgoEcdsaP384Sha384 is the SIGNATURE_ALGO value of ECDSA over P-384 with SHA-384 (the only one SEV-SNP uses today).
	SevSnpSigAlgoEcdsaP384Sha384 = snpSigAlgoECDSAP384
	// AmdMilanArkSpkiSha384 is the SHA-384 (lowercase hex) of the SPKI of AMD's Milan ARK.
	AmdMilanArkSpkiSha384 = "1249f67f15cf229a4069195e1a9ce537d1765ef706a1f4a123c36be9518786515d25ecc007f366b564d2b3f31c48082e"
)

// KnownAmdArkSpkiSha384 returns the pinned ARK SPKI SHA-384 (lowercase hex) of each supported AMD family: milan, genoa, turin.
func KnownAmdArkSpkiSha384() map[string]string {
	out := make(map[string]string, len(amdARKSpkiSHA384))
	for k, v := range amdARKSpkiSHA384 {
		out[k] = v
	}
	return out
}

// SevSnpFirmwareVersion is an SNP firmware version as AMD defines it (major.minor build N).
type SevSnpFirmwareVersion struct{ Major, Minor, Build uint8 }

// SevSnpReport is a parsed AMD SEV-SNP ATTESTATION_REPORT, every field of the report. Byte slices are fresh copies.
type SevSnpReport struct {
	Version, GuestSvn, Vmpl, SignatureAlgo uint32
	Policy, ReportedTcb                    uint64
	CommittedTcb, LaunchTcb                uint64
	ReportData, Measurement, HostData      []byte
	ChipID, Signed, SignatureR, SignatureS []byte
	// FamilyID and ImageID are the 16-byte guest family and image ids; CurrentTcb is the current TCB version and PlatformInfo the
	// platform info word (SMT, TSME ...).
	FamilyID, ImageID        []byte
	CurrentTcb, PlatformInfo uint64
	// IDKeyDigest and AuthorKeyDigest are the SHA-384 digests of the ID and author keys; ReportID and ReportIDMa the 32-byte report
	// ids of the guest and of its migration agent.
	IDKeyDigest, AuthorKeyDigest, ReportID, ReportIDMa []byte
	// CpuidFamID, CpuidModID and CpuidStep are the processor's CPUID family, model and stepping (report version 3 and later; 0 before).
	CpuidFamID, CpuidModID, CpuidStep uint8
	// CurrentVersion and CommittedVersion are the SNP firmware versions running and committed.
	CurrentVersion, CommittedVersion SevSnpFirmwareVersion
	// LaunchMitVector and CurrentMitVector are the mitigation vectors at launch and now (report version 5 and later; 0 before).
	LaunchMitVector, CurrentMitVector uint64
	// Raw is the whole report as given.
	Raw []byte
	r   *snpReport
}

// ParseSevSnpReport parses the fields of an attestation report (it needs at least the signature block, 0x2e8 + 72 bytes).
func ParseSevSnpReport(b []byte) (*SevSnpReport, error) {
	r, err := parseSnpReport(b)
	if err != nil {
		return nil, err
	}
	le := binary.LittleEndian
	cp := func(off, n int) []byte { return append([]byte{}, b[off:off+n]...) }
	return &SevSnpReport{
		Version: le.Uint32(b), GuestSvn: r.guestSvn, Vmpl: r.vmpl, SignatureAlgo: r.sigAlgo, Policy: r.policy, ReportedTcb: r.reportedTcb,
		CommittedTcb: r.committedTcb, LaunchTcb: r.launchTcb, ReportData: r.reportData, Measurement: r.measurement,
		HostData: r.hostData, ChipID: r.chipID, Signed: r.signed, SignatureR: r.sigR, SignatureS: r.sigS, r: r,
		FamilyID: cp(0x010, 16), ImageID: cp(0x020, 16), CurrentTcb: le.Uint64(b[0x038:]), PlatformInfo: le.Uint64(b[0x040:]),
		IDKeyDigest: cp(0x0e0, 48), AuthorKeyDigest: cp(0x110, 48), ReportID: cp(0x140, 32), ReportIDMa: cp(0x160, 32),
		CpuidFamID: b[0x188], CpuidModID: b[0x189], CpuidStep: b[0x18a],
		CurrentVersion:   SevSnpFirmwareVersion{Major: b[0x1ea], Minor: b[0x1e9], Build: b[0x1e8]},
		CommittedVersion: SevSnpFirmwareVersion{Major: b[0x1ee], Minor: b[0x1ed], Build: b[0x1ec]},
		LaunchMitVector:  le.Uint64(b[0x1f8:]), CurrentMitVector: le.Uint64(b[0x200:]), Raw: append([]byte{}, b...),
	}, nil
}

// EcdsaP384PublicKey wraps and validates a P-384 public key given as an uncompressed (97 bytes) or compressed (49 bytes) SEC1 point.
func EcdsaP384PublicKey(sec1 []byte) (*ecdsa.PublicKey, error) {
	c := elliptic.P384()
	var x, y *big.Int
	switch {
	case len(sec1) == 97 && sec1[0] == 4:
		return ecdsa.ParseUncompressedPublicKey(c, sec1)
	case len(sec1) == 49:
		x, y = elliptic.UnmarshalCompressed(c, sec1)
	}
	if x == nil {
		return nil, errors.New("ecdsaP384PublicKey: not a valid P-384 point")
	}
	out := make([]byte, 97)
	out[0] = 4
	x.FillBytes(out[1:49])
	y.FillBytes(out[49:])
	return ecdsa.ParseUncompressedPublicKey(c, out)
}

// SevSnpSignatureToCompact converts AMD's little-endian r and s (72-byte fields, the scalar in the low 48 bytes) into the
// big-endian 96-byte r||s form. A zero scalar or one at or above the curve order is an error.
func SevSnpSignatureToCompact(r, s []byte) ([]byte, error) {
	n := elliptic.P384().Params().N
	rr, ss := leToBig(r), leToBig(s)
	if rr.Sign() <= 0 || rr.Cmp(n) >= 0 {
		return nil, errors.New("sev-snp signature: r out of range")
	}
	if ss.Sign() <= 0 || ss.Cmp(n) >= 0 {
		return nil, errors.New("sev-snp signature: s out of range")
	}
	out := make([]byte, 96)
	rr.FillBytes(out[:48])
	ss.FillBytes(out[48:])
	return out, nil
}

// VerifySevSnpReportSignature verifies the report's ECDSA-P384/SHA-384 signature over its signed region under the VCEK key. It never
// panics; a malformed signature or key is false.
func VerifySevSnpReportSignature(report *SevSnpReport, vcek *ecdsa.PublicKey) bool {
	return report != nil && report.r != nil && vcek != nil && verifySnpReportSignature(report.r, vcek)
}

// ExtractTbsCertificate slices the tbsCertificate DER (header included) out of an X.509 certificate DER.
func ExtractTbsCertificate(certDer []byte) ([]byte, error) { return tbsOfCertificate(certDer) }

// ExtractVcekPublicKey decodes a genuine VCEK certificate (DER) and returns its EC secp384r1 public key and its tbsCertificate.
func ExtractVcekPublicKey(vcekDer []byte) (*ecdsa.PublicKey, []byte, error) {
	c, err := parseCertDER(vcekDer)
	if err != nil {
		return nil, nil, err
	}
	k, err := keyOfCert(c)
	if err != nil {
		return nil, nil, err
	}
	point, err := ecPointOfKey(k, "P-384")
	if err != nil {
		return nil, nil, fmt.Errorf("VCEK is not EC secp384r1: %w", err)
	}
	pub, err := EcdsaP384PublicKey(point)
	if err != nil {
		return nil, nil, err
	}
	tbs, err := tbsOfCertificate(vcekDer)
	return pub, tbs, err
}

var pemCertBundleBlock = regexp.MustCompile(`(?s)-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----`)

// SplitPemCertificates splits a PEM bundle into its individual certificate blocks.
func SplitPemCertificates(pem string) []string {
	out := pemCertBundleBlock.FindAllString(pem, -1)
	if out == nil {
		return []string{}
	}
	return out
}

// SevSnpPolicy is the acceptance policy of a verified report. Every gate is optional; an empty list gates nothing. Hex values are
// compared lowercase.
type SevSnpPolicy struct {
	Measurements []string // allowed MEASUREMENT values (hex of the 48-byte register)
	HostData     []string // allowed HOST_DATA values (hex); a launch-config gate only, the host supplies it
	ChipIds      []string // allowed CHIP_ID values (hex of the 64-byte id)
	// WeightsFromHostData is INSECURE: it maps the host-asserted HOST_DATA to weights_digest (never weights_measured).
	WeightsFromHostData bool
	// AllowDebug is INSECURE: it accepts reports whose guest policy has the DEBUG bit set.
	AllowDebug bool
	// RequireEcdsaP384 nil means true.
	RequireEcdsaP384 *bool
	MinGuestSvn      *float64
	// MinReportedTcb, MinCommittedTcb and MinLaunchTcb are compared as whole integers.
	MinReportedTcb, MinCommittedTcb, MinLaunchTcb *big.Int
	// RequireVmpl is nil (the default, VMPL 0), the string "any", or a number.
	RequireVmpl any
}

func (p *SevSnpPolicy) internal() snpPolicy {
	low := func(l []string) []string { return lowerAll(l) }
	return snpPolicy{
		measurements: low(p.Measurements), hostData: low(p.HostData), chipIDs: low(p.ChipIds), allowDebug: p.AllowDebug,
		requireEcdsaP384: p.RequireEcdsaP384 == nil || *p.RequireEcdsaP384, minGuestSvn: p.MinGuestSvn,
		minReportedTcb: p.MinReportedTcb, minCommittedTcb: p.MinCommittedTcb, minLaunchTcb: p.MinLaunchTcb, requireVmpl: p.RequireVmpl,
	}
}

// CheckSevSnpPolicy checks the report against the policy and returns the reason of the first failure, or "" when it passes.
func CheckSevSnpPolicy(report *SevSnpReport, policy SevSnpPolicy) string {
	if report == nil || report.r == nil {
		return "no report"
	}
	p := policy.internal()
	return p.check(report.r)
}

// MakeDefaultDeriveIdentity is the default report to measured-identity mapping: runtime_measurement = hex(MEASUREMENT),
// operator = hex(CHIP_ID), model_id empty, weights_digest empty (or the host-asserted HOST_DATA when weightsFromHostData) with
// weights_measured always false.
func MakeDefaultDeriveIdentity(weightsFromHostData bool) func(*SevSnpReport) MeasuredIdentity {
	return func(r *SevSnpReport) MeasuredIdentity {
		id := MeasuredIdentity{RuntimeMeasurement: toHexLower(r.Measurement), Operator: toHexLower(r.ChipID)}
		if weightsFromHostData {
			id.WeightsDigest = toHexLower(r.HostData)
		}
		return id
	}
}

// GenuineSevSnpOptions are the inputs of VerifyGenuineSevSnpReport.
type GenuineSevSnpOptions struct {
	Report, VcekDer []byte
	AskArkPem       string
	// TrustAnchorArkSpkiSha384 is the ARK pin (hex); empty means the Milan ARK.
	TrustAnchorArkSpkiSha384 string
	NowMs                    int64
	// ClockSkewMs is the tolerance on every certificate window (nil: none).
	ClockSkewMs *float64
	// Expected, when non-nil, binds report_data to the attestation binding.
	Expected *AttestationBinding
	// Policy, when non-nil, is applied after the signature and binding checks.
	Policy *SevSnpPolicy
}

// GenuineSevSnpResult is the outcome of VerifyGenuineSevSnpReport: Reason is empty exactly when OK.
type GenuineSevSnpResult struct {
	OK       bool
	Reason   string
	Report   *SevSnpReport
	Measured MeasuredIdentity
}

// VerifyGenuineSevSnpReport parses and verifies a genuine report end to end, offline: the report, the VCEK to ASK to ARK chain with
// the ARK pinned, the report signature under the chain-trusted VCEK, the VCEK to report binding, optionally report_data against
// the expected binding, and optionally the acceptance policy. It fails closed with a reason.
func VerifyGenuineSevSnpReport(o GenuineSevSnpOptions) GenuineSevSnpResult {
	pin := o.TrustAnchorArkSpkiSha384
	if pin == "" {
		pin = AmdMilanArkSpkiSha384
	}
	v := &amdVerifier{pin: pin}
	if o.ClockSkewMs != nil {
		v.skew = *o.ClockSkewMs
	}
	v.policy = snpPolicy{allowDebug: true, requireVmpl: "any"} // no policy: nothing beyond the signature, the binding and the chain
	if o.Policy != nil {
		v.policy = o.Policy.internal()
	}
	reason, rep := v.verifyReport(o.Report, o.VcekDer, o.AskArkPem, o.NowMs, o.Expected)
	if reason != "" {
		return GenuineSevSnpResult{Reason: reason}
	}
	pr, _ := ParseSevSnpReport(o.Report)
	pr.r = rep
	return GenuineSevSnpResult{OK: true, Report: pr, Measured: MakeDefaultDeriveIdentity(false)(pr)}
}

// KdsFetch is the transport of FetchVcekFromKds: it returns the HTTP status and body of a GET.
type KdsFetch func(url string) (status int, body []byte, err error)

// KdsOptions configure FetchVcekFromKds. A nil Product is "Milan", a nil BaseURL AMD's KDS and a nil Fetch net/http; a value that
// is set is used exactly as given (an empty one stays empty, a trailing slash stays).
type KdsOptions struct {
	Product, BaseURL *string
	Fetch            KdsFetch
}

func httpKdsFetch(url string) (int, []byte, error) {
	res, err := http.Get(url)
	if err != nil {
		return 0, nil, err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	return res.StatusCode, b, err
}

// FetchVcekFromKds fetches the VCEK certificate (DER) for a live report from AMD's KDS, keyed by CHIP_ID and the four reported-TCB
// SPL bytes (bootloader = byte 0, TEE = byte 1, SNP = byte 6, microcode = byte 7). It performs network I/O only through Fetch and
// is never called by the verifiers. A non-2xx response is an error.
func FetchVcekFromKds(chipID []byte, reportedTcb uint64, o KdsOptions) ([]byte, error) {
	product, base, fetch := "Milan", "https://kdsintf.amd.com/vcek/v1", o.Fetch
	if o.Product != nil {
		product = *o.Product
	}
	if o.BaseURL != nil {
		base = *o.BaseURL
	}
	if fetch == nil {
		fetch = httpKdsFetch
	}
	at := func(i uint) uint64 { return (reportedTcb >> (8 * i)) & 0xff }
	url := fmt.Sprintf("%s/%s/%s?blSPL=%d&teeSPL=%d&snpSPL=%d&ucodeSPL=%d", base, product, toHexLower(chipID), at(0), at(1), at(6), at(7))
	status, body, err := fetch(url)
	if err != nil {
		return nil, err
	}
	if status < 200 || status > 299 {
		return nil, fmt.Errorf("KDS VCEK fetch failed: HTTP %d for %s", status, url)
	}
	return body, nil
}
