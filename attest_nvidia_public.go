package pca

// The public surface of the NVIDIA GPU-CC modules beyond the verifier: the constants, the SPDM challenge, the certificate helpers,
// the report and RIM accessors, the OCSP request builder with the full response and chain policy results, and the fetch helpers over
// an injectable transport (nothing here is ever called by a verifier).

import (
	"crypto"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
)

const (
	// NvidiaSpdmSuite is the attestation suite label of the NVIDIA GPU SPDM root.
	NvidiaSpdmSuite = "nvidia-gpu-spdm-ecdsa-p384-sha384"
	// NvidiaRimBaseUrl is the NVIDIA RIM service, a RIM id is appended to it.
	NvidiaRimBaseUrl = "https://rim.attestation.nvidia.com/v1/rim/"
	// NvidiaOcspUrl is NVIDIA's public OCSP responder.
	NvidiaOcspUrl = "http://ocsp.ndis.nvidia.com/"
	// NvidiaOcspDefaultMaxAgeMs is the default maximum age of a response (thisUpdate to now): 7 days.
	NvidiaOcspDefaultMaxAgeMs = int64(7 * 24 * 3600 * 1000)
)

// NvidiaGh100CrlUrls and NvidiaGb100CrlUrls are the CRL distribution points of the Hopper and Blackwell device chains.
var (
	NvidiaGh100CrlUrls = []string{"https://crl.ndis.nvidia.com/crl/l2-gh100.crl", "https://crl.ndis.nvidia.com/crl/l1-root.crl"}
	NvidiaGb100CrlUrls = []string{"https://crl.ndis.nvidia.com/crl/l2-gb100.crl", "https://crl.ndis.nvidia.com/crl/l1-root.crl"}
)

// NvidiaOpaque are the opaque-data TLV types of a report that are surfaced by name.
var NvidiaOpaque = map[string]int{
	"CERT_ISSUER_NAME": 1, "CERT_AUTHORITY_KEY_IDENTIFIER": 2, "DRIVER_VERSION": 3, "GPU_INFO": 4, "SKU": 5, "VBIOS_VERSION": 6,
	"MANUFACTURER_ID": 7, "TAMPER_DETECTION": 8, "MSRSCNT": 12, "BOARD_ID": 14, "FWID": 20, "OPAQUE_DATA_VERSION": 34, "CHIP_INFO": 35, "FEATURE_FLAG": 36,
}

// NvidiaSpdmChallenge is the 32-byte SPDM challenge that carries the PCA binding: sha256 of the attestation binding of expected.
func NvidiaSpdmChallenge(expected ExpectedAttestationBinding) ([]byte, error) {
	b, err := AttestationBindingBytes(expected)
	if err != nil {
		return nil, err
	}
	return sha256Sum(b), nil
}

// SpkiSha256Hex is the SHA-256 of a certificate's SubjectPublicKeyInfo as lowercase hex: the pin format of a root.
func SpkiSha256Hex(cert *NodeCert) (string, error) {
	k, err := keyOfCert(cert.c)
	if err != nil {
		return "", err
	}
	return k.spkiSHA256(), nil
}

// ParsePemChain splits a PEM bundle into its certificates (leaf first); none, more than five, or one that does not parse is an error.
func ParsePemChain(pem string) ([]*NodeCert, error) {
	blocks := pemCertBlocks(pem)
	if len(blocks) == 0 {
		return nil, errors.New("parsePemChain: no certificates found")
	}
	if len(blocks) > nvidiaMaxChn {
		return nil, fmt.Errorf("parsePemChain: chain longer than %d", nvidiaMaxChn)
	}
	out := make([]*NodeCert, 0, len(blocks))
	for _, b := range blocks {
		c, err := ParseNodeCertPEM(b)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// NvidiaCertOcspUrls lists the OCSP responder URLs a certificate advertises in its Authority Information Access extension.
func NvidiaCertOcspUrls(cert *NodeCert) []string {
	if u := cert.c.ocspServers(); u != nil {
		return u
	}
	return []string{}
}

// AllAsn1TimesWellFormed reports whether every GeneralizedTime and UTCTime inside the DER value is a well-formed DER time with in-range
// fields (no calendar roll-over). The contents of an OCTET STRING or BIT STRING are opaque and never inspected; a value that does not
// parse is false.
func AllAsn1TimesWellFormed(der []byte) bool {
	top, err := readOcspNode(der, 0, len(der))
	if err != nil {
		return false
	}
	return ocspTimesWellFormed(der, top)
}

// ---- report and RIM accessors -------------------------------------------------------------------------------------------------

// SpdmMeasurement is one measurement block of a report: its index, DMTF value type and digest.
type SpdmMeasurement struct {
	Index     int
	ValueType byte
	Digest    []byte
}

// RequestVersion, RequestCode, RequestParam1, RequestParam2, RequestNonce and Slot are the fields of the report's GET_MEASUREMENTS request.
func (r *spdmReport) RequestVersion() byte { return r.reqVersion }
func (r *spdmReport) RequestCode() byte    { return r.reqCode }
func (r *spdmReport) RequestParam1() byte  { return r.reqParam1 }
func (r *spdmReport) RequestParam2() byte  { return r.reqParam2 }
func (r *spdmReport) RequestNonce() []byte { return append([]byte{}, r.requestNonce...) }
func (r *spdmReport) Slot() byte           { return r.slot }

// ResponseVersion, ResponseCode, NumBlocks, Measurements, ResponderNonce, Opaque and Signature are the fields of the response.
func (r *spdmReport) ResponseVersion() byte { return r.respVersion }
func (r *spdmReport) ResponseCode() byte    { return r.respCode }
func (r *spdmReport) NumBlocks() int        { return r.numBlocks }
func (r *spdmReport) Measurements() []SpdmMeasurement {
	out := make([]SpdmMeasurement, len(r.measurements))
	for i, m := range r.measurements {
		out[i] = SpdmMeasurement{Index: m.index, ValueType: m.valueType, Digest: append([]byte{}, m.digest...)}
	}
	return out
}
func (r *spdmReport) ResponderNonce() []byte { return append([]byte{}, r.responderNonce...) }
func (r *spdmReport) Opaque() map[int][]byte {
	out := make(map[int][]byte, len(r.opaque))
	for k, v := range r.opaque {
		out[k] = append([]byte{}, v...)
	}
	return out
}
func (r *spdmReport) Signature() []byte { return append([]byte{}, r.signature...) }

// SignedBytes are the bytes the device key signs: the request and the response without its signature.
func (r *spdmReport) SignedBytes() []byte { return append([]byte{}, r.signedBytes...) }

// RimGolden is one golden measurement of a RIM.
type RimGolden struct {
	Index, Alternatives, Size int
	Active                    bool
	Hashes                    []string
}

// TagID, Product, Version and SignerSubject describe a verified RIM; Golden lists its measurements in ascending index.
func (v *verifiedRim) TagID() string         { return v.tagID }
func (v *verifiedRim) Product() string       { return v.product }
func (v *verifiedRim) Version() string       { return v.version }
func (v *verifiedRim) SignerSubject() string { return v.signerSubject }
func (v *verifiedRim) Golden() []RimGolden {
	idx := make([]int, 0, len(v.golden))
	for i := range v.golden {
		idx = append(idx, i)
	}
	sort.Ints(idx)
	out := make([]RimGolden, 0, len(idx))
	for _, i := range idx {
		g := v.golden[i]
		out = append(out, RimGolden{Index: g.index, Active: g.active, Alternatives: g.alternatives, Size: g.size, Hashes: append([]string{}, g.hashes...)})
	}
	return out
}

// NewVerifiedRim builds the RIM of a golden list (what a verified document carries), for comparing a report without a document.
func NewVerifiedRim(tagID, product, version string, golden []RimGolden) *VerifiedRim {
	v := &verifiedRim{tagID: tagID, product: product, version: version, golden: map[int]rimGolden{}}
	for _, g := range golden {
		v.golden[g.Index] = rimGolden{index: g.Index, active: g.Active, alternatives: g.Alternatives, size: g.Size, hashes: append([]string{}, g.Hashes...)}
	}
	return v
}

// NvidiaRimMismatch is an index at which a report differs from the golden values, with the RIM ("driver" or "vbios") that owns it.
type NvidiaRimMismatch struct {
	Index  int
	Source string
}

// NvidiaRimComparison is the outcome of CompareReportToRimsDetailed: Reason is empty exactly when the report matches, Checked is the
// number of indices compared and Mismatches (ascending) the indices that differ.
type NvidiaRimComparison struct {
	Reason     string
	Checked    int
	Mismatches []NvidiaRimMismatch
}

// CompareReportToRimsDetailed is CompareReportToRims with the number of indices checked and the indices that differ.
func CompareReportToRimsDetailed(rep *SpdmReport, driver, vbios *VerifiedRim) NvidiaRimComparison {
	r := compareRims(rep, driver, vbios)
	out := NvidiaRimComparison{Reason: r.Reason, Checked: r.Checked}
	for _, m := range r.Mismatches {
		out.Mismatches = append(out.Mismatches, NvidiaRimMismatch{Index: m.index, Source: m.source})
	}
	return out
}

// ---- OCSP: request, response, chain policy ------------------------------------------------------------------------------------

var ocspHashOIDs = map[string]struct {
	h   crypto.Hash
	oid []byte
}{
	"sha1":   {crypto.SHA1, []byte{0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a}},
	"sha256": {crypto.SHA256, []byte{0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01}},
	"sha384": {crypto.SHA384, []byte{0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02}},
	"sha512": {crypto.SHA512, []byte{0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03}},
}

// ocspDERElem is one DER element: the tag, the minimal length and the concatenated contents.
func ocspDERElem(tag byte, parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := []byte{tag}
	if n < 0x80 {
		out = append(out, byte(n))
	} else {
		var l []byte
		for v := n; v > 0; v >>= 8 {
			l = append([]byte{byte(v)}, l...)
		}
		out = append(out, 0x80|byte(len(l)))
		out = append(out, l...)
	}
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// NvidiaOcspRequestOptions configure BuildNvidiaOcspRequest: an optional nonce (1 to 32 bytes) and the CertID hash (sha1, sha256,
// sha384 or sha512; default sha384, as NVIDIA's verifier uses).
type NvidiaOcspRequestOptions struct {
	Nonce []byte
	Hash  string
}

// BuildNvidiaOcspRequest builds the DER OCSPRequest for cert (issued by issuer): one Request with a CertID over the issuer name and key
// hashes and the serial, plus the nonce extension when a nonce is given; no requestor name and no signature.
func BuildNvidiaOcspRequest(cert, issuer *NodeCert, opts NvidiaOcspRequestOptions) ([]byte, error) {
	name := opts.Hash
	if name == "" {
		name = "sha384"
	}
	h, ok := ocspHashOIDs[name]
	if !ok {
		return nil, fmt.Errorf("buildNvidiaOcspRequest: unsupported CertID hash '%s'", name)
	}
	keyBits, err := spkiKeyBits(issuer.c)
	if err != nil {
		return nil, err
	}
	certID := ocspDERElem(0x30, ocspDERElem(0x30, h.oid, []byte{0x05, 0x00}), ocspDERElem(0x04, hashBytes(h.h, issuer.c.RawSubject)),
		ocspDERElem(0x04, hashBytes(h.h, keyBits)), ocspDERElem(0x02, certSerialBytes(cert.c)))
	tbs := [][]byte{ocspDERElem(0x30, ocspDERElem(0x30, certID))}
	if opts.Nonce != nil {
		if len(opts.Nonce) < 1 || len(opts.Nonce) > 32 {
			return nil, errors.New("nonce must be 1..32 bytes")
		}
		oid := []byte{0x06, 0x09, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02}
		ext := ocspDERElem(0x30, oid, ocspDERElem(0x04, ocspDERElem(0x04, opts.Nonce)))
		tbs = append(tbs, ocspDERElem(0xa2, ocspDERElem(0x30, ext)))
	}
	return ocspDERElem(0x30, ocspDERElem(0x30, tbs...)), nil
}

// NvidiaOcspOptions are the optional limits of VerifyNvidiaOcspResponseWith: the maximum age of thisUpdate (nil: 7 days), the
// tolerated clock skew in ms and the nonce the response must echo (nil: none required).
type NvidiaOcspOptions struct {
	MaxAgeMs      *int64
	ClockSkewMs   int64
	ExpectedNonce []byte
}

// NvidiaOcspResult is the full outcome of one response: Ok with Status ("good", "revoked", "unknown"), the times in epoch ms, who
// signed it ("issuer" or "delegated") and, for a revoked certificate, RevokedAt and the optional CRL reason; or a Reason.
type NvidiaOcspResult struct {
	Ok                        bool
	Reason, Status, Responder string
	ThisUpdate, ProducedAt    int64
	NextUpdate, RevokedAt     *int64
	RevocationReason          *int
}

// VerifyNvidiaOcspResponseWith is VerifyNvidiaOcspResponse with the optional limits and the full result.
func VerifyNvidiaOcspResponseWith(der []byte, cert, issuer *NodeCert, chain []*NodeCert, nowMs int64, o NvidiaOcspOptions) NvidiaOcspResult {
	var d ocspDetail
	opt := ocspOpts{maxAgeMs: o.MaxAgeMs, skewMs: o.ClockSkewMs, detail: &d}
	if o.ExpectedNonce != nil {
		opt.wantNonce, opt.nonce = true, o.ExpectedNonce
	}
	r := verifyNvidiaOcspResponseWith(der, cert.c, issuer.c, attCerts(chain), nowMs, opt)
	if !r.ok {
		return NvidiaOcspResult{Reason: r.reason}
	}
	out := NvidiaOcspResult{Ok: true, Status: r.status, Responder: d.responder, ThisUpdate: d.thisUpdate, ProducedAt: d.producedAt}
	if d.hasNext {
		n := d.nextUpdate
		out.NextUpdate = &n
	}
	if r.status == "revoked" {
		t := d.revokedAt
		out.RevokedAt = &t
		if d.hasRevocationReason {
			v := d.revocationReason
			out.RevocationReason = &v
		}
	}
	return out
}

// NvidiaChainOcspOptions configure CheckNvidiaChainOcspWith. Which certificates must have a GOOD response: by default the non-root
// ones that advertise a responder, RequireAll every non-root one, RequireIndices (when non-nil) exactly those chain indices (0 = leaf;
// JS numbers, so a fractional or out-of-range index is named as written). MaxAgeMs and ClockSkewMs limit every response;
// ExpectedNonces holds the nonce expected per chain index (a nil entry: none).
type NvidiaChainOcspOptions struct {
	RequireAll     bool
	RequireIndices []float64
	MaxAgeMs       *int64
	ClockSkewMs    int64
	ExpectedNonces [][]byte
}

// NvidiaChainOcspResult is the outcome of the chain policy: Reason is empty exactly when it holds, VerifiedOcsp counts the verified
// responses and Statuses ("good", "revoked", "unknown" or "absent" per non-root chain index) is nil for the failures before any
// response is read.
type NvidiaChainOcspResult struct {
	Reason       string
	VerifiedOcsp int
	Statuses     map[int]string
}

// CheckNvidiaChainOcspWith is CheckNvidiaChainOcsp with the options and the per-certificate statuses.
func CheckNvidiaChainOcspWith(chain []*NodeCert, responses [][]byte, nowMs int64, o NvidiaChainOcspOptions) NvidiaChainOcspResult {
	r := checkChainOcsp(attCerts(chain), responses, nowMs, chainOcspOpts{requireAll: o.RequireAll, requireIdx: o.RequireIndices, maxAgeMs: o.MaxAgeMs,
		skewMs: o.ClockSkewMs, expectedNonces: o.ExpectedNonces})
	return NvidiaChainOcspResult{Reason: r.Reason, VerifiedOcsp: r.Verified, Statuses: r.Statuses}
}

// ---- fetch helpers ------------------------------------------------------------------------------------------------------------

// NvidiaFetch is the transport of the fetch helpers: one request (a POST carries contentType and body) answered by the status and body.
type NvidiaFetch func(method, url, contentType string, body []byte) (status int, respBody []byte, err error)

func httpNvidiaFetch(method, url, contentType string, body []byte) (int, []byte, error) {
	req, err := http.NewRequest(method, url, strings.NewReader(string(body)))
	if err != nil {
		return 0, nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, 16<<20))
	return res.StatusCode, b, err
}

var rimIDRe = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// NvidiaRimFetchOptions configure FetchNvidiaRim: the transport (nil: net/http) and the service base URL (nil: NvidiaRimBaseUrl; used
// exactly as given).
type NvidiaRimFetchOptions struct {
	Fetch   NvidiaFetch
	BaseURL *string
}

// FetchNvidiaRim fetches a RIM document from the NVIDIA RIM service and returns its XML text. The id is limited to letters, digits and
// "_.-"; a non-2xx status or an answer without a string "rim" member is an error.
func FetchNvidiaRim(id string, o NvidiaRimFetchOptions) (string, error) {
	f := o.Fetch
	if f == nil {
		f = httpNvidiaFetch
	}
	if !rimIDRe.MatchString(id) {
		return "", errors.New("fetchNvidiaRim: invalid RIM id")
	}
	base := NvidiaRimBaseUrl
	if o.BaseURL != nil {
		base = *o.BaseURL
	}
	status, body, err := f("GET", base+id, "", nil)
	if err != nil {
		return "", err
	}
	if status < 200 || status > 299 {
		return "", fmt.Errorf("RIM fetch failed: HTTP %d for %s", status, id)
	}
	doc, err := ParseJSONLenient(body)
	m, _ := doc.(map[string]any)
	rim, ok := m["rim"].(string)
	if err != nil || !ok {
		return "", errors.New("RIM fetch: response has no rim field")
	}
	return string(nodeB64(rim)), nil
}

// FetchNvidiaCrl fetches a DER CRL (a nil fetch is net/http, which follows redirects); a non-2xx status is an error.
func FetchNvidiaCrl(url string, fetch NvidiaFetch) ([]byte, error) {
	if fetch == nil {
		fetch = httpNvidiaFetch
	}
	status, body, err := fetch("GET", url, "", nil)
	if err != nil {
		return nil, err
	}
	if status < 200 || status > 299 {
		return nil, fmt.Errorf("CRL fetch failed: HTTP %d for %s", status, url)
	}
	return body, nil
}

// NvidiaOcspFetchOptions configure FetchNvidiaOcsp: the transport (nil: net/http), the responder URL (nil: NvidiaOcspUrl) and an
// optional nonce for the request.
type NvidiaOcspFetchOptions struct {
	Fetch NvidiaFetch
	URL   *string
	Nonce []byte
}

// FetchNvidiaOcsp POSTs an OCSPRequest for cert to the responder and returns the request and the response DER.
func FetchNvidiaOcsp(cert, issuer *NodeCert, o NvidiaOcspFetchOptions) (request, response []byte, err error) {
	f := o.Fetch
	if f == nil {
		f = httpNvidiaFetch
	}
	request, err = BuildNvidiaOcspRequest(cert, issuer, NvidiaOcspRequestOptions{Nonce: o.Nonce})
	if err != nil {
		return nil, nil, err
	}
	url := NvidiaOcspUrl
	if o.URL != nil {
		url = *o.URL
	}
	status, body, err := f("POST", url, "application/ocsp-request", request)
	if err != nil {
		return nil, nil, err
	}
	if status < 200 || status > 299 {
		return nil, nil, fmt.Errorf("OCSP fetch failed: HTTP %d", status)
	}
	return request, body, nil
}
