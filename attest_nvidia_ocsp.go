package pca

// NVIDIA GPU-CC device-chain revocation through OCSP (RFC 6960): the offline-verifiable equivalent of NVIDIA's own check.
// For each non-root certificate the supplied responses are verified (responseStatus, CertID, BasicOCSPResponse signature under the
// issuer or a delegated responder certificate signed by the supplied chain, freshness) and the status must be GOOD where it is
// required. Every time value in a response must be a well-formed DER time (no roll-over).

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

const (
	oidOcspBasic     = "1.3.6.1.5.5.7.48.1.1"
	ocspDefaultMaxMs = int64(7 * 24 * 3600 * 1000)
)

var ocspSigAlgs = map[string]struct {
	hash crypto.Hash
	ec   bool
}{
	"1.2.840.10045.4.3.2":   {crypto.SHA256, true},
	"1.2.840.10045.4.3.3":   {crypto.SHA384, true},
	"1.2.840.10045.4.3.4":   {crypto.SHA512, true},
	"1.2.840.113549.1.1.11": {crypto.SHA256, false},
	"1.2.840.113549.1.1.12": {crypto.SHA384, false},
	"1.2.840.113549.1.1.13": {crypto.SHA512, false},
}

var ocspCertIDHashes = map[string]crypto.Hash{
	"1.3.14.3.2.26":          crypto.SHA1,
	"2.16.840.1.101.3.4.2.1": crypto.SHA256,
	"2.16.840.1.101.3.4.2.2": crypto.SHA384,
	"2.16.840.1.101.3.4.2.3": crypto.SHA512,
}

type ocspNode struct {
	tag             byte
	hdr, start, end int
}

func (n ocspNode) constructed() bool { return n.tag&0x20 != 0 }

func readOcspNode(b []byte, off, limit int) (ocspNode, error) {
	t, err := tlvAt(b[:limit], off)
	if err != nil {
		return ocspNode{}, errors.New("not valid DER")
	}
	if t.tag&0x1f == 0x1f {
		return ocspNode{}, errors.New("multi-byte tags are not supported")
	}
	return ocspNode{tag: t.tag, hdr: off, start: t.start, end: t.end}, nil
}

func ocspKids(b []byte, n ocspNode) ([]ocspNode, error) {
	var out []ocspNode
	p := n.start
	for p < n.end {
		k, err := readOcspNode(b, p, n.end)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
		p = k.end
	}
	return out, nil
}

func ocspOID(b []byte, n ocspNode) (string, error) {
	if n.tag != 0x06 {
		return "", errors.New("expected an OBJECT IDENTIFIER")
	}
	var oid asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(b[n.hdr:n.end], &oid); err != nil {
		return "", err
	}
	return oid.String(), nil
}

var (
	ocspRevTimeRe = regexp.MustCompile(`^[0-9]{14}Z$`)
	ocspGenTimeRe = regexp.MustCompile(`^([0-9]{4})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})(?:\.([0-9]*[1-9]))?Z$`)
	ocspUTCTimeRe = regexp.MustCompile(`^([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})Z$`)
)

// ocspTimeMs reads a DER time in range (no roll-over): epoch ms, or not ok.
func ocspTimeMs(text string, utc bool) (int64, bool) {
	re := ocspGenTimeRe
	if utc {
		re = ocspUTCTimeRe
	}
	m := re.FindStringSubmatch(text)
	if m == nil {
		return 0, false
	}
	y := atoiDigits(m[1])
	if utc {
		if y < 50 {
			y += 2000
		} else {
			y += 1900
		}
	}
	mo, d, h, mi, s := atoiDigits(m[2]), atoiDigits(m[3]), atoiDigits(m[4]), atoiDigits(m[5]), atoiDigits(m[6])
	if mo < 1 || mo > 12 || d < 1 || h > 23 || mi > 59 || s > 59 {
		return 0, false
	}
	t := time.Date(y, time.Month(mo), d, h, mi, s, 0, time.UTC)
	if int(t.Month()) != mo || t.Day() != d {
		return 0, false
	}
	ms := t.UnixMilli()
	if !utc && len(m) > 7 && m[7] != "" {
		frac := (m[7] + "000")[:3]
		ms += int64(atoiDigits(frac))
	}
	return ms, true
}

// ocspTimesWellFormed walks the structure: every UTCTime / GeneralizedTime must be a well-formed DER time.
func ocspTimesWellFormed(b []byte, n ocspNode) bool {
	if n.constructed() {
		kids, err := ocspKids(b, n)
		if err != nil {
			return false
		}
		for _, k := range kids {
			if !ocspTimesWellFormed(b, k) {
				return false
			}
		}
		return true
	}
	if n.tag == 0x17 || n.tag == 0x18 {
		_, ok := ocspTimeMs(string(b[n.start:n.end]), n.tag == 0x17)
		return ok
	}
	return true
}

func stripLeading0(b []byte) []byte {
	i := 0
	for i < len(b)-1 && b[i] == 0 {
		i++
	}
	return b[i:]
}

func certSerialBytes(c *attCert) []byte { return c.Serial }

// spkiKeyBits is the subjectPublicKey BIT STRING content of a certificate (without the unused-bits octet).
func spkiKeyBits(c *attCert) ([]byte, error) {
	spki, err := readCertElem(c.RawSPKI, 0, len(c.RawSPKI), 0x30)
	if err != nil {
		return nil, err
	}
	kids, err := certKids(c.RawSPKI, spki)
	if err != nil || len(kids) != 2 {
		return nil, errors.New("malformed SubjectPublicKeyInfo")
	}
	return c.RawSPKI[kids[1].start+1 : kids[1].end], nil
}

func hashBytes(h crypto.Hash, b []byte) []byte {
	switch h {
	case crypto.SHA1:
		s := sha1.Sum(b)
		return s[:]
	case crypto.SHA256:
		s := sha256.Sum256(b)
		return s[:]
	case crypto.SHA384:
		s := sha512.Sum384(b)
		return s[:]
	}
	s := sha512.Sum512(b)
	return s[:]
}

func ocspSigOK(alg string, tbs, sig []byte, k certKey) bool {
	a, ok := ocspSigAlgs[alg]
	if !ok {
		return false
	}
	digest := hashBytes(a.hash, tbs)
	switch pk := k.pub.(type) {
	case *ecdsa.PublicKey:
		return a.ec && ecdsa.VerifyASN1(pk, digest, sig)
	case *rsa.PublicKey:
		return !a.ec && rsa.VerifyPKCS1v15(pk, a.hash, digest, sig) == nil
	}
	return false
}

type ocspResult struct {
	ok     bool
	reason string
	status string
}

func ocspFail(reason string) ocspResult { return ocspResult{reason: reason} }

// verifyNvidiaOcspResponse verifies one DER OCSPResponse for cert (issued by issuer); malformation is a failure, never a panic.
func verifyNvidiaOcspResponse(der []byte, cert, issuer *attCert, chain []*attCert, nowMs int64) (res ocspResult) {
	defer func() {
		if r := recover(); r != nil {
			res = ocspFail(fmt.Sprintf("OCSP response rejected: %v", r))
		}
	}()
	r, err := verifyOcspInner(der, cert, issuer, chain, nowMs)
	if err != nil {
		return ocspFail("OCSP response rejected: " + err.Error())
	}
	return r
}

func verifyOcspInner(der []byte, cert, issuer *attCert, chain []*attCert, nowMs int64) (ocspResult, error) {
	top, err := readOcspNode(der, 0, len(der))
	if err != nil {
		return ocspFail("response is not valid DER"), nil
	}
	if top.end != len(der) {
		return ocspFail("trailing bytes after OCSPResponse"), nil
	}
	if top.tag != 0x30 {
		return ocspResult{}, errors.New("OCSPResponse is not a SEQUENCE")
	}
	tk, err := ocspKids(der, top)
	if err != nil || len(tk) == 0 || tk[0].tag != 0x0a || tk[0].end-tk[0].start != 1 {
		return ocspResult{}, errors.New("malformed OCSPResponse")
	}
	if status := int(der[tk[0].start]); status != 0 {
		return ocspFail(fmt.Sprintf("OCSP responseStatus is %d (not successful)", status)), nil
	}
	if len(tk) < 2 || tk[1].tag != 0xa0 {
		return ocspFail("successful response carries no responseBytes"), nil
	}
	rbWrap, err := ocspKids(der, tk[1])
	if err != nil || len(rbWrap) != 1 || rbWrap[0].tag != 0x30 {
		return ocspResult{}, errors.New("malformed responseBytes")
	}
	rb, err := ocspKids(der, rbWrap[0])
	if err != nil || len(rb) != 2 || rb[1].tag != 0x04 {
		return ocspResult{}, errors.New("malformed responseBytes")
	}
	rtype, err := ocspOID(der, rb[0])
	if err != nil {
		return ocspResult{}, err
	}
	if rtype != oidOcspBasic {
		return ocspFail("responseType is not id-pkix-ocsp-basic"), nil
	}
	basic := der[rb[1].start:rb[1].end]
	bn, err := readOcspNode(basic, 0, len(basic))
	if err != nil {
		return ocspFail("BasicOCSPResponse is not valid DER"), nil
	}
	if bn.tag != 0x30 {
		return ocspResult{}, errors.New("BasicOCSPResponse is not a SEQUENCE")
	}
	bk, err := ocspKids(basic, bn)
	if err != nil || len(bk) < 3 || bk[0].tag != 0x30 || bk[1].tag != 0x30 || bk[2].tag != 0x03 {
		return ocspResult{}, errors.New("malformed BasicOCSPResponse")
	}
	if !ocspTimesWellFormed(basic, bn) {
		return ocspFail("response carries a malformed (out-of-range) ASN.1 time"), nil
	}
	tbsNode := bk[0]
	tbsBytes := basic[tbsNode.hdr:tbsNode.end]
	algKids, err := ocspKids(basic, bk[1])
	if err != nil || len(algKids) == 0 {
		return ocspResult{}, errors.New("malformed signatureAlgorithm")
	}
	sigAlg, err := ocspOID(basic, algKids[0])
	if err != nil {
		return ocspResult{}, err
	}
	if _, ok := ocspSigAlgs[sigAlg]; !ok {
		return ocspFail("unsupported OCSP signature algorithm " + sigAlg), nil
	}
	if bk[2].end-bk[2].start < 1 {
		return ocspResult{}, errors.New("malformed signature")
	}
	sig := basic[bk[2].start+1 : bk[2].end]

	// ResponseData: [0] version?, responderID, producedAt, responses, [1] extensions?
	rd, err := ocspKids(basic, tbsNode)
	if err != nil {
		return ocspResult{}, err
	}
	ri := 0
	if ri < len(rd) && rd[ri].tag == 0xa0 {
		ri++
	}
	if ri+3 > len(rd) {
		return ocspResult{}, errors.New("malformed ResponseData")
	}
	rid, produced, responses := rd[ri], rd[ri+1], rd[ri+2]
	if produced.tag != 0x18 || responses.tag != 0x30 || (rid.tag != 0xa1 && rid.tag != 0xa2) {
		return ocspResult{}, errors.New("malformed ResponseData")
	}
	producedAt, _ := ocspTimeMs(string(basic[produced.start:produced.end]), false)

	subjectSerial := stripLeading0(certSerialBytes(cert))
	issuerKeyBits, err := spkiKeyBits(issuer)
	if err != nil {
		return ocspResult{}, err
	}
	singles, err := ocspKids(basic, responses)
	if err != nil {
		return ocspResult{}, err
	}
	type single struct {
		status     ocspNode
		thisUpdate int64
		nextUpdate int64
		hasNext    bool
	}
	var matches []single
	for _, s := range singles {
		sk, err := ocspKids(basic, s)
		if err != nil || len(sk) < 3 || sk[0].tag != 0x30 || sk[2].tag != 0x18 {
			return ocspResult{}, errors.New("malformed SingleResponse")
		}
		cid, err := ocspKids(basic, sk[0])
		if err != nil || len(cid) != 4 || cid[0].tag != 0x30 || cid[1].tag != 0x04 || cid[2].tag != 0x04 || cid[3].tag != 0x02 {
			return ocspResult{}, errors.New("malformed CertID")
		}
		hk, err := ocspKids(basic, cid[0])
		if err != nil || len(hk) == 0 {
			return ocspResult{}, errors.New("malformed CertID hash algorithm")
		}
		hoid, err := ocspOID(basic, hk[0])
		if err != nil {
			return ocspResult{}, err
		}
		h, known := ocspCertIDHashes[hoid]
		if !known {
			continue
		}
		wantName := hashBytes(h, issuer.RawSubject)
		wantKey := hashBytes(h, issuerKeyBits)
		if string(stripLeading0(basic[cid[3].start:cid[3].end])) != string(subjectSerial) ||
			string(basic[cid[1].start:cid[1].end]) != string(wantName) ||
			string(basic[cid[2].start:cid[2].end]) != string(wantKey) {
			continue
		}
		tu, _ := ocspTimeMs(string(basic[sk[2].start:sk[2].end]), false)
		m := single{status: sk[1], thisUpdate: tu}
		if len(sk) > 3 && sk[3].tag == 0xa0 {
			nk, err := ocspKids(basic, sk[3])
			if err == nil && len(nk) == 1 && nk[0].tag == 0x18 {
				m.nextUpdate, _ = ocspTimeMs(string(basic[nk[0].start:nk[0].end]), false)
				m.hasNext = true
			}
		}
		matches = append(matches, m)
	}
	if len(matches) == 0 {
		return ocspFail("no SingleResponse matches the certificate (serial / issuer hashes differ)"), nil
	}
	if len(matches) > 1 {
		return ocspFail("ambiguous: multiple SingleResponses match the certificate"), nil
	}
	one := matches[0]

	// responder authentication
	issuerKey, err := keyOfCert(issuer)
	if err != nil {
		return ocspResult{}, err
	}
	ridInner, err := ocspKids(basic, rid)
	if err != nil || len(ridInner) != 1 {
		return ocspResult{}, errors.New("malformed responderID")
	}
	rIn := ridInner[0]
	matchesResponder := func(c *attCert) bool {
		if rid.tag == 0xa1 {
			return rIn.tag == 0x30 && string(basic[rIn.hdr:rIn.end]) == string(c.RawSubject)
		}
		bits, err := spkiKeyBits(c)
		if err != nil || rIn.tag != 0x04 {
			return false
		}
		return string(basic[rIn.start:rIn.end]) == string(hashBytes(crypto.SHA1, bits))
	}
	isIssuerID := matchesResponder(issuer)
	if !(isIssuerID && ocspSigOK(sigAlg, tbsBytes, sig, issuerKey)) {
		var embedded []*attCert
		if len(bk) > 3 && bk[3].tag == 0xa0 {
			if wrap, err := ocspKids(basic, bk[3]); err == nil && len(wrap) == 1 {
				if cs, err := ocspKids(basic, wrap[0]); err == nil {
					for _, c := range cs {
						if x, err := parseCertDER(basic[c.hdr:c.end]); err == nil {
							embedded = append(embedded, x)
						}
					}
				}
			}
		}
		why := "no embedded responder certificate verifies the response"
		var found *attCert
		for _, cand := range embedded {
			if !matchesResponder(cand) {
				why = "embedded certificates do not match the responderID"
				continue
			}
			if !cand.hasOCSPSigningEKU() {
				why = "delegated responder certificate lacks the id-kp-OCSPSigning EKU"
				continue
			}
			from, to := derValidity(cand.Raw)
			if !from.ok || !to.ok || !(from.ms <= nowMs && nowMs <= to.ms) {
				why = "delegated responder certificate is outside its validity window"
				continue
			}
			signers := []*attCert{issuer}
			for i, c := range chain {
				if string(c.Raw) == string(issuer.Raw) {
					signers = chain[i:]
					break
				}
			}
			okSigner := false
			for _, s := range signers {
				if string(cand.RawIssuer) == string(s.RawSubject) && certSigOKBy(cand, s) {
					okSigner = true
				}
			}
			if !okSigner {
				why = "delegated responder certificate is not signed by the supplied NVIDIA chain"
				continue
			}
			ck, err := keyOfCert(cand)
			if err != nil || !ocspSigOK(sigAlg, tbsBytes, sig, ck) {
				why = "OCSP response signature does not verify under the delegated responder key"
				continue
			}
			found = cand
			break
		}
		if found == nil {
			if isIssuerID {
				return ocspFail("OCSP response signature does not verify under the issuer key"), nil
			}
			return ocspFail(why), nil
		}
	}

	// freshness
	if one.thisUpdate > nowMs {
		return ocspFail("response thisUpdate is in the future"), nil
	}
	if producedAt > nowMs {
		return ocspFail("response producedAt is in the future"), nil
	}
	if one.hasNext {
		if one.nextUpdate < one.thisUpdate {
			return ocspFail("response nextUpdate is invalid"), nil
		}
		if nowMs > one.nextUpdate {
			return ocspFail("response is stale (past nextUpdate)"), nil
		}
	}
	if nowMs-one.thisUpdate > ocspDefaultMaxMs {
		return ocspFail("response is older than the maximum accepted age"), nil
	}

	// certStatus: CHOICE [0] good, [1] revoked, [2] unknown
	st := one.status
	if st.tag&0xc0 != 0x80 {
		return ocspFail("malformed certStatus"), nil
	}
	switch st.tag & 0x1f {
	case 0:
		return ocspResult{ok: true, status: "good"}, nil
	case 2:
		return ocspResult{ok: true, status: "unknown"}, nil
	case 1:
		items, err := ocspKids(basic, st)
		if err != nil || len(items) < 1 || !ocspRevTimeRe.MatchString(string(basic[items[0].start:items[0].end])) {
			return ocspFail("malformed revoked certStatus"), nil
		}
		return ocspResult{ok: true, status: "revoked"}, nil
	}
	return ocspFail("unrecognised certStatus"), nil
}

// checkNvidiaChainOcsp checks the device chain with OCSP responses: every response must verify for exactly one chain
// certificate, any REVOKED fails, and every certificate that advertises an OCSP responder must have a GOOD response.
func checkNvidiaChainOcsp(chain []*attCert, responses [][]byte, nowMs int64) string {
	if len(chain) < 2 {
		return "chain too short for OCSP"
	}
	if len(responses) == 0 {
		return "no OCSP responses supplied"
	}
	last := len(chain) - 1
	required := map[int]bool{}
	for i := 0; i < last; i++ {
		if len(chain[i].ocspServers()) > 0 {
			required[i] = true
		}
	}
	statuses := map[int]string{}
	for i := 0; i < last; i++ {
		statuses[i] = "absent"
	}
	for ri, der := range responses {
		matched := false
		lastReason := "matches no chain certificate"
		for i := 0; i < last; i++ {
			r := verifyNvidiaOcspResponse(der, chain[i], chain[i+1], chain, nowMs)
			if !r.ok {
				if !strings.HasPrefix(r.reason, "no SingleResponse matches") {
					return fmt.Sprintf("OCSP response #%d for '%s' rejected: %s", ri, subjectLine(chain[i]), r.reason)
				}
				lastReason = r.reason
				continue
			}
			if matched {
				return fmt.Sprintf("OCSP response #%d matches more than one chain certificate", ri)
			}
			matched = true
			if statuses[i] != "absent" {
				return fmt.Sprintf("duplicate OCSP responses for chain certificate #%d", i)
			}
			statuses[i] = r.status
			if r.status == "revoked" {
				return fmt.Sprintf("chain certificate '%s' is revoked (OCSP)", subjectLine(chain[i]))
			}
		}
		if !matched {
			return fmt.Sprintf("OCSP response #%d rejected: %s", ri, lastReason)
		}
	}
	for i := 0; i < last; i++ {
		if required[i] && statuses[i] != "good" {
			return fmt.Sprintf("no GOOD OCSP response for required certificate '%s' (status: %s)", subjectLine(chain[i]), statuses[i])
		}
	}
	return ""
}
