package pca

// Intel PCS collateral for the genuine DCAP TDX quote path: signed TCB info and QE identity (ECDSA-P256 over the exact bytes
// of the signed value, under the TCB Signing certificate whose issuer chain ends at the pinned Intel SGX Root CA), the PCK
// and Root CA CRLs, the evaluated TCB status and a status policy. Offline given the collateral bytes; fails closed on
// missing, stale, malformed, unsigned or revoked collateral. The CRL reader is shared with the NVIDIA CRL checks.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

var tcbStatusOrder = []string{"UpToDate", "SWHardeningNeeded", "ConfigurationNeeded", "ConfigurationAndSWHardeningNeeded", "OutOfDateConfigurationNeeded", "OutOfDate", "Revoked"}

var defaultAcceptedStatuses = []string{"UpToDate", "SWHardeningNeeded"}

type collateralPolicy struct {
	acceptStatuses []string
	hasAccept      bool
	minEval        float64
	hasMinEval     bool
}

type intelCollateral struct {
	tcbInfoJSON, tcbInfoChain, qeIdentityJSON, qeIdentityChain string
	pckCrl, rootCrl                                            []byte
}

func collateralFromWire(m map[string]any) *intelCollateral {
	s := func(k string) string { v, _ := m[k].(string); return v }
	c := &intelCollateral{tcbInfoJSON: s("tcbInfoJson"), tcbInfoChain: s("tcbInfoIssuerChainPem"), qeIdentityJSON: s("qeIdentityJson"), qeIdentityChain: s("qeIdentityIssuerChainPem")}
	c.pckCrl, _ = evBytes(m, "pckCrlDer")
	c.rootCrl, _ = evBytes(m, "rootCrlDer")
	return c
}

type collateralResult struct {
	ok          bool
	reason      string
	status      string
	advisoryIDs []string
}

// ───────────────────────────────────────────────────────────── CRL reading (lenient lengths, as the reference)

func tlvLenient(b []byte, off, limit int) (derTlv, error) {
	if off+2 > limit {
		return derTlv{}, errors.New("DER truncated")
	}
	tag := b[off]
	l := int(b[off+1])
	p := off + 2
	if l&0x80 != 0 {
		n := l & 0x7f
		if n == 0 || n > 4 || p+n > limit {
			return derTlv{}, errors.New("DER bad length")
		}
		l = 0
		for i := 0; i < n; i++ {
			l = l*256 + int(b[p+i])
		}
		p += n
	}
	if p+l > limit {
		return derTlv{}, errors.New("DER overrun")
	}
	return derTlv{tag: tag, start: p, end: p + l}, nil
}

var (
	utcTimeRe = regexp.MustCompile(`^([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})Z$`)
	genTimeRe = regexp.MustCompile(`^([0-9]{4})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})Z$`)
)

func atoiDigits(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		n = n*10 + int(s[i]-'0')
	}
	return n
}

// dateUTC is Date.UTC (fields roll over; a year 0..99 means 19YY).
func dateUTC(y, mo, d, h, mi, s int) int64 {
	if y >= 0 && y <= 99 {
		y += 1900
	}
	return time.Date(y, time.Month(mo), d, h, mi, s, 0, time.UTC).UnixMilli()
}

func crlTime(b []byte, t derTlv) (int64, error) {
	s := string(b[t.start:t.end])
	switch t.tag {
	case 0x17:
		m := utcTimeRe.FindStringSubmatch(s)
		if m == nil {
			return 0, errors.New("bad UTCTime")
		}
		yy := atoiDigits(m[1])
		y := 2000 + yy
		if yy >= 50 {
			y = 1900 + yy
		}
		return dateUTC(y, atoiDigits(m[2]), atoiDigits(m[3]), atoiDigits(m[4]), atoiDigits(m[5]), atoiDigits(m[6])), nil
	case 0x18:
		m := genTimeRe.FindStringSubmatch(s)
		if m == nil {
			return 0, errors.New("bad GeneralizedTime")
		}
		return dateUTC(atoiDigits(m[1]), atoiDigits(m[2]), atoiDigits(m[3]), atoiDigits(m[4]), atoiDigits(m[5]), atoiDigits(m[6])), nil
	}
	return 0, errors.New("not a DER time")
}

type parsedCRL struct {
	tbs                    []byte
	thisUpdate, nextUpdate int64
	hasNext                bool
	revoked                map[string]bool
	sigDer                 []byte
}

func parseCRL(der []byte) (*parsedCRL, error) {
	outer, err := tlvLenient(der, 0, len(der))
	if err != nil {
		return nil, err
	}
	if outer.tag != 0x30 || outer.end != len(der) {
		return nil, errors.New("CRL: bad outer SEQUENCE")
	}
	tbsT, err := tlvLenient(der, outer.start, outer.end)
	if err != nil {
		return nil, err
	}
	if tbsT.tag != 0x30 {
		return nil, errors.New("CRL: bad TBSCertList")
	}
	crl := &parsedCRL{tbs: append([]byte{}, der[outer.start:tbsT.end]...), revoked: map[string]bool{}}
	algT, err := tlvLenient(der, tbsT.end, outer.end)
	if err != nil {
		return nil, err
	}
	sigT, err := tlvLenient(der, algT.end, outer.end)
	if err != nil {
		return nil, err
	}
	if sigT.tag != 0x03 || sigT.end != outer.end {
		return nil, errors.New("CRL: bad signature")
	}
	if sigT.start+1 <= sigT.end {
		crl.sigDer = append([]byte{}, der[sigT.start+1:sigT.end]...)
	}
	p := tbsT.start
	t, err := tlvLenient(der, p, tbsT.end)
	if err != nil {
		return nil, err
	}
	if t.tag == 0x02 {
		p = t.end
		if t, err = tlvLenient(der, p, tbsT.end); err != nil {
			return nil, err
		}
	}
	p = t.end // signature AlgorithmIdentifier
	iss, err := tlvLenient(der, p, tbsT.end)
	if err != nil {
		return nil, err
	}
	if iss.tag != 0x30 {
		return nil, errors.New("CRL: bad issuer")
	}
	tu, err := tlvLenient(der, iss.end, tbsT.end)
	if err != nil {
		return nil, err
	}
	if crl.thisUpdate, err = crlTime(der, tu); err != nil {
		return nil, err
	}
	q := tu.end
	if q < tbsT.end {
		n, err := tlvLenient(der, q, tbsT.end)
		if err != nil {
			return nil, err
		}
		if n.tag == 0x17 || n.tag == 0x18 {
			if crl.nextUpdate, err = crlTime(der, n); err != nil {
				return nil, err
			}
			crl.hasNext = true
			q = n.end
		}
		if q < tbsT.end {
			n, err = tlvLenient(der, q, tbsT.end)
			if err != nil {
				return nil, err
			}
			if n.tag == 0x30 {
				e := n.start
				for e < n.end {
					ent, err := tlvLenient(der, e, n.end)
					if err != nil {
						return nil, err
					}
					ser, err := tlvLenient(der, ent.start, ent.end)
					if err != nil {
						return nil, err
					}
					if ser.tag != 0x02 {
						return nil, errors.New("CRL: bad revoked entry")
					}
					crl.revoked[normSerial(toHexLower(der[ser.start:ser.end]))] = true
					e = ent.end
				}
			}
		}
	}
	if !crl.hasNext {
		return nil, errors.New("CRL: missing nextUpdate")
	}
	return crl, nil
}

// crlSigOK is verify('sha256', tbs, issuerKey, sig): ECDSA (DER) or RSA PKCS#1 v1.5 under the issuer key.
func crlSigOK(tbs, sig []byte, k certKey) bool {
	switch pk := k.pub.(type) {
	case *ecdsa.PublicKey:
		return ecdsa.VerifyASN1(pk, sha256Sum(tbs), sig)
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(pk, crypto.SHA256, sha256Sum(tbs), sig) == nil
	}
	return false
}

// verifyCRL verifies a DER CRL under the issuer key at nowMs. The revoked serials (lowercase hex, no leading zeros), or the reason.
func verifyCRL(der []byte, issuer certKey, nowMs int64) (map[string]bool, string) {
	crl, err := parseCRL(der)
	if err != nil {
		return nil, "CRL parse failed: " + errMsg(err)
	}
	if !crlSigOK(crl.tbs, crl.sigDer, issuer) {
		return nil, "CRL signature does not verify under the issuer"
	}
	if nowMs < crl.thisUpdate {
		return nil, "CRL thisUpdate is in the future"
	}
	if nowMs > crl.nextUpdate {
		return nil, "CRL is stale (nextUpdate passed)"
	}
	return crl.revoked, ""
}

// ───────────────────────────────────────────────────────────── signed JSON documents

func skipJSSpace(s string, i int) int {
	for i < len(s) {
		r, n := utf8.DecodeRuneInString(s[i:])
		if !isJSSpace(r) {
			break
		}
		i += n
	}
	return i
}

// rawJSONObject is the exact source text of the JSON object following `"<name>":` in a top-level object.
func rawJSONObject(text, name string) (string, bool) {
	i := skipJSSpace(text, 0)
	if i >= len(text) || text[i] != '{' {
		return "", false
	}
	i = skipJSSpace(text, i+1)
	key := `"` + name + `"`
	if !strings.HasPrefix(text[i:], key) {
		return "", false
	}
	i = skipJSSpace(text, i+len(key))
	if i >= len(text) || text[i] != ':' {
		return "", false
	}
	i = skipJSSpace(text, i+1)
	if i >= len(text) || text[i] != '{' {
		return "", false
	}
	start := i
	depth := 0
	inStr := false
	for ; i < len(text); i++ {
		ch := text[i]
		switch {
		case inStr:
			if ch == '\\' {
				i++
			} else if ch == '"' {
				inStr = false
			}
		case ch == '"':
			inStr = true
		case ch == '{':
			depth++
		case ch == '}':
			depth--
			if depth == 0 {
				return text[start : i+1], true
			}
		}
	}
	return "", false
}

var sig128Re = regexp.MustCompile(`^[0-9a-fA-F]{128}$`)

// verifySignedJSON verifies a PCS document: the body under `name`, or the failure text.
func verifySignedJSON(text, name string, k certKey) (map[string]any, string) {
	raw, ok := rawJSONObject(text, name)
	if !ok {
		return nil, name + " not found / malformed"
	}
	doc, err := jsonLenient([]byte(text))
	if err != nil {
		return nil, name + " document is not valid JSON"
	}
	top, _ := doc.(map[string]any)
	sig, _ := top["signature"].(string)
	if !sig128Re.MatchString(sig) {
		return nil, name + " signature missing or malformed"
	}
	pk, isEC := k.pub.(*ecdsa.PublicKey)
	sigBytes, _ := hexDecodeLoose(sig)
	if !isEC || !verifyRawECDSA(pk, sha256Sum([]byte(raw)), sigBytes) {
		return nil, name + " signature does not verify under the TCB Signing certificate"
	}
	body, isObj := top[name].(map[string]any)
	if !isObj {
		return nil, name + " is not an object"
	}
	return body, ""
}

func hexDecodeLoose(s string) ([]byte, bool) {
	out := make([]byte, 0, len(s)/2)
	for i := 0; i+1 < len(s); i += 2 {
		hi, ok1 := hexNibble(s[i])
		lo, ok2 := hexNibble(s[i+1])
		if !ok1 || !ok2 {
			return nil, false
		}
		out = append(out, hi<<4|lo)
	}
	return out, true
}

func hexNibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// jsDateParse is Date.parse for the ISO-8601 forms PCS documents use (epoch ms), not ok otherwise.
func jsDateParse(s string) (int64, bool) {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04Z07:00", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UnixMilli(), true
		}
	}
	return 0, false
}

func checkFresh(body map[string]any, what string, nowMs int64) string {
	is, ok1 := body["issueDate"].(string)
	ns, ok2 := body["nextUpdate"].(string)
	var issue, next int64
	var iok, nok bool
	if ok1 {
		issue, iok = jsDateParse(is)
	}
	if ok2 {
		next, nok = jsDateParse(ns)
	}
	if !iok || !nok {
		return what + ": issueDate/nextUpdate missing"
	}
	if nowMs < issue {
		return what + ": issueDate is in the future"
	}
	if nowMs > next {
		return what + ": stale (nextUpdate passed)"
	}
	return ""
}

// ───────────────────────────────────────────────────────────── status evaluation

func statusRank(s string) int {
	for i, x := range tcbStatusOrder {
		if x == s {
			return i
		}
	}
	return -1
}

func asTcbStatus(v any) (string, bool) {
	s, ok := v.(string)
	if !ok || statusRank(s) < 0 {
		return "", false
	}
	return s, true
}

func worstStatus(a, b string) string {
	if statusRank(a) >= statusRank(b) {
		return a
	}
	return b
}

func svnList(v any) ([]float64, bool) {
	arr, ok := v.([]any)
	if !ok || len(arr) != 16 {
		return nil, false
	}
	out := make([]float64, 0, 16)
	for _, c := range arr {
		rec, ok := c.(map[string]any)
		if !ok {
			return nil, false
		}
		f, ok := asFinite(rec["svn"])
		if !ok {
			return nil, false
		}
		out = append(out, f)
	}
	return out, true
}

func hexBytesN(v any, n int) ([]byte, bool) {
	s, ok := v.(string)
	if !ok || len(s) != n*2 || !hexPattern.MatchString(s) {
		return nil, false
	}
	return hexDecodeLoose(s)
}

func advisoryList(level map[string]any) []string {
	arr, ok := level["advisoryIDs"].([]any)
	if !ok {
		return nil
	}
	var out []string
	for _, x := range arr {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func maskedEq(value, mask, expected []byte) bool {
	for i := range value {
		if (value[i]&mask[i])^(expected[i]&mask[i]) != 0 {
			return false
		}
	}
	return true
}

// findLevel is levels.find(l => isRecord(l) && isRecord(l.tcb) && typeof l.tcb.isvsvn === 'number' && l.tcb.isvsvn <= svn).
func findLevel(levels any, svn float64) map[string]any {
	arr, _ := levels.([]any)
	for _, x := range arr {
		l, ok := x.(map[string]any)
		if !ok {
			continue
		}
		tcb, ok := l["tcb"].(map[string]any)
		if !ok {
			continue
		}
		if f, ok := asFinite(tcb["isvsvn"]); ok && f <= svn {
			return l
		}
	}
	return nil
}

type tcbEval struct {
	platform, module string
	advisories       []string
	err              string
}

func evaluateTcb(info map[string]any, pckSgx []byte, pckPcesvn int, teeTcbSvn, mrSignerSeam, seamAttributes []byte) tcbEval {
	levels, _ := info["tcbLevels"].([]any)
	if len(levels) == 0 {
		return tcbEval{err: "TCB info has no tcbLevels"}
	}
	minor := teeTcbSvn[1]
	moduleStatus := "UpToDate"
	adv := map[string]bool{}
	var modMrSigner, modAttr, modMask any
	if minor > 0 {
		id := fmt.Sprintf("TDX_%02X", minor)
		var ident map[string]any
		if ids, ok := info["tdxModuleIdentities"].([]any); ok {
			for _, x := range ids {
				if r, ok := x.(map[string]any); ok && r["id"] == id {
					ident = r
					break
				}
			}
		}
		if ident == nil {
			return tcbEval{err: fmt.Sprintf("TDX module identity %s not present in TCB info", id)}
		}
		modMrSigner, modAttr, modMask = ident["mrsigner"], ident["attributes"], ident["attributesMask"]
		hit := findLevel(ident["tcbLevels"], float64(teeTcbSvn[0]))
		if hit == nil {
			return tcbEval{err: fmt.Sprintf("TDX module %s SVN %d is below every known level", id, teeTcbSvn[0])}
		}
		st, ok := asTcbStatus(hit["tcbStatus"])
		if !ok {
			return tcbEval{err: "TDX module level has an unknown tcbStatus"}
		}
		moduleStatus = st
		for _, a := range advisoryList(hit) {
			adv[a] = true
		}
	} else {
		m, ok := info["tdxModule"].(map[string]any)
		if !ok {
			return tcbEval{err: "TCB info missing tdxModule"}
		}
		modMrSigner, modAttr, modMask = m["mrsigner"], m["attributes"], m["attributesMask"]
	}
	exMr, ok1 := hexBytesN(modMrSigner, 48)
	exAttr, ok2 := hexBytesN(modAttr, 8)
	mask, ok3 := hexBytesN(modMask, 8)
	if !ok1 || !ok2 || !ok3 {
		return tcbEval{err: "TDX module identity fields malformed"}
	}
	if string(exMr) != string(mrSignerSeam) {
		return tcbEval{err: "TD report MRSIGNERSEAM does not match the TDX module identity"}
	}
	if !maskedEq(seamAttributes, mask, exAttr) {
		return tcbEval{err: "TD report SEAM attributes do not match the TDX module identity"}
	}
	from := 0
	if minor > 0 {
		from = 2
	}
	for _, x := range levels {
		l, ok := x.(map[string]any)
		var tcb map[string]any
		if ok {
			tcb, ok = l["tcb"].(map[string]any)
		}
		if !ok {
			return tcbEval{err: "malformed TCB level"}
		}
		sgx, sok := svnList(tcb["sgxtcbcomponents"])
		tdx, tok := svnList(tcb["tdxtcbcomponents"])
		pce, pok := asFinite(tcb["pcesvn"])
		if !sok || !tok || !pok {
			return tcbEval{err: "malformed TCB level components"}
		}
		st, ok := asTcbStatus(l["tcbStatus"])
		if !ok {
			return tcbEval{err: "TCB level has an unknown tcbStatus"}
		}
		match := float64(pckPcesvn) >= pce
		for i := 0; match && i < 16; i++ {
			if float64(pckSgx[i]) < sgx[i] {
				match = false
			}
		}
		for i := from; match && i < 16; i++ {
			if float64(teeTcbSvn[i]) < tdx[i] {
				match = false
			}
		}
		if !match {
			continue
		}
		for _, a := range advisoryList(l) {
			adv[a] = true
		}
		var list []string
		for a := range adv {
			list = append(list, a)
		}
		sort.Strings(list)
		return tcbEval{platform: st, module: moduleStatus, advisories: list}
	}
	return tcbEval{err: "platform TCB is below every level in the TCB info"}
}

type qeEval struct {
	status     string
	advisories []string
	err        string
}

func evaluateQe(ident map[string]any, qe []byte) qeEval {
	if ident["id"] != "TD_QE" {
		return qeEval{err: "QE identity id is not TD_QE"}
	}
	if v, ok := asFinite(ident["version"]); !ok || v != 2 {
		return qeEval{err: "unsupported QE identity version"}
	}
	miscsel, ok1 := hexBytesN(ident["miscselect"], 4)
	miscMask, ok2 := hexBytesN(ident["miscselectMask"], 4)
	attr, ok3 := hexBytesN(ident["attributes"], 16)
	attrMask, ok4 := hexBytesN(ident["attributesMask"], 16)
	mrsigner, ok5 := hexBytesN(ident["mrsigner"], 32)
	prodID, ok6 := asFinite(ident["isvprodid"])
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 || !ok6 {
		return qeEval{err: "QE identity fields malformed"}
	}
	if len(qe) != 384 {
		return qeEval{err: "QE report has wrong length"}
	}
	if !maskedEq(qe[16:20], miscMask, miscsel) {
		return qeEval{err: "QE MISCSELECT does not match the QE identity"}
	}
	if !maskedEq(qe[48:64], attrMask, attr) {
		return qeEval{err: "QE ATTRIBUTES do not match the QE identity"}
	}
	if string(qe[128:160]) != string(mrsigner) {
		return qeEval{err: "QE MRSIGNER does not match the QE identity"}
	}
	prod := int(qe[256]) | int(qe[257])<<8
	isvsvn := int(qe[258]) | int(qe[259])<<8
	if float64(prod) != prodID {
		return qeEval{err: "QE ISVPRODID does not match the QE identity"}
	}
	hit := findLevel(ident["tcbLevels"], float64(isvsvn))
	if hit == nil {
		return qeEval{err: "QE ISVSVN is below every known level"}
	}
	st, ok := asTcbStatus(hit["tcbStatus"])
	if !ok {
		return qeEval{err: "QE level has an unknown tcbStatus"}
	}
	return qeEval{status: st, advisories: advisoryList(hit)}
}

// signerKeyFromChain verifies a PCS issuer chain (leaf first) to the pinned root, validity at nowMs and that no certificate
// is on the Root CA CRL. The leaf's key, or the failure text.
func signerKeyFromChain(chainPem, pin string, nowMs int64, rootRevoked map[string]bool) (certKey, string) {
	chain := verifyIntelPckChain(chainPem, pin, nowMs)
	if chain.validity {
		return certKey{}, "issuer chain certificate outside its validity period"
	}
	if !chain.ok || chain.leaf == nil {
		return certKey{}, "issuer chain invalid: " + chain.reason
	}
	for _, b := range pemCertBlocks(chainPem) {
		c, err := certFromPEM(b)
		if err != nil {
			return certKey{}, "collateral verification error (fail closed): " + errMsg(err)
		}
		if !derValidAt(c.Raw, nowMs, 0) {
			return certKey{}, "issuer chain certificate outside its validity period"
		}
		if rootRevoked[certSerialHex(c)] {
			return certKey{}, "issuer chain certificate is revoked by the Intel Root CA CRL"
		}
	}
	k, err := keyOfCert(chain.leaf)
	if err != nil {
		return certKey{}, "collateral verification error (fail closed): " + errMsg(err)
	}
	return k, ""
}

// verifyIntelTdxCollateral verifies the quote and then its PCS collateral at nowMs: the evaluated TCB status and the policy decision.
func verifyIntelTdxCollateral(quote []byte, c *intelCollateral, nowMs int64, pol *collateralPolicy, pin string, allowDebug bool) collateralResult {
	fail := func(r string) collateralResult { return collateralResult{reason: r} }
	thrown := func(err error) collateralResult {
		return fail("collateral verification error (fail closed): " + errMsg(err))
	}
	if c == nil || c.tcbInfoJSON == "" || c.qeIdentityJSON == "" || len(c.pckCrl) == 0 || len(c.rootCrl) == 0 || c.tcbInfoChain == "" || c.qeIdentityChain == "" {
		return fail("collateral incomplete (fail closed)")
	}
	base := verifyGenuineTdxQuote(quote, pin, nowMs, nil, allowDebug)
	if !base.ok || base.pck == nil || base.fmspc == "" {
		return fail("quote invalid: " + base.reason)
	}
	q, err := parseDcapQuote(quote)
	if err != nil {
		return thrown(err)
	}
	var quoteCerts []*attCert
	for _, b := range pemCertBlocks(q.pckChainPem) {
		x, err := certFromPEM(b)
		if err != nil {
			return thrown(err)
		}
		quoteCerts = append(quoteCerts, x)
	}
	for _, x := range quoteCerts {
		if !derValidAt(x.Raw, nowMs, 0) {
			return fail("PCK chain certificate outside its validity period")
		}
	}
	var leaf, ca, root *attCert
	for _, x := range quoteCerts {
		issues := false
		for _, y := range quoteCerts {
			if string(y.RawIssuer) == string(x.RawSubject) {
				issues = true
			}
		}
		if !issues {
			leaf = x
			break
		}
	}
	if leaf == nil {
		return fail("PCK leaf not found")
	}
	for _, x := range quoteCerts {
		if string(x.RawSubject) == string(leaf.RawIssuer) {
			ca = x
			break
		}
	}
	if ca == nil {
		return fail("PCK CA not found in the quote chain")
	}
	for _, x := range quoteCerts {
		if certSelfIssued(x) {
			root = x
			break
		}
	}
	if root == nil {
		return fail("Intel root not found in the quote chain")
	}
	rootKey, err := keyOfCert(root)
	if err != nil {
		return thrown(err)
	}
	caKey, err := keyOfCert(ca)
	if err != nil {
		return thrown(err)
	}
	rootRevoked, why := verifyCRL(c.rootCrl, rootKey, nowMs)
	if why != "" {
		return fail("Intel Root CA CRL: " + why)
	}
	pckRevoked, why := verifyCRL(c.pckCrl, caKey, nowMs)
	if why != "" {
		return fail("PCK CRL: " + why)
	}
	if rootRevoked[certSerialHex(ca)] {
		return fail("PCK CA certificate is revoked by the Intel Root CA CRL")
	}
	if pckRevoked[certSerialHex(leaf)] {
		return fail("PCK leaf certificate is revoked by the PCK CRL")
	}

	tcbKey, why := signerKeyFromChain(c.tcbInfoChain, pin, nowMs, rootRevoked)
	if why != "" {
		return fail("TCB info: " + why)
	}
	info, why := verifySignedJSON(c.tcbInfoJSON, "tcbInfo", tcbKey)
	if why != "" {
		return fail("TCB info: " + why)
	}
	if stale := checkFresh(info, "TCB info", nowMs); stale != "" {
		return fail(stale)
	}
	if info["id"] != "TDX" {
		return fail("TCB info is not a TDX v3 document")
	}
	if v, ok := asFinite(info["version"]); !ok || v != 3 {
		return fail("TCB info is not a TDX v3 document")
	}
	if fm, ok := info["fmspc"].(string); !ok || strings.ToLower(fm) != base.fmspc {
		return fail("TCB info FMSPC does not match the quote PCK")
	}

	qeKey, why := signerKeyFromChain(c.qeIdentityChain, pin, nowMs, rootRevoked)
	if why != "" {
		return fail("QE identity: " + why)
	}
	qeBody, why := verifySignedJSON(c.qeIdentityJSON, "enclaveIdentity", qeKey)
	if why != "" {
		return fail("QE identity: " + why)
	}
	if stale := checkFresh(qeBody, "QE identity", nowMs); stale != "" {
		return fail(stale)
	}

	infoNum, qeNum := -1.0, -1.0
	if f, ok := asFinite(info["tcbEvaluationDataNumber"]); ok {
		infoNum = f
	}
	if f, ok := asFinite(qeBody["tcbEvaluationDataNumber"]); ok {
		qeNum = f
	}
	if infoNum < 0 || qeNum < 0 {
		return fail("tcbEvaluationDataNumber missing")
	}
	if pol != nil && pol.hasMinEval && (infoNum < pol.minEval || qeNum < pol.minEval) {
		return fail("tcbEvaluationDataNumber below policy minimum")
	}

	body := q.tdReportBody
	tcb := evaluateTcb(info, base.pck.sgx, base.pck.pcesvn, body[0:16], body[64:112], body[112:120])
	if tcb.err != "" {
		return fail("TCB evaluation: " + tcb.err)
	}
	// the PCK leaf's own issued TCB is the one the quote verification extracted from the verified chain
	qe := evaluateQe(qeBody, q.qeReportBody)
	if qe.err != "" {
		return fail("QE identity: " + qe.err)
	}
	status := worstStatus(worstStatus(tcb.platform, tcb.module), qe.status)
	seen := map[string]bool{}
	var ids []string
	for _, a := range append(append([]string{}, tcb.advisories...), qe.advisories...) {
		if !seen[a] {
			seen[a] = true
			ids = append(ids, a)
		}
	}
	sort.Strings(ids)
	res := collateralResult{status: status, advisoryIDs: ids}
	accepted := defaultAcceptedStatuses
	if pol != nil && pol.hasAccept {
		accepted = pol.acceptStatuses
	}
	if !containsStr(accepted, status) {
		res.reason = fmt.Sprintf("TCB status %s is not accepted by policy", status)
		return res
	}
	res.ok = true
	return res
}
