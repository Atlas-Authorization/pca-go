package pca

// Strict DER readers shared by the hardware-attestation chain verifiers (the native counterpart of the strict X.509
// helpers and the validity reader of @atlasauth/pca). crypto/x509 verifies signatures and names, but it exposes neither the
// raw extension table in the shape the CA-role rules need nor the validity instants without normalisation, so the rules
// are enforced from a small, strict walk of the certificate's own DER. Messages are the reference's, byte for byte.

import (
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"
)

type derTlv struct {
	tag        byte
	start, end int // content [start, end)
}

// readTlvStrict reads one definite-length element at off (inside limit). Minimal lengths only, no multi-byte tags.
func readTlvStrict(b []byte, off, limit int) (derTlv, error) {
	if off+2 > limit {
		return derTlv{}, errors.New("DER: truncated header")
	}
	tag := b[off]
	if tag&0x1f == 0x1f {
		return derTlv{}, errors.New("DER: multi-byte tags are not supported")
	}
	l := int(b[off+1])
	p := off + 2
	if l&0x80 != 0 {
		n := l & 0x7f
		if n == 0 || n > 3 {
			return derTlv{}, errors.New("DER: unsupported length form")
		}
		if p+n > limit {
			return derTlv{}, errors.New("DER: truncated length")
		}
		l = 0
		if n > 1 && b[p] == 0 {
			return derTlv{}, errors.New("DER: non-minimal length (leading zero)")
		}
		for i := 0; i < n; i++ {
			l = l<<8 | int(b[p+i])
		}
		if l < 0x80 {
			return derTlv{}, errors.New("DER: non-minimal length (long form below 128)")
		}
		p += n
	}
	if p+l > limit {
		return derTlv{}, errors.New("DER: element overruns its parent")
	}
	return derTlv{tag: tag, start: p, end: p + l}, nil
}

// certRoleInfo is the CA-role-relevant part of a certificate.
type certRoleInfo struct {
	hasBasicConstraints bool
	ca                  bool
	pathLen             int // -1 when absent
	hasKeyUsage         bool
	keyCertSign         bool
}

var (
	oidBasicConstraintsDER = []byte{0x55, 0x1d, 0x13}
	oidKeyUsageDER         = []byte{0x55, 0x1d, 0x0f}
)

func oidEqualsDER(b []byte, t derTlv, want []byte) bool {
	if t.tag != 0x06 || t.end-t.start != len(want) {
		return false
	}
	for i := range want {
		if b[t.start+i] != want[i] {
			return false
		}
	}
	return true
}

// readCertRoleInfo reads BasicConstraints and keyUsage of a DER certificate; an error on a malformed or duplicated extension.
func readCertRoleInfo(cert []byte) (certRoleInfo, error) {
	info := certRoleInfo{pathLen: -1}
	outer, err := readTlvStrict(cert, 0, len(cert))
	if err != nil {
		return info, err
	}
	if outer.tag != 0x30 {
		return info, errors.New("certificate is not a DER SEQUENCE")
	}
	if outer.end != len(cert) {
		return info, errors.New("trailing bytes after the certificate")
	}
	tbs, err := readTlvStrict(cert, outer.start, outer.end)
	if err != nil {
		return info, err
	}
	if tbs.tag != 0x30 {
		return info, errors.New("certificate has no tbsCertificate")
	}
	p := tbs.start
	for p < tbs.end {
		el, err := readTlvStrict(cert, p, tbs.end)
		if err != nil {
			return info, err
		}
		p = el.end
		if el.tag != 0xa3 {
			continue
		}
		seq, err := readTlvStrict(cert, el.start, el.end)
		if err != nil {
			return info, err
		}
		if seq.tag != 0x30 {
			return info, errors.New("extensions is not a SEQUENCE")
		}
		q := seq.start
		for q < seq.end {
			ext, err := readTlvStrict(cert, q, seq.end)
			if err != nil {
				return info, err
			}
			q = ext.end
			if ext.tag != 0x30 {
				return info, errors.New("extension is not a SEQUENCE")
			}
			id, err := readTlvStrict(cert, ext.start, ext.end)
			if err != nil {
				return info, err
			}
			r := id.end
			next, err := readTlvStrict(cert, r, ext.end)
			if err != nil {
				return info, err
			}
			if next.tag == 0x01 {
				r = next.end
				next, err = readTlvStrict(cert, r, ext.end)
				if err != nil {
					return info, err
				}
			}
			if next.tag != 0x04 {
				return info, errors.New("extension value is not an OCTET STRING")
			}
			if oidEqualsDER(cert, id, oidBasicConstraintsDER) {
				if info.hasBasicConstraints {
					return info, errors.New("duplicate BasicConstraints extension")
				}
				info.hasBasicConstraints = true
				bc, err := readTlvStrict(cert, next.start, next.end)
				if err != nil {
					return info, err
				}
				if bc.tag != 0x30 {
					return info, errors.New("BasicConstraints is not a SEQUENCE")
				}
				c := bc.start
				if c < bc.end {
					first, err := readTlvStrict(cert, c, bc.end)
					if err != nil {
						return info, err
					}
					if first.tag == 0x01 {
						if first.end-first.start != 1 {
							return info, errors.New("BasicConstraints cA is not one byte")
						}
						info.ca = cert[first.start] != 0
						c = first.end
					}
				}
				if c < bc.end {
					pl, err := readTlvStrict(cert, c, bc.end)
					if err != nil {
						return info, err
					}
					if pl.tag != 0x02 || pl.end-pl.start < 1 || pl.end-pl.start > 2 || cert[pl.start]&0x80 != 0 {
						return info, errors.New("BasicConstraints pathLenConstraint malformed")
					}
					n := 0
					for i := pl.start; i < pl.end; i++ {
						n = n<<8 | int(cert[i])
					}
					info.pathLen = n
					c = pl.end
				}
				if c != bc.end {
					return info, errors.New("BasicConstraints has trailing data")
				}
			} else if oidEqualsDER(cert, id, oidKeyUsageDER) {
				if info.hasKeyUsage {
					return info, errors.New("duplicate keyUsage extension")
				}
				info.hasKeyUsage = true
				bs, err := readTlvStrict(cert, next.start, next.end)
				if err != nil {
					return info, err
				}
				if bs.tag != 0x03 || bs.end-bs.start < 2 {
					return info, errors.New("keyUsage is not a BIT STRING")
				}
				if cert[bs.start] > 7 {
					return info, errors.New("keyUsage BIT STRING has more than 7 unused bits")
				}
				info.keyCertSign = cert[bs.start+1]&0x04 != 0
			}
		}
	}
	return info, nil
}

// certExt is one extension of a certificate: the critical flag and the extnValue OCTET STRING content.
type certExt struct {
	critical bool
	value    []byte
}

// extTable keeps extensions in encounter order (the reference iterates a Map).
type extTable struct {
	oids []string
	m    map[string]certExt
}

func (t *extTable) get(oid string) (certExt, bool) {
	e, ok := t.m[oid]
	return e, ok
}

func oidToDotted(b []byte, t derTlv) (string, error) {
	if t.tag != 0x06 || t.end <= t.start {
		return "", errors.New("extension OID is malformed")
	}
	var arcs []*big.Int
	v := new(big.Int)
	open := false
	for i := t.start; i < t.end; i++ {
		by := b[i]
		if !open && by == 0x80 {
			return "", errors.New("extension OID has a non-minimal arc")
		}
		v.Lsh(v, 7)
		v.Or(v, big.NewInt(int64(by&0x7f)))
		open = by&0x80 != 0
		if !open {
			arcs = append(arcs, v)
			v = new(big.Int)
		}
	}
	if open {
		return "", errors.New("extension OID is truncated")
	}
	first := arcs[0]
	var parts []string
	switch {
	case first.Cmp(big.NewInt(40)) < 0:
		parts = []string{"0", first.String()}
	case first.Cmp(big.NewInt(80)) < 0:
		parts = []string{"1", new(big.Int).Sub(first, big.NewInt(40)).String()}
	default:
		parts = []string{"2", new(big.Int).Sub(first, big.NewInt(80)).String()}
	}
	for _, a := range arcs[1:] {
		parts = append(parts, a.String())
	}
	return strings.Join(parts, "."), nil
}

// parseTbsExtensions is the strict extension table of a tbsCertificate (the DER SEQUENCE including its header), keyed by
// dotted OID. It fails closed on a malformed element, a duplicate extension, more than one [3] block, a non-DER critical
// flag, trailing bytes, or an empty Extensions block.
func parseTbsExtensions(tbsDer []byte) (*extTable, error) {
	tbs, err := readTlvStrict(tbsDer, 0, len(tbsDer))
	if err != nil {
		return nil, err
	}
	if tbs.tag != 0x30 {
		return nil, errors.New("tbsCertificate is not a SEQUENCE")
	}
	if tbs.end != len(tbsDer) {
		return nil, errors.New("trailing bytes after tbsCertificate")
	}
	out := &extTable{m: map[string]certExt{}}
	seen := false
	blockEnd := -1
	p := tbs.start
	for p < tbs.end {
		el, err := readTlvStrict(tbsDer, p, tbs.end)
		if err != nil {
			return nil, err
		}
		p = el.end
		if el.tag != 0xa3 {
			continue
		}
		if seen {
			return nil, errors.New("duplicate [3] extensions block")
		}
		seen = true
		blockEnd = el.end
		seq, err := readTlvStrict(tbsDer, el.start, el.end)
		if err != nil {
			return nil, err
		}
		if seq.tag != 0x30 {
			return nil, errors.New("extensions is not a SEQUENCE")
		}
		if seq.end != el.end {
			return nil, errors.New("trailing bytes after the Extensions SEQUENCE")
		}
		if seq.start == seq.end {
			return nil, errors.New("empty Extensions SEQUENCE")
		}
		q := seq.start
		for q < seq.end {
			ext, err := readTlvStrict(tbsDer, q, seq.end)
			if err != nil {
				return nil, err
			}
			q = ext.end
			if ext.tag != 0x30 {
				return nil, errors.New("extension is not a SEQUENCE")
			}
			id, err := readTlvStrict(tbsDer, ext.start, ext.end)
			if err != nil {
				return nil, err
			}
			dotted, err := oidToDotted(tbsDer, id)
			if err != nil {
				return nil, err
			}
			r := id.end
			next, err := readTlvStrict(tbsDer, r, ext.end)
			if err != nil {
				return nil, err
			}
			critical := false
			if next.tag == 0x01 {
				if next.end-next.start != 1 || tbsDer[next.start] != 0xff {
					return nil, fmt.Errorf("extension %s has a non-DER critical flag", dotted)
				}
				critical = true
				r = next.end
				next, err = readTlvStrict(tbsDer, r, ext.end)
				if err != nil {
					return nil, err
				}
			}
			if next.tag != 0x04 {
				return nil, fmt.Errorf("extension %s value is not an OCTET STRING", dotted)
			}
			if next.end != ext.end {
				return nil, fmt.Errorf("extension %s has trailing bytes", dotted)
			}
			if _, dup := out.m[dotted]; dup {
				return nil, fmt.Errorf("duplicate extension %s", dotted)
			}
			out.oids = append(out.oids, dotted)
			out.m[dotted] = certExt{critical: critical, value: append([]byte{}, tbsDer[next.start:next.end]...)}
		}
	}
	if seen && blockEnd != tbs.end {
		return nil, errors.New("extensions block is not the last TBS element")
	}
	return out, nil
}

// tbsOfCertificate is the tbsCertificate bytes (header included) of a DER certificate; trailing bytes are refused.
func tbsOfCertificate(cert []byte) ([]byte, error) {
	outer, err := readTlvStrict(cert, 0, len(cert))
	if err != nil {
		return nil, err
	}
	if outer.tag != 0x30 {
		return nil, errors.New("certificate is not a DER SEQUENCE")
	}
	if outer.end != len(cert) {
		return nil, errors.New("trailing bytes after the certificate")
	}
	tbs, err := readTlvStrict(cert, outer.start, outer.end)
	if err != nil {
		return nil, err
	}
	if tbs.tag != 0x30 {
		return nil, errors.New("certificate has no tbsCertificate")
	}
	return append([]byte{}, cert[outer.start:tbs.end]...), nil
}

func parseCertExtensions(cert []byte) (*extTable, error) {
	tbs, err := tbsOfCertificate(cert)
	if err != nil {
		return nil, err
	}
	return parseTbsExtensions(tbs)
}

// recognisedCriticalExtensions are the only critical extensions the attestation chain verifiers understand.
var recognisedCriticalExtensions = map[string]bool{"2.5.29.19": true, "2.5.29.15": true}

// unrecognisedCriticalExtension returns the first critical extension OID the verifier does not recognise (RFC 5280 4.2).
func unrecognisedCriticalExtension(cert []byte, recognised map[string]bool) (string, bool, error) {
	if recognised == nil {
		recognised = recognisedCriticalExtensions
	}
	t, err := parseCertExtensions(cert)
	if err != nil {
		return "", false, err
	}
	for _, oid := range t.oids {
		if t.m[oid].critical && !recognised[oid] {
			return oid, true, nil
		}
	}
	return "", false, nil
}

// checkChainRoles enforces the CA roles over an ordered chain (index 0 = leaf ... last = self-signed root). The failure
// reason, or "" when the chain is fine.
func checkChainRoles(ordered [][]byte) string {
	n := len(ordered)
	for i := 0; i < n; i++ {
		info, err := readCertRoleInfo(ordered[i])
		if err != nil {
			return "certificate extension parse failed: " + err.Error()
		}
		if i == 0 && n > 1 {
			if info.ca {
				return "leaf certificate asserts BasicConstraints CA:TRUE (an end-entity must not be a CA)"
			}
			continue
		}
		if i == 0 {
			continue
		}
		if !info.hasBasicConstraints {
			return fmt.Sprintf("issuer certificate at depth %d has no BasicConstraints (not a CA)", i)
		}
		if !info.ca {
			return fmt.Sprintf("issuer certificate at depth %d is not a CA (BasicConstraints CA:FALSE)", i)
		}
		if info.hasKeyUsage && !info.keyCertSign {
			return fmt.Sprintf("issuer certificate at depth %d keyUsage lacks keyCertSign", i)
		}
		if info.pathLen >= 0 && info.pathLen < i-1 {
			return fmt.Sprintf("issuer certificate at depth %d pathLenConstraint %d is exceeded (%d intermediate(s) below)", i, info.pathLen, i-1)
		}
	}
	return ""
}

// ───────────────────────────────────────────────────────────── validity (read from the certificate's own DER)

// derInstant is an epoch-millisecond instant, or not ok (the reference's NaN).
type derInstant struct {
	ms int64
	ok bool
}

func tlvAt(der []byte, off int) (derTlv, error) {
	if off+2 > len(der) {
		return derTlv{}, errors.New("truncated")
	}
	tag := der[off]
	l := int(der[off+1])
	start := off + 2
	if l&0x80 != 0 {
		n := l & 0x7f
		if n == 0 || n > 4 || start+n > len(der) {
			return derTlv{}, errors.New("bad length")
		}
		l = 0
		for i := 0; i < n; i++ {
			l = l*256 + int(der[start+i])
		}
		start += n
	}
	end := start + l
	if end > len(der) {
		return derTlv{}, errors.New("truncated")
	}
	return derTlv{tag: tag, start: start, end: end}, nil
}

func allASCIIDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// parseDerTime is the strict RFC 5280 Time: tag 0x17 UTCTime YYMMDDHHMMSSZ (YY >= 50 is 19YY) or tag 0x18 GeneralizedTime
// YYYYMMDDHHMMSSZ, every field in range, no roll-over.
func parseDerTime(tag int, text string) derInstant {
	var y int
	var rest string
	switch {
	case tag == 0x17 && len(text) == 13:
		if !allASCIIDigits(text[:12]) || text[12] != 'Z' {
			return derInstant{}
		}
		yy, _ := strconv.Atoi(text[:2])
		if yy >= 50 {
			y = 1900 + yy
		} else {
			y = 2000 + yy
		}
		rest = text[2:]
	case tag == 0x18 && len(text) == 15:
		if !allASCIIDigits(text[:14]) || text[14] != 'Z' {
			return derInstant{}
		}
		y, _ = strconv.Atoi(text[:4])
		rest = text[4:]
	default:
		return derInstant{}
	}
	mon, _ := strconv.Atoi(rest[0:2])
	day, _ := strconv.Atoi(rest[2:4])
	h, _ := strconv.Atoi(rest[4:6])
	mi, _ := strconv.Atoi(rest[6:8])
	sec, _ := strconv.Atoi(rest[8:10])
	if mon < 1 || mon > 12 || day < 1 || h > 23 || mi > 59 || sec > 59 {
		return derInstant{}
	}
	d := time.Date(y, time.Month(mon), day, h, mi, sec, 0, time.UTC)
	if int(d.Month()) != mon || d.Day() != day {
		return derInstant{}
	}
	return derInstant{ms: d.UnixMilli(), ok: true}
}

// derValidity is the validity window of a DER certificate (Certificate -> tbsCertificate -> validity); both not ok when malformed.
func derValidity(der []byte) (from, to derInstant) {
	cert, err := tlvAt(der, 0)
	if err != nil || cert.tag != 0x30 {
		return
	}
	tbs, err := tlvAt(der, cert.start)
	if err != nil || tbs.tag != 0x30 {
		return
	}
	off := tbs.start
	el, err := tlvAt(der, off)
	if err != nil {
		return
	}
	if el.tag == 0xa0 {
		off = el.end
		if el, err = tlvAt(der, off); err != nil {
			return
		}
	}
	if el.tag != 0x02 { // serialNumber
		return
	}
	if el, err = tlvAt(der, el.end); err != nil || el.tag != 0x30 { // signature
		return
	}
	if el, err = tlvAt(der, el.end); err != nil || el.tag != 0x30 { // issuer
		return
	}
	validity, err := tlvAt(der, el.end)
	if err != nil || validity.tag != 0x30 || validity.end > tbs.end {
		return
	}
	nb, err := tlvAt(der, validity.start)
	if err != nil {
		return
	}
	na, err := tlvAt(der, nb.end)
	if err != nil || na.end != validity.end {
		return
	}
	return parseDerTime(int(nb.tag), string(der[nb.start:nb.end])), parseDerTime(int(na.tag), string(der[na.start:na.end]))
}

// derValidAt is true iff both bounds parse and from - skew <= nowMs <= to + skew (fail closed on an unparseable bound).
func derValidAt(der []byte, nowMs int64, skewMs int64) bool {
	from, to := derValidity(der)
	if !from.ok || !to.ok {
		return false
	}
	return nowMs+skewMs >= from.ms && nowMs-skewMs <= to.ms
}

// derValidAtF is derValidAt with a fractional skew (milliseconds).
func derValidAtF(der []byte, nowMs int64, skewMs float64) bool {
	from, to := derValidity(der)
	if !from.ok || !to.ok {
		return false
	}
	return float64(nowMs)+skewMs >= float64(from.ms) && float64(nowMs)-skewMs <= float64(to.ms)
}
