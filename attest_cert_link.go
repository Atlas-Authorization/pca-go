package pca

// What OpenSSL decodes before it links two certificates (ossl_x509v3_cache_extensions). One that does not decode, on either
// certificate, or that is repeated, marks the certificate invalid: X509_check_issued and X509_check_ca then refuse. Verdicts
// were read from node:crypto on really signed certificates. Refused beyond it, on purpose: proxyCertInfo and the RFC 3779
// extensions (no verifier here reads them), and bytes after an SKI, AKI or SAN.

import "unicode/utf8"

var certCachedExts = map[string]func([]byte) bool{
	"2.5.29.19":          basicConstraintsDecodes,
	"2.5.29.15":          keyUsageDecodes,
	"2.5.29.37":          extKeyUsageDecodes,
	"2.5.29.14":          subjectKeyIDDecodes,
	"2.5.29.35":          authorityKeyIDDecodes,
	"2.5.29.17":          nil, // certSanDecodes, once the repeat check has passed
	"2.5.29.30":          nameConstraintsDecodes,
	"2.5.29.31":          distributionPointsDecodes,
	"1.3.6.1.5.5.7.1.14": refuseCachedExt,
	"1.3.6.1.5.5.7.1.7":  refuseCachedExt,
	"1.3.6.1.5.5.7.1.8":  refuseCachedExt,
}

func certExtsDecode(c *attCert) bool {
	seen := map[string]bool{}
	for _, e := range c.exts {
		decodes, cached := certCachedExts[e.oid]
		if !cached {
			continue
		}
		if seen[e.oid] || (decodes != nil && !decodes(e.value)) {
			return false
		}
		seen[e.oid] = true
	}
	return certSanDecodes(c)
}

// certMayIssue: no keyUsage, or keyCertSign set once the unused bits are cleared, as OpenSSL does. readCertRoleInfo keeps the raw
// byte because the reference's strict chain profile reads it that way.
func certMayIssue(c *attCert) bool {
	v, has := c.extValue("2.5.29.15")
	if !has {
		return true
	}
	first, _, ok := keyUsageBits(v)
	return ok && first&0x04 != 0
}

func refuseCachedExt([]byte) bool { return false }

// derIntMinimal: a DER INTEGER content, not empty and without a padding byte (c2i_ASN1_INTEGER).
func derIntMinimal(b []byte, e certElem) bool {
	if e.end <= e.start {
		return false
	}
	if e.end-e.start == 1 {
		return true
	}
	lead, next := b[e.start], b[e.start+1]&0x80
	return !(lead == 0 && next == 0) && !(lead == 0xff && next != 0)
}

func derIntPositive(b []byte, e certElem) bool { return derIntMinimal(b, e) && b[e.start]&0x80 == 0 }

// nameValueDecodes checks a Name value's content: OpenSSL converts the text types to UTF-8 when it canonicalises the Name.
func nameValueDecodes(b []byte, e certElem) bool {
	n := e.end - e.start
	switch e.tag {
	case 0x0c:
		return utf8.Valid(b[e.start:e.end])
	case 0x1e:
		if n%2 != 0 {
			return false
		}
		for i := e.start; i < e.end; i += 2 {
			if b[i]&0xf8 == 0xd8 {
				return false
			}
		}
	case 0x1c:
		if n%4 != 0 {
			return false
		}
		for i := e.start; i < e.end; i += 4 {
			r := uint32(b[i])<<24 | uint32(b[i+1])<<16 | uint32(b[i+2])<<8 | uint32(b[i+3])
			if r > 0x10ffff || (r >= 0xd800 && r <= 0xdfff) {
				return false
			}
		}
	case 0x03:
		return n >= 1 && b[e.start] <= 7
	}
	return true
}

// rdnDecodes reads an implicitly tagged RelativeDistinguishedName as a Name of that one RDN.
func rdnDecodes(b []byte, e certElem) bool {
	set := append(derLengthHeader(0x31, e.end-e.start), b[e.start:e.end]...)
	name := append(derLengthHeader(0x30, len(set)), set...)
	outer, err := readCertElem(name, 0, len(name), 0x30)
	return err == nil && checkName(name, outer) == nil
}

// otherNameValueTags: the otherName values taken here. node:crypto also takes other well-formed ANY values; none is used by
// the certificates verified here, and each primitive type has its own decode rules.
var otherNameValueTags = map[byte]bool{0x04: true, 0x0c: true, 0x13: true, 0x14: true, 0x16: true, 0x30: true}

// generalNameDecodes is one GeneralName. x400Address is an opaque SEQUENCE to OpenSSL.
func generalNameDecodes(b []byte, n certElem) bool {
	switch n.tag {
	case 0x81, 0x82, 0x86, 0x87, 0xa3:
		return true
	case 0x88:
		return validOID(b, certElem{tag: 0x06, start: n.start, end: n.end})
	}
	kids, err := certKids(b, n)
	if err != nil {
		return false
	}
	switch n.tag {
	case 0xa0:
		if len(kids) != 2 || !validOID(b, kids[0]) || kids[1].tag != 0xa0 {
			return false
		}
		value, err := certKids(b, kids[1])
		return err == nil && len(value) == 1 && otherNameValueTags[value[0].tag]
	case 0xa4:
		return len(kids) == 1 && kids[0].tag == 0x30 && checkName(b, kids[0]) == nil
	case 0xa5:
		return ediPartyNameDecodes(b, kids)
	}
	return false
}

// ediPartyNameDecodes: { [0] DirectoryString OPTIONAL, [1] DirectoryString }, both tags explicit. OpenSSL does not convert these
// strings to UTF-8, so only the BMP and Universal length rules apply.
func ediPartyNameDecodes(b []byte, kids []certElem) bool {
	if len(kids) == 0 || len(kids) > 2 || kids[len(kids)-1].tag != 0xa1 || (len(kids) == 2 && kids[0].tag != 0xa0) {
		return false
	}
	for _, k := range kids {
		str, err := certKids(b, k)
		if err != nil || len(str) != 1 {
			return false
		}
		switch str[0].tag {
		case 0x0c, 0x13, 0x14:
		case 0x1c, 0x1e:
			if !nameValueDecodes(b, str[0]) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func generalNamesDecode(b []byte, e certElem) bool {
	names, err := certKids(b, e)
	if err != nil {
		return false
	}
	for _, n := range names {
		if !generalNameDecodes(b, n) {
			return false
		}
	}
	return true
}

// kidsInOrder: the elements carry only these tags, each at most once, in this order.
func kidsInOrder(kids []certElem, tags ...byte) bool {
	i := 0
	for _, k := range kids {
		for i < len(tags) && tags[i] != k.tag {
			i++
		}
		if i == len(tags) {
			return false
		}
		i++
	}
	return true
}

func basicConstraintsDecodes(v []byte) bool {
	seq, err := readCertElem(v, 0, len(v), 0x30)
	if err != nil {
		return false
	}
	kids, err := certKids(v, seq)
	if err != nil || !kidsInOrder(kids, 0x01, 0x02) {
		return false
	}
	for _, k := range kids {
		if k.tag == 0x02 && !derIntPositive(v, k) {
			return false
		}
		if k.tag == 0x01 && k.end-k.start != 1 {
			return false
		}
	}
	return true
}

// keyUsageBits is the first two bytes of the keyUsage BIT STRING with its unused bits cleared. Not ok when it does not decode.
func keyUsageBits(v []byte) (first, second byte, ok bool) {
	s, err := readCertElem(v, 0, len(v), 0x03)
	if err != nil || s.end-s.start < 2 || v[s.start] > 7 {
		return 0, 0, false
	}
	data := append([]byte{}, v[s.start+1:s.end]...)
	data[len(data)-1] &= 0xff << v[s.start]
	if len(data) > 1 {
		second = data[1]
	}
	return data[0], second, true
}

// keyUsageDecodes: OpenSSL also refuses a keyUsage whose first two bytes assert nothing.
func keyUsageDecodes(v []byte) bool {
	first, second, ok := keyUsageBits(v)
	return ok && first|second != 0
}

func extKeyUsageDecodes(v []byte) bool {
	seq, err := readCertElem(v, 0, len(v), 0x30)
	if err != nil {
		return false
	}
	purposes, err := certKids(v, seq)
	if err != nil {
		return false
	}
	for _, p := range purposes {
		if !validOID(v, p) {
			return false
		}
	}
	return true
}

func subjectKeyIDDecodes(v []byte) bool {
	s, err := readCertElem(v, 0, len(v), 0x04)
	return err == nil && s.end == len(v)
}

// authorityKeyIDDecodes: {[0] keyid, [1] GeneralNames, [2] serial}, every name in full and the serial a DER INTEGER.
func authorityKeyIDDecodes(v []byte) bool {
	seq, err := readCertElem(v, 0, len(v), 0x30)
	if err != nil || seq.end != len(v) {
		return false
	}
	kids, err := certKids(v, seq)
	if err != nil || !kidsInOrder(kids, 0x80, 0xa1, 0x82) {
		return false
	}
	for _, k := range kids {
		if k.tag == 0xa1 && !generalNamesDecode(v, k) {
			return false
		}
		if k.tag == 0x82 && !derIntMinimal(v, k) {
			return false
		}
	}
	return true
}

func nameConstraintsDecodes(v []byte) bool {
	seq, err := readCertElem(v, 0, len(v), 0x30)
	if err != nil {
		return false
	}
	lists, err := certKids(v, seq)
	if err != nil || !kidsInOrder(lists, 0xa0, 0xa1) {
		return false
	}
	for _, list := range lists {
		subtrees, err := certKids(v, list)
		if err != nil {
			return false
		}
		for _, sub := range subtrees {
			if !generalSubtreeDecodes(v, sub) {
				return false
			}
		}
	}
	return true
}

// generalSubtreeDecodes: SEQUENCE { base GeneralName, [0] minimum OPTIONAL, [1] maximum OPTIONAL }.
func generalSubtreeDecodes(v []byte, sub certElem) bool {
	if sub.tag != 0x30 {
		return false
	}
	parts, err := certKids(v, sub)
	if err != nil || len(parts) == 0 || !generalNameDecodes(v, parts[0]) || !kidsInOrder(parts[1:], 0x80, 0x81) {
		return false
	}
	for _, bound := range parts[1:] {
		if !derIntPositive(v, bound) {
			return false
		}
	}
	return true
}

func distributionPointsDecodes(v []byte) bool {
	seq, err := readCertElem(v, 0, len(v), 0x30)
	if err != nil {
		return false
	}
	points, err := certKids(v, seq)
	if err != nil {
		return false
	}
	for _, p := range points {
		if !distributionPointDecodes(v, p) {
			return false
		}
	}
	return true
}

// distributionPointDecodes: { [0] name, [1] reasons, [2] cRLIssuer }. Reasons alone, nothing at all, or an empty cRLIssuer do not
// decode.
func distributionPointDecodes(v []byte, p certElem) bool {
	if p.tag != 0x30 {
		return false
	}
	kids, err := certKids(v, p)
	if err != nil || !kidsInOrder(kids, 0xa0, 0x81, 0xa2) {
		return false
	}
	named := false
	for _, k := range kids {
		switch k.tag {
		case 0x81:
			if k.end <= k.start || v[k.start] > 7 {
				return false
			}
		case 0xa2:
			named = true
			if k.end <= k.start || !generalNamesDecode(v, k) {
				return false
			}
		default:
			named = true
			if !distributionPointNameDecodes(v, k) {
				return false
			}
		}
	}
	return named
}

// distributionPointNameDecodes: the [0] wrapper holds one name, [0] GeneralNames or [1] a RelativeDistinguishedName.
func distributionPointNameDecodes(v []byte, wrap certElem) bool {
	inner, err := certKids(v, wrap)
	if err != nil || len(inner) != 1 {
		return false
	}
	switch inner[0].tag {
	case 0xa0:
		return generalNamesDecode(v, inner[0])
	case 0xa1:
		return rdnDecodes(v, inner[0])
	}
	return false
}
