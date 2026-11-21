package pca

// The SPIFFE / SPIRE workload-identity bridge (the reference @atlasauth/pca-spiffe): SPIFFE ID parsing, JWT-SVID and X.509-SVID
// verification, the SVID -> PCA holder binding, trust-bundle and revocation caches that fail closed, and SPIFFE evidence for
// blueprint admission. Every refusal is a *CodedError: the reference's SpiffeError codes, or for a JOSE refusal the code the
// reference library reports (ERR_JWT_EXPIRED, ERR_JWS_SIGNATURE_VERIFICATION_FAILED, ...).

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

func spiffeErr(code, msg string) error { return &CodedError{Code: code, Msg: msg} }

// ---- SPIFFE ID ------------------------------------------------------------------------------------------------------------

// SpiffeID is a parsed, validated SPIFFE ID: the canonical spiffe://<trust-domain><path> form, its trust domain and its path
// (with the leading "/"; "" for a bare trust-domain ID).
type SpiffeID struct {
	ID          string `json:"id"`
	TrustDomain string `json:"trustDomain"`
	Path        string `json:"path"`
}

const (
	spiffeScheme         = "spiffe://"
	spiffeMaxIDLen       = 2048
	spiffeMaxTrustDomain = 255
)

var (
	spiffeTrustDomainRe = regexp.MustCompile(`^[a-z0-9._-]+$`)
	spiffeSegmentRe     = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)
)

// ParseSpiffeID validates and parses spiffe://<trust-domain>/<path> (the SPIFFE-ID standard: lowercase scheme, a non-empty trust
// domain over [a-z0-9._-] of at most 255 units, path segments over [a-zA-Z0-9._-] with no empty, "." or ".." segment and no trailing
// slash, at most 2048 units in all; lengths count UTF-16 units as the reference does).
func ParseSpiffeID(s string) (SpiffeID, error) {
	if s == "" {
		return SpiffeID{}, spiffeErr("malformed_spiffe_id", "SPIFFE ID must be a non-empty string")
	}
	if jsLen(s) > spiffeMaxIDLen {
		return SpiffeID{}, spiffeErr("id_too_long", fmt.Sprintf("SPIFFE ID exceeds %d bytes", spiffeMaxIDLen))
	}
	if !strings.HasPrefix(s, spiffeScheme) {
		return SpiffeID{}, spiffeErr("malformed_spiffe_id", `SPIFFE ID must begin with "spiffe://"`)
	}
	rest := s[len(spiffeScheme):]
	td, path := rest, ""
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		td, path = rest[:i], rest[i:]
	}
	if td == "" {
		return SpiffeID{}, spiffeErr("empty_trust_domain", "SPIFFE ID has an empty trust domain")
	}
	if jsLen(td) > spiffeMaxTrustDomain {
		return SpiffeID{}, spiffeErr("trust_domain_too_long", fmt.Sprintf("trust domain exceeds %d bytes", spiffeMaxTrustDomain))
	}
	if !spiffeTrustDomainRe.MatchString(td) {
		return SpiffeID{}, spiffeErr("invalid_trust_domain", fmt.Sprintf(`trust domain "%s" must be lowercase and contain only [a-z0-9._-]`, td))
	}
	if path != "" {
		if strings.HasSuffix(path, "/") {
			return SpiffeID{}, spiffeErr("invalid_path", "SPIFFE ID path must not end with a trailing slash")
		}
		for _, seg := range strings.Split(path, "/")[1:] {
			switch {
			case seg == "":
				return SpiffeID{}, spiffeErr("invalid_path", "SPIFFE ID path must not contain an empty segment")
			case seg == "." || seg == "..":
				return SpiffeID{}, spiffeErr("invalid_path", `SPIFFE ID path must not contain a "." or ".." segment`)
			case !spiffeSegmentRe.MatchString(seg):
				return SpiffeID{}, spiffeErr("invalid_path", fmt.Sprintf(`SPIFFE ID path segment "%s" contains an invalid character`, seg))
			}
		}
	}
	return SpiffeID{ID: spiffeScheme + td + path, TrustDomain: td, Path: path}, nil
}

// ---- the X.509 facts the SVID rules need, read from DER ------------------------------------------------------------------------

type spiffeTLV struct {
	tag        byte
	start, end int
}

func spiffeReadTLV(b []byte, off, limit int) (spiffeTLV, error) {
	if off+2 > limit {
		return spiffeTLV{}, errors.New("der: truncated header")
	}
	tag := b[off]
	if tag&0x1f == 0x1f {
		return spiffeTLV{}, errors.New("der: high-tag-number form is not supported")
	}
	n := int(b[off+1])
	p := off + 2
	if n&0x80 != 0 {
		k := n & 0x7f
		if k == 0 || k > 4 {
			return spiffeTLV{}, errors.New("der: unsupported length form")
		}
		if p+k > limit {
			return spiffeTLV{}, errors.New("der: truncated length")
		}
		n = 0
		for i := 0; i < k; i++ {
			n = n*256 + int(b[p+i])
		}
		p += k
	}
	if n < 0 || p+n > limit {
		return spiffeTLV{}, errors.New("der: content exceeds container")
	}
	return spiffeTLV{tag, p, p + n}, nil
}

func spiffeChildren(b []byte, parent spiffeTLV) ([]spiffeTLV, error) {
	var out []spiffeTLV
	for off := parent.start; off < parent.end; {
		t, err := spiffeReadTLV(b, off, parent.end)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
		off = t.end
	}
	return out, nil
}

// extension OIDs understood well enough to ignore when marked critical
var spiffeKnownCritical = setOf("551d0f", "551d11", "551d13", "551d25", "551d0e", "551d23")

type spiffeCertFacts struct {
	isCA                                                    bool
	pathLen                                                 float64 // -1: absent
	keyUsagePresent, digitalSignature, keyCertSign, crlSign bool
	uriSANs, unknownCritical                                []string
	badBoolean                                              bool // a BOOLEAN that is not one byte long (OpenSSL refuses the certificate)
}

func spiffeReadCertFacts(der []byte) (*spiffeCertFacts, error) {
	cert, err := spiffeReadTLV(der, 0, len(der))
	if err != nil {
		return nil, err
	}
	if cert.tag != 0x30 || cert.end != len(der) {
		return nil, errors.New("der: certificate is not a single SEQUENCE")
	}
	kids, err := spiffeChildren(der, cert)
	if err != nil {
		return nil, err
	}
	if len(kids) == 0 || kids[0].tag != 0x30 {
		return nil, errors.New("der: missing tbsCertificate")
	}
	fields, err := spiffeChildren(der, kids[0])
	if err != nil {
		return nil, err
	}
	f := &spiffeCertFacts{pathLen: -1}
	var wrap *spiffeTLV
	for i := range fields {
		if fields[i].tag == 0xa3 {
			wrap = &fields[i]
			break
		}
	}
	if wrap == nil {
		return f, nil
	}
	wk, err := spiffeChildren(der, *wrap)
	if err != nil {
		return nil, err
	}
	if len(wk) == 0 || wk[0].tag != 0x30 {
		return nil, errors.New("der: malformed extensions")
	}
	exts, err := spiffeChildren(der, wk[0])
	if err != nil {
		return nil, err
	}
	at := func(i int) int { // a JavaScript out-of-range read is undefined
		if i >= 0 && i < len(der) {
			return int(der[i])
		}
		return -1
	}
	seen := map[string]bool{}
	for _, ext := range exts {
		parts, err := spiffeChildren(der, ext)
		if err != nil {
			return nil, err
		}
		if len(parts) == 0 || parts[0].tag != 0x06 {
			return nil, errors.New("der: malformed extension")
		}
		oid := hex.EncodeToString(der[parts[0].start:parts[0].end])
		if seen[oid] {
			return nil, errors.New("der: duplicate extension")
		}
		seen[oid] = true
		if len(parts) == 3 && parts[1].tag == 0x01 && parts[1].end-parts[1].start != 1 {
			f.badBoolean = true
		}
		critical := len(parts) == 3 && parts[1].tag == 0x01 && at(parts[1].start) == 0xff
		v := parts[len(parts)-1]
		if v.tag != 0x04 {
			return nil, errors.New("der: malformed extension value")
		}
		if critical && !spiffeKnownCritical[oid] {
			f.unknownCritical = append(f.unknownCritical, oid)
		}
		inner, err := spiffeReadTLV(der, v.start, v.end)
		if err != nil {
			return nil, err
		}
		switch oid {
		case "551d13":
			cs, err := spiffeChildren(der, inner)
			if err != nil {
				return nil, err
			}
			for _, c := range cs {
				switch c.tag {
				case 0x01:
					if c.end-c.start != 1 {
						f.badBoolean = true
					}
					f.isCA = at(c.start) == 0xff
				case 0x02:
					n := 0.0
					for i := c.start; i < c.end; i++ {
						n = n*256 + float64(der[i])
					}
					f.pathLen = n
				}
			}
		case "551d0f":
			if inner.tag != 0x03 || inner.end-inner.start < 2 {
				return nil, errors.New("der: malformed keyUsage")
			}
			b0 := der[inner.start+1]
			f.keyUsagePresent = true
			f.digitalSignature = b0&0x80 != 0
			f.keyCertSign = b0&0x04 != 0
			f.crlSign = b0&0x02 != 0
		case "551d11":
			gns, err := spiffeChildren(der, inner)
			if err != nil {
				return nil, err
			}
			for _, gn := range gns {
				if gn.tag == 0x86 {
					f.uriSANs = append(f.uriSANs, latin1String(der[gn.start:gn.end]))
				}
			}
		}
	}
	return f, nil
}

func latin1String(b []byte) string {
	r := make([]rune, len(b))
	for i, c := range b {
		r[i] = rune(c)
	}
	return string(r)
}

// ---- JWT-SVID -------------------------------------------------------------------------------------------------------------

// JwtSvidAlgorithms are the signature algorithms the JWT-SVID specification allows.
var JwtSvidAlgorithms = []string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"}

// JwtSvid is a verified JWT-SVID (only VerifyJwtSvid makes one that SvidToHolder accepts).
type JwtSvid struct {
	SpiffeID  SpiffeID       `json:"spiffeId"`
	Claims    map[string]any `json:"claims"`
	Audience  any            `json:"audience"`
	ExpiresAt any            `json:"expiresAt"`
	verified  bool
}

// JwtRevocationSubject is what a JWT-SVID revocation check sees.
type JwtRevocationSubject struct {
	SpiffeID  string  `json:"spiffeId"`
	Jti       *string `json:"jti,omitempty"`
	ExpiresAt float64 `json:"expiresAt"`
	TokenHash string  `json:"tokenHash"` // base64url SHA-256 of the token
}

// VerifyJwtSvidOptions configure VerifyJwtSvid. Audience and TrustDomain are required. Key resolves the verification key for the
// protected header (a single key, a JWK Set from NewLocalJWKSet, or SpiffeTrustBundleSource.JwtKey). CurrentDate zero = the wall
// clock. Algorithms nil = JwtSvidAlgorithms ("none" and HS* are always refused). ClockTolerance is seconds (a number) or a period
// string such as "30s" / "2 minutes"; nil = 0. Revocation, when set, runs last and must return false to admit.
type VerifyJwtSvidOptions struct {
	Audience       []string
	Key            OidcKeyResolver
	TrustDomain    string
	CurrentDate    time.Time
	Algorithms     []string
	ClockTolerance any
	Revocation     func(JwtRevocationSubject) (bool, error)
}

var josePeriodRe = regexp.MustCompile(`(?i)^([+-])? ?([0-9]+|[0-9]+\.[0-9]+) ?(seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w|years?|yrs?|y)(?: (ago|from now))?$`)

// joseSecs is the reference library's clockTolerance: a number of seconds, or a period string.
func joseSecs(v any) (float64, error) {
	if v == nil {
		return 0, nil
	}
	if s, ok := v.(string); ok {
		m := josePeriodRe.FindStringSubmatch(s)
		if m == nil || (m[4] != "" && m[1] != "") {
			return 0, errors.New("Invalid time period format")
		}
		n, _ := strconv.ParseFloat(m[2], 64)
		u := strings.ToLower(m[3])
		mult := 31557600.0
		switch {
		case strings.HasPrefix(u, "s"):
			mult = 1
		case strings.HasPrefix(u, "m"):
			mult = 60
		case strings.HasPrefix(u, "h"):
			mult = 3600
		case strings.HasPrefix(u, "d"):
			mult = 86400
		case strings.HasPrefix(u, "w"):
			mult = 604800
		}
		r := math.Floor(n*mult + 0.5)
		if m[1] == "-" || strings.EqualFold(m[4], "ago") {
			r = -r
		}
		return r, nil
	}
	if f, ok := jsNum(v); ok {
		return f, nil
	}
	return 0, errors.New("Invalid clockTolerance option type")
}

// spiffeJoseErr gives a JOSE refusal the code the reference library reports (a key / algorithm mismatch is a plain TypeError there).
func spiffeJoseErr(err error) error {
	var je *JOSEError
	if !errors.As(err, &je) {
		return err
	}
	code := ""
	switch je.Kind {
	case "signature":
		code = "ERR_JWS_SIGNATURE_VERIFICATION_FAILED"
	case "claim":
		code = "ERR_JWT_CLAIM_VALIDATION_FAILED"
	case "expired":
		code = "ERR_JWT_EXPIRED"
	case "invalid":
		switch m := je.Msg; {
		case strings.Contains(m, "no applicable key"):
			code = "ERR_JWKS_NO_MATCHING_KEY"
		case strings.Contains(m, "multiple matching keys"):
			code = "ERR_JWKS_MULTIPLE_MATCHING_KEYS"
		case strings.Contains(m, "malformed"):
			code = "ERR_JWKS_INVALID"
		case strings.Contains(m, "value not allowed"):
			code = "ERR_JOSE_ALG_NOT_ALLOWED"
		case strings.Contains(m, "not recognized"), strings.HasPrefix(m, "Unsupported"):
			code = "ERR_JOSE_NOT_SUPPORTED"
		case strings.HasPrefix(m, "JWT"):
			code = "ERR_JWT_INVALID"
		default:
			code = "ERR_JWS_INVALID"
		}
	}
	if code == "" {
		return err
	}
	return &CodedError{Code: code, Msg: je.Msg}
}

// VerifyJwtSvid verifies a JWT-SVID: the canonical-spelling gate, the signature under Key, the mandatory aud, exp / nbf, typ (JWT
// or JOSE when present), a SPIFFE sub pinned to TrustDomain, then Revocation.
func VerifyJwtSvid(token string, o VerifyJwtSvidOptions) (*JwtSvid, error) {
	if o.TrustDomain == "" {
		return nil, spiffeErr("missing_trust_domain", "verifyJwtSvid requires `trustDomain` (an unpinned JWT-SVID would accept any trust domain the key signs for)")
	}
	bad := len(o.Audience) == 0
	for _, a := range o.Audience {
		bad = bad || a == ""
	}
	if bad {
		return nil, spiffeErr("missing_audience", "verifyJwtSvid requires a non-empty audience (JWT-SVID aud is mandatory)")
	}
	algs := o.Algorithms
	if algs == nil {
		algs = JwtSvidAlgorithms
	}
	for _, a := range algs {
		if a == "none" || strings.HasPrefix(strings.ToUpper(a), "HS") {
			return nil, spiffeErr("forbidden_algorithm", "JWT-SVIDs must not use "+a)
		}
	}
	if len(algs) == 0 {
		return nil, spiffeErr("forbidden_algorithm", "JWT-SVIDs must not use an empty algorithm list")
	}
	if _, isStr := o.ClockTolerance.(string); !isStr {
		if f, isNum := jsNum(o.ClockTolerance); isNum && !(finite(f) && f >= 0) { // a non-finite tolerance makes every exp/nbf comparison pass
			return nil, spiffeErr("malformed_token", "verifyJwtSvid: clockTolerance must be a finite number >= 0")
		}
	}
	tol, err := joseSecs(o.ClockTolerance)
	if err != nil {
		return nil, err
	}
	if _, err := AssertCanonicalCompactJWS(token, 3, 0, true); err != nil {
		return nil, spiffeErr("malformed_token", err.Error())
	}
	if o.Key == nil {
		return nil, errors.New("verifyJwtSvid requires a verification key")
	}
	now := o.CurrentDate
	if now.IsZero() {
		now = time.Now()
	}
	sec := float64(now.UnixMilli()) / 1000
	header, payload, err := JWTVerify(token, o.Key, JWTVerifyOptions{Algorithms: algs, Audience: o.Audience, ClockTolerance: tol, NowSec: &sec}, sec)
	if err != nil {
		return nil, spiffeJoseErr(err)
	}
	if typ, has := header["typ"]; has && typ != "JWT" && typ != "JOSE" {
		return nil, spiffeErr("invalid_typ", fmt.Sprintf("JWT-SVID header typ must be JWT or JOSE, got '%s'", jsValueString(typ)))
	}
	exp, ok := jsNum(payload["exp"])
	if !ok {
		return nil, spiffeErr("missing_exp", `JWT-SVID is missing the required "exp" claim`)
	}
	sub, ok := payload["sub"].(string)
	if !ok {
		return nil, spiffeErr("invalid_subject", `JWT-SVID "sub" must be a string SPIFFE ID`)
	}
	id, err := ParseSpiffeID(sub)
	if err != nil {
		return nil, spiffeErr("invalid_subject", `JWT-SVID "sub" is not a valid SPIFFE ID: `+err.Error())
	}
	if id.TrustDomain != o.TrustDomain {
		return nil, spiffeErr("trust_domain_mismatch", fmt.Sprintf(`JWT-SVID trust domain "%s" does not match expected "%s"`, id.TrustDomain, o.TrustDomain))
	}
	var aud any = []any{}
	if a, has := payload["aud"]; has {
		aud = a
		if s, ok := a.(string); ok {
			aud = []any{s}
		}
	}
	if o.Revocation != nil {
		h := sha256.Sum256([]byte(wellFormedUTF8(token)))
		s := JwtRevocationSubject{SpiffeID: id.ID, ExpiresAt: exp, TokenHash: b64.EncodeToString(h[:])}
		if j, ok := payload["jti"].(string); ok {
			s.Jti = &j
		}
		revoked, err := o.Revocation(s)
		if err != nil {
			return nil, spiffeErr("revocation_unavailable", "revocation check failed: "+err.Error())
		}
		if revoked {
			return nil, spiffeErr("svid_revoked", "JWT-SVID for "+id.ID+" is revoked")
		}
	}
	return &JwtSvid{SpiffeID: id, Claims: payload, Audience: aud, ExpiresAt: payload["exp"], verified: true}, nil
}

// ---- X.509-SVID -----------------------------------------------------------------------------------------------------------

// X509Svid is a parsed X.509-SVID (only VerifyX509Svid makes one that SvidToHolder accepts). PublicKeyDer is the base64url SPKI.
type X509Svid struct {
	SpiffeID     SpiffeID `json:"spiffeId"`
	PublicKeyDer string   `json:"publicKeyDer"`
	cert         *attCert
	verified     bool
}

// X509RevocationSubject is what an X.509-SVID revocation check sees, for every certificate of the chain (leaf at position 0).
// SerialNumber is uppercase hex, Fingerprint256 the uppercase colon-separated SHA-256 of the DER (as node:crypto prints them).
type X509RevocationSubject struct {
	SpiffeID       string `json:"spiffeId"`
	SerialNumber   string `json:"serialNumber"`
	Fingerprint256 string `json:"fingerprint256"`
	Position       int    `json:"position"`
	IsLeaf         bool   `json:"isLeaf"`
}

// VerifyX509SvidOptions configure VerifyX509Svid. Roots are the trust-bundle authorities (PEM text, possibly several, or DER
// bytes). Now zero = the wall clock. MaxChainLength nil = 8. Revocation, when set, runs last for every certificate and must return
// false to admit.
type VerifyX509SvidOptions struct {
	TrustDomain    string
	Roots          []any
	Now            time.Time
	MaxChainLength *int
	Revocation     func(X509RevocationSubject) (bool, error)
}

var spiffePemCertRe = regexp.MustCompile(`-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----`)

// spiffeToCert reads a certificate as X509Certificate does: PEM text (its first CERTIFICATE block), or bytes (PEM when they hold a
// PEM block, otherwise DER; bytes after a DER certificate are not part of it).
func spiffeToCert(x any) (*attCert, error) {
	var c *attCert
	var err error
	switch v := x.(type) {
	case string:
		c, err = certFromPEM(v)
	case []byte:
		if strings.Contains(string(v), "-----BEGIN") {
			c, err = certFromPEM(string(v))
		} else {
			c, err = parseCertDER(v)
		}
	default:
		err = fmt.Errorf("certificate must be PEM text or DER bytes, got %T", x)
	}
	if err != nil {
		return nil, spiffeErr("malformed_certificate", "cannot parse certificate: "+err.Error())
	}
	return c, nil
}

func spiffeCertsOf(x any) ([]*attCert, error) {
	s, ok := x.(string)
	if !ok {
		c, err := spiffeToCert(x)
		if err != nil {
			return nil, err
		}
		return []*attCert{c}, nil
	}
	blocks := spiffePemCertRe.FindAllString(s, -1)
	if len(blocks) == 0 {
		return nil, spiffeErr("malformed_certificate", "no PEM certificate found")
	}
	out := make([]*attCert, 0, len(blocks))
	for _, b := range blocks {
		c, err := spiffeToCert(b)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

func spiffeFactsOf(c *attCert) (*spiffeCertFacts, error) {
	f, err := spiffeReadCertFacts(c.Raw)
	if err != nil {
		return nil, spiffeErr("malformed_certificate", "cannot read certificate extensions: "+err.Error())
	}
	if f.badBoolean {
		return nil, spiffeErr("malformed_certificate", "cannot parse certificate: malformed BOOLEAN")
	}
	return f, nil
}

// spiffeValidateLeaf applies the X509-SVID leaf rules (section 4.3).
func spiffeValidateLeaf(c *attCert) (SpiffeID, error) {
	f, err := spiffeFactsOf(c)
	if err != nil {
		return SpiffeID{}, err
	}
	switch {
	case len(f.unknownCritical) > 0:
		return SpiffeID{}, spiffeErr("unsupported_critical_extension", "certificate has an unsupported critical extension ("+strings.Join(f.unknownCritical, ", ")+")")
	case len(f.uriSANs) == 0:
		return SpiffeID{}, spiffeErr("no_uri_san", "X.509-SVID certificate has no URI SAN")
	case len(f.uriSANs) > 1:
		return SpiffeID{}, spiffeErr("multiple_uri_san", fmt.Sprintf("X.509-SVID certificate must have exactly one URI SAN, found %d", len(f.uriSANs)))
	}
	id, err := ParseSpiffeID(f.uriSANs[0])
	if err != nil {
		return SpiffeID{}, err
	}
	switch {
	case id.Path == "":
		return SpiffeID{}, spiffeErr("leaf_root_path", "X.509-SVID leaf SPIFFE ID must have a non-root path")
	case f.isCA:
		return SpiffeID{}, spiffeErr("leaf_is_ca", "leaf certificate must not have the CA flag set to true")
	case !f.digitalSignature:
		return SpiffeID{}, spiffeErr("leaf_no_digital_signature", "leaf certificate must have 'digitalSignature' set as key usage")
	case f.keyCertSign:
		return SpiffeID{}, spiffeErr("leaf_cert_sign", "leaf certificate must not have 'keyCertSign' set as key usage")
	case f.crlSign:
		return SpiffeID{}, spiffeErr("leaf_crl_sign", "leaf certificate must not have 'cRLSign' set as key usage")
	}
	return id, nil
}

// ParseX509Svid parses an X.509-SVID (PEM text or DER bytes) and applies the leaf rules. It does NOT check the chain, validity or
// revocation: SvidToHolder refuses its result.
func ParseX509Svid(cert any) (*X509Svid, error) {
	c, err := spiffeToCert(cert)
	if err != nil {
		return nil, err
	}
	id, err := spiffeValidateLeaf(c)
	if err != nil {
		return nil, err
	}
	return &X509Svid{SpiffeID: id, PublicKeyDer: b64.EncodeToString(c.RawSPKI), cert: c}, nil
}

func spiffeValidateSigner(c *attCert, label string) (*spiffeCertFacts, error) {
	f, err := spiffeFactsOf(c)
	if err != nil {
		return nil, err
	}
	if len(f.unknownCritical) > 0 {
		return nil, spiffeErr("unsupported_critical_extension", label+" has an unsupported critical extension ("+strings.Join(f.unknownCritical, ", ")+")")
	}
	if !f.isCA {
		return nil, spiffeErr("chain_not_ca", label+" must have the CA flag set to true")
	}
	if !f.keyUsagePresent || !f.keyCertSign {
		return nil, spiffeErr("chain_no_key_cert_sign", label+" must have 'keyCertSign' set as key usage")
	}
	return f, nil
}

func spiffeSignedBy(c, issuer *attCert) bool {
	return certCheckIssued(c, issuer) && certSigOKBy(c, issuer)
}

func spiffeSerialHex(c *attCert) string {
	h := strings.ToUpper(strings.TrimLeft(toHexLower(c.Serial), "0"))
	if len(h)%2 == 1 {
		h = "0" + h
	}
	if h == "" {
		h = "00"
	}
	return h
}

func spiffeFingerprint256(c *attCert) string {
	d := sha256.Sum256(c.Raw)
	h := strings.ToUpper(hex.EncodeToString(d[:]))
	parts := make([]string, 0, len(d))
	for i := 0; i < len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return strings.Join(parts, ":")
}

// VerifyX509Svid verifies an X.509-SVID against a trust bundle (X509-SVID section 4): the leaf rules, the trust domain, the
// validity of every certificate, CA / keyCertSign / pathLenConstraint of every signer, each certificate issued and signed by the
// next, and a chain ending at (or signed by) an authority in Roots; then Revocation. chain is PEM text or a list of PEM / DER items
// ([]any, []string or [][]byte), leaf first.
func VerifyX509Svid(chain any, o VerifyX509SvidOptions) (*X509Svid, error) {
	var items []*attCert
	add := func(x any) error {
		cs, err := spiffeCertsOf(x)
		items = append(items, cs...)
		return err
	}
	switch v := chain.(type) {
	case string:
		if err := add(v); err != nil {
			return nil, err
		}
	case []any:
		for _, x := range v {
			if err := add(x); err != nil {
				return nil, err
			}
		}
	case []string:
		for _, x := range v {
			if err := add(x); err != nil {
				return nil, err
			}
		}
	case [][]byte:
		for _, x := range v {
			if err := add(x); err != nil {
				return nil, err
			}
		}
	default:
		return nil, fmt.Errorf("chain must be PEM text or a list, got %T", chain)
	}
	if len(items) == 0 {
		return nil, spiffeErr("chain_empty", "certificate chain is empty")
	}
	maxLen := 8
	if o.MaxChainLength != nil {
		maxLen = *o.MaxChainLength
	}
	if len(items) > maxLen {
		return nil, spiffeErr("chain_too_long", "certificate chain is too long")
	}
	leaf := items[0]
	id, err := spiffeValidateLeaf(leaf)
	if err != nil {
		return nil, err
	}
	if id.TrustDomain != o.TrustDomain {
		return nil, spiffeErr("chain_trust_domain_mismatch", fmt.Sprintf("SPIFFE ID trust domain '%s' is not '%s'", id.TrustDomain, o.TrustDomain))
	}
	var roots []*attCert
	for _, r := range o.Roots {
		cs, err := spiffeCertsOf(r)
		if err != nil {
			return nil, err
		}
		roots = append(roots, cs...)
	}
	if len(roots) == 0 {
		return nil, spiffeErr("chain_untrusted_root", "trust bundle has no X.509 authorities")
	}
	now := o.Now
	if now.IsZero() {
		now = time.Now()
	}
	nowMs := now.UnixMilli()
	for _, c := range items {
		if !derValidAt(c.Raw, nowMs, 0) {
			return nil, spiffeErr("chain_expired", "a certificate in the chain is not within its validity period")
		}
	}
	// structure first: every signer is a CA with keyCertSign and a satisfied pathLenConstraint
	for i := 1; i < len(items); i++ {
		f, err := spiffeValidateSigner(items[i], fmt.Sprintf("signing certificate #%d", i))
		if err != nil {
			return nil, err
		}
		if f.pathLen >= 0 && float64(i-1) > f.pathLen {
			return nil, spiffeErr("chain_path_len", fmt.Sprintf("signing certificate #%d pathLenConstraint exceeded", i))
		}
	}
	for i := 0; i+1 < len(items); i++ {
		if !spiffeSignedBy(items[i], items[i+1]) {
			return nil, spiffeErr("chain_signature", fmt.Sprintf("certificate #%d is not signed by certificate #%d", i, i+1))
		}
	}
	isRoot := func(c *attCert) bool {
		for _, r := range roots {
			if string(r.Raw) == string(c.Raw) {
				return true
			}
		}
		return false
	}
	top := items[len(items)-1]
	if len(items) == 1 && isRoot(leaf) {
		return nil, spiffeErr("chain_untrusted_root", "a leaf certificate cannot be its own trust anchor")
	}
	if !(len(items) > 1 && isRoot(top)) {
		var signer *attCert
		for _, r := range roots {
			if spiffeSignedBy(top, r) {
				signer = r
				break
			}
		}
		if signer == nil {
			return nil, spiffeErr("chain_untrusted_root", "the chain does not lead to an authority in the trust bundle")
		}
		if !derValidAt(signer.Raw, nowMs, 0) {
			return nil, spiffeErr("chain_expired", "the trust bundle authority is not within its validity period")
		}
		f, err := spiffeValidateSigner(signer, "trust bundle authority")
		if err != nil {
			return nil, err
		}
		if f.pathLen >= 0 && float64(len(items)-1) > f.pathLen {
			return nil, spiffeErr("chain_path_len", "trust bundle authority pathLenConstraint exceeded")
		}
	}
	if o.Revocation != nil {
		for i, c := range items {
			revoked, err := o.Revocation(X509RevocationSubject{SpiffeID: id.ID, SerialNumber: spiffeSerialHex(c), Fingerprint256: spiffeFingerprint256(c), Position: i, IsLeaf: i == 0})
			if err != nil {
				return nil, spiffeErr("revocation_unavailable", "revocation check failed: "+err.Error())
			}
			if revoked && i == 0 {
				return nil, spiffeErr("svid_revoked", "X.509-SVID for "+id.ID+" is revoked")
			}
			if revoked {
				return nil, spiffeErr("chain_revoked", fmt.Sprintf("signing certificate #%d of the chain is revoked", i))
			}
		}
	}
	return &X509Svid{SpiffeID: id, PublicKeyDer: b64.EncodeToString(leaf.RawSPKI), cert: leaf, verified: true}, nil
}

// ---- SPIFFE ID <-> PCA agent-holder identity ------------------------------------------------------------------------------

// SpiffeHolder is a PCA capability holder (a base64url Ed25519 public key, Capability.holder) bound to a SPIFFE workload identity.
type SpiffeHolder struct {
	Holder      string `json:"holder"`
	SpiffeID    string `json:"spiffeId"`
	TrustDomain string `json:"trustDomain"`
	Path        string `json:"path"`
}

// SvidToHolderOptions: Proof is a base64url signature by the X.509-SVID key over HolderBindingMessage (ECDSA as IEEE P1363 with
// SHA-256, SHA-384 for P-384; RSA PKCS#1 v1.5 SHA-256), required when the holder is not the SVID's own Ed25519 key.
// AcceptUnboundJwtHolder admits a JWT-SVID without a matching cnf.jwk: set it ONLY when the holder key is authenticated to the
// token's bearer by other means.
type SvidToHolderOptions struct {
	Proof                  string
	AcceptUnboundJwtHolder bool
}

func spiffeNormalizeHolderKey(k any) (string, error) {
	if b, ok := k.([]byte); ok {
		if len(b) != 32 {
			return "", spiffeErr("invalid_holder_key", "holder key must be a 32-byte Ed25519 public key")
		}
		return b64.EncodeToString(b), nil
	}
	s, isStr := k.(string)
	raw, ok := DecodeB64uStrict(s, 32)
	if !isStr || !ok {
		return "", spiffeErr("invalid_holder_key", "holder key must be a 32-byte Ed25519 public key encoded as base64url")
	}
	return b64.EncodeToString(raw), nil
}

// HolderBindingMessage is the domain-separated message a workload signs with its SVID key to bind a PCA holder key to its SPIFFE ID.
func HolderBindingMessage(spiffeID, holder string) []byte {
	return []byte(wellFormedUTF8("pca-spiffe-holder-binding-v1\n" + spiffeID + "\n" + holder))
}

func spiffeProofOK(c *attCert, msg, sig []byte) bool {
	k, err := keyOfCert(c)
	if err != nil {
		return false
	}
	switch pk := k.pub.(type) {
	case ed25519.PublicKey:
		return len(sig) == ed25519.SignatureSize && ed25519.Verify(pk, msg, sig)
	case *ecdsa.PublicKey:
		n := (pk.Curve.Params().BitSize + 7) / 8
		if len(sig) != 2*n {
			return false
		}
		var d []byte
		if pk.Curve == elliptic.P384() {
			h := sha512.Sum384(msg)
			d = h[:]
		} else {
			h := sha256.Sum256(msg)
			d = h[:]
		}
		return ecdsa.Verify(pk, d, new(big.Int).SetBytes(sig[:n]), new(big.Int).SetBytes(sig[n:]))
	case *rsa.PublicKey:
		h := sha256.Sum256(msg)
		return k.typ != "rsa-pss" && rsaKeyOK(pk) && rsa.VerifyPKCS1v15(pk, crypto.SHA256, h[:], sig) == nil
	}
	return false
}

// SvidToHolder binds a VERIFIED SVID (what VerifyJwtSvid / VerifyX509Svid returned; anything else is unverified_svid) to a PCA
// holder. holderKey is nil (omitted), a base64url string or 32 raw bytes. An X.509-SVID with an Ed25519 key: the holder IS that
// key. Another key type, or a different holder: o.Proof. A JWT-SVID: its cnf.jwk must be the holder unless
// o.AcceptUnboundJwtHolder.
func SvidToHolder(svid any, holderKey any, o SvidToHolderOptions) (SpiffeHolder, error) {
	var id SpiffeID
	var holder string
	var err error
	switch s := svid.(type) {
	case *X509Svid:
		if s == nil || !s.verified {
			break
		}
		id = s.SpiffeID
		certEd := ""
		if k, err := keyOfCert(s.cert); err == nil {
			if pk, ok := k.pub.(ed25519.PublicKey); ok {
				certEd = b64.EncodeToString(pk)
			}
		}
		if holderKey == nil {
			if certEd == "" {
				return SpiffeHolder{}, spiffeErr("invalid_holder_key", "the X.509-SVID key is not Ed25519, so the holder cannot be derived from it: pass holderKey and opts.proof")
			}
			holder = certEd
		} else {
			if holder, err = spiffeNormalizeHolderKey(holderKey); err != nil {
				return SpiffeHolder{}, err
			}
			if certEd == "" || certEd != holder {
				if o.Proof == "" {
					return SpiffeHolder{}, spiffeErr("holder_binding_failed", "the holder key is not the SVID key: opts.proof (a signature by the SVID key over holderBindingMessage) is required")
				}
				sig, ok := DecodeB64uStrict(o.Proof, -1)
				if !ok || !spiffeProofOK(s.cert, HolderBindingMessage(id.ID, holder), sig) {
					return SpiffeHolder{}, spiffeErr("holder_binding_failed", "opts.proof does not verify under the X.509-SVID key")
				}
			}
		}
		return SpiffeHolder{Holder: holder, SpiffeID: id.ID, TrustDomain: id.TrustDomain, Path: id.Path}, nil
	case *JwtSvid:
		if s == nil || !s.verified {
			break
		}
		id = s.SpiffeID
		if holderKey == nil {
			return SpiffeHolder{}, spiffeErr("invalid_holder_key", "a JWT-SVID has no key of its own: pass holderKey")
		}
		if holder, err = spiffeNormalizeHolderKey(holderKey); err != nil {
			return SpiffeHolder{}, err
		}
		cnf, _ := s.Claims["cnf"].(map[string]any)
		jwk, _ := cnf["jwk"].(map[string]any)
		x, xok := jwk["x"].(string)
		bound := jwk["kty"] == "OKP" && jwk["crv"] == "Ed25519" && xok && x == holder
		if !bound && !o.AcceptUnboundJwtHolder {
			return SpiffeHolder{}, spiffeErr("holder_binding_failed", "the JWT-SVID carries no cnf.jwk equal to the holder key (set acceptUnboundJwtHolder only if the key is authenticated by other means)")
		}
		return SpiffeHolder{Holder: holder, SpiffeID: id.ID, TrustDomain: id.TrustDomain, Path: id.Path}, nil
	}
	return SpiffeHolder{}, spiffeErr("unverified_svid", "svidToHolder needs the result of verifyJwtSvid / verifyX509Svid (a string, a parsed-only SVID or a hand-built object is not accepted)")
}

// HolderToSpiffeID is the validated, canonical SPIFFE ID a SpiffeHolder was bridged from.
func HolderToSpiffeID(h SpiffeHolder) (string, error) {
	id, err := ParseSpiffeID(h.SpiffeID)
	return id.ID, err
}

// SpiffeIDForHolder is the SPIFFE ID the spiffe_bound caveat compares: the identity of a VERIFIED SVID, only when it is bound to
// leafHolder (the key that signed the PCActn).
func SpiffeIDForHolder(svid any, leafHolder string, o SvidToHolderOptions) (string, error) {
	h, err := SvidToHolder(svid, leafHolder, o)
	if err != nil {
		return "", err
	}
	if h.Holder != leafHolder {
		return "", spiffeErr("holder_binding_failed", "the SVID is not bound to the PCActn leaf holder")
	}
	return h.SpiffeID, nil
}

// WorkloadDischargePin is a discharge-issuer pin for a workload: its own Ed25519 X.509-SVID key and SPIFFE ID, class "workload".
func WorkloadDischargePin(label string, svid *X509Svid) (map[string]string, error) {
	h, err := SvidToHolder(svid, nil, SvidToHolderOptions{})
	if err != nil {
		return nil, err
	}
	return map[string]string{"label": label, "class": "workload", "pk": h.Holder, "spiffe_id": h.SpiffeID}, nil
}

// ---- trust-bundle and revocation caches (fail closed) ---------------------------------------------------------------------------

func spiffeCheckWindows(refreshMs, maxStaleMs float64, code string) error {
	fin := func(f float64) bool { return !math.IsNaN(f) && !math.IsInf(f, 0) }
	if !(fin(refreshMs) && refreshMs > 0) || !(fin(maxStaleMs) && maxStaleMs >= refreshMs) {
		return spiffeErr(code, "refreshMs must be > 0 and maxStaleMs >= refreshMs (both finite)")
	}
	return nil
}

func spiffeClockMs() float64 { return float64(time.Now().UnixMilli()) }

// SpiffeTrustBundleSourceOptions: Fetch returns the bundle as its JSON object form {"jwks": {"keys": [...]}, "x509Authorities":
// [PEM or DER, ...]}. Now is the clock in epoch ms (nil = the wall clock).
type SpiffeTrustBundleSourceOptions struct {
	Fetch                 func() (any, error)
	RefreshMs, MaxStaleMs float64
	Now                   func() float64
}

// SpiffeTrustBundleSource is a trust-bundle cache that fails closed: before the first successful fetch, or more than MaxStaleMs
// after the last one, every call refuses (trust_bundle_unavailable when the fetch failed, trust_bundle_invalid when the bundle was
// empty or malformed). A refresh REPLACES the bundle.
type SpiffeTrustBundleSource struct {
	o        SpiffeTrustBundleSourceOptions
	mu       sync.Mutex
	good     map[string]any
	at       float64
	lastFail error
}

// NewSpiffeTrustBundleSource checks the windows: RefreshMs > 0 and MaxStaleMs >= RefreshMs, both finite.
func NewSpiffeTrustBundleSource(o SpiffeTrustBundleSourceOptions) (*SpiffeTrustBundleSource, error) {
	if o.Fetch == nil {
		return nil, spiffeErr("trust_bundle_unavailable", "createTrustBundleSource requires `fetch`")
	}
	if err := spiffeCheckWindows(o.RefreshMs, o.MaxStaleMs, "trust_bundle_unavailable"); err != nil {
		return nil, err
	}
	if o.Now == nil {
		o.Now = spiffeClockMs
	}
	return &SpiffeTrustBundleSource{o: o}, nil
}

func spiffeNonEmptyList(v any) bool { l, ok := v.([]any); return ok && len(l) > 0 }

func (s *SpiffeTrustBundleSource) refresh() {
	b, err := s.o.Fetch()
	if err == nil {
		m, ok := b.(map[string]any)
		j, hasJ := m["jwks"]
		switch {
		case ok && hasJ && j == nil: // the reference reads .keys of it: a failed fetch, not an invalid bundle
			err = errors.New("Cannot read properties of null (reading 'keys')")
		case !ok:
			err = spiffeErr("trust_bundle_invalid", "fetched trust bundle has no authorities")
		default:
			jm, _ := j.(map[string]any)
			if !spiffeNonEmptyList(jm["keys"]) && !spiffeNonEmptyList(m["x509Authorities"]) {
				err = spiffeErr("trust_bundle_invalid", "fetched trust bundle has no authorities")
			} else {
				s.good, s.at, s.lastFail = m, s.o.Now(), nil
				return
			}
		}
	}
	var ce *CodedError
	if errors.As(err, &ce) && ce.Code != "" {
		s.lastFail = err
	} else {
		s.lastFail = spiffeErr("trust_bundle_unavailable", "trust bundle fetch failed: "+err.Error())
	}
}

func (s *SpiffeTrustBundleSource) current() (map[string]any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.good == nil || !(s.o.Now()-s.at < s.o.RefreshMs) {
		s.refresh()
	}
	if s.good == nil || !spiffeWithin(s.o.Now()-s.at, s.o.MaxStaleMs) {
		if s.lastFail != nil {
			return nil, s.lastFail
		}
		return nil, spiffeErr("trust_bundle_unavailable", "no trust bundle available")
	}
	return s.good, nil
}

// JwtKey is the key resolver for VerifyJwtSvidOptions.Key.
func (s *SpiffeTrustBundleSource) JwtKey(header map[string]any) (*JOSEKey, error) {
	b, err := s.current()
	if err != nil {
		return nil, err
	}
	jwks, _ := b["jwks"].(map[string]any)
	if !spiffeNonEmptyList(jwks["keys"]) {
		return nil, spiffeErr("trust_bundle_invalid", "trust bundle has no JWT authorities")
	}
	r, err := NewLocalJWKSet(jwks)
	if err != nil {
		return nil, spiffeJoseErr(&JOSEError{Kind: "invalid", Msg: err.Error()})
	}
	k, err := r(header)
	if err != nil {
		return nil, spiffeJoseErr(err)
	}
	return k, nil
}

// X509Roots are the authorities for VerifyX509SvidOptions.Roots.
func (s *SpiffeTrustBundleSource) X509Roots() ([]any, error) {
	b, err := s.current()
	if err != nil {
		return nil, err
	}
	l, ok := b["x509Authorities"].([]any)
	if !ok || len(l) == 0 {
		return nil, spiffeErr("trust_bundle_invalid", "trust bundle has no X.509 authorities")
	}
	return append([]any{}, l...), nil
}

// SpiffeRevocationSourceOptions: Fetch returns the revocation list as its JSON object form, optional string lists fingerprints,
// serials, spiffeIds, jtis and tokenHashes. Now is the clock in epoch ms (nil = the wall clock).
type SpiffeRevocationSourceOptions struct {
	Fetch                 func() (any, error)
	RefreshMs, MaxStaleMs float64
	Now                   func() float64
}

type spiffeRevSnapshot struct{ fingerprints, serials, spiffeIDs, jtis, tokenHashes map[string]bool }

// SpiffeRevocationSource is a revocation snapshot cache that fails closed, in the shape of SpiffeTrustBundleSource. X509 uses the
// cached snapshot (call EnsureFresh first); Jwt refreshes when due.
type SpiffeRevocationSource struct {
	o        SpiffeRevocationSourceOptions
	mu       sync.Mutex
	good     *spiffeRevSnapshot
	at       float64
	lastFail error
}

// NewSpiffeRevocationSource checks the windows: RefreshMs > 0 and MaxStaleMs >= RefreshMs, both finite.
func NewSpiffeRevocationSource(o SpiffeRevocationSourceOptions) (*SpiffeRevocationSource, error) {
	if o.Fetch == nil {
		return nil, spiffeErr("revocation_unavailable", "createRevocationSource requires `fetch`")
	}
	if err := spiffeCheckWindows(o.RefreshMs, o.MaxStaleMs, "revocation_unavailable"); err != nil {
		return nil, err
	}
	if o.Now == nil {
		o.Now = spiffeClockMs
	}
	return &SpiffeRevocationSource{o: o}, nil
}

func spiffeNormHex(s string) string { return strings.ToUpper(strings.ReplaceAll(s, ":", "")) }

func spiffeNormSerial(s string) string {
	h := spiffeNormHex(s)
	t := strings.TrimLeft(h, "0")
	if t == "" && h != "" {
		return "0"
	}
	return t
}

func spiffeRevSnapshotOf(v any) (*spiffeRevSnapshot, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, spiffeErr("revocation_unavailable", "revocation list must be an object")
	}
	list := func(k string, norm func(string) string) (map[string]bool, error) {
		out := map[string]bool{}
		x, has := m[k]
		if !has {
			return out, nil
		}
		l, ok := x.([]any)
		if !ok {
			return nil, spiffeErr("revocation_unavailable", `revocation list field "`+k+`" must be an array of strings`)
		}
		for _, e := range l {
			s, ok := e.(string)
			if !ok {
				return nil, spiffeErr("revocation_unavailable", `revocation list field "`+k+`" must be an array of strings`)
			}
			out[norm(s)] = true
		}
		return out, nil
	}
	same := func(s string) string { return s }
	snap := &spiffeRevSnapshot{}
	var err error
	if snap.fingerprints, err = list("fingerprints", spiffeNormHex); err != nil {
		return nil, err
	}
	if snap.serials, err = list("serials", spiffeNormSerial); err != nil {
		return nil, err
	}
	if snap.spiffeIDs, err = list("spiffeIds", same); err != nil {
		return nil, err
	}
	if snap.jtis, err = list("jtis", same); err != nil {
		return nil, err
	}
	if snap.tokenHashes, err = list("tokenHashes", same); err != nil {
		return nil, err
	}
	return snap, nil
}

func (s *SpiffeRevocationSource) run() {
	v, err := s.o.Fetch()
	var snap *spiffeRevSnapshot
	if err == nil {
		snap, err = spiffeRevSnapshotOf(v)
	}
	if err == nil {
		s.good, s.at, s.lastFail = snap, s.o.Now(), nil
		return
	}
	var ce *CodedError
	if errors.As(err, &ce) && ce.Code != "" {
		s.lastFail = err
	} else {
		s.lastFail = spiffeErr("revocation_unavailable", "revocation fetch failed: "+err.Error())
	}
}

func (s *SpiffeRevocationSource) usable() (*spiffeRevSnapshot, error) {
	if s.good == nil || !spiffeWithin(s.o.Now()-s.at, s.o.MaxStaleMs) {
		if s.lastFail != nil {
			return nil, s.lastFail
		}
		return nil, spiffeErr("revocation_unavailable", "no revocation snapshot available")
	}
	return s.good, nil
}

// Refresh fetches now; it refuses when the fetch fails or returns a malformed list (the previous snapshot stays).
func (s *SpiffeRevocationSource) Refresh() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.run()
	return s.lastFail
}

func (s *SpiffeRevocationSource) ensureFresh() (*spiffeRevSnapshot, error) {
	if s.good == nil || !(s.o.Now()-s.at < s.o.RefreshMs) {
		s.run()
	}
	return s.usable()
}

// EnsureFresh fetches when the snapshot is older than RefreshMs; it refuses when no snapshot younger than MaxStaleMs exists after.
func (s *SpiffeRevocationSource) EnsureFresh() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.ensureFresh()
	return err
}

// X509 is a VerifyX509SvidOptions.Revocation check over the cached snapshot.
func (s *SpiffeRevocationSource) X509(x X509RevocationSubject) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap, err := s.usable()
	if err != nil {
		return false, err
	}
	return snap.fingerprints[spiffeNormHex(x.Fingerprint256)] || snap.serials[spiffeNormSerial(x.SerialNumber)] || snap.spiffeIDs[x.SpiffeID], nil
}

// Jwt is a VerifyJwtSvidOptions.Revocation check; it refreshes the snapshot when due.
func (s *SpiffeRevocationSource) Jwt(j JwtRevocationSubject) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap, err := s.ensureFresh()
	if err != nil {
		return false, err
	}
	return snap.spiffeIDs[j.SpiffeID] || (j.Jti != nil && snap.jtis[*j.Jti]) || snap.tokenHashes[j.TokenHash], nil
}

// ---- evidence for blueprint admission -------------------------------------------------------------------------------------

// SpiffeEvidence is an SVID presented for admission: Kind "x509" (Chain, X509) or "jwt" (Token, Jwt), with its binding options.
type SpiffeEvidence struct {
	Kind  string
	Chain any
	X509  VerifyX509SvidOptions
	Token string
	Jwt   VerifyJwtSvidOptions
	Bind  SvidToHolderOptions
}

// SpiffeAdmissionResult: Identity is {"spiffe_id": ...} when admitted; Reason names the refusal (its code).
type SpiffeAdmissionResult struct {
	OK       bool              `json:"ok"`
	Bound    bool              `json:"bound"`
	Identity map[string]string `json:"identity,omitempty"`
	Reason   string            `json:"reason,omitempty"`
}

// SpiffeAdmissionEvidence admits a workload under its verified SPIFFE ID: the SVID is verified, then bound to the INSTANCE KEY.
// Anything unverifiable, unbound or bound to another key is {ok: false, bound: false, reason}.
func SpiffeAdmissionEvidence(e SpiffeEvidence, instanceKey string) SpiffeAdmissionResult {
	var svid any
	var err error
	if e.Kind == "x509" {
		svid, err = VerifyX509Svid(e.Chain, e.X509)
	} else {
		svid, err = VerifyJwtSvid(e.Token, e.Jwt)
	}
	var h SpiffeHolder
	if err == nil {
		h, err = SvidToHolder(svid, instanceKey, e.Bind)
	}
	if err != nil {
		reason := "Error"
		var ce *CodedError
		if errors.As(err, &ce) && ce.Code != "" {
			reason = ce.Code
		}
		return SpiffeAdmissionResult{Reason: reason}
	}
	if h.Holder != instanceKey {
		return SpiffeAdmissionResult{Reason: "SVID is bound to a different key"}
	}
	return SpiffeAdmissionResult{OK: true, Bound: true, Identity: map[string]string{"spiffe_id": h.SpiffeID}}
}

// spiffeWithin reports whether a snapshot of this age is still usable: a non-finite age never is.
func spiffeWithin(age, maxStaleMs float64) bool { return finite(age) && age <= maxStaleMs }
