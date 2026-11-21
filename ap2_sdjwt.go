package pca

// AP2 mandates as SD-JWT credentials (RFC 9901): strict compact parsing, disclosure processing, the sd_hash / issuer_jwt_hash binding
// digests and ES256 (P-256) signing and verification. Nothing here implements a primitive: SHA-2 and ECDSA come from the standard
// library. The code is the SD-JWT format (what is hashed, in which order, which shapes are accepted) and it fails closed on every
// ambiguity (duplicate digests, unreferenced disclosures, malformed base64url, duplicate JSON keys, unknown _sd_alg, non-ES256).

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"hash"
	"math/big"
	"strings"
)

// Ap2IsSdAlg reports whether v is one of the _sd_alg values the AP2 reference accepts.
func Ap2IsSdAlg(v any) bool {
	s, ok := v.(string)
	return ok && (s == "sha-256" || s == "sha-384" || s == "sha-512")
}

func ap2NewHash(alg string) (hash.Hash, bool) {
	switch alg {
	case "sha-256":
		return sha256.New(), true
	case "sha-384":
		return sha512.New384(), true
	case "sha-512":
		return sha512.New(), true
	}
	return nil, false
}

// Ap2SdDigest is base64url(hash(ascii(value))): the digest used for disclosures, sd_hash and checkout_hash.
func Ap2SdDigest(value, alg string) (string, error) {
	for i := 0; i < len(value); i++ {
		if value[i] < 0x20 || value[i] > 0x7e {
			return "", ap2Fail("digest input must be ASCII")
		}
	}
	h, ok := ap2NewHash(alg)
	if !ok {
		return "", ap2Fail("unsupported digest algorithm %s", ap2JSON(alg))
	}
	h.Write([]byte(value))
	return ap2B64uEnc(h.Sum(nil)), nil
}

// ---- ES256 keys (P-256) ------------------------------------------------------------------------------------------------

// Ap2KeyPair is an ES256 key pair: the public JWK (never carrying d) and the private key.
type Ap2KeyPair struct {
	PublicJwk map[string]any
	priv      *ecdsa.PrivateKey
}

func ap2IsB64u43(v any) (string, bool) {
	s, ok := v.(string)
	if !ok || len(s) != 43 {
		return "", false
	}
	for i := 0; i < 43; i++ {
		c := s[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return "", false
		}
	}
	return s, true
}

// ap2PublicKey builds the public key of a JWK whose coordinates are 43-character base64url (an alias of a coordinate, whose unused
// low bits differ, decodes to the same key) and proves the point is on the curve.
func ap2PublicKey(x, y string) (*ecdsa.PublicKey, bool) {
	xb, err1 := base64.RawURLEncoding.DecodeString(x)
	yb, err2 := base64.RawURLEncoding.DecodeString(y)
	if err1 != nil || err2 != nil || len(xb) != 32 || len(yb) != 32 {
		return nil, false
	}
	raw := make([]byte, 0, 65)
	raw = append(raw, 4)
	raw = append(raw, xb...)
	raw = append(raw, yb...)
	if _, err := ecdh.P256().NewPublicKey(raw); err != nil {
		return nil, false
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(xb), Y: new(big.Int).SetBytes(yb)}, true
}

// Ap2AssertP256Jwk validates a public JWK against the AP2 JWK schema and proves the point is on the curve. It returns the JWK itself.
func Ap2AssertP256Jwk(jwk any, what string) (map[string]any, error) {
	m, ok := ap2Obj(jwk)
	if !ok {
		return nil, ap2Fail("%s: JWK must be an object", what)
	}
	if !ap2StrictEq(ap2Get(m, "kty"), "EC") || !ap2StrictEq(ap2Get(m, "crv"), "P-256") {
		return nil, ap2Fail("%s: JWK must be EC P-256", what)
	}
	x, okx := ap2IsB64u43(ap2Get(m, "x"))
	if !okx {
		return nil, ap2Fail("%s: bad JWK x", what)
	}
	y, oky := ap2IsB64u43(ap2Get(m, "y"))
	if !oky {
		return nil, ap2Fail("%s: bad JWK y", what)
	}
	if ap2Has(m, "d") {
		return nil, ap2Fail("%s: JWK carries private material", what)
	}
	if alg := ap2Get(m, "alg"); !ap2IsU(alg) && !ap2StrictEq(alg, "ES256") {
		return nil, ap2Fail("%s: JWK alg must be ES256", what)
	}
	if _, ok := ap2PublicKey(x, y); !ok {
		return nil, ap2Fail("%s: JWK is not a valid P-256 point", what)
	}
	return m, nil
}

func ap2KeyFromScalar(d []byte) (*Ap2KeyPair, error) {
	k, err := ecdh.P256().NewPrivateKey(d)
	if err != nil {
		return nil, ap2Fail("Invalid JWK EC key")
	}
	pub := k.PublicKey().Bytes()
	priv := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(pub[1:33]), Y: new(big.Int).SetBytes(pub[33:65])},
		D:         new(big.Int).SetBytes(d),
	}
	return &Ap2KeyPair{PublicJwk: ap2Map("kty", "EC", "crv", "P-256", "x", ap2B64uEnc(pub[1:33]), "y", ap2B64uEnc(pub[33:65])), priv: priv}, nil
}

// GenerateAp2KeyPair makes a fresh ES256 key pair; kid (when non-empty) is carried on the public JWK.
func GenerateAp2KeyPair(kid string) (*Ap2KeyPair, error) {
	d := make([]byte, 32)
	for {
		if _, err := rand.Read(d); err != nil {
			return nil, err
		}
		kp, err := ap2KeyFromScalar(d)
		if err != nil {
			continue
		}
		if kid != "" {
			kp.PublicJwk = ap2New().spread(kp.PublicJwk).set("kid", kid).done()
		}
		return kp, nil
	}
}

// Ap2KeyPairFromPrivateJwk rebuilds a key pair from a private JWK (d present). The public part is derived from d and the JWK's own
// x and y must agree with it (a mismatched pair is refused).
func Ap2KeyPairFromPrivateJwk(jwk map[string]any) (*Ap2KeyPair, error) {
	if !ap2StrictEq(ap2Get(jwk, "kty"), "EC") || !ap2StrictEq(ap2Get(jwk, "crv"), "P-256") {
		return nil, ap2Fail("Invalid JWK EC key")
	}
	ds, okd := jwk["d"].(string)
	xs, okx := jwk["x"].(string)
	ys, oky := jwk["y"].(string)
	if !okd || !okx || !oky {
		return nil, ap2Fail("Invalid JWK EC key")
	}
	db, err := base64.RawURLEncoding.DecodeString(ds)
	xb, err2 := base64.RawURLEncoding.DecodeString(xs)
	yb, err3 := base64.RawURLEncoding.DecodeString(ys)
	if err != nil || err2 != nil || err3 != nil || len(db) != 32 || len(xb) != 32 || len(yb) != 32 {
		return nil, ap2Fail("Invalid JWK EC key")
	}
	kp, err := ap2KeyFromScalar(db)
	if err != nil {
		return nil, err
	}
	if new(big.Int).SetBytes(xb).Cmp(kp.priv.X) != 0 || new(big.Int).SetBytes(yb).Cmp(kp.priv.Y) != 0 {
		return nil, ap2Fail("Invalid JWK EC key")
	}
	if kid, ok := jwk["kid"].(string); ok {
		kp.PublicJwk = ap2New().spread(kp.PublicJwk).set("kid", kid).done()
	}
	return kp, nil
}

// Ap2JwkThumbprint is the RFC 7638 thumbprint (SHA-256) of an EC P-256 key; the members are read as the reference reads them.
func Ap2JwkThumbprint(jwk any) (string, error) {
	if jwk == nil || ap2IsU(jwk) {
		return "", ap2Fail("Cannot read properties of %s (reading 'x')", ap2Str(jwk))
	}
	sum := sha256.Sum256([]byte(wtfToUTF8(`{"crv":"P-256","kty":"EC","x":"` + ap2Str(ap2Get(jwk, "x")) + `","y":"` + ap2Str(ap2Get(jwk, "y")) + `"}`)))
	return ap2B64uEnc(sum[:]), nil
}

func ap2Es256Sign(priv *ecdsa.PrivateKey, signingInput string) (string, error) {
	h := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, priv, h[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return ap2B64uEnc(sig), nil
}

func ap2Es256Verify(jwk map[string]any, signingInput string, sig []byte) bool {
	if len(sig) != 64 {
		return false
	}
	pub, ok := ap2PublicKey(jwk["x"].(string), jwk["y"].(string))
	if !ok {
		return false
	}
	h := sha256.Sum256([]byte(signingInput))
	return ecdsa.Verify(pub, h[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
}

// ---- compact JWT / SD-JWT parsing --------------------------------------------------------------------------------------

// Ap2SdJwtHop is one SD-JWT: an issuer-signed JWT plus its disclosures (no trailing KB-JWT; AP2 binds with chain hops).
type Ap2SdJwtHop struct {
	Raw          string // canonical serialisation <jwt>~<d1>~...~<dn>~
	Jwt          string
	Header       map[string]any
	Payload      map[string]any // the signed payload exactly as issued (digest placeholders still in place)
	Disclosures  []string
	SdAlg        string
	SigningInput string
	Signature    []byte
}

// Ap2HopSdJwt is the hop's ~-joined serialisation: what sd_hash is computed over.
func Ap2HopSdJwt(jwt string, disclosures []string) string {
	var sb strings.Builder
	sb.WriteString(jwt)
	sb.WriteByte('~')
	for _, d := range disclosures {
		sb.WriteString(d)
		sb.WriteByte('~')
	}
	return sb.String()
}

// Ap2ParseSdJwtHop parses one SD-JWT (jwt~d1~...~dn~). The serialisation must end with "~".
func Ap2ParseSdJwtHop(token string) (*Ap2SdJwtHop, error) {
	if len(token) == 0 {
		return nil, ap2Fail("SD-JWT: empty")
	}
	if strings.HasPrefix(token, "~") {
		return nil, ap2Fail("SD-JWT: empty issuer JWT")
	}
	if !strings.HasSuffix(token, "~") {
		return nil, ap2Fail("SD-JWT: must end with \"~\" (a trailing KB-JWT is not an AP2 form)")
	}
	parts := strings.Split(token[:len(token)-1], "~")
	jwt := parts[0]
	disclosures := parts[1:]
	for _, d := range disclosures {
		if len(d) == 0 {
			return nil, ap2Fail("SD-JWT: empty disclosure segment")
		}
	}
	seg := strings.Split(jwt, ".")
	if len(seg) != 3 || len(seg[0]) == 0 || len(seg[1]) == 0 || len(seg[2]) == 0 {
		return nil, ap2Fail("SD-JWT: issuer JWT must be header.payload.signature")
	}
	header, err := ap2DecodeJSONSegment(seg[0], "JWT header")
	if err != nil {
		return nil, err
	}
	payload, err := ap2DecodeJSONSegment(seg[1], "JWT payload")
	if err != nil {
		return nil, err
	}
	signature, err := Ap2B64uDecode(seg[2], "JWT signature")
	if err != nil {
		return nil, err
	}
	rawAlg := ap2Get(payload, "_sd_alg")
	if !ap2IsU(rawAlg) && !Ap2IsSdAlg(rawAlg) {
		return nil, ap2Fail("SD-JWT: unsupported _sd_alg %s", ap2JSON(rawAlg))
	}
	alg := "sha-256"
	if Ap2IsSdAlg(rawAlg) {
		alg = rawAlg.(string)
	}
	if disclosures == nil {
		disclosures = []string{}
	}
	return &Ap2SdJwtHop{Raw: token, Jwt: jwt, Header: header, Payload: payload, Disclosures: disclosures, SdAlg: alg,
		SigningInput: seg[0] + "." + seg[1], Signature: signature}, nil
}

// Ap2SdHashOf is the sd_hash of a hop: the digest of <jwt>~<d1>~...~ (alg "" = the hop's own _sd_alg).
func Ap2SdHashOf(h *Ap2SdJwtHop, alg string) (string, error) {
	if alg == "" {
		alg = h.SdAlg
	}
	return Ap2SdDigest(Ap2HopSdJwt(h.Jwt, h.Disclosures), alg)
}

// Ap2IssuerJwtHashOf is the issuer_jwt_hash of a hop: the digest of the issuer-signed JWT alone.
func Ap2IssuerJwtHashOf(h *Ap2SdJwtHop, alg string) (string, error) {
	if alg == "" {
		alg = h.SdAlg
	}
	return Ap2SdDigest(h.Jwt, alg)
}

// Ap2VerifyHopSignature verifies the issuer JWT's ES256 signature. Anything other than alg ES256 is rejected (before the key is read).
func Ap2VerifyHopSignature(h *Ap2SdJwtHop, key any) (bool, error) {
	if !ap2StrictEq(ap2Get(h.Header, "alg"), "ES256") {
		return false, nil
	}
	jwk, err := Ap2AssertP256Jwk(key, "verification key")
	if err != nil {
		return false, err
	}
	return ap2Es256Verify(jwk, h.SigningInput, h.Signature), nil
}

// Ap2ParsedJwt is a compact JWT split into its decoded parts.
type Ap2ParsedJwt struct {
	Header       map[string]any
	Payload      map[string]any
	SigningInput string
	Signature    []byte
}

// Ap2ParseJwt parses header.payload.signature.
func Ap2ParseJwt(jwt, what string) (*Ap2ParsedJwt, error) {
	seg := strings.Split(jwt, ".")
	if len(seg) != 3 || len(seg[0]) == 0 || len(seg[1]) == 0 || len(seg[2]) == 0 {
		return nil, ap2Fail("%s: must be header.payload.signature", what)
	}
	header, err := ap2DecodeJSONSegment(seg[0], what+" header")
	if err != nil {
		return nil, err
	}
	payload, err := ap2DecodeJSONSegment(seg[1], what+" payload")
	if err != nil {
		return nil, err
	}
	sig, err := Ap2B64uDecode(seg[2], what+" signature")
	if err != nil {
		return nil, err
	}
	return &Ap2ParsedJwt{Header: header, Payload: payload, SigningInput: seg[0] + "." + seg[1], Signature: sig}, nil
}

// Ap2VerifyJwtEs256 verifies a parsed JWT under an ES256 key (alg must be ES256).
func Ap2VerifyJwtEs256(p *Ap2ParsedJwt, key any) (bool, error) {
	if !ap2StrictEq(ap2Get(p.Header, "alg"), "ES256") {
		return false, nil
	}
	jwk, err := Ap2AssertP256Jwk(key, "verification key")
	if err != nil {
		return false, err
	}
	return ap2Es256Verify(jwk, p.SigningInput, p.Signature), nil
}

// ---- disclosure processing (RFC 9901 section 7) ------------------------------------------------------------------------

type ap2Disc struct {
	kind  string // "property" | "element"
	name  string
	value any
}

func ap2DecodeDisclosure(raw string) (*ap2Disc, error) {
	b, err := Ap2B64uDecode(raw, "disclosure")
	if err != nil {
		return nil, err
	}
	text, err := ap2Utf8Text(b, "disclosure")
	if err != nil {
		return nil, err
	}
	v, err := ap2ParseJson(text, "disclosure")
	if err != nil {
		return nil, err
	}
	arr, ok := v.([]any)
	if !ok {
		return nil, ap2Fail("disclosure: must be a JSON array")
	}
	if len(arr) == 0 || !ap2IsNonEmptyStr(arr[0]) {
		return nil, ap2Fail("disclosure: salt must be a non-empty string")
	}
	switch len(arr) {
	case 3:
		name, ok := arr[1].(string)
		if !ok {
			return nil, ap2Fail("disclosure: claim name must be a string")
		}
		if name == "_sd" || name == "..." {
			return nil, ap2Fail("disclosure: claim name %s is reserved", name)
		}
		return &ap2Disc{kind: "property", name: name, value: arr[2]}, nil
	case 2:
		return &ap2Disc{kind: "element", value: arr[1]}, nil
	}
	return nil, ap2Fail("disclosure: array must have 2 or 3 elements")
}

// Ap2ProcessDisclosures resolves every selectively-disclosable claim in payload using disclosures and returns the processed claims
// (_sd, "..." markers and _sd_alg removed). It refuses a disclosure that is duplicated, not referenced from the payload, colliding
// with an existing claim, or used in the wrong position.
func Ap2ProcessDisclosures(payload map[string]any, disclosures []string, alg string) (map[string]any, error) {
	byDigest := map[string]*ap2Disc{}
	for _, raw := range disclosures {
		d, err := ap2DecodeDisclosure(raw)
		if err != nil {
			return nil, err
		}
		digest, err := Ap2SdDigest(raw, alg)
		if err != nil {
			return nil, err
		}
		if _, dup := byDigest[digest]; dup {
			return nil, ap2Fail("SD-JWT: duplicate disclosure")
		}
		byDigest[digest] = d
	}
	used := map[string]bool{}
	take := func(digest, want string) (*ap2Disc, error) {
		d, ok := byDigest[digest]
		if !ok {
			return nil, nil // decoy digest, or a disclosure the holder chose not to reveal
		}
		if used[digest] {
			return nil, ap2Fail("SD-JWT: a digest is referenced more than once")
		}
		if d.kind != want {
			return nil, ap2Fail("SD-JWT: a %s disclosure is referenced from a %s position", d.kind, want)
		}
		used[digest] = true
		return d, nil
	}
	var walk func(node any, depth int) (any, error)
	walk = func(node any, depth int) (any, error) {
		if depth > 32 {
			return nil, ap2Fail("SD-JWT: nesting too deep")
		}
		switch n := node.(type) {
		case []any:
			out := []any{}
			for _, el := range n {
				if m, ok := ap2Obj(el); ok && ap2Has(m, "...") {
					digest, isStr := m["..."].(string)
					if len(m) != 1 || !isStr {
						return nil, ap2Fail("SD-JWT: malformed array digest placeholder")
					}
					d, err := take(digest, "element")
					if err != nil {
						return nil, err
					}
					if d != nil {
						x, err := walk(d.value, depth+1)
						if err != nil {
							return nil, err
						}
						out = append(out, x)
					}
					continue
				}
				x, err := walk(el, depth+1)
				if err != nil {
					return nil, err
				}
				out = append(out, x)
			}
			return out, nil
		case map[string]any:
			out := ap2New()
			for _, k := range jsKeys(n) {
				if k == "_sd" || k == "_sd_alg" {
					continue
				}
				if k == "..." {
					return nil, ap2Fail("SD-JWT: \"...\" is only valid as the sole key of an array element")
				}
				x, err := walk(n[k], depth+1)
				if err != nil {
					return nil, err
				}
				out.set(k, x)
			}
			if sd, has := n["_sd"]; has {
				list, ok := sd.([]any)
				if !ok {
					return nil, ap2Fail("SD-JWT: _sd must be an array of strings")
				}
				for _, e := range list {
					if _, isStr := e.(string); !isStr {
						return nil, ap2Fail("SD-JWT: _sd must be an array of strings")
					}
				}
				for _, e := range list {
					d, err := take(e.(string), "property")
					if err != nil {
						return nil, err
					}
					if d == nil || d.kind != "property" {
						continue
					}
					if ap2Has(out.m, d.name) {
						return nil, ap2Fail("SD-JWT: disclosed claim %s collides with an existing claim", d.name)
					}
					x, err := walk(d.value, depth+1)
					if err != nil {
						return nil, err
					}
					out.set(d.name, x)
				}
			}
			return out.done(), nil
		}
		return node, nil
	}
	res, err := walk(payload, 0)
	if err != nil {
		return nil, err
	}
	if len(used) != len(byDigest) {
		return nil, ap2Fail("SD-JWT: a disclosure is not referenced by the signed payload")
	}
	return res.(map[string]any), nil
}

// ---- issuing -----------------------------------------------------------------------------------------------------------

// Ap2NewSalt is a fresh 128-bit salt.
func Ap2NewSalt() string {
	b := make([]byte, 16)
	rand.Read(b) // never fails since Go 1.24
	return ap2B64uEnc(b)
}

// Ap2DisclosureBuilder collects the disclosures of one SD-JWT.
type Ap2DisclosureBuilder struct {
	alg         string
	salt        func() string
	Disclosures []string
}

// Ap2NewDisclosureBuilder starts a builder (alg "" = sha-256, salt nil = random).
func Ap2NewDisclosureBuilder(alg string, salt func() string) *Ap2DisclosureBuilder {
	if alg == "" {
		alg = "sha-256"
	}
	if salt == nil {
		salt = Ap2NewSalt
	}
	return &Ap2DisclosureBuilder{alg: alg, salt: salt, Disclosures: []string{}}
}

func (b *Ap2DisclosureBuilder) add(parts []any) (string, error) {
	text, err := ap2Stringify(parts)
	if err != nil {
		return "", err
	}
	raw := Ap2B64uEncode(text)
	b.Disclosures = append(b.Disclosures, raw)
	return Ap2SdDigest(raw, b.alg)
}

// Element is an array-element disclosure for value; it returns the {"...": digest} placeholder.
func (b *Ap2DisclosureBuilder) Element(value any) (map[string]any, error) {
	d, err := b.add([]any{b.salt(), value})
	if err != nil {
		return nil, err
	}
	return ap2Map("...", d), nil
}

// Property is a property disclosure; it returns the digest to put into the parent's _sd.
func (b *Ap2DisclosureBuilder) Property(name string, value any) (string, error) {
	return b.add([]any{b.salt(), name, value})
}

// Ap2SignSdJwt signs payload as an ES256 JWT and appends disclosures: <jwt>~<d1>~...~<dn>~. header carries typ (and optionally kid / x5c);
// alg ES256 leads it.
func Ap2SignSdJwt(header, payload map[string]any, disclosures []string, key *Ap2KeyPair) (string, error) {
	jwt, err := ap2SignCompact(ap2New().set("alg", "ES256").spread(header).done(), payload, key)
	if err != nil {
		return "", err
	}
	return Ap2HopSdJwt(jwt, disclosures), nil
}

// Ap2SignJwtEs256 signs an arbitrary compact JWT (used for the merchant-signed checkout_jwt).
func Ap2SignJwtEs256(header, payload map[string]any, key *Ap2KeyPair) (string, error) {
	return ap2SignCompact(ap2New().set("alg", "ES256").set("typ", "JWT").spread(header).done(), payload, key)
}

func ap2SignCompact(header, payload map[string]any, key *Ap2KeyPair) (string, error) {
	h, err := ap2Stringify(header)
	if err != nil {
		return "", err
	}
	p, err := ap2Stringify(payload)
	if err != nil {
		return "", err
	}
	input := Ap2B64uEncode(h) + "." + Ap2B64uEncode(p)
	sig, err := ap2Es256Sign(key.priv, input)
	if err != nil {
		return "", err
	}
	return input + "." + sig, nil
}
