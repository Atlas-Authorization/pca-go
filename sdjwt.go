package pca

// SD-JWT serialization of a PCActn (IETF SD-JWT / RFC 9901 with key binding): the standard claims in the clear, the capability
// claims as salted Disclosures (`_sd` digests), an optional `cnf` holder key and a KB-JWT at presentation. A bridge, not a
// replacement: VerifySdJwtRecovered rebuilds the PCActn from the disclosed claims and runs the core verifier on it.

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

const (
	SdJwtSdAlg              = "sha-256"
	PcaSdJwtTyp             = "pca+sd-jwt"
	SdJwtKbTyp              = "kb+jwt"
	SdJwtDefaultSigningAlg  = "EdDSA"
	sdjwtClearDiscriminator = "ver"
)

// PcaCapabilityClaims are the PCActn fields carried as selectively disclosable claims by default (claim name == field name).
var PcaCapabilityClaims = []string{"action", "grant_ref", "cap_chain", "plan", "attestation", "provenance", "freshness", "counter", "risk_claim",
	"nonce", "caution", "rationale_commitment", "progress_step", "prohibition_evidence", "tool_binding", "alg", "pq_pk", "sig", "pq_sig",
	"threshold", "zk_compliance", "bond_ref"}

var (
	sdjwtStandardMapped = map[string]bool{"aud": true, "iat": true, "exp": true}
	sdjwtCritical       = map[string]bool{"iss": true, "aud": true, "exp": true, "nbf": true, "cnf": true, "status": true}
	sdjwtReserved       = map[string]bool{"iss": true, "sub": true, "aud": true, "iat": true, "exp": true, "_sd": true, "_sd_alg": true, "cnf": true}
)

// sdjwtHash is base64url(SHA-256(ASCII(s))): Node's "ascii" encoding keeps the low byte of each UTF-16 unit.
func sdjwtHash(s string) string {
	units := utf16Units(s)
	b := make([]byte, len(units))
	for i, u := range units {
		b[i] = byte(u)
	}
	d := sha256.Sum256(b)
	return base64.RawURLEncoding.EncodeToString(d[:])
}

// Ed25519PublicJwk is the {kty: OKP, crv: Ed25519, x} JWK of a raw 32-byte Ed25519 public key.
func Ed25519PublicJwk(raw []byte) (map[string]any, error) {
	if len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("pca-sdjwt: Ed25519 public key must be 32 bytes")
	}
	return map[string]any{"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(raw)}, nil
}

// ImportEd25519PrivateKey turns a raw 32-byte Ed25519 seed (the PCA secret key) into a signing key.
func ImportEd25519PrivateKey(seed []byte) (ed25519.PrivateKey, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("pca-sdjwt: Ed25519 private seed must be 32 bytes")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// ImportEd25519PublicKey turns a raw 32-byte Ed25519 public key into a verification key.
func ImportEd25519PublicKey(raw []byte) (*JOSEKey, error) {
	if len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("pca-sdjwt: Ed25519 public key must be 32 bytes")
	}
	return &JOSEKey{Kty: "OKP", Crv: "Ed25519", Ed25519: ed25519.PublicKey(append([]byte(nil), raw...))}, nil
}

// SdJwtKeyBindingEmbed: HolderPublicKey is a JWK map, a raw 32-byte Ed25519 key, or nil for the chain's leaf holder.
type SdJwtKeyBindingEmbed struct{ HolderPublicKey any }

// SdJwtIssueOptions: IssuerSeed is the issuer's Ed25519 seed; Disclosable nil = PcaCapabilityClaims (a capability claim not
// listed is emitted in the clear); KeyBinding embeds `cnf`; Iss / Sub / Typ / SigningAlg override the defaults.
type SdJwtIssueOptions struct {
	IssuerSeed                []byte
	Disclosable               []string
	KeyBinding                *SdJwtKeyBindingEmbed
	Iss, Sub, Typ, SigningAlg *string
}

func sdjwtMs(v any, label string, round func(float64) float64) (float64, error) {
	f, ok := jsNum(v)
	if !ok || math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, fmt.Errorf("pca-sdjwt: PCActn.%s must be a finite number (epoch ms)", label)
	}
	return round(f / 1000), nil
}

func sdjwtSalt() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func sdjwtSignEdDSA(header, payload rawJSON, seed []byte, alg string) (string, error) {
	if alg != "EdDSA" {
		return "", fmt.Errorf("pca-sdjwt: alg %q does not fit an Ed25519 key", alg)
	}
	return SignCompactEdDSA(header, payload, seed)
}

// IssuePcaSdJwt serializes a signed PCActn as `<issuer JWT>~<Disclosure>~...~` (no KB-JWT at issuance).
func IssuePcaSdJwt(pc map[string]any, o SdJwtIssueOptions) (string, error) {
	if pc == nil {
		return "", errors.New("pca-sdjwt: pcActn must be an object")
	}
	chain, _ := pc["cap_chain"].([]any)
	if len(chain) == 0 {
		return "", errors.New("pca-sdjwt: pcActn.cap_chain must be a non-empty array")
	}
	root, _ := chain[0].(map[string]any)
	rootIss, ok := root["issuer"].(string)
	if !ok {
		return "", errors.New("pca-sdjwt: cap_chain root issuer is missing")
	}
	leaf, _ := chain[len(chain)-1].(map[string]any)
	leafHolder, ok := leaf["holder"].(string)
	if !ok {
		return "", errors.New("pca-sdjwt: cap_chain leaf holder is missing")
	}
	if a, _ := pc["aud"].(string); a == "" {
		return "", errors.New("pca-sdjwt: pcActn.aud is required")
	}
	iss, sub := rootIss, leafHolder
	if o.Iss != nil {
		iss = *o.Iss
	}
	if o.Sub != nil {
		sub = *o.Sub
	}
	iat, err := sdjwtMs(pc["iat"], "iat", math.Floor)
	if err != nil {
		return "", err
	}
	exp, err := sdjwtMs(pc["exp"], "exp", math.Ceil)
	if err != nil {
		return "", err
	}
	if exp <= iat {
		exp = iat + 1
	}
	disclosable := map[string]bool{}
	list := o.Disclosable
	if list == nil {
		list = PcaCapabilityClaims
	}
	for _, k := range list {
		disclosable[k] = true
	}
	payload := map[string]any{"iss": iss, "sub": sub, "aud": pc["aud"], "iat": jsNumber(iat), "exp": jsNumber(exp), "iat_ms": pc["iat"], "exp_ms": pc["exp"], "_sd_alg": SdJwtSdAlg}
	if v, has := pc[sdjwtClearDiscriminator]; has {
		payload[sdjwtClearDiscriminator] = v
	}
	var disclosures, sd []any
	keys := make([]string, 0, len(pc))
	for k := range pc {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if sdjwtStandardMapped[k] || k == sdjwtClearDiscriminator {
			continue
		}
		if !disclosable[k] {
			payload[k] = pc[k]
			continue
		}
		j, ok := canonicalLenient([]any{sdjwtSalt(), k, pc[k]})
		if !ok {
			return "", fmt.Errorf("pca-sdjwt: claim %q is not JSON-serializable", k)
		}
		enc := base64.RawURLEncoding.EncodeToString([]byte(wellFormedUTF8(j)))
		disclosures = append(disclosures, enc)
		sd = append(sd, sdjwtHash(enc))
	}
	if len(sd) > 0 {
		payload["_sd"] = sd
	}
	if o.KeyBinding != nil {
		jwk, err := sdjwtCnfJwk(leafHolder, o.KeyBinding.HolderPublicKey)
		if err != nil {
			return "", err
		}
		payload["cnf"] = map[string]any{"jwk": jwk}
	}
	alg, typ := SdJwtDefaultSigningAlg, PcaSdJwtTyp
	if o.SigningAlg != nil {
		alg = *o.SigningAlg
	}
	if o.Typ != nil {
		typ = *o.Typ
	}
	pj, ok := canonicalLenient(payload)
	if !ok {
		return "", errors.New("pca-sdjwt: payload is not JSON-serializable")
	}
	hj, err := jsonObject("alg", alg, "typ", typ)
	if err != nil {
		return "", err
	}
	jwt, err := sdjwtSignEdDSA(hj, rawJSON(wellFormedUTF8(pj)), o.IssuerSeed, alg)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString(jwt + "~")
	for _, d := range disclosures {
		b.WriteString(d.(string) + "~")
	}
	return b.String(), nil
}

func sdjwtCnfJwk(leafHolder string, hp any) (map[string]any, error) {
	switch k := hp.(type) {
	case nil:
		if leafHolder == "" {
			return nil, errors.New("pca-sdjwt: cannot derive holder key — cap_chain leaf holder is missing")
		}
		return Ed25519PublicJwk(nodeBase64Lenient(leafHolder))
	case []byte:
		return Ed25519PublicJwk(k)
	case map[string]any:
		if _, ok := k["kty"].(string); ok {
			return k, nil
		}
	}
	return nil, errors.New("pca-sdjwt: keyBinding.holderPublicKey must be a JWK or a raw Ed25519 public key")
}

// ---- parsing ----

type sdjwtParsed struct {
	jwt         string
	disclosures []string
	kbJwt       string
	head        string
	payload     map[string]any
}

func sdjwtParse(sdjwt string) (*sdjwtParsed, error) {
	if sdjwt == "" {
		return nil, errors.New("pca-sdjwt: empty SD-JWT")
	}
	segs := strings.Split(sdjwt, "~")
	if len(segs) < 2 {
		return nil, errors.New("pca-sdjwt: malformed SD-JWT (missing ~ separator)")
	}
	p := &sdjwtParsed{jwt: segs[0], disclosures: segs[1 : len(segs)-1]}
	if p.jwt == "" {
		return nil, errors.New("pca-sdjwt: empty issuer JWT")
	}
	for _, d := range p.disclosures {
		if d == "" {
			return nil, errors.New("pca-sdjwt: empty disclosure segment")
		}
	}
	cj, err := AssertCanonicalCompactJWS(p.jwt, 3, 0, true)
	if err != nil {
		return nil, err
	}
	p.payload = cj.Payload
	last := segs[len(segs)-1]
	if last == "" {
		p.head = sdjwt
		return p, nil
	}
	if _, err := AssertCanonicalCompactJWS(last, 3, 0, true); err != nil {
		return nil, err
	}
	p.kbJwt, p.head = last, sdjwt[:len(sdjwt)-len(last)]
	return p, nil
}

func sdjwtDisclosureParts(enc string) ([]any, error) {
	raw, err := decodeCanonicalBase64url(enc)
	var v any
	if err == nil {
		v, err = jwsJSONSegment(raw)
	}
	if err != nil {
		return nil, errors.New("pca-sdjwt: disclosure is not canonical base64url strict JSON")
	}
	parts, ok := v.([]any)
	if !ok || (len(parts) != 2 && len(parts) != 3) {
		return nil, errors.New("pca-sdjwt: disclosure must be a [salt, name, value] triple or a [salt, value] pair")
	}
	if _, ok := parts[0].(string); !ok {
		return nil, errors.New("pca-sdjwt: disclosure salt must be a string")
	}
	return parts, nil
}

func sdjwtKeys(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// sdjwtCollectDigests lists every digest referenced by `_sd` arrays or `{"...": digest}` entries inside node.
func sdjwtCollectDigests(node any, out *[]string) {
	switch n := node.(type) {
	case []any:
		for _, x := range n {
			sdjwtCollectDigests(x, out)
		}
	case map[string]any:
		for _, k := range sdjwtKeys(n) {
			v := n[k]
			if l, ok := v.([]any); ok && k == "_sd" {
				for _, x := range l {
					if s, ok := x.(string); ok {
						*out = append(*out, s)
					}
				}
			} else if s, ok := v.(string); ok && k == "..." {
				*out = append(*out, s)
			} else {
				sdjwtCollectDigests(v, out)
			}
		}
	}
}

// SdJwtPresentKeyBinding signs a KB-JWT over the presentation: HolderSeed is the holder's Ed25519 seed; Iat nil = now; Alg nil
// = EdDSA.
type SdJwtPresentKeyBinding struct {
	HolderSeed      []byte
	Audience, Nonce *string
	Iat             *float64
	Alg             *string
}

// PresentSdJwt discloses only the Disclosures of selectClaims (each with everything nested in its value), drops the rest and
// any KB-JWT, and with kb appends a fresh KB-JWT over the new presentation.
func PresentSdJwt(sdjwt string, selectClaims []string, kb *SdJwtPresentKeyBinding) (string, error) {
	if kb == nil {
		return sdjwtPresent(sdjwt, selectClaims, nil)
	}
	r := &sdjwtKbClaims{seed: kb.HolderSeed, alg: SdJwtDefaultSigningAlg}
	if kb.Alg != nil {
		r.alg = *kb.Alg
	}
	if kb.Iat != nil {
		r.iat = jsNumber(*kb.Iat)
	}
	if kb.Audience != nil {
		r.aud, r.hasAud = *kb.Audience, true
	}
	if kb.Nonce != nil {
		r.nonce, r.hasNonce = *kb.Nonce, true
	}
	return sdjwtPresent(sdjwt, selectClaims, r)
}

// sdjwtKbClaims are the KB-JWT inputs as JSON values (iat nil = now; aud / nonce only when present).
type sdjwtKbClaims struct {
	seed             []byte
	alg              string
	iat, aud, nonce  any
	hasAud, hasNonce bool
}

func sdjwtPresent(sdjwt string, selectClaims []string, kb *sdjwtKbClaims) (string, error) {
	p, err := sdjwtParse(sdjwt)
	if err != nil {
		return "", err
	}
	keep := map[string]bool{}
	for _, s := range selectClaims {
		keep[s] = true
	}
	byDigest := map[string]string{}
	for _, e := range p.disclosures {
		byDigest[sdjwtHash(e)] = e
	}
	kept := map[string]bool{}
	var include func(d string) error
	include = func(d string) error {
		enc, has := byDigest[d]
		if !has || kept[d] {
			return nil
		}
		kept[d] = true
		parts, err := sdjwtDisclosureParts(enc)
		if err != nil {
			return err
		}
		var ds []string
		sdjwtCollectDigests(parts[len(parts)-1], &ds)
		for _, x := range ds {
			if err := include(x); err != nil {
				return err
			}
		}
		return nil
	}
	sd, _ := p.payload["_sd"].([]any)
	for _, x := range sd {
		d, ok := x.(string)
		if !ok {
			continue
		}
		enc, has := byDigest[d]
		if !has {
			continue
		}
		parts, err := sdjwtDisclosureParts(enc)
		if err != nil {
			return "", err
		}
		if name, ok := parts[1].(string); ok && len(parts) == 3 && keep[name] {
			if err := include(d); err != nil {
				return "", err
			}
		}
	}
	for _, k := range sdjwtKeys(p.payload) {
		if k == "_sd" || !keep[k] {
			continue
		}
		var ds []string
		sdjwtCollectDigests(p.payload[k], &ds)
		for _, d := range ds {
			if err := include(d); err != nil {
				return "", err
			}
		}
	}
	parts := []string{p.jwt}
	for _, e := range p.disclosures {
		if kept[sdjwtHash(e)] {
			parts = append(parts, e)
		}
	}
	head := strings.Join(parts, "~") + "~"
	if kb == nil {
		return head, nil
	}
	iat := kb.iat
	if iat == nil {
		iat = jsNumber(math.Floor(float64(time.Now().UnixMilli()) / 1000))
	}
	kv := []any{"iat", iat}
	if kb.hasAud {
		kv = append(kv, "aud", kb.aud)
	}
	kv = append(kv, "sd_hash", sdjwtHash(head))
	if kb.hasNonce {
		kv = append(kv, "nonce", kb.nonce)
	}
	pl, err := jsonObject(kv...)
	if err != nil {
		return "", err
	}
	hj, err := jsonObject("alg", kb.alg, "typ", SdJwtKbTyp)
	if err != nil {
		return "", err
	}
	kbJwt, err := sdjwtSignEdDSA(hj, pl, kb.seed, kb.alg)
	if err != nil {
		return "", err
	}
	return head + kbJwt, nil
}

// ---- verification ----

// SdJwtVerifyOptions. ExpectedAudience: nil = no check; [""] = an `aud` must be present but any value passes (the reference's
// falsy audience); otherwise `aud` must name one of them (on the issuer JWT and, unless ExpectedKbAudience is set, the KB-JWT).
// KeyBindingKey (a JWK map, raw Ed25519 bytes or a *JOSEKey) requires a KB-JWT bound to that cnf key. Algorithms / KbAlgorithms
// nil = [EdDSA]. NowMs nil = the wall clock; KbMaxAgeSec bounds the KB-JWT iat; ClockToleranceSec must be finite and >= 0.
type SdJwtVerifyOptions struct {
	IssuerKey                             *JOSEKey
	RequiredDisclosures                   []string
	ExpectedAudience, ExpectedKbAudience  []string
	KeyBindingKey                         any
	ExpectedNonce                         *string
	RequireKeyBinding                     bool
	Algorithms, KbAlgorithms              []string
	NowMs, KbMaxAgeSec, ClockToleranceSec *float64
}

// SdJwtKeyBindingResult is the key-binding outcome.
type SdJwtKeyBindingResult struct {
	Presented bool    `json:"presented"`
	Verified  bool    `json:"verified"`
	Aud       *string `json:"aud,omitempty"`
	Nonce     *string `json:"nonce,omitempty"`
}

// SdJwtVerifyResult is {ok: true, payload, processed, protectedHeader, disclosed, claims, keyBinding} or {ok: false, reason}.
type SdJwtVerifyResult struct {
	OK                                                     bool
	Reason                                                 string
	Payload, Processed, ProtectedHeader, Disclosed, Claims map[string]any
	KeyBinding                                             SdJwtKeyBindingResult
}

func (r SdJwtVerifyResult) MarshalJSON() ([]byte, error) {
	if !r.OK {
		return json.Marshal(map[string]any{"ok": false, "reason": r.Reason})
	}
	return json.Marshal(map[string]any{"ok": true, "payload": r.Payload, "processed": r.Processed, "protectedHeader": r.ProtectedHeader,
		"disclosed": r.Disclosed, "claims": r.Claims, "keyBinding": r.KeyBinding})
}

type sdjwtDisclosure struct {
	parts []any
	used  bool
}

type sdjwtProcErr struct{ msg string }

func (e *sdjwtProcErr) Error() string { return e.msg }

func sdjwtProcess(payload map[string]any, byDigest map[string]*sdjwtDisclosure) (map[string]any, map[string]any, error) {
	seen := map[string]bool{}
	disclosedTop := map[string]any{}
	claim := func(d string) (*sdjwtDisclosure, error) {
		if seen[d] {
			return nil, &sdjwtProcErr{"a digest appears more than once in the payload"}
		}
		seen[d] = true
		return byDigest[d], nil
	}
	var walk func(node any, top bool) (any, error)
	walk = func(node any, top bool) (any, error) {
		switch n := node.(type) {
		case []any:
			out := []any{}
			for _, el := range n {
				if m, ok := el.(map[string]any); ok && len(m) == 1 && hasKey(m, "...") {
					digest, ok := m["..."].(string)
					if !ok {
						return nil, &sdjwtProcErr{"an array '...' entry must reference a string digest"}
					}
					d, err := claim(digest)
					if err != nil {
						return nil, err
					}
					if d == nil {
						continue
					}
					if len(d.parts) != 2 {
						return nil, &sdjwtProcErr{"an array-element disclosure must be [salt, value]"}
					}
					d.used = true
					v, err := walk(d.parts[1], false)
					if err != nil {
						return nil, err
					}
					out = append(out, v)
					continue
				}
				v, err := walk(el, false)
				if err != nil {
					return nil, err
				}
				out = append(out, v)
			}
			return out, nil
		case map[string]any:
			out := map[string]any{}
			for _, k := range sdjwtKeys(n) {
				if k == "_sd" {
					continue
				}
				v, err := walk(n[k], false)
				if err != nil {
					return nil, err
				}
				out[k] = v
			}
			sdv, has := n["_sd"]
			if !has {
				return out, nil
			}
			list, ok := sdv.([]any)
			if ok {
				for _, x := range list {
					if _, s := x.(string); !s {
						ok = false
					}
				}
			}
			if !ok {
				return nil, &sdjwtProcErr{"_sd must be an array of strings"}
			}
			for _, x := range list {
				d, err := claim(x.(string))
				if err != nil {
					return nil, err
				}
				if d == nil {
					continue
				}
				if len(d.parts) != 3 {
					return nil, &sdjwtProcErr{"an object-property disclosure must be [salt, name, value]"}
				}
				name, ok := d.parts[1].(string)
				if !ok {
					return nil, &sdjwtProcErr{"disclosure claim name must be a string"}
				}
				if name == "_sd" || name == "..." {
					return nil, &sdjwtProcErr{fmt.Sprintf("disclosure claim name '%s' is reserved", name)}
				}
				if _, dup := out[name]; dup {
					return nil, &sdjwtProcErr{fmt.Sprintf("disclosure claim '%s' collides with an existing claim", name)}
				}
				if top && sdjwtCritical[name] {
					return nil, &sdjwtProcErr{fmt.Sprintf("'%s' is security-critical and must not be selectively disclosable", name)}
				}
				d.used = true
				v, err := walk(d.parts[2], false)
				if err != nil {
					return nil, err
				}
				out[name] = v
				if top {
					disclosedTop[name] = v
				}
			}
			return out, nil
		}
		return node, nil
	}
	pv, err := walk(payload, true)
	if err != nil {
		return nil, nil, err
	}
	processed := pv.(map[string]any)
	delete(processed, "_sd_alg")
	for _, d := range byDigest {
		if !d.used {
			return nil, nil, &sdjwtProcErr{"a presented disclosure is not referenced by any digest in the payload"}
		}
	}
	return processed, disclosedTop, nil
}

// sdjwtThumbX is the `x` member a key-binding key carries (undefined: ok false).
func sdjwtThumbX(k any) (string, bool, error) {
	switch v := k.(type) {
	case []byte:
		return base64.RawURLEncoding.EncodeToString(v), true, nil
	case map[string]any:
		if _, ok := v["kty"].(string); ok {
			x, ok := v["x"].(string)
			return x, ok, nil
		}
		return "", false, errors.New("key is not a JWK")
	case *JOSEKey:
		switch {
		case v == nil:
		case v.Ed25519 != nil:
			return base64.RawURLEncoding.EncodeToString(v.Ed25519), true, nil
		case v.Ed448 != nil:
			return base64.RawURLEncoding.EncodeToString(v.Ed448), true, nil
		case v.EC != nil:
			n := (v.EC.Curve.Params().BitSize + 7) / 8
			return base64.RawURLEncoding.EncodeToString(v.EC.X.FillBytes(make([]byte, n))), true, nil
		}
		return "", false, nil
	}
	return "", false, nil
}

// sdjwtPublicPart drops a JWK's private members (the verifier only needs the public key).
func sdjwtPublicPart(jwk map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range jwk {
		out[k] = v
	}
	for _, m := range jwkPrivateMembers {
		if m != "k" {
			delete(out, m)
		}
	}
	return out
}

func sdjwtJoseOpts(algs []string, aud []string, o SdJwtVerifyOptions) JWTVerifyOptions {
	jo := JWTVerifyOptions{Algorithms: algs}
	if algs == nil {
		jo.Algorithms = []string{SdJwtDefaultSigningAlg}
	}
	if aud != nil {
		if len(aud) == 1 && aud[0] == "" {
			jo.Audience, jo.AudienceAny = []string{""}, true
		} else {
			jo.Audience = aud
		}
	}
	if o.NowMs != nil {
		n := math.Floor(*o.NowMs / 1000)
		jo.NowSec = &n
	}
	if o.ClockToleranceSec != nil {
		jo.ClockTolerance = *o.ClockToleranceSec
	}
	return jo
}

// VerifyPcaSdJwt verifies a PCA SD-JWT, fail-closed: issuer signature and claims, `_sd_alg`, every Disclosure referenced exactly
// once (no reserved, colliding or security-critical names), required disclosures, and the KB-JWT when presented or required.
func VerifyPcaSdJwt(sdjwt string, o SdJwtVerifyOptions) SdJwtVerifyResult {
	fail := func(r string) SdJwtVerifyResult { return SdJwtVerifyResult{Reason: r} }
	if o.NowMs != nil && (math.IsNaN(*o.NowMs) || math.IsInf(*o.NowMs, 0)) {
		return fail("pca-sdjwt: now must be a finite epoch-ms clock")
	}
	if t := o.ClockToleranceSec; t != nil && (math.IsNaN(*t) || math.IsInf(*t, 0) || *t < 0) {
		return fail("Invalid clockTolerance option type")
	}
	p, err := sdjwtParse(sdjwt)
	if err != nil {
		return fail(err.Error())
	}
	if o.IssuerKey == nil {
		return fail("pca-sdjwt: issuerKey is required")
	}
	header, payload, err := JWTVerify(p.jwt, func(map[string]any) (*JOSEKey, error) { return o.IssuerKey, nil },
		sdjwtJoseOpts(o.Algorithms, o.ExpectedAudience, o), float64(time.Now().Unix()))
	if err != nil {
		return fail(err.Error())
	}
	if a, has := payload["_sd_alg"]; has && a != SdJwtSdAlg {
		return fail(`unsupported _sd_alg (require "sha-256")`)
	}
	byDigest := map[string]*sdjwtDisclosure{}
	for _, enc := range p.disclosures {
		d := sdjwtHash(enc)
		if byDigest[d] != nil {
			return fail("duplicate disclosure")
		}
		parts, err := sdjwtDisclosureParts(enc)
		if err != nil {
			return fail(err.Error())
		}
		byDigest[d] = &sdjwtDisclosure{parts: parts}
	}
	processed, disclosed, err := sdjwtProcess(payload, byDigest)
	if err != nil {
		if strings.Contains(err.Error(), "not referenced") {
			return fail("a presented disclosure does not match any _sd digest (tampered)")
		}
		return fail(err.Error())
	}
	for _, r := range o.RequiredDisclosures {
		if _, has := disclosed[r]; !has {
			return fail(fmt.Sprintf("required disclosure '%s' was not presented", r))
		}
	}
	var cnfJwk map[string]any
	if cnf, ok := payload["cnf"].(map[string]any); ok {
		if j, ok := cnf["jwk"].(map[string]any); ok {
			if _, ok := j["kty"].(string); ok {
				cnfJwk = j
			}
		}
	}
	kbr := SdJwtKeyBindingResult{Presented: p.kbJwt != ""}
	if p.kbJwt != "" {
		if cnfJwk == nil {
			return fail("KB-JWT presented but issuer JWT has no cnf key")
		}
		if o.KeyBindingKey != nil {
			want, wok, err := sdjwtThumbX(o.KeyBindingKey)
			if err != nil {
				return fail(err.Error())
			}
			have, hok, _ := sdjwtThumbX(cnfJwk)
			if !wok || !hok || want != have {
				return fail("cnf key does not match the expected keyBindingKey")
			}
		}
		kbKey, kerr := ImportPublicJWK(sdjwtPublicPart(cnfJwk))
		if kerr != nil && (cnfJwk["kty"] == "OKP" || cnfJwk["kty"] == "EC") {
			return fail(kerr.Error()) // an OKP / EC key is validated at import, before the KB-JWT is looked at
		}
		kbAud := o.ExpectedKbAudience
		if kbAud == nil {
			kbAud = o.ExpectedAudience
		}
		kh, kp, err := JWTVerify(p.kbJwt, func(map[string]any) (*JOSEKey, error) { return kbKey, kerr }, sdjwtJoseOpts(o.KbAlgorithms, kbAud, o), float64(time.Now().Unix()))
		if err != nil {
			return fail("KB-JWT signature/claims invalid: " + err.Error())
		}
		if kh["typ"] != SdJwtKbTyp {
			return fail(`KB-JWT typ must be "kb+jwt"`)
		}
		kiat, ok := jsNum(kp["iat"])
		if !ok {
			return fail("KB-JWT iat is required")
		}
		if o.KbMaxAgeSec != nil {
			nowMs := float64(time.Now().UnixMilli())
			if o.NowMs != nil {
				nowMs = *o.NowMs
			}
			nowSec := math.Floor(nowMs / 1000)
			tol := 0.0
			if o.ClockToleranceSec != nil {
				tol = *o.ClockToleranceSec
			}
			if !(finite(nowSec) && finite(kiat) && nowSec-kiat <= *o.KbMaxAgeSec) {
				return fail("KB-JWT is older than the accepted window")
			}
			if !(finite(nowSec) && finite(kiat) && kiat-nowSec <= tol) {
				return fail("KB-JWT iat is in the future")
			}
		}
		aud, audStr := kp["aud"].(string)
		if _, arr := kp["aud"].([]any); !audStr && !arr {
			return fail("KB-JWT aud is required")
		}
		if kp["sd_hash"] != sdjwtHash(p.head) {
			return fail("KB-JWT sd_hash does not cover this presentation")
		}
		if o.ExpectedNonce != nil {
			if n, ok := kp["nonce"].(string); !ok || n != *o.ExpectedNonce {
				return fail("KB-JWT nonce does not match")
			}
		}
		kbr.Verified = true
		if audStr {
			kbr.Aud = &aud
		}
		if n, ok := kp["nonce"].(string); ok {
			kbr.Nonce = &n
		}
	} else if o.KeyBindingKey != nil || o.RequireKeyBinding {
		return fail("key binding required but no KB-JWT was presented")
	}
	claims := map[string]any{}
	for k, v := range processed {
		if !sdjwtReserved[k] {
			claims[k] = v
		}
	}
	return SdJwtVerifyResult{OK: true, Payload: payload, Processed: processed, ProtectedHeader: header, Disclosed: disclosed, Claims: claims, KeyBinding: kbr}
}

// VerifySdJwtRecovered rebuilds the PCActn from a verified SD-JWT's claims and runs the core verifier on it (the JWT layer
// alone does not check the chain, plan or sig). A withheld required claim, inconsistent iat_ms / exp_ms or an iss / sub that
// disagrees with the chain denies.
func VerifySdJwtRecovered(res SdJwtVerifyResult, grant map[string]any, nowMs int64, audience string, opts VerifyOptions) Verdict {
	deny := func(r string) Verdict { return Verdict{Allow: false, Checks: map[string]bool{}, Reason: r} }
	c, p := res.Claims, res.Processed
	iatMs, ok1 := jsNum(c["iat_ms"])
	expMs, ok2 := jsNum(c["exp_ms"])
	if !ok1 || !ok2 {
		return deny("pca-sdjwt: iat_ms/exp_ms missing; cannot rebuild the PCActn")
	}
	if pi, ok := jsNum(p["iat"]); !ok || math.Floor(iatMs/1000) != pi {
		return deny("pca-sdjwt: iat_ms disagrees with iat")
	}
	if pe, ok := jsNum(p["exp"]); !ok || math.Max(math.Ceil(expMs/1000), math.Floor(iatMs/1000)+1) != pe {
		return deny("pca-sdjwt: exp_ms disagrees with exp")
	}
	rest := map[string]any{}
	for k, v := range c {
		if k != "iat_ms" && k != "exp_ms" {
			rest[k] = v
		}
	}
	for _, k := range []string{"action", "cap_chain", "plan", "sig", "grant_ref", "counter"} {
		if _, has := rest[k]; !has {
			return deny(fmt.Sprintf("pca-sdjwt: required claim '%s' was not disclosed", k))
		}
	}
	aud, ok := p["aud"].(string)
	if !ok {
		return deny("pca-sdjwt: aud must be a string")
	}
	chain, _ := rest["cap_chain"].([]any)
	if len(chain) == 0 {
		return deny("pca-sdjwt: cap_chain is empty")
	}
	root, _ := chain[0].(map[string]any)
	leaf, _ := chain[len(chain)-1].(map[string]any)
	if !sdjwtSame(p, "iss", root, "issuer") {
		return deny("pca-sdjwt: iss does not match the chain root issuer")
	}
	if !sdjwtSame(p, "sub", leaf, "holder") {
		return deny("pca-sdjwt: sub does not match the chain leaf holder")
	}
	rest["aud"], rest["iat"], rest["exp"] = aud, c["iat_ms"], c["exp_ms"]
	if v, has := p["ver"]; has {
		rest["ver"] = v
	} else {
		delete(rest, "ver")
	}
	v, err := VerifyPCActnCoreWith(rest, grant, nowMs, audience, opts)
	if err != nil {
		return deny("pca-sdjwt: core verification threw: " + err.Error())
	}
	return v
}

// sdjwtSame is a[ka] === b[kb] over JSON values (an absent member is undefined; a nil map has none).
func sdjwtSame(a map[string]any, ka string, b map[string]any, kb string) bool {
	va, ha := a[ka]
	vb, hb := b[kb]
	if !ha || !hb {
		return ha == hb
	}
	switch x := va.(type) {
	case string:
		y, ok := vb.(string)
		return ok && x == y
	case bool:
		y, ok := vb.(bool)
		return ok && x == y
	case nil:
		return vb == nil
	}
	if fa, ok := jsNum(va); ok {
		fb, ok := jsNum(vb)
		return ok && fa == fb
	}
	return false // objects compare by identity in the reference: two decoded values are never ===
}
