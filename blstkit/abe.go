package blstkit

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"math/big"
	"sort"
	"strings"

	pca "github.com/Atlas-Authorization/pca-go"
	blst "github.com/supranational/blst/bindings/go"
)

// Proof-carrying encryption: FAME ciphertext-policy ABE (fame.go) in the asymmetric BLS12-381 pairing, with the payload
// sealed under AES-256-GCM and the whole header authenticated. Keys, ciphertexts and policies are generic JSON values
// (map[string]any), parsed fail-closed: a malformed ciphertext or key is a refusal, never a panic.
//
// Honest limits (as the reference): no key revocation, the policy is public in the ciphertext, the master-key holder decrypts
// everything, and it is not post-quantum or constant time.

// AbeAlg is the ciphertext algorithm label.
const AbeAlg = "fame-cpabe-bls12381-type3/aes-256-gcm"

const (
	abeCekInfo = "atlas-pca-abe/cek/v3"
	abeSaltLen = 16
)

var abeV2 = json.Number("2")

func isV2(v any) bool { return isNum(v, 2) }

// ---- wire ------------------------------------------------------------------------------------------------------------

func abeUnb64u(x any) ([]byte, bool) {
	s, ok := x.(string)
	if !ok {
		return nil, false
	}
	return pca.DecodeB64uStrict(s, -1)
}

func abeG1FromB64(x any) (*blst.P1, bool) {
	b, ok := abeUnb64u(x)
	if !ok || len(b) != 48 || isInfEncoding(b) {
		return nil, false
	}
	p, err := strictG1(b)
	return p, err == nil
}

func abeG2FromB64(x any) (*blst.P2, bool) {
	b, ok := abeUnb64u(x)
	if !ok || len(b) != 96 || isInfEncoding(b) {
		return nil, false
	}
	p, err := strictG2(b)
	return p, err == nil
}

func triOf(x any) ([]any, bool) {
	l, ok := x.([]any)
	return l, ok && len(l) == 3
}

func readTri1(x any) (abeG1x3, bool) {
	var out abeG1x3
	l, ok := triOf(x)
	if !ok {
		return out, false
	}
	for i := range out {
		if out[i], ok = abeG1FromB64(l[i]); !ok {
			return out, false
		}
	}
	return out, true
}

func readTri2(x any) (abeG2x3, bool) {
	var out abeG2x3
	l, ok := triOf(x)
	if !ok {
		return out, false
	}
	for i := range out {
		if out[i], ok = abeG2FromB64(l[i]); !ok {
			return out, false
		}
	}
	return out, true
}

func b64s(b []byte) string { return b64u.EncodeToString(b) }

func tri1JSON(x abeG1x3) []any {
	return []any{b64s(g1Bytes(x[0])), b64s(g1Bytes(x[1])), b64s(g1Bytes(x[2]))}
}
func tri2JSON(x abeG2x3) []any {
	return []any{b64s(g2Bytes(x[0])), b64s(g2Bytes(x[1])), b64s(g2Bytes(x[2]))}
}

// ---- setup / keygen ---------------------------------------------------------------------------------------------------

// AbeSetup generates a fresh master key pair (mpk, msk) as JSON values.
func AbeSetup() (mpk, msk map[string]any, err error) {
	var s [7]*big.Int
	for i := range s {
		if s[i], err = abeRandomScalar(); err != nil {
			return nil, nil, err
		}
	}
	pk, sk, err := fameSetup([2]*big.Int{s[0], s[1]}, [2]*big.Int{s[2], s[3]}, [3]*big.Int{s[4], s[5], s[6]})
	if err != nil {
		return nil, nil, err
	}
	mpk = map[string]any{"v": abeV2, "curve": "bls12-381",
		"h": []any{b64s(g2Bytes(pk.h1)), b64s(g2Bytes(pk.h2))},
		"t": []any{b64s(pk.t1), b64s(pk.t2)}}
	msk = map[string]any{"v": abeV2, "curve": "bls12-381",
		"a": []any{b64s(scalarBE(sk.a[0])), b64s(scalarBE(sk.a[1]))},
		"b": []any{b64s(scalarBE(sk.b[0])), b64s(scalarBE(sk.b[1]))},
		"g": tri1JSON(sk.g)}
	return mpk, msk, nil
}

var errInvalidMsk = abeErr("invalid master secret key")
var errInvalidMpk = abeErr("invalid master public key")

// canonicalScalar: exactly one encoding per scalar: 32 bytes, non-zero, and < r.
func canonicalScalar(x any) (*big.Int, bool) {
	b, ok := abeUnb64u(x)
	if !ok || len(b) != 32 {
		return nil, false
	}
	n := new(big.Int).SetBytes(b)
	return n, n.Sign() != 0 && n.Cmp(BbsR) < 0
}

func parseMsk(x any) (*fameMsk, error) {
	m, ok := x.(map[string]any)
	if !ok || !isV2(m["v"]) {
		return nil, errInvalidMsk
	}
	msk := &fameMsk{}
	for k, dst := range map[string]*[2]*big.Int{"a": &msk.a, "b": &msk.b} {
		l, ok := m[k].([]any)
		if !ok || len(l) != 2 {
			return nil, errInvalidMsk
		}
		for i := range l {
			if dst[i], ok = canonicalScalar(l[i]); !ok {
				return nil, errInvalidMsk
			}
		}
	}
	var ok2 bool
	if msk.g, ok2 = readTri1(m["g"]); !ok2 {
		return nil, errInvalidMsk
	}
	return msk, nil
}

func parseMpk(x any) (*fameMpk, error) {
	m, ok := x.(map[string]any)
	if !ok || !isV2(m["v"]) {
		return nil, errInvalidMpk
	}
	h, ok1 := m["h"].([]any)
	t, ok2 := m["t"].([]any)
	if !ok1 || !ok2 || len(h) != 2 || len(t) != 2 {
		return nil, errInvalidMpk
	}
	mpk := &fameMpk{}
	var okh1, okh2 bool
	mpk.h1, okh1 = abeG2FromB64(h[0])
	mpk.h2, okh2 = abeG2FromB64(h[1])
	if !okh1 || !okh2 {
		return nil, errInvalidMpk
	}
	for i, dst := range []*[]byte{&mpk.t1, &mpk.t2} {
		b, ok := abeUnb64u(t[i])
		if !ok || !gtIsElement(b) {
			return nil, errInvalidMpk
		}
		*dst = b
	}
	return mpk, nil
}

func isEmptyOrIllFormed(a string) bool { return a == "" || isIllFormedUTF16(a) }

// abeIssue issues a decryption key for the (deduplicated, in order) attribute tokens and returns the issued names.
func abeIssue(msk any, attrs []string) (map[string]any, []string, error) {
	m, err := parseMsk(msk)
	if err != nil {
		return nil, nil, err
	}
	seen := map[string]bool{}
	var names []string
	for _, a := range attrs {
		if !seen[a] {
			seen[a] = true
			if !isEmptyOrIllFormed(a) {
				names = append(names, a)
			}
		}
	}
	var r [2]*big.Int
	var sp *big.Int
	sigmas := make([]*big.Int, len(names))
	for i := range r {
		if r[i], err = abeRandomScalar(); err != nil {
			return nil, nil, err
		}
	}
	for i := range sigmas {
		if sigmas[i], err = abeRandomScalar(); err != nil {
			return nil, nil, err
		}
	}
	if sp, err = abeRandomScalar(); err != nil {
		return nil, nil, err
	}
	key, err := fameKeygen(m, names, r, sigmas, sp)
	if err != nil {
		return nil, nil, err
	}
	am := make(map[string]any, len(names))
	for _, n := range names {
		am[n] = map[string]any{"k": tri1JSON(key.attrs[n])}
	}
	return map[string]any{"v": abeV2, "curve": "bls12-381", "k0": tri2JSON(key.k0), "kp": tri1JSON(key.kp), "attrs": am}, names, nil
}

// AbeKeygenForAttributes issues a decryption key for an explicit set of attribute tokens.
func AbeKeygenForAttributes(msk any, attrs []string) (map[string]any, error) {
	k, _, err := abeIssue(msk, attrs)
	return k, err
}

// parseKey validates an untrusted key; a malformed attribute component is treated as not held. Nil if K0, K' or the
// container is malformed.
func parseKey(x any) *fameKey {
	m, ok := x.(map[string]any)
	if !ok || !isV2(m["v"]) {
		return nil
	}
	am, ok := m["attrs"].(map[string]any)
	if !ok {
		return nil
	}
	k0, ok1 := readTri2(m["k0"])
	kp, ok2 := readTri1(m["kp"])
	if !ok1 || !ok2 {
		return nil
	}
	key := &fameKey{k0: k0, kp: kp, attrs: map[string]abeG1x3{}}
	for name, comp := range am {
		if cm, ok := comp.(map[string]any); ok {
			if k, ok := readTri1(cm["k"]); ok {
				key.attrs[name] = k
			}
		}
	}
	return key
}

// ---- encrypt ----------------------------------------------------------------------------------------------------------

type abeCt struct {
	salt, iv, ct, tag string
	ct0               [3]string
	tree              *abeTree
	rows              [][3]string
}

func (c *abeCt) aad() ([]byte, error) {
	rows := make([]any, len(c.rows))
	for i, r := range c.rows {
		rows[i] = []any{r[0], r[1], r[2]}
	}
	s, err := pca.Canonicalize(map[string]any{"v": abeV2, "alg": AbeAlg, "salt": c.salt,
		"ct0": []any{c.ct0[0], c.ct0[1], c.ct0[2]}, "tree": c.tree.toJSON(), "rows": rows})
	return []byte(s), err
}

func (c *abeCt) json() map[string]any {
	rows := make([]any, len(c.rows))
	for i, r := range c.rows {
		rows[i] = []any{r[0], r[1], r[2]}
	}
	return map[string]any{"v": abeV2, "alg": AbeAlg, "salt": c.salt, "ct0": []any{c.ct0[0], c.ct0[1], c.ct0[2]},
		"tree": c.tree.toJSON(), "rows": rows, "iv": c.iv, "ct": c.ct, "tag": c.tag}
}

// abeCek is HKDF-SHA256(ikm, salt, info) to 32 bytes (one block).
func abeCek(ikm, salt []byte) []byte {
	ext := hmac.New(sha256.New, salt)
	ext.Write(ikm)
	exp := hmac.New(sha256.New, ext.Sum(nil))
	exp.Write([]byte(abeCekInfo))
	exp.Write([]byte{1})
	return exp.Sum(nil)
}

func abeGCM(key []byte) (cipher.AEAD, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

// AbeEncryptForPolicy encrypts plaintext so that it decrypts only for a holder whose attributes satisfy policy. It errors on
// an invalid policy (including one naming an attribute twice) or master public key.
func AbeEncryptForPolicy(mpk, policy any, plaintext []byte) (map[string]any, error) {
	tree, why := abeNormalizePolicy(policy)
	if why != "" {
		return nil, abeErr("invalid policy: " + why)
	}
	if dup := tree.firstRepeatedAttribute(); dup != "" {
		q, _ := pca.Canonicalize(dup)
		return nil, abeErr("invalid policy: attribute " + q + " is named by more than one leaf (single-use attributes only)")
	}
	pk, err := parseMpk(mpk)
	if err != nil {
		return nil, err
	}
	salt := make([]byte, abeSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	var s [2]*big.Int
	for i := range s {
		if s[i], err = abeRandomScalar(); err != nil {
			return nil, err
		}
	}
	fc, k, err := fameEncrypt(pk, tree, s)
	if err != nil {
		return nil, err
	}
	c := &abeCt{salt: b64s(salt), tree: tree}
	for i, p := range fc.ct0 {
		c.ct0[i] = b64s(g2Bytes(p))
	}
	for _, r := range fc.rows {
		c.rows = append(c.rows, [3]string{b64s(g1Bytes(r[0])), b64s(g1Bytes(r[1])), b64s(g1Bytes(r[2]))})
	}
	aad, err := c.aad()
	if err != nil {
		return nil, abeErr("policy cannot be authenticated (header outside the canonical JSON profile)")
	}
	gcm, err := abeGCM(abeCek(k, salt))
	if err != nil {
		return nil, err
	}
	iv := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	sealed := gcm.Seal(nil, iv, plaintext, aad)
	cut := len(sealed) - gcm.Overhead()
	c.iv, c.ct, c.tag = b64s(iv), b64s(sealed[:cut]), b64s(sealed[cut:])
	return c.json(), nil
}

// ---- parse / decrypt --------------------------------------------------------------------------------------------------

func strTri(x any) ([3]string, bool) {
	var out [3]string
	l, ok := triOf(x)
	if !ok {
		return out, false
	}
	for i, e := range l {
		s, ok := e.(string)
		if !ok {
			return out, false
		}
		if _, ok := abeUnb64u(s); !ok {
			return out, false
		}
		out[i] = s
	}
	return out, true
}

func parseCt(x any) *abeCt {
	m, ok := x.(map[string]any)
	if !ok || !isV2(m["v"]) || m["alg"] != AbeAlg {
		return nil
	}
	c := &abeCt{}
	for _, f := range []struct {
		k string
		d *string
	}{{"salt", &c.salt}, {"iv", &c.iv}, {"ct", &c.ct}, {"tag", &c.tag}} {
		s, ok := m[f.k].(string)
		if !ok {
			return nil
		}
		if _, ok := abeUnb64u(s); !ok {
			return nil
		}
		*f.d = s
	}
	nodes := 0
	ct0, ok1 := strTri(m["ct0"])
	c.tree = abeParseTree(m["tree"], 0, &nodes)
	rows, ok2 := m["rows"].([]any)
	if !ok1 || c.tree == nil || !ok2 {
		return nil
	}
	c.ct0 = ct0
	if len(rows) != c.tree.leafCount() || c.tree.firstRepeatedAttribute() != "" {
		return nil
	}
	for _, r := range rows {
		t, ok := strTri(r)
		if !ok {
			return nil
		}
		c.rows = append(c.rows, t)
	}
	return c
}

// AbeParseCiphertext validates an untrusted value as a ciphertext; nil (fail closed) on any deviation.
func AbeParseCiphertext(x any) map[string]any {
	if c := parseCt(x); c != nil {
		return c.json()
	}
	return nil
}

// AbeDecrypt returns the plaintext iff the key's attributes satisfy the ciphertext's policy AND the AEAD authenticates;
// otherwise false. It never panics.
func AbeDecrypt(key any, ciphertext any) ([]byte, bool) {
	ct := parseCt(ciphertext)
	if ct == nil {
		return nil, false
	}
	pk := parseKey(key)
	if pk == nil {
		return nil, false
	}
	salt, _ := abeUnb64u(ct.salt)
	iv, _ := abeUnb64u(ct.iv)
	body, _ := abeUnb64u(ct.ct)
	tag, _ := abeUnb64u(ct.tag)
	fc := &fameCt{}
	var ok bool
	if fc.ct0, ok = readTri2([]any{ct.ct0[0], ct.ct0[1], ct.ct0[2]}); !ok {
		return nil, false
	}
	for _, r := range ct.rows {
		t, ok := readTri1([]any{r[0], r[1], r[2]})
		if !ok {
			return nil, false
		}
		fc.rows = append(fc.rows, t)
	}
	k, ok := fameDecrypt(pk, ct.tree, fc)
	if !ok {
		return nil, false
	}
	aad, err := ct.aad()
	if err != nil {
		return nil, false // header outside the canonical profile: cannot be authentic
	}
	gcm, err := abeGCM(abeCek(k, salt))
	if err != nil || len(iv) != gcm.NonceSize() || len(tag) != gcm.Overhead() {
		return nil, false
	}
	pt, err := gcm.Open(nil, iv, append(append([]byte(nil), body...), tag...), aad)
	if err != nil {
		return nil, false
	}
	return pt, true
}

// AbeDecryptText is AbeDecrypt with the plaintext decoded as UTF-8 text (invalid sequences replaced, a leading BOM dropped).
func AbeDecryptText(key, ciphertext any) (string, bool) {
	pt, ok := AbeDecrypt(key, ciphertext)
	if !ok {
		return "", false
	}
	return strings.ToValidUTF8(string(bytes.TrimPrefix(pt, []byte{0xEF, 0xBB, 0xBF})), "�"), true
}

// ---- capability attributes and payloads -------------------------------------------------------------------------------

// AbeCapabilityOpts parameterises AbeCapabilityAttributes.
type AbeCapabilityOpts struct {
	// HaveChain: Chain is supplied (root first, ending in the capability); required for scope/act/verb/resource tokens on a
	// delegated hop. A supplied chain that fails verification yields no attributes.
	HaveChain bool
	Chain     []any
	// Principal pins the root issuer (default: the chain's own root issuer).
	Principal *string
	// PqPins pins post-quantum authority by Ed25519 root identity.
	PqPins map[string]string
}

func jsVerbs(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []any:
		var out []string
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// abeCapAttrs derives the canonical attribute set a capability possesses, in insertion order (deterministic and total).
// scope:, act:, verb: and resource: tokens come only from the ROOT capability: a delegated hop's own caveats are
// restrictions, never grants.
func abeCapAttrs(capability map[string]any, opts AbeCapabilityOpts) []string {
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	var scopeSource any
	var envSource map[string]any
	if opts.HaveChain {
		if len(opts.Chain) == 0 {
			return nil
		}
		root, _ := opts.Chain[0].(map[string]any)
		last, _ := opts.Chain[len(opts.Chain)-1].(map[string]any)
		if root == nil || last == nil || !sameID(last["id"], capability["id"]) {
			return nil
		}
		principal, have := "", false
		if opts.Principal != nil {
			principal, have = *opts.Principal, true
		} else if s, ok := root["issuer"].(string); ok {
			principal, have = s, true
		}
		if _, ok := pca.VerifyChainPolicy(opts.Chain, principal, have, nil, opts.PqPins, nil); !ok {
			return nil
		}
		scopeSource, envSource = root["caveats"], root
	} else if _, delegated := capability["parent"]; !delegated {
		scopeSource, envSource = capability["caveats"], capability
	}
	if h, ok := capability["holder"].(string); ok && h != "" {
		add("holder:" + h)
	}
	if cavs, ok := scopeSource.([]any); ok {
		for _, c := range cavs {
			cv, ok := c.(map[string]any)
			if !ok {
				continue
			}
			if cv["type"] == "scope" {
				if v, ok := cv["value"].(string); ok {
					add("scope:" + v)
				}
			}
			if cv["type"] == "scopes" {
				if vs, ok := cv["values"].([]any); ok {
					for _, s := range vs {
						if v, ok := s.(string); ok {
							add("scope:" + v)
						}
					}
				}
			}
		}
	}
	var env map[string]any
	if envSource != nil {
		env = pca.ReadEnvelope(envSource)
	}
	if plist, ok := env["predicates"].([]any); ok {
		var preds []map[string]any // an array counts as a predicate that names no verb or resource
		for _, p := range plist {
			switch x := p.(type) {
			case map[string]any:
				preds = append(preds, x)
			case []any:
				preds = append(preds, map[string]any{})
			}
		}
		for _, p := range preds {
			if r, ok := p["resource"].(string); ok {
				for _, v := range jsVerbs(p["verb"]) {
					pair, err := pca.Canonicalize([]any{v, r})
					if err == nil {
						add("act:" + pair)
					}
				}
			}
		}
		if len(preds) == 1 {
			for _, v := range jsVerbs(preds[0]["verb"]) {
				add("verb:" + v)
			}
			if r, ok := preds[0]["resource"].(string); ok {
				add("resource:" + r)
			}
		}
	}
	return out
}

// sameID: === on identifiers; objects are never identical.
func sameID(a, b any) bool {
	switch x := a.(type) {
	case nil:
		return b == nil
	case string:
		y, ok := b.(string)
		return ok && x == y
	}
	return false
}

// AbeCapabilityAttributes is the sorted canonical attribute set a capability possesses.
func AbeCapabilityAttributes(capability map[string]any, opts AbeCapabilityOpts) []string {
	out := abeCapAttrs(capability, opts)
	sort.Strings(out)
	return out
}

// AbeKeygenForCapability issues a key bound to a capability's attributes plus any extra tokens; holder is recorded.
func AbeKeygenForCapability(msk any, capability map[string]any, extra []string, opts AbeCapabilityOpts) (map[string]any, error) {
	k, _, err := abeIssueCapability(msk, capability, extra, opts)
	return k, err
}

func abeIssueCapability(msk any, capability map[string]any, extra []string, opts AbeCapabilityOpts) (map[string]any, []string, error) {
	attrs := abeCapAttrs(capability, opts)
	for _, a := range extra {
		if a != "" {
			attrs = append(attrs, a)
		}
	}
	key, names, err := abeIssue(msk, attrs)
	if err != nil {
		return nil, nil, err
	}
	if h, ok := capability["holder"].(string); ok {
		key["holder"] = h
	}
	return key, names, nil
}

// AbeEncryptToolPayload encrypts a JSON-serialisable payload under a capability policy.
func AbeEncryptToolPayload(mpk, policy any, payload any) (map[string]any, error) {
	b, err := json.Marshal(payload) // JSON.stringify(payload ?? null)
	if err != nil {
		return nil, err
	}
	return AbeEncryptForPolicy(mpk, policy, b)
}

// AbeDecryptWithCapability decrypts a tool payload with a capability-derived key and parses it.
func AbeDecryptWithCapability(key, ciphertext any) (payload any, ok bool, reason string) {
	pt, good := AbeDecrypt(key, ciphertext)
	if !good {
		return nil, false, "capability does not satisfy the policy, or ciphertext is invalid"
	}
	v, err := pca.ParseJSONLenient(pt)
	if err != nil {
		return nil, false, "decrypted payload is not valid JSON"
	}
	return v, true, ""
}
