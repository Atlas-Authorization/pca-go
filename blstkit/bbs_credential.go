package blstkit

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"strings"

	pca "github.com/Atlas-Authorization/pca-go"
)

// A PCA capability as a multi-message BBS credential, presented with selective disclosure and unlinkable proofs. The message
// vector is: index 0 = iss (issuer key), 1 = sub (holder key), 2.. = one message per caveat, named cav:<i>:<type>, whose
// value is the strict-canonical JSON of the caveat. Each message's octets are utf8(name) || 0x00 || utf8(value).
// Credentials and presentations are generic JSON values (map[string]any), so hostile shapes are refused, never trusted.

// encodeAttribute is the deterministic message octets of one attribute; the NUL separator must be unambiguous.
func encodeAttribute(name, value string) ([]byte, error) {
	if strings.ContainsRune(name, 0) {
		return nil, errors.New("attribute name must not contain NUL")
	}
	return append(append(textEncode(name), 0), textEncode(value)...), nil
}

// textEncode is TextEncoder.encode: each lone surrogate (kept as its 3-byte WTF-8 form by the lenient JSON parser) becomes U+FFFD.
func textEncode(s string) []byte {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == 0xED && i+2 < len(s) && s[i+1] >= 0xA0 && s[i+1] <= 0xBF {
			out = append(out, 0xEF, 0xBF, 0xBD)
			i += 2
			continue
		}
		out = append(out, s[i])
	}
	return out
}

type bbsAttr struct {
	index       int
	name, value string
}

// attrOf reads one {index, name, value} attribute; false for any other shape (non-string name or value, non-integer index).
func attrOf(v any) (bbsAttr, bool) {
	m, ok := v.(map[string]any)
	if !ok {
		return bbsAttr{}, false
	}
	name, ok1 := m["name"].(string)
	value, ok2 := m["value"].(string)
	n, ok3 := m["index"].(json.Number)
	if !ok1 || !ok2 || !ok3 {
		return bbsAttr{}, false
	}
	i, err := strconv.Atoi(n.String())
	if err != nil {
		return bbsAttr{}, false
	}
	return bbsAttr{i, name, value}, true
}

func attrsOf(v any) ([]bbsAttr, bool) {
	l, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]bbsAttr, len(l))
	for i, a := range l {
		if out[i], ok = attrOf(a); !ok {
			return nil, false
		}
	}
	return out, true
}

func attrJSON(a bbsAttr) map[string]any {
	return map[string]any{"index": json.Number(strconv.Itoa(a.index)), "name": a.name, "value": a.value}
}

func encodeAll(attrs []bbsAttr) ([][]byte, error) {
	out := make([][]byte, len(attrs))
	for i, a := range attrs {
		b, err := encodeAttribute(a.name, a.value)
		if err != nil {
			return nil, err
		}
		out[i] = b
	}
	return out, nil
}

// BbsCapabilityAttributes builds the ordered attribute vector for a capability {issuer, holder, caveats}.
func BbsCapabilityAttributes(capability map[string]any) ([]any, error) {
	issuer, ok1 := capability["issuer"].(string)
	holder, ok2 := capability["holder"].(string)
	if !ok1 || !ok2 {
		return nil, errors.New("capability issuer and holder must be strings")
	}
	out := []any{
		attrJSON(bbsAttr{0, "iss", issuer}),
		attrJSON(bbsAttr{1, "sub", holder}),
	}
	caveats, _ := capability["caveats"].([]any)
	for i, cv := range caveats {
		typ := "undefined" // a caveat without a type, as the reference stringifies it
		if m, ok := cv.(map[string]any); ok {
			if t, present := m["type"]; present {
				if typ, ok = t.(string); !ok {
					return nil, errors.New("caveat type must be a string")
				}
			}
		}
		canon, err := pca.Canonicalize(cv)
		if err != nil {
			return nil, err
		}
		out = append(out, attrJSON(bbsAttr{i + 2, fmt.Sprintf("cav:%d:%s", i, typ), canon}))
	}
	return out, nil
}

// BbsIssueCapabilityCredential signs a capability's attributes as a BBS credential. header is bound into the signature.
func BbsIssueCapabilityCredential(capability map[string]any, sk *big.Int, pk, header []byte) (map[string]any, error) {
	attrs, err := BbsCapabilityAttributes(capability)
	if err != nil {
		return nil, err
	}
	parsed, _ := attrsOf(attrs)
	msgs, err := encodeAll(parsed)
	if err != nil {
		return nil, err
	}
	sig, err := BbsSign(sk, pk, header, msgs)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"issuerPublicKey": b64u.EncodeToString(pk),
		"header":          b64u.EncodeToString(header),
		"attributes":      attrs,
		"signature":       b64u.EncodeToString(sig),
	}, nil
}

func jsonStr(m map[string]any, k string) (string, bool) { s, ok := m[k].(string); return s, ok }

// BbsVerifyCredential verifies a whole credential against its issuer key. Never panics; false on any malformed input.
func BbsVerifyCredential(cred map[string]any) bool {
	pks, ok1 := jsonStr(cred, "issuerPublicKey")
	hs, ok2 := jsonStr(cred, "header")
	ss, ok3 := jsonStr(cred, "signature")
	if !ok1 || !ok2 || !ok3 {
		return false
	}
	pk, ok1 := unb64u(pks)
	header, ok2 := unb64u(hs)
	sig, ok3 := unb64u(ss)
	attrs, ok4 := attrsOf(cred["attributes"])
	if !ok1 || !ok2 || !ok3 || !ok4 {
		return false
	}
	msgs, err := encodeAll(attrs)
	return err == nil && BbsVerify(pk, sig, header, msgs)
}

// BbsPresentOptions pins the verifier's own expectations; every field is optional (nil = take the presentation's value).
type BbsPresentOptions struct {
	PublicKey          []byte
	Disclosed          []any
	PresentationHeader []byte
}

func sameDisclosure(a, b []bbsAttr) bool {
	if len(a) != len(b) {
		return false
	}
	key := func(x bbsAttr) string { return fmt.Sprintf("%d\x00%s\x00%s", x.index, x.name, x.value) }
	ka, kb := make([]string, len(a)), make([]string, len(b))
	for i := range a {
		ka[i], kb[i] = key(a[i]), key(b[i])
	}
	sort.Strings(ka)
	sort.Strings(kb)
	for i := range ka {
		if ka[i] != kb[i] {
			return false
		}
	}
	return true
}

// BbsVerifyPresentation checks a selective-disclosure proof; opts (may be nil) asserts the verifier's own expectations
// (a pinned issuer key, the exact attributes required, the action digest the proof must be bound to).
func BbsVerifyPresentation(pres map[string]any, opts *BbsPresentOptions) bool {
	if opts == nil {
		opts = &BbsPresentOptions{}
	}
	pks, ok1 := jsonStr(pres, "issuerPublicKey")
	hs, ok2 := jsonStr(pres, "header")
	prs, ok3 := jsonStr(pres, "proof")
	if !ok1 || !ok2 || !ok3 {
		return false
	}
	pk := opts.PublicKey
	if pk == nil {
		if pk, ok1 = unb64u(pks); !ok1 {
			return false
		}
	}
	header, ok1 := unb64u(hs)
	proof, ok2 := unb64u(prs)
	if !ok1 || !ok2 {
		return false
	}
	// a pinned issuer key must be the one the presentation claims
	if opts.PublicKey != nil && b64u.EncodeToString(opts.PublicKey) != pks {
		return false
	}
	ph := opts.PresentationHeader
	phs, _ := jsonStr(pres, "presentationHeader")
	if ph == nil {
		var ok bool
		if ph, ok = unb64u(phs); !ok {
			return false
		}
	}
	if opts.PresentationHeader != nil && len(opts.PresentationHeader) > 0 && b64u.EncodeToString(ph) != phs {
		return false
	}
	shown, ok := attrsOf(pres["disclosed"])
	if !ok {
		return false
	}
	disclosed := shown
	if opts.Disclosed != nil {
		pinned, ok := attrsOf(opts.Disclosed)
		if !ok || !sameDisclosure(pinned, shown) {
			return false
		}
		disclosed = pinned
	}
	count, ok := pres["messageCount"].(json.Number)
	if !ok {
		return false
	}
	n, err := count.Int64()
	if err != nil {
		return false
	}
	sorted := append([]bbsAttr(nil), disclosed...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].index < sorted[j].index })
	msgs, err := encodeAll(sorted)
	if err != nil {
		return false
	}
	idxs := make([]int, len(sorted))
	for i, a := range sorted {
		if int64(a.index) >= n || a.index < 0 {
			return false
		}
		idxs[i] = a.index
	}
	return BbsProofVerify(pk, proof, header, ph, msgs, idxs)
}
