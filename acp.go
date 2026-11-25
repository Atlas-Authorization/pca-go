package pca

// Agentic Commerce Protocol (ACP) for PCA: delegated one-time payment tokens minted FROM a PCActn (the proof's spend cap, merchant and
// category allowlists and human-present requirement gate issuance) and their settlement-time verification. The x402 rail and the
// Stripe Shared Payment Granted Tokens live in acp_x402.go and acp_spt.go.
//
// Inputs and results are JSON values (map[string]any, []any, string, bool, nil, json.Number) shaped like the reference, so every check
// runs on the value the reference would see. No network is performed: the single-use store is injected.
// shortcut: a Go map keeps no insertion order, so where the reference's JSON.stringify output depends on the member order of a
// caller-supplied nested object (paymentMethod, an x402 extension, ...) the keys are written in a fixed order (array indexes, the
// members the reference itself emits, then code-unit order); the decoded JSON value is identical. Upgrade to an ordered object
// type if byte-identical output for arbitrary member order is ever required.

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// The ACP delegated-token and caveat vocabulary.
const (
	AcpDelegatedTokenVersion = 1
	AcpDelegatedTokenType    = "acp-delegated-payment"
	AcpSpendCapType          = "max_amount"
	AcpMerchantAllowType     = "merchant_allow"
	AcpMerchantCategoryType  = "merchant_category"
	AcpHumanPresentType      = "human_present"
)

// AcpAuthorityError: a delegated payment token cannot be minted (or an allowance cannot be built) because the request exceeds the
// proof's authority or a claim cannot be expressed.
type AcpAuthorityError struct{ Msg string }

func (e *AcpAuthorityError) Error() string { return e.Msg }

func acpAuthErr(format string, a ...any) error {
	return &AcpAuthorityError{Msg: fmt.Sprintf(format, a...)}
}

// AcpSingleUseStore is the atomic first-use claim: Claim reports true exactly once per jti (a conditional insert such as
// INSERT .. ON CONFLICT DO NOTHING, or Redis SET NX PX). A store that errs never admits a token.
type AcpSingleUseStore interface {
	Claim(jti string, expiresAtMs float64) (bool, error)
}

// ---- JavaScript value helpers -----------------------------------------------------------------------------------------

type acpUndef struct{}

// acpU is JavaScript undefined where it must stay distinct from null (nil).
var acpU any = acpUndef{}

// acpGet is `o.k`: acpU for a missing member or a non-object.
func acpGet(o any, k string) any {
	if m, ok := o.(map[string]any); ok {
		if v, has := m[k]; has {
			return v
		}
	}
	return acpU
}

func acpNullish(v any) bool { return v == nil || v == acpU }

func acpTruthy(v any) bool { return v != acpU && jsTruthy(v) }

// acpS is String(v) for a JSON value or undefined.
func acpS(v any) string {
	if v == acpU {
		return "undefined"
	}
	return jsValueString(v)
}

func acpFinite(v any) bool {
	f, ok := jsNum(v)
	return ok && !math.IsInf(f, 0) && !math.IsNaN(f)
}

// acpIsAmount: integer minor units (safe integer, strictly positive).
func acpIsAmount(v any) bool {
	f, ok := jsNum(v)
	return ok && jsIsSafeInteger(v) && f > 0
}

// acpToNumber is Number(v) (NaN for undefined).
func acpToNumber(v any) float64 {
	if v == acpU {
		return math.NaN()
	}
	return jsToNumber(v)
}

// acpGt is `a > b` for a number a and any b (ToNumber coercion, NaN compares false).
func acpGt(a float64, b any) bool {
	bn := acpToNumber(b)
	return !(finite(a) && a <= bn) // the bound may be infinite, the compared value may not
}

// acpLower is String.prototype.toLowerCase for the code points that matter here (U+0130 lowercases to two code points).
func acpLower(s string) string { return strings.ToLower(strings.ReplaceAll(s, "İ", "i̇")) }

// acpSpread is the own enumerable members JavaScript object spread copies: a map as is, an array or string by index.
func acpSpread(v any) map[string]any {
	out := map[string]any{}
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			out[k] = x
		}
	case []any:
		for i, x := range t {
			out[strconv.Itoa(i)] = x
		}
	case string:
		for i, u := range utf16Units(t) {
			out[strconv.Itoa(i)] = acpUnitString(u)
		}
	}
	return out
}

func acpUnitString(u uint16) string {
	if u >= 0xD800 && u <= 0xDFFF {
		var sb strings.Builder
		writeWTF8(&sb, rune(u))
		return sb.String()
	}
	return string(rune(u))
}

// acpUTF8 is Buffer.toString('utf8'): every invalid byte becomes U+FFFD.
// shortcut: one U+FFFD per invalid byte, not per maximal subpart; differs only inside a truncated multi-byte sequence.
func acpUTF8(b []byte) string {
	var sb strings.Builder
	for len(b) > 0 {
		r, n := utf8.DecodeRune(b)
		if r == utf8.RuneError && n == 1 {
			sb.WriteString("�")
		} else {
			sb.Write(b[:n])
		}
		b = b[n:]
	}
	return sb.String()
}

// ---- JSON.stringify and JSON.parse ------------------------------------------------------------------------------------

type acpKV struct {
	K string
	V any
}

// acpObj is an object written in the given member order (acpU members are skipped, as undefined is).
type acpObj []acpKV

var acpKeyOrder = []string{"x402Version", "error", "resource", "accepts", "accepted", "payload", "extensions", "url", "description",
	"mimeType", "serviceName", "tags", "iconUrl", "success", "errorReason", "transaction", "scheme", "network", "payer", "amount", "asset",
	"payTo", "maxTimeoutSeconds", "extra", "type", "display", "token", "info", "schema"}

var acpKeyRank = func() map[string]int {
	m := make(map[string]int, len(acpKeyOrder))
	for i, k := range acpKeyOrder {
		m[k] = i
	}
	return m
}()

func acpKeyLess(a, b string) bool {
	ia, aok := arrayIndex(a)
	ib, bok := arrayIndex(b)
	switch {
	case aok && bok:
		return ia < ib
	case aok:
		return true
	case bok:
		return false
	}
	ra, ha := acpKeyRank[a]
	rb, hb := acpKeyRank[b]
	switch {
	case ha && hb:
		return ra < rb
	case ha:
		return true
	case hb:
		return false
	}
	return compareUnits(utf16Units(a), utf16Units(b)) < 0
}

func acpKeys(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Slice(ks, func(i, j int) bool { return acpKeyLess(ks[i], ks[j]) })
	return ks
}

func acpWrite(sb *strings.Builder, v any) {
	switch t := v.(type) {
	case nil:
		sb.WriteString("null")
	case bool:
		sb.WriteString(strconv.FormatBool(t))
	case string:
		lenientString(sb, t)
	case []any:
		sb.WriteByte('[')
		for i, x := range t {
			if i > 0 {
				sb.WriteByte(',')
			}
			if x == acpU {
				sb.WriteString("null")
			} else {
				acpWrite(sb, x)
			}
		}
		sb.WriteByte(']')
	case map[string]any:
		kv := make(acpObj, 0, len(t))
		for _, k := range acpKeys(t) {
			kv = append(kv, acpKV{k, t[k]})
		}
		acpWrite(sb, kv)
	case acpObj:
		sb.WriteByte('{')
		first := true
		for _, e := range t {
			if e.V == acpU {
				continue
			}
			if !first {
				sb.WriteByte(',')
			}
			first = false
			lenientString(sb, e.K)
			sb.WriteByte(':')
			acpWrite(sb, e.V)
		}
		sb.WriteByte('}')
	default:
		f, ok := jsNum(v)
		if !ok || math.IsNaN(f) || math.IsInf(f, 0) {
			sb.WriteString("null")
			return
		}
		sb.WriteString(jsLenientNumber(f))
	}
}

// acpStringify is JSON.stringify of a JSON value.
func acpStringify(v any) string {
	var sb strings.Builder
	acpWrite(&sb, v)
	return sb.String()
}

type acpParser struct {
	s string
	i int
}

// acpParse is JSON.parse: standard JSON text only (no raw control character in a string, no unknown escape), a duplicate member
// keeps the last value, numbers stay as their lexeme (json.Number).
func acpParse(text string) (any, error) {
	p := &acpParser{s: text}
	v, err := p.value(0)
	if err != nil {
		return nil, err
	}
	p.ws()
	if p.i != len(p.s) {
		return nil, errors.New("Unexpected non-whitespace character after JSON")
	}
	return v, nil
}

func (p *acpParser) ws() {
	for p.i < len(p.s) {
		switch p.s[p.i] {
		case ' ', '\t', '\n', '\r':
			p.i++
		default:
			return
		}
	}
}

func (p *acpParser) value(depth int) (any, error) {
	if depth > 512 {
		return nil, errors.New("JSON nesting too deep")
	}
	p.ws()
	if p.i >= len(p.s) {
		return nil, errors.New("Unexpected end of JSON input")
	}
	switch c := p.s[p.i]; {
	case c == '{':
		p.i++
		o := map[string]any{}
		p.ws()
		if p.i < len(p.s) && p.s[p.i] == '}' {
			p.i++
			return o, nil
		}
		for {
			p.ws()
			if p.i >= len(p.s) || p.s[p.i] != '"' {
				return nil, errors.New("Expected property name in JSON")
			}
			k, err := p.str()
			if err != nil {
				return nil, err
			}
			p.ws()
			if p.i >= len(p.s) || p.s[p.i] != ':' {
				return nil, errors.New("Expected ':' after property name in JSON")
			}
			p.i++
			v, err := p.value(depth + 1)
			if err != nil {
				return nil, err
			}
			o[k] = v
			p.ws()
			if p.i < len(p.s) && p.s[p.i] == ',' {
				p.i++
				continue
			}
			if p.i < len(p.s) && p.s[p.i] == '}' {
				p.i++
				return o, nil
			}
			return nil, errors.New("Expected ',' or '}' after property value in JSON")
		}
	case c == '[':
		p.i++
		l := []any{}
		p.ws()
		if p.i < len(p.s) && p.s[p.i] == ']' {
			p.i++
			return l, nil
		}
		for {
			v, err := p.value(depth + 1)
			if err != nil {
				return nil, err
			}
			l = append(l, v)
			p.ws()
			if p.i < len(p.s) && p.s[p.i] == ',' {
				p.i++
				continue
			}
			if p.i < len(p.s) && p.s[p.i] == ']' {
				p.i++
				return l, nil
			}
			return nil, errors.New("Expected ',' or ']' after array element in JSON")
		}
	case c == '"':
		return p.str()
	case c == '-' || (c >= '0' && c <= '9'):
		return p.num()
	case strings.HasPrefix(p.s[p.i:], "true"):
		p.i += 4
		return true, nil
	case strings.HasPrefix(p.s[p.i:], "false"):
		p.i += 5
		return false, nil
	case strings.HasPrefix(p.s[p.i:], "null"):
		p.i += 4
		return nil, nil
	}
	return nil, errors.New("Unexpected token in JSON")
}

func (p *acpParser) str() (string, error) {
	p.i++ // opening quote
	var sb strings.Builder
	for {
		if p.i >= len(p.s) {
			return "", errors.New("Unterminated string in JSON")
		}
		c := p.s[p.i]
		switch {
		case c == '"':
			p.i++
			return sb.String(), nil
		case c < 0x20:
			return "", errors.New("Bad control character in string literal in JSON")
		case c == '\\':
			p.i++
			if p.i >= len(p.s) {
				return "", errors.New("Unterminated string in JSON")
			}
			switch e := p.s[p.i]; e {
			case '"', '\\', '/':
				sb.WriteByte(e)
			case 'b':
				sb.WriteByte('\b')
			case 'f':
				sb.WriteByte('\f')
			case 'n':
				sb.WriteByte('\n')
			case 'r':
				sb.WriteByte('\r')
			case 't':
				sb.WriteByte('\t')
			case 'u':
				r, ok := hex4(p.s[p.i+1:])
				if !ok {
					return "", errors.New("Bad Unicode escape in JSON")
				}
				p.i += 4
				if r >= 0xD800 && r <= 0xDBFF && strings.HasPrefix(p.s[p.i+1:], `\u`) {
					if lo, ok2 := hex4(p.s[p.i+3:]); ok2 && lo >= 0xDC00 && lo <= 0xDFFF {
						sb.WriteRune(0x10000 + (r-0xD800)<<10 + (lo - 0xDC00))
						p.i += 6
						break
					}
				}
				if r >= 0xD800 && r <= 0xDFFF {
					writeWTF8(&sb, r)
				} else {
					sb.WriteRune(r)
				}
			default:
				return "", errors.New("Bad escaped character in JSON")
			}
			p.i++
		default:
			sb.WriteByte(c)
			p.i++
		}
	}
}

func (p *acpParser) num() (any, error) {
	start := p.i
	if p.s[p.i] == '-' {
		p.i++
	}
	if p.i >= len(p.s) || !isDigit(p.s[p.i]) {
		return nil, errors.New("No number after minus sign in JSON")
	}
	if p.s[p.i] == '0' {
		p.i++
	} else {
		for p.i < len(p.s) && isDigit(p.s[p.i]) {
			p.i++
		}
	}
	if p.i < len(p.s) && p.s[p.i] == '.' {
		p.i++
		if p.i >= len(p.s) || !isDigit(p.s[p.i]) {
			return nil, errors.New("Unterminated fractional number in JSON")
		}
		for p.i < len(p.s) && isDigit(p.s[p.i]) {
			p.i++
		}
	}
	if p.i < len(p.s) && (p.s[p.i] == 'e' || p.s[p.i] == 'E') {
		p.i++
		if p.i < len(p.s) && (p.s[p.i] == '+' || p.s[p.i] == '-') {
			p.i++
		}
		if p.i >= len(p.s) || !isDigit(p.s[p.i]) {
			return nil, errors.New("Exponent part is missing a number in JSON")
		}
		for p.i < len(p.s) && isDigit(p.s[p.i]) {
			p.i++
		}
	}
	return json.Number(p.s[start:p.i]), nil
}

// ---- caveat vocabulary ------------------------------------------------------------------------------------------------

// AcpSpendCapCaveat builds `{type: "max_amount", max, currency?}`.
func AcpSpendCapCaveat(max float64, currency *string) map[string]any {
	out := map[string]any{"type": AcpSpendCapType, "max": jsNumber(max)}
	if currency != nil {
		out["currency"] = *currency
	}
	return out
}

func acpStringsAny(l []string) []any {
	out := make([]any, len(l))
	for i, s := range l {
		out[i] = s
	}
	return out
}

// AcpMerchantAllowCaveat builds `{type: "merchant_allow", merchants}`.
func AcpMerchantAllowCaveat(merchants []string) map[string]any {
	return map[string]any{"type": AcpMerchantAllowType, "merchants": acpStringsAny(merchants)}
}

// AcpMerchantCategoryCaveat builds `{type: "merchant_category", categories}`.
func AcpMerchantCategoryCaveat(categories []string) map[string]any {
	return map[string]any{"type": AcpMerchantCategoryType, "categories": acpStringsAny(categories)}
}

// AcpHumanPresentCaveat builds `{type: "human_present", required}`.
func AcpHumanPresentCaveat(required bool) map[string]any {
	return map[string]any{"type": AcpHumanPresentType, "required": required}
}

func acpStringList(v any, label string) ([]string, error) {
	l, ok := v.([]any)
	if !ok {
		return nil, acpAuthErr("malformed %s caveat: expected a string[] (fail closed)", label)
	}
	out := make([]string, 0, len(l))
	for _, x := range l {
		s, ok := x.(string)
		if !ok {
			return nil, acpAuthErr("malformed %s caveat: expected a string[] (fail closed)", label)
		}
		out = append(out, s)
	}
	return out, nil
}

func acpDedupe(l []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range l {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func acpFilterIn(have, list []string) []string {
	in := map[string]bool{}
	for _, s := range list {
		in[s] = true
	}
	out := []string{}
	for _, s := range have {
		if in[s] {
			out = append(out, s)
		}
	}
	return out
}

// AcpExtractPaymentAuthority collapses a leaf capability's cumulative caveat list into its effective payment authority:
// {maxAmount?, currency?, merchants (list or null), categories (list or null), humanPresentRequired}. Payment caveats combine
// conjunctively (tightest cap, intersected allowlists, a sticky human-present requirement); a malformed PAYMENT caveat is an
// *AcpAuthorityError (fail closed); any other caveat type is ignored.
func AcpExtractPaymentAuthority(caveats any) (map[string]any, error) {
	var list []any
	switch t := caveats.(type) {
	case []any:
		list = t
	case string:
		list = nil // a string iterates its characters; none is an object, so none is a caveat
	default:
		return nil, errors.New("caveats is not iterable")
	}
	var maxF float64
	hasMax, hasCur, human := false, false, false
	curS := ""
	var merchants, categories []string
	merchantsSet, categoriesSet := false, false
	for _, c := range list {
		if c == nil {
			return nil, errors.New("Cannot read properties of null (reading 'type')")
		}
		switch acpGet(c, "type") {
		case AcpSpendCapType:
			mx := acpGet(c, "max")
			mf, isn := jsNum(mx)
			if !isn || !jsIsSafeInteger(mx) || mf < 0 || (mf == 0 && math.Signbit(mf)) {
				return nil, acpAuthErr("malformed max_amount caveat: max must be an integer >= 0 in minor units (fail closed)")
			}
			if !hasMax || mf < maxF {
				maxF = mf
			}
			hasMax = true
			if cur := acpGet(c, "currency"); cur != acpU {
				cs, ok := cur.(string)
				if !ok || cs == "" {
					return nil, acpAuthErr("malformed max_amount caveat: currency must be a non-empty string (fail closed)")
				}
				if hasCur && curS != cs {
					return nil, acpAuthErr(`conflicting spend-cap currencies "%s" vs "%s" (fail closed)`, curS, cs)
				}
				curS, hasCur = cs, true
			}
		case AcpMerchantAllowType:
			l, err := acpStringList(acpGet(c, "merchants"), "merchant_allow")
			if err != nil {
				return nil, err
			}
			if merchantsSet {
				merchants = acpFilterIn(merchants, l)
			} else {
				merchants, merchantsSet = acpDedupe(l), true
			}
		case AcpMerchantCategoryType:
			l, err := acpStringList(acpGet(c, "categories"), "merchant_category")
			if err != nil {
				return nil, err
			}
			if categoriesSet {
				categories = acpFilterIn(categories, l)
			} else {
				categories, categoriesSet = acpDedupe(l), true
			}
		case AcpHumanPresentType:
			req, ok := acpGet(c, "required").(bool)
			if !ok {
				return nil, acpAuthErr("malformed human_present caveat: required must be a boolean (fail closed)")
			}
			human = human || req
		}
	}
	out := map[string]any{"merchants": nil, "categories": nil, "humanPresentRequired": human}
	if hasMax {
		out["maxAmount"] = jsNumber(maxF)
	}
	if hasCur {
		out["currency"] = curS
	}
	if merchantsSet {
		out["merchants"] = acpStringsAny(merchants)
	}
	if categoriesSet {
		out["categories"] = acpStringsAny(categories)
	}
	return out, nil
}

func acpCheckFail(reason string) map[string]any { return map[string]any{"ok": false, "reason": reason} }

func acpIncludesStr(l []any, s string) bool {
	for _, x := range l {
		if t, ok := x.(string); ok && t == s {
			return true
		}
	}
	return false
}

// AcpCheckPaymentAuthority checks a concrete purchase request {amount, currency, merchant, category?, humanPresent?} against a
// payment authority. Pure and fail closed: an over-cap amount, a forbidden currency, a merchant or category outside the allowlist
// or a missing human-present signal returns {ok: false, reason}.
func AcpCheckPaymentAuthority(authority, request any) (map[string]any, error) {
	if acpNullish(request) {
		return nil, errors.New("Cannot read properties of null (reading 'amount')")
	}
	amount, currency, merchant := acpGet(request, "amount"), acpGet(request, "currency"), acpGet(request, "merchant")
	if !acpIsAmount(amount) {
		return acpCheckFail("amount must be a positive integer in minor units"), nil
	}
	cs, ok := currency.(string)
	if !ok || cs == "" {
		return acpCheckFail("currency must be a non-empty string"), nil
	}
	ms, ok := merchant.(string)
	if !ok || ms == "" {
		return acpCheckFail("merchant must be a non-empty string"), nil
	}
	if acpNullish(authority) {
		return nil, errors.New("Cannot read properties of null (reading 'currency')")
	}
	if ac := acpGet(authority, "currency"); ac != acpU {
		if acs, isS := ac.(string); !isS || acs != cs {
			return acpCheckFail(fmt.Sprintf(`currency "%s" is not the authorized currency "%s"`, cs, acpS(ac))), nil
		}
	}
	af, _ := jsNum(amount)
	if cp := acpGet(authority, "maxAmount"); cp != acpU { // null is present and not a number: refused
		if f, ok := jsNum(cp); !ok || !jsIsInt(cp) || f < 0 {
			return acpCheckFail("authorized spend cap is not a non-negative integer (fail closed)"), nil
		}
	}
	if cp := acpGet(authority, "maxAmount"); cp != acpU && af > acpToNumber(cp) {
		return acpCheckFail(fmt.Sprintf("amount %s exceeds the authorized spend cap %s", acpS(amount), acpS(cp))), nil
	}
	if mv := acpGet(authority, "merchants"); mv != nil {
		l, isL := mv.([]any)
		if !isL {
			return nil, errors.New("authority.merchants.includes is not a function")
		}
		if !acpIncludesStr(l, ms) {
			return acpCheckFail(fmt.Sprintf(`merchant "%s" is not in the authorized allowlist`, ms)), nil
		}
	}
	if cv := acpGet(authority, "categories"); cv != nil {
		l, isL := cv.([]any)
		if !isL {
			return nil, errors.New("authority.categories.includes is not a function")
		}
		cat := acpGet(request, "category")
		if cat == acpU {
			return acpCheckFail("the proof constrains merchant categories but no category was supplied"), nil
		}
		if cstr, isS := cat.(string); !isS || !acpIncludesStr(l, cstr) {
			return acpCheckFail(fmt.Sprintf(`category "%s" is not in the authorized allowlist`, acpS(cat))), nil
		}
	}
	if acpTruthy(acpGet(authority, "humanPresentRequired")) && acpGet(request, "humanPresent") != true {
		return acpCheckFail("the proof requires a human-present charge but humanPresent was not asserted"), nil
	}
	return map[string]any{"ok": true}, nil
}

// ---- delegated payment token ------------------------------------------------------------------------------------------

func acpLeaf(pcActn any) (any, error) {
	if acpNullish(pcActn) {
		return nil, errors.New("Cannot read properties of null (reading 'cap_chain')")
	}
	chain, ok := acpGet(pcActn, "cap_chain").([]any)
	if !ok || len(chain) == 0 {
		return nil, acpAuthErr("PCActn carries no capability chain (fail closed)")
	}
	return chain[len(chain)-1], nil
}

// acpSigningSeed is importJWK for a signing key: an Ed25519 private JWK (kty OKP, crv Ed25519, d) under alg EdDSA.
func acpSigningSeed(key, alg any) ([]byte, error) {
	if a, ok := alg.(string); !ok || a != "EdDSA" {
		return nil, errors.New("Invalid key for this operation")
	}
	m, ok := key.(map[string]any)
	if !ok || m["kty"] != "OKP" || m["crv"] != "Ed25519" {
		return nil, errors.New("Invalid key for this operation")
	}
	d, ok := m["d"].(string)
	if !ok {
		return nil, errors.New("a private key is required to sign")
	}
	seed := nodeB64(d)
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("Invalid Ed25519 private key")
	}
	return seed, nil
}

// AcpMintDelegatedPaymentToken mints a one-time ACP delegated payment token (a compact EdDSA JWS) FROM a PCActn. The token is bound
// to session, merchant, amount, currency and expiry and carries the proof's authority BY REFERENCE (pca.digest). The proof's leaf
// caveats gate issuance: an over-authority request, an expiry in the past or one that would outlive the proof is an
// *AcpAuthorityError. opts: amount, currency, merchant, session, expiresAt, paymentMethod, signingKey (a private Ed25519 JWK),
// alg, category, humanPresent, issuer, kid, jti, now (epoch ms; default the wall clock).
func AcpMintDelegatedPaymentToken(pcActn any, opts map[string]any) (string, error) {
	if opts == nil {
		return "", errors.New("Cannot read properties of null (reading 'now')")
	}
	now := float64(time.Now().UnixMilli())
	if f, ok := jsNum(opts["now"]); ok && acpFinite(opts["now"]) {
		now = f
	}
	leaf, err := acpLeaf(pcActn)
	if err != nil {
		return "", err
	}
	if acpNullish(leaf) {
		return "", errors.New("Cannot read properties of null (reading 'caveats')")
	}
	authority, err := AcpExtractPaymentAuthority(acpGet(leaf, "caveats"))
	if err != nil {
		return "", err
	}
	req := map[string]any{}
	for _, k := range []string{"amount", "currency", "merchant", "category", "humanPresent"} {
		if v := acpGet(opts, k); v != acpU {
			req[k] = v
		}
	}
	check, err := AcpCheckPaymentAuthority(authority, req)
	if err != nil {
		return "", err
	}
	if check["ok"] != true {
		return "", acpAuthErr("refused: %s", acpS(check["reason"]))
	}
	expAt := acpGet(opts, "expiresAt")
	if !acpFinite(expAt) {
		return "", acpAuthErr("refused: expiresAt must be a finite epoch-ms timestamp")
	}
	ef, _ := jsNum(expAt)
	if !(finite(ef) && finite(now) && ef > now) {
		return "", acpAuthErr("refused: expiresAt is not in the future")
	}
	if !acpFinite(acpGet(pcActn, "exp")) || acpGt(ef, acpGet(pcActn, "exp")) { // the proof expiry must be a finite number
		return "", acpAuthErr("refused: token expiry %s would outlive the proof's exp %s", acpS(expAt), acpS(acpGet(pcActn, "exp")))
	}
	session := acpGet(opts, "session")
	if !acpTruthy(session) {
		return "", acpAuthErr("refused: a session id is required")
	}
	digest, err := HashCanonical(pcActn)
	if err != nil {
		return "", err
	}
	action := acpGet(pcActn, "action")
	if acpNullish(action) {
		return "", errors.New("Cannot read properties of undefined (reading 'verb')")
	}
	ref := acpObj{{"digest", digest}, {"aud", acpGet(pcActn, "aud")}, {"grant_ref", acpGet(pcActn, "grant_ref")}, {"leaf_holder", acpGet(leaf, "holder")},
		{"verb", acpGet(action, "verb")}, {"resource", acpGet(action, "resource")}, {"params_digest", acpGet(action, "params_digest")}}
	jti := acpGet(opts, "jti")
	if acpNullish(jti) {
		pm, _ := pcActn.(map[string]any)
		seed := make(map[string]any, len(pm)+1)
		for k, v := range pm {
			seed[k] = v
		}
		seed["nonce"] = fmt.Sprintf("acp:%s:%s:%s:%s:%s:%s", acpS(session), acpS(acpGet(opts, "merchant")), acpS(acpGet(opts, "amount")),
			acpS(acpGet(opts, "currency")), acpS(expAt), digest)
		if jti, err = HashCanonical(seed); err != nil {
			return "", err
		}
	}
	claims := acpObj{{"typ", AcpDelegatedTokenType}, {"ver", AcpDelegatedTokenVersion}, {"jti", jti}, {"session", session},
		{"merchant", acpGet(opts, "merchant")}, {"amount", acpGet(opts, "amount")}, {"currency", acpGet(opts, "currency")},
		{"iat", jsNumber(now)}, {"exp", expAt}, {"paymentMethod", acpSpread(acpGet(opts, "paymentMethod"))},
		{"humanPresent", acpGet(opts, "humanPresent") == true}}
	if v := acpGet(opts, "category"); v != acpU {
		claims = append(claims, acpKV{"category", v})
	}
	if v := acpGet(opts, "issuer"); v != acpU {
		claims = append(claims, acpKV{"iss", v})
	}
	claims = append(claims, acpKV{"pca", ref})
	alg := acpGet(opts, "alg")
	if acpNullish(alg) {
		alg = "EdDSA"
	}
	header := acpObj{{"alg", alg}, {"typ", AcpDelegatedTokenType}}
	if kid := acpGet(opts, "kid"); kid != acpU {
		header = append(header, acpKV{"kid", kid})
	}
	seed, err := acpSigningSeed(acpGet(opts, "signingKey"), alg)
	if err != nil {
		return "", err
	}
	return SignCompactEdDSA(rawJSON(acpStringify(header)), rawJSON(acpStringify(claims)), seed)
}

// ---- verification -----------------------------------------------------------------------------------------------------

// acpImportVerifyKey is importJWK for a verification key (a private JWK yields its public key).
func acpImportVerifyKey(k any) (*JOSEKey, error) {
	m, ok := k.(map[string]any)
	if !ok {
		return nil, errors.New("Key must be a JWK")
	}
	if _, has := m["kty"]; !has {
		return nil, errors.New("Key must be a JWK")
	}
	switch m["kty"] {
	case "oct":
		ks, ok := m["k"].(string)
		if !ok || ks == "" {
			return nil, errors.New("Invalid JWK")
		}
		return &JOSEKey{Kty: "oct", HMAC: nodeB64(ks)}, nil
	case "OKP", "EC", "RSA":
		if d, has := m["d"]; has && acpTruthy(d) {
			ds, isS := d.(string)
			if m["kty"] != "OKP" || m["crv"] != "Ed25519" || !isS {
				return nil, errors.New("Invalid private JWK for verification")
			}
			seed := nodeB64(ds)
			if len(seed) != ed25519.SeedSize {
				return nil, errors.New("Invalid Ed25519 private key")
			}
			pub, _ := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
			return &JOSEKey{Kty: "OKP", Crv: "Ed25519", Ed25519: pub}, nil
		}
		if _, hasD := m["d"]; hasD {
			return nil, errors.New("Invalid JWK: a falsy private member")
		}
		if xs, isS := m["x"].(string); m["kty"] == "OKP" && m["crv"] == "Ed25519" && isS {
			// Node decodes a JWK coordinate leniently (invalid characters skipped)
			if x := nodeB64(xs); len(x) == ed25519.PublicKeySize {
				return &JOSEKey{Kty: "OKP", Crv: "Ed25519", Ed25519: ed25519.PublicKey(x)}, nil
			}
			return nil, errors.New("Invalid Ed25519 public key")
		}
		return ImportPublicJWK(m)
	}
	return nil, errors.New(`Unsupported "kty" (Key Type) Parameter value`)
}

// acpCompactVerify is jose compactVerify with algorithms [alg]: header rules, the allowed algorithm, the signature. It returns the
// payload bytes.
func acpCompactVerify(token string, key *JOSEKey, alg any) ([]byte, error) {
	segs := strings.Split(token, ".")
	if len(segs) != 3 {
		return nil, errors.New("Invalid Compact JWS")
	}
	prot, pay, sig := segs[0], segs[1], segs[2]
	hv, err := acpParse(acpUTF8(nodeB64(prot)))
	h, ok := hv.(map[string]any)
	if err != nil || !ok {
		return nil, errors.New("JWS Protected Header is invalid")
	}
	b64Payload := true
	if c, has := h["crit"]; has {
		l, isL := c.([]any)
		if !isL || len(l) == 0 {
			return nil, errors.New(`"crit" (Critical) Header Parameter MUST be an array of non-empty strings when present`)
		}
		for _, x := range l {
			s, isS := x.(string)
			if !isS || s == "" {
				return nil, errors.New(`"crit" (Critical) Header Parameter MUST be an array of non-empty strings when present`)
			}
			if s != "b64" {
				return nil, fmt.Errorf("Extension Header Parameter %q is not recognized", s)
			}
		}
		bv, isB := h["b64"].(bool)
		if !isB {
			return nil, errors.New(`The "b64" (base64url-encode payload) Header Parameter must be a boolean`)
		}
		b64Payload = bv
	}
	halg, ok := h["alg"].(string)
	if !ok || halg == "" {
		return nil, errors.New(`JWS "alg" (Algorithm) Header Parameter missing or invalid`)
	}
	allowed, ok := alg.(string)
	if !ok {
		return nil, errors.New(`"algorithms" option must be an array of strings`)
	}
	if halg != allowed {
		return nil, errors.New(`"alg" (Algorithm) Header Parameter value not allowed`)
	}
	if key == nil || !JOSEVerify(halg, key, []byte(prot+"."+pay), nodeB64(sig)) {
		return nil, errors.New("signature verification failed")
	}
	if b64Payload {
		return nodeB64(pay), nil
	}
	return []byte(pay), nil
}

func acpIsPaymentMethod(v any) bool {
	m, ok := v.(map[string]any)
	if !ok {
		return false
	}
	_, isS := m["type"].(string)
	return isS
}

// acpParseClaims returns the claims when the payload is a well-formed delegated payment token, else nil.
func acpParseClaims(payload []byte) map[string]any {
	parsed, err := acpParse(acpUTF8(payload))
	if err != nil {
		return nil
	}
	c, ok := parsed.(map[string]any)
	if !ok {
		return nil
	}
	if c["typ"] != AcpDelegatedTokenType {
		return nil
	}
	if f, isN := jsNum(c["ver"]); !isN || f != AcpDelegatedTokenVersion {
		return nil
	}
	for _, k := range []string{"jti", "session", "merchant", "currency"} {
		if s, isS := c[k].(string); !isS || s == "" {
			return nil
		}
	}
	if !acpIsAmount(c["amount"]) || !acpFinite(c["iat"]) || !acpFinite(c["exp"]) {
		return nil
	}
	if _, isB := c["humanPresent"].(bool); !isB || !acpIsPaymentMethod(c["paymentMethod"]) {
		return nil
	}
	p, ok := c["pca"].(map[string]any)
	if !ok {
		return nil
	}
	for _, k := range []string{"digest", "aud", "grant_ref", "leaf_holder", "verb", "resource", "params_digest"} {
		if _, isS := p[k].(string); !isS {
			return nil
		}
	}
	return c
}

func acpFail(reason string, claims map[string]any) map[string]any {
	out := map[string]any{"ok": false, "reason": reason}
	if claims != nil {
		out["claims"] = claims
	}
	return out
}

func acpVerifyBinding(token any, opts map[string]any) (map[string]any, error) {
	alg := acpGet(opts, "alg")
	if acpNullish(alg) {
		alg = "EdDSA"
	}
	now := float64(time.Now().UnixMilli())
	if f, ok := jsNum(opts["now"]); ok && acpFinite(opts["now"]) {
		now = f
	}
	var claims map[string]any
	sigErr := func() error {
		if _, err := AssertCanonicalCompactJWS(token, 3, 0, true); err != nil {
			return err
		}
		key, err := acpImportVerifyKey(opts["verifyKey"])
		if err != nil {
			return err
		}
		payload, err := acpCompactVerify(token.(string), key, alg)
		if err != nil {
			return err
		}
		claims = acpParseClaims(payload)
		return nil
	}()
	if sigErr != nil {
		return acpFail("token signature did not verify: "+sigErr.Error(), nil), nil
	}
	if claims == nil {
		return acpFail("token payload is not a well-formed delegated payment token", nil), nil
	}
	cm, _ := claims["merchant"].(string)
	if em, isS := acpGet(opts, "expectedMerchant").(string); !isS || em != cm {
		return acpFail(fmt.Sprintf(`token merchant "%s" does not match expected "%s"`, cm, acpS(acpGet(opts, "expectedMerchant"))), claims), nil
	}
	amount := acpGet(opts, "amount")
	if !acpIsAmount(amount) {
		return acpFail("settlement amount must be a positive integer in minor units", claims), nil
	}
	af, _ := jsNum(amount)
	if cf, _ := jsNum(claims["amount"]); !(finite(af) && finite(cf) && af <= cf) {
		return acpFail(fmt.Sprintf("settlement amount %s exceeds the token's authorized amount %s", acpS(amount), acpS(claims["amount"])), claims), nil
	}
	if ex, _ := jsNum(claims["exp"]); !(finite(now) && finite(ex) && now <= ex) {
		return acpFail("the delegated payment token has expired", claims), nil
	}
	if es := acpGet(opts, "expectedSession"); es != acpU {
		if s, isS := es.(string); !isS || s != claims["session"] {
			return acpFail(fmt.Sprintf(`token session "%s" does not match expected "%s"`, acpS(claims["session"]), acpS(es)), claims), nil
		}
	}
	if ec := acpGet(opts, "expectedCurrency"); ec != acpU {
		if s, isS := ec.(string); !isS || s != claims["currency"] {
			return acpFail(fmt.Sprintf(`token currency "%s" does not match expected "%s"`, acpS(claims["currency"]), acpS(ec)), claims), nil
		}
	}
	grant, pc := acpGet(opts, "grant"), acpGet(opts, "pcActn")
	if grant != acpU && pc == acpU {
		return acpFail("a grant was supplied without the pcActn to re-verify (fail closed)", claims), nil
	}
	if pc == acpU {
		return map[string]any{"ok": true, "claims": claims}, nil
	}
	dg, err := HashCanonical(pc)
	if err != nil {
		return nil, err
	}
	if ref, _ := claims["pca"].(map[string]any); ref["digest"] != dg {
		return acpFail("pcactn_digest mismatch: the supplied proof is not the one that minted this token", claims), nil
	}
	if grant == acpU {
		return map[string]any{"ok": true, "claims": claims}, nil
	}
	var verdict Verdict
	pm, pok := pc.(map[string]any)
	gm, gok := grant.(map[string]any)
	if !pok || !gok {
		verdict = Verdict{Reason: "wire: the PCActn and the grant must be objects"}
	} else {
		// audience: a string is checked, an explicit null opts out (this proof's own audience), an omitted one fails closed
		aud := ""
		switch a := acpGet(opts, "audience").(type) {
		case string:
			aud = a
		case nil:
			aud, _ = pm["aud"].(string)
		}
		vo := VerifyOptions{InsecureSkipPlanRootCheck: acpGet(opts, "insecureSkipPlanRootCheck") == true}
		if roots, has := opts["authorizedPlanRoots"]; has {
			rs := []string{}
			if l, isL := roots.([]any); isL {
				for _, r := range l {
					if s, isS := r.(string); isS {
						rs = append(rs, s)
					}
				}
			}
			vo.AuthorizedPlanRoots = rs
		}
		v, verr := VerifyPCActnCoreWith(pm, gm, int64(now), aud, vo)
		if verr != nil {
			return nil, verr
		}
		verdict = v
	}
	checks := map[string]any{}
	for k, b := range verdict.Checks {
		checks[k] = b
	}
	result := map[string]any{"allow": verdict.Allow, "checks": checks}
	if verdict.Reason != "" {
		result["reason"] = verdict.Reason
	}
	if !verdict.Allow {
		why := verdict.Reason
		if why == "" {
			why = "denied"
		}
		out := acpFail("bound proof failed to verify: "+why, claims)
		out["pcaResult"] = result
		return out, nil
	}
	return map[string]any{"ok": true, "claims": claims, "pcaResult": result}, nil
}

// AcpVerifyDelegatedPaymentToken verifies a delegated payment token at settlement: the signature (canonical spelling first), then
// the merchant, amount, expiry, session and currency bindings and, with a pcActn, the proof's digest (end to end with a grant).
// Strict by default: a singleUse store (an AcpSingleUseStore) and an expectedCurrency are required, and after every other check the
// token's jti is claimed once. Fails CLOSED on every mismatch, an already redeemed token or an unavailable store. opts: expectedMerchant,
// amount, verifyKey (a JWK), alg, now, expectedSession, expectedCurrency, pcActn, grant, audience (string; null opts out, omitted fails
// closed), authorizedPlanRoots, insecureSkipPlanRootCheck, singleUse, strict. The result is {ok, reason?, claims?, pcaResult?}.
func AcpVerifyDelegatedPaymentToken(token any, opts map[string]any) (map[string]any, error) {
	if opts == nil {
		return nil, errors.New("Cannot read properties of null (reading 'strict')")
	}
	su := acpGet(opts, "singleUse")
	store, isStore := su.(AcpSingleUseStore)
	if v, isB := opts["strict"].(bool); !isB || v {
		if !acpTruthy(su) || !isStore {
			return map[string]any{"ok": false, "reason": "strict settlement requires a singleUse store (fail closed)"}, nil
		}
		if cur, isS := opts["expectedCurrency"].(string); !isS || cur == "" {
			return map[string]any{"ok": false, "reason": "strict settlement requires expectedCurrency (fail closed)"}, nil
		}
	}
	res, err := acpVerifyBinding(token, opts)
	if err != nil {
		return nil, err
	}
	if res["ok"] != true || su == acpU {
		return res, nil
	}
	claims, _ := res["claims"].(map[string]any)
	unavailable := map[string]any{"ok": false, "reason": "single-use store unavailable (fail closed)", "claims": claims}
	if !isStore {
		return unavailable, nil
	}
	jti, _ := claims["jti"].(string)
	exp, _ := jsNum(claims["exp"])
	first, cerr := store.Claim(jti, exp)
	if cerr != nil {
		return unavailable, nil
	}
	if !first {
		return acpFail("the delegated payment token was already redeemed", claims), nil
	}
	return res, nil
}

// ---- ACP delegate_payment allowance -----------------------------------------------------------------------------------

// acpISO is Date.prototype.toISOString of an epoch-ms time (ok false for an invalid date).
func acpISO(ms float64) (string, bool) {
	if math.IsNaN(ms) || math.IsInf(ms, 0) {
		return "", false
	}
	t := math.Trunc(ms)
	if math.Abs(t) > 8.64e15 {
		return "", false
	}
	tm := time.UnixMilli(int64(t)).UTC()
	y := tm.Year()
	var ys string
	switch {
	case y >= 0 && y <= 9999:
		ys = fmt.Sprintf("%04d", y)
	case y < 0:
		ys = fmt.Sprintf("-%06d", -y)
	default:
		ys = fmt.Sprintf("+%06d", y)
	}
	return fmt.Sprintf("%s-%02d-%02dT%02d:%02d:%02d.%03dZ", ys, int(tm.Month()), tm.Day(), tm.Hour(), tm.Minute(), tm.Second(), tm.Nanosecond()/1000000), true
}

// AcpToAllowance maps VERIFIED token claims to the ACP delegate_payment `allowance`. It refuses (an *AcpAuthorityError) a claim that
// cannot be expressed in the ACP shape (currency not three letters, merchant over 256 characters, expiry not a date) instead of
// emitting an allowance the PSP would reject or misread.
func AcpToAllowance(claims any) (map[string]any, error) {
	if acpNullish(claims) {
		return nil, errors.New("Cannot read properties of null (reading 'amount')")
	}
	amount := acpGet(claims, "amount")
	if !acpIsAmount(amount) {
		return nil, acpAuthErr("allowance: amount must be a positive integer in minor units")
	}
	currency := ""
	if s, ok := acpGet(claims, "currency").(string); ok {
		currency = acpLower(s)
	}
	if len(currency) != 3 || strings.Trim(currency, "abcdefghijklmnopqrstuvwxyz") != "" {
		return nil, acpAuthErr("allowance: currency must be a three-letter ISO-4217 code")
	}
	merchant, ok := acpGet(claims, "merchant").(string)
	if !ok || merchant == "" || jsLen(merchant) > 256 {
		return nil, acpAuthErr("allowance: merchant_id must be 1 to 256 characters")
	}
	session, ok := acpGet(claims, "session").(string)
	if !ok || session == "" {
		return nil, acpAuthErr("allowance: checkout_session_id is required")
	}
	exp := acpGet(claims, "exp")
	ef, isN := jsNum(exp)
	if !isN || !acpFinite(exp) {
		return nil, acpAuthErr("allowance: expiry is not a valid time")
	}
	at, valid := acpISO(ef)
	if !valid {
		return nil, acpAuthErr("allowance: expiry is not a valid time")
	}
	return map[string]any{"reason": "one_time", "max_amount": amount, "currency": currency, "checkout_session_id": session,
		"merchant_id": merchant, "expires_at": at}, nil
}
