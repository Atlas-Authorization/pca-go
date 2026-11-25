package pca

// Web Bot Auth for Proof-Carrying Authority (port of the TypeScript @atlasauth/pca-webbotauth): RFC 9421 HTTP Message Signatures
// over outbound agent requests in the `web-bot-auth` profile (Ed25519), a framework-agnostic key-directory handler, and the PCA
// proof binding (the `PCA-Action` header is a covered component, so one request is both bot-verified and proof-carrying).
// Content-Digest lives in webbotauth_digest.go, the signed key directory and its fetch in webbotauth_directory.go.
// Verification FAILS CLOSED: any parse error, missing field, stale window, wrong tag, unknown key or bad signature is
// {"valid": false, "reason": ...} and never an error.
//
// Requests, options and results are JSON values (map[string]any / []any, numbers as json.Number or float64) with the member
// names of the reference. A signing key is a *KeyPair, a 32-byte seed or {"secretKey": seed}. Go-typed option members: resolveKey is
// func(keyid string) (any, error) returning a 32-byte []byte, a public JWK map or nil; replayCache is a WebBotAuthReplayCache.
//
// shortcut: only special-scheme URLs (http, https, ws, wss, ftp) are signed or verified; others are refused. A URL with
// credentials is refused where the serialized URL itself is needed (@target-uri, the directory fetch).
// shortcut: duplicate header names that differ in case merge in the member order of the header object; a map built in code has no
// recorded order and merges in sorted order.

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// WebBotAuthTag is the RFC 9421 `tag` parameter of the Web Bot Auth profile.
	WebBotAuthTag = "web-bot-auth"
	// WebBotAuthAlg is the signature algorithm label the profile pins.
	WebBotAuthAlg = "ed25519"
	// WebBotAuthWellKnownDirectoryPath is where the key directory (JWKS) is served.
	WebBotAuthWellKnownDirectoryPath = "/.well-known/http-message-signatures-directory"
	// WebBotAuthDirectoryContentType is the content type of the key directory response.
	WebBotAuthDirectoryContentType = "application/http-message-signatures-directory+json"
	// WebBotAuthDefaultSignatureLabel is the default signature label.
	WebBotAuthDefaultSignatureLabel = "sig1"
	// WebBotAuthDefaultExpiresSec is the default signature lifetime.
	WebBotAuthDefaultExpiresSec = 300
	// WebBotAuthSignatureAgentHeader carries the signing directory URL.
	WebBotAuthSignatureAgentHeader = "Signature-Agent"
	// WebBotAuthPCAHeader is the request header that carries the PCActn.
	WebBotAuthPCAHeader = "PCA-Action"
	// WebBotAuthPCAProofComponent is the covered-component (lower case) name of the PCA proof header.
	WebBotAuthPCAProofComponent = "pca-action"
	// WebBotAuthDirectorySignatureTag is the tag of a signed key-directory response.
	WebBotAuthDirectorySignatureTag = "http-message-signatures-directory"

	wbaJSWhitespace = "\t\n\v\f\r \u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"
)

var (
	wbaIntRe          = regexp.MustCompile(`^-?[0-9]+$`)
	wbaDecRe          = regexp.MustCompile(`^-?[0-9]+\.[0-9]+$`)
	wbaKeyParamRe     = regexp.MustCompile(`^;key=("(?:[^"\\]|\\[^\n\r\x{2028}\x{2029}])*")$`)
	wbaMemberParamsRe = regexp.MustCompile(`^(?:;[a-z*][a-z0-9_.*-]*(?:=(?:"(?:[^"\\]|\\[^\n\r\x{2028}\x{2029}])*"|[A-Za-z0-9_.:/*+%-]+))?)*$`)
)

// ---- small JS-semantics helpers -----------------------------------------------------------------------------------

func wbaTrim(s string) string { return strings.Trim(s, wbaJSWhitespace) }

func wbaUTF8(s string) []byte { return []byte(wellFormedUTF8(s)) }

// wbaNodeB64 is Buffer.from(s, 'base64'): both alphabets, any other character skipped, decoding stops at '='.
func wbaNodeB64(s string) []byte {
	var out []byte
	var acc uint32
	n := 0
loop:
	for i := 0; i < len(s); i++ {
		c := s[i]
		var v uint32
		switch {
		case c >= 'A' && c <= 'Z':
			v = uint32(c - 'A')
		case c >= 'a' && c <= 'z':
			v = uint32(c-'a') + 26
		case c >= '0' && c <= '9':
			v = uint32(c-'0') + 52
		case c == '+' || c == '-':
			v = 62
		case c == '/' || c == '_':
			v = 63
		case c == '=':
			break loop
		default:
			continue
		}
		acc = acc<<6 | v
		n++
		if n == 4 {
			out = append(out, byte(acc>>16), byte(acc>>8), byte(acc))
			acc, n = 0, 0
		}
	}
	switch n {
	case 2:
		out = append(out, byte(acc>>4))
	case 3:
		out = append(out, byte(acc>>10), byte(acc>>2))
	}
	return out
}

func wbaKeyPair(key any) (*KeyPair, error) {
	switch k := key.(type) {
	case *KeyPair:
		if k != nil {
			return k, nil
		}
	case []byte:
		return KeyPairFromSeed(k)
	case map[string]any:
		if s, ok := k["secretKey"].([]byte); ok {
			return KeyPairFromSeed(s)
		}
	}
	return nil, errors.New("the signing key must be a KeyPair, a 32-byte seed or {secretKey: seed}")
}

// wbaNumber reads an optional number member: absent or null is the default; anything else must be a number.
func wbaNumber(m map[string]any, k string, def float64) (float64, error) {
	v, has := m[k]
	if !has || v == nil {
		return def, nil
	}
	f, ok := jsNum(v)
	if !ok {
		return 0, fmt.Errorf("%s must be a number", k)
	}
	return f, nil
}

func wbaNowSec() float64 { return float64(time.Now().Unix()) }

func wbaThumbprintOfX(x string) string {
	h := sha256.Sum256([]byte(`{"crv":"Ed25519","kty":"OKP","x":"` + x + `"}`))
	return b64.EncodeToString(h[:])
}

// WebBotAuthJWKThumbprint is the RFC 7638 thumbprint of an Ed25519 public key.
func WebBotAuthJWKThumbprint(publicKey []byte) string {
	return wbaThumbprintOfX(b64.EncodeToString(publicKey))
}

// ---- structured-field helpers (targeted to the RFC 9421 Signature-Input / Signature grammars) ---------------------------

func wbaSfString(s string) string {
	return `"` + strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), `"`, `\"`) + `"`
}

func wbaSplitTopLevel(s string, sep byte) []string {
	var out []string
	depth := 0
	inStr := false
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inStr {
			if c == '\\' {
				i++
			} else if c == '"' {
				inStr = false
			}
			continue
		}
		switch {
		case c == '"':
			inStr = true
		case c == '(':
			depth++
		case c == ')':
			if depth > 0 {
				depth--
			}
		case c == sep && depth == 0:
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

func wbaIndexTopLevel(s string, ch byte) int {
	depth := 0
	inStr := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inStr {
			if c == '\\' {
				i++
			} else if c == '"' {
				inStr = false
			}
			continue
		}
		switch {
		case c == '"':
			inStr = true
		case c == '(':
			depth++
		case c == ')':
			if depth > 0 {
				depth--
			}
		case c == ch && depth == 0:
			return i
		}
	}
	return -1
}

func wbaMatchingParen(s string, open int) int {
	if open >= len(s) || s[open] != '(' {
		return -1
	}
	depth := 0
	inStr := false
	for i := open; i < len(s); i++ {
		c := s[i]
		if inStr {
			if c == '\\' {
				i++
			} else if c == '"' {
				inStr = false
			}
			continue
		}
		switch {
		case c == '"':
			inStr = true
		case c == '(':
			depth++
		case c == ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// wbaReadSfString reads an sf-string starting at s[i] (which must be `"`): the decoded value and the next index.
func wbaReadSfString(s string, i int) (string, int, error) {
	if i >= len(s) || s[i] != '"' {
		return "", 0, errors.New("expected a quoted string")
	}
	var out []byte
	for j := i + 1; j < len(s); j++ {
		c := s[j]
		switch c {
		case '\\':
			var n byte
			if j+1 < len(s) {
				n = s[j+1]
			}
			if n != '"' && n != '\\' {
				return "", 0, errors.New("invalid escape in string")
			}
			out = append(out, n)
			j++
		case '"':
			return string(out), j + 1, nil
		default:
			out = append(out, c)
		}
	}
	return "", 0, errors.New("unterminated string")
}

// wbaParseParamValue parses a parameter value: string, integer / decimal (float64), boolean or token.
func wbaParseParamValue(raw string) (any, error) {
	s := wbaTrim(raw)
	switch {
	case len(s) == 0:
		return true, nil // a valueless parameter is boolean true
	case s[0] == '"':
		v, next, err := wbaReadSfString(s, 0)
		if err != nil {
			return nil, err
		}
		if next != len(s) {
			return nil, errors.New("trailing characters after string parameter")
		}
		return v, nil
	case s == "?1":
		return true, nil
	case s == "?0":
		return false, nil
	case wbaIntRe.MatchString(s), wbaDecRe.MatchString(s):
		f, _ := strconv.ParseFloat(s, 64) // an out-of-range magnitude is +-Inf, as parseInt gives
		return f, nil
	}
	return s, nil // token
}

func wbaParseParams(paramStr string) (map[string]any, error) {
	params := map[string]any{}
	trimmed := wbaTrim(paramStr)
	if len(trimmed) == 0 {
		return params, nil
	}
	if trimmed[0] != ';' {
		return nil, errors.New(`expected parameters to start with ";"`)
	}
	for _, part := range wbaSplitTopLevel(trimmed[1:], ';') {
		seg := wbaTrim(part)
		if len(seg) == 0 {
			continue
		}
		eq := wbaIndexTopLevel(seg, '=')
		if eq == -1 {
			params[seg] = true
			continue
		}
		v, err := wbaParseParamValue(seg[eq+1:])
		if err != nil {
			return nil, err
		}
		params[wbaTrim(seg[:eq])] = v
	}
	return params, nil
}

type wbaComponent struct {
	id, raw string
	key     *string // RFC 9421 section 2.1.2 `key` parameter: the dictionary member of a Structured Field header
}

type wbaSigInput struct {
	label     string
	comps     []wbaComponent
	paramsRaw string // the verbatim `(...)` + params, reused byte for byte in the signature base
	params    map[string]any
}

func wbaParseSignatureInput(value string) ([]wbaSigInput, error) {
	var entries []wbaSigInput
	for _, memberRaw := range wbaSplitTopLevel(value, ',') {
		member := wbaTrim(memberRaw)
		if len(member) == 0 {
			continue
		}
		eq := wbaIndexTopLevel(member, '=')
		if eq == -1 {
			return nil, errors.New("malformed Signature-Input member")
		}
		label := wbaTrim(member[:eq])
		paramsRaw := wbaTrim(member[eq+1:])
		if len(paramsRaw) == 0 || paramsRaw[0] != '(' {
			return nil, errors.New("Signature-Input value must be an inner list")
		}
		closeAt := wbaMatchingParen(paramsRaw, 0)
		if closeAt == -1 {
			return nil, errors.New("unterminated inner list")
		}
		var comps []wbaComponent
		for _, chunkRaw := range wbaSplitTopLevel(paramsRaw[1:closeAt], ' ') {
			chunk := wbaTrim(chunkRaw)
			if len(chunk) == 0 {
				continue
			}
			id, next, err := wbaReadSfString(chunk, 0)
			if err != nil {
				return nil, err
			}
			lowered := strings.ToLower(id)
			rest := wbaTrim(chunk[next:])
			if len(rest) == 0 {
				comps = append(comps, wbaComponent{id: lowered, raw: `"` + lowered + `"`})
				continue
			}
			// the only component parameter supported is `key` (dictionary member), on header components
			m := wbaKeyParamRe.FindStringSubmatch(rest)
			if m == nil || strings.HasPrefix(lowered, "@") {
				return nil, fmt.Errorf(`unsupported component parameters on "%s"`, id)
			}
			key, _, err := wbaReadSfString(m[1], 0)
			if err != nil {
				return nil, err
			}
			comps = append(comps, wbaComponent{id: lowered, raw: `"` + lowered + `";key=` + wbaSfString(key), key: &key})
		}
		params, err := wbaParseParams(paramsRaw[closeAt+1:])
		if err != nil {
			return nil, err
		}
		entries = append(entries, wbaSigInput{label: label, comps: comps, paramsRaw: paramsRaw, params: params})
	}
	return entries, nil
}

func wbaParseSignature(value string) (map[string][]byte, error) {
	out := map[string][]byte{}
	for _, memberRaw := range wbaSplitTopLevel(value, ',') {
		member := wbaTrim(memberRaw)
		if len(member) == 0 {
			continue
		}
		eq := wbaIndexTopLevel(member, '=')
		if eq == -1 {
			return nil, errors.New("malformed Signature member")
		}
		v := wbaTrim(member[eq+1:])
		if len(v) < 2 || v[0] != ':' || v[len(v)-1] != ':' {
			return nil, errors.New("Signature value must be a byte sequence (:base64:)")
		}
		out[wbaTrim(member[:eq])] = wbaNodeB64(v[1 : len(v)-1])
	}
	return out, nil
}

// ---- headers and the request context ------------------------------------------------------------------------------------

type wbaKV struct {
	k string
	v any
}

// wbaEntries is Object.entries(h) of a JSON value (also the members of `{...h}`): a map in its recorded member order, an array or
// a string by index; anything else has none.
func wbaEntries(h any) []wbaKV {
	var out []wbaKV
	switch t := h.(type) {
	case map[string]any:
		for _, k := range jsKeys(t) {
			out = append(out, wbaKV{k, t[k]})
		}
	case []any:
		for i, v := range t {
			out = append(out, wbaKV{strconv.Itoa(i), v})
		}
	case string:
		i := 0
		for _, r := range t {
			out = append(out, wbaKV{strconv.Itoa(i), string(r)})
			i++
		}
	}
	return out
}

func wbaNormalizeHeaders(entries []wbaKV) (map[string]string, error) {
	m := map[string]string{}
	for _, e := range entries {
		name := strings.ToLower(e.k)
		var value string
		if l, ok := e.v.([]any); ok {
			parts := make([]string, len(l))
			for i, x := range l {
				s, ok := x.(string)
				if !ok {
					return nil, errors.New("x.trim is not a function")
				}
				parts[i] = wbaTrim(s)
			}
			value = strings.Join(parts, ", ")
		} else {
			s, ok := e.v.(string)
			if !ok {
				return nil, errors.New("v.trim is not a function")
			}
			value = wbaTrim(s)
		}
		if prev, has := m[name]; has {
			value = prev + ", " + value
		}
		m[name] = value
	}
	return m, nil
}

type wbaCtx struct {
	method, authority, path, scheme, query, requestTarget string
	rawURL                                                string
	headers                                               map[string]string
}

var wbaSpecialSchemes = map[string]bool{"http": true, "https": true, "ws": true, "wss": true, "ftp": true}

// wbaURL is a special-scheme URL as the WHATWG parser reads it.
type wbaURL struct {
	whatwgURL
	search   string  // "" or "?" + the percent-encoded query
	hasQuery bool    // a `?` starts a query (even an empty one)
	fragment *string // the text after `#`, as written
	creds    bool
}

func wbaParseURL(raw any) (*wbaURL, error) {
	s, ok := raw.(string)
	if !ok {
		return nil, errors.New("Invalid URL")
	}
	u, err := whatwgParse(s)
	if err != nil || !wbaSpecialSchemes[u.scheme] {
		return nil, errors.New("Invalid URL")
	}
	text := strings.NewReplacer("\t", "", "\n", "", "\r", "").Replace(strings.TrimFunc(wellFormedUTF8(s), func(r rune) bool { return r <= 0x20 }))
	out := &wbaURL{whatwgURL: u}
	nofrag := text
	if h := strings.IndexByte(text, '#'); h >= 0 {
		frag := text[h+1:]
		out.fragment = &frag
		nofrag = text[:h]
	}
	if q := strings.IndexByte(nofrag, '?'); q >= 0 {
		out.hasQuery = true
		if query := nofrag[q+1:]; query != "" {
			out.search = "?" + wbaPct(query, `"#<>'`)
		}
	}
	auth := strings.TrimLeft(text[strings.IndexByte(text, ':')+1:], `/\`)
	if e := strings.IndexAny(auth, `/\?#`); e >= 0 {
		auth = auth[:e]
	}
	out.creds = strings.Contains(auth, "@")
	return out, nil
}

// wbaPct percent-encodes controls, the space, everything above `~` and the bytes of set.
func wbaPct(s, set string) string {
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= 0x20 || c >= 0x7f || strings.IndexByte(set, c) >= 0 {
			fmt.Fprintf(&sb, "%%%02X", c)
		} else {
			sb.WriteByte(c)
		}
	}
	return sb.String()
}

// href is `new URL(url).href`; a URL with credentials is refused.
func (u *wbaURL) href() (string, error) {
	if u.creds {
		return "", errors.New("a URL with credentials is not supported")
	}
	out := u.scheme + "://" + u.host + u.pathname + u.search
	if u.hasQuery && u.search == "" {
		out += "?"
	}
	if u.fragment != nil {
		out += "#" + wbaPct(*u.fragment, "\"<>`")
	}
	return out, nil
}

func wbaBuildContext(method, rawURL any, headers map[string]string) (*wbaCtx, error) {
	u, err := wbaParseURL(rawURL)
	if err != nil {
		return nil, err
	}
	m, ok := method.(string)
	if !ok {
		return nil, errors.New("method.toUpperCase is not a function")
	}
	path := u.pathname
	if path == "" {
		path = "/"
	}
	query := u.search
	if query == "" {
		query = "?"
	}
	return &wbaCtx{
		method: strings.ToUpper(m), authority: strings.ToLower(u.host), path: path, rawURL: rawURL.(string),
		scheme: strings.ToLower(u.scheme), query: query, requestTarget: path + u.search, headers: headers,
	}, nil
}

// wbaDictionaryMember is RFC 9421 section 2.1.2: the serialized value of dictionary member key of a Structured Field dictionary
// header. Only string-valued members with canonical, compact parameters are supported; anything else fails closed.
func wbaDictionaryMember(header, key, headerName string) (string, error) {
	for _, memberRaw := range wbaSplitTopLevel(header, ',') {
		member := wbaTrim(memberRaw)
		eq := wbaIndexTopLevel(member, '=')
		if eq == -1 || wbaTrim(member[:eq]) != key {
			continue
		}
		value := wbaTrim(member[eq+1:])
		_, next, err := wbaReadSfString(value, 0)
		if err != nil {
			return "", err
		}
		if !wbaMemberParamsRe.MatchString(value[next:]) {
			return "", fmt.Errorf(`member "%s" of "%s" is not in canonical form`, key, headerName)
		}
		return value, nil
	}
	return "", fmt.Errorf(`"%s" has no dictionary member "%s"`, headerName, key)
}

func wbaDeriveComponent(c wbaComponent, ctx *wbaCtx) (string, error) {
	switch c.id {
	case "@method":
		return ctx.method, nil
	case "@authority":
		return ctx.authority, nil
	case "@path":
		return ctx.path, nil
	case "@target-uri":
		u, err := wbaParseURL(ctx.rawURL)
		if err != nil {
			return "", err
		}
		return u.href()
	case "@scheme":
		return ctx.scheme, nil
	case "@query":
		return ctx.query, nil
	case "@request-target":
		return ctx.requestTarget, nil
	}
	if strings.HasPrefix(c.id, "@") {
		return "", fmt.Errorf(`unsupported derived component "%s"`, c.id)
	}
	v, has := ctx.headers[c.id]
	if !has {
		return "", fmt.Errorf(`covered header "%s" is absent from the request`, c.id)
	}
	if c.key != nil {
		return wbaDictionaryMember(v, *c.key, c.id)
	}
	return v, nil
}

func wbaSignatureBase(comps []wbaComponent, paramsRaw string, ctx *wbaCtx) (string, error) {
	lines := make([]string, 0, len(comps)+1)
	for _, c := range comps {
		v, err := wbaDeriveComponent(c, ctx)
		if err != nil {
			return "", err
		}
		lines = append(lines, c.raw+": "+v)
	}
	lines = append(lines, `"@signature-params": `+paramsRaw)
	return strings.Join(lines, "\n"), nil
}

// ---- signing ------------------------------------------------------------------------------------------------------------

// wbaIterStrings is `for (const x of v)` over a JSON value that must yield strings: an array, or a string by character.
func wbaIterStrings(v any, what string) ([]string, error) {
	switch t := v.(type) {
	case nil:
		return nil, nil
	case []any:
		out := make([]string, len(t))
		for i, x := range t {
			s, ok := x.(string)
			if !ok {
				return nil, fmt.Errorf("%s must hold strings", what)
			}
			out[i] = s
		}
		return out, nil
	case string:
		var out []string
		for _, r := range t {
			out = append(out, string(r))
		}
		return out, nil
	}
	return nil, fmt.Errorf("%s is not iterable", what)
}

// wbaSign builds the signature over input; entries are the request headers (in member order) and cover the extra header names to cover.
func wbaSign(in map[string]any, entries []wbaKV, cover []string) (map[string]any, error) {
	label := WebBotAuthDefaultSignatureLabel
	if v := in["label"]; v != nil {
		label = jsValueString(v)
	}
	created, err := wbaNumber(in, "created", wbaNowSec())
	if err != nil {
		return nil, err
	}
	life, err := wbaNumber(in, "expiresInSec", WebBotAuthDefaultExpiresSec)
	if err != nil {
		return nil, err
	}
	expires := created + life

	working, err := wbaNormalizeHeaders(entries)
	if err != nil {
		return nil, err
	}
	emitted := map[string]any{}

	derived := []string{"@authority", "@method", "@path"}
	if c, has := in["components"]; has && c != nil {
		l, ok := c.([]any)
		if !ok {
			return nil, errors.New("components is not an array")
		}
		derived = derived[:0]
		for _, x := range l {
			s, ok := x.(string)
			if !ok {
				return nil, errors.New("id.toLowerCase is not a function")
			}
			derived = append(derived, s)
		}
	} else if !has {
		// a URL with a query string also covers @query by default (the verifier requires it)
		u, ok := in["url"].(string)
		if !ok {
			return nil, errors.New("Invalid URL")
		}
		for i := 0; i+1 < len(u); i++ {
			if u[i] == '?' && u[i+1] != '#' {
				derived = append(derived, "@query")
				break
			}
		}
	}
	hasAuthority := false
	for _, id := range derived {
		hasAuthority = hasAuthority || id == "@authority"
	}
	if !hasAuthority {
		return nil, errors.New("signRequest: the web-bot-auth profile requires @authority to be covered")
	}
	var comps []wbaComponent
	for _, id := range derived {
		lower := strings.ToLower(id)
		if !strings.HasPrefix(lower, "@") {
			return nil, fmt.Errorf(`signRequest: components must be derived components, got "%s" (use coverHeaders for headers)`, id)
		}
		comps = append(comps, wbaComponent{id: lower, raw: `"` + lower + `"`})
	}

	signatureAgent := ""
	agentURL, hasAgent := in["agentDirectoryUrl"]
	agentKey, hasKey := in["agentDirectoryKey"]
	if hasAgent {
		u, ok := agentURL.(string)
		if !ok {
			return nil, errors.New("s.replace is not a function")
		}
		if !hasKey {
			signatureAgent = wbaSfString(u)
			comps = append(comps, wbaComponent{id: "signature-agent", raw: `"signature-agent"`})
		} else {
			k, ok := agentKey.(string)
			if !ok {
				return nil, errors.New("s.replace is not a function")
			}
			signatureAgent = k + "=" + wbaSfString(u)
			comps = append(comps, wbaComponent{id: "signature-agent", raw: `"signature-agent";key=` + wbaSfString(k), key: &k})
		}
		working["signature-agent"] = signatureAgent
		emitted[WebBotAuthSignatureAgentHeader] = signatureAgent
	} else if hasKey {
		return nil, errors.New("signRequest: agentDirectoryKey requires agentDirectoryUrl")
	}

	for _, name := range cover {
		lower := strings.ToLower(name)
		if _, has := working[lower]; !has {
			return nil, fmt.Errorf(`signRequest: covered header "%s" is not present in headers`, name)
		}
		dup := false
		for _, c := range comps {
			dup = dup || c.id == lower
		}
		if !dup {
			comps = append(comps, wbaComponent{id: lower, raw: `"` + lower + `"`})
		}
	}

	ctx, err := wbaBuildContext(in["method"], in["url"], working)
	if err != nil {
		return nil, err
	}

	// the parameter order follows the examples of the Web Bot Auth architecture draft: created, keyid, alg, expires, nonce, tag
	raws := make([]string, len(comps))
	for i, c := range comps {
		raws[i] = c.raw
	}
	keyid, ok := in["keyid"].(string)
	if !ok {
		return nil, errors.New("s.replace is not a function")
	}
	paramsRaw := "(" + strings.Join(raws, " ") + ");created=" + jsLenientNumber(created) + ";keyid=" + wbaSfString(keyid) +
		";alg=" + wbaSfString(WebBotAuthAlg) + ";expires=" + jsLenientNumber(expires)
	if n, has := in["nonce"]; has {
		s, ok := n.(string)
		if !ok {
			return nil, errors.New("s.replace is not a function")
		}
		paramsRaw += ";nonce=" + wbaSfString(s)
	}
	paramsRaw += ";tag=" + wbaSfString(WebBotAuthTag)

	base, err := wbaSignatureBase(comps, paramsRaw, ctx)
	if err != nil {
		return nil, err
	}
	kp, err := wbaKeyPair(in["key"])
	if err != nil {
		return nil, err
	}
	sig := kp.Sign(wbaUTF8(base))

	signatureInput := label + "=" + paramsRaw
	signature := label + "=:" + base64.StdEncoding.EncodeToString(sig) + ":"
	emitted["Signature-Input"] = signatureInput
	emitted["Signature"] = signature
	covered := make([]any, len(comps))
	for i, c := range comps {
		covered[i] = c.id
	}
	out := map[string]any{"signatureInput": signatureInput, "signature": signature, "covered": covered, "headers": emitted}
	if hasAgent {
		out["signatureAgent"] = signatureAgent
	}
	return out, nil
}

// WebBotAuthSign builds the Signature-Input and Signature header values over the RFC 9421 base (@authority @method @path, plus
// @query when the URL has a query string, the Signature-Agent component and any coverHeaders). input: method, url, headers, key
// (a *KeyPair, a 32-byte seed or {"secretKey": seed}), keyid, created, expiresInSec, agentDirectoryUrl, agentDirectoryKey,
// components, coverHeaders, nonce, label. The result is {signatureInput, signature, signatureAgent?, covered, headers}.
func WebBotAuthSign(input map[string]any) (map[string]any, error) {
	if input == nil {
		return nil, errors.New("Cannot read properties of null (reading 'label')")
	}
	cover, err := wbaIterStrings(input["coverHeaders"], "coverHeaders")
	if err != nil {
		return nil, err
	}
	return wbaSign(input, wbaEntries(input["headers"]), cover)
}

// ---- verification -------------------------------------------------------------------------------------------------------

// WebBotAuthReplayCache is the single-use store for accepted signatures: Claim atomically claims key until expiresAtSec and
// reports whether this is the first use. A claim that fails refuses the request.
type WebBotAuthReplayCache interface {
	Claim(key string, expiresAtSec, nowSec float64) (bool, error)
}

// WebBotAuthMemoryReplayCache is the in-process replay cache. It fails CLOSED (an error) when maxEntries unexpired claims are held.
type WebBotAuthMemoryReplayCache struct {
	mu   sync.Mutex
	seen map[string]float64
	max  int
}

// NewWebBotAuthMemoryReplayCache returns a replay cache holding at most maxEntries claims (default 100000).
func NewWebBotAuthMemoryReplayCache(maxEntries ...int) *WebBotAuthMemoryReplayCache {
	m := 100_000
	if len(maxEntries) > 0 {
		m = maxEntries[0]
	}
	return &WebBotAuthMemoryReplayCache{seen: map[string]float64{}, max: m}
}

// Claim implements WebBotAuthReplayCache.
func (c *WebBotAuthMemoryReplayCache) Claim(key string, expiresAtSec, nowSec float64) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.seen) >= c.max {
		for k, exp := range c.seen {
			if finite(nowSec) && exp < nowSec {
				delete(c.seen, k)
			}
		}
		if len(c.seen) >= c.max {
			return false, errors.New("replay cache full")
		}
	}
	if existing, has := c.seen[key]; has && !(finite(nowSec) && existing < nowSec) {
		return false, nil
	}
	c.seen[key] = expiresAtSec
	return true, nil
}

// wbaXFromResolved is the base64url `x` of a resolved key: 32 raw bytes or a public Ed25519 OKP JWK; false for anything else.
func wbaXFromResolved(k any) (string, bool) {
	switch t := k.(type) {
	case []byte:
		if len(t) == 32 {
			return b64.EncodeToString(t), true
		}
	case map[string]any:
		if x, ok := t["x"].(string); ok && t["crv"] == "Ed25519" && t["kty"] == "OKP" {
			return x, true
		}
	}
	return "", false
}

// wbaResolveFromJwks resolves keyid in a key directory, honoring a published validity window (a bound that is present but not a
// finite number cannot be checked, so the key resolves to nothing).
func wbaResolveFromJwks(keyid string, jwks any, now, skew float64) (string, bool, error) {
	jm, _ := jwks.(map[string]any)
	keys, ok := jm["keys"].([]any)
	if !ok {
		return "", false, errors.New("opts.jwks.keys.find is not a function")
	}
	var match map[string]any
	for _, j := range keys {
		if j == nil {
			return "", false, errors.New("Cannot read properties of null (reading 'kid')")
		}
		if m, ok := j.(map[string]any); ok && m["kid"] == keyid {
			match = m
			break
		}
	}
	if match == nil {
		return "", false, nil
	}
	var bounds [2]float64
	var has [2]bool
	for i, name := range []string{"nbf", "exp"} {
		v, present := match[name]
		if !present {
			continue
		}
		f, ok := jsNum(v)
		if !ok || math.IsNaN(f) || math.IsInf(f, 0) {
			return "", false, nil
		}
		bounds[i], has[i] = f, true
	}
	if has[0] && now+skew < bounds[0] {
		return "", false, nil
	}
	if has[1] && now-skew > bounds[1] {
		return "", false, nil
	}
	x, ok := wbaXFromResolved(match)
	return x, ok, nil
}

func wbaEdVerifyX(x string, msg, sig []byte) bool {
	if len(sig) != 64 {
		return false
	}
	pub := wbaNodeB64(x)
	return len(pub) == 32 && VerifyStrict(pub, msg, sig)
}

func wbaStrEq(a any, b any) bool {
	x, ok1 := a.(string)
	y, ok2 := b.(string)
	return ok1 && ok2 && x == y
}

// wbaIterAny is `for (const x of v)` over a JSON value: an array, or a string by character.
func wbaIterAny(v any) ([]any, error) {
	switch t := v.(type) {
	case []any:
		return t, nil
	case string:
		var out []any
		for _, r := range t {
			out = append(out, string(r))
		}
		return out, nil
	}
	return nil, errors.New("requiredComponents is not iterable")
}

func wbaVerify(req, opts map[string]any) (map[string]any, error) {
	fail := func(reason string) (map[string]any, error) {
		return map[string]any{"valid": false, "reason": reason}, nil
	}
	resolve, jwks := opts["resolveKey"], opts["jwks"]
	if !jsTruthy(resolve) && !jsTruthy(jwks) {
		return fail("verifySignedRequest: provide resolveKey or jwks")
	}
	headers, err := wbaNormalizeHeaders(wbaEntries(req["headers"]))
	if err != nil {
		return nil, err
	}
	sigInputHeader, ok1 := headers["signature-input"]
	sigHeader, ok2 := headers["signature"]
	if !ok1 || !ok2 {
		return fail("missing Signature-Input or Signature header")
	}
	inputs, err := wbaParseSignatureInput(sigInputHeader)
	if err != nil {
		return nil, err
	}
	sigs, err := wbaParseSignature(sigHeader)
	if err != nil {
		return nil, err
	}
	var requiredTag any = WebBotAuthTag
	if v, has := opts["requiredTag"]; has {
		requiredTag = v
	}

	var chosen *wbaSigInput
	switch label, hasLabel := opts["label"]; {
	case hasLabel:
		for i := range inputs {
			if wbaStrEq(inputs[i].label, label) {
				chosen = &inputs[i]
				break
			}
		}
	case requiredTag != nil:
		for i := range inputs {
			if wbaStrEq(inputs[i].params["tag"], requiredTag) {
				chosen = &inputs[i]
				break
			}
		}
		if chosen == nil && len(inputs) > 0 {
			chosen = &inputs[0]
		}
	case len(inputs) > 0:
		chosen = &inputs[0]
	}
	if chosen == nil {
		return fail("no matching signature in Signature-Input")
	}
	sigBytes, has := sigs[chosen.label]
	if !has {
		return fail(fmt.Sprintf(`no Signature entry for label "%s"`, chosen.label))
	}

	tag, hasTag := chosen.params["tag"].(string)
	if requiredTag != nil && !(hasTag && wbaStrEq(tag, requiredTag)) {
		shown := "undefined"
		if hasTag {
			shown = tag
		}
		return fail(fmt.Sprintf(`tag "%s" does not match required "%s"`, shown, jsValueString(requiredTag)))
	}

	// @authority is required by the profile; @method and @path too, so a signature cannot be replayed on another method or path
	covered := map[string]bool{}
	for _, c := range chosen.comps {
		covered[c.id] = true
	}
	required := []any{"@authority", "@method", "@path"}
	reqComp, hasReqComp := opts["requiredComponents"]
	if hasReqComp && reqComp != nil {
		if required, err = wbaIterAny(reqComp); err != nil {
			return nil, err
		}
	}
	for _, id := range required {
		if s, ok := id.(string); !ok || !covered[s] {
			return fail(jsValueString(id) + " is not a covered component")
		}
	}
	if !hasReqComp {
		u, ok := req["url"].(string)
		if !ok {
			return nil, errors.New("req.url.indexOf is not a function")
		}
		if q := strings.IndexByte(u, '?'); q >= 0 {
			query, _, _ := strings.Cut(u[q+1:], "#")
			if query != "" && !covered["@query"] {
				return fail("@query is not a covered component")
			}
		}
	}

	if alg, has := chosen.params["alg"]; has && !wbaStrEq(alg, WebBotAuthAlg) {
		return fail(fmt.Sprintf(`unsupported alg "%s"`, jsValueString(alg)))
	}

	now, err := wbaNumber(opts, "now", wbaNowSec())
	if err != nil {
		return nil, err
	}
	skew, err := wbaNumber(opts, "clockSkewSec", 0)
	if err != nil {
		return nil, err
	}
	created, hasCreated := chosen.params["created"].(float64)
	expires, hasExpires := chosen.params["expires"].(float64)
	if rx, has := opts["requireExpires"].(bool); !hasExpires && !(has && !rx) {
		return fail("missing expires parameter")
	}
	if hasExpires && !(finite(now) && finite(skew) && now <= expires+skew) {
		return fail("signature has expired")
	}
	if hasCreated && !(finite(now) && finite(skew) && created <= now+skew) {
		return fail("signature created-time is in the future")
	}
	if v, has := opts["maxAgeSec"]; has && hasCreated {
		maxAge := 0.0 // null counts as 0, as in `null + skew`
		if v != nil {
			f, ok := jsNum(v)
			if !ok {
				return nil, errors.New("maxAgeSec must be a number")
			}
			maxAge = f
		}
		if !(finite(now) && finite(created) && finite(skew) && now-created <= maxAge+skew) {
			return fail("signature is older than maxAgeSec")
		}
	}
	maxLifetime, err := wbaNumber(opts, "maxLifetimeSec", 300)
	if err != nil {
		return nil, err
	}
	finiteLife := !math.IsInf(maxLifetime, 0) && !math.IsNaN(maxLifetime)
	if finiteLife {
		if !hasCreated {
			return fail("missing created parameter (needed to bound the signature lifetime)")
		}
		if hasExpires && expires-created > maxLifetime {
			return fail("signature lifetime exceeds maxLifetimeSec")
		}
	}

	keyid, ok := chosen.params["keyid"].(string)
	if !ok {
		return fail("missing keyid parameter")
	}
	var x string
	var found bool
	if jsTruthy(resolve) {
		fn, ok := resolve.(func(string) (any, error))
		if !ok {
			return nil, errors.New("opts.resolveKey is not a function")
		}
		k, err := fn(keyid)
		if err != nil {
			return nil, err
		}
		x, found = wbaXFromResolved(k)
	} else if x, found, err = wbaResolveFromJwks(keyid, jwks, now, skew); err != nil {
		return nil, err
	}
	if !found {
		return fail(fmt.Sprintf(`could not resolve key "%s"`, keyid))
	}

	ctx, err := wbaBuildContext(req["method"], req["url"], headers)
	if err != nil {
		return nil, err
	}
	base, err := wbaSignatureBase(chosen.comps, chosen.paramsRaw, ctx)
	if err != nil {
		return nil, err
	}
	if !wbaEdVerifyX(x, wbaUTF8(base), sigBytes) {
		return fail("signature does not verify under the resolved key")
	}

	nonce, hasNonce := chosen.params["nonce"].(string)
	if cache := opts["replayCache"]; jsTruthy(cache) {
		rc, ok := cache.(WebBotAuthReplayCache)
		if !ok {
			return nil, errors.New("opts.replayCache.claim is not a function")
		}
		until := now + 3600
		switch {
		case hasExpires:
			until = expires
		case hasCreated:
			until = created + 3600
			if finiteLife {
				until = created + maxLifetime
			}
		}
		id := b64.EncodeToString(sigBytes)
		if hasNonce {
			id = nonce
		}
		first, err := rc.Claim(keyid+"|"+id, until+skew, now)
		if err != nil {
			return nil, err
		}
		if !first {
			return fail("replayed signature")
		}
	}
	coveredIDs := make([]any, len(chosen.comps))
	for i, c := range chosen.comps {
		coveredIDs[i] = c.id
	}
	out := map[string]any{"valid": true, "label": chosen.label, "keyid": keyid, "covered": coveredIDs}
	if hasCreated {
		out["created"] = jsNumber(created)
	}
	if hasExpires {
		out["expires"] = jsNumber(expires)
	}
	if hasTag {
		out["tag"] = tag
	}
	if hasNonce {
		out["nonce"] = nonce
	}
	return out, nil
}

// WebBotAuthVerify verifies an RFC 9421 signature over req = {method, url, headers}. opts: resolveKey (func(keyid string)
// (any, error): 32 raw bytes, a public JWK map or nil) or jwks ({"keys": [...]}), now, clockSkewSec, maxAgeSec, requireExpires
// (default true), requiredTag (default "web-bot-auth"; nil = not enforced), label, requiredComponents (default @authority @method
// @path, plus @query when the URL has a query string), maxLifetimeSec (default 300; +Inf disables) and replayCache (a
// WebBotAuthReplayCache). It never fails open: any problem is {"valid": false, "reason": ...}.
func WebBotAuthVerify(req, opts map[string]any) map[string]any {
	out, err := wbaVerify(req, opts)
	if err != nil {
		return map[string]any{"valid": false, "reason": "verification failed (fail closed): " + err.Error()}
	}
	return out
}

// ---- PCA proof binding --------------------------------------------------------------------------------------------------

// WebBotAuthProofHeaders is the PCA-Action header carrying a PCActn (base64url of its canonical wire form).
func WebBotAuthProofHeaders(pcactn any) (map[string]string, error) {
	s, ok := canonicalLenient(pcactn)
	if !ok {
		return nil, errors.New("canonicalize: unsupported type")
	}
	return map[string]string{WebBotAuthPCAHeader: b64.EncodeToString([]byte(s))}, nil
}

// WebBotAuthDecodeProofHeader reverses WebBotAuthProofHeaders: the PCA-Action header value to the PCActn.
func WebBotAuthDecodeProofHeader(value string) (map[string]any, error) {
	text, err := DecodePCAHeader(value)
	if err != nil {
		return nil, err
	}
	return ParsePCActn(text)
}

// WebBotAuthSignWithProof signs a request AND binds it to a PCActn: the PCActn goes in the PCA-Action header, which is a covered
// component, so the one request is bot-verifiable and carries tamper-evident proof of authority. input is the WebBotAuthSign input
// plus pcactn; the result is the sign result with the proof header merged into headers, and proofHeader.
func WebBotAuthSignWithProof(input map[string]any) (map[string]any, error) {
	if input == nil {
		return nil, errors.New("Cannot read properties of null (reading 'pcactn')")
	}
	pcactn, has := input["pcactn"]
	if !has {
		return nil, errors.New("canonicalize: unsupported type undefined")
	}
	proof, err := WebBotAuthProofHeaders(pcactn)
	if err != nil {
		return nil, err
	}
	entries := append(wbaEntries(input["headers"]), wbaKV{WebBotAuthPCAHeader, proof[WebBotAuthPCAHeader]})
	cover, err := wbaIterStrings(input["coverHeaders"], "coverHeaders")
	if err != nil {
		return nil, err
	}
	cover = append(cover, WebBotAuthPCAProofComponent)
	rest := agentcardCopy(input)
	delete(rest, "pcactn")
	res, err := wbaSign(rest, entries, cover)
	if err != nil {
		return nil, err
	}
	headers := agentcardCopy(res["headers"].(map[string]any))
	headers[WebBotAuthPCAHeader] = proof[WebBotAuthPCAHeader]
	res["headers"] = headers
	res["proofHeader"] = map[string]any{WebBotAuthPCAHeader: proof[WebBotAuthPCAHeader]}
	return res, nil
}

// WebBotAuthVerifyWithProof verifies the HTTP Message Signature AND extracts the proof: PCA-Action must be a covered component;
// opts["expectedPCActn"], when present, must equal the carried PCActn by canonical digest. The returned pcactn is bound to the
// verified signature. An error is returned only where the expected PCActn has no canonical digest.
func WebBotAuthVerifyWithProof(req, opts map[string]any) (map[string]any, error) {
	base := WebBotAuthVerify(req, opts)
	if base["valid"] != true {
		return base, nil
	}
	fail := func(reason string) (map[string]any, error) {
		return map[string]any{"valid": false, "reason": reason}, nil
	}
	isCovered := false
	for _, c := range base["covered"].([]any) {
		isCovered = isCovered || c == WebBotAuthPCAProofComponent
	}
	if !isCovered {
		return fail("the PCA-Action proof header is not covered by the signature")
	}
	headers, err := wbaNormalizeHeaders(wbaEntries(req["headers"]))
	if err != nil {
		return nil, err
	}
	value, has := headers[WebBotAuthPCAProofComponent]
	if !has {
		return fail("missing PCA-Action header")
	}
	pcactn, err := WebBotAuthDecodeProofHeader(value)
	if err != nil {
		return fail("invalid PCActn in PCA-Action: " + err.Error())
	}
	if want, has := opts["expectedPCActn"]; has {
		got, err := HashCanonical(pcactn)
		if err != nil {
			return nil, err
		}
		exp, err := HashCanonical(want)
		if err != nil {
			return nil, err
		}
		if got != exp {
			return fail("carried PCActn does not match the expected proof")
		}
	}
	out := agentcardCopy(base)
	out["pcactn"] = pcactn
	return out, nil
}
