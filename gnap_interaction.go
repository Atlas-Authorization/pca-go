package pca

// GNAP interaction modes (RFC 9635 sections 2.5, 3.3, 4, 5.1): the start modes, the finish methods, the interaction hash,
// single-use interaction references and the authorization-server state machine (pending -> approved -> finalized). Refusals
// are *CodedError with the reference InteractionError code (invalid_interaction, unknown_interaction, too_many_attempts,
// invalid_request, expired, wrong_state, unsupported_hash).

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"crypto/subtle"
	"errors"
	"hash"
	"strings"
	"unicode/utf8"
)

var (
	// GnapStartModes are the interaction start modes this implementation knows.
	GnapStartModes = []string{"redirect", "app", "user_code", "user_code_uri"}
	// GnapFinishMethods are the interaction finish methods.
	GnapFinishMethods = []string{"redirect", "push"}
	// GnapHashMethods are the Named Information hash names computed for the interaction hash.
	GnapHashMethods = []string{"sha-256", "sha-384", "sha-512", "sha3-256", "sha3-512"}
)

var gnapHashes = map[string]func() hash.Hash{"sha-256": sha256.New, "sha-384": sha512.New384, "sha-512": sha512.New,
	"sha3-256": func() hash.Hash { return sha3.New256() }, "sha3-512": func() hash.Hash { return sha3.New512() }}

// gnapProtoNames are the names a JavaScript `in` test on the reference's method table also finds (Object.prototype members).
var gnapProtoNames = setOf("constructor", "__defineGetter__", "__defineSetter__", "hasOwnProperty", "__lookupGetter__",
	"__lookupSetter__", "isPrototypeOf", "propertyIsEnumerable", "toString", "valueOf", "__proto__", "toLocaleString")

func gnapInHashMethods(v any) bool {
	k := jsValueString(v)
	return gnapHashes[k] != nil || gnapProtoNames[k]
}

func gnapInteractionErr(code, msg string) error { return &CodedError{Code: code, Msg: msg} }

func gnapStartName(e any) (string, bool) {
	switch t := e.(type) {
	case string:
		return t, true
	case map[string]any:
		m, ok := t["mode"].(string)
		return m, ok
	}
	return "", false
}

// GnapCallbackURIOk is RFC 9635 2.5.2: an absolute URI without a fragment; HTTPS, plain HTTP only to a loopback host, or an
// application-specific scheme (never javascript:, data:, file: or blob:).
func GnapCallbackURIOk(uri any) bool {
	s, ok := uri.(string)
	if !ok || jsLen(s) > 2048 || strings.Contains(s, "#") {
		return false
	}
	u, err := whatwgParse(s)
	if err != nil {
		return false
	}
	switch u.scheme {
	case "https":
		return true
	case "http":
		h := u.host
		if strings.HasPrefix(h, "[") {
			h = h[:strings.IndexByte(h, ']')+1]
		} else if i := strings.LastIndexByte(h, ':'); i >= 0 {
			h = h[:i]
		}
		return h == "localhost" || h == "127.0.0.1" || h == "[::1]"
	}
	return u.scheme != "javascript" && u.scheme != "data" && u.scheme != "file" && u.scheme != "blob"
}

// GnapValidateInteractRequest validates an `interact` request and returns the problems (empty = valid). Unknown start modes
// are tolerated (the registry is open).
func GnapValidateInteractRequest(r any) []string {
	e := []string{}
	o, ok := r.(map[string]any)
	if !ok {
		return []string{"interact must be an object"}
	}
	start, ok := o["start"].([]any)
	if !ok || len(start) == 0 || len(start) > 16 {
		e = append(e, "start must be a non-empty array of modes")
	} else {
		for _, s := range start {
			if _, ok := gnapStartName(s); !ok {
				e = append(e, "each start entry is a mode name or an object with a mode")
			}
		}
	}
	if f, has := o["finish"]; has {
		_, isObj := f.(map[string]any)
		if !isObj && !isArray(f) {
			return append(e, "finish must be an object")
		}
		method, _ := gnapMember(f, "method")
		if m, ok := method.(string); !ok || m != "redirect" && m != "push" {
			e = append(e, "finish.method must be redirect or push")
		}
		if u, _ := gnapMember(f, "uri"); !GnapCallbackURIOk(u) {
			e = append(e, "finish.uri must be an absolute https, loopback or app-scheme URI without a fragment")
		}
		if n, ok := gnapMemberStr(f, "nonce"); !ok || jsLen(n) < 8 || jsLen(n) > 256 || !gnapPrintable(n) {
			e = append(e, "finish.nonce must be 8..256 printable ASCII characters")
		}
		if hm, has := gnapMember(f, "hash_method"); has && !gnapInHashMethods(hm) {
			e = append(e, "finish.hash_method is not a supported Named Information hash")
		}
	}
	return e
}

func gnapPrintable(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return s != ""
}

// gnapASCII is Node's 'ascii' string encoding: the low byte of each UTF-16 code unit.
func gnapASCII(s string) []byte {
	u := utf16Units(s)
	b := make([]byte, len(u))
	for i, c := range u {
		b[i] = byte(c)
	}
	return b
}

// GnapInteractionHash is RFC 9635 4.2.3: base64url (no padding) of HASH(clientNonce \n asNonce \n interactRef \n grantEndpoint).
// a carries clientNonce, asNonce, interactRef, grantEndpoint and hashMethod (default sha-256).
func GnapInteractionHash(a map[string]any) (string, error) {
	var m any = "sha-256"
	if v, has := a["hashMethod"]; has && v != nil {
		m = v
	}
	if !gnapInHashMethods(m) {
		return "", gnapInteractionErr("unsupported_hash", "hash_method "+jsValueString(m)+" is not supported")
	}
	h := gnapHashes[jsValueString(m)]
	if h == nil {
		return "", errors.New("hash_method " + jsValueString(m) + " is not a hash algorithm")
	}
	text := jsMemberString(a, "clientNonce") + "\n" + jsMemberString(a, "asNonce") + "\n" + jsMemberString(a, "interactRef") + "\n" +
		jsMemberString(a, "grantEndpoint")
	d := h()
	d.Write(gnapASCII(text))
	return b64.EncodeToString(d.Sum(nil)), nil
}

// GnapVerifyInteractionHash is the client-side check of a callback hash (constant time). A hash that does not validate means
// the interact_ref must not be sent.
func GnapVerifyInteractionHash(received any, a map[string]any) (bool, error) {
	s, ok := received.(string)
	if !ok {
		return false, nil
	}
	want, err := GnapInteractionHash(a)
	if err != nil {
		return false, err
	}
	got := []byte(wellFormedUTF8(s))
	return len(want) == len(got) && subtle.ConstantTimeCompare([]byte(want), got) == 1, nil
}

const gnapCodeAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// GnapNewUserCode draws a user code of n characters (6..12) from an alphabet without look-alikes.
func GnapNewUserCode(n int) (string, error) {
	if n < 6 || n > 12 {
		return "", errors.New("user code length 6..12")
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = gnapCodeAlphabet[b[i]%32] // 256 % 32 == 0: no modulo bias
	}
	return string(b), nil
}

// gnapNormCode is c.replace(/[\s-]/g, ”).toUpperCase().
func gnapNormCode(c string) string {
	var sb strings.Builder
	for _, r := range c {
		if r == '-' || r == '\t' || r == '\n' || r == '\v' || r == '\f' || r == '\r' || r == ' ' || r == 0xa0 || r == 0x1680 ||
			r >= 0x2000 && r <= 0x200a || r == 0x2028 || r == 0x2029 || r == 0x202f || r == 0x205f || r == 0x3000 || r == 0xfeff {
			continue
		}
		sb.WriteRune(r)
	}
	return jsUpper(sb.String())
}

// GnapAcceptFinish validates a finish callback ({hash, interact_ref}) against the client's context (clientNonce, asNonce,
// grantEndpoint, hashMethod?) and returns the interact_ref to send.
func GnapAcceptFinish(cb any, ctx map[string]any) (string, error) {
	ref, ok := gnapMemberStr(cb, "interact_ref")
	h, okH := gnapMember(cb, "hash")
	if _, isS := h.(string); !ok || ref == "" || !okH || !isS {
		return "", gnapInteractionErr("unknown_interaction", "hash and interact_ref are required")
	}
	a := copyMap(ctx)
	a["interactRef"] = ref
	good, err := GnapVerifyInteractionHash(h, a)
	if err != nil {
		return "", err
	}
	if !good {
		return "", gnapInteractionErr("unknown_interaction", "the callback hash does not validate")
	}
	return ref, nil
}

// GnapAccessToNeeds turns access rights into needs, one per (action, location), resource gnap:<type>:<location>. A right
// without explicit actions and locations is refused (a need must be explicit).
func GnapAccessToNeeds(access []any) ([]any, error) {
	out := []any{}
	for _, a := range access {
		m, ok := a.(map[string]any)
		if !ok {
			return nil, errors.New("access entry is not an object")
		}
		acts, ok1 := gnapList(m, "actions")
		locs, ok2 := gnapList(m, "locations")
		if !ok1 || !ok2 {
			return nil, gnapInteractionErr("invalid_request", `access "`+jsMemberString(m, "type")+`" needs explicit actions and locations to become a need`)
		}
		for _, v := range acts {
			for _, l := range locs {
				out = append(out, map[string]any{"verb": v, "resource": "gnap:" + jsMemberString(m, "type") + ":" + jsValueString(l)})
			}
		}
	}
	return out, nil
}

// ---- the authorization-server state machine ----------------------------------------------------------------------------

// GnapInteractionFinish is an interaction's finish method with both nonces.
type GnapInteractionFinish struct {
	Method      string `json:"method"`
	URI         string `json:"uri"`
	ClientNonce string `json:"clientNonce"`
	AsNonce     string `json:"asNonce"`
	HashMethod  string `json:"hashMethod"`
}

// GnapInteraction is one interaction's state.
type GnapInteraction struct {
	ID            string                 `json:"id"`
	State         string                 `json:"state"` // pending | approved | finalized
	GrantEndpoint string                 `json:"grantEndpoint"`
	Modes         []string               `json:"modes"`
	Finish        *GnapInteractionFinish `json:"finish,omitempty"`
	UserCode      string                 `json:"userCode,omitempty"`
	InteractRef   string                 `json:"interactRef,omitempty"`
	RefUsed       bool                   `json:"refUsed"`
	ExpiresAt     float64                `json:"expiresAt"`
}

// GnapInteractionServerOptions configure the AS side. AppURI nil / UserCodeURI "" mean those modes are not offered.
type GnapInteractionServerOptions struct {
	GrantEndpoint string
	Supports      []string
	RedirectURI   func(id string) string
	AppURI        func(id string) string
	UserCodeURI   string
	TTLSec        *float64 // nil: 600
	Now           func() float64
}

// GnapInteractionServer is the AS side: the response never offers a mode the client did not ask for nor one the AS does not
// support, and each interact_ref is single use (a second presentation is too_many_attempts and finalizes the grant).
type GnapInteractionServer struct {
	o      GnapInteractionServerOptions
	byID   map[string]*GnapInteraction
	byCode map[string]string
	byRef  map[string]string
}

// NewGnapInteractionServer creates an interaction server.
func NewGnapInteractionServer(o GnapInteractionServerOptions) *GnapInteractionServer {
	return &GnapInteractionServer{o: o, byID: map[string]*GnapInteraction{}, byCode: map[string]string{}, byRef: map[string]string{}}
}

func gnapRandB64(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return b64.EncodeToString(b), nil
}

func gnapHas(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// Start begins an interaction for an `interact` request: the interaction and the interact response.
func (s *GnapInteractionServer) Start(req any) (*GnapInteraction, map[string]any, error) {
	if p := GnapValidateInteractRequest(req); len(p) > 0 {
		return nil, nil, gnapInteractionErr("invalid_request", strings.Join(p, "; "))
	}
	r := req.(map[string]any)
	asked := map[string]bool{}
	for _, e := range r["start"].([]any) {
		n, _ := gnapStartName(e)
		asked[n] = true
	}
	modes := []string{}
	for _, m := range s.o.Supports {
		if asked[m] && (m != "app" || s.o.AppURI != nil) && (m != "user_code_uri" || s.o.UserCodeURI != "") {
			modes = append(modes, m)
		}
	}
	finish, hasFinish := r["finish"].(map[string]any)
	if len(modes) == 0 && !hasFinish {
		return nil, nil, gnapInteractionErr("invalid_interaction", "no requested interaction mode is supported")
	}
	id, err := gnapRandB64(16)
	if err != nil {
		return nil, nil, err
	}
	ttl := 600.0
	if s.o.TTLSec != nil {
		ttl = *s.o.TTLSec
	}
	it := &GnapInteraction{ID: id, State: "pending", GrantEndpoint: s.o.GrantEndpoint, Modes: modes, ExpiresAt: s.o.Now() + ttl}
	res := map[string]any{"expires_in": jsNumber(ttl)}
	if gnapHas(modes, "redirect") {
		res["redirect"] = s.o.RedirectURI(id)
	}
	if gnapHas(modes, "app") {
		res["app"] = s.o.AppURI(id)
	}
	if gnapHas(modes, "user_code") || gnapHas(modes, "user_code_uri") {
		if it.UserCode, err = GnapNewUserCode(8); err != nil {
			return nil, nil, err
		}
		s.byCode[it.UserCode] = id
		if gnapHas(modes, "user_code") {
			res["user_code"] = it.UserCode
		}
		if gnapHas(modes, "user_code_uri") {
			res["user_code_uri"] = map[string]any{"code": it.UserCode, "uri": s.o.UserCodeURI}
		}
	}
	if hasFinish {
		asNonce, err := gnapRandB64(24)
		if err != nil {
			return nil, nil, err
		}
		hm, ok := finish["hash_method"].(string)
		if !ok {
			hm = "sha-256"
		}
		it.Finish = &GnapInteractionFinish{Method: finish["method"].(string), URI: finish["uri"].(string), ClientNonce: finish["nonce"].(string),
			AsNonce: asNonce, HashMethod: hm}
		res["finish"] = asNonce
	}
	s.byID[id] = it
	return it, res, nil
}

// LookupUserCode finds the pending interaction a resource owner's typed code names (case-insensitive, spaces and dashes
// ignored). A 32^8 code space is only safe behind a per-source rate limit on this lookup: the caller MUST apply one.
func (s *GnapInteractionServer) LookupUserCode(code string) *GnapInteraction {
	it := s.byID[s.byCode[gnapNormCode(code)]]
	if it == nil || it.State != "pending" || s.o.Now() > it.ExpiresAt {
		return nil
	}
	return it
}

// Get returns an interaction by id (nil when unknown).
func (s *GnapInteractionServer) Get(id string) *GnapInteraction { return s.byID[id] }

func (s *GnapInteractionServer) live(id string) (*GnapInteraction, error) {
	it := s.byID[id]
	if it == nil {
		return nil, gnapInteractionErr("unknown_interaction", "no such interaction")
	}
	if s.o.Now() > it.ExpiresAt {
		return nil, gnapInteractionErr("expired", "the interaction expired")
	}
	return it, nil
}

// Approve records the resource owner's approval and returns {interactRef, finish?}: the finish message to deliver, a
// redirect {method, url} or a push {method, uri, body: {hash, interact_ref}}.
func (s *GnapInteractionServer) Approve(id string) (map[string]any, error) {
	it, err := s.live(id)
	if err != nil {
		return nil, err
	}
	if it.State != "pending" {
		return nil, gnapInteractionErr("wrong_state", "interaction is "+it.State)
	}
	it.State = "approved"
	if it.InteractRef, err = gnapRandB64(18); err != nil {
		return nil, err
	}
	s.byRef[it.InteractRef] = id
	if it.UserCode != "" {
		delete(s.byCode, it.UserCode)
	}
	out := map[string]any{"interactRef": it.InteractRef}
	if it.Finish == nil {
		return out, nil
	}
	f := it.Finish
	h, err := GnapInteractionHash(map[string]any{"clientNonce": f.ClientNonce, "asNonce": f.AsNonce, "interactRef": it.InteractRef,
		"grantEndpoint": it.GrantEndpoint, "hashMethod": f.HashMethod})
	if err != nil {
		return nil, err
	}
	if f.Method == "push" {
		out["finish"] = map[string]any{"method": "push", "uri": f.URI, "body": map[string]any{"hash": h, "interact_ref": it.InteractRef}}
		return out, nil
	}
	u, err := gnapRedirectURL(f.URI, h, it.InteractRef)
	if err != nil {
		return nil, err
	}
	out["finish"] = map[string]any{"method": "redirect", "url": u}
	return out, nil
}

// Consume presents an interact_ref once (RFC 9635 5.1); a replay finalizes the grant and is too_many_attempts.
func (s *GnapInteractionServer) Consume(ref string) (*GnapInteraction, error) {
	it := s.byID[s.byRef[ref]]
	if it == nil {
		return nil, gnapInteractionErr("unknown_interaction", "no such interaction reference")
	}
	if it.RefUsed || it.State == "finalized" {
		it.State = "finalized"
		return nil, gnapInteractionErr("too_many_attempts", "the interaction reference was already used")
	}
	if s.o.Now() > it.ExpiresAt {
		return nil, gnapInteractionErr("expired", "the interaction expired")
	}
	if it.State != "approved" {
		return nil, gnapInteractionErr("wrong_state", "interaction is "+it.State)
	}
	it.RefUsed = true
	return it, nil
}

// Finalize ends an interaction.
func (s *GnapInteractionServer) Finalize(id string) {
	if it := s.byID[id]; it != nil {
		it.State = "finalized"
	}
}

// ---- the redirect callback URL ----------------------------------------------------------------------------------------------

const gnapUserinfoEnc = "\"#<>?`{}/:;=@[\\]^|"

func gnapPct(s, set string) string {
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x21 || c > 0x7e || strings.IndexByte(set, c) >= 0 {
			sb.WriteString("%" + strings.ToUpper(hexByte(c)))
			continue
		}
		sb.WriteByte(c)
	}
	return sb.String()
}

func hexByte(c byte) string {
	const h = "0123456789abcdef"
	return string([]byte{h[c>>4], h[c&15]})
}

func gnapFormDecode(s string) string {
	s = strings.ReplaceAll(s, "+", " ")
	b := percentDecodeLenient(s)
	if !utf8.Valid(b) {
		return strings.ToValidUTF8(string(b), "�")
	}
	return string(b)
}

// percentDecodeLenient is the WHATWG percent-decode: %XX with two hex digits becomes the byte, anything else stays.
func percentDecodeLenient(s string) []byte {
	out := make([]byte, 0, len(s))
	hexv := func(c byte) (byte, bool) {
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
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			hi, ok1 := hexv(s[i+1])
			lo, ok2 := hexv(s[i+2])
			if ok1 && ok2 {
				out = append(out, hi<<4|lo)
				i += 2
				continue
			}
		}
		out = append(out, s[i])
	}
	return out
}

func gnapFormEncode(s string) string {
	var sb strings.Builder
	for _, c := range []byte(wellFormedUTF8(s)) {
		switch {
		case c == ' ':
			sb.WriteByte('+')
		case c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '*' || c == '-' || c == '.' || c == '_':
			sb.WriteByte(c)
		default:
			sb.WriteString("%" + strings.ToUpper(hexByte(c)))
		}
	}
	return sb.String()
}

// gnapRedirectURL is `u = new URL(uri); u.searchParams.set('hash', h); u.searchParams.set('interact_ref', ref); u.toString()`
// for a URI GnapCallbackURIOk accepted (no fragment): the URL re-serialized, its query rebuilt as form-urlencoded pairs.
func gnapRedirectURL(uri, h, ref string) (string, error) {
	d, err := whatwgParse(uri)
	if err != nil {
		return "", err
	}
	s := strings.TrimFunc(uri, func(r rune) bool { return r <= 0x20 })
	s = strings.NewReplacer("\t", "", "\n", "", "\r", "").Replace(s)
	rest := s[strings.IndexByte(s, ':')+1:]
	rawQ := ""
	if q := strings.IndexByte(rest, '?'); q >= 0 {
		rawQ, rest = rest[q+1:], rest[:q]
	}
	_, special := whatwgDefaultPort[d.scheme]
	authority, hasAuth := "", false
	if special {
		rest = strings.TrimLeft(rest, `/\`)
		cut := strings.IndexAny(rest, `/\`)
		if cut < 0 {
			cut = len(rest)
		}
		authority, hasAuth = rest[:cut], true
	} else if strings.HasPrefix(rest, "//") {
		inner := rest[2:]
		cut := strings.IndexByte(inner, '/')
		if cut < 0 {
			cut = len(inner)
		}
		authority, hasAuth, rest = inner[:cut], true, inner[cut:]
	}
	out := d.scheme + ":"
	if hasAuth {
		out += "//"
		if at := strings.LastIndexByte(authority, '@'); at >= 0 {
			user, pw, _ := strings.Cut(authority[:at], ":")
			user, pw = gnapPct(user, gnapUserinfoEnc), gnapPct(pw, gnapUserinfoEnc)
			if user != "" || pw != "" {
				out += user
				if pw != "" {
					out += ":" + pw
				}
				out += "@"
			}
		}
		out += d.host
	}
	if !(hasAuth && !special && rest == "") {
		out += d.pathname
	}
	var pairs [][2]string
	for _, seg := range strings.Split(rawQ, "&") {
		if seg == "" {
			continue
		}
		n, v, _ := strings.Cut(seg, "=")
		pairs = append(pairs, [2]string{gnapFormDecode(n), gnapFormDecode(v)})
	}
	for _, nv := range [][2]string{{"hash", h}, {"interact_ref", ref}} {
		idx := -1
		kept := pairs[:0:0]
		for _, p := range pairs {
			if p[0] == nv[0] {
				if idx >= 0 {
					continue
				}
				idx = len(kept)
				p[1] = nv[1]
			}
			kept = append(kept, p)
		}
		if idx < 0 {
			kept = append(kept, nv)
		}
		pairs = kept
	}
	enc := make([]string, len(pairs))
	for i, p := range pairs {
		enc[i] = gnapFormEncode(p[0]) + "=" + gnapFormEncode(p[1])
	}
	return out + "?" + strings.Join(enc, "&"), nil
}
