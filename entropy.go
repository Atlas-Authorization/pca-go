package pca

// Quantum-random entropy as an ADD to key generation, never a trust dependency: every seed is HKDF-SHA256(local CSPRNG || quantum),
// so a hostile or broken quantum source cannot lower a seed below the strength of the local CSPRNG. Parts: an HTTP QRNG source (ANU
// style JSON, hex or base64 bodies; strict, fail-closed validation; https only; the API key never appears in an error), the
// unavailable-source stub, the SP 800-90B 4.4 continuous health tests (repetition count, adaptive proportion), the combiner
// MixEntropy, SecureSeed (CSPRNG plus a best-effort, health-tested QRNG) and an Ed25519 key-pair helper. The HTTP source has no
// network client of its own: the caller injects a QrngTransport.
// shortcut: Go's math.Pow is not the engine pow the reference uses; the adaptive-proportion cutoff could differ at a boundary by one
// where the binomial CDF lands within a few ulp of 1 - 2^-20, upgrade by porting the reference pow if a corpus case ever flips.

import (
	"context"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

const (
	// MaxHkdfOutput is the largest HKDF-SHA256 output (255 * 32 bytes, RFC 5869).
	MaxHkdfOutput = 255 * 32
	// MinLocalBytes is the smallest local CSPRNG input the combiner accepts: the safety argument rests on it, so a shorter one fails closed.
	MinLocalBytes = 16
	// DefaultSeedBytes is the default seed length (256 bit).
	DefaultSeedBytes = 32
	// DefaultMaxQrngBytes is the default per-request cap of an HTTP QRNG backend.
	DefaultMaxQrngBytes = 1024
	// DefaultQrngTimeoutMs is the default HTTP timeout of a QRNG fetch.
	DefaultQrngTimeoutMs = 5000
)

const (
	entropyMixLabel = "atlas-pca/entropy/mix/v1"
	entropyMixSalt  = "atlas-pca/entropy/salt/v1"
)

// EntropyError is the typed failure thrown only where a caller demanded quantum entropy or the transport is unsafe. Code is one of
// "quantum_required", "health_test_failed", "insecure_transport".
type EntropyError struct {
	Code string
	Msg  string
}

func (e *EntropyError) Error() string { return e.Msg }

// NewEntropyError builds an EntropyError (any code string is accepted).
func NewEntropyError(code, message string) *EntropyError {
	return &EntropyError{Code: code, Msg: message}
}

// QrngSource is a source of quantum random bytes: Fetch returns exactly n bytes or an error.
type QrngSource interface {
	// Name is a short, log-safe identifier of the backend (never a secret).
	Name() string
	Fetch(n int) ([]byte, error)
}

// NullQrngSource is the unavailable source: every Fetch fails.
type NullQrngSource struct{ reason string }

// NewNullQrngSource returns the unavailable source; the optional reason replaces "no QRNG source configured" (an empty reason is kept).
func NewNullQrngSource(reason ...string) *NullQrngSource {
	r := "no QRNG source configured"
	if len(reason) > 0 {
		r = reason[0]
	}
	return &NullQrngSource{reason: r}
}

// Name is "null-qrng".
func (*NullQrngSource) Name() string { return "null-qrng" }

// Fetch always fails with "QRNG unavailable: <reason>".
func (s *NullQrngSource) Fetch(int) ([]byte, error) {
	return nil, errors.New("QRNG unavailable: " + s.reason)
}

// UnavailableSource is the shared unavailable source (see NewNullQrngSource for the reason argument).
func UnavailableSource(reason ...string) QrngSource { return NewNullQrngSource(reason...) }

// QrngResponse is the part of an HTTP response the source reads. OK is the transport's own success flag (the status is only quoted).
type QrngResponse struct {
	OK     bool
	Status int
	// JSON decodes the body as JSON (the "anu-uint8" format); Text returns the body (the "hex" and "base64" formats).
	JSON func() (any, error)
	Text func() (string, error)
}

// QrngTransport performs one GET. The source always passes redirect "error" (a redirect must fail) and a context that carries the
// timeout; a transport must stop when the context ends.
type QrngTransport func(ctx context.Context, url string, headers map[string]string, redirect string) (*QrngResponse, error)

// QrngParam is one query parameter, in order.
type QrngParam struct{ Name, Value string }

// HttpQrngConfig configures an HttpQrngSource.
type HttpQrngConfig struct {
	// URL is the base endpoint; the requested length is added as a query parameter unless BuildURL is set.
	URL string
	// APIKey is sent as a header and never appears in an error.
	APIKey string
	// APIKeyHeader is the header name of the key (default "x-api-key").
	APIKeyHeader string
	// Format is "anu-uint8" (default), "hex" or "base64"; any other value reads the body as base64.
	Format string
	// TimeoutMs is the request timeout (0 selects DefaultQrngTimeoutMs, a negative value is refused).
	TimeoutMs int
	// MaxBytes is the per-request cap (0 selects DefaultMaxQrngBytes, a negative value is refused).
	MaxBytes int
	// LengthParam names the length query parameter (default "length"; ignored with BuildURL).
	LengthParam string
	// ExtraParams are static query parameters added after the length, each replacing an existing one of the same name.
	ExtraParams []QrngParam
	// BuildURL builds the full request URL itself (overrides LengthParam and ExtraParams); the result is still checked for https.
	BuildURL func(base string, numBytes int) string
	// AllowInsecureLoopback permits plain http for localhost, 127.0.0.1 and [::1] only.
	AllowInsecureLoopback bool
	// Transport performs the request; without one every Fetch fails.
	Transport QrngTransport
}

// HttpQrngSource is a QRNG backend over an injected HTTP transport. Validation is fail-closed: a non-success status, a malformed body,
// a wrong-length payload, an out-of-range byte or a timeout all fail rather than return partial entropy.
type HttpQrngSource struct {
	cfg  HttpQrngConfig
	name string
}

// NewHttpQrngSource validates the configuration. The name is "http-qrng(<host>)" ("unknown" when the URL does not parse).
func NewHttpQrngSource(cfg HttpQrngConfig) (*HttpQrngSource, error) {
	if cfg.URL == "" {
		return nil, errors.New("HttpQrngSource: `url` must be a non-empty string")
	}
	if cfg.MaxBytes < 0 {
		return nil, errors.New("HttpQrngSource: `maxBytes` must be a positive integer")
	}
	if cfg.TimeoutMs < 0 {
		return nil, errors.New("HttpQrngSource: `timeoutMs` must be a positive integer")
	}
	if cfg.MaxBytes == 0 {
		cfg.MaxBytes = DefaultMaxQrngBytes
	}
	if cfg.TimeoutMs == 0 {
		cfg.TimeoutMs = DefaultQrngTimeoutMs
	}
	if cfg.APIKeyHeader == "" {
		cfg.APIKeyHeader = "x-api-key"
	}
	if cfg.Format == "" {
		cfg.Format = "anu-uint8"
	}
	if cfg.LengthParam == "" {
		cfg.LengthParam = "length"
	}
	host := "unknown"
	if u, err := whatwgParse(cfg.URL); err == nil && u.host != "" {
		host = u.host
	}
	return &HttpQrngSource{cfg: cfg, name: "http-qrng(" + host + ")"}, nil
}

// Name is "http-qrng(<host>)".
func (s *HttpQrngSource) Name() string { return s.name }

// Fetch requests exactly n bytes (1..MaxBytes).
func (s *HttpQrngSource) Fetch(n int) ([]byte, error) {
	if n <= 0 {
		return nil, fmt.Errorf("QRNG: numBytes must be a positive integer, got %d", n)
	}
	if n > s.cfg.MaxBytes {
		return nil, fmt.Errorf("QRNG: requested %d bytes exceeds per-request cap %d", n, s.cfg.MaxBytes)
	}
	if s.cfg.Transport == nil {
		return nil, errors.New("QRNG: no fetch implementation available in this runtime")
	}
	url, err := s.buildURL(n)
	if err != nil {
		return nil, err
	}
	// Fail closed on transport: the key header and the entropy itself must not cross a cleartext link.
	if err := entropyAssertSecure(url, s.cfg.AllowInsecureLoopback); err != nil {
		return nil, err
	}
	headers := map[string]string{"accept": "application/json, text/plain"}
	if s.cfg.APIKey != "" {
		headers[s.cfg.APIKeyHeader] = s.cfg.APIKey
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(s.cfg.TimeoutMs)*time.Millisecond)
	defer cancel()
	type result struct {
		res *QrngResponse
		err error
	}
	done := make(chan result, 1)
	go func() {
		defer func() {
			if p := recover(); p != nil {
				done <- result{nil, fmt.Errorf("%v", p)}
			}
		}()
		r, e := s.cfg.Transport(ctx, url, headers, "error")
		done <- result{r, e}
	}()
	var out result
	select {
	case out = <-done:
	case <-ctx.Done():
		out = result{nil, ctx.Err()}
	}
	if out.err != nil {
		detail := out.err.Error()
		if errors.Is(out.err, context.DeadlineExceeded) || errors.Is(out.err, context.Canceled) {
			detail = "timeout"
		}
		if s.cfg.APIKey != "" {
			detail = strings.ReplaceAll(detail, s.cfg.APIKey, "[redacted]")
		}
		return nil, fmt.Errorf("QRNG: fetch failed (%s)", detail)
	}
	if out.res == nil {
		return nil, errors.New("QRNG: fetch failed (unknown error)")
	}
	if !out.res.OK {
		return nil, fmt.Errorf("QRNG: endpoint returned HTTP %d", out.res.Status)
	}
	var b []byte
	if s.cfg.Format == "anu-uint8" {
		if out.res.JSON == nil {
			return nil, errors.New("QRNG: response body is not a JSON object")
		}
		body, err := out.res.JSON()
		if err != nil {
			return nil, err
		}
		b, err = ParseAnuUint8(body)
		if err != nil {
			return nil, err
		}
	} else {
		if out.res.Text == nil {
			return nil, errors.New("QRNG: response has no text body")
		}
		text, err := out.res.Text()
		if err != nil {
			return nil, err
		}
		text = strings.TrimFunc(text, entropyIsJSSpace)
		if s.cfg.Format == "hex" {
			b, err = ParseHex(text)
		} else {
			b, err = ParseBase64(text)
		}
		if err != nil {
			return nil, err
		}
	}
	if len(b) != n {
		return nil, fmt.Errorf("QRNG: expected %d bytes, response decoded to %d", n, len(b))
	}
	return b, nil
}

// entropyIsJSSpace is the JavaScript String.prototype.trim whitespace set.
func entropyIsJSSpace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', ' ', 0xa0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff:
		return true
	}
	return r >= 0x2000 && r <= 0x200a
}

func (s *HttpQrngSource) buildURL(n int) (string, error) {
	if s.cfg.BuildURL != nil {
		return s.cfg.BuildURL(s.cfg.URL, n), nil
	}
	return entropyBuildURL(s.cfg.URL, s.cfg.LengthParam, n, s.cfg.ExtraParams)
}

// entropyBuildURL is `u = new URL(base); u.searchParams.set(lengthParam, n); for each extra: u.searchParams.set(k, v); u.toString()`
// for an http(s) URL (the only schemes the transport check lets through; any other scheme is refused here as insecure).
// shortcut: userinfo and fragment use the WHATWG percent-encode sets but not the full IDNA/opaque-path edge cases of the parser;
// upgrade to a full WHATWG serializer if exotic userinfo must round-trip.
func entropyBuildURL(base, lengthParam string, n int, extra []QrngParam) (string, error) {
	u, err := whatwgParse(base)
	if err != nil {
		return "", err
	}
	if u.scheme != "https" && u.scheme != "http" {
		return "", NewEntropyError("insecure_transport", entropyInsecureMsg)
	}
	raw := strings.TrimFunc(base, func(r rune) bool { return r <= 0x20 })
	raw = strings.NewReplacer("\t", "", "\n", "", "\r", "").Replace(raw)
	frag, hasFrag := "", false
	if i := strings.IndexByte(raw, '#'); i >= 0 {
		raw, frag, hasFrag = raw[:i], raw[i+1:], true
	}
	query := ""
	if i := strings.IndexByte(raw, '?'); i >= 0 {
		raw, query = raw[:i], raw[i+1:]
	}
	// userinfo: the authority follows the scheme and any run of / or \.
	auth := strings.TrimLeft(raw[strings.IndexByte(raw, ':')+1:], `/\`)
	if e := strings.IndexAny(auth, `/\`); e >= 0 {
		auth = auth[:e]
	}
	userinfo := ""
	if at := strings.LastIndexByte(auth, '@'); at >= 0 {
		name, pw, hasPw := strings.Cut(auth[:at], ":")
		userinfo = entropyPercentEncode(name, entropyUserinfoSet)
		if hasPw && pw != "" {
			userinfo += ":" + entropyPercentEncode(pw, entropyUserinfoSet)
		}
		if userinfo != "" {
			userinfo += "@"
		}
	}
	params := entropyParseQuery(query)
	params = entropySetParam(params, lengthParam, strconv.Itoa(n))
	for _, p := range extra {
		params = entropySetParam(params, p.Name, p.Value)
	}
	var b strings.Builder
	b.WriteString(u.scheme + "://" + userinfo + u.host + u.pathname)
	if len(params) > 0 {
		b.WriteByte('?')
		for i, p := range params {
			if i > 0 {
				b.WriteByte('&')
			}
			b.WriteString(entropyFormEncode(p.Name) + "=" + entropyFormEncode(p.Value))
		}
	}
	if hasFrag {
		b.WriteString("#" + entropyPercentEncode(frag, entropyFragmentSet))
	}
	return b.String(), nil
}

const (
	entropyUserinfoSet = " \"#<>?`{}/:;=@[\\]^|"
	entropyFragmentSet = " \"<>`"
)

func entropyPercentEncode(s, set string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= 0x20 || c > 0x7e || strings.IndexByte(set, c) >= 0 {
			fmt.Fprintf(&b, "%%%02X", c)
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}

// entropyFormEncode is the application/x-www-form-urlencoded byte serializer: * - . _ and alphanumerics stay, space is +.
func entropyFormEncode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '*' || c == '-' || c == '.' || c == '_':
			b.WriteByte(c)
		case c == ' ':
			b.WriteByte('+')
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func entropyFormDecode(s string) string {
	var out []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '+':
			out = append(out, ' ')
		case c == '%' && i+2 < len(s) && entropyHexVal(s[i+1]) >= 0 && entropyHexVal(s[i+2]) >= 0:
			out = append(out, byte(entropyHexVal(s[i+1])<<4|entropyHexVal(s[i+2])))
			i += 2
		default:
			out = append(out, c)
		}
	}
	return strings.ToValidUTF8(string(out), "�")
}

func entropyHexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

func entropyParseQuery(q string) []QrngParam {
	var out []QrngParam
	for _, part := range strings.Split(q, "&") {
		if part == "" {
			continue
		}
		name, value, _ := strings.Cut(part, "=")
		out = append(out, QrngParam{entropyFormDecode(name), entropyFormDecode(value)})
	}
	return out
}

// entropySetParam is URLSearchParams.set: the first match takes the value, later matches are dropped, no match appends.
func entropySetParam(ps []QrngParam, name, value string) []QrngParam {
	out := make([]QrngParam, 0, len(ps)+1)
	found := false
	for _, p := range ps {
		if p.Name == name {
			if found {
				continue
			}
			found = true
			p.Value = value
		}
		out = append(out, p)
	}
	if !found {
		out = append(out, QrngParam{name, value})
	}
	return out
}

const entropyInsecureMsg = "QRNG: endpoint must be https (http only for loopback with allowInsecureLoopback)"

func entropyAssertSecure(url string, allowLoopback bool) error {
	u, err := whatwgParse(url)
	if err != nil {
		return NewEntropyError("insecure_transport", "QRNG: endpoint URL is not a valid URL")
	}
	if u.scheme == "https" {
		return nil
	}
	hostname := u.host
	if strings.HasPrefix(hostname, "[") {
		hostname = hostname[:strings.IndexByte(hostname, ']')+1]
	} else if i := strings.LastIndexByte(hostname, ':'); i >= 0 {
		hostname = hostname[:i]
	}
	if u.scheme == "http" && allowLoopback && (hostname == "localhost" || hostname == "127.0.0.1" || hostname == "[::1]") {
		return nil
	}
	return NewEntropyError("insecure_transport", entropyInsecureMsg)
}

// ParseAnuUint8 reads the ANU / hardware REST JSON shape {success?: true, data: [0..255, ...]} from a decoded JSON value.
func ParseAnuUint8(body any) ([]byte, error) {
	rec, ok := body.(map[string]any)
	if _, isList := body.([]any); isList {
		rec, ok = map[string]any{}, true // typeof [] is "object": it just has no members
	}
	if !ok {
		return nil, errors.New("QRNG: response body is not a JSON object")
	}
	if s, has := rec["success"]; has && s != true {
		return nil, errors.New("QRNG: response reports success=false")
	}
	data, ok := rec["data"].([]any)
	if !ok {
		return nil, errors.New("QRNG: response `data` is not an array")
	}
	out := make([]byte, len(data))
	for i, v := range data {
		f, isNum := jsNum(v)
		if !isNum || f != math.Trunc(f) || f < 0 || f > 255 {
			return nil, fmt.Errorf("QRNG: response data[%d] is not a 0..255 integer", i)
		}
		out[i] = byte(f)
	}
	return out, nil
}

// ParseHex reads a flat hex string (either case); an odd length or a non-hex character is refused.
func ParseHex(text string) ([]byte, error) {
	if len(text)%2 != 0 {
		return nil, errors.New("QRNG: malformed hex payload")
	}
	out := make([]byte, len(text)/2)
	for i := range out {
		hi, lo := entropyHexVal(text[2*i]), entropyHexVal(text[2*i+1])
		if hi < 0 || lo < 0 {
			return nil, errors.New("QRNG: malformed hex payload")
		}
		out[i] = byte(hi<<4 | lo)
	}
	return out, nil
}

// ParseBase64 reads standard base64 as the WHATWG forgiving-base64 decode does (missing padding accepted, non-canonical trailing bits
// dropped) after the alphabet check; url-safe characters, whitespace and misplaced '=' are refused.
func ParseBase64(text string) ([]byte, error) {
	bad := errors.New("QRNG: malformed base64 payload")
	s, eq := text, 0
	for eq < 2 && strings.HasSuffix(s, "=") {
		s = s[:len(s)-1]
		eq++
	}
	for i := 0; i < len(s); i++ {
		if entropyB64Val(s[i]) < 0 {
			return nil, bad
		}
	}
	// The forgiving decode strips padding only from a full quad; padding on any other length stays and is not base64.
	if eq > 0 && len(text)%4 != 0 || len(s)%4 == 1 {
		return nil, bad
	}
	out := []byte{}
	var acc uint32
	bits := 0
	for i := 0; i < len(s); i++ {
		acc = acc<<6 | uint32(entropyB64Val(s[i]))
		bits += 6
		if bits >= 8 {
			bits -= 8
			out = append(out, byte(acc>>uint(bits)))
			acc &= 1<<uint(bits) - 1
		}
	}
	return out, nil
}

func entropyB64Val(c byte) int {
	switch {
	case c >= 'A' && c <= 'Z':
		return int(c - 'A')
	case c >= 'a' && c <= 'z':
		return int(c-'a') + 26
	case c >= '0' && c <= '9':
		return int(c-'0') + 52
	case c == '+':
		return 62
	case c == '/':
		return 63
	}
	return -1
}

// HealthTestOptions are the health-test parameters; nil members select the defaults (h = 8, window = 512). H is the assessed
// min-entropy per 8-bit sample (1..8); alpha is fixed at 2^-20.
type HealthTestOptions struct {
	H      *float64
	Window *float64
}

// HealthVerdict is the outcome of the health tests; Test names the failing one ("repetition-count" or "adaptive-proportion").
type HealthVerdict struct {
	OK   bool
	Test string
}

// RepetitionCutoff is the SP 800-90B 4.4.1 cutoff 1 + ceil(20 / h) for alpha = 2^-20.
func RepetitionCutoff(h float64) float64 { return 1 + math.Ceil(20/h) }

// ProportionCutoff is the SP 800-90B 4.4.2 cutoff 1 + CRITBINOM(w, 2^-h, 1 - 2^-20).
func ProportionCutoff(h, w float64) float64 {
	p := math.Pow(2, -h)
	target := 1 - math.Pow(2, -20)
	pmf := math.Pow(1-p, w)
	cdf := pmf
	k := 0.0
	for cdf < target && k < w {
		pmf *= ((w - k) / (k + 1)) * (p / (1 - p))
		k++
		cdf += pmf
	}
	return 1 + k
}

// HealthTestBytes runs the repetition-count and adaptive-proportion tests over one buffer. It fails closed (repetition-count) on bad
// parameters or an empty buffer; only complete windows are tested, the window shrinking to a shorter buffer.
func HealthTestBytes(b []byte, opts HealthTestOptions) HealthVerdict {
	h, w0 := 8.0, 512.0
	if opts.H != nil {
		h = *opts.H
	}
	if opts.Window != nil {
		w0 = *opts.Window
	}
	failed := HealthVerdict{false, "repetition-count"}
	if !(h >= 1 && h <= 8) || math.IsNaN(w0) || math.IsInf(w0, 0) || w0 != math.Trunc(w0) || w0 < 2 {
		return failed
	}
	if len(b) == 0 {
		return failed
	}
	rc := RepetitionCutoff(h)
	run := 1.0
	for i := 1; i < len(b); i++ {
		if b[i] == b[i-1] {
			run++
		} else {
			run = 1
		}
		if run >= rc {
			return failed
		}
	}
	w := int(math.Min(w0, float64(len(b))))
	ac := ProportionCutoff(h, float64(w))
	for start := 0; start+w <= len(b); start += w {
		count := 0
		for i := start; i < start+w; i++ {
			if b[i] == b[start] {
				count++
			}
		}
		if float64(count) >= ac {
			return HealthVerdict{false, "adaptive-proportion"}
		}
	}
	return HealthVerdict{OK: true}
}

// MixOptions are the options of MixEntropy.
type MixOptions struct {
	// Length is the output length (0 = the local input length; 1..MaxHkdfOutput otherwise).
	Length int
	// Context is extra domain separation folded into the HKDF info; empty means none.
	Context string
}

// MixEntropy is the robust randomness combiner HKDF-SHA256(ikm = len(local) || len(quantum) || local || quantum, salt, info = label ||
// context || length). The local bytes are always part of the keying material, so a hostile or empty quantum input cannot lower the
// output below the strength of local alone. It fails closed when local is shorter than MinLocalBytes or the length is out of range;
// quantum may be empty.
func MixEntropy(local, quantum []byte, opts MixOptions) ([]byte, error) {
	if len(local) < MinLocalBytes {
		return nil, fmt.Errorf("mixEntropy: local CSPRNG must be >= %d bytes (fail-closed)", MinLocalBytes)
	}
	length := opts.Length
	if length == 0 {
		length = len(local)
	}
	if length <= 0 || length > MaxHkdfOutput {
		return nil, fmt.Errorf("mixEntropy: length must be an integer in 1..%d", MaxHkdfOutput)
	}
	ikm := make([]byte, 0, 8+len(local)+len(quantum))
	ikm = append(ikm, byte(len(local)>>24), byte(len(local)>>16), byte(len(local)>>8), byte(len(local)))
	ikm = append(ikm, byte(len(quantum)>>24), byte(len(quantum)>>16), byte(len(quantum)>>8), byte(len(quantum)))
	ikm = append(ikm, local...)
	ikm = append(ikm, quantum...)
	label := entropyMixLabel
	if opts.Context != "" {
		label += "/" + opts.Context
	}
	label = strings.ToValidUTF8(label, "�")
	info := label + string([]byte{byte(length >> 24), byte(length >> 16), byte(length >> 8), byte(length)})
	out, err := hkdf.Key(sha256.New, ikm, []byte(entropyMixSalt), info, length)
	for i := range ikm {
		ikm[i] = 0 // best-effort zeroization of the transient keying material
	}
	return out, err
}

// SecureSeedOptions are the options of SecureSeed.
type SecureSeedOptions struct {
	// Length is the seed length (0 = DefaultSeedBytes).
	Length int
	// Source is the best-effort QRNG; nil means CSPRNG only.
	Source QrngSource
	// QuantumBytes and LocalBytes are the bytes requested (0 = max(32, Length)).
	QuantumBytes int
	LocalBytes   int
	// Context is extra domain separation for the combiner (nil = none).
	Context *string
	// RequireQuantum fails closed (EntropyError "quantum_required") when no healthy quantum bytes were obtained.
	RequireQuantum bool
	// HealthTest tunes the SP 800-90B tests; DisableHealthTest turns them off (tests only).
	HealthTest        HealthTestOptions
	DisableHealthTest bool
	// OnQrngError observes a skipped or failed QRNG; it must not be relied on to run to completion (a panic in it is swallowed).
	OnQrngError func(error)
	// RandomBytes replaces the platform CSPRNG (tests); it must return exactly n bytes.
	RandomBytes func(n int) ([]byte, error)
}

// SecureSeedResult is the outcome of SecureSeed.
type SecureSeedResult struct {
	// Seed is always full length and at least CSPRNG strength.
	Seed []byte
	// UsedQuantum is true iff genuine quantum bytes were mixed in; QuantumByteCount is how many (0 on fallback).
	UsedQuantum      bool
	QuantumByteCount int
	// Source is the source name, nil when none was configured.
	Source *string
}

// SecureSeed produces a key seed = MixEntropy(CSPRNG, best-effort QRNG). A missing, failing, timing-out or adversarial QRNG never
// blocks and never lowers the seed below CSPRNG strength (UsedQuantum is false). The only errors are configuration errors, a local
// CSPRNG malfunction (the trust anchor) and, when RequireQuantum is set, a missing healthy quantum source.
func SecureSeed(opts SecureSeedOptions) (SecureSeedResult, error) {
	length := opts.Length
	if length == 0 {
		length = DefaultSeedBytes
	}
	if length < 0 || length > MaxHkdfOutput {
		return SecureSeedResult{}, fmt.Errorf("secureSeed: length must be an integer in 1..%d", MaxHkdfOutput)
	}
	dflt := length
	if dflt < DefaultSeedBytes {
		dflt = DefaultSeedBytes
	}
	localBytes := opts.LocalBytes
	if localBytes == 0 {
		localBytes = dflt
	}
	if localBytes < MinLocalBytes {
		return SecureSeedResult{}, fmt.Errorf("secureSeed: localBytes must be an integer >= %d", MinLocalBytes)
	}
	quantumBytes := opts.QuantumBytes
	if quantumBytes == 0 {
		quantumBytes = dflt
	}
	if quantumBytes < 0 {
		return SecureSeedResult{}, errors.New("secureSeed: quantumBytes must be a positive integer")
	}

	var local []byte
	var err error
	if opts.RandomBytes != nil {
		local, err = opts.RandomBytes(localBytes)
	} else {
		local = make([]byte, localBytes)
		_, err = rand.Read(local)
	}
	if err != nil {
		return SecureSeedResult{}, err
	}
	if len(local) != localBytes {
		// The local CSPRNG is the trust anchor; if it misbehaves we fail CLOSED.
		return SecureSeedResult{}, errors.New("secureSeed: local CSPRNG did not return the requested bytes (fail-closed)")
	}

	quantum := []byte{}
	used := false
	var sourceName *string
	if opts.Source != nil {
		name := opts.Source.Name()
		sourceName = &name
		q, qerr := entropyFetchQuantum(opts, quantumBytes)
		if qerr == nil {
			quantum, used = q, true
		} else if opts.OnQrngError != nil {
			func() {
				defer func() { _ = recover() }() // observability must never break key generation
				opts.OnQrngError(qerr)
			}()
		}
	}
	if opts.RequireQuantum && !used {
		for i := range local {
			local[i] = 0
		}
		return SecureSeedResult{}, NewEntropyError("quantum_required", "secureSeed: quantum entropy is required but was not obtained (fail-closed)")
	}
	ctx := ""
	if opts.Context != nil {
		ctx = *opts.Context
	}
	seed, err := MixEntropy(local, quantum, MixOptions{Length: length, Context: ctx})
	for i := range local {
		local[i] = 0
	}
	if err != nil {
		return SecureSeedResult{}, err
	}
	count := 0
	if used {
		count = len(quantum)
	}
	return SecureSeedResult{Seed: seed, UsedQuantum: used, QuantumByteCount: count, Source: sourceName}, nil
}

// entropyFetchQuantum asks the source for n bytes, validates the answer and runs the health tests; a panic in the source is a failure.
func entropyFetchQuantum(opts SecureSeedOptions, n int) (q []byte, err error) {
	defer func() {
		if p := recover(); p != nil {
			q, err = nil, fmt.Errorf("%v", p)
		}
	}()
	q, err = opts.Source.Fetch(n)
	if err != nil {
		return nil, err
	}
	if len(q) != n {
		return nil, fmt.Errorf("QRNG: source returned %d, expected %d", len(q), n)
	}
	if !opts.DisableHealthTest {
		if v := HealthTestBytes(q, opts.HealthTest); !v.OK {
			t := v.Test
			if t == "" {
				t = "health"
			}
			return nil, NewEntropyError("health_test_failed", "QRNG: "+t+" test failed; source rejected")
		}
	}
	return q, nil
}

// EntropyKeyPair is an Ed25519 key pair whose 32-byte seed came from SecureSeed.
type EntropyKeyPair struct {
	// SecretKey is the 32-byte Ed25519 seed.
	SecretKey []byte
	// PublicKey is the Ed25519 public key.
	PublicKey   []byte
	UsedQuantum bool
}

// GenerateKeyPairWithEntropy generates an Ed25519 key pair whose secret is SecureSeed(...) (CSPRNG mixed with a health-tested QRNG).
// opts.Length is ignored (the seed is 32 bytes) and a nil Context defaults to "ed25519-key" (an explicit empty one stays empty).
func GenerateKeyPairWithEntropy(opts SecureSeedOptions) (EntropyKeyPair, error) {
	opts.Length = 32
	if opts.Context == nil {
		c := "ed25519-key"
		opts.Context = &c
	}
	r, err := SecureSeed(opts)
	if err != nil {
		return EntropyKeyPair{}, err
	}
	pub := ed25519.NewKeyFromSeed(r.Seed).Public().(ed25519.PublicKey)
	return EntropyKeyPair{SecretKey: r.Seed, PublicKey: []byte(pub), UsedQuantum: r.UsedQuantum}, nil
}
