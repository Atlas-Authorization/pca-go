package pca

// Checks a live PCA deployment's assumptions: clock skew, trusted-proxy settings, the signature-suite policy, root-caveat
// enforcement and the verifier's required checks. Every check returns a result map {id, status, detail, remediation?, observed?}
// (status pass / warn / fail / skip); DoctorRun merges them, DoctorVerdictOf reduces them, DoctorFormatResults prints them, and
// nothing printed carries a credential (DoctorScrubText). Configuration is a decoded JSON object with the reference's sections and
// member names (url, clock, store, proxy, verifier); values keep JavaScript semantics (a string where a number belongs is read the
// way the reference reads it). Checks that cannot be observed from here say so instead of passing.
//
// Network access and the library probe are injected (DoctorDeps); the defaults are net/http (redirects not followed) and this
// module's own caveat evaluation. The replay-store checks need an adapter and the conformance kit: DoctorDeps.Store runs them.

import (
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

var DoctorCheckGroups = []string{"clock", "store", "proxy", "suites", "caveats"}

const (
	DoctorDefaultReferenceURL    = "https://www.google.com/generate_204"
	DoctorRootCaveatMinVersion   = "0.4.1"
	DoctorSDKVersion             = "0.6.0"
	doctorMaxSkewMs              = 60000
	doctorStoreAdapterNotLoadMsg = "store adapters are loaded by the host program (set DoctorDeps.Store)"
)

var DoctorDefaultRequired = []string{"counter_format", "replay", "revocation", "plan_root_authorized", "audience", "validity", "grant_ref_bound"}

var doctorProxyHeaders = []string{"x-forwarded-for", "forwarded", "x-real-ip"}

// DoctorResponse is what the injected fetch returns: the response headers, keyed by lower-case name.
type DoctorResponse struct{ Headers map[string]string }

type DoctorFetch func(url, method string, headers map[string]string, timeoutMs float64) (*DoctorResponse, error)

// DoctorPca is the library under test: its Version, where it was found (Path) and how to Probe it: Probe(rootCaveat, amount)
// decides a payment of amount USD under a root grant that carries rootCaveat and returns {allowed, reasons}.
type DoctorPca struct {
	Version string
	Path    string
	Probe   func(rootCaveat map[string]any, amount float64) (any, error)
}

// DoctorDeps are the injected dependencies of DoctorRun / DoctorMain (every field optional).
type DoctorDeps struct {
	Fetch DoctorFetch
	Now   func() float64
	Load  func(dir *string) (*DoctorPca, error)
	Store func(cfg any) ([]map[string]any, error)
}

// ---- JavaScript value semantics over decoded JSON -----------------------------------------------------------------------

type docUndefT struct{}

var docUndef any = &docUndefT{}

func docG(o any, k string) any {
	if m, ok := o.(map[string]any); ok {
		if v, has := m[k]; has {
			return v
		}
	}
	return docUndef
}

func docNN(v, d any) any {
	if v == docUndef || v == nil {
		return d
	}
	return v
}

func docTruthy(v any) bool { return v != docUndef && jsTruthy(v) }

func docStr(v any) string {
	if v == docUndef {
		return "undefined"
	}
	return gwToString(v)
}

// docNumber is ECMAScript Number(v).
func docNumber(v any) float64 {
	switch t := v.(type) {
	case nil:
		return 0
	case bool:
		if t {
			return 1
		}
		return 0
	case string:
		return jsStringToNumber(t)
	case []any:
		return jsStringToNumber(gwToString(t))
	}
	if f, ok := jsNum(v); ok {
		return f
	}
	return math.NaN()
}

func docFinite(v any) (float64, bool) {
	f, ok := jsNum(v)
	return f, ok && !math.IsNaN(f) && !math.IsInf(f, 0)
}

func docIsInteger(v any) bool {
	f, ok := docFinite(v)
	return ok && f == math.Floor(f)
}

func docNegZero(v any) bool {
	f, ok := jsNum(v)
	return ok && f == 0 && math.Signbit(f)
}

func docPadEnd(s string, n int) string {
	if l := jsLen(s); l < n {
		return s + strings.Repeat(" ", n-l)
	}
	return s
}

func docAsciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

func docContains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func docRes(id, status, detail, remediation string, observed map[string]any) map[string]any {
	r := map[string]any{"id": id, "status": status, "detail": detail}
	if remediation != "" {
		r["remediation"] = remediation
	}
	if observed != nil {
		r["observed"] = observed
	}
	return r
}

func docStrings(l []string) []any {
	out := make([]any, len(l))
	for i, s := range l {
		out[i] = s
	}
	return out
}

// ---- scrub --------------------------------------------------------------------------------------------------------------

// docS is the ECMAScript \s class body.
const docS = `\t\n\v\f\r \x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}\x{feff}`

// docCI spells a word case-insensitively over ASCII only (Go's (?i) also folds U+212A and U+017F, the reference does not).
func docCI(w string) string {
	var sb strings.Builder
	for _, c := range w {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			sb.WriteString("[" + strings.ToLower(string(c)) + strings.ToUpper(string(c)) + "]")
		} else {
			sb.WriteRune(c)
		}
	}
	return sb.String()
}

var (
	docReJWT    = regexp.MustCompile(`\beyJ[\w-]{5,}\.[\w-]{5,}\.[\w-]*`)
	docReAuth   = regexp.MustCompile(`\b(` + docCI("authorization") + `["']?[` + docS + `]*[:=][` + docS + `]*)[^\n"']*`)
	docReBearer = regexp.MustCompile(`\b(` + docCI("Bearer") + `|` + docCI("Basic") + `|` + docCI("Token") + `)[` + docS + `]+[\w.~+/=-]{6,}`)
	docReURL    = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)[^` + docS + `/@]*:[^` + docS + `/@]*@`)
	docRePair   = regexp.MustCompile(`\b((?:` + docCI("token") + `|` + docCI("secret") + `|` + docCI("password") + `|` + docCI("passwd") + `|` + docCI("pwd") + `|` +
		docCI("api") + `[_-]?` + docCI("key") + `|` + docCI("key") + `|` + docCI("signature") + `|` + docCI("sig") + `|` + docCI("credential") + `|` +
		docCI("auth") + `|` + docCI("sslpassword") + `)["']?[` + docS + `]*[:=][` + docS + `]*)("[^"]*"|'[^']*'|[^` + docS + `"'&,;]+)`)
	docReLong = regexp.MustCompile(`[A-Za-z0-9_-]{40,}`)
)

// docFromUnits is a UTF-16 slice back to a string (a lone surrogate keeps its WTF-8 form).
func docFromUnits(u []uint16) string {
	var sb strings.Builder
	for i := 0; i < len(u); i++ {
		c := rune(u[i])
		if c >= 0xD800 && c < 0xDC00 && i+1 < len(u) && u[i+1] >= 0xDC00 && u[i+1] < 0xE000 {
			sb.WriteRune(0x10000 + (c-0xD800)<<10 + rune(u[i+1]) - 0xDC00)
			i++
		} else if c >= 0xD800 && c < 0xE000 {
			sb.WriteByte(byte(0xE0 | c>>12))
			sb.WriteByte(byte(0x80 | (c>>6)&0x3F))
			sb.WriteByte(byte(0x80 | c&0x3F))
		} else {
			sb.WriteRune(c)
		}
	}
	return sb.String()
}

// DoctorScrubText removes credentials from text the doctor prints: URL userinfo, `token=` / `password=` pairs, bearer credentials,
// JWTs and long token runs; cut to 600 UTF-16 units.
func DoctorScrubText(text any) string {
	t, ok := text.(string)
	if !ok {
		t = docStr(text)
	}
	t = docReJWT.ReplaceAllString(t, "[redacted]")
	t = docReAuth.ReplaceAllString(t, "${1}[redacted]")
	t = docReBearer.ReplaceAllString(t, "${1} [redacted]")
	t = docReURL.ReplaceAllString(t, "${1}[redacted]@")
	t = docRePair.ReplaceAllString(t, "${1}[redacted]")
	t = docReLong.ReplaceAllString(t, "[redacted]")
	if u := utf16Units(t); len(u) > 600 {
		return docFromUnits(u[:600]) + "..."
	}
	return t
}

// DoctorScrubDeep scrubs every string inside a JSON-like value (nesting deeper than 8 is left as it is).
func DoctorScrubDeep(v any, depth int) any {
	switch t := v.(type) {
	case string:
		return DoctorScrubText(t)
	case []any:
		if depth > 8 {
			return v
		}
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = DoctorScrubDeep(x, depth+1)
		}
		return out
	case map[string]any:
		if depth > 8 {
			return v
		}
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[k] = DoctorScrubDeep(x, depth+1)
		}
		return out
	}
	return v
}

// ---- fetch and clock ----------------------------------------------------------------------------------------------------

// DoctorDefaultFetch is the default client: redirects are not followed and an HTTP error status is a response, not an error.
func DoctorDefaultFetch(u, method string, headers map[string]string, timeoutMs float64) (*DoctorResponse, error) {
	req, err := http.NewRequest(method, u, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	c := &http.Client{Timeout: time.Duration(timeoutMs * float64(time.Millisecond)),
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	r, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 1<<16))
	h := map[string]string{}
	for k := range r.Header {
		h[strings.ToLower(k)] = r.Header.Get(k)
	}
	return &DoctorResponse{Headers: h}, nil
}

var (
	docMonths  = []string{"jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"}
	docRFCDate = regexp.MustCompile(`^(?:[A-Za-z]+,?[ \t\n\r\f\v]+)?(\d{1,2})[ \t\n\r\f\v]+([A-Za-z]{3})[A-Za-z]*[ \t\n\r\f\v]+(\d{4})[ \t\n\r\f\v]+(\d{1,2}):(\d{2})(?::(\d{2}))?[ \t\n\r\f\v]*(` +
		docCI("GMT") + `|` + docCI("UTC") + `|` + docCI("UT") + `|[Zz]|[+-]\d{4})$`)
	docISODate = regexp.MustCompile(`^(\d{4})-(\d{2})-(\d{2})(?:T(\d{2}):(\d{2})(?::(\d{2})(?:\.(\d{1,9}))?)?(Z|[+-]\d{2}:\d{2}))?$`)
)

func docAtoi(s string) int { n, _ := strconv.Atoi(s); return n }

func docEpoch(y, mo, d, h, mi, s, ms, offMin int) float64 {
	days := time.Date(y, time.Month(mo), 1, 0, 0, 0, 0, time.UTC).Unix()/86400 + int64(d) - 1
	return float64(((days*24+int64(h))*60+int64(mi))*60_000 + int64(s)*1000 + int64(ms) - int64(offMin)*60_000)
}

// docParseDate is Date.parse for the HTTP date (RFC 1123 with a zone; a weekday word is ignored) and ISO 8601 with a zone or date
// only (UTC); NaN otherwise. shortcut: a date without a zone is local time in the reference engine (host-dependent) and is NaN
// here; other legacy spellings are NaN.
func docParseDate(s string) float64 {
	t := jsTrim(s)
	if m := docRFCDate.FindStringSubmatch(t); m != nil {
		mi := -1
		for i, n := range docMonths {
			if n == strings.ToLower(m[2]) {
				mi = i
			}
		}
		if mi < 0 {
			return math.NaN()
		}
		h, min, sec := docAtoi(m[4]), docAtoi(m[5]), docAtoi(m[6])
		if h > 24 || min > 59 || sec > 59 || (h == 24 && (min != 0 || sec != 0)) {
			return math.NaN()
		}
		off := 0
		if z := m[7]; len(z) == 5 && (z[0] == '+' || z[0] == '-') {
			off = docAtoi(z[1:3])*60 + docAtoi(z[3:5])
			if z[0] == '-' {
				off = -off
			}
		}
		day, y := docAtoi(m[1]), docAtoi(m[3])
		if day < 1 || day > 31 || y < 1 {
			return math.NaN()
		}
		return docEpoch(y, mi+1, day, h, min, sec, 0, off)
	}
	if m := docISODate.FindStringSubmatch(t); m != nil {
		y, mo, d := docAtoi(m[1]), docAtoi(m[2]), docAtoi(m[3])
		if y < 1 || mo < 1 || mo > 12 || d < 1 || d > time.Date(y, time.Month(mo)+1, 0, 0, 0, 0, 0, time.UTC).Day() {
			return math.NaN()
		}
		h, min, sec := docAtoi(m[4]), docAtoi(m[5]), docAtoi(m[6])
		if h > 24 || min > 59 || sec > 59 || (h == 24 && (min != 0 || sec != 0 || m[7] != "")) {
			return math.NaN()
		}
		ms := 0
		if m[7] != "" {
			ms = docAtoi((m[7] + "00")[:3])
		}
		off := 0
		if z := m[8]; z != "" && z != "Z" {
			off = docAtoi(z[1:3])*60 + docAtoi(z[4:6])
			if z[0] == '-' {
				off = -off
			}
		}
		return docEpoch(y, mo, d, h, min, sec, ms, off)
	}
	return math.NaN()
}

func docWallMs() float64 { return float64(time.Now().UnixNano()) / 1e6 }

// DoctorReadDate is one reading of a server's clock from its Date header (one-second resolution: +-0.5 s plus half the round
// trip): {offsetMs, uncertaintyMs} (remote minus local) or {error}.
func DoctorReadDate(u string, fetch DoctorFetch, now func() float64, timeoutMs float64) map[string]any {
	t0 := now()
	res, err := fetch(u, "HEAD", nil, timeoutMs)
	if err != nil {
		return map[string]any{"error": "request failed: " + err.Error()}
	}
	t1 := now()
	date, has := res.Headers["date"]
	d := math.NaN()
	if has {
		d = docParseDate(date)
	}
	if math.IsNaN(d) || math.IsInf(d, 0) {
		if !has {
			return map[string]any{"error": "no Date header"}
		}
		return map[string]any{"error": "unparseable Date header '" + date + "'"}
	}
	return map[string]any{"offsetMs": d + 500 - (t0+t1)/2, "uncertaintyMs": 500 + (t1-t0)/2}
}

func docSignedS(ms float64) string {
	sign := "-"
	if ms >= 0 {
		sign = "+"
	}
	return sign + harnessToFixed(math.Abs(ms)/1000, 1) + " s"
}

func docNum(m map[string]any, k string) float64 { f, _ := m[k].(float64); return f }

// DoctorCheckClock is the clock skew of the deployment against a reference (the Date headers of both, or this machine's clock).
// FAIL only when the skew is beyond the limit even at the favourable end of the uncertainty interval; WARN when it is above the
// warning fraction or could be beyond the limit.
func DoctorCheckClock(cfg any, fetch DoctorFetch, now func() float64) map[string]any {
	if now == nil {
		now = docWallMs
	}
	u := docG(cfg, "url")
	if !docTruthy(u) {
		return docRes("clock", "skip", "no deployment URL given (--url)", "", nil)
	}
	cc := docG(cfg, "clock")
	maxSkew := docNumber(docNN(docG(cc, "maxSkewMs"), json2(doctorMaxSkewMs)))
	warnAt := maxSkew * docNumber(docNN(docG(cc, "warnFraction"), 0.25))
	timeout := docNumber(docNN(docG(cc, "timeoutMs"), json2(10000)))
	dep := DoctorReadDate(docStr(u), fetch, now, timeout)
	if e, bad := dep["error"]; bad {
		return docRes("clock", "warn", fmt.Sprintf("cannot observe the deployment's clock at %s: %s", docStr(u), e),
			"Make the deployment answer with a Date header (RFC 9110 requires one from an origin with a clock), or check its clock on the host. "+DoctorClockRemediation, nil)
	}
	refURL := docStr(docNN(docG(cc, "referenceUrl"), DoctorDefaultReferenceURL))
	ref := map[string]any{"offsetMs": 0.0, "uncertaintyMs": 0.0}
	refName, refNote := "this machine's clock", ""
	if refURL != "local" {
		r := DoctorReadDate(refURL, fetch, now, timeout)
		if e, bad := r["error"]; bad {
			refNote = fmt.Sprintf(" (reference %s unusable: %s; compared with this machine's clock instead)", refURL, e)
		} else {
			ref, refName = r, refURL
		}
	}
	skew := docNum(dep, "offsetMs") - docNum(ref, "offsetMs")
	unc := docNum(dep, "uncertaintyMs") + docNum(ref, "uncertaintyMs")
	lower, upper := math.Abs(skew)-unc, math.Abs(skew)+unc
	status := "pass"
	// a skew, uncertainty or threshold that is not a number (NaN, an infinite clock reading) can show nothing: fail, never pass
	measurable := finite(lower) && finite(upper) && !math.IsNaN(maxSkew) && !math.IsNaN(warnAt)
	if !measurable || lower > maxSkew {
		status = "fail"
	} else if math.Abs(skew) > warnAt || upper > maxSkew {
		status = "warn"
	}
	detail := fmt.Sprintf("deployment clock %s relative to %s%s (+-%s s: Date has 1 s resolution, plus round trips); fail beyond %s s, warn above %s s. "+
		"The Date header is written by whatever answers the request (a CDN or proxy may set it).",
		docSignedS(skew), refName, refNote, harnessToFixed(unc/1000, 1), jsNumberString(maxSkew/1000), jsNumberString(warnAt/1000))
	rem := DoctorClockRemediation
	if status == "pass" {
		rem = ""
	}
	return docRes("clock", status, detail, rem, map[string]any{"skewMs": skew, "uncertaintyMs": unc, "maxSkewMs": maxSkew, "warnAtMs": warnAt, "reference": refName})
}

// json2 is a plain number as the decoded-JSON number type.
func json2(f float64) any { return jsNumber(f) }

// ---- proxy --------------------------------------------------------------------------------------------------------------

// DoctorCheckProxyConfig is the stated TRUSTED_PROXY_COUNT / TRUSTED_PROXY_HEADER against the stated number of appending proxies.
func DoctorCheckProxyConfig(cfg any) map[string]any {
	p := docG(cfg, "proxy")
	n := docG(p, "trustedProxyCount")
	if n == docUndef {
		return docRes("proxy.config", "skip", "TRUSTED_PROXY_COUNT not given (config proxy.trustedProxyCount or env TRUSTED_PROXY_COUNT)", "", nil)
	}
	header := docNN(docG(p, "header"), "x-forwarded-for")
	hs, ns := docStr(header), docStr(n)
	fail := func(detail string) map[string]any {
		return docRes("proxy.config", "fail", detail, DoctorProxyRemediation, nil)
	}
	nf, _ := jsNum(n)
	if !docIsInteger(n) || nf < 0 || docNegZero(n) || nf > 16 {
		return fail(fmt.Sprintf("TRUSTED_PROXY_COUNT=%s is not an integer in 0..16", ns))
	}
	if header == "x-real-ip" && nf == 0 {
		return fail("TRUSTED_PROXY_HEADER=x-real-ip needs TRUSTED_PROXY_COUNT >= 1 (with 0 every forwarding header is ignored)")
	}
	hops := docG(p, "hops")
	if hops == docUndef {
		status, rem := "warn", DoctorProxyRemediation
		if nf == 0 {
			status, rem = "pass", ""
		}
		return docRes("proxy.config", status, fmt.Sprintf("TRUSTED_PROXY_COUNT=%s (%s); the real number of appending proxies was not stated (proxy.hops / PCA_TRUSTED_PROXY_HOPS), so it cannot be compared", ns, hs), rem, nil)
	}
	hp, h := docStr(hops), docNumber(hops)
	if nf > h {
		return fail(fmt.Sprintf("TRUSTED_PROXY_COUNT=%s is larger than the %s proxies in front of the API: a client chooses its own address (and rate-limit bucket) with extra %s entries", ns, hp, hs))
	}
	if nf < h {
		return docRes("proxy.config", "warn", fmt.Sprintf("TRUSTED_PROXY_COUNT=%s is smaller than the %s proxies in front of the API: clients are keyed by a proxy's address and share its bucket", ns, hp), DoctorProxyRemediation, nil)
	}
	return docRes("proxy.config", "pass", fmt.Sprintf("TRUSTED_PROXY_COUNT=%s (%s) matches the stated %s appending proxies", ns, hs, hp), "", nil)
}

// DoctorTestNetIP is a random documentation address (RFC 5737 TEST-NET-2 / -3): never a real client.
func DoctorTestNetIP(rand func() float64) string {
	net := "203.0.113"
	if rand() < 0.5 {
		net = "198.51.100"
	}
	return fmt.Sprintf("%s.%d", net, 1+int(math.Floor(rand()*254)))
}

// DoctorForgedHeaders are forged values for all three forwarding headers at once (the server trusts at most one of them).
func DoctorForgedHeaders(rand func() float64) map[string]string {
	chain := make([]string, 17)
	for i := range chain {
		chain[i] = DoctorTestNetIP(rand)
	}
	forwarded := make([]string, 17)
	for i, ip := range chain {
		forwarded[i] = "for=" + ip
	}
	return map[string]string{"x-forwarded-for": strings.Join(chain, ", "), "forwarded": strings.Join(forwarded, ", "), "x-real-ip": DoctorTestNetIP(rand)}
}

// docRemaining reads RateLimit-Remaining from one response (ok false when absent or not a finite number).
func docRemaining(fetch DoctorFetch, u string, headers map[string]string, timeoutMs float64) (float64, bool, error) {
	r, err := fetch(u, "GET", headers, timeoutMs)
	if err != nil {
		return 0, false, err
	}
	v, has := r.Headers["ratelimit-remaining"]
	if !has {
		return 0, false, nil
	}
	n := jsStringToNumber(v)
	return n, !math.IsNaN(n) && !math.IsInf(n, 0), nil
}

// docHref is `new URL(path, base).href` for the shapes a probe path takes (absolute URL, rooted path, relative path).
func docHref(path, base string) (string, error) {
	b, err := url.Parse(base)
	if err != nil || b.Scheme == "" || b.Host == "" {
		return "", errors.New("Invalid URL")
	}
	if b.Path == "" {
		b, _ = url.Parse(base + "/")
	}
	r, err := url.Parse(path)
	if err != nil {
		return "", errors.New("Invalid URL")
	}
	return b.ResolveReference(r).String(), nil
}

// DoctorCheckProxyProbe sends forged forwarding headers to a public rate-limited path, watching RateLimit-Remaining: a forged
// request that lands in a FRESH bucket while plain requests keep draining one bucket means client-written entries are trusted. A
// count that is too LOW is not observable from one vantage point.
func DoctorCheckProxyProbe(cfg any, fetch DoctorFetch, rand func() float64) (map[string]any, error) {
	const id = "proxy.probe"
	u := docG(cfg, "url")
	if !docTruthy(u) {
		return docRes(id, "skip", "no deployment URL given (--url)", "", nil), nil
	}
	proxy := docG(cfg, "proxy")
	if docG(proxy, "probe") == false {
		return docRes(id, "skip", "disabled (--no-probe)", "", nil), nil
	}
	target, err := docHref(docStr(docNN(docG(proxy, "probePath"), "/v1/pca/suites")), docStr(u))
	if err != nil {
		return nil, err
	}
	t := docNumber(docNN(docG(docG(cfg, "clock"), "timeoutMs"), json2(10000)))
	if rand == nil {
		rand = func() float64 { return float64(time.Now().UnixNano()%1000003) / 1000003 }
	}
	var vals [4]float64
	var oks [4]bool
	heads := []map[string]string{nil, nil, nil, nil}
	for i := range heads {
		if i == 2 {
			heads[i] = DoctorForgedHeaders(rand)
		}
		v, ok, ferr := docRemaining(fetch, target, heads[i], t)
		if ferr != nil {
			return docRes(id, "warn", fmt.Sprintf("probe request to %s failed: %s", target, ferr.Error()),
				"Set proxy.probePath to a public, rate-limited path of the deployment, or run with --no-probe.", nil), nil
		}
		vals[i], oks[i] = v, ok
	}
	rem := make([]any, 4)
	for i := range rem {
		if oks[i] {
			rem[i] = jsNumber(vals[i])
		}
	}
	observed := map[string]any{"url": target, "remaining": rem}
	if !(oks[0] && oks[1] && oks[2] && oks[3]) {
		return docRes(id, "skip", fmt.Sprintf("not observable remotely: %s does not return a RateLimit-Remaining header on every response", target), "", observed), nil
	}
	a, b, f, c := vals[0], vals[1], vals[2], vals[3]
	sa, sb, sf, sc := jsNumberString(a), jsNumberString(b), jsNumberString(f), jsNumberString(c)
	if !(b < a && c < b) {
		return docRes(id, "warn", fmt.Sprintf("inconclusive: the plain requests' bucket did not drain monotonically (%s, %s, then %s): a window rollover, a shared bucket or concurrent traffic. Re-run.", sa, sb, sc), "", observed), nil
	}
	if f > b {
		return docRes(id, "fail", fmt.Sprintf("a request with FORGED forwarding headers got a fresh rate-limit bucket (remaining %s, while the plain requests' bucket was at %s): the deployment trusts client-written forwarding entries", sf, sb), DoctorProxyRemediation, observed), nil
	}
	return docRes(id, "pass", fmt.Sprintf("forged X-Forwarded-For / Forwarded / X-Real-IP did not move the client to another bucket (remaining %s, %s, forged %s, %s). A count that is too LOW is not observable from one client.", sa, sb, sf, sc), "", observed), nil
}

// ---- suites -------------------------------------------------------------------------------------------------------------

var (
	docReB64u  = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	docReEdID  = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	docNoVerif = "no verifier configuration given (config verifier.*)"
)

func docIsPq(alg any) bool {
	s, ok := alg.(string)
	return ok && s != "ed25519" && docContains(RegisteredSuites, s)
}

// doctorRegistryOrder is the suite registry as the reference lists it (object-key order: the two FN-DSA suites sit around the LESS ones).
var doctorRegistryOrder = []string{"ed25519", "ml-dsa-65", "hybrid-ed25519-ml-dsa-65", "hybrid-nested-ed25519-ml-dsa-65", "slh-dsa-sha2-128f",
	"hybrid-ed25519-slh-dsa-sha2-128f", "ml-dsa-87", "hybrid-ed25519-ml-dsa-87", "slh-dsa-sha2-256s", "hybrid-ed25519-slh-dsa-sha2-256s",
	"fn-dsa-512", "less-cat1", "hybrid-ed25519-less-cat1", "fn-dsa-1024"}

// DoctorCheckAllowedSuites is allowedSuites against the closed suite registry (the library's registered suite names, in order).
func DoctorCheckAllowedSuites(cfg any) map[string]any {
	const id = "suites.allowed"
	v := docG(cfg, "verifier")
	if !docTruthy(v) {
		return docRes(id, "skip", docNoVerif, "", nil)
	}
	// the reference lists its registry in object-key order, which puts the two FN-DSA suites around the LESS ones
	known := strings.Join(doctorRegistryOrder, ", ")
	lst := docG(v, "allowedSuites")
	if lst == docUndef {
		return docRes(id, "warn", fmt.Sprintf("allowedSuites is unset: every registered suite is accepted (%d: %s)", len(RegisteredSuites), known), DoctorSuitesRemediation, nil)
	}
	l, isList := lst.([]any)
	if !isList || len(l) == 0 {
		return docRes(id, "fail", "allowedSuites is empty or not a list: no PCActn can verify", DoctorSuitesRemediation, nil)
	}
	var unknown, names []string
	for _, s := range l {
		if str, ok := s.(string); !ok || !docContains(RegisteredSuites, str) {
			unknown = append(unknown, docStr(s))
		} else {
			names = append(names, str)
		}
	}
	if len(unknown) > 0 {
		return docRes(id, "fail", fmt.Sprintf("allowedSuites names suite(s) outside the registry: %s (known: %s)", strings.Join(unknown, ", "), known), DoctorSuitesRemediation, nil)
	}
	return docRes(id, "pass", "allowedSuites = "+strings.Join(names, ", "), "", nil)
}

// DoctorCheckPqBinding is the allowUnboundPq / pqPins / trustedRoot sanity check. It errors on an allowedSuites that is not a list.
func DoctorCheckPqBinding(cfg any) (map[string]any, error) {
	const id = "suites.pq-binding"
	v := docG(cfg, "verifier")
	if !docTruthy(v) {
		return docRes(id, "skip", docNoVerif, "", nil), nil
	}
	fail := func(detail string) (map[string]any, error) {
		return docRes(id, "fail", detail, DoctorPqRemediation, nil), nil
	}
	if docG(v, "allowUnboundPq") == true {
		return fail("allowUnboundPq is set: PQ keys are read from the artifact, so a hybrid gives no protection against an Ed25519 forger and a pure-PQ hop can be signed by any key")
	}
	pins := docG(v, "pqPins")
	var pinMap map[string]any
	if pins != docUndef {
		m, isObj := pins.(map[string]any)
		if !isObj {
			return fail("pqPins is not an object of { ed25519 identity: pq public key }")
		}
		pinMap = m
		var bad []string
		for _, k := range jsKeys(m) {
			if s, ok := m[k].(string); !docReEdID.MatchString(k) || !ok || !docReB64u.MatchString(s) {
				bad = append(bad, k)
			}
		}
		if len(bad) > 0 {
			return fail("pqPins has malformed entries (key must be a 43-char base64url Ed25519 identity, value a base64url PQ key): " + strings.Join(bad, ", "))
		}
	}
	var allowed []any
	if a := docNN(docG(v, "allowedSuites"), nil); a == nil {
		allowed = docStrings(doctorRegistryOrder)
	} else if l, ok := a.([]any); ok {
		allowed = l
	} else {
		return nil, errors.New("allowedSuites.filter is not a function")
	}
	var pq []string
	for _, s := range allowed {
		if docIsPq(s) {
			pq = append(pq, s.(string))
		}
	}
	if len(pq) == 0 {
		return docRes(id, "pass", "no post-quantum suite is accepted (Ed25519 only: no PQ binding needed, and no PQ protection)", "", nil), nil
	}
	pinned := pinMap != nil && len(pinMap) > 0
	if !pinned && docG(v, "trustedRoot") != true {
		return docRes(id, "warn", fmt.Sprintf("post-quantum suite(s) accepted (%s) with neither pqPins nor a stored trustedRoot: a non-Ed25519 root is refused (fail closed) or its PQ key is not pinned", strings.Join(pq, ", ")), DoctorPqRemediation, nil), nil
	}
	how := "stored trustedRoot"
	if pinned {
		how = fmt.Sprintf("%d pin(s)", len(pinMap))
	}
	return docRes(id, "pass", fmt.Sprintf("PQ suites (%s) are bound: %s; allowUnboundPq off", strings.Join(pq, ", "), how), "", nil), nil
}

// ---- root caveats and enforcement ---------------------------------------------------------------------------------------

// DoctorCompareVersion is -1 / 0 / 1 for a < b / = / > over major.minor.patch (pre-release tags ignored); NaN parts compare as -1.
func DoctorCompareVersion(a, b string) int {
	split := func(s string) []float64 {
		var parts []string
		start := 0
		for i := 0; i <= len(s); i++ {
			if i == len(s) || s[i] == '.' || s[i] == '+' || s[i] == '-' {
				parts = append(parts, s[start:i])
				start = i + 1
			}
		}
		if len(parts) > 3 {
			parts = parts[:3]
		}
		out := make([]float64, len(parts))
		for i, p := range parts {
			out[i] = jsStringToNumber(p)
		}
		return out
	}
	pa, pb := split(a), split(b)
	part := func(p []float64, i int) float64 {
		if i < len(p) && !math.IsNaN(p[i]) && !math.IsInf(p[i], 0) {
			return p[i]
		}
		return -1
	}
	for i := 0; i < 3; i++ {
		x, y := part(pa, i), part(pb, i)
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

// DoctorLoadPca is the default library under test: this module, probed through its own caveat evaluation.
func DoctorLoadPca(dir *string) (*DoctorPca, error) {
	if dir != nil {
		return nil, errors.New("a Go program cannot probe another deployed copy of the library (pass DoctorDeps.Load)")
	}
	return &DoctorPca{Version: DoctorSDKVersion, Path: "github.com/Atlas-Authorization/pca-go", Probe: func(cv map[string]any, amount float64) (any, error) {
		ok, failed := EvaluateCaveats([]any{cv}, map[string]any{"now": jsNumber(float64(time.Now().UnixMilli())),
			"action": map[string]any{"verb": "pay", "resource": "invoice:42", "reversibility_class": "reversible",
				"params": map[string]any{"amount": jsNumber(amount), "currency": "usd"}}})
		return map[string]any{"allowed": ok, "reasons": docStrings(failed)}, nil
	}}, nil
}

func docDecision(raw any) map[string]any {
	m, _ := raw.(map[string]any)
	reasons := []any{}
	if l, ok := m["reasons"].([]any); ok {
		for _, r := range l {
			reasons = append(reasons, docStr(r))
		}
	}
	return map[string]any{"allowed": m != nil && m["allowed"] == true, "reasons": reasons}
}

func docReasonText(d map[string]any) string {
	var parts []string
	for _, r := range d["reasons"].([]any) {
		parts = append(parts, r.(string))
	}
	return strings.Join(parts, "; ")
}

// DoctorCheckRootCaveats is the root-caveat enforcement check (the 0.4.1 security fix): the deployed library must be >= 0.4.1, and
// a functional probe through THAT library must show a root max_spend of 100 denying 150 and allowing 50, and an unknown root caveat
// type denying (fail closed).
func DoctorCheckRootCaveats(cfg any, load func(dir *string) (*DoctorPca, error)) map[string]any {
	const id = "caveats.root"
	if load == nil {
		load = DoctorLoadPca
	}
	var dir *string
	if d := docG(docG(cfg, "verifier"), "pcaDir"); docTruthy(d) {
		s := docStr(d)
		dir = &s
	}
	pca, err := load(dir)
	if err != nil {
		from := ""
		if dir != nil {
			from = " from " + *dir
		}
		return docRes(id, "fail", fmt.Sprintf("cannot load @atlasauth/pca%s: %s", from, err.Error()), DoctorCaveatRemediation, nil)
	}
	where := fmt.Sprintf("@atlasauth/pca %s at %s", pca.Version, pca.Path)
	if DoctorCompareVersion(pca.Version, DoctorRootCaveatMinVersion) < 0 {
		return docRes(id, "fail", fmt.Sprintf("%s: root caveats outside the envelope are NOT enforced before %s (legacy behaviour)", where, DoctorRootCaveatMinVersion), DoctorCaveatRemediation, nil)
	}
	probe := func(cv map[string]any, amount float64) (map[string]any, error) {
		raw, perr := pca.Probe(cv, amount)
		if perr != nil {
			return nil, perr
		}
		return docDecision(raw), nil
	}
	over, e1 := probe(map[string]any{"type": "max_spend", "usd": jsNumber(100)}, 150)
	var under, unknown map[string]any
	var e2, e3 error
	if e1 == nil {
		under, e2 = probe(map[string]any{"type": "max_spend", "usd": jsNumber(100)}, 50)
	}
	if e1 == nil && e2 == nil {
		unknown, e3 = probe(map[string]any{"type": "pca-doctor-unknown-caveat"}, 50)
	}
	for _, e := range []error{e1, e2, e3} {
		if e != nil {
			return docRes(id, "fail", fmt.Sprintf("%s: the enforcement probe could not run: %s", where, e.Error()), DoctorCaveatRemediation, nil)
		}
	}
	observed := map[string]any{"version": pca.Version, "over": over, "under": under, "unknown": unknown}
	if over["allowed"] == true || unknown["allowed"] == true {
		what := "an unknown root caveat type was allowed"
		if over["allowed"] == true {
			what = "max_spend 100 allowed a 150 payment"
		}
		return docRes(id, "fail", fmt.Sprintf("%s: a root caveat was NOT enforced (%s)", where, what), DoctorCaveatRemediation, observed)
	}
	if under["allowed"] != true {
		return docRes(id, "warn", fmt.Sprintf("%s: inconclusive: the control payment within the root max_spend was denied too (%s)", where, docReasonText(under)), "", observed)
	}
	return docRes(id, "pass", where+": root caveats enforced (max_spend 100 denies 150, allows 50; an unknown root caveat type denies)", "", observed)
}

// DoctorCheckEnforcement: requirePCA must not run with insecureAllowUnenforced, and a custom `require` list should keep the
// defaults. It errors on a `require` that is neither a list nor a string.
func DoctorCheckEnforcement(cfg any) (map[string]any, error) {
	const id = "verifier.enforcement"
	v := docG(cfg, "verifier")
	if !docTruthy(v) {
		return docRes(id, "skip", docNoVerif, "", nil), nil
	}
	if docG(v, "insecureAllowUnenforced") == true {
		return docRes(id, "fail", "requirePCA runs with insecureAllowUnenforced: required checks that are not enforced do not deny",
			"Remove insecureAllowUnenforced and supply the stores the required checks need (counter / revocation / budget).", nil), nil
	}
	req := docG(v, "require")
	if req != docUndef {
		var missing []string
		switch t := req.(type) {
		case []any:
			for _, c := range DoctorDefaultRequired {
				found := false
				for _, x := range t {
					found = found || x == c
				}
				if !found {
					missing = append(missing, c)
				}
			}
		case string:
			for _, c := range DoctorDefaultRequired {
				if !strings.Contains(t, c) {
					missing = append(missing, c)
				}
			}
		default:
			return nil, errors.New("require.includes is not a function")
		}
		if len(missing) > 0 {
			return docRes(id, "warn", "the require list drops default check(s): "+strings.Join(missing, ", "),
				fmt.Sprintf("Keep every default required check (%s) and add to it.", strings.Join(DoctorDefaultRequired, ", ")), nil), nil
		}
	}
	if docTruthy(req) {
		l, ok := req.([]any)
		if !ok {
			return nil, errors.New("require.join is not a function")
		}
		parts := make([]string, len(l))
		for i, x := range l {
			if x != nil {
				parts[i] = docStr(x)
			}
		}
		return docRes(id, "pass", "require = "+strings.Join(parts, ", "), "", nil), nil
	}
	return docRes(id, "pass", "default required checks; insecureAllowUnenforced off", "", nil), nil
}

// DoctorCheckStore reports the replay-store checks: skipped without an adapter in the config, otherwise run by deps.Store (the
// store conformance kit lives with the host program's adapter).
func DoctorCheckStore(cfg any, deps DoctorDeps) ([]map[string]any, error) {
	spec := docG(docG(cfg, "store"), "adapter")
	if !docTruthy(spec) {
		detail := "no store adapter given (--store ./adapter.mjs); the replay store cannot be exercised remotely"
		return []map[string]any{docRes("store.atomicity", "skip", detail, "", nil), docRes("store.durability", "skip", detail, "", nil)}, nil
	}
	if deps.Store == nil {
		return []map[string]any{docRes("store.atomicity", "fail", fmt.Sprintf("cannot load the store adapter %s: %s", docStr(spec), doctorStoreAdapterNotLoadMsg),
			"Point --store at a module exporting a store adapter (see the store conformance kit guide).", nil)}, nil
	}
	return deps.Store(cfg)
}

// ---- configuration ------------------------------------------------------------------------------------------------------

// docURLScheme is the scheme of u when it parses as an absolute URL, else "" (the reference's `new URL` throws).
func docURLScheme(v any) string {
	s, ok := v.(string)
	if !ok {
		return ""
	}
	u, err := url.Parse(jsTrim(s))
	if err != nil || u.Scheme == "" {
		return ""
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https", "ftp", "ws", "wss":
		if u.Hostname() == "" {
			return ""
		}
	}
	return strings.ToLower(u.Scheme)
}

// DoctorConfigProblems lists the numeric settings that would make a check meaningless (NaN, negative, zero where a duration is
// needed): they are configuration errors.
func DoctorConfigProblems(cfg any) []string {
	out := []string{}
	pos := func(name string, v any, integer bool) {
		if v == docUndef {
			return
		}
		f, ok := docFinite(v)
		if !ok || f <= 0 || (integer && f != math.Floor(f)) {
			kind := "number"
			if integer {
				kind = "integer"
			}
			out = append(out, fmt.Sprintf("%s must be a positive %s", name, kind))
		}
	}
	nonneg := func(name string, v any) {
		if v == docUndef {
			return
		}
		f, ok := jsNum(v)
		if !ok || !docIsInteger(v) || f < 0 || docNegZero(v) {
			out = append(out, name+" must be a non-negative integer")
		}
	}
	clock, store, proxy := docG(cfg, "clock"), docG(cfg, "store"), docG(cfg, "proxy")
	pos("clock.maxSkewMs", docG(clock, "maxSkewMs"), false)
	pos("clock.timeoutMs", docG(clock, "timeoutMs"), false)
	if wf := docG(clock, "warnFraction"); wf != docUndef {
		if f, ok := jsNum(wf); !ok || !(f > 0 && f <= 1) {
			out = append(out, "clock.warnFraction must be a number in (0, 1]")
		}
	}
	pos("store.concurrency", docG(store, "concurrency"), true)
	pos("store.rounds", docG(store, "rounds"), true)
	nonneg("proxy.trustedProxyCount", docG(proxy, "trustedProxyCount"))
	nonneg("proxy.hops", docG(proxy, "hops"))
	if u := docG(cfg, "url"); u != docUndef {
		switch s := docURLScheme(u); s {
		case "":
			out = append(out, "url is not a valid URL")
		case "http", "https":
		default:
			out = append(out, "url must be an http(s) URL")
		}
	}
	return out
}

// DoctorRun runs the selected check groups (all when only is nil) and scrubs everything they report. An invalid configuration is
// reported as `config` failures and nothing else runs. A group that errors is a failed check, not a crashed run and not a skipped
// one.
func DoctorRun(cfg any, only []string, deps DoctorDeps) []map[string]any {
	sel := only
	if sel == nil {
		sel = DoctorCheckGroups
	}
	if problems := DoctorConfigProblems(cfg); len(problems) > 0 {
		out := []map[string]any{}
		for _, p := range problems {
			out = append(out, docRes("config", "fail", DoctorScrubText("invalid configuration: "+p), "Correct the setting; no check was run.", nil))
		}
		return out
	}
	fetch := deps.Fetch
	if fetch == nil {
		fetch = DoctorDefaultFetch
	}
	var out []map[string]any
	guarded := func(id string, run func() ([]map[string]any, error)) {
		r, err := run()
		if err != nil {
			out = append(out, docRes(id, "fail", fmt.Sprintf("%s could not run: %s", id, DoctorScrubText(err.Error())),
				"Fix the configuration or the dependency named above and run the doctor again.", nil))
			return
		}
		out = append(out, r...)
	}
	one := func(m map[string]any) ([]map[string]any, error) { return []map[string]any{m}, nil }
	oneE := func(m map[string]any, err error) ([]map[string]any, error) {
		if err != nil {
			return nil, err
		}
		return []map[string]any{m}, nil
	}
	if docContains(sel, "clock") {
		guarded("clock", func() ([]map[string]any, error) { return one(DoctorCheckClock(cfg, fetch, deps.Now)) })
	}
	if docContains(sel, "store") {
		guarded("store", func() ([]map[string]any, error) { return DoctorCheckStore(cfg, deps) })
	}
	if docContains(sel, "proxy") {
		guarded("proxy.config", func() ([]map[string]any, error) { return one(DoctorCheckProxyConfig(cfg)) })
		guarded("proxy.probe", func() ([]map[string]any, error) { return oneE(DoctorCheckProxyProbe(cfg, fetch, nil)) })
	}
	if docContains(sel, "suites") {
		guarded("suites.allowed", func() ([]map[string]any, error) { return one(DoctorCheckAllowedSuites(cfg)) })
		guarded("suites.pq", func() ([]map[string]any, error) { return oneE(DoctorCheckPqBinding(cfg)) })
	}
	if docContains(sel, "caveats") {
		guarded("caveats.root", func() ([]map[string]any, error) { return one(DoctorCheckRootCaveats(cfg, deps.Load)) })
		guarded("caveats.enforcement", func() ([]map[string]any, error) { return oneE(DoctorCheckEnforcement(cfg)) })
	}
	// nothing the doctor prints may carry a credential from the deployment URL, an adapter option or an error message
	res := make([]map[string]any, len(out))
	for i, r := range out {
		res[i] = DoctorScrubDeep(r, 0).(map[string]any)
	}
	return res
}

// DoctorVerdictOf reduces results: fail if any check failed; warn if any warned (fail under strict); else pass. A run in which
// nothing was checked (no results, or every result skipped) is a fail: a doctor that looked at nothing must not report a healthy
// deployment.
func DoctorVerdictOf(results []map[string]any, strict bool) string {
	nonSkip, fail, warn := false, false, false
	for _, r := range results {
		switch r["status"] {
		case "skip":
		case "fail":
			nonSkip, fail = true, true
		case "warn":
			nonSkip, warn = true, true
		default:
			nonSkip = true
		}
	}
	switch {
	case !nonSkip || fail:
		return "fail"
	case warn && strict:
		return "fail"
	case warn:
		return "warn"
	}
	return "pass"
}

// DoctorFormatResults prints results as text; target (when non-empty) names the deployment.
func DoctorFormatResults(results []map[string]any, target string, strict bool) string {
	head := "pca-doctor"
	if target != "" {
		head += ": " + target
	}
	lines := []string{head}
	for _, r := range results {
		lines = append(lines, fmt.Sprintf("  %s  %s %s", docPadEnd(strings.ToUpper(docStr(r["status"])), 4), docPadEnd(docStr(r["id"]), 20), docStr(r["detail"])))
		if rem, ok := r["remediation"]; ok && docTruthy(rem) {
			lines = append(lines, fmt.Sprintf("  %s  %s fix: %s", strings.Repeat(" ", 4), strings.Repeat(" ", 20), docStr(rem)))
		}
	}
	n := func(s string) int {
		c := 0
		for _, r := range results {
			if r["status"] == s {
				c++
			}
		}
		return c
	}
	if n("skip") == len(results) {
		lines = append(lines, "  FAIL  nothing checked        no check produced a result: nothing about this deployment was verified")
	}
	lines = append(lines, fmt.Sprintf("Summary: %d pass, %d warn, %d fail, %d skip -> %s", n("pass"), n("warn"), n("fail"), n("skip"), strings.ToUpper(DoctorVerdictOf(results, strict))))
	return strings.Join(lines, "\n")
}

func docEnvInt(name, v string, present bool) (any, bool, error) {
	if !present || v == "" {
		return nil, false, nil
	}
	n := jsStringToNumber(v)
	if !docIsInteger(n) || n < 0 || (n == 0 && math.Signbit(n)) {
		return nil, false, fmt.Errorf("%s must be a non-negative integer", name)
	}
	return jsNumber(n), true, nil
}

// DoctorConfigFromEnv reads the deployment's own environment variable names (as the API and the guides use them).
func DoctorConfigFromEnv(env map[string]string) (map[string]any, error) {
	c := map[string]any{}
	get := func(k string) (string, bool) { v, ok := env[k]; return v, ok }
	if v, _ := get("PCA_DOCTOR_URL"); v != "" {
		c["url"] = v
	}
	if v, _ := get("PCA_DOCTOR_REFERENCE_URL"); v != "" {
		c["clock"] = map[string]any{"referenceUrl": v}
	}
	if v, _ := get("PCA_DOCTOR_STORE"); v != "" {
		c["store"] = map[string]any{"adapter": v}
	}
	proxy := map[string]any{}
	touched := false
	if v, ok := get("TRUSTED_PROXY_COUNT"); ok {
		touched = true
		n, set, err := docEnvInt("TRUSTED_PROXY_COUNT", v, ok)
		if err != nil {
			return nil, err
		}
		if set {
			proxy["trustedProxyCount"] = n
		}
	}
	if v, _ := get("TRUSTED_PROXY_HEADER"); v != "" {
		touched = true
		h := strings.ToLower(v)
		if !docContains(doctorProxyHeaders, h) {
			return nil, fmt.Errorf("TRUSTED_PROXY_HEADER must be one of %s", strings.Join(doctorProxyHeaders, ", "))
		}
		proxy["header"] = h
	}
	if v, ok := get("PCA_TRUSTED_PROXY_HOPS"); ok {
		touched = true
		n, set, err := docEnvInt("PCA_TRUSTED_PROXY_HOPS", v, ok)
		if err != nil {
			return nil, err
		}
		if set {
			proxy["hops"] = n
		}
	}
	if touched {
		c["proxy"] = proxy
	}
	verifier := map[string]any{}
	if v, ok := get("PCA_ALLOWED_SUITES"); ok {
		l := []any{}
		for _, s := range strings.Split(v, ",") {
			if t := jsTrim(s); t != "" {
				l = append(l, t)
			}
		}
		verifier["allowedSuites"] = l
	}
	if v, _ := get("PCA_PQ_PINS"); v != "" {
		pins, err := ParseJSONLenient([]byte(v))
		if err != nil {
			return nil, errors.New("PCA_PQ_PINS is not valid JSON") // never echo the value
		}
		m, isObj := pins.(map[string]any)
		if isObj {
			for _, x := range m {
				if _, isStr := x.(string); !isStr {
					isObj = false
				}
			}
		}
		if !isObj {
			return nil, errors.New("PCA_PQ_PINS must be a JSON object of issuer -> public key strings")
		}
		verifier["pqPins"] = m
	}
	if v, ok := get("PCA_ALLOW_UNBOUND_PQ"); ok {
		verifier["allowUnboundPq"] = docContains([]string{"1", "true", "yes", "on"}, docAsciiLower(v))
	}
	if len(verifier) > 0 {
		c["verifier"] = verifier
	}
	return c, nil
}

// docSpread is `{...v}` of a decoded JSON value: an object's members, an array's or a string's indices.
func docSpread(v any) map[string]any {
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
			out[strconv.Itoa(i)] = docFromUnits([]uint16{u})
		}
	}
	return out
}

// DoctorMergeConfig is a two-level merge: later sources win per field inside each section.
func DoctorMergeConfig(cs ...map[string]any) (map[string]any, error) {
	out := map[string]any{}
	for _, c := range cs {
		for _, k := range jsKeys(c) {
			if k == "__proto__" || k == "constructor" || k == "prototype" {
				return nil, fmt.Errorf("config key \"%s\" is not allowed", k)
			}
			if val, isObj := c[k].(map[string]any); isObj {
				prev, has := out[k]
				if !has || prev == nil {
					prev = map[string]any{}
				}
				merged := docSpread(prev)
				for mk, mv := range val {
					merged[mk] = mv
				}
				out[k] = merged
			} else {
				out[k] = c[k]
			}
		}
	}
	return out, nil
}

// DoctorLoadConfigFile reads a JSON config file.
func DoctorLoadConfigFile(path string) (map[string]any, error) {
	if !strings.HasSuffix(path, ".json") {
		return nil, fmt.Errorf("only a .json config file can be loaded: %s", path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	v, err := ParseJSONLenient(b)
	if err != nil {
		return nil, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s: not a JSON object", path)
	}
	return m, nil
}

// ---- CLI ----------------------------------------------------------------------------------------------------------------

// DoctorArgs is the parsed command line.
type DoctorArgs struct {
	Flags  map[string]any // a config
	Only   []string
	JSON   bool
	Strict bool
	Help   bool
	Config *string
}

func docGroups(flag string, v *string) ([]string, error) {
	var g, bad []string
	if v != nil {
		for _, x := range strings.Split(*v, ",") {
			if x != "" {
				g = append(g, x)
			}
		}
	}
	for _, x := range g {
		if !docContains(DoctorCheckGroups, x) {
			bad = append(bad, x)
		}
	}
	if len(bad) > 0 || len(g) == 0 {
		why := strings.Join(bad, ", ")
		if why == "" {
			why = "(none given)"
		}
		return nil, fmt.Errorf("%s: unknown check group(s) %s", flag, why)
	}
	return g, nil
}

func docNumArg(flag string, v *string) (any, error) {
	n := math.NaN()
	if v != nil && *v != "" {
		n = jsStringToNumber(*v)
	}
	if math.IsNaN(n) || math.IsInf(n, 0) {
		return nil, fmt.Errorf("%s needs a number", flag)
	}
	return jsNumber(n), nil
}

// DoctorParseArgs parses the command line (the arguments after the program name).
func DoctorParseArgs(argv []string) (*DoctorArgs, error) {
	a := &DoctorArgs{Flags: map[string]any{}, Only: append([]string{}, DoctorCheckGroups...)}
	f := a.Flags
	sub := func(name string) map[string]any {
		d := map[string]any{}
		if old, ok := f[name].(map[string]any); ok {
			for k, v := range old {
				d[k] = v
			}
		}
		f[name] = d
		return d
	}
	i := 0
	nxt := func() *string {
		i++
		if i < len(argv) {
			return &argv[i]
		}
		return nil
	}
	set := func(d map[string]any, key string, v *string) {
		if v == nil {
			delete(d, key)
		} else {
			d[key] = *v
		}
	}
	for i < len(argv) {
		k := argv[i]
		switch k {
		case "--url":
			set(f, "url", nxt())
		case "--config":
			a.Config = nxt()
		case "--store":
			set(sub("store"), "adapter", nxt())
		case "--store-option":
			kv := ""
			if p := nxt(); p != nil {
				kv = *p
			}
			eq := strings.IndexByte(kv, '=')
			if eq < 1 {
				return nil, errors.New("--store-option needs k=v")
			}
			st := sub("store")
			opts := map[string]any{}
			if old, ok := st["options"].(map[string]any); ok {
				for ok2, ov := range old {
					opts[ok2] = ov
				}
			}
			opts[kv[:eq]] = kv[eq+1:]
			st["options"] = opts
		case "--reference":
			set(sub("clock"), "referenceUrl", nxt())
		case "--max-skew-ms":
			n, err := docNumArg(k, nxt())
			if err != nil {
				return nil, err
			}
			sub("clock")["maxSkewMs"] = n
		case "--trusted-proxy-count":
			n, err := docNumArg(k, nxt())
			if err != nil {
				return nil, err
			}
			sub("proxy")["trustedProxyCount"] = n
		case "--proxy-header":
			h := ""
			if p := nxt(); p != nil {
				h = strings.ToLower(*p)
			}
			if !docContains(doctorProxyHeaders, h) {
				return nil, errors.New("--proxy-header must be x-forwarded-for, forwarded or x-real-ip")
			}
			sub("proxy")["header"] = h
		case "--proxy-hops":
			n, err := docNumArg(k, nxt())
			if err != nil {
				return nil, err
			}
			sub("proxy")["hops"] = n
		case "--no-probe":
			sub("proxy")["probe"] = false
		case "--pca-dir":
			set(sub("verifier"), "pcaDir", nxt())
		case "--only":
			g, err := docGroups(k, nxt())
			if err != nil {
				return nil, err
			}
			a.Only = g
		case "--skip":
			s, err := docGroups(k, nxt())
			if err != nil {
				return nil, err
			}
			keep := []string{}
			for _, g := range a.Only {
				if !docContains(s, g) {
					keep = append(keep, g)
				}
			}
			a.Only = keep
		case "--strict":
			a.Strict = true
		case "--json":
			a.JSON = true
		case "-h", "--help":
			a.Help = true
		default:
			return nil, fmt.Errorf("unknown argument %s", k)
		}
		i++
	}
	return a, nil
}

// docKeyRank gives the member order of the doctor's own JSON objects (the reference prints them in insertion order).
var docKeyRank = func() map[string]int {
	m := map[string]int{}
	for i, k := range []string{"target", "verdict", "results", "id", "status", "detail", "remediation", "observed", "skewMs", "uncertaintyMs", "maxSkewMs",
		"warnAtMs", "reference", "url", "remaining", "version", "over", "under", "unknown", "allowed", "reasons"} {
		m[k] = i + 1
	}
	return m
}()

// docStringify is JSON.stringify(v, null, 2) over decoded JSON values (the doctor's own members in their reference order).
func docStringify(v any, ind string) string {
	inner := ind + "  "
	switch t := v.(type) {
	case nil:
		return "null"
	case bool:
		return strconv.FormatBool(t)
	case string:
		return gwJSONString(t)
	case []any:
		if len(t) == 0 {
			return "[]"
		}
		parts := make([]string, len(t))
		for i, x := range t {
			parts[i] = inner + docStringify(x, inner)
		}
		return "[\n" + strings.Join(parts, ",\n") + "\n" + ind + "]"
	case []map[string]any:
		l := make([]any, len(t))
		for i, x := range t {
			l[i] = x
		}
		return docStringify(l, ind)
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			ri, rj := docKeyRank[keys[i]], docKeyRank[keys[j]]
			if (ri == 0) != (rj == 0) {
				return ri != 0
			}
			if ri != rj {
				return ri < rj
			}
			return keys[i] < keys[j]
		})
		if len(keys) == 0 {
			return "{}"
		}
		parts := make([]string, len(keys))
		for i, k := range keys {
			parts[i] = inner + gwJSONString(k) + ": " + docStringify(t[k], inner)
		}
		return "{\n" + strings.Join(parts, ",\n") + "\n" + ind + "}"
	}
	if f, ok := jsNum(v); ok {
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return "null"
		}
		return jsNumberString(f)
	}
	return "null"
}

// DoctorMain runs the CLI: exit code 1 on any fail (and on warn with --strict), 2 on usage errors, else 0. A nil env reads the
// process environment.
func DoctorMain(argv []string, env map[string]string, printOut, printErr func(string), deps DoctorDeps) int {
	if env == nil {
		env = map[string]string{}
		for _, kv := range os.Environ() {
			if eq := strings.IndexByte(kv, '='); eq > 0 {
				env[kv[:eq]] = kv[eq+1:]
			}
		}
	}
	usage := func(err error) int {
		printErr(DoctorScrubText(err.Error()) + "\n\n" + DoctorUsage)
		return 2
	}
	a, err := DoctorParseArgs(argv)
	if err != nil {
		return usage(err)
	}
	if a.Help {
		printOut(DoctorUsage)
		return 0
	}
	file := map[string]any{}
	if a.Config != nil && *a.Config != "" {
		if file, err = DoctorLoadConfigFile(*a.Config); err != nil {
			return usage(err)
		}
	}
	fromEnv, err := DoctorConfigFromEnv(env)
	if err != nil {
		return usage(err)
	}
	cfg, err := DoctorMergeConfig(file, fromEnv, a.Flags)
	if err != nil {
		return usage(err)
	}
	results := DoctorRun(cfg, a.Only, deps)
	verdict := DoctorVerdictOf(results, a.Strict)
	u := cfg["url"]
	if a.JSON {
		printOut(docStringify(map[string]any{"target": u, "verdict": verdict, "results": results}, ""))
	} else {
		target := ""
		if docTruthy(docNN(u, docUndef)) {
			target = docStr(u)
		}
		printOut(DoctorFormatResults(results, target, a.Strict))
	}
	if verdict == "fail" {
		return 1
	}
	return 0
}
