package pca

// The host part of the WHATWG URL parser (what `new URL(u).host` returns): scheme detection, the special-scheme authority
// rules (any run of / or \ after the scheme, userinfo dropped, default ports removed), IPv4 in all its numeric forms, IPv6
// compression, IDNA to ASCII and opaque hosts of non-special schemes.
// By default IDNA is lower-casing + NFC + punycode, not the full UTS #46 mapping table; a host using a code point UTS #46 maps
// differently (or forbids) can serialize differently. For full parity install the optional adakit module (SetWhatwgDomainToASCII),
// which routes domain-to-ASCII through the Ada URL parser.

import (
	"errors"
	"strconv"
	"strings"
	"sync/atomic"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

var errInvalidURL = errors.New("Invalid URL")

// whatwgDomainHook is the optional full UTS #46 domain-to-ASCII (see SetWhatwgDomainToASCII).
var whatwgDomainHook atomic.Pointer[func(string) (string, error)]

// SetWhatwgDomainToASCII installs a full WHATWG domain-to-ASCII (UTS #46 mapping, validation, punycode; IPv4 forms may come back
// normalised) used for every non-IP-literal host in place of the built-in lower-case + NFC + punycode. It receives the percent-decoded
// host with no URL-structural character in it, and returns the ASCII host or an error (the URL then fails to parse). nil restores the
// built-in. The adakit module installs an Ada-backed one; call this once at start-up, before any URL is parsed.
func SetWhatwgDomainToASCII(fn func(domain string) (string, error)) {
	if fn == nil {
		whatwgDomainHook.Store(nil)
		return
	}
	whatwgDomainHook.Store(&fn)
}

var whatwgDefaultPort = map[string]string{"http": "80", "https": "443", "ws": "80", "wss": "443", "ftp": "21", "file": ""}

// whatwgURL is the part of a parsed WHATWG URL the bridges read: the scheme (no colon), `host` (with a non-default port) and
// `pathname`.
type whatwgURL struct{ scheme, host, pathname string }

// whatwgHost returns new URL(u).host, or errInvalidURL where the parser fails.
func whatwgHost(u string) (string, error) {
	p, err := whatwgParse(u)
	return p.host, err
}

// whatwgParse parses an absolute URL (there is no base) as the WHATWG URL parser does, up to the pathname.
// shortcut: a file URL's `C|` drive letter is not rewritten to `C:`; upgrade if file URLs with `|` drive letters must be compared.
func whatwgParse(u string) (whatwgURL, error) {
	u = strings.TrimFunc(u, func(r rune) bool { return r <= 0x20 })
	u = strings.NewReplacer("\t", "", "\n", "", "\r", "").Replace(u)
	colon := strings.IndexByte(u, ':')
	if colon < 1 || !isASCIIAlpha(u[0]) {
		return whatwgURL{}, errInvalidURL
	}
	for i := 1; i < colon; i++ {
		if c := u[i]; !isASCIIAlpha(c) && !(c >= '0' && c <= '9') && c != '+' && c != '-' && c != '.' {
			return whatwgURL{}, errInvalidURL
		}
	}
	out := whatwgURL{scheme: strings.ToLower(u[:colon])}
	rest := u[colon+1:]
	def, special := whatwgDefaultPort[out.scheme]
	isSep := func(c byte) bool { return c == '/' || special && c == '\\' }
	var err error
	switch {
	case out.scheme == "file":
		if len(rest) >= 2 && isSep(rest[0]) && isSep(rest[1]) {
			rest = rest[2:]
			end := strings.IndexAny(rest, `/\?#`)
			if end < 0 {
				end = len(rest)
			}
			if auth := rest[:end]; auth != "" && !whatwgDriveLetter(auth) {
				if out.host, err = whatwgDomainHost(auth); err != nil {
					return whatwgURL{}, err
				}
				if out.host == "localhost" {
					out.host = ""
				}
				rest = rest[end:]
			}
		}
	case special:
		rest = strings.TrimLeft(rest, `/\`)
		end := strings.IndexAny(rest, `/\?#`)
		if end < 0 {
			end = len(rest)
		}
		if out.host, err = whatwgAuthority(rest[:end], def, true); err != nil {
			return whatwgURL{}, err
		}
		rest = rest[end:]
	case strings.HasPrefix(rest, "//"):
		rest = rest[2:]
		end := strings.IndexAny(rest, "/?#")
		if end < 0 {
			end = len(rest)
		}
		if out.host, err = whatwgAuthority(rest[:end], "", false); err != nil {
			return whatwgURL{}, err
		}
		rest = rest[end:]
	case !strings.HasPrefix(rest, "/"): // an opaque path
		var b strings.Builder
		for i, r := range rest {
			if r == '?' || r == '#' {
				break
			}
			if r == ' ' && i+1 < len(rest) && (rest[i+1] == '?' || rest[i+1] == '#') {
				b.WriteString("%20")
				continue
			}
			whatwgEncodeRune(&b, r, r < 0x20 || r > 0x7e)
		}
		out.pathname = b.String()
		return out, nil
	}
	if e := strings.IndexAny(rest, "?#"); e >= 0 {
		rest = rest[:e]
	}
	out.pathname = whatwgPath(rest, special, out.scheme == "file")
	return out, nil
}

// whatwgAuthority parses userinfo@host:port (the userinfo is dropped) into the serialized host.
func whatwgAuthority(auth, defPort string, special bool) (string, error) {
	hadCreds := false
	if at := strings.LastIndexByte(auth, '@'); at >= 0 {
		auth, hadCreds = auth[at+1:], true
	}
	host, port := auth, ""
	inBracket := false
	for i := 0; i < len(auth); i++ {
		switch auth[i] {
		case '[':
			inBracket = true
		case ']':
			inBracket = false
		case ':':
			if !inBracket {
				host, port = auth[:i], auth[i+1:]
				i = len(auth)
			}
		}
	}
	if host == "" && (special || hadCreds || port != "") {
		return "", errInvalidURL
	}
	if port != "" {
		for i := 0; i < len(port); i++ {
			if port[i] < '0' || port[i] > '9' {
				return "", errInvalidURL
			}
		}
		n, err := strconv.ParseUint(port, 10, 64)
		if err != nil || n > 65535 {
			return "", errInvalidURL
		}
		port = strconv.FormatUint(n, 10)
		if special && port == defPort {
			port = ""
		}
	}
	var h string
	var err error
	if special {
		h, err = whatwgDomainHost(host)
	} else {
		h, err = whatwgOpaqueHost(host)
	}
	if err != nil {
		return "", err
	}
	if port != "" {
		return h + ":" + port, nil
	}
	return h, nil
}

func whatwgDriveLetter(s string) bool {
	return len(s) == 2 && isASCIIAlpha(s[0]) && (s[1] == ':' || s[1] == '|')
}

// whatwgPath runs the path state over p (query and fragment already cut) and serializes the pathname.
func whatwgPath(p string, special, file bool) string {
	isSep := func(c byte) bool { return c == '/' || special && c == '\\' }
	if p != "" && isSep(p[0]) {
		p = p[1:]
	} else if p == "" && !special {
		return ""
	}
	var segs []string
	var buf strings.Builder
	for i := 0; ; i++ {
		atEnd := i >= len(p)
		if atEnd || isSep(p[i]) {
			seg := buf.String()
			buf.Reset()
			switch l := strings.ToLower(seg); {
			case l == ".." || l == ".%2e" || l == "%2e." || l == "%2e%2e":
				if len(segs) > 0 && !(file && len(segs) == 1 && len(segs[0]) == 2 && isASCIIAlpha(segs[0][0]) && segs[0][1] == ':') {
					segs = segs[:len(segs)-1]
				}
				if atEnd {
					segs = append(segs, "")
				}
			case l == "." || l == "%2e":
				if atEnd {
					segs = append(segs, "")
				}
			default:
				segs = append(segs, seg)
			}
			if atEnd {
				break
			}
			continue
		}
		r, n := utf8.DecodeRuneInString(p[i:])
		i += n - 1
		whatwgEncodeRune(&buf, r, r < 0x20 || r > 0x7e || strings.ContainsRune(" \"#<>?^`{}", r))
	}
	return "/" + strings.Join(segs, "/")
}

func whatwgEncodeRune(b *strings.Builder, r rune, encode bool) {
	if !encode {
		b.WriteRune(r)
		return
	}
	var tmp [4]byte
	for _, c := range tmp[:utf8.EncodeRune(tmp[:], r)] {
		b.WriteString("%" + strings.ToUpper(strconv.FormatUint(uint64(c)|0x100, 16)[1:]))
	}
}

func isASCIIAlpha(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

func whatwgOpaqueHost(h string) (string, error) {
	if strings.HasPrefix(h, "[") {
		if !strings.HasSuffix(h, "]") {
			return "", errInvalidURL
		}
		return whatwgIPv6(h[1 : len(h)-1])
	}
	if strings.ContainsAny(h, " #/:<>?@[\\]^|\x00") {
		return "", errInvalidURL
	}
	var b strings.Builder
	for _, c := range []byte(h) {
		if c < 0x20 || c > 0x7e {
			b.WriteString("%" + strings.ToUpper(strconv.FormatUint(uint64(c)|0x100, 16)[1:]))
		} else {
			b.WriteByte(c)
		}
	}
	return b.String(), nil
}

func whatwgDomainHost(h string) (string, error) {
	if strings.HasPrefix(h, "[") {
		if !strings.HasSuffix(h, "]") {
			return "", errInvalidURL
		}
		return whatwgIPv6(h[1 : len(h)-1])
	}
	d, err := percentDecodeBytes(h)
	if err != nil || !utf8.ValidString(d) {
		return "", errInvalidURL
	}
	if fn := whatwgDomainHook.Load(); fn != nil && d != "" { // an empty host stays the caller's case, as without a hook
		return whatwgHookHost(*fn, d)
	}
	d = norm.NFC.String(strings.ToLower(d))
	for _, r := range d {
		if r <= 0x20 || r == 0x7f || strings.ContainsRune("#%/:<>?@[\\]^|", r) {
			return "", errInvalidURL
		}
	}
	labels := strings.Split(d, ".")
	for i, l := range labels {
		if l == "" {
			continue
		}
		ascii := true
		for j := 0; j < len(l); j++ {
			ascii = ascii && l[j] < 0x80
		}
		if !ascii {
			p, ok := punycodeEncode(l)
			if !ok {
				return "", errInvalidURL
			}
			labels[i] = "xn--" + p
		}
	}
	d = strings.Join(labels, ".")
	if whatwgEndsInNumber(labels) {
		return whatwgIPv4(labels)
	}
	return d, nil
}

// whatwgHookHost is the domain branch with an installed domain-to-ASCII: forbidden host code points are refused first, since the hook
// sees the decoded text and must not re-read it as URL structure.
func whatwgHookHost(fn func(string) (string, error), d string) (string, error) {
	for _, r := range d {
		if r <= 0x20 || r == 0x7f || strings.ContainsRune("#%/:<>?@[\\]^|", r) {
			return "", errInvalidURL
		}
	}
	a, err := fn(d)
	if err != nil || a == "" {
		return "", errInvalidURL
	}
	labels := strings.Split(a, ".")
	if whatwgEndsInNumber(labels) {
		return whatwgIPv4(labels)
	}
	return a, nil
}

func percentDecodeBytes(s string) (string, error) {
	var b []byte
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
				b = append(b, byte(v))
				i += 2
				continue
			}
		}
		b = append(b, s[i])
	}
	return string(b), nil
}

func whatwgEndsInNumber(labels []string) bool {
	if len(labels) > 1 && labels[len(labels)-1] == "" {
		labels = labels[:len(labels)-1]
	}
	last := labels[len(labels)-1]
	if last == "" {
		return false
	}
	digits := true
	for i := 0; i < len(last); i++ {
		digits = digits && last[i] >= '0' && last[i] <= '9'
	}
	if digits {
		return true
	}
	_, ok := whatwgIPv4Part(last)
	return ok
}

func whatwgIPv4Part(p string) (uint64, bool) {
	base := 10
	switch {
	case len(p) >= 2 && (p[:2] == "0x" || p[:2] == "0X"):
		p, base = p[2:], 16
		if p == "" {
			return 0, true
		}
	case len(p) >= 2 && p[0] == '0':
		p, base = p[1:], 8
	}
	n, err := strconv.ParseUint(p, base, 64)
	if err != nil {
		if ne, ok := err.(*strconv.NumError); ok && ne.Err == strconv.ErrRange {
			return 1 << 40, true // larger than any part may be: refused by the caller
		}
		return 0, false
	}
	return n, true
}

func whatwgIPv4(labels []string) (string, error) {
	if len(labels) > 1 && labels[len(labels)-1] == "" {
		labels = labels[:len(labels)-1]
	}
	if len(labels) > 4 {
		return "", errInvalidURL
	}
	nums := make([]uint64, len(labels))
	for i, l := range labels {
		n, ok := whatwgIPv4Part(l)
		if l == "" || !ok {
			return "", errInvalidURL
		}
		nums[i] = n
	}
	for _, n := range nums[:len(nums)-1] {
		if n > 255 {
			return "", errInvalidURL
		}
	}
	last := nums[len(nums)-1]
	if last >= 1<<(8*(5-len(nums))) {
		return "", errInvalidURL
	}
	v := last
	for i, n := range nums[:len(nums)-1] {
		v += n << (8 * (3 - i))
	}
	return strconv.FormatUint(v>>24, 10) + "." + strconv.FormatUint(v>>16&255, 10) + "." + strconv.FormatUint(v>>8&255, 10) + "." + strconv.FormatUint(v&255, 10), nil
}

func whatwgIPv6(s string) (string, error) {
	var parts [8]uint16
	head, tail := s, ""
	double := strings.Contains(s, "::")
	if double {
		i := strings.Index(s, "::")
		head, tail = s[:i], s[i+2:]
		if strings.Contains(tail, "::") {
			return "", errInvalidURL
		}
	}
	parse := func(x string) ([]uint16, error) {
		if x == "" {
			return nil, nil
		}
		var out []uint16
		segs := strings.Split(x, ":")
		for i, g := range segs {
			if i == len(segs)-1 && strings.Contains(g, ".") {
				v4, err := whatwgIPv4Strict(g)
				if err != nil {
					return nil, err
				}
				out = append(out, uint16(v4>>16), uint16(v4))
				continue
			}
			if g == "" || len(g) > 4 {
				return nil, errInvalidURL
			}
			n, err := strconv.ParseUint(g, 16, 16)
			if err != nil {
				return nil, errInvalidURL
			}
			out = append(out, uint16(n))
		}
		return out, nil
	}
	h, err := parse(head)
	if err != nil {
		return "", err
	}
	t, err := parse(tail)
	if err != nil {
		return "", err
	}
	if (!double && len(h) != 8) || (double && len(h)+len(t) > 7) {
		return "", errInvalidURL
	}
	copy(parts[:], h)
	copy(parts[8-len(t):], t)
	// compress the first longest run of two or more zero pieces
	best, bestLen := -1, 1
	for i := 0; i < 8; {
		if parts[i] != 0 {
			i++
			continue
		}
		j := i
		for j < 8 && parts[j] == 0 {
			j++
		}
		if j-i > bestLen {
			best, bestLen = i, j-i
		}
		i = j
	}
	var b strings.Builder
	b.WriteByte('[')
	for i := 0; i < 8; i++ {
		if i == best {
			if i == 0 {
				b.WriteByte(':')
			}
			b.WriteByte(':')
			i += bestLen - 1
			continue
		}
		b.WriteString(strconv.FormatUint(uint64(parts[i]), 16))
		if i < 7 {
			b.WriteByte(':')
		}
	}
	b.WriteByte(']')
	return b.String(), nil
}

func whatwgIPv4Strict(s string) (uint32, error) {
	ps := strings.Split(s, ".")
	if len(ps) != 4 {
		return 0, errInvalidURL
	}
	var v uint32
	for _, p := range ps {
		if p == "" || len(p) > 1 && p[0] == '0' {
			return 0, errInvalidURL
		}
		n, err := strconv.ParseUint(p, 10, 8)
		if err != nil {
			return 0, errInvalidURL
		}
		v = v<<8 | uint32(n)
	}
	return v, nil
}

// punycodeEncode is RFC 3492 encoding of one label.
func punycodeEncode(label string) (string, bool) {
	const base, tmin, tmax, skew, damp, initialBias, initialN = 36, 1, 26, 38, 700, 72, 128
	rs := []rune(label)
	var out []byte
	for _, r := range rs {
		if r < 0x80 {
			out = append(out, byte(r))
		}
	}
	b := len(out)
	h := b
	if b > 0 {
		out = append(out, '-')
	}
	digit := func(d int) byte {
		if d < 26 {
			return byte('a' + d)
		}
		return byte('0' + d - 26)
	}
	adapt := func(delta, numPoints int, first bool) int {
		if first {
			delta /= damp
		} else {
			delta /= 2
		}
		delta += delta / numPoints
		k := 0
		for delta > ((base-tmin)*tmax)/2 {
			delta /= base - tmin
			k += base
		}
		return k + (base-tmin+1)*delta/(delta+skew)
	}
	n, delta, bias := initialN, 0, initialBias
	for h < len(rs) {
		m := int(^uint(0) >> 1)
		for _, r := range rs {
			if int(r) >= n && int(r) < m {
				m = int(r)
			}
		}
		if (m-n)*(h+1) < 0 {
			return "", false
		}
		delta += (m - n) * (h + 1)
		n = m
		for _, r := range rs {
			if int(r) < n {
				delta++
			}
			if int(r) == n {
				q := delta
				for k := base; ; k += base {
					t := k - bias
					if t < tmin {
						t = tmin
					} else if t > tmax {
						t = tmax
					}
					if q < t {
						break
					}
					out = append(out, digit(t+(q-t)%(base-t)))
					q = (q - t) / (base - t)
				}
				out = append(out, digit(q))
				bias = adapt(delta, h+1, h == b)
				delta = 0
				h++
			}
		}
		delta++
		n++
	}
	return string(out), true
}
