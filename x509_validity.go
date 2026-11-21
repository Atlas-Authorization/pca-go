package pca

// Certificate validity windows read the way the reference does: from the certificate's own DER with the RFC 5280 Time profile
// applied strictly (no roll-over, no fractions, no offsets), never from a locale-dependent rendering; an unreadable bound is
// reported as not ok and every validity check on it fails closed.

import (
	"regexp"
	"strconv"
	"time"
)

// DerValidityMs returns the notBefore and notAfter instants (epoch ms) of a DER certificate; ok is false when either is unreadable.
func DerValidityMs(der []byte) (from, to int64, ok bool) {
	f, t := derValidity(der)
	return f.ms, t.ms, f.ok && t.ok
}

// ParseDerTime parses a strict RFC 5280 Time (tag 0x17 UTCTime or 0x18 GeneralizedTime, ending in Z) to epoch ms; ok is false for
// anything else.
func ParseDerTime(tag int, text string) (ms int64, ok bool) {
	i := parseDerTime(tag, text)
	return i.ms, i.ok
}

var openSslRendered = regexp.MustCompile(`^([A-Z][a-z]{2}) {1,2}(\d{1,2}) (\d{2}):(\d{2}):(\d{2})(\.\d+)? (\d{4}) GMT$`)

var openSslMonths = []string{"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"}

// ParseOpenSslTime parses OpenSSL's rendered ASN1_TIME ("Mon DD HH:MM:SS[.fff] YYYY GMT", a four-digit year only) to epoch ms; ok
// is false for anything else, including a roll-over date such as Feb 30.
func ParseOpenSslTime(s string) (ms int64, ok bool) {
	m := openSslRendered.FindStringSubmatch(s)
	if m == nil {
		return 0, false
	}
	mon := -1
	for i, n := range openSslMonths {
		if n == m[1] {
			mon = i
		}
	}
	day, _ := strconv.Atoi(m[2])
	h, _ := strconv.Atoi(m[3])
	mi, _ := strconv.Atoi(m[4])
	sec, _ := strconv.Atoi(m[5])
	y, _ := strconv.Atoi(m[7])
	if mon < 0 || day < 1 || day > 31 || h > 23 || mi > 59 || sec > 59 {
		return 0, false
	}
	nanos := 0
	if m[6] != "" {
		frac, _ := strconv.ParseFloat("0"+m[6], 64)
		nanos = int(frac*1000) * 1_000_000
	}
	d := time.Date(y, time.Month(mon+1), day, h, mi, sec, nanos, time.UTC)
	if int(d.Month()) != mon+1 || d.Day() != day {
		return 0, false
	}
	return d.UnixMilli(), true
}

// X509ValidityLike is the validity facts of a certificate as a host library reports them. Raw (the DER of the whole certificate),
// when present, is the ONLY source of the instants; without it the date members (epoch ms) are used, then the rendered strings.
type X509ValidityLike struct {
	ValidFrom, ValidTo         string
	ValidFromDate, ValidToDate *int64
	Raw                        []byte
}

// X509ValidityMs is the certificate's validity window in epoch ms; each ok is false when that bound is unreadable.
func X509ValidityMs(c X509ValidityLike) (from, to int64, fromOK, toOK bool) {
	if c.Raw != nil {
		f, t := derValidity(c.Raw)
		return f.ms, t.ms, f.ok, t.ok
	}
	one := func(date *int64, rendered string) (int64, bool) {
		if date != nil {
			return *date, true
		}
		return ParseOpenSslTime(rendered)
	}
	from, fromOK = one(c.ValidFromDate, c.ValidFrom)
	to, toOK = one(c.ValidToDate, c.ValidTo)
	return
}

// X509ValidAt reports from - skew <= nowMs <= to + skew; false (fail closed) when either bound is unreadable.
func X509ValidAt(c X509ValidityLike, nowMs int64, skewMs int64) bool {
	from, to, fOK, tOK := X509ValidityMs(c)
	return fOK && tOK && nowMs+skewMs >= from && nowMs-skewMs <= to
}
