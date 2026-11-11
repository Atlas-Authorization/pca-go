package pca

// This file sorts first in the package. A mutant of the DER/CRL reader that indexes out of range or returns (nil, nil) makes
// the covering tests panic, which kills the test binary with no failing test reported. Each case below runs under recover so
// that the panic (or a nil result) becomes an ordinary assertion failure.

import (
	"reflect"
	"testing"
	"time"
)

func r7n1safe(t *testing.T, what string, f func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("%s panicked: %v", what, r)
		}
	}()
	f()
}

func TestR7N1_TlvLenientNeverIndexesOutOfRange(t *testing.T) {
	r7n1safe(t, "tlvLenient", func() {
		for _, c := range []struct {
			b     []byte
			limit int
			want  derTlv
		}{
			{[]byte{0x30, 0x00}, 2, derTlv{tag: 0x30, start: 2, end: 2}},
			{[]byte{0x30, 0x81, 0x00}, 3, derTlv{tag: 0x30, start: 3, end: 3}},
			{[]byte{0x30, 0x82, 0x00, 0x01, 0xee}, 5, derTlv{tag: 0x30, start: 4, end: 5}},
			{[]byte{0x30, 0x84, 0, 0, 0, 1, 0xee}, 7, derTlv{tag: 0x30, start: 6, end: 7}},
		} {
			got, err := tlvLenient(c.b, 0, c.limit)
			if err != nil || got != c.want {
				t.Fatalf("%x/%d: %+v %v, want %+v", c.b, c.limit, got, err, c.want)
			}
		}
	})
}

func TestR7N1_CrlTimeNeverIndexesOutOfRange(t *testing.T) {
	r7n1safe(t, "crlTime", func() {
		at := func(y, mo, d, h, mi, s int) int64 {
			return time.Date(y, time.Month(mo), d, h, mi, s, 0, time.UTC).UnixMilli()
		}
		for _, c := range []struct {
			tag  byte
			s    string
			want int64
		}{
			{0x17, "500203040506Z", at(1950, 2, 3, 4, 5, 6)},
			{0x17, "490203040506Z", at(2049, 2, 3, 4, 5, 6)},
			{0x18, "20500203040506Z", at(2050, 2, 3, 4, 5, 6)},
		} {
			b := []byte(c.s)
			got, err := crlTime(b, derTlv{tag: c.tag, start: 0, end: len(b)})
			if err != nil || got != c.want {
				t.Fatalf("%x %s: %d %v, want %d", c.tag, c.s, got, err, c.want)
			}
		}
	})
}

func TestR7N1_ParseCRLReadsEveryFieldWithoutPanicking(t *testing.T) {
	r7n1safe(t, "parseCRL", func() {
		revoked := derTLV(0x30, derTLV(0x30, derTLV(0x02, []byte{0x01, 0x23}), g06tu), derTLV(0x30, derTLV(0x02, []byte{0x00, 0x45}), g06tu))
		for _, c := range []struct {
			name string
			tbs  []byte
		}{
			{"version, UTC times, revoked", g06tbs(g06ver, g06alg, g06iss, g06tu, g06nu, revoked)},
			{"no version", g06tbs(g06alg, g06iss, g06tu, g06nu, revoked)},
			{"GeneralizedTime next", g06tbs(g06ver, g06alg, g06iss, g06tu, derTLV(0x18, []byte("20300101000000Z")), revoked)},
		} {
			crl, err := parseCRL(g06outer(c.tbs))
			if err != nil || crl == nil {
				t.Fatalf("%s: %v %v", c.name, crl, err)
			}
			if crl.thisUpdate != g06TU || crl.nextUpdate != g06NU || !crl.hasNext ||
				!reflect.DeepEqual(crl.revoked, map[string]bool{"123": true, "45": true}) {
				t.Fatalf("%s: %+v", c.name, crl)
			}
		}
	})
}
