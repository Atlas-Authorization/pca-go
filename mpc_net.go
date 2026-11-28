package pca

// The pure parts of the MPC networked runner: the length-prefixed JSON frame codec with strict envelope validation, the canonical
// hex field-element encoding, the structured abort that blames a party only when the evidence names one, pairwise-authenticated
// shares for the identifiable-abort mode, the forensic audit of a failed offline triple and the gadget-seed commitment helpers.
// Sockets, TLS and the distributed protocol driver are not part of this file.
//
// Native stringify: object members are written in sorted key order (Go maps are unordered), except a forensic disclosure record
// ({bits, y, z, recv, rho}), whose fixed member order is the wire form. The reference writes insertion order; the two agree on
// every value the protocol itself produces, and a peer must not depend on member order (frames are parsed, not compared as text).

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/big"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	// MpcWireVersion is the frame envelope version; a peer on another version is rejected as a version mismatch.
	MpcWireVersion = 2
	// MpcMaxFrameBytes is the largest frame body accepted or produced (4 MiB).
	MpcMaxFrameBytes = 4 * 1024 * 1024
	// MpcDefaultForensicDeadlineMs is the default window of the forensic disclosure exchange.
	MpcDefaultForensicDeadlineMs = 30000
)

// MpcAbortKinds are the abort kinds, sorted.
var MpcAbortKinds = []string{"commitment", "dealer", "disconnect", "duplicate", "equivocation", "flood", "identity", "local", "mac-check", "malformed",
	"ot-check", "out-of-order", "oversize", "peer-abort", "timeout", "version", "wrong-round", "wrong-session"}

var (
	mpcFrameTypes = map[string]bool{"hello": true, "msg": true, "abort": true}
	mpcHex61      = regexp.MustCompile(`^(0|[1-9a-f][0-9a-f]{0,15})$`)
	mpcHex255     = regexp.MustCompile(`^(0|[1-9a-f][0-9a-f]{0,63})$`)
	mpcB64Re      = regexp.MustCompile(`^[A-Za-z0-9+/]*={0,2}$`)
	mpcEcQ        = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
)

// MpcNetAbort is a protocol abort; Blamed is nil when the evidence names no culprit (then Reason explains why).
type MpcNetAbort struct {
	Kind         string
	Blamed       *int
	Reporter     int
	ClaimedKind  *string
	ClaimedBlame *int
	Reason       *string
	Evidence     any
	DeadlineMs   *int
	msg          string
}

func (e *MpcNetAbort) Error() string { return e.msg }

func NewMpcNetAbort(kind string, blamed *int, reporter int, detail string, claimedKind *string, claimedBlame *int, reason *string, evidence any, deadlineMs *int) *MpcNetAbort {
	b := "none"
	if blamed != nil {
		b = strconv.Itoa(*blamed)
	}
	e := &MpcNetAbort{Kind: kind, Blamed: blamed, Reporter: reporter, ClaimedKind: claimedKind, ClaimedBlame: claimedBlame, Evidence: evidence, DeadlineMs: deadlineMs,
		msg: fmt.Sprintf("[%s] blamed=%s reporter=%d: %s", kind, b, reporter, detail)}
	if blamed == nil {
		r := "unattributable: the evidence available to this party does not identify a culprit"
		if reason != nil && *reason != "" {
			r = *reason
		}
		e.Reason = &r
	}
	return e
}

// ---- JSON text (JSON.stringify for the value shapes the protocol uses)

func MpcStringify(v any) (string, error) {
	var sb strings.Builder
	if err := mpcWrite(&sb, v); err != nil {
		return "", err
	}
	return sb.String(), nil
}

func mpcWrite(sb *strings.Builder, v any) error {
	switch t := v.(type) {
	case nil:
		sb.WriteString("null")
	case bool:
		sb.WriteString(strconv.FormatBool(t))
	case string:
		mpcQuote(sb, t)
	case int:
		sb.WriteString(strconv.Itoa(t))
	case int64:
		sb.WriteString(strconv.FormatInt(t, 10))
	case *big.Int:
		sb.WriteString(t.String())
	case []any:
		sb.WriteByte('[')
		for i, x := range t {
			if i > 0 {
				sb.WriteByte(',')
			}
			if err := mpcWrite(sb, x); err != nil {
				return err
			}
		}
		sb.WriteByte(']')
	case map[string]any:
		// a frame a peer sent keeps the member order it arrived in (JSON.stringify of the parsed value, which the transcript digest
		// hashes: a sender that writes its members in another order is hashed as it wrote them); a map built here has no recorded
		// order, so it takes the reference's construction order for the shapes below and sorted order otherwise
		keys, recorded := mpcKeyOrder(t)
		if !recorded {
			keys = make([]string, 0, len(t))
			for k := range t {
				keys = append(keys, k)
			}
			sort.Strings(keys)
		}
		if !recorded && len(keys) == 2 && t["s"] != nil && t["nonce"] != nil { // a sigma opening: the reference's member order, which the transcript hashes
			keys = []string{"s", "nonce"}
		}
		if !recorded && len(keys) == 5 && t["bits"] != nil && t["recv"] != nil && t["rho"] != nil && t["y"] != nil && t["z"] != nil {
			keys = []string{"bits", "y", "z", "recv", "rho"}
		}
		sb.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				sb.WriteByte(',')
			}
			mpcQuote(sb, k)
			sb.WriteByte(':')
			if err := mpcWrite(sb, t[k]); err != nil {
				return err
			}
		}
		sb.WriteByte('}')
	default:
		f, ok := jsNum(v)
		if !ok {
			return fmt.Errorf("stringify: unsupported value %T", v)
		}
		sb.WriteString(jsNumberString(f))
	}
	return nil
}

func mpcQuote(sb *strings.Builder, s string) {
	sb.WriteByte('"')
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1: // a lone surrogate (WTF-8) or invalid byte
			fmt.Fprintf(sb, "\\ufffd")
		case r == '"':
			sb.WriteString(`\"`)
		case r == '\\':
			sb.WriteString(`\\`)
		case r == '\b':
			sb.WriteString(`\b`)
		case r == '\f':
			sb.WriteString(`\f`)
		case r == '\n':
			sb.WriteString(`\n`)
		case r == '\r':
			sb.WriteString(`\r`)
		case r == '\t':
			sb.WriteString(`\t`)
		case r < 0x20:
			fmt.Fprintf(sb, "\\u%04x", r)
		default:
			sb.WriteString(s[i : i+size])
		}
		i += size
	}
	sb.WriteByte('"')
}

// MpcEncodeFrame is the length-prefixed (4-byte big-endian) JSON frame {v, ty, sid, seq, rd, d}; a body over MpcMaxFrameBytes is refused.
func MpcEncodeFrame(v any, ty, sid string, seq any, rd string, d any) ([]byte, error) {
	var sb strings.Builder
	sb.WriteString(`{"v":`)
	if err := mpcWrite(&sb, v); err != nil {
		return nil, err
	}
	for _, kv := range []struct {
		k string
		v any
	}{{"ty", ty}, {"sid", sid}, {"seq", seq}, {"rd", rd}, {"d", d}} {
		sb.WriteString(`,"` + kv.k + `":`)
		if err := mpcWrite(&sb, kv.v); err != nil {
			return nil, err
		}
	}
	sb.WriteByte('}')
	if sb.Len() > MpcMaxFrameBytes {
		return nil, errors.New("frame too large")
	}
	out := binary.BigEndian.AppendUint32(nil, uint32(sb.Len()))
	return append(out, sb.String()...), nil
}

// MpcFrameSplitter reassembles length-prefixed frames from arbitrary chunking; an oversize length prefix is refused.
type MpcFrameSplitter struct{ data []byte }

func (s *MpcFrameSplitter) Push(chunk []byte) ([][]byte, error) {
	s.data = append(s.data, chunk...)
	out := [][]byte{}
	off := 0
	for len(s.data)-off >= 4 {
		n := int(binary.BigEndian.Uint32(s.data[off:]))
		if n > MpcMaxFrameBytes {
			return nil, errors.New("oversize")
		}
		if len(s.data)-off < 4+n {
			break
		}
		out = append(out, append([]byte(nil), s.data[off+4:off+4+n]...))
		off += 4 + n
	}
	s.data = append([]byte(nil), s.data[off:]...)
	return out, nil
}

// ---- envelope validation

func mpcParseObject(body []byte) map[string]any {
	v, err := ParseJSONLastWins(body) // JSON.parse: a repeated member keeps its last value
	if err != nil {
		return nil
	}
	m, _ := mpcNormalize(v).(map[string]any)
	return m
}

// mpcNormalize is normalizeJSON keeping each object's member order (jsKeys of the parsed value), so a frame re-stringified for the
// transcript reads in the order the peer wrote it.
func mpcNormalize(v any) any {
	switch t := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(t))
		for k, x := range t {
			m[k] = mpcNormalize(x)
		}
		recordKeyOrder(m, jsKeys(t))
		return m
	case []any:
		a := make([]any, len(t))
		for i, x := range t {
			a[i] = mpcNormalize(x)
		}
		return a
	}
	return normalizeJSON(v)
}

// mpcKeyOrder is the recorded member order of a parsed object, false for a map built in code.
func mpcKeyOrder(m map[string]any) ([]string, bool) {
	p := reflect.ValueOf(m).UnsafePointer()
	if p == nil {
		return nil, false
	}
	v, ok := keyOrders.Load(uintptr(p))
	if !ok {
		return nil, false
	}
	e := v.(*keyOrderEntry)
	if len(e.keys) != len(m) {
		return nil, false
	}
	for _, k := range e.keys {
		if _, has := m[k]; !has {
			return nil, false
		}
	}
	return append([]string(nil), e.keys...), true
}

func mpcSafeInt(f float64, ok bool) bool {
	return ok && !math.IsInf(f, 0) && !math.IsNaN(f) && f == math.Trunc(f) && math.Abs(f) <= 9007199254740991
}

func mpcNegZero(f float64) bool { return f == 0 && math.Signbit(f) }

// MpcPeekVersion is the envelope version of a body, or false when it is not a JSON object with a safe-integer v.
func MpcPeekVersion(body []byte) (int64, bool) {
	o := mpcParseObject(body)
	if o == nil {
		return 0, false
	}
	f, ok := jsNum(o["v"])
	if !mpcSafeInt(f, ok) || mpcNegZero(f) {
		return 0, false
	}
	return int64(f), true
}

func mpcEnvelopeOK(o map[string]any) bool {
	if len(o) != 6 {
		return false
	}
	if _, has := o["v"]; !has {
		return false
	}
	if ty, ok := o["ty"].(string); !ok || !mpcFrameTypes[ty] {
		return false
	}
	if _, ok := o["sid"].(string); !ok {
		return false
	}
	if _, ok := o["rd"].(string); !ok {
		return false
	}
	seq, ok := jsNum(o["seq"])
	if !mpcSafeInt(seq, ok) || seq < 0 || mpcNegZero(seq) {
		return false
	}
	_, has := o["d"]
	return has
}

// MpcParseFrame is the frame as a map when it is a well-formed envelope of the current version, else nil.
func MpcParseFrame(body []byte) map[string]any {
	o := mpcParseObject(body)
	if o == nil {
		return nil
	}
	if v, ok := jsNum(o["v"]); !ok || v != MpcWireVersion || !mpcEnvelopeOK(o) {
		return nil
	}
	return o
}

// MpcVersionMismatch is the peer's version when the body is a well-formed envelope of a DIFFERENT version.
func MpcVersionMismatch(body []byte) (int64, bool) {
	o := mpcParseObject(body)
	if o == nil {
		return 0, false
	}
	v, ok := jsNum(o["v"])
	if !mpcSafeInt(v, ok) || mpcNegZero(v) || v == MpcWireVersion || !mpcEnvelopeOK(o) {
		return 0, false
	}
	return int64(v), true
}

// ---- canonical field-element hex

func MpcHx(x *big.Int) string { return x.Text(16) }

// MpcUnhx is a canonical lowercase hex field element below the prime, or nil.
func MpcUnhx(s any) *big.Int {
	str, ok := s.(string)
	if !ok || !mpcHex61.MatchString(str) {
		return nil
	}
	v, _ := new(big.Int).SetString(str, 16)
	if v.Cmp(MpcPrime) >= 0 {
		return nil
	}
	return v
}

func MpcUnhxArray(a any, n int) []*big.Int {
	l, ok := a.([]any)
	if !ok || len(l) != n {
		return nil
	}
	out := make([]*big.Int, n)
	for i, x := range l {
		if out[i] = MpcUnhx(x); out[i] == nil {
			return nil
		}
	}
	return out
}

// ---- pairwise-authenticated shares

// MpcPA is x with Tag[j] (my tag for verifier j) and Key[j] (my key for verifying j's share).
type MpcPA struct {
	X        *big.Int
	Tag, Key []*big.Int
}

// MpcAW is an authenticated value: a value share plus one MAC share per global key, each pairwise-authenticated.
type MpcAW struct {
	V MpcPA
	M []MpcPA
}

type MpcPaEnv struct {
	ID, N  int
	Delta  *big.Int
	Tagged bool
}

func mpcZipPA(a, b []*big.Int, f func(x, y *big.Int) *big.Int) []*big.Int {
	o := make([]*big.Int, len(a))
	for i := range a {
		o[i] = f(a[i], b[i])
	}
	return o
}

func mpcMapPA(a []*big.Int, f func(x *big.Int) *big.Int) []*big.Int {
	o := make([]*big.Int, len(a))
	for i := range a {
		o[i] = f(a[i])
	}
	return o
}

func MpcPaAdd(a, b MpcPA) MpcPA {
	return MpcPA{MpcFAdd(a.X, b.X), mpcZipPA(a.Tag, b.Tag, MpcFAdd), mpcZipPA(a.Key, b.Key, MpcFAdd)}
}
func MpcPaSub(a, b MpcPA) MpcPA {
	return MpcPA{MpcFSub(a.X, b.X), mpcZipPA(a.Tag, b.Tag, MpcFSub), mpcZipPA(a.Key, b.Key, MpcFSub)}
}
func MpcPaNeg(a MpcPA) MpcPA {
	return MpcPA{MpcFNeg(a.X), mpcMapPA(a.Tag, MpcFNeg), mpcMapPA(a.Key, MpcFNeg)}
}
func MpcPaScale(a MpcPA, c *big.Int) MpcPA {
	m := func(t *big.Int) *big.Int { return MpcFMul(t, c) }
	return MpcPA{MpcFMul(a.X, c), mpcMapPA(a.Tag, m), mpcMapPA(a.Key, m)}
}

// MpcPaAddPublic0 adds a PUBLIC constant to party 0's share (every party applies the same call).
func MpcPaAddPublic0(env MpcPaEnv, a MpcPA, c *big.Int) MpcPA {
	if env.ID == 0 {
		return MpcPA{MpcFAdd(a.X, c), a.Tag, a.Key}
	}
	if !env.Tagged {
		return a
	}
	key := append([]*big.Int(nil), a.Key...)
	key[0] = MpcFSub(key[0], MpcFMul(env.Delta, c))
	return MpcPA{a.X, a.Tag, key}
}

func MpcWAdd(a, b MpcAW) MpcAW {
	m := make([]MpcPA, len(a.M))
	for l := range m {
		m[l] = MpcPaAdd(a.M[l], b.M[l])
	}
	return MpcAW{MpcPaAdd(a.V, b.V), m}
}

func MpcWSub(a, b MpcAW) MpcAW {
	m := make([]MpcPA, len(a.M))
	for l := range m {
		m[l] = MpcPaSub(a.M[l], b.M[l])
	}
	return MpcAW{MpcPaSub(a.V, b.V), m}
}

func MpcWNeg(a MpcAW) MpcAW {
	m := make([]MpcPA, len(a.M))
	for l := range m {
		m[l] = MpcPaNeg(a.M[l])
	}
	return MpcAW{MpcPaNeg(a.V), m}
}

func MpcWScale(a MpcAW, c *big.Int) MpcAW {
	m := make([]MpcPA, len(a.M))
	for l := range m {
		m[l] = MpcPaScale(a.M[l], c)
	}
	return MpcAW{MpcPaScale(a.V, c), m}
}

// MpcWAddPublic is x + c for a PUBLIC c: party 0's value share moves by c and every MAC share moves by alpha_i * c.
func MpcWAddPublic(env MpcPaEnv, a MpcAW, c *big.Int, alpha []MpcPA) MpcAW {
	m := make([]MpcPA, len(a.M))
	for l := range m {
		m[l] = MpcPaAdd(a.M[l], MpcPaScale(alpha[l], c))
	}
	return MpcAW{MpcPaAddPublic0(env, a.V, c), m}
}

// MpcPaVerify checks peer from's opened share x with tag against my key for that peer.
func MpcPaVerify(env MpcPaEnv, a MpcPA, from int, x, tag *big.Int) bool {
	return MpcFAdd(a.Key[from], MpcFMul(env.Delta, x)).Cmp(tag) == 0
}

func MpcPaWidth(n int, tagged bool) int {
	if tagged {
		return 1 + 2*(n-1)
	}
	return 1
}

func MpcPaFlat(a MpcPA, id, n int, tagged bool) []*big.Int {
	out := []*big.Int{a.X}
	if tagged {
		for j := 0; j < n; j++ {
			if j != id {
				out = append(out, a.Tag[j])
			}
		}
		for j := 0; j < n; j++ {
			if j != id {
				out = append(out, a.Key[j])
			}
		}
	}
	return out
}

func MpcPaParse(nums []*big.Int, off, id, n int, tagged bool) (MpcPA, error) {
	if off < 0 || off >= len(nums) {
		return MpcPA{}, errors.New("paParse: short input")
	}
	if !tagged {
		return MpcPA{nums[off], []*big.Int{}, []*big.Int{}}, nil
	}
	if off+MpcPaWidth(n, true) > len(nums) {
		return MpcPA{}, errors.New("paParse: short input")
	}
	tag, key := make([]*big.Int, n), make([]*big.Int, n)
	for j := range tag {
		tag[j], key[j] = new(big.Int), new(big.Int)
	}
	o := off + 1
	for j := 0; j < n; j++ {
		if j != id {
			tag[j] = nums[o]
			o++
		}
	}
	for j := 0; j < n; j++ {
		if j != id {
			key[j] = nums[o]
			o++
		}
	}
	return MpcPA{nums[off], tag, key}, nil
}

func MpcAwWidth(n, keys int, tagged bool) int { return (1 + keys) * MpcPaWidth(n, tagged) }

func MpcAwFlat(a MpcAW, id, n int, tagged bool) []*big.Int {
	out := MpcPaFlat(a.V, id, n, tagged)
	for _, p := range a.M {
		out = append(out, MpcPaFlat(p, id, n, tagged)...)
	}
	return out
}

func MpcAwParse(nums []*big.Int, off, id, n, keys int, tagged bool) (MpcAW, error) {
	w := MpcPaWidth(n, tagged)
	v, err := MpcPaParse(nums, off, id, n, tagged)
	if err != nil {
		return MpcAW{}, err
	}
	m := make([]MpcPA, keys)
	for l := range m {
		if m[l], err = MpcPaParse(nums, off+(1+l)*w, id, n, tagged); err != nil {
			return MpcAW{}, err
		}
	}
	return MpcAW{v, m}, nil
}

// MpcSharingsPerTriple is the number of authenticated sharings one triple with that many sacrifice partners needs.
func MpcSharingsPerTriple(partners int) int { return 3 + 2*partners }

// ---- codecs and the gadget-seed agreement

func MpcB64(u []byte) string { return base64.StdEncoding.EncodeToString(u) }

// MpcUnb64 is strict base64: re-encoding must reproduce the input (no trailing-bit or padding aliases); n < 0 means any length.
func MpcUnb64(s any, n int) ([]byte, error) {
	str, ok := s.(string)
	if !ok || !mpcB64Re.MatchString(str) {
		return nil, errors.New("bad base64")
	}
	b, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return nil, errors.New("bad base64")
	}
	if base64.StdEncoding.EncodeToString(b) != str {
		return nil, errors.New("non-canonical base64")
	}
	if n >= 0 && len(b) != n {
		return nil, errors.New("bad length")
	}
	return b, nil
}

// MpcHexBig is a canonical lowercase hex element below the curve field prime 2^255 - 19.
func MpcHexBig(s any) (*big.Int, error) {
	str, ok := s.(string)
	if !ok || !mpcHex255.MatchString(str) {
		return nil, errors.New("bad field element")
	}
	v, _ := new(big.Int).SetString(str, 16)
	if v.Cmp(mpcEcQ) >= 0 {
		return nil, errors.New("non-canonical field element")
	}
	return v, nil
}

// MpcGadgetCommit is the commitment to a party's gadget seed: SHA-256(tag, session, decimal party, seed) as hex.
func MpcGadgetCommit(sessionID string, party int, seed []byte) string {
	h := sha256.New()
	h.Write([]byte("atlas-pca-mpc/gadget-commit"))
	h.Write([]byte(wellFormedUTF8(sessionID)))
	h.Write([]byte(strconv.Itoa(party)))
	h.Write(seed)
	return hex.EncodeToString(h.Sum(nil))
}

// MpcGadgetStatement is the exact bytes a party signs in the gadget seed exchange (round is "gd-c" or "gd-o").
func MpcGadgetStatement(sessionID, round string, signer int, value string) ([]byte, error) {
	s, err := MpcStringify([]any{"atlas-pca-mpc/gadget-sig/v1", sessionID, round, signer, value})
	return []byte(s), err
}

// ---- forensics

// MpcPeerEntry is one peer's per-row values (the peer table keeps its wire order).
type MpcPeerEntry struct {
	Peer int
	Vals []*big.Int
}

// MpcSlotDisclosure is one product item's disclosure.
type MpcSlotDisclosure struct {
	Bits      []int
	Y, Z      *big.Int
	Recv, Rho []MpcPeerEntry
}

func mpcPeerVals(es []MpcPeerEntry, peer int) []*big.Int {
	for _, e := range es {
		if e.Peer == peer {
			return e.Vals
		}
	}
	return nil
}

func MpcSlotsFor(partners int) int { return 1 + partners }

func mpcSideWire(es []MpcPeerEntry) []any {
	out := []any{}
	for _, e := range es {
		vals := []any{}
		for _, v := range e.Vals {
			vals = append(vals, MpcHx(v))
		}
		out = append(out, []any{e.Peer, vals})
	}
	return out
}

// MpcWireDisclosure is the wire (JSON) form of a disclosure.
func MpcWireDisclosure(d []MpcSlotDisclosure) []any {
	out := []any{}
	for _, s := range d {
		var bits strings.Builder
		for _, b := range s.Bits {
			bits.WriteString(strconv.Itoa(b))
		}
		out = append(out, map[string]any{"bits": bits.String(), "y": MpcHx(s.Y), "z": MpcHx(s.Z), "recv": mpcSideWire(s.Recv), "rho": mpcSideWire(s.Rho)})
	}
	return out
}

func mpcSideParse(x any, rows int, peers []int) ([]MpcPeerEntry, error) {
	l, ok := x.([]any)
	if !ok || len(l) != len(peers) {
		return nil, errors.New("bad peer table")
	}
	var out []MpcPeerEntry
	seen := map[int]bool{}
	for _, e := range l {
		pair, ok := e.([]any)
		if !ok || len(pair) != 2 {
			return nil, errors.New("bad peer entry")
		}
		pd, ok := jsNum(pair[0])
		if _, isNum := pair[0].(string); isNum || !ok || pd != math.Trunc(pd) || math.Abs(pd) >= 1e9 {
			return nil, errors.New("bad peer entry")
		}
		p := int(pd)
		known := false
		for _, q := range peers {
			known = known || q == p
		}
		if !known || seen[p] {
			return nil, errors.New("bad peer entry")
		}
		seen[p] = true
		vals, ok := pair[1].([]any)
		if !ok || len(vals) != rows {
			return nil, errors.New("bad row table")
		}
		arr := make([]*big.Int, rows)
		for i := range arr {
			if arr[i] = MpcUnhx(vals[i]); arr[i] == nil {
				return nil, errors.New("bad field element")
			}
		}
		out = append(out, MpcPeerEntry{p, arr})
	}
	return out, nil
}

// MpcParseDisclosure is the strict parse of a peer's disclosure; any deviation from the expected shape is refused.
func MpcParseDisclosure(raw any, slots, rows int, peers []int) ([]MpcSlotDisclosure, error) {
	l, ok := raw.([]any)
	if !ok || len(l) != slots {
		return nil, errors.New("bad forensic disclosure")
	}
	out := []MpcSlotDisclosure{}
	for _, o := range l {
		r, ok := o.(map[string]any)
		if !ok {
			return nil, errors.New("bad choice bits")
		}
		bs, ok := r["bits"].(string)
		if !ok || len(bs) != rows || strings.Trim(bs, "01") != "" {
			return nil, errors.New("bad choice bits")
		}
		bits := make([]int, len(bs))
		for i := range bits {
			bits[i] = int(bs[i] - '0')
		}
		y, z := MpcUnhx(r["y"]), MpcUnhx(r["z"])
		if y == nil || z == nil {
			return nil, errors.New("bad field element")
		}
		recv, err := mpcSideParse(r["recv"], rows, peers)
		if err != nil {
			return nil, err
		}
		rho, err := mpcSideParse(r["rho"], rows, peers)
		if err != nil {
			return nil, err
		}
		out = append(out, MpcSlotDisclosure{bits, y, z, recv, rho})
	}
	return out, nil
}

// MpcAuditResult: SelfBad (sorted) are parties whose own disclosure is inconsistent; PairBad are ordered [receiver, sender] pairs
// whose OT transcripts disagree.
type MpcAuditResult struct {
	SelfBad []int
	PairBad [][2]int
}

// MpcAuditDisclosures cross-checks every party's disclosure of one failed triple against the public gadget.
func MpcAuditDisclosures(all map[int][]MpcSlotDisclosure, gadget []*big.Int) (*MpcAuditResult, error) {
	parties := make([]int, 0, len(all))
	for p := range all {
		parties = append(parties, p)
	}
	sort.Ints(parties)
	selfBad := map[int]bool{}
	res := &MpcAuditResult{}
	for _, i := range parties {
		for s, sd := range all[i] {
			value := new(big.Int)
			for k := range gadget {
				if k < len(sd.Bits) && sd.Bits[k] == 1 {
					value.Add(value, gadget[k])
				}
			}
			implied := MpcFMul(MpcMod(value), sd.Y)
			for _, p := range parties {
				if p == i {
					continue
				}
				recv, rho := mpcPeerVals(sd.Recv, p), mpcPeerVals(sd.Rho, p)
				if recv == nil || rho == nil {
					return nil, errors.New("audit: disclosure misses a peer")
				}
				for _, v := range recv {
					implied = MpcFAdd(implied, MpcMod(v))
				}
				for _, v := range rho {
					implied = MpcFSub(implied, v)
				}
			}
			if implied.Cmp(sd.Z) != 0 {
				selfBad[i] = true
			}
			for _, p := range parties {
				if p == i {
					continue
				}
				if s >= len(all[p]) {
					return nil, errors.New("audit: slot count mismatch")
				}
				sp := all[p][s]
				rho, got := mpcPeerVals(sp.Rho, i), mpcPeerVals(sd.Recv, p)
				if rho == nil || got == nil || len(rho) < len(gadget) || len(got) < len(gadget) {
					return nil, errors.New("audit: disclosure misses a peer")
				}
				y := MpcMod(sp.Y)
				for k := range gadget {
					want := rho[k]
					if k < len(sd.Bits) && sd.Bits[k] == 1 {
						want = MpcFAdd(rho[k], MpcFMul(gadget[k], y))
					} else {
						want = MpcFAdd(rho[k], new(big.Int))
					}
					if MpcMod(got[k]).Cmp(want) != 0 {
						res.PairBad = append(res.PairBad, [2]int{i, p})
						break
					}
				}
			}
		}
	}
	for p := range selfBad {
		res.SelfBad = append(res.SelfBad, p)
	}
	sort.Ints(res.SelfBad)
	return res, nil
}

// MpcBlameFrom is the party the verifier me blames; false when the evidence cannot name one.
func MpcBlameFrom(me int, r *MpcAuditResult) (int, bool) {
	for _, p := range r.SelfBad {
		if p != me {
			return p, true
		}
	}
	for _, pr := range r.PairBad {
		if pr[0] == me {
			return pr[1], true
		}
		if pr[1] == me {
			return pr[0], true
		}
	}
	return 0, false
}

// MpcDisclosureCommit is the binding commitment to a disclosure: session, party, triple index, deadline, a 256-bit nonce and the
// wire form.
func MpcDisclosureCommit(sessionID string, party, tripleIndex int, deadlineMs int64, nonce string, wire any) (string, error) {
	s, err := MpcStringify([]any{sessionID, party, tripleIndex, deadlineMs, nonce, wire})
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(append([]byte("atlas-pca-mpc/forensic-commit/v1\x00"), s...))
	return hex.EncodeToString(h[:]), nil
}
