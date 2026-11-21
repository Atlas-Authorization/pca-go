package pca

// The authenticated-channel interface of the FROST DKG and the driver that runs one participant's whole ceremony over it. The channel
// supplies the sender's identity (for a TLS channel, the pinned certificate); the message never does. A message names one session; a
// second message of one kind from one sender is refused (identical is "duplicate", different is "equivocation") and the refusal is
// sticky for that peer; every message is size-capped before it is parsed, parsed with the strict JSON profile and shape-checked with
// exact member sets; a missing message at the timeout aborts the run (fail closed); the echo round catches transcript equivocation.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// DkgWireVersion is the version member of every wire message.
	DkgWireVersion = 1
	// DkgMaxMessageBytes is the largest wire message a channel accepts, checked before parsing.
	DkgMaxMessageBytes = 256 * 1024
	// DkgMaxParticipants is the largest participant set the driver accepts.
	DkgMaxParticipants = 256
)

// DkgMessageKinds are the message kinds in protocol order.
var DkgMessageKinds = []string{"round1", "share", "complaints", "rebuttals", "echo"}

// DkgChannelError is every channel and driver refusal. Code is one of timeout, identity, wrong-session, duplicate, equivocation,
// malformed, oversize, closed, protocol, disqualified; Peer is the authenticated party the refusal is about, when HasPeer.
type DkgChannelError struct {
	Code    string
	Peer    int64
	HasPeer bool
	Detail  string
}

func (e *DkgChannelError) Error() string {
	p := ""
	if e.HasPeer {
		p = ", peer " + strconv.FormatInt(e.Peer, 10)
	}
	return "dkg channel (" + e.Code + p + "): " + e.Detail
}

func dkgErr(code string, detail string) *DkgChannelError {
	return &DkgChannelError{Code: code, Detail: detail}
}

func dkgErrPeer(code string, peer int64, detail string) *DkgChannelError {
	return &DkgChannelError{Code: code, Peer: peer, HasPeer: true, Detail: detail}
}

// DkgCollected is one collected body with the AUTHENTICATED sender it came from.
type DkgCollected struct {
	From int64
	Body any
}

// DkgChannel is one participant's end of the authenticated channel. Bodies are wire values (see DkgObject for member order).
type DkgChannel interface {
	Self() int64
	// Peers is every other participant this channel is connected to, ascending.
	Peers() []int64
	// Broadcast is the authenticated broadcast of body to every peer.
	Broadcast(kind string, body any) error
	// Send is the private, authenticated delivery of body to one peer.
	Send(to int64, kind string, body any) error
	// Collect waits for exactly one kind message from each of from and returns the bodies, ascending by AUTHENTICATED sender.
	// It fails with a *DkgChannelError on timeout, a duplicate or divergent second message, a malformed, oversize or wrong-session
	// message from any of from, or a closed channel.
	Collect(kind string, from []int64, timeoutMs float64) ([]DkgCollected, error)
	Close() error
}

// DkgField is one member of a DkgObject.
type DkgField struct {
	Key   string
	Value any
}

// DkgObject is a JSON object whose members are written in the order given (a Go map has none).
type DkgObject []DkgField

// ---- JSON writer (JSON.stringify of a wire value) ------------------------------------------------------------------------------

func dkgWriteJSON(sb *strings.Builder, v any) error {
	switch t := v.(type) {
	case nil:
		sb.WriteString("null")
	case bool:
		sb.WriteString(strconv.FormatBool(t))
	case string:
		return jsString(sb, t)
	case int:
		sb.WriteString(strconv.Itoa(t))
	case int64:
		sb.WriteString(strconv.FormatInt(t, 10))
	case float64:
		dkgWriteNumber(sb, t)
	case interface{ String() string }:
		f, ok := jsNum(v)
		if !ok {
			return fmt.Errorf("dkg: unsupported value %T", v)
		}
		dkgWriteNumber(sb, f)
	case []any:
		sb.WriteByte('[')
		for i, x := range t {
			if i > 0 {
				sb.WriteByte(',')
			}
			if err := dkgWriteJSON(sb, x); err != nil {
				return err
			}
		}
		sb.WriteByte(']')
	case []string:
		a := make([]any, len(t))
		for i, x := range t {
			a[i] = x
		}
		return dkgWriteJSON(sb, a)
	case map[string]any:
		o := make(DkgObject, 0, len(t))
		for _, k := range jsKeys(t) {
			o = append(o, DkgField{k, t[k]})
		}
		return dkgWriteJSON(sb, o)
	case DkgObject:
		sb.WriteByte('{')
		for i, f := range t {
			if i > 0 {
				sb.WriteByte(',')
			}
			if err := jsString(sb, f.Key); err != nil {
				return err
			}
			sb.WriteByte(':')
			if err := dkgWriteJSON(sb, f.Value); err != nil {
				return err
			}
		}
		sb.WriteByte('}')
	default:
		return fmt.Errorf("dkg: unsupported value %T", v)
	}
	return nil
}

func dkgWriteNumber(sb *strings.Builder, f float64) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		sb.WriteString("null")
		return
	}
	if f == 0 {
		sb.WriteByte('0')
		return
	}
	sb.WriteString(jsNumberString(f))
}

// ---- wire envelope --------------------------------------------------------------------------------------------------------------

// EncodeDkgMessage encodes one wire message: {"v":1,"sid":..,"kind":..,"body":..}.
func EncodeDkgMessage(sessionID []byte, kind string, body any) ([]byte, error) {
	return dkgEncodeEnvelope(sessionID, kind, body)
}

func dkgEncodeEnvelope(sessionID []byte, kind any, body any) ([]byte, error) {
	var sb strings.Builder
	sb.WriteString(`{"v":1,"sid":`)
	if err := jsString(&sb, B64u(sessionID)); err != nil {
		return nil, err
	}
	sb.WriteString(`,"kind":`)
	if err := dkgWriteJSON(&sb, kind); err != nil {
		return nil, err
	}
	sb.WriteString(`,"body":`)
	if err := dkgWriteJSON(&sb, body); err != nil {
		return nil, err
	}
	sb.WriteByte('}')
	if sb.Len() > DkgMaxMessageBytes {
		return nil, dkgErr("oversize", fmt.Sprintf("message of %d bytes exceeds the cap", sb.Len()))
	}
	return []byte(sb.String()), nil
}

// DecodeDkgMessage strictly decodes one wire message for sessionID; every deviation is a typed *DkgChannelError.
func DecodeDkgMessage(b []byte, sessionID []byte) (kind string, body any, err error) {
	if len(b) > DkgMaxMessageBytes {
		return "", nil, dkgErr("oversize", fmt.Sprintf("message of %d bytes exceeds the cap", len(b)))
	}
	msg, perr := StrictParseBytes(b)
	if perr != nil {
		return "", nil, dkgErr("malformed", "message is not strict JSON")
	}
	o, err := dkgRecord(msg, []string{"v", "sid", "kind", "body"}, "envelope")
	if err != nil {
		return "", nil, err
	}
	if v, ok := jsNum(o["v"]); !ok || v != DkgWireVersion {
		return "", nil, dkgErr("malformed", "unsupported wire version")
	}
	k, isStr := o["kind"].(string)
	known := false
	for _, x := range DkgMessageKinds {
		known = known || x == k
	}
	if !isStr || !known {
		return "", nil, dkgErr("malformed", "unknown message kind")
	}
	if o["sid"] != B64u(sessionID) {
		return "", nil, dkgErr("wrong-session", "message names another session")
	}
	return k, o["body"], nil
}

func dkgRecord(x any, keys []string, what string) (map[string]any, error) {
	m, ok := x.(map[string]any)
	if !ok {
		return nil, dkgErr("malformed", what+" is not an object")
	}
	if len(m) != len(keys) {
		return nil, dkgErr("malformed", what+" has unexpected or missing members")
	}
	for _, k := range keys {
		if _, has := m[k]; !has {
			return nil, dkgErr("malformed", what+" has unexpected or missing members")
		}
	}
	return m, nil
}

func dkgPosInt(x any, what string) (int64, error) {
	f, ok := jsNum(x)
	if !ok || f != math.Trunc(f) || f <= 0 || f > frostMaxSafeInt {
		return 0, dkgErr("malformed", what+" is not a positive integer")
	}
	return int64(f), nil
}

func dkgB64Field(x any, what string, length int) (string, error) {
	s, ok := x.(string)
	if !ok {
		return "", dkgErr("malformed", what+" is not canonical base64url")
	}
	if _, good := DecodeB64uStrict(s, length); !good {
		return "", dkgErr("malformed", what+" is not canonical base64url")
	}
	return s, nil
}

// ---- message-body decoders --------------------------------------------------------------------------------------------------

// DecodeDkgRound1Package decodes a round-1 package body; t is the threshold the package must commit to.
func DecodeDkgRound1Package(x any, t int) (DkgRound1Package, error) {
	o, err := dkgRecord(x, []string{"identifier", "sessionId", "coefficientCommitments", "proofOfKnowledge"}, "round-1 package")
	if err != nil {
		return DkgRound1Package{}, err
	}
	pok, err := dkgRecord(o["proofOfKnowledge"], []string{"R", "mu"}, "proof of knowledge")
	if err != nil {
		return DkgRound1Package{}, err
	}
	cc, isList := o["coefficientCommitments"].([]any)
	if !isList || len(cc) != t {
		return DkgRound1Package{}, dkgErr("malformed", fmt.Sprintf("round-1 package must commit to exactly t=%d coefficients", t))
	}
	id, err := dkgPosInt(o["identifier"], "identifier")
	if err != nil {
		return DkgRound1Package{}, err
	}
	sid, err := dkgB64Field(o["sessionId"], "sessionId", -1)
	if err != nil {
		return DkgRound1Package{}, err
	}
	out := DkgRound1Package{Identifier: id, SessionID: sid, CoefficientCommitments: make([]string, len(cc))}
	for i, c := range cc {
		if out.CoefficientCommitments[i], err = dkgB64Field(c, "coefficient commitment", 32); err != nil {
			return DkgRound1Package{}, err
		}
	}
	if out.ProofOfKnowledge.R, err = dkgB64Field(pok["R"], "PoP R", 32); err != nil {
		return DkgRound1Package{}, err
	}
	if out.ProofOfKnowledge.Mu, err = dkgB64Field(pok["mu"], "PoP mu", 32); err != nil {
		return DkgRound1Package{}, err
	}
	return out, nil
}

// DecodeDkgShareMessage decodes a private share body (the share as bytes).
func DecodeDkgShareMessage(x any) (DkgShareToSend, error) {
	o, err := dkgRecord(x, []string{"from", "to", "sessionId", "share", "sig"}, "share message")
	if err != nil {
		return DkgShareToSend{}, err
	}
	var out DkgShareToSend
	if out.From, err = dkgPosInt(o["from"], "from"); err != nil {
		return out, err
	}
	if out.To, err = dkgPosInt(o["to"], "to"); err != nil {
		return out, err
	}
	if out.SessionID, err = dkgB64Field(o["sessionId"], "sessionId", -1); err != nil {
		return out, err
	}
	sh, err := dkgB64Field(o["share"], "share", 32)
	if err != nil {
		return out, err
	}
	out.Share, _ = DecodeB64uStrict(sh, 32)
	out.Sig, err = dkgB64Field(o["sig"], "share signature", 64)
	return out, err
}

func dkgComplaintOf(x any) (DkgComplaint, error) {
	o, err := dkgRecord(x, []string{"accused", "accuser", "sessionId", "revealedShare", "shareSig"}, "complaint")
	if err != nil {
		return DkgComplaint{}, err
	}
	var c DkgComplaint
	if c.Accused, err = dkgPosInt(o["accused"], "accused"); err != nil {
		return c, err
	}
	if c.Accuser, err = dkgPosInt(o["accuser"], "accuser"); err != nil {
		return c, err
	}
	if c.SessionID, err = dkgB64Field(o["sessionId"], "sessionId", -1); err != nil {
		return c, err
	}
	if c.RevealedShare, err = dkgB64Field(o["revealedShare"], "revealed share", 32); err != nil {
		return c, err
	}
	c.ShareSig, err = dkgB64Field(o["shareSig"], "share signature", 64)
	return c, err
}

func dkgRebuttalOf(x any) (DkgRebuttal, error) {
	o, err := dkgRecord(x, []string{"accused", "accuser", "sessionId", "presentedShare", "shareSig"}, "rebuttal")
	if err != nil {
		return DkgRebuttal{}, err
	}
	var r DkgRebuttal
	if r.Accused, err = dkgPosInt(o["accused"], "accused"); err != nil {
		return r, err
	}
	if r.Accuser, err = dkgPosInt(o["accuser"], "accuser"); err != nil {
		return r, err
	}
	if r.SessionID, err = dkgB64Field(o["sessionId"], "sessionId", -1); err != nil {
		return r, err
	}
	if r.PresentedShare, err = dkgB64Field(o["presentedShare"], "presented share", 32); err != nil {
		return r, err
	}
	r.ShareSig, err = dkgB64Field(o["shareSig"], "share signature", 64)
	return r, err
}

func dkgListOf(x any, key string) ([]any, error) {
	o, err := dkgRecord(x, []string{key}, key)
	if err != nil {
		return nil, err
	}
	l, ok := o[key].([]any)
	if !ok || len(l) > DkgMaxParticipants {
		return nil, dkgErr("malformed", key+" is not a bounded list")
	}
	return l, nil
}

// DecodeDkgComplaints decodes a complaints body ({"complaints": [...]}, possibly empty).
func DecodeDkgComplaints(x any) ([]DkgComplaint, error) {
	l, err := dkgListOf(x, "complaints")
	if err != nil {
		return nil, err
	}
	out := make([]DkgComplaint, len(l))
	for i, e := range l {
		if out[i], err = dkgComplaintOf(e); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// DecodeDkgRebuttals decodes a rebuttals body ({"rebuttals": [...]}, possibly empty).
func DecodeDkgRebuttals(x any) ([]DkgRebuttal, error) {
	l, err := dkgListOf(x, "rebuttals")
	if err != nil {
		return nil, err
	}
	out := make([]DkgRebuttal, len(l))
	for i, e := range l {
		if out[i], err = dkgRebuttalOf(e); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// DecodeDkgEcho decodes an echo body.
func DecodeDkgEcho(x any) (DkgEcho, error) {
	o, err := dkgRecord(x, []string{"identifier", "sessionId", "transcriptDigest"}, "echo")
	if err != nil {
		return DkgEcho{}, err
	}
	var e DkgEcho
	if e.Identifier, err = dkgPosInt(o["identifier"], "identifier"); err != nil {
		return e, err
	}
	if e.SessionID, err = dkgB64Field(o["sessionId"], "sessionId", -1); err != nil {
		return e, err
	}
	e.TranscriptDigest, err = dkgB64Field(o["transcriptDigest"], "transcript digest", 32)
	return e, err
}

// ---- wire forms of the typed messages (member order is part of the bytes) ---------------------------------------------------

func dkgPackageWire(p DkgRound1Package) DkgObject {
	cc := make([]any, len(p.CoefficientCommitments))
	for i, c := range p.CoefficientCommitments {
		cc[i] = c
	}
	return DkgObject{{"identifier", p.Identifier}, {"sessionId", p.SessionID}, {"coefficientCommitments", cc},
		{"proofOfKnowledge", DkgObject{{"R", p.ProofOfKnowledge.R}, {"mu", p.ProofOfKnowledge.Mu}}}}
}

func dkgEchoWire(e DkgEcho) DkgObject {
	return DkgObject{{"identifier", e.Identifier}, {"sessionId", e.SessionID}, {"transcriptDigest", e.TranscriptDigest}}
}

// ---- shared inbox ------------------------------------------------------------------------------------------------------------

type dkgSeen struct {
	digest string
	body   any
}

// DkgInbox is the receive side shared by channel implementations: it holds at most one message per (kind, authenticated sender),
// records a sticky error per peer and implements Collect. A channel calls Accept with the AUTHENTICATED sender.
type DkgInbox struct {
	mu        sync.Mutex
	seen      map[string]dkgSeen
	errs      map[int64]*DkgChannelError
	gone      map[int64]bool
	waiters   map[chan struct{}]struct{}
	closed    bool
	sessionID []byte
	peers     []int64
}

// NewDkgInbox is an inbox for one session and the given peers.
func NewDkgInbox(sessionID []byte, peers []int64) *DkgInbox {
	return &DkgInbox{seen: map[string]dkgSeen{}, errs: map[int64]*DkgChannelError{}, gone: map[int64]bool{}, waiters: map[chan struct{}]struct{}{},
		sessionID: append([]byte(nil), sessionID...), peers: append([]int64(nil), peers...)}
}

func (in *DkgInbox) wake() {
	for w := range in.waiters {
		select {
		case w <- struct{}{}:
		default:
		}
	}
}

// Fail records a peer failure (the first one wins).
func (in *DkgInbox) Fail(peer int64, e *DkgChannelError) {
	in.mu.Lock()
	defer in.mu.Unlock()
	in.fail(peer, e)
}

func (in *DkgInbox) fail(peer int64, e *DkgChannelError) {
	if _, has := in.errs[peer]; !has {
		in.errs[peer] = dkgErrPeer(e.Code, peer, e.Detail)
	}
	in.wake()
}

// Accept takes one wire message from the authenticated sender. It never refuses: a bad message becomes a sticky peer error.
func (in *DkgInbox) Accept(sender int64, b []byte) {
	in.mu.Lock()
	defer in.mu.Unlock()
	known := false
	for _, p := range in.peers {
		known = known || p == sender
	}
	if !known {
		return // not a participant: nothing to attribute to
	}
	kind, body, err := DecodeDkgMessage(b, in.sessionID)
	if err == nil {
		key := kind + "\x00" + strconv.FormatInt(sender, 10)
		digest := B64u(b)
		if prev, dup := in.seen[key]; dup {
			code := "equivocation"
			if prev.digest == digest {
				code = "duplicate"
			}
			err = dkgErrPeer(code, sender, "second "+kind+" message")
		} else {
			in.seen[key] = dkgSeen{digest, body}
			in.wake()
			return
		}
	}
	var ce *DkgChannelError
	if !errors.As(err, &ce) {
		ce = dkgErrPeer("malformed", sender, "undecodable message")
	}
	in.fail(sender, ce)
}

// PeerGone records that the link to peer ended: it matters only if a message that peer owed is still missing.
func (in *DkgInbox) PeerGone(peer int64) {
	in.mu.Lock()
	defer in.mu.Unlock()
	in.gone[peer] = true
	in.wake()
}

// Close ends the inbox: a Collect still missing messages fails "closed".
func (in *DkgInbox) Close() {
	in.mu.Lock()
	defer in.mu.Unlock()
	in.closed = true
	in.wake()
}

// Collect waits for exactly one kind message from each of from, within timeoutMs.
func (in *DkgInbox) Collect(kind string, from []int64, timeoutMs float64) ([]DkgCollected, error) {
	want := append([]int64(nil), from...)
	sort.Slice(want, func(i, j int) bool { return want[i] < want[j] })
	deadline := time.Now().Add(time.Duration(timeoutMs * float64(time.Millisecond)))
	for {
		in.mu.Lock()
		for _, id := range want {
			if e := in.errs[id]; e != nil {
				in.mu.Unlock()
				return nil, e
			}
		}
		got := map[int64]any{}
		var out []DkgCollected
		for _, id := range want {
			if m, ok := in.seen[kind+"\x00"+strconv.FormatInt(id, 10)]; ok {
				if _, dup := got[id]; !dup {
					out = append(out, DkgCollected{id, m.body})
				}
				got[id] = m.body
			}
		}
		if len(got) == len(want) {
			in.mu.Unlock()
			return out, nil
		}
		if in.closed {
			in.mu.Unlock()
			return nil, dkgErr("closed", "channel closed before all messages arrived")
		}
		for _, id := range want {
			if _, has := got[id]; !has && in.gone[id] {
				in.mu.Unlock()
				return nil, dkgErrPeer("closed", id, "link ended before its "+kind+" message arrived")
			}
		}
		left := time.Until(deadline)
		if left <= 0 {
			var missing []string
			first := int64(0)
			for _, id := range want {
				if _, has := got[id]; !has {
					if len(missing) == 0 {
						first = id
					}
					missing = append(missing, strconv.FormatInt(id, 10))
				}
			}
			in.mu.Unlock()
			return nil, dkgErrPeer("timeout", first, "no "+kind+" message from "+strings.Join(missing, ","))
		}
		w := make(chan struct{}, 1)
		in.waiters[w] = struct{}{}
		in.mu.Unlock()
		timer := time.NewTimer(left)
		select {
		case <-w:
		case <-timer.C:
		}
		timer.Stop()
		in.mu.Lock()
		delete(in.waiters, w)
		in.mu.Unlock()
	}
}

// ---- in-memory reference channel ---------------------------------------------------------------------------------------------

// DkgDelivery is one message in flight on the in-memory network.
type DkgDelivery struct {
	From, To int64
	Kind     string
	Bytes    []byte
}

// MemoryDkgNetwork is the in-process reference network.
type MemoryDkgNetwork struct {
	Channels map[int64]DkgChannel
	inboxes  map[int64]*DkgInbox
}

// Deliver is the adversary hook: it delivers raw bytes to `to` as if sent by `from`.
func (n *MemoryDkgNetwork) Deliver(from, to int64, b []byte) {
	if in := n.inboxes[to]; in != nil {
		in.Accept(from, b)
	}
}

type memoryDkgChannel struct {
	net       *MemoryDkgNetwork
	self      int64
	peers     []int64
	session   []byte
	intercept func(DkgDelivery) []byte // nil result drops the delivery
	hasHook   bool
}

// NewMemoryDkgNetwork builds the in-process network. intercept (optional) sees every delivery and returns the bytes to deliver, or nil to
// drop it, so a test models a network or a corrupted peer without any private API.
func NewMemoryDkgNetwork(ids []int64, sessionID []byte, intercept func(DkgDelivery) []byte) *MemoryDkgNetwork {
	sorted := append([]int64(nil), ids...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	net := &MemoryDkgNetwork{Channels: map[int64]DkgChannel{}, inboxes: map[int64]*DkgInbox{}}
	without := func(self int64) []int64 {
		out := []int64{}
		for _, p := range sorted {
			if p != self {
				out = append(out, p)
			}
		}
		return out
	}
	for _, id := range sorted {
		net.inboxes[id] = NewDkgInbox(sessionID, without(id))
	}
	for _, self := range sorted {
		net.Channels[self] = &memoryDkgChannel{net: net, self: self, peers: without(self), session: sessionID, intercept: intercept, hasHook: intercept != nil}
	}
	return net
}

func (c *memoryDkgChannel) Self() int64    { return c.self }
func (c *memoryDkgChannel) Peers() []int64 { return append([]int64(nil), c.peers...) }

func (c *memoryDkgChannel) route(to int64, kind string, body any) error {
	b, err := dkgEncodeEnvelope(c.session, kind, body)
	if err != nil {
		return err
	}
	out := b
	if c.hasHook {
		out = c.intercept(DkgDelivery{From: c.self, To: to, Kind: kind, Bytes: b})
	}
	if out != nil {
		c.net.Deliver(c.self, to, out)
	}
	return nil
}

func (c *memoryDkgChannel) Broadcast(kind string, body any) error {
	for _, p := range c.peers {
		if err := c.route(p, kind, body); err != nil {
			return err
		}
	}
	return nil
}

func (c *memoryDkgChannel) Send(to int64, kind string, body any) error {
	for _, p := range c.peers {
		if p == to {
			return c.route(to, kind, body)
		}
	}
	return dkgErrPeer("identity", to, "not a connected peer")
}

func (c *memoryDkgChannel) Collect(kind string, from []int64, timeoutMs float64) ([]DkgCollected, error) {
	return c.net.inboxes[c.self].Collect(kind, from, timeoutMs)
}

func (c *memoryDkgChannel) Close() error {
	c.net.inboxes[c.self].Close()
	return nil
}

// ---- framing (4-byte big-endian length, then the message) ---------------------------------------------------------------------

// DkgFrame prefixes payload with its 4-byte big-endian length.
func DkgFrame(payload []byte) []byte {
	f := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(f, uint32(len(payload)))
	copy(f[4:], payload)
	return f
}

// DkgFrameReader splits a byte stream into frames; a length above DkgMaxMessageBytes is refused (as "oversize") before any
// allocation, and the reader stays failed.
type DkgFrameReader struct {
	buf    []byte
	failed bool
}

// Push appends a chunk and returns the complete frames now available, or the oversize refusal.
func (r *DkgFrameReader) Push(chunk []byte) ([][]byte, error) {
	if r.failed {
		return nil, dkgErr("oversize", "frame length exceeds the cap")
	}
	r.buf = append(r.buf, chunk...)
	var out [][]byte
	for len(r.buf) >= 4 {
		n := binary.BigEndian.Uint32(r.buf)
		if n > DkgMaxMessageBytes {
			r.failed = true
			return out, dkgErr("oversize", fmt.Sprintf("frame of %d bytes exceeds the cap", n))
		}
		if len(r.buf) < 4+int(n) {
			break
		}
		out = append(out, append([]byte(nil), r.buf[4:4+n]...))
		r.buf = r.buf[4+n:]
	}
	return out, nil
}

// Buffered is the number of bytes held that do not yet form a frame.
func (r *DkgFrameReader) Buffered() int { return len(r.buf) }

// ---- the driver ----------------------------------------------------------------------------------------------------------------

// RunDkgOpts configure RunDkgOverChannel. TimeoutMs (nil: 30000) is the per-phase wait for the other parties; a missing message after
// it aborts the run.
type RunDkgOpts struct {
	T            int
	Participants []int64
	SessionID    []byte
	TimeoutMs    *float64
	Coefficients [][]byte
}

// RunDkgResult is one participant's outcome.
type RunDkgResult struct {
	KeyPackage DkgKeyPackage
	Qualified  []int64
	Complaints []DkgComplaint
}

func dkgBind(peer int64, err error) error {
	var ce *DkgChannelError
	if errors.As(err, &ce) {
		return dkgErrPeer(ce.Code, peer, ce.Detail)
	}
	return err
}

// RunDkgOverChannel runs ONE participant's whole DKG over ch: round 1, proof-of-possession checks, round 2 with signed shares, share
// verification, complaints, rebuttals, the qualified set, the echo round and finalize. It returns this participant's key package, or
// a *DkgChannelError on any channel or protocol violation (nothing partial is returned).
func RunDkgOverChannel(ch DkgChannel, o RunDkgOpts) (*RunDkgResult, error) {
	self := ch.Self()
	ids := append([]int64(nil), o.Participants...)
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	bad := len(ids) > DkgMaxParticipants
	for k, i := range ids {
		if !frostIsID(i) || (k > 0 && ids[k-1] == i) {
			bad = true
		}
	}
	if bad {
		return nil, dkgErr("protocol", "participants must be distinct positive integers within the cap")
	}
	member := false
	for _, i := range ids {
		member = member || i == self
	}
	if !member {
		return nil, dkgErr("protocol", "this participant is not in the participant list")
	}
	if o.T < 1 || o.T > len(ids) {
		return nil, dkgErr("protocol", "need 1 <= t <= n")
	}
	others := []int64{}
	for _, i := range ids {
		if i != self {
			others = append(others, i)
		}
	}
	peers := ch.Peers()
	if len(peers) != len(others) {
		return nil, dkgErr("protocol", "the channel peers are not exactly the other participants")
	}
	for k, p := range others {
		if peers[k] != p {
			return nil, dkgErr("protocol", "the channel peers are not exactly the other participants")
		}
	}
	sid := o.SessionID
	sidB64 := B64u(sid)
	tmo := 30000.0
	if o.TimeoutMs != nil {
		tmo = *o.TimeoutMs
	}
	n := len(ids)

	// Round 1: broadcast, collect, bind each package to its authenticated sender.
	r1, err := DkgRound1(self, o.T, n, sid, DkgRound1Opts{Coefficients: o.Coefficients})
	if err != nil {
		return nil, err
	}
	if err := ch.Broadcast("round1", dkgPackageWire(r1.Package)); err != nil {
		return nil, err
	}
	pkgs := []DkgRound1Package{r1.Package}
	got, err := ch.Collect("round1", others, tmo)
	if err != nil {
		return nil, err
	}
	for _, c := range got {
		p, err := DecodeDkgRound1Package(c.Body, o.T)
		if err != nil {
			return nil, dkgBind(c.From, err)
		}
		if p.Identifier != c.From {
			return nil, dkgErrPeer("identity", c.From, fmt.Sprintf("package claims identifier %d", p.Identifier))
		}
		if p.SessionID != sidB64 {
			return nil, dkgErrPeer("wrong-session", c.From, "package names another session")
		}
		pkgs = append(pkgs, p)
	}
	byID := map[int64]DkgRound1Package{}
	for _, p := range pkgs {
		byID[p.Identifier] = p
	}
	// A package whose proof of possession fails is dropped by the qualified set; it gets and gives no shares.
	var pok []DkgRound1Package
	okSet := map[int64]bool{}
	for _, p := range pkgs {
		if DkgVerifyRound1(p.Identifier, p, sid) {
			pok = append(pok, p)
			okSet[p.Identifier] = true
		}
	}
	okPeers := []int64{}
	for _, p := range others {
		if okSet[p] {
			okPeers = append(okPeers, p)
		}
	}

	// Round 2: signed shares out (private), signed shares in.
	outs, err := DkgRound2(r1.State, pok)
	if err != nil {
		return nil, err
	}
	for _, s := range outs {
		body := DkgObject{{"from", s.From}, {"to", s.To}, {"sessionId", s.SessionID}, {"share", B64u(s.Share)}, {"sig", s.Sig}}
		if err := ch.Send(s.To, "share", body); err != nil {
			return nil, err
		}
	}
	var inbox []DkgReceivedShare
	var mine []DkgComplaint
	got, err = ch.Collect("share", okPeers, tmo)
	if err != nil {
		return nil, err
	}
	for _, c := range got {
		m, err := DecodeDkgShareMessage(c.Body)
		if err != nil {
			return nil, dkgBind(c.From, err)
		}
		if m.From != c.From {
			return nil, dkgErrPeer("identity", c.From, fmt.Sprintf("share claims sender %d", m.From))
		}
		if m.To != self {
			return nil, dkgErrPeer("identity", c.From, fmt.Sprintf("share is addressed to %d", m.To))
		}
		if m.SessionID != sidB64 {
			return nil, dkgErrPeer("wrong-session", c.From, "share names another session")
		}
		received := DkgReceivedShare{From: c.From, SessionID: m.SessionID, Share: m.Share, Sig: m.Sig}
		sender := byID[c.From]
		if DkgVerifyShare(DkgSignedShare{From: received.From, Share: received.Share, Sig: received.Sig}, sender, self, sid) {
			inbox = append(inbox, received)
			continue
		}
		cm, err := DkgFileComplaint(DkgFileComplaintParams{Accused: c.From, Accuser: self, ReceivedShare: m.Share, ShareSig: m.Sig, SenderCommitments: sender.CoefficientCommitments, SessionID: sid})
		if err != nil {
			return nil, err
		}
		// Only a share the sender really signed is attributable blame; anything else aborts the run instead of accusing.
		if !DkgVerifyComplaint(cm, pkgs).Justified {
			return nil, dkgErrPeer("protocol", c.From, "share failed verification and is not admissible blame")
		}
		mine = append(mine, cm)
	}

	// Complaints (broadcast, possibly empty), then rebuttals by the accused.
	cl := make([]any, len(mine))
	for i, c := range mine {
		cl[i] = DkgObject{{"accused", c.Accused}, {"accuser", c.Accuser}, {"sessionId", c.SessionID}, {"revealedShare", c.RevealedShare}, {"shareSig", c.ShareSig}}
	}
	if err := ch.Broadcast("complaints", DkgObject{{"complaints", cl}}); err != nil {
		return nil, err
	}
	complaints := append([]DkgComplaint{}, mine...)
	got, err = ch.Collect("complaints", others, tmo)
	if err != nil {
		return nil, err
	}
	for _, c := range got {
		list, err := DecodeDkgComplaints(c.Body)
		if err != nil {
			return nil, dkgBind(c.From, err)
		}
		pairs := map[int64]bool{}
		for _, cm := range list {
			if cm.Accuser != c.From {
				return nil, dkgErrPeer("identity", c.From, fmt.Sprintf("complaint filed as %d", cm.Accuser))
			}
			if cm.SessionID != sidB64 {
				return nil, dkgErrPeer("wrong-session", c.From, "complaint names another session")
			}
			in := false
			for _, i := range ids {
				in = in || i == cm.Accused
			}
			if cm.Accused == c.From || !in {
				return nil, dkgErrPeer("protocol", c.From, "complaint names an invalid accused")
			}
			if pairs[cm.Accused] {
				return nil, dkgErrPeer("duplicate", c.From, "two complaints against one accused")
			}
			pairs[cm.Accused] = true
			complaints = append(complaints, cm)
		}
	}
	var rebuttals []DkgRebuttal
	for _, c := range complaints {
		if c.Accused == self {
			r, err := DkgRebut(self, c, r1.State)
			if err != nil {
				return nil, err
			}
			rebuttals = append(rebuttals, r)
		}
	}
	rl := make([]any, len(rebuttals))
	for i, r := range rebuttals {
		rl[i] = DkgObject{{"accused", r.Accused}, {"accuser", r.Accuser}, {"sessionId", r.SessionID}, {"presentedShare", r.PresentedShare}, {"shareSig", r.ShareSig}}
	}
	if err := ch.Broadcast("rebuttals", DkgObject{{"rebuttals", rl}}); err != nil {
		return nil, err
	}
	allRebuttals := append([]DkgRebuttal{}, rebuttals...)
	got, err = ch.Collect("rebuttals", others, tmo)
	if err != nil {
		return nil, err
	}
	for _, c := range got {
		list, err := DecodeDkgRebuttals(c.Body)
		if err != nil {
			return nil, dkgBind(c.From, err)
		}
		for _, r := range list {
			if r.Accused != c.From {
				return nil, dkgErrPeer("identity", c.From, fmt.Sprintf("rebuttal made as %d", r.Accused))
			}
			if r.SessionID != sidB64 {
				return nil, dkgErrPeer("wrong-session", c.From, "rebuttal names another session")
			}
			allRebuttals = append(allRebuttals, r)
		}
	}

	qualified := DkgQualifiedSet(ids, complaints, pkgs, allRebuttals)
	inQ := false
	for _, q := range qualified {
		inQ = inQ || q == self
	}
	if !inQ {
		return nil, dkgErrPeer("disqualified", self, "this participant was disqualified by the blame round")
	}
	if len(qualified) < o.T {
		return nil, dkgErr("protocol", "fewer than t participants remain qualified")
	}

	// Echo round: every qualified party must have seen the identical transcript.
	echo, err := DkgMakeEcho(self, pkgs, complaints, qualified, sid)
	if err != nil {
		return nil, err
	}
	if err := ch.Broadcast("echo", dkgEchoWire(echo)); err != nil {
		return nil, err
	}
	echoes := []DkgEcho{echo}
	var qOthers []int64
	for _, q := range qualified {
		if q != self {
			qOthers = append(qOthers, q)
		}
	}
	got, err = ch.Collect("echo", qOthers, tmo)
	if err != nil {
		return nil, err
	}
	for _, c := range got {
		e, err := DecodeDkgEcho(c.Body)
		if err != nil {
			return nil, dkgBind(c.From, err)
		}
		if e.Identifier != c.From {
			return nil, dkgErrPeer("identity", c.From, fmt.Sprintf("echo claims identifier %d", e.Identifier))
		}
		echoes = append(echoes, e)
	}
	if ag := DkgCheckEchoes(qualified, echoes, sid); !ag.Agreed {
		return nil, dkgErr("equivocation", ag.Reason)
	}
	kp, err := DkgFinalize(self, r1.State, inbox, pkgs, qualified, &DkgAgreement{Echoes: echoes, Complaints: complaints})
	if err != nil {
		return nil, err
	}
	return &RunDkgResult{KeyPackage: *kp, Qualified: qualified, Complaints: complaints}, nil
}
