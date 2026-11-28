package pca

// Authenticated, confidential, fail-closed point-to-point mesh over TLS 1.3 (research prototype), the native twin of the
// reference mesh.
//
//   - MUTUAL TLS with PINNED self-signed certificates. A peer is identified by the SHA-256 fingerprint of its certificate, never
//     by anything it claims; the id in the hello frame must agree with the pin. A node dials the lower-numbered ids and accepts
//     the higher-numbered ones.
//   - Strict framing and per-link sequence numbers. A malformed frame, a replayed or skipped sequence number, a frame for the
//     wrong round or session, or an oversize length prefix aborts the run with an attributable MpcNetAbort naming the sender.
//   - Every receive has a deadline; a silent peer is blamed when it elapses.
//   - ABORT PROPAGATION: the first failure poisons the mesh, wakes every pending receive, best-effort tells every other peer and
//     closes the sockets. Once failed, nothing further is sent as protocol data.

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"math"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// MpcNodeAddr is one node of the session; CertPEM is its PUBLIC certificate (the pinned trust anchor and identity).
type MpcNodeAddr struct {
	ID      int
	Host    string
	Port    int
	CertPEM string
}

// MpcMeshConfig configures a mesh node. Zero timeouts mean the defaults (recv 20 s, connect 30 s).
type MpcMeshConfig struct {
	SelfID    int
	Nodes     []MpcNodeAddr
	LinkTo    []int // nil = every other node
	KeyPEM    string
	CertPEM   string
	SessionID string
	// Listener, when set, is used instead of listening on ListenHost:self.Port (so a launcher can reserve free ports).
	Listener       net.Listener
	ListenHost     string
	ConnectTimeout time.Duration
	RecvTimeout    time.Duration
	// Tamper is a TEST HOOK: a (malicious) sender rewriting its own outgoing frames. Refused unless UnsafeTestHooks is true.
	Tamper          func(to int, raw []byte) [][]byte
	UnsafeTestHooks bool
	// BeforeHello is a TEST HOOK: runs on the attaching goroutine once the link is open and before our hello is sent, with the peer id. Refused unless UnsafeTestHooks is true.
	BeforeHello func(peer int)
	// Clock is the time source for the connect and receive deadlines (nil = real time); a test injects MpcManualClock.
	Clock          MpcMeshClock
	MaxInboxFrames int // default 1024
	MaxInboxBytes  int // default 32 MiB
}

// MpcMaxMeshEvents bounds the stored non-fatal observations; further ones are only counted.
const MpcMaxMeshEvents = 64

type mpcInboxItem struct {
	f     map[string]any
	size  int
	abort *MpcNetAbort
}

type mpcLink struct {
	id        int
	conn      net.Conn
	splitter  MpcFrameSplitter
	inbox     []mpcInboxItem
	inboxByte int
	paused    bool
	recvSeq   int
	closed    bool
	helloSeen bool
	bytesIn   int
	framesIn  int

	wmu       sync.Mutex // guards sendSeq, bytesOut, framesOut and writes
	sendSeq   int
	bytesOut  int
	framesOut int
}

// MpcLinkStats are the application-level byte counters of one link.
type MpcLinkStats struct {
	Peer                    int
	AppBytesOut, AppBytesIn int
	FramesOut, FramesIn     int
}

// MpcMesh is one node's authenticated mesh.
type MpcMesh struct {
	cfg      MpcMeshConfig
	selfID   int
	cert     tls.Certificate
	sigKey   *ecdsa.PrivateKey
	pinned   map[string]int // fingerprint -> node id
	pubKeys  map[int]*ecdsa.PublicKey
	clk      MpcMeshClock
	recvTO   time.Duration
	connTO   time.Duration
	maxFrm   int
	maxBytes int

	mu         sync.Mutex
	links      map[int]*mpcLink
	wake       chan struct{}
	failure    *MpcNetAbort
	finished   bool
	deferAbort bool
	events     []string
	evDropped  int
	listener   net.Listener
}

func NewMpcMesh(cfg MpcMeshConfig) (*MpcMesh, error) {
	if (cfg.Tamper != nil || cfg.BeforeHello != nil) && !cfg.UnsafeTestHooks {
		return nil, errors.New("mesh: the test hooks require UnsafeTestHooks (test-only)")
	}
	m := &MpcMesh{cfg: cfg, selfID: cfg.SelfID, pinned: map[string]int{}, pubKeys: map[int]*ecdsa.PublicKey{}, links: map[int]*mpcLink{}, wake: make(chan struct{})}
	m.recvTO, m.connTO = cfg.RecvTimeout, cfg.ConnectTimeout
	if m.clk = cfg.Clock; m.clk == nil {
		m.clk = MpcWallClock{}
	}
	if m.recvTO <= 0 {
		m.recvTO = 20 * time.Second
	}
	if m.connTO <= 0 {
		m.connTO = 30 * time.Second
	}
	m.maxFrm, m.maxBytes = cfg.MaxInboxFrames, cfg.MaxInboxBytes
	if m.maxFrm <= 0 {
		m.maxFrm = 1024
	}
	if m.maxBytes <= 0 {
		m.maxBytes = 32 * 1024 * 1024
	}
	cert, err := tls.X509KeyPair([]byte(cfg.CertPEM), []byte(cfg.KeyPEM))
	if err != nil {
		return nil, fmt.Errorf("mesh: identity: %w", err)
	}
	k, ok := cert.PrivateKey.(*ecdsa.PrivateKey)
	if !ok || k.Curve.Params().Name != "P-256" {
		return nil, errors.New("mesh: the identity key must be ECDSA P-256")
	}
	m.cert, m.sigKey = cert, k
	selfFound := false
	for _, n := range cfg.Nodes {
		if n.ID == cfg.SelfID {
			selfFound = true
			continue
		}
		fp, err := MpcFingerprintOf(n.CertPEM)
		if err != nil {
			return nil, fmt.Errorf("mesh: node %d certificate: %w", n.ID, err)
		}
		if _, dup := m.pinned[fp]; dup {
			return nil, fmt.Errorf("mesh: node %d reuses another node's certificate", n.ID)
		}
		m.pinned[fp] = n.ID
		der, _ := mpcCertDER(n.CertPEM)
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("mesh: node %d certificate: %w", n.ID, err)
		}
		if pk, ok := c.PublicKey.(*ecdsa.PublicKey); ok {
			m.pubKeys[n.ID] = pk
		}
	}
	if !selfFound {
		return nil, errors.New("mesh: self not in nodes")
	}
	want := cfg.LinkTo
	if want == nil {
		for _, n := range cfg.Nodes {
			if n.ID != cfg.SelfID {
				want = append(want, n.ID)
			}
		}
	}
	for _, id := range want {
		if m.node(id) == nil || id == cfg.SelfID {
			return nil, fmt.Errorf("mesh: unknown link target %d", id)
		}
		m.links[id] = &mpcLink{id: id}
	}
	return m, nil
}

func (m *MpcMesh) node(id int) *MpcNodeAddr {
	for i := range m.cfg.Nodes {
		if m.cfg.Nodes[i].ID == id {
			return &m.cfg.Nodes[i]
		}
	}
	return nil
}

// SessionID is the session every frame on this mesh carries.
func (m *MpcMesh) SessionID() string { return m.cfg.SessionID }

// Peers are the linked node ids, ascending.
func (m *MpcMesh) Peers() []int {
	out := make([]int, 0, len(m.links))
	for id := range m.links {
		out = append(out, id)
	}
	sort.Ints(out)
	return out
}

// Failed is the first failure, or nil.
func (m *MpcMesh) Failed() *MpcNetAbort {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.failure
}

// Events are the stored non-fatal observations (a TLS client rejected at the door, a duplicate connection, ...).
func (m *MpcMesh) Events() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.events...)
}

func (m *MpcMesh) noteLocked(msg string) {
	if len(m.events) < MpcMaxMeshEvents {
		m.events = append(m.events, msg)
	} else {
		m.evDropped++
	}
}

func (m *MpcMesh) wakeLocked() {
	close(m.wake)
	m.wake = make(chan struct{})
}

func (m *MpcMesh) abort(kind string, blamed int, detail string) *MpcNetAbort {
	b := blamed
	return NewMpcNetAbort(kind, &b, m.selfID, detail, nil, nil, nil, nil, nil)
}

// ------------------------------------------------------------------ connect

func (m *MpcMesh) pinCheck(want func(fp string) bool, mismatch *bool) func([][]byte, [][]*x509.Certificate) error {
	return func(raw [][]byte, _ [][]*x509.Certificate) error {
		if len(raw) == 0 {
			*mismatch = true
			return errors.New("no peer certificate")
		}
		c, err := x509.ParseCertificate(raw[0])
		now := time.Now()
		if err != nil || now.Before(c.NotBefore) || now.After(c.NotAfter) || !want(mpcFingerprintDER(raw[0])) {
			*mismatch = true
			return errors.New("peer certificate is not a pinned identity")
		}
		return nil
	}
}

// Connect listens, dials every lower-numbered link target and waits until every link has completed the authenticated hello.
func (m *MpcMesh) Connect() error {
	ln := m.cfg.Listener
	if ln == nil {
		host := m.cfg.ListenHost
		if host == "" {
			host = "0.0.0.0"
		}
		var err error
		ln, err = net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(m.node(m.selfID).Port)))
		if err != nil {
			return err
		}
	}
	m.listener = ln
	go m.acceptLoop(ln)
	deadline := m.clk.Now().Add(m.connTO)
	for _, id := range m.Peers() {
		if id < m.selfID {
			go m.dial(id, deadline)
		}
	}
	for {
		m.mu.Lock()
		if m.failure != nil {
			f := m.failure
			m.mu.Unlock()
			return f
		}
		var missing []string
		first := -1
		for _, id := range m.Peers() {
			if !m.links[id].helloSeen {
				if first < 0 {
					first = id
				}
				missing = append(missing, strconv.Itoa(id))
			}
		}
		if len(missing) == 0 {
			m.mu.Unlock()
			return nil
		}
		if m.clk.Now().After(deadline) {
			e := m.abort("timeout", first, "connect: no authenticated link from "+strings.Join(missing, ","))
			m.failLocked(e, -1)
			m.mu.Unlock()
			return e
		}
		m.mu.Unlock()
		time.Sleep(20 * time.Millisecond)
	}
}

func (m *MpcMesh) acceptLoop(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go m.onIncoming(c)
	}
}

func (m *MpcMesh) onIncoming(c net.Conn) {
	var mismatch bool
	cfg := &tls.Config{
		Certificates:          []tls.Certificate{m.cert},
		MinVersion:            tls.VersionTLS13,
		ClientAuth:            tls.RequireAnyClientCert,
		VerifyPeerCertificate: m.pinCheck(func(fp string) bool { _, ok := m.pinned[fp]; return ok }, &mismatch),
	}
	tc := tls.Server(c, cfg)
	_ = tc.SetDeadline(time.Now().Add(m.connTO))
	if err := tc.Handshake(); err != nil {
		m.mu.Lock()
		m.noteLocked("tlsClientError: " + mpcSanitize(err.Error(), 120))
		m.mu.Unlock()
		_ = c.Close()
		return
	}
	_ = tc.SetDeadline(time.Time{})
	st := tc.ConnectionState()
	id := -1
	fp := "none"
	if len(st.PeerCertificates) > 0 {
		fp = mpcFingerprintDER(st.PeerCertificates[0].Raw)
		if v, ok := m.pinned[fp]; ok {
			id = v
		}
	}
	m.mu.Lock()
	l := m.links[id]
	switch {
	case id < 0 || l == nil || id < m.selfID:
		m.noteLocked("rejected incoming connection (fp=" + fp + ")")
		m.mu.Unlock()
		_ = tc.Close()
		return
	case l.conn != nil:
		m.noteLocked(fmt.Sprintf("duplicate connection from node %d", id))
		m.mu.Unlock()
		_ = tc.Close()
		return
	}
	m.mu.Unlock()
	m.attach(l, tc)
}

func (m *MpcMesh) dial(id int, deadline time.Time) {
	node := m.node(id)
	for m.clk.Now().Before(deadline) {
		if m.Failed() != nil {
			return
		}
		if m.dialOnce(id, node) {
			return
		}
		time.Sleep(150 * time.Millisecond)
	}
}

// dialOnce reports true when no further retry is needed (attached, or failed closed on an identity mismatch).
func (m *MpcMesh) dialOnce(id int, node *MpcNodeAddr) bool {
	want, err := MpcFingerprintOf(node.CertPEM)
	if err != nil {
		return false
	}
	c, err := net.DialTimeout("tcp", net.JoinHostPort(node.Host, strconv.Itoa(node.Port)), 5*time.Second)
	if err != nil {
		return false
	}
	var mismatch bool
	tc := tls.Client(c, &tls.Config{
		Certificates: []tls.Certificate{m.cert},
		MinVersion:   tls.VersionTLS13,
		// Pinned by certificate fingerprint (VerifyPeerCertificate), not by hostname or a CA chain.
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: m.pinCheck(func(fp string) bool { return fp == want }, &mismatch),
	})
	_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
	if err := tc.Handshake(); err != nil {
		_ = c.Close()
		if mismatch {
			m.Fail(m.abort("identity", id, fmt.Sprintf("dial: peer certificate is not the pinned identity of node %d", id)))
			return true
		}
		return false
	}
	_ = tc.SetDeadline(time.Time{})
	st := tc.ConnectionState()
	if len(st.PeerCertificates) == 0 || mpcFingerprintDER(st.PeerCertificates[0].Raw) != want {
		_ = c.Close()
		m.Fail(m.abort("identity", id, fmt.Sprintf("dial: peer certificate is not the pinned identity of node %d", id)))
		return true
	}
	m.attach(m.links[id], tc)
	return true
}

func (m *MpcMesh) attach(l *mpcLink, c net.Conn) {
	// The write lock is held from publishing the link until our hello is out: a protocol goroutine whose Connect already returned
	// may Send on this link at once, and its frame must not take seq 0 ahead of the hello ("data before hello" at the peer).
	l.wmu.Lock()
	defer l.wmu.Unlock()
	m.mu.Lock()
	if l.conn != nil {
		m.mu.Unlock()
		_ = c.Close()
		return
	}
	l.conn = c
	m.mu.Unlock()
	go m.readLoop(l, c)
	if m.cfg.BeforeHello != nil {
		m.cfg.BeforeHello(l.id)
	}
	// hello: the first frame on every link (seq 0); carries our id so the peer can cross-check the pin.
	m.sendFrameLocked(l, "hello", "hello", map[string]any{"id": m.selfID})
}

// ------------------------------------------------------------------ receive path

func (m *MpcMesh) readLoop(l *mpcLink, c net.Conn) {
	buf := make([]byte, 32*1024)
	for {
		for {
			m.mu.Lock()
			p := l.paused && m.failure == nil && !m.finished && !l.closed
			ch := m.wake
			m.mu.Unlock()
			if !p {
				break
			}
			select {
			case <-ch:
			case <-time.After(100 * time.Millisecond):
			}
		}
		n, err := c.Read(buf)
		if n > 0 {
			m.onData(l, buf[:n])
		}
		if err != nil {
			m.onClosed(l, "socket closed: "+err.Error())
			return
		}
	}
}

func (m *MpcMesh) onData(l *mpcLink, chunk []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failure != nil {
		return
	}
	l.bytesIn += len(chunk)
	bodies, err := l.splitter.Push(chunk)
	if err != nil {
		m.failLocked(m.abort("oversize", l.id, "length prefix above MAX_FRAME_BYTES"), -1)
		return
	}
	for _, b := range bodies {
		f := MpcParseFrame(b)
		if f == nil {
			if pv, ok := MpcVersionMismatch(b); ok {
				m.failLocked(m.abort("version", l.id, fmt.Sprintf("peer %d speaks wire version %d, this node speaks %d; upgrade both peers", l.id, pv, MpcWireVersion)), -1)
				return
			}
			m.failLocked(m.abort("malformed", l.id, "undecodable or ill-shaped frame"), -1)
			return
		}
		if sid, _ := f["sid"].(string); sid != m.cfg.SessionID {
			m.failLocked(m.abort("wrong-session", l.id, "frame from another session"), -1)
			return
		}
		if f["ty"] == "abort" {
			claim := m.parseAbortClaim(l, f["d"])
			if m.deferAbort {
				// Order-preserving: the claim takes effect when it is READ, after every frame the peer sent before it.
				l.inbox = append(l.inbox, mpcInboxItem{f: f, size: len(b), abort: claim})
				continue
			}
			m.failLocked(claim, l.id)
			return
		}
		seqF, _ := jsNum(f["seq"])
		seq := int(seqF)
		if seq != l.recvSeq {
			kind := "out-of-order"
			if seq < l.recvSeq {
				kind = "duplicate"
			}
			m.failLocked(m.abort(kind, l.id, fmt.Sprintf("expected seq %d, got %d (round %v)", l.recvSeq, seq, f["rd"])), -1)
			return
		}
		l.recvSeq++
		l.framesIn++
		if f["ty"] == "hello" {
			d, _ := f["d"].(map[string]any)
			idF, ok := jsNum(d["id"])
			if l.helloSeen || !ok || idF != float64(l.id) {
				m.failLocked(m.abort("identity", l.id, fmt.Sprintf("hello claims id %v on the link pinned to %d", d["id"], l.id)), -1)
				return
			}
			l.helloSeen = true
			continue
		}
		if !l.helloSeen {
			m.failLocked(m.abort("malformed", l.id, "data before hello"), -1)
			return
		}
		l.inbox = append(l.inbox, mpcInboxItem{f: f, size: len(b)})
		l.inboxByte += len(b)
		if len(l.inbox) > m.maxFrm || l.inboxByte > m.maxBytes {
			m.failLocked(m.abort("flood", l.id, fmt.Sprintf("peer %d queued more than the inbox cap allows", l.id)), -1)
			return
		}
		if !l.paused && (len(l.inbox) > m.maxFrm/2 || l.inboxByte > m.maxBytes/2) {
			l.paused = true
		}
	}
	m.wakeLocked()
}

// parseAbortClaim: an abort frame is only a CLAIM by its sender. We blame that authenticated sender, never the party it names,
// and a relayed abort (an honest peer passing on what ITS peer said) names no one.
func (m *MpcMesh) parseAbortClaim(l *mpcLink, dv any) *MpcNetAbort {
	d, _ := dv.(map[string]any)
	relayed := d["relayed"] == true
	var ck *string
	if s, ok := d["kind"].(string); ok && mpcIsAbortKind(s) {
		ck = &s
	}
	maxID := 0
	for _, n := range m.cfg.Nodes {
		maxID = max(maxID, n.ID)
	}
	var cb *int
	if f, ok := jsNum(d["blamed"]); ok && f == math.Trunc(f) && !mpcNegZero(f) && f >= 0 && f <= float64(maxID) {
		v := int(f)
		cb = &v
	}
	detail := ""
	if s, ok := d["detail"].(string); ok {
		detail = mpcSanitize(s, 120)
	}
	kindS, blameS := "unspecified", "no one"
	if ck != nil {
		kindS = *ck
	}
	if cb != nil {
		blameS = strconv.Itoa(*cb)
	}
	verb := "reported"
	var blamed *int
	var reason *string
	if relayed {
		verb = "relayed"
		r := "relayed abort: a second-hand claim passed on by an honest peer; it names no one and is never evidence"
		reason = &r
	} else {
		id := l.id
		blamed = &id
	}
	return NewMpcNetAbort("peer-abort", blamed, m.selfID, fmt.Sprintf("peer %d %s an abort (%s, accuses %s, unverified) %s", l.id, verb, kindS, blameS, detail), ck, cb, reason, nil, nil)
}

func mpcIsAbortKind(s string) bool {
	for _, k := range MpcAbortKinds {
		if k == s {
			return true
		}
	}
	return false
}

func (m *MpcMesh) onClosed(l *mpcLink, why string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if l.closed {
		return
	}
	l.closed = true
	if !m.finished && m.failure == nil && !l.helloSeen {
		m.noteLocked(fmt.Sprintf("link %d closed before hello: %s", l.id, mpcSanitize(why, 120)))
	}
	m.wakeLocked()
}

// ------------------------------------------------------------------ send path

func (m *MpcMesh) writeLink(l *mpcLink, raw []byte, wd time.Duration) {
	m.mu.Lock()
	c := l.conn
	m.mu.Unlock()
	if c == nil {
		return
	}
	_ = c.SetWriteDeadline(time.Now().Add(wd))
	if _, err := c.Write(raw); err == nil {
		l.bytesOut += len(raw)
	}
}

func (m *MpcMesh) sendFrame(l *mpcLink, ty, rd string, d any) {
	l.wmu.Lock()
	defer l.wmu.Unlock()
	m.sendFrameLocked(l, ty, rd, d)
}

// sendFrameLocked requires l.wmu.
func (m *MpcMesh) sendFrameLocked(l *mpcLink, ty, rd string, d any) {
	raw, err := MpcEncodeFrame(MpcWireVersion, ty, m.cfg.SessionID, l.sendSeq, rd, d)
	l.sendSeq++
	if err != nil {
		m.Fail(NewMpcNetAbort("local", nil, m.selfID, "cannot encode frame: "+err.Error(), nil, nil, nil, nil, nil))
		return
	}
	outs := [][]byte{raw}
	if m.cfg.Tamper != nil && ty != "hello" {
		outs = m.cfg.Tamper(l.id, raw)
	}
	for _, b := range outs {
		m.writeLink(l, b, 30*time.Second)
	}
	l.framesOut++
}

// Send sends a protocol message to one peer. It returns the mesh failure if already aborted (fail closed).
func (m *MpcMesh) Send(to int, round string, payload any) error {
	if f := m.Failed(); f != nil {
		return f
	}
	l := m.links[to]
	if l == nil {
		return fmt.Errorf("mesh: no link to %d", to)
	}
	m.sendFrame(l, "msg", round, payload)
	if f := m.Failed(); f != nil {
		return f
	}
	return nil
}

// Broadcast sends to every peer in to (nil = all peers).
func (m *MpcMesh) Broadcast(round string, payload any, to []int) error {
	if to == nil {
		to = m.Peers()
	}
	for _, p := range to {
		if err := m.Send(p, round, payload); err != nil {
			return err
		}
	}
	return nil
}

// Sign is an ECDSA-P256/SHA-256 (ASN.1 DER) signature over data with this node's TLS identity key, verifiable against the pinned certificate.
func (m *MpcMesh) Sign(data []byte) ([]byte, error) {
	h := sha256.Sum256(data)
	return ecdsa.SignASN1(rand.Reader, m.sigKey, h[:])
}

// Verify checks sig over data against the PINNED certificate of node peer; false on any failure.
func (m *MpcMesh) Verify(peer int, data, sig []byte) bool {
	pk := m.pubKeys[peer]
	if pk == nil || peer == m.selfID {
		return false
	}
	h := sha256.Sum256(data)
	return ecdsa.VerifyASN1(pk, h[:], sig)
}

// Recv returns the next message from `from`, which must belong to round. timeout 0 means the default; it never hangs.
func (m *MpcMesh) Recv(from int, round string, timeout time.Duration) (any, error) {
	l := m.links[from]
	if l == nil {
		return nil, fmt.Errorf("mesh: no link to %d", from)
	}
	if timeout <= 0 {
		timeout = m.recvTO
	}
	deadline := m.clk.Now().Add(timeout)
	for {
		m.mu.Lock()
		if m.failure != nil {
			f := m.failure
			m.mu.Unlock()
			return nil, f
		}
		if len(l.inbox) > 0 {
			it := l.inbox[0]
			l.inbox = l.inbox[1:]
			if it.abort != nil {
				m.failLocked(it.abort, from)
				m.mu.Unlock()
				return nil, it.abort
			}
			l.inboxByte -= it.size
			if l.paused && len(l.inbox) <= m.maxFrm/2 && l.inboxByte <= m.maxBytes/2 {
				l.paused = false
				m.wakeLocked()
			}
			if rd, _ := it.f["rd"].(string); rd != round {
				e := m.abort("wrong-round", from, fmt.Sprintf("expected round '%s', got '%s'", round, rd))
				m.failLocked(e, -1)
				m.mu.Unlock()
				return nil, e
			}
			m.mu.Unlock()
			return it.f["d"], nil
		}
		if l.closed {
			e := m.abort("disconnect", from, fmt.Sprintf("link to %d closed while awaiting '%s'", from, round))
			m.failLocked(e, -1)
			m.mu.Unlock()
			return nil, e
		}
		left := deadline.Sub(m.clk.Now())
		if left <= 0 {
			ms := int(timeout / time.Millisecond)
			b := from
			e := NewMpcNetAbort("timeout", &b, m.selfID, fmt.Sprintf("no '%s' message from %d within %dms (deadline %dms; a silent peer is blamed on this local observation only)", round, from, ms, ms), nil, nil, nil, nil, &ms)
			m.failLocked(e, -1)
			m.mu.Unlock()
			return nil, e
		}
		ch := m.wake
		m.mu.Unlock()
		stop := m.clk.AfterFunc(left, func() {
			m.mu.Lock()
			m.wakeLocked()
			m.mu.Unlock()
		})
		<-ch
		stop()
	}
}

// SetDeferAborts: while on, a peer's abort frame does not poison the mesh on arrival; it is queued behind that peer's earlier
// frames and takes effect only when a receive from that peer reaches it (used by the blame round).
func (m *MpcMesh) SetDeferAborts(on bool) {
	m.mu.Lock()
	m.deferAbort = on
	m.mu.Unlock()
}

// Collect receives round from every peer in from concurrently. A failure on any link fails the whole call.
func (m *MpcMesh) Collect(round string, from []int, timeout time.Duration) (map[int]any, error) {
	type res struct {
		p int
		v any
		e error
	}
	ch := make(chan res, len(from))
	for _, p := range from {
		go func() {
			v, e := m.Recv(p, round, timeout)
			ch <- res{p, v, e}
		}()
	}
	out := map[int]any{}
	var first error
	for range from {
		r := <-ch
		if r.e != nil && first == nil {
			first = r.e
		}
		out[r.p] = r.v
	}
	if first != nil {
		return nil, first
	}
	return out, nil
}

// ------------------------------------------------------------------ failure / shutdown

// Fail poisons the mesh with err (the first failure wins).
func (m *MpcMesh) Fail(err *MpcNetAbort) {
	m.mu.Lock()
	m.failLocked(err, -1)
	m.mu.Unlock()
}

// failLocked records the first failure, tells every peer except skip (the one that just told us; the original accusation is
// forwarded so an innocent bystander is never blamed for merely closing), then closes everything.
func (m *MpcMesh) failLocked(err *MpcNetAbort, skip int) {
	if m.failure != nil {
		return
	}
	m.failure = err
	var targets []*mpcLink
	for _, l := range m.links {
		if l.id != skip && l.conn != nil && !l.closed {
			targets = append(targets, l)
		}
	}
	kind, blamed := err.Kind, any(nil)
	if err.Blamed != nil {
		blamed = *err.Blamed
	}
	relayed := false
	if err.Kind == "peer-abort" {
		relayed = true
		kind = "peer-abort"
		if err.ClaimedKind != nil {
			kind = *err.ClaimedKind
		}
		blamed = nil
		if err.ClaimedBlame != nil {
			blamed = *err.ClaimedBlame
		}
	}
	d := map[string]any{"kind": kind, "blamed": blamed, "detail": mpcSanitize(err.Error(), 200)}
	if relayed {
		d["relayed"] = true
	}
	m.wakeLocked()
	go func() {
		for _, l := range targets {
			l.wmu.Lock()
			if raw, e := MpcEncodeFrame(MpcWireVersion, "abort", m.cfg.SessionID, l.sendSeq, "abort", d); e == nil {
				l.sendSeq++
				m.writeLink(l, raw, 2*time.Second)
			}
			l.wmu.Unlock()
		}
		time.Sleep(50 * time.Millisecond)
		m.closeAll()
	}()
}

// Finish is normal completion: flush and close. Peers still reading see EOF only after our data.
func (m *MpcMesh) Finish() {
	m.mu.Lock()
	m.finished = true
	m.mu.Unlock()
	time.Sleep(100 * time.Millisecond)
	m.closeAll()
}

func (m *MpcMesh) closeAll() {
	m.mu.Lock()
	var cs []net.Conn
	for _, l := range m.links {
		if l.conn != nil {
			cs = append(cs, l.conn)
		}
	}
	ln := m.listener
	m.mu.Unlock()
	for _, c := range cs {
		if tc, ok := c.(*tls.Conn); ok {
			_ = tc.CloseWrite()
		}
	}
	time.AfterFunc(100*time.Millisecond, func() {
		for _, c := range cs {
			_ = c.Close()
		}
		if ln != nil {
			_ = ln.Close()
		}
	})
}

// Close tears the mesh down at once (listener and links), for cleanup after a test or an abandoned run.
func (m *MpcMesh) Close() {
	m.mu.Lock()
	var cs []net.Conn
	for _, l := range m.links {
		if l.conn != nil {
			cs = append(cs, l.conn)
		}
	}
	ln := m.listener
	m.mu.Unlock()
	for _, c := range cs {
		_ = c.Close()
	}
	if ln != nil {
		_ = ln.Close()
	}
}

// Stats are the per-link application-level counters.
func (m *MpcMesh) Stats() []MpcLinkStats {
	var out []MpcLinkStats
	for _, p := range m.Peers() {
		l := m.links[p]
		m.mu.Lock()
		in, fin := l.bytesIn, l.framesIn
		m.mu.Unlock()
		l.wmu.Lock()
		out = append(out, MpcLinkStats{Peer: p, AppBytesOut: l.bytesOut, AppBytesIn: in, FramesOut: l.framesOut, FramesIn: fin})
		l.wmu.Unlock()
	}
	return out
}

// mpcSanitize is a printable-ASCII, length-capped copy of untrusted text (no control characters, no log forging).
func mpcSanitize(x string, limit int) string {
	var sb strings.Builder
	n := 0
	for _, r := range x {
		if n >= limit {
			break
		}
		if r < 0x20 || r > 0x7e {
			r = '?'
		}
		sb.WriteRune(r)
		n++
	}
	return sb.String()
}
