package pca

// A mutual-TLS channel for the FROST DKG: one TLS 1.3 connection per pair of participants, mutually authenticated by pinned
// certificate. Each side trusts exactly the other participants' certificates, and the peer's SHA-256 certificate fingerprint maps to
// its participant id, so the sender identity the DKG driver sees comes from the handshake and never from message content. The
// higher-numbered party dials the lower-numbered one. A peer without a pinned certificate, a plaintext client, a TLS 1.2 client, a
// second connection for an already linked identity and a connection from a party that should have been dialled are all refused before
// any DKG byte is read. Frames are a 4-byte big-endian length then the message; the length is checked against DkgMaxMessageBytes
// before any allocation. Certificate issuance, rotation and revocation are the deployer's.

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// TlsDkgPeerCert pins the certificate of one other participant.
type TlsDkgPeerCert struct {
	ID      int64
	CertPEM string
}

// TlsDkgNodeOpts configure StartTlsDkgNode. ListenPort 0 is ephemeral (read TlsDkgNode.Port); an empty ListenHost is 127.0.0.1.
type TlsDkgNodeOpts struct {
	Self       int64
	SessionID  []byte
	KeyPEM     string
	CertPEM    string
	PeerCerts  []TlsDkgPeerCert
	ListenPort int
	ListenHost string
}

// TlsDkgAddress is where to dial one lower-numbered peer.
type TlsDkgAddress struct {
	ID   int64
	Host string
	Port int
}

// TlsDkgNode is one participant's listener and links.
type TlsDkgNode struct {
	opts    TlsDkgNodeOpts
	pinned  map[string]int64
	peers   []int64
	inbox   *DkgInbox
	ln      net.Listener
	keyPair tls.Certificate

	mu      sync.Mutex
	links   map[int64]*tlsDkgLink
	conns   map[net.Conn]struct{}
	waiters map[chan struct{}]struct{}
	closed  bool
}

type tlsDkgLink struct {
	conn net.Conn
	wmu  sync.Mutex
}

func tlsDkgFingerprint(der []byte) string {
	h := sha256.Sum256(der)
	return hex.EncodeToString(h[:])
}

func tlsDkgCertDER(certPEM string) ([]byte, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("startTlsDkgNode: a peer certificate is not a PEM certificate")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return nil, err
	}
	return block.Bytes, nil
}

// StartTlsDkgNode listens for the higher-numbered peers.
func StartTlsDkgNode(o TlsDkgNodeOpts) (*TlsDkgNode, error) {
	n := &TlsDkgNode{opts: o, pinned: map[string]int64{}, links: map[int64]*tlsDkgLink{}, conns: map[net.Conn]struct{}{}, waiters: map[chan struct{}]struct{}{}}
	for _, p := range o.PeerCerts {
		der, err := tlsDkgCertDER(p.CertPEM)
		if err != nil {
			return nil, err
		}
		n.pinned[tlsDkgFingerprint(der)] = p.ID
		n.peers = append(n.peers, p.ID)
	}
	if len(n.pinned) != len(o.PeerCerts) {
		return nil, errors.New("startTlsDkgNode: peer certificates must be distinct and none may be this node")
	}
	for _, p := range o.PeerCerts {
		if p.ID == o.Self {
			return nil, errors.New("startTlsDkgNode: peer certificates must be distinct and none may be this node")
		}
	}
	sort.Slice(n.peers, func(i, j int) bool { return n.peers[i] < n.peers[j] })
	kp, err := tls.X509KeyPair([]byte(o.CertPEM), []byte(o.KeyPEM))
	if err != nil {
		return nil, err
	}
	n.keyPair = kp
	n.inbox = NewDkgInbox(o.SessionID, n.peers)
	host := o.ListenHost
	if host == "" {
		host = "127.0.0.1"
	}
	ln, err := tls.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(o.ListenPort)), n.config(true))
	if err != nil {
		return nil, err
	}
	n.ln = ln
	go n.serve()
	return n, nil
}

// pinCheck is the certificate verification: a TLS 1.3 handshake whose peer certificate is one of the pinned ones, inside its validity.
func (n *TlsDkgNode) pinCheck(raw [][]byte, _ [][]*x509.Certificate) error {
	if len(raw) == 0 {
		return errors.New("no certificate")
	}
	if _, ok := n.pinned[tlsDkgFingerprint(raw[0])]; !ok {
		return errors.New("certificate is not pinned")
	}
	c, err := x509.ParseCertificate(raw[0])
	if err != nil {
		return err
	}
	if now := time.Now(); now.Before(c.NotBefore) || now.After(c.NotAfter) {
		return errors.New("certificate is outside its validity")
	}
	return nil
}

func (n *TlsDkgNode) config(server bool) *tls.Config {
	c := &tls.Config{Certificates: []tls.Certificate{n.keyPair}, MinVersion: tls.VersionTLS13, VerifyPeerCertificate: n.pinCheck}
	if server {
		c.ClientAuth = tls.RequireAnyClientCert
	} else {
		c.InsecureSkipVerify = true // pinned by certificate (VerifyPeerCertificate), not by host name
	}
	return c
}

// Port is the port the node listens on.
func (n *TlsDkgNode) Port() int { return n.ln.Addr().(*net.TCPAddr).Port }

func (n *TlsDkgNode) track(c net.Conn) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return false
	}
	n.conns[c] = struct{}{}
	return true
}

func (n *TlsDkgNode) serve() {
	for {
		c, err := n.ln.Accept()
		if err != nil {
			return
		}
		go func() {
			tc := c.(*tls.Conn)
			if !n.track(tc) {
				_ = c.Close()
				return
			}
			_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
			if err := tc.Handshake(); err != nil {
				_ = c.Close()
				return
			}
			_ = tc.SetDeadline(time.Time{})
			certs := tc.ConnectionState().PeerCertificates
			id, pinned := int64(0), false
			if len(certs) > 0 {
				id, pinned = n.pinned[tlsDkgFingerprint(certs[0].Raw)]
			}
			// Only a pinned, authorized peer that is supposed to dial us (higher id), once.
			n.mu.Lock()
			_, linked := n.links[id]
			n.mu.Unlock()
			if !pinned || id < n.opts.Self || linked {
				_ = c.Close()
				return
			}
			n.attach(id, c)
		}()
	}
}

func (n *TlsDkgNode) attach(id int64, c net.Conn) {
	link := &tlsDkgLink{conn: c}
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		_ = c.Close()
		return
	}
	if _, linked := n.links[id]; linked {
		n.mu.Unlock()
		_ = c.Close()
		return
	}
	n.links[id] = link
	for w := range n.waiters {
		select {
		case w <- struct{}{}:
		default:
		}
	}
	n.mu.Unlock()
	go func() {
		var r DkgFrameReader
		buf := make([]byte, 32*1024)
		for {
			k, err := c.Read(buf)
			if k > 0 {
				frames, ferr := r.Push(buf[:k])
				for _, f := range frames {
					n.inbox.Accept(id, f)
				}
				if ferr != nil {
					n.inbox.Fail(id, dkgErr("oversize", "frame exceeds the cap"))
					_ = c.Close()
					break
				}
			}
			if err != nil {
				break
			}
		}
		n.mu.Lock()
		if n.links[id] == link {
			delete(n.links, id)
		}
		n.mu.Unlock()
		n.inbox.PeerGone(id)
	}()
}

func (n *TlsDkgNode) dial(a TlsDkgAddress, stop func() bool) {
	for !stop() {
		d := net.Dialer{Timeout: 5 * time.Second}
		raw, err := d.Dial("tcp", net.JoinHostPort(a.Host, strconv.Itoa(a.Port)))
		if err == nil {
			tc := tls.Client(raw, n.config(false))
			if n.track(tc) {
				_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
				if err = tc.Handshake(); err == nil {
					_ = tc.SetDeadline(time.Time{})
					certs := tc.ConnectionState().PeerCertificates
					if len(certs) > 0 && n.pinned[tlsDkgFingerprint(certs[0].Raw)] == a.ID {
						n.attach(a.ID, tc)
						return
					}
				}
			}
			_ = raw.Close()
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (n *TlsDkgNode) isClosed() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.closed
}

// Connect dials the lower-numbered peers, waits for the higher-numbered ones and returns the channel once every link is authenticated.
// connectTimeoutMs <= 0 is 15000.
func (n *TlsDkgNode) Connect(addresses []TlsDkgAddress, connectTimeoutMs float64) (DkgChannel, error) {
	if connectTimeoutMs <= 0 {
		connectTimeoutMs = 15000
	}
	stopped := false
	var smu sync.Mutex
	stop := func() bool { smu.Lock(); defer smu.Unlock(); return stopped || n.isClosed() }
	for _, a := range addresses {
		known := false
		for _, p := range n.peers {
			known = known || p == a.ID
		}
		if !known {
			return nil, dkgErrPeer("identity", a.ID, "address for a participant that is not a pinned peer")
		}
		if a.ID < n.opts.Self {
			go n.dial(a, stop)
		}
	}
	deadline := time.NewTimer(time.Duration(connectTimeoutMs * float64(time.Millisecond)))
	defer deadline.Stop()
	for {
		n.mu.Lock()
		have := len(n.links)
		var missing []string
		first := int64(0)
		for _, p := range n.peers {
			if _, ok := n.links[p]; !ok {
				if len(missing) == 0 {
					first = p
				}
				missing = append(missing, strconv.FormatInt(p, 10))
			}
		}
		w := make(chan struct{}, 1)
		n.waiters[w] = struct{}{}
		n.mu.Unlock()
		if have >= len(n.peers) {
			n.dropWaiter(w)
			break
		}
		select {
		case <-w:
			n.dropWaiter(w)
		case <-deadline.C:
			n.dropWaiter(w)
			smu.Lock()
			stopped = true
			smu.Unlock()
			_ = n.Close()
			return nil, dkgErrPeer("timeout", first, "no authenticated link to "+strings.Join(missing, ","))
		}
	}
	smu.Lock()
	stopped = true
	smu.Unlock()
	return &tlsDkgChannel{n: n}, nil
}

func (n *TlsDkgNode) dropWaiter(w chan struct{}) {
	n.mu.Lock()
	delete(n.waiters, w)
	n.mu.Unlock()
}

// Close ends every link and the listener.
func (n *TlsDkgNode) Close() error {
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return nil
	}
	n.closed = true
	conns := make([]net.Conn, 0, len(n.conns))
	for c := range n.conns {
		conns = append(conns, c)
	}
	n.mu.Unlock()
	n.inbox.Close()
	for _, c := range conns {
		_ = c.Close()
	}
	return n.ln.Close()
}

type tlsDkgChannel struct{ n *TlsDkgNode }

func (c *tlsDkgChannel) Self() int64    { return c.n.opts.Self }
func (c *tlsDkgChannel) Peers() []int64 { return append([]int64(nil), c.n.peers...) }

func (c *tlsDkgChannel) write(to int64, kind string, body any) error {
	c.n.mu.Lock()
	link := c.n.links[to]
	c.n.mu.Unlock()
	if link == nil {
		return dkgErrPeer("closed", to, "no authenticated link")
	}
	payload, err := dkgEncodeEnvelope(c.n.opts.SessionID, kind, body)
	if err != nil {
		return err
	}
	link.wmu.Lock()
	defer link.wmu.Unlock()
	if _, err := link.conn.Write(DkgFrame(payload)); err != nil {
		return dkgErrPeer("closed", to, "write failed")
	}
	return nil
}

func (c *tlsDkgChannel) Broadcast(kind string, body any) error {
	errs := make([]error, len(c.n.peers))
	var wg sync.WaitGroup
	for i, p := range c.n.peers {
		wg.Add(1)
		go func(i int, p int64) { defer wg.Done(); errs[i] = c.write(p, kind, body) }(i, p)
	}
	wg.Wait()
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}

func (c *tlsDkgChannel) Send(to int64, kind string, body any) error {
	for _, p := range c.n.peers {
		if p == to {
			return c.write(to, kind, body)
		}
	}
	return dkgErrPeer("identity", to, "not a connected peer")
}

func (c *tlsDkgChannel) Collect(kind string, from []int64, timeoutMs float64) ([]DkgCollected, error) {
	return c.n.inbox.Collect(kind, from, timeoutMs)
}

func (c *tlsDkgChannel) Close() error { return c.n.Close() }
