package pca

// A forward proxy for non-WASM tools: set it as the tool's only route out (HTTP(S)_PROXY, a network namespace, or the generated OS
// profile that permits connecting only to this proxy). Every request is claimed against the admissions of an EgressPolicy;
// refusals answer 403 and are receipted. The upstream address is resolved through a guard that refuses private addresses (the
// strict IsPrivateAddress rule) unless AllowPrivate, checked on the resolved list AND again at connect time, so an admitted host
// name cannot be re-pointed at an internal service (DNS rebinding) and an IP literal is refused too.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// EgressProxyOptions configure NewEgressProxy.
type EgressProxyOptions struct {
	Policy          *EgressPolicy
	Log             *SandboxReceiptLog
	RuntimeClass    string        // default egress_default_deny
	AllowPrivate    bool          // permit upstreams that resolve to private / loopback addresses (tests, internal APIs); default false
	MaxBodyBytes    int64         // default 1 MiB
	UpstreamTimeout time.Duration // default 10 s
	// LookupHost resolves a host name; nil = the system resolver. A seam for tests.
	LookupHost func(ctx context.Context, host string) ([]string, error)
}

// EgressProxy is an http.Handler serving both plain forward requests and CONNECT tunnels.
type EgressProxy struct {
	o         EgressProxyOptions
	mu        sync.Mutex // the policy and the receipt log are not safe for concurrent use
	transport *http.Transport
}

var errEgressPrivate = errors.New("private_address")

var egressHop = map[string]bool{"connection": true, "keep-alive": true, "proxy-authenticate": true, "proxy-authorization": true,
	"proxy-connection": true, "te": true, "trailer": true, "transfer-encoding": true, "upgrade": true, "host": true}

// NewEgressProxy builds the proxy. Policy and Log are required.
func NewEgressProxy(o EgressProxyOptions) (*EgressProxy, error) {
	if o.Policy == nil || o.Log == nil {
		return nil, errors.New("egress proxy: policy and log are required")
	}
	if o.RuntimeClass == "" {
		o.RuntimeClass = "egress_default_deny"
	}
	if o.MaxBodyBytes <= 0 {
		o.MaxBodyBytes = 1 << 20
	}
	if o.UpstreamTimeout <= 0 {
		o.UpstreamTimeout = 10 * time.Second
	}
	p := &EgressProxy{o: o}
	p.transport = &http.Transport{
		Proxy:                 nil, // never chain through another proxy
		DialContext:           p.dial,
		ResponseHeaderTimeout: o.UpstreamTimeout,
		TLSHandshakeTimeout:   o.UpstreamTimeout,
		DisableCompression:    true,
	}
	return p, nil
}

func (p *EgressProxy) isPrivateLiteral(host string) bool {
	h := strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	return !p.o.AllowPrivate && net.ParseIP(h) != nil && IsPrivateAddress(h)
}

// dial resolves host, refuses when ANY resolved address is private, then connects to the resolved addresses only (the connect
// itself re-checks the address it reaches).
func (p *EgressProxy) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	ips := []string{host}
	if net.ParseIP(host) == nil {
		lookup := p.o.LookupHost
		if lookup == nil {
			lookup = net.DefaultResolver.LookupHost
		}
		if ips, err = lookup(ctx, host); err != nil {
			return nil, err
		}
	}
	if len(ips) == 0 {
		return nil, errors.New("no address")
	}
	if !p.o.AllowPrivate {
		for _, ip := range ips {
			if IsPrivateAddress(ip) {
				return nil, errEgressPrivate
			}
		}
	}
	d := net.Dialer{Timeout: p.o.UpstreamTimeout, Control: func(_, address string, _ syscall.RawConn) error {
		if h, _, err := net.SplitHostPort(address); err != nil || (!p.o.AllowPrivate && IsPrivateAddress(h)) {
			return errEgressPrivate
		}
		return nil
	}}
	var last error
	for _, ip := range ips {
		c, err := d.DialContext(ctx, network, net.JoinHostPort(ip, port))
		if err == nil {
			return c, nil
		}
		last = err
	}
	return nil, last
}

func egressCode(err error) string {
	var ne net.Error
	switch {
	case errors.Is(err, errEgressPrivate):
		return "EACCES"
	case errors.As(err, &ne) && ne.Timeout(), errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	}
	s := err.Error()
	if len(s) > 56 {
		s = s[:56]
	}
	return s
}

func egressText(v any) any {
	if v == nil {
		return ""
	}
	return v
}

func (p *EgressProxy) claim(method, target string, body []byte) map[string]any {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.o.Policy.Claim(method, target, body)
}

func (p *EgressProxy) receipt(method, target string, d map[string]any, outcome, reason string) {
	subject := map[string]any{"op_id": "", "verb": "", "resource": "", "params_digest": ""}
	if d["allow"] == true {
		adm, _ := d["admission"].(map[string]any)
		subject = map[string]any{"op_id": egressText(d["op_id"]), "verb": egressText(adm["verb"]), "resource": egressText(adm["resource"]),
			"params_digest": egressText(adm["params_digest"])}
	} else {
		r := []rune(method + " " + target)
		if len(r) > 256 {
			r = r[:256]
		}
		subject["resource"] = string(r)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	_, _ = p.o.Log.Append(p.o.RuntimeClass, map[string]any{"kind": "egress", "subject": subject, "outcome": outcome, "reason": reason})
}

func (p *EgressProxy) deny(w http.ResponseWriter, method, target, reason string, status int) {
	p.receipt(method, target, map[string]any{"allow": false, "reason": reason}, "refused", reason)
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, `{"error":"egress_denied","reason":%q}`, reason)
}

// ServeHTTP implements http.Handler.
func (p *EgressProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.connect(w, r)
		return
	}
	target := r.RequestURI
	body, err := io.ReadAll(io.LimitReader(r.Body, p.o.MaxBodyBytes+1))
	if err != nil {
		p.deny(w, r.Method, target, "body_unreadable", http.StatusBadRequest)
		return
	}
	if int64(len(body)) > p.o.MaxBodyBytes {
		p.deny(w, r.Method, target, "body_too_large", http.StatusRequestEntityTooLarge)
		return
	}
	d := p.claim(r.Method, target, body)
	if d["allow"] != true {
		reason, _ := d["reason"].(string)
		p.deny(w, r.Method, target, reason, http.StatusForbidden)
		return
	}
	u, err := url.Parse(target)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		p.receipt(r.Method, target, d, "error", "upstream:bad_url")
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	if p.isPrivateLiteral(u.Hostname()) {
		p.receipt(r.Method, target, d, "error", "upstream:EACCES")
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), p.o.UpstreamTimeout)
	defer cancel()
	out, err := http.NewRequestWithContext(ctx, r.Method, u.String(), bytes.NewReader(body))
	if err != nil {
		p.receipt(r.Method, target, d, "error", "upstream:"+egressCode(err))
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	for k, vs := range r.Header {
		if !egressHop[strings.ToLower(k)] {
			out.Header[k] = vs
		}
	}
	out.ContentLength = int64(len(body))
	resp, err := p.transport.RoundTrip(out)
	if err != nil {
		p.receipt(r.Method, target, d, "error", "upstream:"+egressCode(err))
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for k, vs := range resp.Header {
		if !egressHop[strings.ToLower(k)] {
			w.Header()[k] = vs
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
	p.receipt(r.Method, target, d, "ok", "status:"+strconv.Itoa(resp.StatusCode))
}

func (p *EgressProxy) connect(w http.ResponseWriter, r *http.Request) {
	target := r.RequestURI
	if target == "" {
		target = r.Host
	}
	d := p.claim("CONNECT", target, nil)
	if d["allow"] != true {
		reason, _ := d["reason"].(string)
		p.receipt("CONNECT", target, d, "refused", reason)
		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusForbidden)
		return
	}
	i := strings.LastIndex(target, ":")
	host := ""
	if i >= 0 {
		host = strings.TrimSuffix(strings.TrimPrefix(target[:i], "["), "]")
	}
	port := ""
	if i >= 0 {
		port = target[i+1:]
	}
	fail := func(reason string) {
		p.receipt("CONNECT", target, d, "error", reason)
		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusBadGateway)
	}
	if i < 0 || p.isPrivateLiteral(host) {
		fail("upstream:EACCES")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), p.o.UpstreamTimeout)
	defer cancel()
	up, err := p.dial(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		fail("upstream:" + egressCode(err))
		return
	}
	defer up.Close()
	hj, ok := w.(http.Hijacker)
	if !ok {
		fail("upstream:no_hijack")
		return
	}
	client, buf, err := hj.Hijack()
	if err != nil {
		fail("upstream:hijack")
		return
	}
	defer client.Close()
	p.receipt("CONNECT", target, d, "ok", "tunnel")
	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}
	if n := buf.Reader.Buffered(); n > 0 {
		head, _ := buf.Reader.Peek(n)
		if _, err := up.Write(head); err != nil {
			return
		}
	}
	done := make(chan struct{}, 2)
	pipe := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if c, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = c.CloseWrite()
		}
		done <- struct{}{}
	}
	go pipe(up, client)
	go pipe(client, up)
	<-done
	<-done
}
