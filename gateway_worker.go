package pca

// The Cloudflare Worker adapter of the gateway, free of any runtime: a request is {Method, URL, Headers} (header names compared
// case-insensitively), and the upstream call and the response builder are injected. On allow the upstream is called with every
// client-supplied x-pca-* header removed (the gateway's own verdict headers are the only ones a downstream may trust); on deny the
// 401 / 403 JSON body is built by Respond and the upstream is never called.

import (
	"errors"
	"sort"
	"strings"
)

// GatewayWorkerRequest is a fetch-style request. Body is read only in full-policy mode with body params.
type GatewayWorkerRequest struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    string
}

// GatewayWorkerOptions: Gateway is the gateway configuration; Next forwards an allowed request upstream; Respond builds a response
// from a JSON body, a status and headers. Rewrite removes the named headers from a request that carried forged ones (false: it
// cannot, so the request is refused with 400); nil uses the default (copy the request without those headers); NoRewrite opts
// out, so any forged x-pca-* header is a 400.
type GatewayWorkerOptions struct {
	Gateway   GatewayOptions
	Next      func(GatewayWorkerRequest) (any, error)
	Respond   func(body string, status int, headers map[string]string) any
	Rewrite   func(req GatewayWorkerRequest, drop []string) (GatewayWorkerRequest, bool)
	NoRewrite bool
}

// gwUrlParts splits a request URL into path, authority and query without a URL parser (the reference does the same).
func gwUrlParts(url string) (path, authority, query string) {
	rest := url
	if i := strings.Index(rest, "://"); i >= 0 {
		rest = rest[i+3:]
		if slash := strings.IndexByte(rest, '/'); slash >= 0 {
			authority, rest = rest[:slash], rest[slash:]
		} else {
			authority, rest = rest, "/"
		}
	}
	path = rest
	if i := strings.IndexAny(rest, "?#"); i >= 0 {
		path = rest[:i]
	}
	if path == "" {
		path = "/"
	}
	return path, authority, gwQueryOfTarget(rest)
}

// GatewayCloudflareWorker builds the worker handler. Construction errors are the gateway's (a missing policy).
func GatewayCloudflareWorker(o GatewayWorkerOptions) (func(GatewayWorkerRequest) (any, error), error) {
	if o.Next == nil || o.Respond == nil {
		return nil, errors.New("pca-gateway: Next and Respond are required")
	}
	gw, err := GatewayCreate(o.Gateway)
	if err != nil {
		return nil, err
	}
	bodyMode := o.Gateway.PolicyMode == "full" && o.Gateway.Full != nil && o.Gateway.Full.ParamsBody
	return func(r GatewayWorkerRequest) (any, error) {
		hs := make(map[string]string, len(r.Headers))
		for k, v := range r.Headers {
			hs[strings.ToLower(k)] = v
		}
		r.Headers = hs
		path, authority, query := gwUrlParts(r.URL)
		headers := map[string]any{}
		for _, h := range []string{"pca-action", "pca-discharges", "pca-narrow"} {
			if v, ok := hs[h]; ok {
				headers[h] = v
			}
		}
		req := GatewayRequest{Method: r.Method, Path: path, Query: &query, Authority: &authority, Headers: headers}
		if bodyMode { // the caller's body is still forwarded intact: this reads a copy of the text
			req.Body = &r.Body
		}
		d := gw(req)
		if !d.Allow {
			h := map[string]string{"content-type": "application/json"}
			for k, v := range d.Headers {
				h[k] = v
			}
			return o.Respond(gwErrorBody(d.Code, d.Reason), d.Status, h), nil
		}
		var forged []string
		for k := range hs {
			if strings.HasPrefix(k, "x-pca-") {
				forged = append(forged, k)
			}
		}
		for _, k := range GatewayInjectedHeaders { // an injected name is always x-pca-*; kept for the reference's explicit check
			if _, ok := hs[k]; ok && !contains(forged, k) {
				forged = append(forged, k)
			}
		}
		if len(forged) == 0 {
			return o.Next(r)
		}
		sort.Strings(forged)
		if !o.NoRewrite {
			if o.Rewrite != nil {
				if clean, ok := o.Rewrite(r, forged); ok {
					return o.Next(clean)
				}
			} else {
				kept := make(map[string]string, len(hs))
				for k, v := range hs {
					if !contains(forged, k) {
						kept[k] = v
					}
				}
				clean := r
				clean.Headers = kept
				return o.Next(clean)
			}
		}
		return o.Respond(`{"error":"forged-pca-header","reason":"inbound x-pca-* header cannot be removed"}`, 400, map[string]string{"content-type": "application/json"}), nil
	}, nil
}
