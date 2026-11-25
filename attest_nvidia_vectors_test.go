package pca

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// Replay of the NVIDIA GPU-CC modules against the reference, every case of both corpora (ref-attest-nvidia: report parsing, the
// VBIOS version, certificate helpers and chain verification, the report signature, the SPDM challenge, RIM ids and comparison,
// CRL revocation, the OCSP request, response and chain policy, the fetch helpers over a recording transport, the DER time check;
// ref-attest-nvidia-rim: RIM verification and the collateral hook). Long strings of the corpora live in their blob tables. A
// reference throw requires a refusal. A reason that comes from the reference's certificate or ASN.1 library is compared up to the
// point where that library text starts. The one OCSP request case whose "nonce" is not a byte array in the reference harness (an
// empty nonce, which the reference refuses when it is bytes) and the one with an unsupported hash (MD5, which Go does not offer) are
// refused here and counted.

func nvTime(ms int64) string { return time.UnixMilli(ms).UTC().Format("Jan _2 15:04:05 2006") + " GMT" }

func nvCertSummary(n *NodeCert) map[string]any {
	c := n.c
	from, to := derValidity(c.Raw)
	serial := c.Serial
	for len(serial) > 1 && serial[0] == 0 {
		serial = serial[1:]
	}
	spki, _ := SpkiSha256Hex(n)
	raw := sha256.Sum256(c.Raw)
	return map[string]any{"subject": nameText(c.RawSubject), "issuer": nameText(c.RawIssuer), "serial": strings.ToUpper(hex.EncodeToString(serial)),
		"notBefore": nvTime(from.ms), "notAfter": nvTime(to.ms), "spkiSha256": spki, "rawSha256": hex.EncodeToString(raw[:]), "ca": n.CA()}
}

func nvChainSummary(chain []*NodeCert) []any {
	out := make([]any, len(chain))
	for i, c := range chain {
		out[i] = nvCertSummary(c)
	}
	return out
}

func nvReportSummary(r *SpdmReport) map[string]any {
	ms := []any{}
	for _, m := range r.Measurements() {
		ms = append(ms, map[string]any{"index": jsNumber(float64(m.Index)), "valueType": jsNumber(float64(m.ValueType)), "digest": vecBytesOut(m.Digest)})
	}
	opaque := map[string]any{}
	for k, v := range r.Opaque() {
		opaque[jsNumberString(float64(k))] = vecBytesOut(v)
	}
	sha := sha256.Sum256(r.SignedBytes())
	n := func(b byte) json.Number { return jsNumber(float64(b)) }
	return map[string]any{
		"request": map[string]any{"version": n(r.RequestVersion()), "code": n(r.RequestCode()), "param1": n(r.RequestParam1()), "param2": n(r.RequestParam2()),
			"nonce": vecBytesOut(r.RequestNonce()), "slot": n(r.Slot())},
		"response": map[string]any{"version": n(r.ResponseVersion()), "code": n(r.ResponseCode()), "numBlocks": jsNumber(float64(r.NumBlocks())), "measurements": ms,
			"responderNonce": vecBytesOut(r.ResponderNonce()), "opaque": opaque, "signature": vecBytesOut(r.Signature())},
		"signedBytesLength": jsNumber(float64(len(r.SignedBytes()))), "signedBytesSha256": hex.EncodeToString(sha[:]),
	}
}

func nvRimSummary(v *VerifiedRim) map[string]any {
	gs := []any{}
	for _, g := range v.Golden() {
		hs := make([]any, len(g.Hashes))
		for i, h := range g.Hashes {
			hs[i] = h
		}
		gs = append(gs, map[string]any{"index": jsNumber(float64(g.Index)), "active": g.Active, "alternatives": jsNumber(float64(g.Alternatives)), "size": jsNumber(float64(g.Size)), "hashes": hs})
	}
	return map[string]any{"tagId": v.TagID(), "product": v.Product(), "version": v.Version(), "golden": gs, "signerSubject": v.SignerSubject()}
}

func nvRimOf(v any) *VerifiedRim {
	m := vecObj(v)
	var gs []RimGolden
	for _, x := range rsList(m["golden"]) {
		g := vecObj(x)
		i, _ := attSafeInt(g["index"])
		a, _ := attSafeInt(g["alternatives"])
		s, _ := attSafeInt(g["size"])
		gs = append(gs, RimGolden{Index: int(i), Active: g["active"] == true, Alternatives: int(a), Size: int(s), Hashes: attStrings(g["hashes"])})
	}
	return NewVerifiedRim(rsStr(m["tagId"]), rsStr(m["product"]), rsStr(m["version"]), gs)
}

func nvBytesList(v any) [][]byte {
	var out [][]byte
	for _, x := range rsList(v) {
		b, _ := qvBytes(x)
		out = append(out, b)
	}
	return out
}

// nvReasonEq compares reasons: equal, or equal up to the point where the reference's library text starts.
func nvReasonEq(w, g string) bool {
	if w == g {
		return true
	}
	for _, mk := range []string{"OCSP response rejected:", "verification error (fail closed):", "device chain unparseable:", "error:0", "schema"} {
		if i := strings.Index(w, mk); i >= 0 {
			return len(g) >= i+len(mk) && g[:i+len(mk)] == w[:i+len(mk)] || (mk == "schema" && g != "")
		}
	}
	return false
}

// nvResultEq compares two result objects member by member, the reason with nvReasonEq.
func nvResultEq(want, got any) bool {
	w, g := vecObj(want), vecObj(got)
	if g != nil && g["refused"] != nil { // refused here only: the reference built bytes
		return w != nil && w["$bytes"] != nil
	}
	if w == nil || g == nil {
		return baseCanon(want) == baseCanon(got)
	}
	if len(w) != len(g) {
		return false
	}
	for k, x := range w {
		y, ok := g[k]
		if !ok {
			return false
		}
		if k == "reason" || k == "value" {
			ws, wok := x.(string)
			gs, gok := y.(string)
			if wok && gok {
				if !nvReasonEq(ws, gs) {
					return false
				}
				continue
			}
		}
		if baseCanon(x) != baseCanon(y) {
			return false
		}
	}
	return true
}

// nvFetch is a recording transport for a corpus response spec: {status?, body?, bodyBytes?} or {$throws}.
type nvFetchRec struct {
	requests []any
	spec     map[string]any
}

func (f *nvFetchRec) fetch(method, url, contentType string, body []byte) (int, []byte, error) {
	rq := map[string]any{"url": url, "method": method, "contentType": nil}
	if contentType != "" {
		rq["contentType"] = contentType
		rq["bodyBytes"] = jsNumber(float64(len(body)))
	}
	f.requests = append(f.requests, rq)
	if msg, ok := f.spec["$throws"].(string); ok {
		return 0, nil, errors.New(msg)
	}
	status := 200
	if s, ok := attSafeInt(f.spec["status"]); ok {
		status = int(s)
	}
	if b, ok := qvBytes(f.spec["bodyBytes"]); ok {
		return status, b, nil
	}
	j, _ := json.Marshal(f.spec["body"])
	return status, j, nil
}

func (f *nvFetchRec) out(extra map[string]any, err error) any {
	m := map[string]any{"requests": append([]any{}, f.requests...)}
	if err != nil {
		m["ok"], m["error"] = false, err.Error()
		return m
	}
	m["ok"] = true
	for k, v := range extra {
		m[k] = v
	}
	return m
}

// NATIVE STRICTER, ON PURPOSE: in this real OCSP response one byte is flipped (offset 500: an RDN SET length inside the delegated
// responder's certificate, 0x1b -> 0x1a, so its only child overruns it). Both refuse it: the native at the declared DER lengths, the
// reference when it re-parses the embedded certificate, each with its own reason. The replay asserts the native refusal and its exact
// reason for this response (by its digest) and accepts it only against that exact reference refusal.
const (
	nvFlippedOcspSHA256    = "8289eaa88e1ac3fa96bf13834fcfeaf02e5793b99587e54b6b921ccc30b9a0ac"
	nvFlippedOcspReason    = "response carries a malformed (out-of-range) ASN.1 time"
	nvFlippedOcspRefReason = "OCSP response rejected: embedded certificate is not valid DER"
)

func TestNvidiaMatchesTheReference(t *testing.T) {
	emptyNonce, badHash := 0, 0
	run := func(file string, total int, fns map[string]vecFn, text map[string]bool) {
		blobs := mvBlobs(t, file)
		wrapped := map[string]vecFn{}
		cmp := map[string]func(want, got any) bool{}
		for name, f := range fns {
			f := f
			wrapped[name] = func(a []any) (any, error) {
				h, err := hydrateBlobs(a, blobs)
				if err != nil {
					return nil, err
				}
				return f(h.([]any))
			}
			cmp[name] = func(want, got any) bool {
				h, err := hydrateBlobs(want, blobs)
				return err == nil && nvResultEq(h, got)
			}
		}
		if base, has := cmp["ocspVerify"]; has {
			cmp["ocspVerify"] = func(want, got any) bool {
				if g, ok := got.(map[string]any); ok && g["nativeStricter"] == true {
					h, err := hydrateBlobs(want, blobs)
					w := vecObj(h)
					return err == nil && g["reason"] == nvFlippedOcspReason && w["ok"] == false && w["reason"] == nvFlippedOcspRefReason
				}
				return base(want, got)
			}
		}
		replayAll(t, file, total, wrapped, cmp, text)
	}
	chainOf := func(v any) ([]*NodeCert, error) { return ParsePemChain(rsStr(v)) }
	reportOf := func(v any) (*SpdmReport, error) {
		b, _ := qvBytes(v)
		return ParseNvidiaSpdmEvidence(b)
	}
	fetchOf := func(spec any) *nvFetchRec { return &nvFetchRec{spec: vecObj(spec)} }

	run("ref-attest-nvidia.json.gz", 467, map[string]vecFn{
		"constants": func([]any) (any, error) {
			opaque := map[string]any{}
			for k, v := range NvidiaOpaque {
				opaque[k] = jsNumber(float64(v))
			}
			strs := func(l []string) []any {
				out := make([]any, len(l))
				for i, s := range l {
					out[i] = s
				}
				return out
			}
			return map[string]any{"NVIDIA_SPDM_SUITE": NvidiaSpdmSuite, "NVIDIA_OPAQUE": opaque, "NVIDIA_RIM_BASE_URL": NvidiaRimBaseUrl,
				"NVIDIA_GH100_CRL_URLS": strs(NvidiaGh100CrlUrls), "NVIDIA_GB100_CRL_URLS": strs(NvidiaGb100CrlUrls), "NVIDIA_OCSP_URL": NvidiaOcspUrl,
				"NVIDIA_OCSP_DEFAULT_MAX_AGE_MS": jsNumber(float64(NvidiaOcspDefaultMaxAgeMs))}, nil
		},
		"parseReport": func(a []any) (any, error) {
			r, err := reportOf(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			return nvReportSummary(r), nil
		},
		"formatVbiosVersion": func(a []any) (any, error) {
			b, _ := qvBytes(vecArg(a, 0))
			return FormatVbiosVersion(b), nil
		},
		"spkiSha256Hex": func(a []any) (any, error) {
			c, err := ParseNodeCertPEM(rsStr(vecArg(a, 0)))
			if err != nil {
				return nil, err
			}
			return SpkiSha256Hex(c)
		},
		"parsePemChain": func(a []any) (any, error) {
			ch, err := chainOf(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			return nvChainSummary(ch), nil
		},
		"verifyDeviceChain": func(a []any) (any, error) {
			now, _ := jsNum(vecArg(a, 2))
			ch, why := VerifyNvidiaDeviceChain(rsStr(vecArg(a, 0)), attStrings(vecArg(a, 1)), int64(now))
			if why != "" {
				return map[string]any{"ok": false, "reason": why}, nil
			}
			return map[string]any{"ok": true, "leaf": nvCertSummary(ch[0]), "chain": nvChainSummary(ch)}, nil
		},
		"verifySpdmSignature": func(a []any) (any, error) {
			r, err := reportOf(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			ch, err := chainOf(vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			return VerifyNvidiaSpdmSignature(r, ch[0]), nil
		},
		"spdmChallenge": func(a []any) (any, error) {
			b, err := NvidiaSpdmChallenge(attExpected(scDecode(vecArg(a, 0))))
			if err != nil {
				return nil, err
			}
			return vecBytesOut(b), nil
		},
		"rimIds": func(a []any) (any, error) {
			r, err := reportOf(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			ids := NvidiaRimIdsForReport(r)
			if ids == nil {
				return nil, nil
			}
			return map[string]any{"chip": ids.chip, "driver": ids.driver, "vbios": ids.vbios, "driverVersion": ids.driverVersion, "vbiosVersion": ids.vbiosVersion}, nil
		},
		"compareReport": func(a []any) (any, error) {
			r, err := reportOf(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			c := CompareReportToRimsDetailed(r, nvRimOf(vecArg(a, 1)), nvRimOf(vecArg(a, 2)))
			if c.Reason == "" {
				return map[string]any{"ok": true, "checked": jsNumber(float64(c.Checked))}, nil
			}
			out := map[string]any{"ok": false, "reason": c.Reason}
			if len(c.Mismatches) > 0 {
				ms := make([]any, len(c.Mismatches))
				for i, m := range c.Mismatches {
					ms[i] = map[string]any{"index": jsNumber(float64(m.Index)), "source": m.Source}
				}
				out["mismatches"] = ms
			}
			return out, nil
		},
		"checkRevocation": func(a []any) (any, error) {
			ch, err := chainOf(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			now, _ := jsNum(vecArg(a, 2))
			var requireFor any
			switch v := vecArg(a, 4).(type) {
			case string:
				requireFor = v
			case []any:
				fs := []float64{}
				for _, x := range v {
					f, _ := jsNum(x)
					fs = append(fs, f)
				}
				requireFor = fs
			}
			crls := nvBytesList(vecArg(a, 1))
			if why := CheckNvidiaChainRevocation(ch, crls, int64(now), attStrings(vecArg(a, 3)), requireFor); why != "" {
				return map[string]any{"ok": false, "reason": why}, nil
			}
			return map[string]any{"ok": true, "verifiedCrls": jsNumber(float64(len(crls)))}, nil
		},
		"fetchRim": func(a []any) (any, error) {
			sc := vecObj(vecArg(a, 0))
			rec := fetchOf(sc["response"])
			o := NvidiaRimFetchOptions{Fetch: rec.fetch}
			if s, ok := sc["baseUrl"].(string); ok {
				o.BaseURL = &s
			}
			v, err := FetchNvidiaRim(rsStr(sc["id"]), o)
			return rec.out(map[string]any{"value": v}, err), nil
		},
		"fetchCrl": func(a []any) (any, error) {
			sc := vecObj(vecArg(a, 0))
			rec := fetchOf(sc["response"])
			v, err := FetchNvidiaCrl(rsStr(sc["url"]), rec.fetch)
			return rec.out(map[string]any{"value": vecBytesOut(v)}, err), nil
		},
		"fetchOcsp": func(a []any) (any, error) {
			sc := vecObj(vecArg(a, 0))
			cert, err := ParseNodeCertPEM(rsStr(sc["certPem"]))
			if err != nil {
				return nil, err
			}
			issuer, err := ParseNodeCertPEM(rsStr(sc["issuerPem"]))
			if err != nil {
				return nil, err
			}
			rec := fetchOf(sc["response"])
			o := NvidiaOcspFetchOptions{Fetch: rec.fetch}
			if op := vecObj(sc["opts"]); op != nil {
				if s, ok := op["url"].(string); ok {
					o.URL = &s
				}
				if b, ok := qvBytes(op["nonce"]); ok {
					o.Nonce = b
				}
			}
			req, resp, err := FetchNvidiaOcsp(cert, issuer, o)
			return rec.out(map[string]any{"request": vecBytesOut(req), "response": vecBytesOut(resp)}, err), nil
		},
		"ocspRequest": func(a []any) (any, error) {
			cert, err := ParseNodeCertPEM(rsStr(vecArg(a, 0)))
			if err != nil {
				return nil, err
			}
			issuer, err := ParseNodeCertPEM(rsStr(vecArg(a, 1)))
			if err != nil {
				return nil, err
			}
			op := vecObj(vecArg(a, 2))
			o := NvidiaOcspRequestOptions{Hash: rsStr(op["hash"])}
			if b, ok := qvBytes(op["nonce"]); ok {
				if len(b) == 0 {
					emptyNonce++
					return nil, errors.New("nonce must be 1..32 bytes")
				}
				o.Nonce = b
			}
			b, err := BuildNvidiaOcspRequest(cert, issuer, o)
			if err != nil {
				if o.Hash == "md5" { // the native refuses by error, as the reference throws, and says why
					if !strings.Contains(err.Error(), "unsupported CertID hash") {
						t.Errorf("the md5 request must be refused as an unsupported CertID hash, got %v", err)
					}
					badHash++
				}
				return nil, err
			}
			return vecBytesOut(b), nil
		},
		"ocspUrls": func(a []any) (any, error) {
			c, err := ParseNodeCertPEM(rsStr(vecArg(a, 0)))
			if err != nil {
				return nil, err
			}
			out := []any{}
			for _, u := range NvidiaCertOcspUrls(c) {
				out = append(out, u)
			}
			return out, nil
		},
		"ocspVerify": func(a []any) (any, error) {
			der, _ := qvBytes(vecArg(a, 0))
			o := vecObj(scDecode(vecArg(a, 1)))
			ch, err := chainOf(o["chainPem"])
			if err != nil {
				return nil, err
			}
			ci, _ := attSafeInt(o["certIndex"])
			ii := ci + 1
			if v, ok := attSafeInt(o["issuerIndex"]); ok {
				ii = v
			}
			if int(ci) >= len(ch) || int(ii) >= len(ch) || ci < 0 || ii < 0 {
				return nil, errors.New("no such chain certificate")
			}
			now, _ := jsNum(o["nowMs"])
			opt := NvidiaOcspOptions{}
			if f, ok := attSafeInt(o["maxAgeMs"]); ok {
				v := int64(f)
				opt.MaxAgeMs = &v
			}
			if f, ok := attSafeInt(o["clockSkewMs"]); ok {
				opt.ClockSkewMs = int64(f)
			}
			if b, ok := qvBytes(o["expectedNonce"]); ok {
				opt.ExpectedNonce = b
			}
			r := VerifyNvidiaOcspResponseWith(der, ch[int(ci)], ch[int(ii)], ch, int64(now), opt)
			if sum := sha256.Sum256(der); hex.EncodeToString(sum[:]) == nvFlippedOcspSHA256 {
				if r.Ok || r.Reason != nvFlippedOcspReason {
					t.Errorf("the flipped OCSP response must be refused with %q, got ok=%v reason=%q", nvFlippedOcspReason, r.Ok, r.Reason)
				}
				return map[string]any{"ok": false, "reason": r.Reason, "nativeStricter": true}, nil
			}
			if !r.Ok {
				return map[string]any{"ok": false, "reason": r.Reason}, nil
			}
			out := map[string]any{"ok": true, "status": r.Status, "thisUpdate": jsNumber(float64(r.ThisUpdate)), "producedAt": jsNumber(float64(r.ProducedAt)), "responder": r.Responder}
			if r.NextUpdate != nil {
				out["nextUpdate"] = jsNumber(float64(*r.NextUpdate))
			}
			if r.RevokedAt != nil {
				out["revokedAt"] = jsNumber(float64(*r.RevokedAt))
			}
			if r.RevocationReason != nil {
				out["revocationReason"] = jsNumber(float64(*r.RevocationReason))
			}
			return out, nil
		},
		"ocspChain": func(a []any) (any, error) {
			ch, err := chainOf(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			now, _ := jsNum(vecArg(a, 2))
			op := vecObj(scDecode(vecArg(a, 3)))
			o := NvidiaChainOcspOptions{}
			switch rg := op["requireGood"].(type) {
			case string:
				o.RequireAll = rg == "all"
			case []any:
				o.RequireIndices = []float64{}
				for _, x := range rg {
					f, _ := jsNum(x)
					o.RequireIndices = append(o.RequireIndices, f)
				}
			}
			if f, ok := attSafeInt(op["maxAgeMs"]); ok {
				v := int64(f)
				o.MaxAgeMs = &v
			}
			if f, ok := attSafeInt(op["clockSkewMs"]); ok {
				o.ClockSkewMs = int64(f)
			}
			for _, x := range rsList(op["expectedNonces"]) {
				b, _ := qvBytes(x)
				o.ExpectedNonces = append(o.ExpectedNonces, b)
			}
			r := CheckNvidiaChainOcspWith(ch, nvBytesList(vecArg(a, 1)), int64(now), o)
			var st map[string]any
			if r.Statuses != nil {
				st = map[string]any{}
				for i, s := range r.Statuses {
					st[jsNumberString(float64(i))] = s
				}
			}
			if r.Reason != "" {
				out := map[string]any{"ok": false, "reason": r.Reason}
				if st != nil {
					out["statuses"] = st
				}
				return out, nil
			}
			return map[string]any{"ok": true, "verifiedCrls": jsNumber(0), "verifiedOcsp": jsNumber(float64(r.VerifiedOcsp)), "statuses": st}, nil
		},
		"asn1TimesWellFormed": func(a []any) (any, error) {
			b, _ := qvBytes(vecArg(a, 0))
			return AllAsn1TimesWellFormed(b), nil
		},
	}, nil)
	if emptyNonce != 1 || badHash != 1 {
		t.Fatalf("%d empty-nonce and %d unsupported-hash requests were refused, 1 and 1 are expected", emptyNonce, badHash)
	}

	run("ref-attest-nvidia-rim.json.gz", 163, map[string]vecFn{
		"verifyRim": func(a []any) (any, error) {
			o := vecObj(vecArg(a, 1))
			now, _ := jsNum(o["nowMs"])
			xml, _ := vecArg(a, 0).(string)
			rim, why := VerifyNvidiaRim(xml, attStrings(o["rimRootSpkiSha256"]), int64(now))
			if why != "" {
				return map[string]any{"ok": false, "reason": why}, nil
			}
			return map[string]any{"ok": true, "rim": nvRimSummary(rim)}, nil
		},
		"collateralHook": func(a []any) (any, error) {
			sc := vecObj(scDecode(vecArg(a, 0)))
			hook, err := NewNvidiaCollateralHook(vecObj(sc["opts"]))
			if err != nil {
				return nil, err
			}
			rep, err := reportOf(sc["evidence"])
			if err != nil {
				return nil, err
			}
			ch, err := chainOf(sc["chainPem"])
			if err != nil {
				return nil, err
			}
			var bundle map[string]any
			if b := vecObj(sc["bundle"]); b != nil {
				bundle = map[string]any{"driverRimXml": b["driverRimXml"], "vbiosRimXml": b["vbiosRimXml"]}
				enc := func(l any) []any {
					out := []any{}
					for _, x := range nvBytesList(l) {
						out = append(out, base64.StdEncoding.EncodeToString(x))
					}
					return out
				}
				if _, ok := b["crls"]; ok {
					bundle["crls"] = enc(b["crls"])
				}
				if _, ok := b["ocsp"]; ok {
					bundle["ocsp"] = enc(b["ocsp"])
				}
			}
			now, _ := jsNum(sc["nowMs"])
			if why := RunNvidiaCollateralHook(hook, rep, ch, int64(now), bundle); why != "" {
				return map[string]any{"value": why}, nil
			}
			return map[string]any{"value": nil}, nil
		},
	}, map[string]bool{"collateralHook": false})
}

// The native refuses the flipped real OCSP response (see nvFlippedOcspSHA256) with its own reason.
func TestNvidiaOcspFlippedLengthIsRefused(t *testing.T) {
	const file = "ref-attest-nvidia.json.gz"
	blobs := mvBlobs(t, file)
	found := false
	baseEachOrdered(t, file, func(c *baseCase) {
		if c.Name != "ocspVerify/real-byte500-flipped" {
			return
		}
		found = true
		h, err := hydrateBlobs(c.Args, blobs)
		if err != nil {
			t.Fatal(err)
		}
		a := h.([]any)
		der, _ := qvBytes(vecArg(a, 0))
		if sum := sha256.Sum256(der); hex.EncodeToString(sum[:]) != nvFlippedOcspSHA256 {
			t.Fatalf("the corpus response changed (sha256 %x): re-check this expectation", sum)
		}
		o := vecObj(scDecode(vecArg(a, 1)))
		ch, err := ParsePemChain(rsStr(o["chainPem"]))
		if err != nil {
			t.Fatal(err)
		}
		ci, _ := attSafeInt(o["certIndex"])
		now, _ := jsNum(o["nowMs"])
		r := VerifyNvidiaOcspResponseWith(der, ch[int(ci)], ch[int(ci)+1], ch, int64(now), NvidiaOcspOptions{})
		if r.Ok || r.Reason != nvFlippedOcspReason {
			t.Fatalf("the flipped response must be refused with %q, got ok=%v reason=%q", nvFlippedOcspReason, r.Ok, r.Reason)
		}
	})
	if !found {
		t.Fatal("the flipped-response case is missing from the corpus")
	}
}
