package pca

// Replay of the vendor attestation facades against the reference (ref-attest-vendors, 758 cases, 22 entries): the suite and pin
// constants, the DCAP quote and TD report parsers, the PCK extension reader and chain, the genuine-quote and collateral verifiers,
// CRL and signed-JSON checks, the Azure runtime-data binding, the MAA and Confidential Space token parsers, the x5c chain checks, the
// hardware-model mapper and both JWKS fetchers over a scripted transport (every requested URL is compared). Every function is
// replayed in full and the totals are pinned.
//
// A reason or throw text that comes from a library (OpenSSL "error:<8 hex>:" text, the JSON.parse messages, the P-256 library's point
// errors) is compared by presence; every other text exactly. A case whose certificate bytes are not DER at all only requires a
// refusal. No case is a counted deviation: the typed API expresses every input of the corpus (the legacy allowUnboundPq option does
// not exist here and the corpus has no case for it).

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"regexp"
	"strings"
	"testing"
)

const avFile = "ref-attest-vendors.json.gz"

var avTotals = map[string]int{"constants": 1, "toHex": 8, "pemToDer": 10, "ecdsaP256PublicKey": 12, "parseDcapTdReport": 11, "parseDcapQuote": 45,
	"extractPckFmspcAndTcb": 25, "verifyIntelPckChainX509": 46, "verifyGenuineTdxQuote": 64, "verifyCrl": 34, "serialIsRevoked": 10, "verifySignedJson": 31,
	"decodeIssuerChainHeader": 13, "verifyIntelTdxCollateral": 159, "checkAzureRuntimeDataBinding": 24, "parseMaaJwt": 57, "parseGcpCsJwt": 57,
	"verifyX5cChain": 61, "verifyJwkX5cChain": 27, "teeTypeOfHwModel": 15, "fetchMaaJwks": 22, "fetchGcpConfidentialSpaceJwks": 26}

var avLib = regexp.MustCompile(`error:[0-9A-Fa-f]{8}:|Unexpected token|Unexpected end of JSON input|bad point:|invalid Point, expected length|URI malformed`)

var avNotDer = []string{"malformed-certificate", "pem-malformed-block", "garbage"}

func avB(b []byte) map[string]any {
	return map[string]any{"$bytes": base64.RawURLEncoding.EncodeToString(b)}
}

// avResolve replaces every {"$blob": id} by the blob's string.
func avResolve(v any, blobs map[string]any) any {
	switch t := v.(type) {
	case map[string]any:
		if id, ok := t["$blob"].(string); ok && len(t) == 1 {
			return blobs[id]
		}
		m := make(map[string]any, len(t))
		for k, x := range t {
			m[k] = avResolve(x, blobs)
		}
		recordKeyOrder(m, jsKeys(t))
		return m
	case []any:
		a := make([]any, len(t))
		for i, x := range t {
			a[i] = avResolve(x, blobs)
		}
		return a
	}
	return v
}

func avStrs(v any) []string {
	l, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(l))
	for _, x := range l {
		s, _ := x.(string)
		out = append(out, s)
	}
	return out
}

func avList(v any) []any { l, _ := v.([]any); return l }

func avNow(m map[string]any) int64 { n, _ := baseI64(m["nowMs"]); return n }

func avPin(m map[string]any) string { return vecStr(m, "trustAnchorRootCaSpkiSha256") }

func avExpected(v any) *AttestationBinding {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	ep, isNum := jsNum(m["epoch"])
	if !isNum {
		ep = math.NaN()
	}
	return &AttestationBinding{HolderPub: vecStr(m, "holderPub"), GrantRef: vecStr(m, "grantRef"), Epoch: ep, Nonce: vecStr(m, "nonce")}
}

func avTdxPolicy(v any) *TdxQuotePolicy {
	p, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	var seams, signer []string
	if _, has := p["mrSeams"]; has {
		seams = avStrs(p["mrSeams"])
	}
	if _, has := p["mrSignerSeams"]; has {
		signer = avStrs(p["mrSignerSeams"])
	}
	return NewTdxQuotePolicy(avStrs(p["mrtds"]), avStrs(p["fmspcs"]), avStrs(p["rtmrs"]), seams, signer, p["allowDebug"] == true)
}

func avTdReport(r *DcapTdReport) map[string]any {
	return map[string]any{"teeTcbSvn": avB(r.TeeTcbSvn), "mrSeam": avB(r.MrSeam), "mrSignerSeam": avB(r.MrSignerSeam), "tdAttributes": avB(r.TdAttributes),
		"mrTd": avB(r.MrTd), "mrConfigId": avB(r.MrConfigId), "rtmr0": avB(r.Rtmr0), "rtmr1": avB(r.Rtmr1), "rtmr2": avB(r.Rtmr2), "rtmr3": avB(r.Rtmr3),
		"reportData": avB(r.ReportData), "raw": avB(r.Raw)}
}

func avPckTcb(t *PckTcb) map[string]any {
	return map[string]any{"fmspc": avB(t.fmspc), "sgxTcbComponents": avB(t.sgx), "pcesvn": t.pcesvn, "cpusvn": avB(t.cpusvn)}
}

func avRefusal(ok bool, reason string) map[string]any {
	out := map[string]any{"ok": ok}
	if reason != "" {
		out["reason"] = reason
	}
	return out
}

func avCollateral(v any) *IntelCollateral {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	txt := func(k string) string { // a JSON member is a string or bytes
		switch t := m[k].(type) {
		case string:
			return t
		case map[string]any:
			return string(baseBytes(t))
		}
		return ""
	}
	return NewIntelCollateral(txt("tcbInfoJson"), txt("tcbInfoIssuerChainPem"), txt("qeIdentityJson"), txt("qeIdentityIssuerChainPem"), baseBytes(m["pckCrlDer"]), baseBytes(m["rootCrlDer"]))
}

func avJwt(p *ParsedJwt, err error) (any, error) {
	if err != nil {
		return nil, err
	}
	h := map[string]any{"alg": p.Header.Alg}
	for k, v := range map[string]*string{"kid": p.Header.Kid, "jku": p.Header.Jku, "typ": p.Header.Typ} {
		if v != nil {
			h[k] = *v
		}
	}
	if p.Header.X5c != nil {
		h["x5c"] = p.Header.X5c
	}
	return map[string]any{"header": h, "payload": p.Payload, "signingInput": avB(p.SigningInput), "signature": avB(p.Signature)}, nil
}

// avTransport is the scripted transport of a fetch case: the i-th call gets script[min(i, last)].
func avTransport(a map[string]any, log *[]string) VendorFetch {
	script := avList(a["script"])
	i := 0
	return func(url string) (VendorFetchResponse, error) {
		*log = append(*log, url)
		r, _ := script[min(i, len(script)-1)].(map[string]any)
		i++
		if msg, has := r["$throws"]; has {
			return VendorFetchResponse{}, errors.New(msg.(string))
		}
		status := 200
		if s, ok := baseI64(r["status"]); ok {
			status = int(s)
		}
		if b, ok := r["body"].(map[string]any); ok {
			if raw, isText := b["$text"].(string); isText {
				return VendorFetchResponse{Status: status, Body: []byte(raw)}, nil
			}
		}
		body, _ := json.Marshal(r["body"])
		return VendorFetchResponse{Status: status, Body: body}, nil
	}
}

func avFetch(call func(a map[string]any, opts map[string]any, f VendorFetch) (any, error)) func(args []any) (any, error) {
	return func(args []any) (any, error) {
		a := vecObj(args[0])
		var log []string
		jwks, err := call(a, vecObj(a["opts"]), avTransport(a, &log))
		reqs := make([]any, len(log))
		for i, u := range log {
			reqs[i] = u
		}
		if err != nil {
			return map[string]any{"ok": false, "error": err.Error(), "requests": reqs}, nil
		}
		return map[string]any{"ok": true, "jwks": map[string]any{"keys": jwks}, "requests": reqs}, nil
	}
}

func avMember(out map[string]any, k string, v *string) {
	if v != nil {
		out[k] = *v
	}
}

var avHandlers = map[string]func(args []any) (any, error){
	"constants": func([]any) (any, error) { return VendorConstants(), nil },
	"toHex":     func(a []any) (any, error) { return ToHex(baseBytes(a[0])), nil },
	"pemToDer": func(a []any) (any, error) {
		der, err := PemToDer(a[0].(string))
		if err != nil {
			return nil, err
		}
		return avB(der), nil
	},
	"ecdsaP256PublicKey": func(a []any) (any, error) {
		pt, err := EcdsaP256PublicKey(baseBytes(a[0]))
		if err != nil {
			return nil, err
		}
		return map[string]any{"point": avB(pt)}, nil
	},
	"parseDcapTdReport": func(a []any) (any, error) {
		r, err := ParseDcapTdReport(baseBytes(a[0]))
		if err != nil {
			return nil, err
		}
		return avTdReport(r), nil
	},
	"parseDcapQuote": func(a []any) (any, error) {
		q, err := ParseDcapQuote(baseBytes(a[0]))
		if err != nil {
			return nil, err
		}
		return map[string]any{"version": q.version, "attKeyType": q.attKeyType, "teeType": q.teeType, "header": avB(q.header), "tdReportBody": avB(q.tdReportBody),
			"quoteSignature": avB(q.quoteSignature), "akPubRaw": avB(q.akPubRaw), "qeReportBody": avB(q.qeReportBody), "qeReportSignature": avB(q.qeReportSignature),
			"qeAuthData": avB(q.qeAuthData), "pckChainPem": q.pckChainPem}, nil
	},
	"extractPckFmspcAndTcb": func(a []any) (any, error) {
		t, err := ExtractPckFmspcAndTcb(baseBytes(a[0]))
		if err != nil {
			return nil, err
		}
		return avPckTcb(t), nil
	},
	"verifyIntelPckChainX509": func(a []any) (any, error) {
		o := vecObj(a[0])
		r := VerifyIntelPckChainX509(vecStr(o, "pckChainPem"), avPin(o), avNow(o))
		if !r.Ok {
			out := avRefusal(false, r.Reason)
			if r.Failure != "" {
				out["failure"] = r.Failure
			}
			return out, nil
		}
		return map[string]any{"ok": true, "leafKey": map[string]any{"point": avB(r.LeafPoint)}, "leafDer": avB(r.LeafDer), "depth": r.Depth}, nil
	},
	"verifyGenuineTdxQuote": func(a []any) (any, error) {
		o := vecObj(a[0])
		pin := avPin(o)
		if pin == "" {
			pin = intelSGXRootCASpkiSHA256
		}
		r := VerifyGenuineTdxQuoteBound(baseBytes(o["quote"]), pin, avNow(o), avTdxPolicy(o["policy"]), avExpected(o["expected"]), false)
		if !r.Ok {
			return avRefusal(false, r.Reason), nil
		}
		return map[string]any{"ok": true, "report": avTdReport(r.Report), "fmspc": r.Fmspc, "pckTcb": avPckTcb(r.Pck), "akPub": map[string]any{"point": avB(r.AkPoint)},
			"chainDepth": r.ChainDepth, "measured": newMeasured(ToHex(r.MrTd), "")}, nil
	},
	"verifyCrl": func(a []any) (any, error) {
		revoked, why := VerifyCrlSpki(baseBytes(a[0]), baseBytes(vecObj(a[1])["spkiDer"]), avNowArg(a[2]))
		if why != "" {
			return avRefusal(false, why), nil
		}
		return map[string]any{"ok": true, "revoked": revoked}, nil
	},
	"serialIsRevoked": func(a []any) (any, error) {
		set := map[string]bool{}
		for _, s := range avStrs(a[0]) {
			set[s] = true
		}
		return SerialIsRevoked(set, a[1].(string)), nil
	},
	"verifySignedJson": func(a []any) (any, error) {
		body, why := VerifySignedJsonSpki(a[0].(string), a[1].(string), baseBytes(vecObj(a[2])["spkiDer"]))
		if why != "" {
			return map[string]any{"error": why}, nil
		}
		return map[string]any{"body": body}, nil
	},
	"decodeIssuerChainHeader": func(a []any) (any, error) { return DecodeIssuerChainHeader(a[0].(string)) },
	"verifyIntelTdxCollateral": func(a []any) (any, error) {
		o := vecObj(a[0])
		var pol *CollateralPolicy
		if p, ok := o["policy"].(map[string]any); ok {
			var minEval *float64
			if f, isNum := jsNum(p["minTcbEvaluationDataNumber"]); isNum {
				minEval = &f
			}
			var accept []string
			if _, has := p["acceptStatuses"]; has {
				accept = avStrs(p["acceptStatuses"])
			}
			pol = NewCollateralPolicy(accept, minEval)
		}
		pin := avPin(o)
		if pin == "" {
			pin = intelSGXRootCASpkiSHA256
		}
		r := VerifyIntelTdxCollateral(baseBytes(o["quote"]), avCollateral(o["collateral"]), avNow(o), pol, pin, o["allowDebug"] == true)
		out := avRefusal(r.Ok, r.Reason)
		if r.Status != "" {
			ids := r.AdvisoryIDs
			if ids == nil {
				ids = []string{}
			}
			out["status"], out["platformStatus"], out["tdxModuleStatus"], out["qeStatus"] = r.Status, r.PlatformStatus, r.TdxModuleStatus, r.QeStatus
			out["advisoryIds"], out["tcbEvaluationDataNumber"], out["fmspc"] = ids, r.TcbEvaluationDataNumber, r.Fmspc
		}
		return out, nil
	},
	"checkAzureRuntimeDataBinding": func(a []any) (any, error) {
		exp := avExpected(a[2])
		if exp == nil {
			exp = &AttestationBinding{Epoch: math.NaN()}
		}
		if why := CheckAzureRuntimeDataBinding(baseBytes(a[0]), baseBytes(a[1]), *exp); why != "" {
			return why, nil
		}
		return nil, nil
	},
	"parseMaaJwt":   func(a []any) (any, error) { return avJwt(ParseMaaJwt(a[0].(string))) },
	"parseGcpCsJwt": func(a []any) (any, error) { return avJwt(ParseGcpCsJwt(a[0].(string))) },
	"verifyX5cChain": func(a []any) (any, error) {
		anchors, o := vecObj(a[1]), vecObj(a[2])
		skew, _ := jsNum(o["clockSkewMs"])
		r := VerifyX5cChain(avList(a[0]), avStrs(anchors["rootCertsPem"]), avStrs(anchors["rootSpkiSha256"]), avNow(o), skew)
		if !r.Ok {
			return avRefusal(false, r.Reason), nil
		}
		return map[string]any{"ok": true, "leafDer": avB(r.LeafDer), "leafSpkiSha256": r.LeafSpkiSha256}, nil
	},
	"verifyJwkX5cChain": func(a []any) (any, error) {
		anchors, o := vecObj(a[1]), vecObj(a[2])
		skew, _ := jsNum(o["skewMs"])
		if why := VerifyJwkX5cChain(avList(a[0]), avStrs(anchors["trustedKeySpki"]), avStrs(anchors["rootCertsPem"]), avNow(o), skew); why != "" {
			return why, nil
		}
		return nil, nil
	},
	"teeTypeOfHwModel": func(a []any) (any, error) {
		if t := TeeTypeOfHwModel(a[0].(string)); t != "" {
			return t, nil
		}
		return nil, nil
	},
	"fetchMaaJwks": avFetch(func(a, opts map[string]any, f VendorFetch) (any, error) {
		var path *string
		if p, ok := opts["certsPath"].(string); ok {
			path = &p
		}
		jwks, err := FetchMaaJwks(vecStr(a, "issuer"), f, path)
		if err != nil {
			return nil, err
		}
		keys := []any{}
		for _, k := range jwks.Keys {
			m := map[string]any{}
			avMember(m, "kid", k.Kid)
			avMember(m, "kty", k.Kty)
			avMember(m, "alg", k.Alg)
			if k.X5c != nil {
				m["x5c"] = k.X5c
			}
			keys = append(keys, m)
		}
		return keys, nil
	}),
	"fetchGcpConfidentialSpaceJwks": avFetch(func(a, opts map[string]any, f VendorFetch) (any, error) {
		jwks, err := FetchGcpConfidentialSpaceJwks(vecStr(a, "issuer"), f, vecStr(opts, "jwksUri"))
		if err != nil {
			return nil, err
		}
		keys := []any{}
		for _, k := range jwks {
			m := map[string]any{}
			for name, v := range map[string]*string{"kid": k.Kid, "kty": k.Kty, "alg": k.Alg, "use": k.Use, "n": k.N, "e": k.E, "crv": k.Crv, "x": k.X, "y": k.Y} {
				avMember(m, name, v)
			}
			if k.X5c != nil {
				m["x5c"] = k.X5c
			}
			keys = append(keys, m)
		}
		return keys, nil
	}),
}

func avNowArg(v any) int64 { n, _ := baseI64(v); return n }

// avEq compares the reference value with the native one (both normalized JSON): a library text by presence, everything else exactly.
func avEq(want, got any) bool {
	switch w := want.(type) {
	case map[string]any:
		g, ok := got.(map[string]any)
		if !ok || len(g) != len(w) {
			return false
		}
		for k, x := range w {
			y, has := g[k]
			if !has || !avEq(x, y) {
				return false
			}
		}
		return true
	case []any:
		g, ok := got.([]any)
		if !ok || len(g) != len(w) {
			return false
		}
		for i := range w {
			if !avEq(w[i], g[i]) {
				return false
			}
		}
		return true
	case string:
		if avLib.MatchString(w) {
			g, ok := got.(string)
			return ok && g != ""
		}
	}
	return baseCanon(want) == baseCanon(got)
}

// avSame is avEq for a whole result: a refusal whose reason is library text compares the other members and the presence of the reason.
func avSame(name string, want, got any) bool {
	w, wOk := want.(map[string]any)
	g, gOk := got.(map[string]any)
	if wOk && gOk {
		for _, m := range avNotDer {
			if strings.Contains(name, m) && w["ok"] == false {
				return g["ok"] == false
			}
		}
		if r, isStr := w["reason"].(string); isStr && avLib.MatchString(r) {
			rest := func(m map[string]any) map[string]any {
				c := map[string]any{}
				for k, v := range m {
					if k != "reason" {
						c[k] = v
					}
				}
				return c
			}
			gr, _ := g["reason"].(string)
			return gr != "" && avEq(rest(w), rest(g))
		}
	}
	return avEq(want, got)
}

func TestVendorAttestationFacadesMatchTheReference(t *testing.T) {
	blobs := mvBlobs(t, avFile)
	var k baseTally
	totals := map[string]int{}
	n := 0
	baseEach(t, avFile, func(c *baseCase) {
		h, ok := avHandlers[c.Fn]
		if !ok {
			k.fail(c, "no Go entry point for %s", c.Fn)
			return
		}
		n++
		totals[c.Fn]++
		k.run(c.Fn)
		args, _ := avResolve(c.Args, blobs).([]any)
		out := avResolve(c.Out, blobs)
		var got any
		var err error
		if p := baseCall(func() { got, err = h(args) }); p != "" {
			k.fail(c, "panic: %s", p)
			return
		}
		if throws, _ := baseThrows(out); throws {
			msg, _ := out.(map[string]any)["$throws"].(string)
			switch {
			case err == nil && vecEngineCrash(out) && vecRefusalValue(vecJSON(got)):
			case err == nil:
				k.fail(c, "reference refuses (%s), Go returned %s", msg, baseCanon(vecJSON(got)))
			case avLib.MatchString(msg):
				if err.Error() == "" {
					k.fail(c, "Go refuses with no text, reference: %s", msg)
				}
			case err.Error() != msg:
				k.fail(c, "reference refuses with %q, Go with %q", msg, err.Error())
			}
			return
		}
		if err != nil {
			k.fail(c, "Go refuses (%v), reference returned %s", err, baseCanon(out))
			return
		}
		if g := vecJSON(got); !avSame(c.Name, out, g) {
			k.fail(c, "want %s got %s", baseCanon(out), baseCanon(g))
		}
	})
	k.finish(t)
	if n != 758 {
		t.Fatalf("replayed %d cases, want 758", n)
	}
	for fn, want := range avTotals {
		if totals[fn] != want {
			t.Errorf("%s: %d cases replayed, want %d", fn, totals[fn], want)
		}
	}
	if len(totals) != len(avTotals) {
		t.Errorf("%d functions replayed, want %d", len(totals), len(avTotals))
	}
}
