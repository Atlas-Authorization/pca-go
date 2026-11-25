package pca

// The Web Bot Auth key directory: the JWKS document, the well-known handler, the strict parse, signed directory responses
// (draft-meunier-http-message-signatures-directory section 5.2: RFC 9421 over `"@authority";req`, one signature per key, the
// keyid the RFC 7638 thumbprint of the signing key) and the fail-closed fetch. A client keeps only the keys that carry a valid
// signature.

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const wbaDirectoryLifetimeSec = 86400

var (
	wbaXRe         = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	wbaAuthorityRe = regexp.MustCompile(`^[a-z0-9.\-\[\]:]+$`)
	wbaDirEntryRe  = regexp.MustCompile(`^([a-z][a-z0-9_.*-]*)=\("@authority";req\)((?:;[a-z]+=(?:[0-9]+|"[A-Za-z0-9_.\-]*"))*)$`)
	wbaDirSigRe    = regexp.MustCompile(`^([a-z][a-z0-9_.*-]*)=:([A-Za-z0-9+/]+={0,2}):$`)
	wbaDigitsRe    = regexp.MustCompile(`^[0-9]+$`)
)

// WebBotAuthBuildKeyDirectory builds the JWKS for the agent's public keys: each input is {"publicKey": []byte, "keyid", "use",
// "nbf", "exp"}; the kid defaults to the RFC 7638 thumbprint. Members are written kty, crv, x, kid, use, nbf, exp.
func WebBotAuthBuildKeyDirectory(keys []any) (map[string]any, error) {
	entries := make([]any, 0, len(keys))
	for _, k := range keys {
		km, ok := k.(map[string]any)
		if !ok {
			return nil, errors.New("a directory key input must be an object")
		}
		pk, ok := km["publicKey"].([]byte)
		if !ok {
			return nil, errors.New("publicKey must be bytes")
		}
		var kid any = WebBotAuthJWKThumbprint(pk)
		if v := km["keyid"]; v != nil {
			kid = v
		}
		entry := map[string]any{"kty": "OKP", "crv": "Ed25519", "x": b64.EncodeToString(pk), "kid": kid}
		order := []string{"kty", "crv", "x", "kid"}
		for _, f := range []string{"use", "nbf", "exp"} {
			if v, has := km[f]; has {
				entry[f] = v
				order = append(order, f)
			}
		}
		recordKeyOrder(entry, order)
		entries = append(entries, entry)
	}
	return map[string]any{"keys": entries}, nil
}

// WebBotAuthResolveFromDirectory is the directory entry whose kid is keyid, or nil.
func WebBotAuthResolveFromDirectory(directory any, keyid string) (map[string]any, error) {
	dm, _ := directory.(map[string]any)
	keys, ok := dm["keys"].([]any)
	if !ok {
		return nil, errors.New("directory.keys.find is not a function")
	}
	for _, j := range keys {
		if j == nil {
			return nil, errors.New("Cannot read properties of null (reading 'kid')")
		}
		if m, ok := j.(map[string]any); ok && m["kid"] == keyid {
			return m, nil
		}
	}
	return nil, nil
}

// WebBotAuthDirectoryHandler is a framework-agnostic handler for the well-known directory path: the 200 response when the
// pathname (query cut off) is WebBotAuthWellKnownDirectoryPath, otherwise nil so a caller can fall through.
func WebBotAuthDirectoryHandler(keys []any) (func(pathname string) map[string]any, error) {
	dir, err := WebBotAuthBuildKeyDirectory(keys)
	if err != nil {
		return nil, err
	}
	var sb strings.Builder
	if err := agentcardStringify(&sb, dir); err != nil {
		return nil, err
	}
	body := sb.String()
	return func(pathname string) map[string]any {
		if path, _, _ := strings.Cut(pathname, "?"); path != WebBotAuthWellKnownDirectoryPath {
			return nil
		}
		return map[string]any{
			"status":  200,
			"headers": map[string]any{"content-type": WebBotAuthDirectoryContentType, "cache-control": "max-age=86400"},
			"body":    body,
		}
	}, nil
}

// WebBotAuthParseKeyDirectory strictly parses a directory document: every key must be a well-formed Ed25519 OKP JWK with a
// non-empty string kid and a 43-character x; a nbf or exp that is present must be a finite number. Anything else refuses.
func WebBotAuthParseKeyDirectory(text string) (map[string]any, error) {
	v, err := ParseNoDuplicates(text) // a repeated member is refused, naming it
	if err != nil {
		return nil, err
	}
	doc, _ := v.(map[string]any)
	keys, ok := doc["keys"].([]any)
	if !ok || len(keys) == 0 {
		return nil, errors.New("directory has no keys")
	}
	malformed := errors.New("directory contains a malformed key")
	for _, k := range keys {
		j, ok := k.(map[string]any)
		if !ok || j["kty"] != "OKP" || j["crv"] != "Ed25519" {
			return nil, malformed
		}
		if kid, ok := j["kid"].(string); !ok || kid == "" {
			return nil, malformed
		}
		if x, ok := j["x"].(string); !ok || !wbaXRe.MatchString(x) {
			return nil, malformed
		}
		for _, f := range []string{"nbf", "exp"} {
			if val, has := j[f]; has {
				if n, ok := jsNum(val); !ok || math.IsNaN(n) || math.IsInf(n, 0) {
					return nil, malformed
				}
			}
		}
	}
	return doc, nil
}

// WebBotAuthSignDirectory signs a directory response. input: keys (signing keys, one signature each: *KeyPair, a seed or
// {"secretKey": seed}), directory (as built by WebBotAuthBuildKeyDirectory; every signing key must be in it), authority (a
// lower-case host or host:port), created, expiresInSec. It returns the exact body to serve and the headers to send with it.
func WebBotAuthSignDirectory(input map[string]any) (map[string]any, error) {
	keys, ok := input["keys"].([]any)
	if !ok {
		return nil, errors.New("input.keys.length is not a number")
	}
	if len(keys) == 0 {
		return nil, errors.New("signDirectoryResponse: at least one signing key is required")
	}
	authority, ok := input["authority"].(string)
	if !ok || !wbaAuthorityRe.MatchString(authority) {
		return nil, errors.New("signDirectoryResponse: authority must be a lower-case host or host:port")
	}
	created, err := wbaNumber(input, "created", wbaNowSec())
	if err != nil {
		return nil, err
	}
	life, err := wbaNumber(input, "expiresInSec", wbaDirectoryLifetimeSec)
	if err != nil {
		return nil, err
	}
	expires := created + life
	var sb strings.Builder
	if err := agentcardStringify(&sb, input["directory"]); err != nil {
		return nil, err
	}
	dm, _ := input["directory"].(map[string]any)
	dirKeys, ok := dm["keys"].([]any)
	if !ok {
		return nil, errors.New("input.directory.keys.some is not a function")
	}
	var inputs, sigs []string
	for i, k := range keys {
		kp, err := wbaKeyPair(k)
		if err != nil {
			return nil, err
		}
		x := kp.Public
		inDir := false
		for _, j := range dirKeys {
			if j == nil {
				return nil, errors.New("Cannot read properties of null (reading 'x')")
			}
			if m, ok := j.(map[string]any); ok && m["x"] == x {
				inDir = true
				break
			}
		}
		if !inDir {
			return nil, errors.New("signDirectoryResponse: a signing key is not in the directory")
		}
		label := "sig" + strconv.Itoa(i+1)
		params := `("@authority";req);created=` + jsLenientNumber(created) + ";expires=" + jsLenientNumber(expires) +
			`;keyid="` + wbaThumbprintOfX(x) + `";alg="ed25519";tag="` + WebBotAuthDirectorySignatureTag + `"`
		base := `"@authority";req: ` + authority + "\n" + `"@signature-params": ` + params
		inputs = append(inputs, label+"="+params)
		sigs = append(sigs, label+"=:"+base64.StdEncoding.EncodeToString(kp.Sign(wbaUTF8(base)))+":")
	}
	return map[string]any{"body": sb.String(), "headers": map[string]any{
		"content-type": WebBotAuthDirectoryContentType, "signature-input": strings.Join(inputs, ", "), "signature": strings.Join(sigs, ", "),
	}}, nil
}

// WebBotAuthVerifyDirectory verifies a signed directory response. input: authority, headers (lower-case signature-input and
// signature), body, now, clockSkewSec, maxLifetimeSec. Fail closed: {"valid": false, "reason", "keys": []} unless at least one
// signature is valid; when valid, keys holds only the directory keys that carry a valid signature.
func WebBotAuthVerifyDirectory(input map[string]any) map[string]any {
	out, err := wbaVerifyDirectory(input)
	if err != nil {
		return wbaDirFail("verification failed (fail closed): " + err.Error())
	}
	return out
}

func wbaDirFail(reason string) map[string]any {
	return map[string]any{"valid": false, "reason": reason, "keys": []any{}}
}

func wbaVerifyDirectory(input map[string]any) (map[string]any, error) {
	hm, ok := input["headers"].(map[string]any)
	if !ok {
		return nil, errors.New("Cannot read properties of undefined (reading 'signature-input')")
	}
	siV, sgV := hm["signature-input"], hm["signature"]
	if !jsTruthy(siV) || !jsTruthy(sgV) {
		return wbaDirFail("missing signature-input or signature header"), nil
	}
	sigInput, ok1 := siV.(string)
	sigHeader, ok2 := sgV.(string)
	if !ok1 || !ok2 {
		return nil, errors.New("sigInput.split is not a function")
	}
	body, ok := input["body"].(string)
	if !ok {
		return nil, errors.New("directory has no keys")
	}
	dir, err := WebBotAuthParseKeyDirectory(body)
	if err != nil {
		return nil, err
	}
	sigs := map[string][]byte{}
	for _, part := range strings.Split(sigHeader, ", ") {
		m := wbaDirSigRe.FindStringSubmatch(part)
		if m == nil {
			return wbaDirFail("malformed signature header"), nil
		}
		sigs[m[1]] = wbaNodeB64(m[2])
	}
	now, err := wbaNumber(input, "now", wbaNowSec())
	if err != nil {
		return nil, err
	}
	skew, err := wbaNumber(input, "clockSkewSec", 0)
	if err != nil {
		return nil, err
	}
	maxLife, err := wbaNumber(input, "maxLifetimeSec", wbaDirectoryLifetimeSec)
	if err != nil {
		return nil, err
	}
	authority := jsValueString(input["authority"])

	var order []string
	good := map[string]any{}
	lastReason := "no signature entry"
	for _, raw := range strings.Split(sigInput, ", ") {
		m := wbaDirEntryRe.FindStringSubmatch(raw)
		if m == nil {
			lastReason = `malformed signature-input entry (must cover exactly "@authority";req)`
			continue
		}
		label := m[1]
		params := map[string]string{}
		dup := false
		for _, p := range strings.Split(m[2], ";")[1:] {
			eq := strings.IndexByte(p, '=')
			if _, has := params[p[:eq]]; has {
				dup = true
			}
			params[p[:eq]] = p[eq+1:]
		}
		if dup {
			lastReason = "duplicate signature parameter"
			continue
		}
		str := func(k string) (string, bool) {
			v, has := params[k]
			if !has || !strings.HasPrefix(v, `"`) {
				return "", false
			}
			return v[1 : len(v)-1], true
		}
		num := func(k string) (float64, bool) {
			v, has := params[k]
			if !has || !wbaDigitsRe.MatchString(v) {
				return 0, false
			}
			f, _ := strconv.ParseFloat(v, 64)
			return f, true
		}
		if tag, _ := str("tag"); tag != WebBotAuthDirectorySignatureTag {
			lastReason = "wrong tag"
			continue
		}
		if alg, has := params["alg"]; has && alg != `"ed25519"` {
			lastReason = "unsupported alg"
			continue
		}
		created, okC := num("created")
		expires, okE := num("expires")
		if !okC || !okE {
			lastReason = "created and expires are required"
			continue
		}
		if !(finite(now) && finite(skew) && created <= now+skew) {
			lastReason = "signature created-time is in the future"
			continue
		}
		if !(finite(now) && finite(skew) && now <= expires+skew) {
			lastReason = "signature has expired"
			continue
		}
		if !(expires-created <= maxLife) {
			lastReason = "signature lifetime exceeds maxLifetimeSec"
			continue
		}
		keyid, hasKeyid := str("keyid")
		if !hasKeyid {
			lastReason = "missing keyid"
			continue
		}
		var key map[string]any
		for _, k := range dir["keys"].([]any) {
			if km := k.(map[string]any); wbaThumbprintOfX(km["x"].(string)) == keyid {
				key = km
				break
			}
		}
		if key == nil {
			lastReason = "keyid is not the thumbprint of any directory key"
			continue
		}
		nbf, hasNbf := jsNum(key["nbf"])
		exp, hasExp := jsNum(key["exp"])
		if (hasNbf && !(finite(now) && finite(skew) && now+skew >= nbf)) || (hasExp && !(finite(now) && finite(skew) && now-skew <= exp)) {
			lastReason = "directory key is outside its validity window"
			continue
		}
		sig, has := sigs[label]
		if !has || len(sig) != 64 {
			lastReason = "no valid signature bytes for the label"
			continue
		}
		base := `"@authority";req: ` + authority + "\n" + `"@signature-params": ` + raw[len(label)+1:]
		if !wbaEdVerifyX(key["x"].(string), wbaUTF8(base), sig) {
			lastReason = "signature does not verify"
			continue
		}
		kid := jsValueString(key["kid"])
		if _, seen := good[kid]; !seen {
			order = append(order, kid)
		}
		good[kid] = key
	}
	if len(order) == 0 {
		return wbaDirFail(lastReason), nil
	}
	keys := make([]any, len(order))
	for i, kid := range order {
		keys[i] = good[kid]
	}
	return map[string]any{"valid": true, "keys": keys}, nil
}

// WebBotAuthFetchResponse is a directory fetch response; Headers are keyed by lower-case name.
type WebBotAuthFetchResponse struct {
	Status  int
	Headers map[string]string
	Body    string
}

// WebBotAuthFetchFunc fetches a URL. fetchInit carries redirect ("error": a redirect is an error), headers (the request headers),
// timeoutMs and maxBytes. Inject your own for SSRF-safe egress.
type WebBotAuthFetchFunc func(url string, fetchInit map[string]any) (*WebBotAuthFetchResponse, error)

func wbaDefaultFetch(url string, fetchInit map[string]any) (*WebBotAuthFetchResponse, error) {
	timeout := 5 * time.Second
	if t, ok := fetchInit["timeoutMs"].(float64); ok {
		timeout = time.Duration(t * float64(time.Millisecond))
	}
	client := &http.Client{Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("a directory redirect is refused")
	}}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if h, ok := fetchInit["headers"].(map[string]any); ok {
		for k, v := range h {
			req.Header.Set(k, fmt.Sprint(v))
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	limit := int64(65536)
	if m, ok := fetchInit["maxBytes"].(float64); ok && m >= 0 && m < 1<<40 {
		limit = int64(m)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit*3+4)) // a UTF-16 unit takes at most 3 UTF-8 bytes
	if err != nil {
		return nil, err
	}
	headers := map[string]string{}
	for k, v := range resp.Header {
		if len(v) > 0 {
			headers[strings.ToLower(k)] = v[0]
		}
	}
	return &WebBotAuthFetchResponse{Status: resp.StatusCode, Headers: headers, Body: string(data)}, nil
}

func wbaHeader(h map[string]string, name string) string {
	for k, v := range h {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

// WebBotAuthFetchKeyDirectory fetches and strictly parses a Web Bot Auth key directory. FAIL-CLOSED: it refuses a non-https URL,
// a redirect, a non-200 status, the wrong content type, an oversize body, invalid JSON, or any key that is not a well-formed
// Ed25519 OKP JWK; it never returns a partial directory. options: fetch (a WebBotAuthFetchFunc; default net/http), maxBytes
// (characters, default 65536), timeoutMs (default 5000), allowInsecureHttp, requireSignature (keep only the keys with a valid
// directory signature) and now.
func WebBotAuthFetchKeyDirectory(rawURL string, options map[string]any) (map[string]any, error) {
	u, err := whatwgParse(rawURL)
	if err != nil {
		return nil, errors.New("Invalid URL")
	}
	if insecure, _ := options["allowInsecureHttp"].(bool); u.scheme != "https" && !(insecure && u.scheme == "http") {
		return nil, errors.New("directory URL must be https")
	}
	parsed, err := wbaParseURL(rawURL)
	if err != nil {
		return nil, err
	}
	href, err := parsed.href()
	if err != nil {
		return nil, err
	}
	fetch := wbaDefaultFetch
	if f, ok := options["fetch"].(WebBotAuthFetchFunc); ok && f != nil {
		fetch = f
	}
	maxBytes, err := wbaNumber(options, "maxBytes", 65536)
	if err != nil {
		return nil, err
	}
	timeout, err := wbaNumber(options, "timeoutMs", 5000)
	if err != nil {
		return nil, err
	}
	res, err := fetch(href, map[string]any{
		"redirect": "error", "headers": map[string]any{"accept": WebBotAuthDirectoryContentType}, "timeoutMs": timeout, "maxBytes": maxBytes,
	})
	if err != nil {
		return nil, err
	}
	if res.Status != 200 {
		return nil, fmt.Errorf("directory fetch returned status %d", res.Status)
	}
	ct, _, _ := strings.Cut(wbaHeader(res.Headers, "content-type"), ";")
	if strings.ToLower(wbaTrim(ct)) != WebBotAuthDirectoryContentType {
		return nil, errors.New("directory has the wrong content type")
	}
	if float64(jsLen(res.Body)) > maxBytes {
		return nil, errors.New("directory response is too large")
	}
	directory, err := WebBotAuthParseKeyDirectory(res.Body)
	if err != nil {
		return nil, err
	}
	if sig, _ := options["requireSignature"].(bool); sig {
		in := map[string]any{
			"authority": strings.ToLower(u.host), "body": res.Body,
			"headers": map[string]any{"signature-input": wbaHeader(res.Headers, "signature-input"), "signature": wbaHeader(res.Headers, "signature")},
		}
		if n, has := options["now"]; has && n != nil {
			in["now"] = n
		}
		v := WebBotAuthVerifyDirectory(in)
		if v["valid"] != true {
			return nil, fmt.Errorf("directory signature: %v", v["reason"])
		}
		return map[string]any{"keys": v["keys"]}, nil
	}
	return directory, nil
}
