package pca

// SIEM export for PCA authorization decisions (port of the TypeScript @atlasauth/pca-siem): every PCA verify / deny becomes a
// security event in the schemas SIEMs already ingest (OCSF Authorize Session, ArcSight CEF, Elastic Common Schema), each citing the
// cryptographic proof (the PCActn digest and the leaf signature) and carrying the full delegation chain, and is shippable to any
// HEC / bulk / intake endpoint through a sink. Everything is pure and read-only over the decision record; nothing is re-authorized.
//
// FAIL-SAFE: shipping an event to a SIEM never panics or returns an error into the caller's authorization path. A sink failure is
// caught, reported through the optional OnError (itself guarded), dropped and returned as a result value.
//
// A decision record is a JSON object {pcactn, verify, decision?, now?, session?} (map[string]any / []any, numbers as json.Number
// or float64) with the member names of the reference, so a hostile shape is judged exactly as the reference judges it. The
// serializers are total over JSON data. The OCSF / ECS event objects come back as map[string]any; the Line of a SiemEvent keeps
// the reference's member order (JSON.stringify order), which a Go map cannot.
//
// shortcut: the ECS / OCSF objects returned as maps carry no member order; use SiemEvent.Line (or SiemFormatDecision) for it.
// shortcut: the proof digest of a record whose reference form carries an `undefined` member is a real digest here (JSON has no
// undefined); a record built by decoding JSON never has one.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// SiemSerializeOptions controls what the serializers put in an event. Signature is how much of the leaf signature to log:
// "prefix" (the default, and any other value: the first 16 UTF-16 units), "full" or "omit".
type SiemSerializeOptions struct {
	Signature string
}

// Event formats.
const (
	SiemFormatOCSF = "ocsf"
	SiemFormatCEF  = "cef"
	SiemFormatECS  = "ecs"
)

var siemSecurityChecks = []string{"wire", "version", "audience", "validity", "cap_chain", "plan_inclusion", "leaf_signature", "counter_format", "replay"}

// ---- small JS-semantics helpers ---------------------------------------------------------------------------------------

func siemGet(v any, k string) (any, bool) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, false
	}
	x, has := m[k]
	return x, has
}

// siemPath is v?.a?.b?.c over JSON values (a non-object link is undefined).
func siemPath(v any, keys ...string) (any, bool) {
	cur := v
	for _, k := range keys {
		x, has := siemGet(cur, k)
		if !has {
			return nil, false
		}
		cur = x
	}
	return cur, true
}

func siemStr(v any, fallback string) string {
	if s, ok := v.(string); ok && s != "" {
		return s
	}
	return fallback
}

func siemFinite(v any) (float64, bool) {
	f, ok := jsNum(v)
	if !ok || math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, false
	}
	return f, true
}

// siemNumStr is Number::toString with -0 printed "0" (what JSON.stringify and String() give).
func siemNumStr(f float64) string {
	if f == 0 {
		return "0"
	}
	return jsNumberString(f)
}

func siemNum(f float64) json.Number { return json.Number(siemNumStr(f)) }

func siemInt(i int) json.Number { return json.Number(strconv.Itoa(i)) }

// siemFromUnits builds a (WTF-8) string from UTF-16 code units: a lone surrogate keeps its 3-byte form.
func siemFromUnits(u []uint16) string {
	var sb strings.Builder
	for i := 0; i < len(u); i++ {
		c := rune(u[i])
		switch {
		case c >= 0xD800 && c < 0xDC00 && i+1 < len(u) && u[i+1] >= 0xDC00 && u[i+1] < 0xE000:
			sb.WriteRune(0x10000 + (c-0xD800)<<10 + (rune(u[i+1]) - 0xDC00))
			i++
		case c >= 0xD800 && c < 0xE000:
			sb.WriteByte(byte(0xE0 | c>>12))
			sb.WriteByte(byte(0x80 | (c>>6)&0x3f))
			sb.WriteByte(byte(0x80 | c&0x3f))
		default:
			sb.WriteRune(c)
		}
	}
	return sb.String()
}

// siemSlice is s.slice(0, n) by UTF-16 code units.
func siemSlice(s string, n int) string {
	u := utf16Units(s)
	if n >= len(u) {
		return s
	}
	return siemFromUnits(u[:n])
}

// siemShortKey abbreviates a long b64u key for display; a non-string or empty key is "(none)".
func siemShortKey(key string, defined bool) string {
	if !defined || key == "" {
		return "(none)"
	}
	if jsLen(key) <= 13 {
		return key
	}
	return siemSlice(key, 12) + "…"
}

// siemEntries is Object.entries over a JSON value (an array or a string has index keys; other values have none).
func siemEntries(v any) [][2]any {
	switch t := v.(type) {
	case map[string]any:
		var out [][2]any
		for _, k := range jsKeys(t) {
			out = append(out, [2]any{k, t[k]})
		}
		return out
	case []any:
		out := make([][2]any, 0, len(t))
		for i, x := range t {
			out = append(out, [2]any{strconv.Itoa(i), x})
		}
		return out
	case string:
		u := utf16Units(t)
		out := make([][2]any, 0, len(u))
		for i, c := range u {
			out = append(out, [2]any{strconv.Itoa(i), siemFromUnits([]uint16{c})})
		}
		return out
	}
	return nil
}

// siemISO is new Date(epochMs).toISOString(), or the epoch for a non-finite / out-of-range time.
func siemISO(f float64) string {
	if math.IsNaN(f) || math.IsInf(f, 0) || math.Abs(f) > 8.64e15 {
		f = 0
	}
	ms := int64(math.Trunc(f))
	days := ms / 86400000
	rem := ms % 86400000
	if rem < 0 {
		rem += 86400000
		days--
	}
	z := days + 719468
	era := z / 146097
	if z < 0 {
		era = (z - 146096) / 146097
	}
	doe := z - era*146097
	yoe := (doe - doe/1460 + doe/36524 - doe/146096) / 365
	y := yoe + era*400
	doy := doe - (365*yoe + yoe/4 - yoe/100)
	mp := (5*doy + 2) / 153
	d := doy - (153*mp+2)/5 + 1
	m := mp + 3
	if mp >= 10 {
		m = mp - 9
	}
	if m <= 2 {
		y++
	}
	var ys string
	if y >= 0 && y <= 9999 {
		ys = fmt.Sprintf("%04d", y)
	} else if y < 0 {
		ys = fmt.Sprintf("-%06d", -y)
	} else {
		ys = fmt.Sprintf("+%06d", y)
	}
	return fmt.Sprintf("%s-%02d-%02dT%02d:%02d:%02d.%03dZ", ys, m, d, rem/3600000, rem/60000%60, rem/1000%60, rem%1000)
}

// ---- ordered output tree and JSON.stringify -----------------------------------------------------------------------------

type siemObj struct {
	keys []string
	vals map[string]any
}

func siemNew() *siemObj { return &siemObj{vals: map[string]any{}} }

func (o *siemObj) put(k string, v any) *siemObj {
	if _, has := o.vals[k]; !has {
		o.keys = append(o.keys, k)
	}
	o.vals[k] = v
	return o
}

func (o *siemObj) putIf(ok bool, k string, v any) *siemObj {
	if ok {
		o.put(k, v)
	}
	return o
}

// siemPlain converts the ordered tree to plain maps and slices.
func siemPlain(v any) any {
	switch t := v.(type) {
	case *siemObj:
		m := make(map[string]any, len(t.vals))
		for k, x := range t.vals {
			m[k] = siemPlain(x)
		}
		return m
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = siemPlain(x)
		}
		return out
	}
	return v
}

func siemStrings(l []string) []any {
	out := make([]any, len(l))
	for i, s := range l {
		out[i] = s
	}
	return out
}

// siemQuote is JSON.stringify of a string: well-formed (a lone surrogate is \udXXX), U+2028 / U+2029 literal.
func siemQuote(sb *strings.Builder, s string) {
	const hexd = "0123456789abcdef"
	sb.WriteByte('"')
	for i := 0; i < len(s); {
		c := s[i]
		if c == 0xED && i+2 < len(s) && s[i+1] >= 0xA0 && s[i+1] <= 0xBF {
			u := 0xD000 | int(s[i+1]&0x3f)<<6 | int(s[i+2]&0x3f)
			sb.WriteString(`\u`)
			sb.WriteByte(hexd[u>>12&15])
			sb.WriteByte(hexd[u>>8&15])
			sb.WriteByte(hexd[u>>4&15])
			sb.WriteByte(hexd[u&15])
			i += 3
			continue
		}
		switch {
		case c == '"':
			sb.WriteString(`\"`)
		case c == '\\':
			sb.WriteString(`\\`)
		case c == '\b':
			sb.WriteString(`\b`)
		case c == '\f':
			sb.WriteString(`\f`)
		case c == '\n':
			sb.WriteString(`\n`)
		case c == '\r':
			sb.WriteString(`\r`)
		case c == '\t':
			sb.WriteString(`\t`)
		case c < 0x20:
			sb.WriteString(`\u00`)
			sb.WriteByte(hexd[c>>4])
			sb.WriteByte(hexd[c&15])
		case c < utf8.RuneSelf:
			sb.WriteByte(c)
		default:
			r, n := utf8.DecodeRuneInString(s[i:])
			if r == utf8.RuneError && n == 1 {
				sb.WriteString("�")
			} else {
				sb.WriteString(s[i : i+n])
			}
			i += n
			continue
		}
		i++
	}
	sb.WriteByte('"')
}

// siemStringify is JSON.stringify over the ordered tree and decoded JSON values (member order of a decoded object is its text order).
func siemStringify(sb *strings.Builder, v any) error {
	switch t := v.(type) {
	case nil:
		sb.WriteString("null")
	case bool:
		sb.WriteString(strconv.FormatBool(t))
	case string:
		siemQuote(sb, t)
	case json.Number, float64, int, int64:
		f, ok := jsNum(t)
		if !ok || math.IsNaN(f) || math.IsInf(f, 0) {
			sb.WriteString("null")
		} else {
			sb.WriteString(siemNumStr(f))
		}
	case []any:
		sb.WriteByte('[')
		for i, x := range t {
			if i > 0 {
				sb.WriteByte(',')
			}
			if err := siemStringify(sb, x); err != nil {
				return err
			}
		}
		sb.WriteByte(']')
	case *siemObj:
		sb.WriteByte('{')
		for i, k := range t.keys {
			if i > 0 {
				sb.WriteByte(',')
			}
			siemQuote(sb, k)
			sb.WriteByte(':')
			if err := siemStringify(sb, t.vals[k]); err != nil {
				return err
			}
		}
		sb.WriteByte('}')
	case map[string]any:
		sb.WriteByte('{')
		for i, k := range jsKeys(t) {
			if i > 0 {
				sb.WriteByte(',')
			}
			siemQuote(sb, k)
			sb.WriteByte(':')
			if err := siemStringify(sb, t[k]); err != nil {
				return err
			}
		}
		sb.WriteByte('}')
	default:
		return fmt.Errorf("siem: cannot serialize %T", v)
	}
	return nil
}

// ---- normalization --------------------------------------------------------------------------------------------------

type siemHop struct {
	index        int
	isRoot       bool
	issuer       string
	holder       string
	addedCaveats int
}

type siemNorm struct {
	now                float64
	outcome            string
	reason             string
	verifiable         bool
	checks             any
	agentHolder        string
	principal          string
	hasPrincipal       bool
	session            string
	hops               []siemHop
	depth              int
	chainString        string
	verb               string
	resource           string
	paramsDigest       string
	reversibilityClass string
	grantRef           string
	counter            float64
	nonce              string
	hasNonce           bool
	planRoot           string
	signatureSuite     string
	leafSignature      string
	proofDigest        string
	riskScore          float64
	hasRisk            bool
	tier               any
	hasTier            bool
	proofStrength      any
	hasProof           bool
	caution            float64
	hasCaution         bool
	bondRef            string
	hasBond            bool
	humanApproved      bool
	approvers          []string
	guardians          []string
	roles              []string
	sevID              int
	sevName            string
	sevCef             int
	iat                float64
	exp                float64
}

func siemFirstReasonOr(decision any, fallback string) string {
	rs, _ := siemGet(decision, "reasons")
	l, _ := rs.([]any)
	if len(l) > 0 {
		if s, ok := l[0].(string); ok && s != "" {
			return s
		}
	}
	return fallback
}

func siemResolveOutcome(verify, decision any) (string, string) {
	vm, isMap := verify.(map[string]any)
	if !jsTruthy(verify) || !isMap || vm["allow"] != true {
		r, _ := siemGet(verify, "reason")
		return "deny", siemStr(r, "proof failed verification")
	}
	if !jsTruthy(decision) {
		return "allow", "proof verified; no policy decision supplied"
	}
	admit, _ := siemGet(decision, "admit")
	if jsTruthy(admit) {
		return "allow", siemFirstReasonOr(decision, "auto-admitted within policy and budget")
	}
	rel, _ := siemGet(decision, "releaseGuardianShare")
	if jsTruthy(rel) {
		return "step-up", siemFirstReasonOr(decision, "policy satisfied but a co-signature is required")
	}
	return "deny", siemFirstReasonOr(decision, "policy did not release authority (default-deny)")
}

func siemNormalize(record any, serialize SiemSerializeOptions) (*siemNorm, error) {
	rec, ok := record.(map[string]any)
	if !ok {
		return nil, errors.New("siem: the decision record must be an object")
	}
	p, pHas := rec["pcactn"]
	var verify any = rec["verify"]
	if verify == nil {
		verify = map[string]any{"allow": false, "checks": map[string]any{}}
	}
	var checks any = map[string]any{}
	if c, has := siemGet(verify, "checks"); has && c != nil {
		checks = c
	}
	now := float64(time.Now().UnixMilli())
	if f, ok := siemFinite(rec["now"]); ok {
		now = f
	}
	cc, _ := siemGet(p, "cap_chain")
	chain, _ := cc.([]any)
	hops := make([]siemHop, 0, len(chain))
	for i, cp := range chain {
		if !jsTruthy(cp) {
			continue
		}
		parentLen := 0
		if i > 0 {
			if cv, _ := siemGet(chain[i-1], "caveats"); cv != nil {
				if l, ok := cv.([]any); ok {
					parentLen = len(l)
				}
			}
		}
		ownLen := 0
		if cv, _ := siemGet(cp, "caveats"); cv != nil {
			if l, ok := cv.([]any); ok {
				ownLen = len(l)
			}
		}
		added := ownLen
		if i != 0 {
			added = ownLen - parentLen
			if added < 0 {
				added = 0
			}
		}
		iss, _ := siemGet(cp, "issuer")
		hol, _ := siemGet(cp, "holder")
		hops = append(hops, siemHop{index: i, isRoot: i == 0, issuer: siemStr(iss, "(none)"), holder: siemStr(hol, "(none)"), addedCaveats: added})
	}
	var leaf, root any
	if len(chain) > 0 {
		leaf, root = chain[len(chain)-1], chain[0]
	}
	outcome, reason := siemResolveOutcome(verify, rec["decision"])
	dec := rec["decision"]
	tier, hasTier := siemPath(dec, "requiredThreshold", "t")
	proofStrength, hasProof := siemPath(dec, "requiredThreshold", "proof")
	rv, _ := siemPath(dec, "r")
	risk, hasRisk := siemFinite(rv)

	n := &siemNorm{now: now, outcome: outcome, reason: reason, checks: checks, hops: hops, tier: tier, hasTier: hasTier,
		proofStrength: proofStrength, hasProof: hasProof, riskScore: risk, hasRisk: hasRisk}
	wire, _ := siemGet(checks, "wire")
	ls, _ := siemGet(checks, "leaf_signature")
	n.verifiable = wire == "pass" && ls == "pass"

	// the threshold shares sit outside the signed body: report an approval only when a threshold verifier passed
	th, _ := siemGet(p, "threshold")
	thCheck, _ := siemGet(checks, "threshold")
	n.approvers, n.guardians, n.roles = []string{}, []string{}, []string{}
	if thCheck == "pass" {
		sh, _ := siemGet(th, "shares")
		if shares, ok := sh.([]any); ok {
			for _, s := range shares {
				role, ok := siemPathStr(s, "role")
				if !ok {
					continue
				}
				n.roles = append(n.roles, role)
				pk, pkOK := siemPathStr(s, "publicKey")
				if role == "principal" && pkOK {
					n.approvers = append(n.approvers, pk)
				}
				if role == "guardian" && pkOK {
					n.guardians = append(n.guardians, pk)
				}
			}
		}
		n.humanApproved = len(n.approvers) > 0
	}

	gr, _ := siemGet(p, "grant_ref")
	n.grantRef = siemStr(gr, "(none)")
	hol, _ := siemGet(leaf, "holder")
	n.agentHolder = siemStr(hol, "(none)")
	if iss, ok := siemPathStr(root, "issuer"); ok && iss != "" {
		n.principal, n.hasPrincipal = iss, true
	}
	parts := []string{"(principal?)"}
	if n.hasPrincipal {
		parts[0] = n.principal
	}
	for _, h := range hops {
		parts = append(parts, h.holder)
	}
	for i, k := range parts {
		parts[i] = siemShortKey(k, true)
	}
	n.chainString = strings.Join(parts, " -> ")
	if s, ok := siemFirstPathStr(rec["session"]); ok && s != "" {
		n.session = s
	} else {
		n.session = n.grantRef
	}
	if len(hops) > 0 {
		n.depth = len(hops) - 1
	}
	v, _ := siemPath(p, "action", "verb")
	n.verb = siemStr(v, "(unknown verb)")
	r, _ := siemPath(p, "action", "resource")
	n.resource = siemStr(r, "(unknown resource)")
	pd, _ := siemPath(p, "action", "params_digest")
	n.paramsDigest = siemStr(pd, "(none)")
	rc, _ := siemPath(p, "action", "reversibility_class")
	n.reversibilityClass = siemStr(rc, "(unknown)")
	cv, _ := siemGet(p, "counter")
	n.counter = -1
	if f, ok := siemFinite(cv); ok {
		n.counter = f
	}
	nv, _ := siemGet(p, "nonce")
	n.nonce, n.hasNonce = siemFirstPathStr(nv)
	pr, _ := siemPath(p, "plan", "root")
	n.planRoot = siemStr(pr, "(none)")
	alg, _ := siemGet(p, "alg")
	n.signatureSuite = siemStr(alg, "ed25519")
	sg, _ := siemGet(p, "sig")
	sig := siemStr(sg, "(unsigned)")
	switch serialize.Signature {
	case "full":
		n.leafSignature = sig
	case "omit":
		n.leafSignature = "(omitted)"
	default:
		if jsLen(sig) <= 16 {
			n.leafSignature = sig
		} else {
			n.leafSignature = siemSlice(sig, 16) + "…"
		}
	}
	n.proofDigest = "(undigestible)"
	if pHas {
		if d, err := HashCanonical(p); err == nil {
			n.proofDigest = d
		}
	}
	cn, _ := siemGet(p, "caution")
	n.caution, n.hasCaution = siemFinite(cn)
	bv, _ := siemGet(p, "bond_ref")
	n.bondRef, n.hasBond = siemFirstPathStr(bv)

	switch outcome {
	case "deny":
		n.sevID, n.sevName, n.sevCef = 3, "Medium", 5
		for _, k := range siemSecurityChecks {
			if c, _ := siemGet(checks, k); c == "fail" {
				n.sevID, n.sevName, n.sevCef = 4, "High", 8
				break
			}
		}
	case "step-up":
		n.sevID, n.sevName, n.sevCef = 3, "Medium", 5
	default:
		f, isNum := jsNum(tier)
		switch {
		case isNum && f == 3:
			n.sevID, n.sevName, n.sevCef = 3, "Medium", 5
		case isNum && f == 2:
			n.sevID, n.sevName, n.sevCef = 2, "Low", 3
		default:
			n.sevID, n.sevName, n.sevCef = 1, "Informational", 1
		}
	}
	n.iat, n.exp = now, now
	if f, ok := siemPathFinite(p, "iat"); ok {
		n.iat = f
	}
	if f, ok := siemPathFinite(p, "exp"); ok {
		n.exp = f
	}
	return n, nil
}

// siemPathStr is (v.k as a string): ok only for a string member of an object.
func siemPathStr(v any, k string) (string, bool) {
	x, _ := siemGet(v, k)
	s, ok := x.(string)
	return s, ok
}

func siemFirstPathStr(v any) (string, bool) {
	s, ok := v.(string)
	return s, ok
}

func siemPathFinite(v any, k string) (float64, bool) {
	x, _ := siemGet(v, k)
	return siemFinite(x)
}

func siemNarrative(n *siemNorm) string {
	word := "STEP-UP"
	switch n.outcome {
	case "allow":
		word = "ALLOWED"
	case "deny":
		word = "DENIED"
	}
	verif := "proof not cryptographically verifiable"
	if n.verifiable {
		verif = "cryptographically verifiable proof"
	}
	human := ""
	if n.humanApproved {
		human = "; human-signed step-up"
	}
	return fmt.Sprintf("Agent %s %s to %s on %s (%d-hop chain rooted at principal %s; %s%s). %s",
		siemShortKey(n.agentHolder, true), word, n.verb, n.resource, len(n.hops), siemShortKey(n.principal, n.hasPrincipal), verif, human, n.reason)
}

func siemHumanOverride(n *siemNorm) *siemObj {
	return siemNew().put("human_approved", true).put("approvers", siemStrings(n.approvers)).
		put("guardian_cosigners", siemStrings(n.guardians)).put("roles", siemStrings(n.roles))
}

// siemExtensions is the PCA-specific block every schema carries (the cryptographic edge).
func siemExtensions(n *siemNorm) *siemObj {
	chain := make([]any, 0, len(n.hops))
	for _, h := range n.hops {
		chain = append(chain, siemNew().put("index", siemInt(h.index)).put("is_root", h.isRoot).put("issuer", h.issuer).
			put("holder", h.holder).put("added_caveats", siemInt(h.addedCaveats)))
	}
	o := siemNew().put("proof_digest", n.proofDigest).put("leaf_signature", n.leafSignature).put("signature_suite", n.signatureSuite).
		put("cryptographically_verifiable", n.verifiable).put("plan_root", n.planRoot).put("params_digest", n.paramsDigest).
		put("grant_ref", n.grantRef).put("counter", siemNum(n.counter))
	o.putIf(n.hasNonce, "nonce", n.nonce)
	o.put("reversibility_class", n.reversibilityClass)
	o.putIf(n.hasRisk, "risk_score", siemNum(n.riskScore))
	o.putIf(n.hasTier, "risk_tier", n.tier)
	o.putIf(n.hasProof, "required_proof", n.proofStrength)
	o.putIf(n.hasCaution, "caution", siemNum(n.caution))
	o.putIf(n.hasBond, "bond_ref", n.bondRef)
	o.put("delegation_depth", siemInt(n.depth)).put("delegation_chain", chain).put("checks", n.checks)
	o.putIf(n.humanApproved, "human_override", siemHumanOverride(n))
	return o
}

// ---- OCSF -------------------------------------------------------------------------------------------------------------

func siemOcsfTree(n *siemNorm) *siemObj {
	actID, actName, actionID, action := 3, "Step-Up", 99, "Other"
	statusID, status, detail := 99, "Other", "step-up / co-signature required: "+n.reason
	switch n.outcome {
	case "allow":
		actID, actName, actionID, action = 1, "Allow", 1, "Allowed"
		statusID, status, detail = 1, "Success", n.reason
	case "deny":
		actID, actName, actionID, action = 2, "Deny", 2, "Denied"
		statusID, status, detail = 2, "Failure", n.reason
	}
	className := "Authorize Session"
	session := siemNew().put("uid", n.session)
	session.putIf(n.hasPrincipal, "issuer", n.principal)
	principalUID := "(none)"
	if n.hasPrincipal {
		principalUID = n.principal
	}
	actor := siemNew().
		put("user", siemNew().put("type_id", siemInt(99)).put("type", "Agent").put("uid", n.agentHolder).put("name", siemShortKey(n.agentHolder, true))).
		put("invoked_by", principalUID).put("session", session).put("app_name", "PCA")
	return siemNew().
		put("activity_id", siemInt(actID)).put("activity_name", actName).
		put("category_uid", siemInt(3)).put("category_name", "Identity & Access Management").
		put("class_uid", siemInt(3003)).put("class_name", className).
		put("type_uid", siemInt(3003*100+actID)).put("type_name", className+": "+actName).
		put("action_id", siemInt(actionID)).put("action", action).
		put("severity_id", siemInt(n.sevID)).put("severity", n.sevName).
		put("status_id", siemInt(statusID)).put("status", status).put("status_detail", detail).
		put("time", siemNum(n.iat)).
		put("actor", actor).
		put("user", siemNew().put("type_id", siemInt(1)).put("type", "User").put("uid", principalUID).put("name", siemShortKey(n.principal, n.hasPrincipal))).
		put("resources", []any{siemNew().put("type", "pca.resource").put("name", n.resource).put("uid", n.resource)}).
		put("api", siemNew().put("operation", n.verb).put("service", siemNew().put("name", "PCA"))).
		put("metadata", siemNew().put("version", "1.1.0").
			put("product", siemNew().put("name", "PCA").put("vendor_name", "Atlas").put("version", "1.1.0")).
			put("logged_time", siemNum(n.now)).put("uid", n.proofDigest).
			put("labels", []any{"pca", "outcome:" + n.outcome, "suite:" + n.signatureSuite})).
		put("observables", []any{
			siemNew().put("name", "actor.user.uid").put("type", "User Name").put("type_id", siemInt(4)).put("value", n.agentHolder),
			siemNew().put("name", "pca.proof.digest").put("type", "Hash").put("type_id", siemInt(8)).put("value", n.proofDigest),
			siemNew().put("name", "resources.uid").put("type", "Resource UID").put("type_id", siemInt(10)).put("value", n.resource),
		}).
		put("count", siemInt(1)).put("message", siemNarrative(n)).put("unmapped", siemExtensions(n))
}

// ---- CEF --------------------------------------------------------------------------------------------------------------

func siemCefHeaderEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `|`, `\|`)
	var sb strings.Builder
	prevNL := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\r' || c == '\n' {
			if !prevNL {
				sb.WriteByte(' ')
			}
			prevNL = true
			continue
		}
		prevNL = false
		sb.WriteByte(c)
	}
	return sb.String()
}

func siemCefExtEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `=`, `\=`)
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '\r':
			if i+1 < len(s) && s[i+1] == '\n' {
				i++
			}
			sb.WriteString(`\n`)
		case '\n':
			sb.WriteString(`\n`)
		default:
			sb.WriteByte(c)
		}
	}
	return sb.String()
}

func siemCefLine(record any, n *siemNorm) string {
	deviceVersion := "2"
	if v, _ := siemPath(record.(map[string]any)["pcactn"], "ver"); v != nil {
		if f, ok := siemFinite(v); ok {
			deviceVersion = siemNumStr(f)
		}
	}
	header := strings.Join([]string{
		"CEF:0",
		siemCefHeaderEscape("Atlas"),
		siemCefHeaderEscape("PCA"),
		siemCefHeaderEscape(deviceVersion),
		siemCefHeaderEscape("pca-authz-" + n.outcome),
		siemCefHeaderEscape("PCA authorization " + n.outcome + ": " + n.verb + " on " + n.resource),
		strconv.Itoa(n.sevCef),
	}, "|")
	principal := "(none)"
	if n.hasPrincipal {
		principal = n.principal
	}
	externalID := siemNumStr(n.counter)
	if n.hasNonce {
		externalID = n.nonce
	}
	proof := "n/a"
	if n.hasProof && n.proofStrength != nil {
		proof = jsValueString(n.proofStrength)
	}
	var checkParts []string
	for _, e := range siemEntries(n.checks) {
		checkParts = append(checkParts, e[0].(string)+":"+jsValueString(e[1]))
	}
	risk := ""
	if n.hasRisk {
		risk = siemNumStr(n.riskScore)
	}
	tier := ""
	if n.hasTier && n.tier != nil {
		tier = jsValueString(n.tier)
	}
	human := "false"
	if n.humanApproved {
		human = "true"
	}
	pairs := [][2]string{
		{"act", n.outcome}, {"outcome", n.outcome}, {"suser", principal}, {"suid", principal},
		{"duser", n.agentHolder}, {"duid", n.agentHolder}, {"destinationServiceName", n.verb},
		{"rt", siemNumStr(n.now)}, {"start", siemNumStr(n.iat)}, {"end", siemNumStr(n.exp)},
		{"externalId", externalID}, {"request", n.resource}, {"requestMethod", n.verb},
		{"cs1Label", "pcaProofDigest"}, {"cs1", n.proofDigest},
		{"cs2Label", "pcaDelegationChain"}, {"cs2", n.chainString},
		{"cs3Label", "pcaProofStrength"}, {"cs3", proof},
		{"cs4Label", "pcaSignatureSuite"}, {"cs4", n.signatureSuite},
		{"cs5Label", "pcaVerifyChecks"}, {"cs5", strings.Join(checkParts, ";")},
		{"cs6Label", "pcaGrantRef"}, {"cs6", n.grantRef},
		{"cn1Label", "pcaRiskScore"}, {"cn1", risk},
		{"cn2Label", "pcaDelegationDepth"}, {"cn2", strconv.Itoa(n.depth)},
		{"cn3Label", "pcaRiskTier"}, {"cn3", tier},
		{"flexString1Label", "pcaHumanApproved"}, {"flexString1", human},
		{"cat", "authorization"}, {"msg", n.reason},
	}
	ext := make([]string, 0, len(pairs))
	for _, p := range pairs {
		ext = append(ext, p[0]+"="+siemCefExtEscape(p[1]))
	}
	return header + "|" + strings.Join(ext, " ")
}

// ---- ECS --------------------------------------------------------------------------------------------------------------

func siemUnique(l []string) []any {
	out := []any{}
	seen := map[string]bool{}
	for _, s := range l {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func siemEcsTree(n *siemNorm) *siemObj {
	typ, outcome := "info", "unknown"
	switch n.outcome {
	case "allow":
		typ, outcome = "allowed", "success"
	case "deny":
		typ, outcome = "denied", "failure"
	}
	related := []string{n.agentHolder}
	if n.hasPrincipal {
		related = append(related, n.principal)
	}
	related = append(related, n.approvers...)
	principalUID := "(none)"
	if n.hasPrincipal {
		principalUID = n.principal
	}
	event := siemNew().put("kind", "event").put("category", []any{"iam"}).put("type", []any{typ}).put("action", n.verb).
		put("outcome", outcome).put("module", "pca").put("dataset", "pca.authorization").put("provider", "pca").
		put("id", n.proofDigest).put("severity", siemInt(n.sevCef)).put("reason", n.reason)
	event.putIf(n.hasRisk, "risk_score", siemNum(n.riskScore))
	proof := siemNew().put("digest", n.proofDigest).put("leaf_signature", n.leafSignature).put("signature_suite", n.signatureSuite).
		put("cryptographically_verifiable", n.verifiable).put("plan_root", n.planRoot).put("params_digest", n.paramsDigest)
	risk := siemNew()
	risk.putIf(n.hasRisk, "score", siemNum(n.riskScore))
	risk.putIf(n.hasTier, "tier", n.tier)
	risk.putIf(n.hasProof, "required_proof", n.proofStrength)
	risk.putIf(n.hasCaution, "caution", siemNum(n.caution))
	hops := make([]any, 0, len(n.hops))
	for _, h := range n.hops {
		hops = append(hops, siemNew().put("index", siemInt(h.index)).put("isRoot", h.isRoot).put("issuer", h.issuer).
			put("holder", h.holder).put("addedCaveats", siemInt(h.addedCaveats)))
	}
	pca := siemNew().put("outcome", n.outcome).put("proof", proof).put("risk", risk).
		put("delegation", siemNew().put("depth", siemInt(n.depth)).put("chain", n.chainString).put("hops", hops)).
		put("grant_ref", n.grantRef).put("counter", siemNum(n.counter))
	pca.putIf(n.hasNonce, "nonce", n.nonce)
	pca.put("reversibility_class", n.reversibilityClass)
	pca.putIf(n.hasBond, "bond_ref", n.bondRef)
	pca.put("checks", n.checks)
	pca.putIf(n.humanApproved, "human_override", siemHumanOverride(n))
	return siemNew().put("@timestamp", siemISO(n.iat)).put("ecs.version", "8.11.0").put("event", event).
		put("user", siemNew().put("id", n.agentHolder).put("name", siemShortKey(n.agentHolder, true)).put("roles", []any{"agent"}).
			put("effective", siemNew().put("id", principalUID).put("name", siemShortKey(n.principal, n.hasPrincipal)))).
		put("service", siemNew().put("name", "pca").put("type", "authorization")).
		put("related", siemNew().put("user", siemUnique(related)).put("hash", siemUnique([]string{n.proofDigest, n.leafSignature}))).
		put("message", siemNarrative(n)).put("pca", pca)
}

// ---- public mappers -------------------------------------------------------------------------------------------------

// SiemToOcsfEvent maps a decision record to an OCSF 1.x Authorize Session event (category 3, class 3003). activity_id carries the
// allow / deny / step-up disposition, action_id the canonical Allowed / Denied, `actor` names the agent AND the authorizing
// principal, and `unmapped` carries the proof digest, the risk tier and the delegation chain.
func SiemToOcsfEvent(record any, opts SiemSerializeOptions) (map[string]any, error) {
	n, err := siemNormalize(record, opts)
	if err != nil {
		return nil, err
	}
	return siemPlain(siemOcsfTree(n)).(map[string]any), nil
}

// SiemToCef maps a decision record to one ArcSight CEF line.
func SiemToCef(record any, opts SiemSerializeOptions) (string, error) {
	n, err := siemNormalize(record, opts)
	if err != nil {
		return "", err
	}
	return siemCefLine(record, n), nil
}

// SiemToEcs maps a decision record to an Elastic Common Schema event.
func SiemToEcs(record any, opts SiemSerializeOptions) (map[string]any, error) {
	n, err := siemNormalize(record, opts)
	if err != nil {
		return nil, err
	}
	return siemPlain(siemEcsTree(n)).(map[string]any), nil
}

// SiemEvent is one serialized event ready to ship: the structured object for OCSF / ECS (nil for CEF) and one line to POST
// (NDJSON for OCSF / ECS, the CEF line for CEF). Format is the requested format verbatim.
type SiemEvent struct {
	Format string
	Object map[string]any
	Line   string
}

// Map is the {format, object?, line} form of the event.
func (e SiemEvent) Map() map[string]any {
	m := map[string]any{"format": e.Format, "line": e.Line}
	if e.Object != nil {
		m["object"] = e.Object
	}
	return m
}

// SiemFormatDecision serializes a decision record into the given format ("cef", "ocsf"; any other value yields ECS).
func SiemFormatDecision(record any, format string, opts SiemSerializeOptions) (SiemEvent, error) {
	n, err := siemNormalize(record, opts)
	if err != nil {
		return SiemEvent{}, err
	}
	if format == SiemFormatCEF {
		return SiemEvent{Format: format, Line: siemCefLine(record, n)}, nil
	}
	var tree *siemObj
	if format == SiemFormatOCSF {
		tree = siemOcsfTree(n)
	} else {
		tree = siemEcsTree(n)
	}
	var sb strings.Builder
	if err := siemStringify(&sb, tree); err != nil {
		return SiemEvent{}, err
	}
	return SiemEvent{Format: format, Object: siemPlain(tree).(map[string]any), Line: sb.String()}, nil
}

// ---- scrubError -----------------------------------------------------------------------------------------------------

// siemWS is the JavaScript \s class (Go's \s is ASCII only).
const siemWS = `\x{9}\x{a}\x{b}\x{c}\x{d}\x{20}\x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}\x{feff}`

// siemCI spells a literal case-insensitively with ASCII-only folding (as the reference's non-unicode i flag does).
func siemCI(w string) string {
	var sb strings.Builder
	for _, c := range w {
		if c >= 'a' && c <= 'z' {
			sb.WriteString("[" + string(c) + strings.ToUpper(string(c)) + "]")
		} else {
			sb.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	return sb.String()
}

var (
	siemScrubURL    = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.-]*://)[^` + siemWS + `/@]*:[^` + siemWS + `/@]*@`)
	siemScrubAuth   = regexp.MustCompile(`\b(` + siemCI("authorization") + `["']?[` + siemWS + `]*[:=][` + siemWS + `]*)[^\n"']*`)
	siemScrubScheme = regexp.MustCompile(`\b(` + siemCI("bearer") + `|` + siemCI("basic") + `|` + siemCI("splunk") + `|` + siemCI("token") + `)[` + siemWS + `]+[\w.~+/=-]{6,}`)
	siemScrubPair   = regexp.MustCompile(`\b((?:` + siemCI("token") + `|` + siemCI("secret") + `|` + siemCI("password") + `|` + siemCI("passwd") + `|` + siemCI("pwd") +
		`|` + siemCI("api") + `[_-]?` + siemCI("key") + `|` + siemCI("dd-api-key") + `|` + siemCI("key") + `|` + siemCI("signature") + `|` + siemCI("sig") + `|` + siemCI("credential") +
		`)["']?[` + siemWS + `]*[:=][` + siemWS + `]*)("[^"]*"|'[^']*'|[^` + siemWS + `"'&,;]+)`)
	siemScrubRun = regexp.MustCompile(`[A-Za-z0-9_-]{32,}`)
)

// SiemScrubError removes credentials from an error message before it is returned or handed to OnError: URL userinfo, token= /
// key= style pairs, authorization values, bearer-style credentials and long token-like runs; the result is capped at 300
// UTF-16 units.
func SiemScrubError(message string) string {
	t := message
	t = siemScrubURL.ReplaceAllString(t, "${1}[redacted]@")
	t = siemScrubAuth.ReplaceAllString(t, "${1}[redacted]")
	t = siemScrubScheme.ReplaceAllString(t, "${1} [redacted]")
	t = siemScrubPair.ReplaceAllString(t, "${1}[redacted]")
	t = siemScrubRun.ReplaceAllString(t, "[redacted]")
	if jsLen(t) > 300 {
		return siemSlice(t, 300) + "..."
	}
	return t
}

// ---- sinks ------------------------------------------------------------------------------------------------------------

// SiemSinkResult is a delivery outcome; Error is nil unless the sink reported one.
type SiemSinkResult struct {
	OK    bool
	Error *string
}

// SiemSink is a pluggable SIEM destination. Format is the schema it expects; Deliver ships a batch of already-serialized events.
// A sink should not panic; the exporters guard against it regardless.
type SiemSink interface {
	Name() string
	Format() string
	Deliver(events []SiemEvent) SiemSinkResult
}

// SiemFetchInit is the request a SiemFetch sends.
type SiemFetchInit struct {
	Method  string
	Headers map[string]string
	Body    string
}

// SiemFetchResponse is the part of an HTTP response the sink reads.
type SiemFetchResponse struct {
	OK         bool
	Status     int
	StatusText string
}

// SiemFetch performs one HTTP request; it must honor ctx (the delivery timeout cancels it).
type SiemFetch func(ctx context.Context, url string, in SiemFetchInit) (SiemFetchResponse, error)

// SiemHttpSinkOptions configures SiemHttpSink. ContentType, Name and TimeoutMs are optional (nil = default: NDJSON for ocsf / ecs,
// text/plain for cef; "http:<format>"; 10000 ms, also used for a non-positive or non-finite value).
type SiemHttpSinkOptions struct {
	Format      string
	Headers     map[string]string
	Fetch       SiemFetch
	ContentType *string
	Name        *string
	TimeoutMs   *float64
	Serialize   SiemSerializeOptions
}

type siemHTTP struct {
	url  string
	opts SiemHttpSinkOptions
	name string
}

// SiemHttpSink is an HTTP sink that batches events into ONE POST: NDJSON for OCSF / ECS, the raw CEF lines for CEF (the body is
// the lines joined by newlines). Delivery NEVER panics and never returns an error: a network error, a timeout or a non-2xx status
// is a {OK: false, Error} result with credentials scrubbed.
func SiemHttpSink(url string, opts SiemHttpSinkOptions) SiemSink {
	name := "http:" + opts.Format
	if opts.Name != nil {
		name = *opts.Name
	}
	return &siemHTTP{url: url, opts: opts, name: name}
}

func (h *siemHTTP) Name() string   { return h.name }
func (h *siemHTTP) Format() string { return h.opts.Format }

func siemDefaultFetch(ctx context.Context, url string, in SiemFetchInit) (SiemFetchResponse, error) {
	req, err := http.NewRequestWithContext(ctx, in.Method, url, strings.NewReader(in.Body))
	if err != nil {
		return SiemFetchResponse{}, err
	}
	for k, v := range in.Headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return SiemFetchResponse{}, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	return SiemFetchResponse{OK: resp.StatusCode >= 200 && resp.StatusCode < 300, Status: resp.StatusCode, StatusText: http.StatusText(resp.StatusCode)}, nil
}

func siemFail(msg string) SiemSinkResult {
	s := SiemScrubError(msg)
	return SiemSinkResult{OK: false, Error: &s}
}

func (h *siemHTTP) Deliver(events []SiemEvent) SiemSinkResult {
	fetch := h.opts.Fetch
	if fetch == nil {
		fetch = siemDefaultFetch
	}
	lines := make([]string, 0, len(events))
	for _, e := range events {
		lines = append(lines, e.Line)
	}
	headers := map[string]string{}
	if h.opts.ContentType != nil {
		headers["content-type"] = *h.opts.ContentType
	} else {
		switch h.opts.Format {
		case SiemFormatOCSF, SiemFormatECS:
			headers["content-type"] = "application/x-ndjson"
		case SiemFormatCEF:
			headers["content-type"] = "text/plain; charset=utf-8"
		}
	}
	for k, v := range h.opts.Headers {
		headers[k] = v
	}
	timeout := 10000.0
	if h.opts.TimeoutMs != nil && !math.IsNaN(*h.opts.TimeoutMs) && !math.IsInf(*h.opts.TimeoutMs, 0) && *h.opts.TimeoutMs > 0 {
		timeout = *h.opts.TimeoutMs
	}
	if timeout > 1e12 {
		timeout = 1e12
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type outcome struct {
		resp SiemFetchResponse
		err  error
	}
	ch := make(chan outcome, 1)
	request := SiemFetchInit{Method: "POST", Headers: headers, Body: strings.Join(lines, "\n")}
	go func() {
		defer func() {
			if r := recover(); r != nil {
				ch <- outcome{err: fmt.Errorf("%v", r)}
			}
		}()
		resp, err := fetch(ctx, h.url, request)
		ch <- outcome{resp: resp, err: err}
	}()
	timer := time.NewTimer(time.Duration(timeout * float64(time.Millisecond)))
	defer timer.Stop()
	select {
	case o := <-ch:
		if o.err != nil {
			return siemFail(o.err.Error())
		}
		if o.resp.OK {
			return SiemSinkResult{OK: true}
		}
		msg := "HTTP " + strconv.Itoa(o.resp.Status)
		if o.resp.StatusText != "" {
			msg += " " + o.resp.StatusText
		}
		return siemFail(msg)
	case <-timer.C:
		cancel() // the timeout settles first; the aborted request's own failure must not win
		return SiemSinkResult{OK: false, Error: siemStrPtr("delivery timed out")}
	}
}

func siemStrPtr(s string) *string { return &s }

// SiemConsoleSinkOptions configures SiemConsoleSink: Format defaults to ocsf, Logger to printing the line, Name to console:<format>.
type SiemConsoleSinkOptions struct {
	Format string
	Logger func(line string)
	Name   *string
}

type siemConsole struct {
	format string
	logger func(string)
	name   string
}

// SiemConsoleSink writes each event's serialized line to a logger. Never panics: a panicking logger is a failed result.
func SiemConsoleSink(opts SiemConsoleSinkOptions) SiemSink {
	f := opts.Format
	if f == "" {
		f = SiemFormatOCSF
	}
	lg := opts.Logger
	if lg == nil {
		lg = func(line string) { fmt.Println(line) }
	}
	name := "console:" + f
	if opts.Name != nil {
		name = *opts.Name
	}
	return &siemConsole{format: f, logger: lg, name: name}
}

func (c *siemConsole) Name() string   { return c.name }
func (c *siemConsole) Format() string { return c.format }

func siemPanicMessage(r any) string {
	if e, ok := r.(error); ok {
		return e.Error()
	}
	return fmt.Sprint(r)
}

func (c *siemConsole) Deliver(events []SiemEvent) (res SiemSinkResult) {
	defer func() {
		if r := recover(); r != nil {
			res = siemFail(siemPanicMessage(r))
		}
	}()
	for _, e := range events {
		c.logger(e.Line)
	}
	return SiemSinkResult{OK: true}
}

// ---- export orchestration ---------------------------------------------------------------------------------------------

// SiemExportOptions configures the exporters. OnError is called (log + drop) when delivery fails; it is guarded so it can
// never panic back into the caller, and its error message is scrubbed of credentials.
type SiemExportOptions struct {
	OnError   func(err error, sink string, count int)
	Serialize SiemSerializeOptions
}

// SiemExportResult is the outcome of an export. Error is set (possibly empty) whenever OK is false; Skipped counts records that
// could not be serialized and were left out of the delivery.
type SiemExportResult struct {
	OK        bool
	Delivered int
	Format    string
	Error     string
	Skipped   int
}

func siemSafeOnError(opts SiemExportOptions, err error, sink string, count int) {
	if opts.OnError == nil {
		return
	}
	defer func() { _ = recover() }() // an OnError that panics must not escape: the auth path is never touched
	opts.OnError(err, sink, count)
}

// SiemExportDecision exports one decision to a sink. Fail-safe: see SiemExportBatch.
func SiemExportDecision(record any, sink SiemSink, opts SiemExportOptions) SiemExportResult {
	return SiemExportBatch([]any{record}, sink, opts)
}

// SiemExportBatch exports a batch of decisions to a sink in ONE delivery (serialized in the sink's format). Fail-safe: an error
// anywhere (serialization or delivery, including a sink that panics) is caught, reported through OnError and returned as a
// result, never raised. A record that cannot be serialized is skipped and reported; it does not take the others with it.
func SiemExportBatch(records []any, sink SiemSink, opts SiemExportOptions) (result SiemExportResult) {
	if sink == nil {
		siemSafeOnError(opts, errors.New(SiemScrubError("a sink is required")), "(unknown sink)", 0)
		return SiemExportResult{OK: false, Error: "a sink is required"}
	}
	format := sink.Format()
	count := 0
	defer func() {
		if r := recover(); r != nil {
			err := errors.New(SiemScrubError(siemPanicMessage(r)))
			siemSafeOnError(opts, err, sink.Name(), count)
			result = SiemExportResult{OK: false, Format: format, Error: err.Error()}
		}
	}()
	events := make([]SiemEvent, 0, len(records))
	skipped := 0
	for _, r := range records {
		e, err := SiemFormatDecision(r, format, opts.Serialize)
		if err != nil {
			skipped++
			siemSafeOnError(opts, errors.New(SiemScrubError("record could not be serialized: "+err.Error())), sink.Name(), 1)
			continue
		}
		events = append(events, e)
	}
	count = len(events)
	if len(events) == 0 && skipped > 0 {
		return SiemExportResult{OK: false, Format: format, Error: "no record could be serialized", Skipped: skipped}
	}
	res := sink.Deliver(events)
	if res.OK {
		return SiemExportResult{OK: true, Delivered: len(events), Format: format, Skipped: skipped}
	}
	msg := "sink reported a delivery failure"
	if res.Error != nil {
		msg = *res.Error
	}
	err := errors.New(SiemScrubError(msg))
	siemSafeOnError(opts, err, sink.Name(), len(events))
	return SiemExportResult{OK: false, Format: format, Error: err.Error(), Skipped: skipped}
}
