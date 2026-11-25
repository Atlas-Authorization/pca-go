package pca

// A platform's own business rules for one action, written in plain terms (amount ceilings per currency, approval thresholds,
// "only the caller's own records", rate limits, business hours, allowed recipients, required fields) and COMPILED into tighten
// rules and count accumulators. Every compiled rule signals `escalate` or `deny`, never `allow`: a rule can only lower a
// decision. Anything the evaluator cannot decide (an absent caller attribute, an unknown currency, an unreadable clock, an unset
// count) fires the rule: fail closed. Definitions, rules and compiled forms are JSON values (map[string]any / []any).

import (
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	_ "time/tzdata" // the zone database travels with the binary
	"unicode/utf16"
)

// ActionRuleDays are the weekday names of an hours rule (index = day of week, 0 = Sunday).
var ActionRuleDays = []string{"sun", "mon", "tue", "wed", "thu", "fri", "sat"}

var rbRatePeriods = map[string]int64{"hour": 3_600_000, "day": 86_400_000}

const (
	rbMaxCurrencies = 32
	rbMaxList       = 64
	rbMaxApprovers  = 16
	rbMaxExamples   = 32

	// ActionBusinessRulesDomain separates the rules digest; ActionRulesReviewDomain the reviewer's signature.
	ActionBusinessRulesDomain = "atlas-pca/action-business-rules/v1"
	ActionRulesReviewDomain   = "atlas-pca/action-rules-review/v1"
	rbDefaultExampleAt        = "2026-01-07T15:00:00Z"
)

var (
	rbCcyRe     = regexp.MustCompile(`^[A-Z]{3}$`)
	rbNameRe    = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	rbHHMMRe    = regexp.MustCompile(`^([01][0-9]|2[0-3]):([0-5][0-9])$`)
	rbDomainRe  = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)
	rbAddressRe = regexp.MustCompile(`^[a-z0-9._%+-]{1,64}@[a-z0-9.-]{1,253}$`)
	rbDecRe     = regexp.MustCompile(`^(0|[1-9][0-9]{0,14})(?:\.([0-9]{1,6}))?$`)
	rbAtRe      = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)
	rbTzRe      = regexp.MustCompile(`^[A-Za-z0-9_+\-/]+$`)
	rbRuleKeys  = []string{"amount", "approval", "scope", "rate", "hours", "recipients", "required", "examples"}
)

// ---- refusals -------------------------------------------------------------------------------------------------------------

type rbBadErr struct{ msg string }

func rbBad(msg string) { panic(rbBadErr{msg}) }

// rbRun runs f. A bad_rules refusal gives (msg, true); any other panic (the reference's TypeError on a malformed value) gives
// (msg, false); no panic gives ("", false) and failed == false.
func rbRun(f func()) (msg string, isBad, failed bool) {
	defer func() {
		if r := recover(); r != nil {
			failed = true
			if b, ok := r.(rbBadErr); ok {
				msg, isBad = b.msg, true
			} else {
				msg = fmt.Sprint(r)
			}
		}
	}()
	f()
	return
}

// rbErr turns a refusal into an error: bad_rules carries the code, anything else is a plain error.
func rbErr(msg string, isBad bool) error {
	if isBad {
		return &CodedError{Code: "bad_rules", Msg: msg}
	}
	return errors.New(msg)
}

func rbObj(v any) (map[string]any, bool) { m, ok := v.(map[string]any); return m, ok }

func rbHas(m map[string]any, k string) bool { _, ok := m[k]; return ok }

func rbClosed(o map[string]any, allowed []string, at string) {
	for _, k := range jsKeys(o) {
		if !contains(allowed, k) {
			rbBad(at + ": unknown member '" + k + "'")
		}
	}
}

func rbTruthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case string:
		return t != ""
	}
	if f, ok := jsNum(v); ok {
		return f != 0 && !math.IsNaN(f)
	}
	return true
}

func rbSafeInt(v any) bool { return jsIsSafeInteger(v) }

// rbNonNegCount: a safe integer >= 0 that is not -0.
func rbNonNegCount(v any) bool { return jsIsNonNeg(v) }

func rbNum(v any) float64 { return jsF(v) }

func rbParams(d map[string]any) map[string]any {
	p, ok := d["params"].(map[string]any)
	if !ok {
		panic("params is not an object")
	}
	return p
}

func rbVerb(d map[string]any) string { return jsValueString(d["verb"]) }

func rbParamOf(d map[string]any, name string) map[string]any {
	p, _ := rbParams(d)[name].(map[string]any)
	return p
}

// ---- parameter references, money ------------------------------------------------------------------------------------------

func rbResolve(d map[string]any, rv any, at string) (string, map[string]any) {
	r, ok := rbObj(rv)
	if !ok {
		rbBad(at + ": name a parameter ({param} or {role})")
	}
	pn, hasP := r["param"].(string)
	_, hasR := r["role"].(string)
	if hasP == hasR {
		rbBad(at + ": give exactly one of param or role")
	}
	params := rbParams(d)
	if hasP {
		if _, has := params[pn]; !has {
			rbBad(at + ": '" + rbVerb(d) + "' has no parameter '" + pn + "'")
		}
		return pn, rbParamOf(d, pn)
	}
	var hits []string
	for n := range params {
		if jsStrictEq(rbParamOf(d, n)["role"], r["role"]) {
			hits = append(hits, n)
		}
	}
	adSortU16(hits)
	if len(hits) != 1 {
		what, plural := "several", "s"
		if len(hits) == 0 {
			what, plural = "no", ""
		}
		rbBad(at + ": '" + rbVerb(d) + "' has " + what + " parameter" + plural + " with role " + jsValueString(r["role"]))
	}
	return hits[0], rbParamOf(d, hits[0])
}

type rbMoney struct {
	amount string
	exp    float64
	expV   any
	lit    string
	param  string
	isParm bool
}

func rbMoneyOf(d map[string]any) rbMoney {
	params := rbParams(d)
	var hits []string
	for n := range params {
		if rbParamOf(d, n)["role"] == "money.amount" {
			hits = append(hits, n)
		}
	}
	adSortU16(hits)
	if len(hits) != 1 {
		rbBad("'" + rbVerb(d) + "' needs exactly one parameter with role money.amount for an amount or approval-above rule (has " + strconv.Itoa(len(hits)) + ")")
	}
	name := hits[0]
	p := rbParamOf(d, name)
	if p["type"] != "integer" {
		rbBad("'" + rbVerb(d) + "': the money.amount parameter '" + name + "' must be an integer")
	}
	u, isObj := rbObj(p["unit"])
	if !isObj || u["kind"] != "money" {
		rbBad("'" + rbVerb(d) + "': the amount parameter '" + name + "' declares no money unit (its currency)")
	}
	exp := rbNum(u["exp"])
	if s, ok := u["ccy"].(string); ok {
		return rbMoney{amount: name, exp: exp, expV: u["exp"], lit: s}
	}
	cm, ok := rbObj(u["ccy"])
	if !ok {
		panic("ccy is not an object")
	}
	from := jsValueString(cm["from"])
	if _, has := params[from]; !has {
		rbBad("'" + rbVerb(d) + "': the currency parameter '" + from + "' does not exist")
	}
	return rbMoney{amount: name, exp: exp, expV: u["exp"], param: from, isParm: true}
}

// ActionMoneyOf: the money parameters of an action: {amount, exp, ccy: {literal} | {param}}.
func ActionMoneyOf(d map[string]any) (res map[string]any, err error) {
	var m rbMoney
	if msg, bad, failed := rbRun(func() { m = rbMoneyOf(d) }); failed {
		return nil, rbErr(msg, bad)
	}
	ccy := map[string]any{"literal": m.lit}
	if m.isParm {
		ccy = map[string]any{"param": m.param}
	}
	return map[string]any{"amount": m.amount, "exp": m.expV, "ccy": ccy}, nil
}

func rbMinor(v any, exp float64, at string) int64 {
	if f, ok := jsNum(v); ok {
		if !rbSafeInt(v) || f < 0 || (f == 0 && math.Signbit(f)) {
			rbBad(at + ": an amount is a non-negative integer of minor units, or a decimal string")
		}
		return int64(f)
	}
	s, ok := v.(string)
	if !ok {
		rbBad(at + ": an amount is a number of minor units or a decimal string")
	}
	m := rbDecRe.FindStringSubmatch(s)
	if m == nil {
		rbBad(at + ": '" + s + "' is not a decimal amount")
	}
	frac := m[2]
	if float64(len(frac)) > exp {
		rbBad(at + ": '" + s + "' has more decimals than the currency's " + jsNumberString(exp))
	}
	pad := frac
	if !math.IsNaN(exp) {
		for len(pad) < int(exp) {
			pad += "0"
		}
	}
	if pad == "" {
		pad = "0"
	}
	ip, _ := strconv.ParseFloat(m[1], 64)
	fp, _ := strconv.ParseFloat(pad, 64)
	n := float64(ip*math.Pow(10, exp)) + fp
	if math.IsNaN(n) || n != math.Trunc(n) || math.Abs(n) > maxSafeInt {
		rbBad(at + ": '" + s + "' is too large")
	}
	return int64(n)
}

// ActionMinorUnits: integer minor units of a money value under exponent exp (a bad_rules error for a non-integer or over-precise one).
func ActionMinorUnits(v any, exp int, at string) (n int64, err error) {
	if msg, bad, failed := rbRun(func() { n = rbMinor(v, float64(exp), at) }); failed {
		return 0, rbErr(msg, bad)
	}
	return n, nil
}

func rbMins(hhmm string) int {
	h, _ := strconv.Atoi(hhmm[0:2])
	m, _ := strconv.Atoi(hhmm[3:5])
	return h*60 + m
}

// ---- time zones -----------------------------------------------------------------------------------------------------------

// shortcut: a name that differs only in case is matched by upper-casing the first letter of each word (america/new_york,
// utc), not by a scan of the whole database; upgrade if a zone with an odd capitalisation (e.g. Etc/GMT-14 variants) is needed.
func rbZone(tz string) *time.Location {
	if tz == "" || len(tz) > 64 || !rbTzRe.MatchString(tz) || strings.EqualFold(tz, "local") {
		return nil
	}
	if l, err := time.LoadLocation(tz); err == nil {
		return l
	}
	cands := []string{strings.ToUpper(tz)}
	var b strings.Builder
	up := true
	for _, c := range strings.ToLower(tz) {
		if up && c >= 'a' && c <= 'z' {
			c -= 'a' - 'A'
		}
		up = c == '/' || c == '_' || c == '-'
		b.WriteRune(c)
	}
	cands = append(cands, b.String())
	for _, c := range cands {
		if l, err := time.LoadLocation(c); err == nil {
			return l
		}
	}
	return nil
}

// ActionKnownTimeZone: is this a time zone the runtime knows (IANA name)?
func ActionKnownTimeZone(tz any) bool {
	s, ok := tz.(string)
	return ok && rbZone(s) != nil
}

// ActionClockAt is the day of week (0 = Sunday) and minute of day at now (ms since the epoch) in tz, or nil when it cannot be computed.
func ActionClockAt(now any, tz string) map[string]any {
	f, ok := jsNum(now)
	if !ok || math.IsNaN(f) || math.IsInf(f, 0) || math.Abs(f) > 8.64e15 {
		return nil
	}
	loc := rbZone(tz)
	if loc == nil {
		return nil
	}
	t := time.UnixMilli(int64(f)).In(loc)
	return map[string]any{"dow": jsNumber(float64(t.Weekday())), "min": jsNumber(float64(t.Hour()*60 + t.Minute()))}
}

func rbDaysFromCivil(y, m, d int) int64 {
	if m <= 2 {
		y--
	}
	era := y / 400
	if y < 0 {
		era = (y - 399) / 400
	}
	yoe := y - era*400
	mp := m - 3
	if m <= 2 {
		mp = m + 9
	}
	doy := (153*mp+2)/5 + d - 1
	doe := yoe*365 + yoe/4 - yoe/100 + doy
	return int64(era)*146097 + int64(doe) - 719468
}

// rbParseUTC is Date.parse of an RFC 3339 `...Z` second-precision time: day 1..31 rolls over the month, 24:00:00 is the next day.
func rbParseUTC(v any) (float64, bool) {
	s, ok := v.(string)
	if !ok || !rbAtRe.MatchString(s) {
		return 0, false
	}
	a := func(i, j int) int { n, _ := strconv.Atoi(s[i:j]); return n }
	y, mo, d, h, mi, se := a(0, 4), a(5, 7), a(8, 10), a(11, 13), a(14, 16), a(17, 19)
	if mo < 1 || mo > 12 || d < 1 || d > 31 || mi > 59 || se > 59 || (h > 24 || (h == 24 && (mi != 0 || se != 0))) {
		return 0, false
	}
	return float64((rbDaysFromCivil(y, mo, 1)+int64(d)-1)*86_400_000 + int64(h)*3_600_000 + int64(mi)*60_000 + int64(se)*1000), true
}

// ---- validation -----------------------------------------------------------------------------------------------------------

// ActionBusinessRulesError is "" iff rules is a well-formed rules block for d (closed members, every reference resolves to a
// parameter of the right kind, every amount integral in the currency's exponent, every list bounded); the reason otherwise.
func ActionBusinessRulesError(d map[string]any, rules any) string {
	msg, _, failed := rbRun(func() { rbValidate(d, rules) })
	if failed && msg == "" {
		return "malformed rules"
	}
	return msg
}

func rbCcyMap(d map[string]any, mv any, at string) {
	m, ok := rbObj(mv)
	if !ok || len(m) == 0 || len(m) > rbMaxCurrencies {
		rbBad(at + ": a map of 1.." + strconv.Itoa(rbMaxCurrencies) + " currencies to amounts")
	}
	money := rbMoneyOf(d)
	for _, c := range jsKeys(m) {
		if !rbCcyRe.MatchString(c) {
			rbBad(at + ": '" + c + "' is not an ISO 4217 currency code")
		}
		rbMinor(m[c], money.exp, at+"."+c)
	}
}

func rbRef(s map[string]any) map[string]any {
	ref := map[string]any{}
	for _, k := range []string{"param", "role"} {
		if v, has := s[k]; has {
			ref[k] = v
		}
	}
	return ref
}

func rbDistinct(xs []any) bool {
	for i := range xs {
		for j := 0; j < i; j++ {
			if jsStrictEq(xs[i], xs[j]) {
				return false
			}
		}
	}
	return true
}

func rbValidate(d map[string]any, rulesV any) {
	r, ok := rbObj(rulesV)
	if !ok {
		rbBad("rules must be an object")
	}
	rbClosed(r, rbRuleKeys, "rules")
	named := 0
	for k := range r {
		if k != "examples" {
			named++
		}
	}
	if named == 0 {
		rbBad("rules: name at least one rule")
	}
	if rbHas(r, "amount") {
		a, ok := rbObj(r["amount"])
		if !ok {
			rbBad("rules.amount must be {max: {CCY: amount}}")
		}
		rbClosed(a, []string{"max"}, "rules.amount")
		rbCcyMap(d, a["max"], "rules.amount.max")
	}
	if rbHas(r, "approval") {
		ap, ok := rbObj(r["approval"])
		if !ok {
			rbBad("rules.approval must be an object")
		}
		rbClosed(ap, []string{"above", "always", "approvers", "group"}, "rules.approval")
		if rbHas(ap, "always") && ap["always"] != true {
			rbBad("rules.approval.always is true or absent")
		}
		if rbHas(ap, "above") == rbHas(ap, "always") {
			rbBad("rules.approval: give exactly one of above or always")
		}
		if rbHas(ap, "above") {
			rbCcyMap(d, ap["above"], "rules.approval.above")
		}
		if rbHas(ap, "approvers") {
			if f := rbNum(ap["approvers"]); !rbSafeInt(ap["approvers"]) || f < 1 || f > rbMaxApprovers {
				rbBad("rules.approval.approvers is 1.." + strconv.Itoa(rbMaxApprovers))
			}
		}
		if rbHas(ap, "group") {
			if g, ok := ap["group"].(string); !ok || !rbNameRe.MatchString(g) {
				rbBad("rules.approval.group is a lowercase name")
			}
		}
	}
	if rbHas(r, "scope") {
		sc, ok := r["scope"].([]any)
		if !ok || len(sc) == 0 || len(sc) > rbMaxList {
			rbBad("rules.scope is a list of 1.." + strconv.Itoa(rbMaxList) + " bindings")
		}
		for i, s0 := range sc {
			at := "rules.scope[" + strconv.Itoa(i) + "]"
			s, ok := rbObj(s0)
			if !ok {
				rbBad(at + " must be an object")
			}
			rbClosed(s, []string{"param", "role", "caller"}, at)
			_, p := rbResolve(d, rbRef(s), at)
			if p["type"] != "string" && p["type"] != "integer" {
				rbBad(at + ": the bound parameter must be a string or integer id")
			}
			if c, ok := s["caller"].(string); !ok || !rbNameRe.MatchString(c) {
				rbBad(at + ".caller is a lowercase attribute name of the caller")
			}
		}
	}
	if rbHas(r, "rate") {
		rt, ok := r["rate"].([]any)
		if !ok || len(rt) == 0 || len(rt) > 4 {
			rbBad("rules.rate is a list of 1..4 limits")
		}
		for i, x0 := range rt {
			at := "rules.rate[" + strconv.Itoa(i) + "]"
			x, ok := rbObj(x0)
			if !ok {
				rbBad(at + " must be an object")
			}
			rbClosed(x, []string{"max", "per", "by"}, at)
			if f := rbNum(x["max"]); !rbSafeInt(x["max"]) || f < 1 || f > 1_000_000 {
				rbBad(at + ".max is 1..1000000")
			}
			if per, ok := x["per"].(string); !ok || rbRatePeriods[per] == 0 {
				rbBad(at + ".per is hour or day")
			}
			if rbHas(x, "by") && x["by"] != "principal" && x["by"] != "org" {
				rbBad(at + ".by is principal or org")
			}
		}
	}
	if rbHas(r, "hours") {
		h, ok := rbObj(r["hours"])
		if !ok {
			rbBad("rules.hours must be an object")
		}
		rbClosed(h, []string{"days", "from", "to", "tz", "outside"}, "rules.hours")
		days, ok := h["days"].([]any)
		okDays := ok && len(days) > 0 && rbDistinct(days)
		for _, x := range days {
			if s, isS := x.(string); !isS || !contains(ActionRuleDays, s) {
				okDays = false
			}
		}
		if !okDays {
			rbBad("rules.hours.days is a list of distinct days (" + strings.Join(ActionRuleDays, ", ") + ")")
		}
		from, fok := h["from"].(string)
		to, tok := h["to"].(string)
		if !fok || !rbHHMMRe.MatchString(from) || !tok || !rbHHMMRe.MatchString(to) {
			rbBad("rules.hours.from and .to are HH:MM (24 h)")
		}
		if !ActionKnownTimeZone(h["tz"]) {
			rbBad("rules.hours.tz '" + jsMemberString(h, "tz") + "' is not a known IANA time zone")
		}
		if rbHas(h, "outside") && h["outside"] != "escalate" && h["outside"] != "deny" {
			rbBad("rules.hours.outside is escalate or deny")
		}
	}
	if rbHas(r, "recipients") {
		x, ok := rbObj(r["recipients"])
		if !ok {
			rbBad("rules.recipients must be an object")
		}
		rbClosed(x, []string{"param", "role", "domains", "addresses"}, "rules.recipients")
		name, p := rbResolve(d, rbRef(x), "rules.recipients")
		if p["type"] == "array" || p["type"] == "set" {
			if it, has := p["items"]; has && it != "string" {
				rbBad("rules.recipients: '" + name + "' must hold strings")
			}
			if mi := p["max_items"]; !rbSafeInt(mi) || rbNum(mi) > rbMaxList || (rbNum(mi) == 0 && math.Signbit(rbNum(mi))) {
				rbBad("rules.recipients: the list parameter '" + name + "' needs max_items <= " + strconv.Itoa(rbMaxList) + " so every entry can be checked")
			}
		} else if p["type"] != "string" {
			rbBad("rules.recipients: '" + name + "' must be a string or a bounded list of strings")
		}
		if !rbHas(x, "domains") && !rbHas(x, "addresses") {
			rbBad("rules.recipients: give domains and/or addresses")
		}
		if rbHas(x, "domains") && !rbStrList(x["domains"], func(s string) bool { return len(s) >= 1 && len(s) <= 253 && rbDomainRe.MatchString(s) }) {
			rbBad("rules.recipients.domains is a list of lowercase domain names")
		}
		if rbHas(x, "addresses") && !rbStrList(x["addresses"], rbAddressRe.MatchString) {
			rbBad("rules.recipients.addresses is a list of lowercase email addresses")
		}
	}
	if rbHas(r, "required") {
		rq, ok := r["required"].([]any)
		if !ok || len(rq) == 0 || len(rq) > rbMaxList || !rbDistinct(rq) {
			rbBad("rules.required is a list of distinct parameter names")
		}
		params := rbParams(d)
		for _, n := range rq {
			if s, ok := n.(string); !ok || !rbHas(params, s) {
				rbBad("rules.required: '" + rbVerb(d) + "' has no parameter '" + jsValueString(n) + "'")
			}
		}
	}
	if rbHas(r, "examples") {
		ex, ok := r["examples"].([]any)
		if !ok || len(ex) > rbMaxExamples {
			rbBad("rules.examples is a list of at most " + strconv.Itoa(rbMaxExamples))
		}
		for i, e0 := range ex {
			at := "rules.examples[" + strconv.Itoa(i) + "]"
			e, ok := rbObj(e0)
			if !ok {
				rbBad(at + " must be an object")
			}
			rbClosed(e, []string{"params", "caller", "at", "recent", "expect"}, at)
			if _, ok := rbObj(e["params"]); !ok {
				rbBad(at + ".params must be an object")
			}
			if rbHas(e, "caller") {
				if _, ok := rbObj(e["caller"]); !ok {
					rbBad(at + ".caller must be an object")
				}
			}
			if rbHas(e, "at") {
				if _, ok := rbParseUTC(e["at"]); !ok {
					rbBad(at + ".at is an RFC 3339 UTC time (…Z)")
				}
			}
			if rbHas(e, "recent") {
				rc, ok := rbObj(e["recent"])
				good := ok
				for _, n := range rc {
					if !rbNonNegCount(n) {
						good = false
					}
				}
				if !good {
					rbBad(at + ".recent maps rate indexes to counts")
				}
			}
			if x := e["expect"]; x != "allow" && x != "escalate" && x != "deny" {
				rbBad(at + ".expect is allow, escalate or deny")
			}
		}
	}
}

func rbStrList(v any, ok func(string) bool) bool {
	xs, isL := v.([]any)
	if !isL || len(xs) == 0 || len(xs) > rbMaxList {
		return false
	}
	for _, x := range xs {
		if s, isS := x.(string); !isS || !ok(s) {
			return false
		}
	}
	return true
}

// ---- compiled form --------------------------------------------------------------------------------------------------------

// ActionBusinessRulesDigest is the digest of a rules block (examples are tests, not rules).
func ActionBusinessRulesDigest(verb string, rules map[string]any) (string, error) {
	body := map[string]any{}
	for k, v := range rules {
		if k != "examples" {
			body[k] = v
		}
	}
	return HashCanonical(map[string]any{"d": ActionBusinessRulesDomain, "verb": verb, "rules": body})
}

func rbP(n string) string { return "action.params." + n }

func rbCcyCond(m rbMoney, c string) any {
	if m.isParm {
		return map[string]any{"field": rbP(m.param), "op": "eq", "value": c}
	}
	if m.lit == c {
		return nil
	}
	return map[string]any{"field": "action.verb", "op": "eq", "value": "\u0000never"}
}

func rbAnd(cs ...any) any {
	xs := []any{}
	for _, c := range cs {
		if c != nil {
			xs = append(xs, c)
		}
	}
	if len(xs) == 1 {
		return xs[0]
	}
	return map[string]any{"all_of": xs}
}

func rbAlways(verb string) any {
	return map[string]any{"field": "action.verb", "op": "eq", "value": verb}
}

func rbRuleID(s string) string {
	var b strings.Builder
	for _, c := range strings.ToLower(s) {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' {
			b.WriteRune(c)
		} else {
			b.WriteByte('_')
		}
	}
	u := utf16Units(b.String())
	if len(u) > 64 {
		u = u[:64]
	}
	return string(utf16.Decode(u))
}

func rbRule(id string, when any, signal, reason string) any {
	return map[string]any{"id": id, "when": when, "signal": signal, "reason": reason}
}

// ActionFormatMoney: 12345 minor units of USD (exp 2) -> "123.45 USD". Deterministic (no locale).
func ActionFormatMoney(minor int64, ccy string, exp int) string {
	s := strconv.FormatInt(minor, 10)
	for len(s) < exp+1 {
		s = "0" + s
	}
	if exp > 0 {
		s = s[:len(s)-exp] + "." + s[len(s)-exp:]
	}
	return s + " " + ccy
}

func rbFmt(minor int64, ccy string, exp float64) string {
	return ActionFormatMoney(minor, ccy, int(exp))
}

var rbDayNames = map[string]string{"sun": "Sun", "mon": "Mon", "tue": "Tue", "wed": "Wed", "thu": "Thu", "fri": "Fri", "sat": "Sat"}

func rbDayIdx(s string) int {
	for i, x := range ActionRuleDays {
		if x == s {
			return i
		}
	}
	return -1
}

func rbHoursText(h map[string]any) string {
	days, _ := strsOf(h["days"])
	ds := append([]string{}, days...)
	sort.SliceStable(ds, func(i, j int) bool { return rbDayIdx(ds[i]) < rbDayIdx(ds[j]) })
	run := len(ds) > 2
	for k := 1; k < len(ds) && run; k++ {
		run = rbDayIdx(ds[k]) == rbDayIdx(ds[k-1])+1
	}
	var txt string
	if run {
		txt = rbDayNames[ds[0]] + "-" + rbDayNames[ds[len(ds)-1]]
	} else {
		names := make([]string, len(ds))
		for i, x := range ds {
			names[i] = rbDayNames[x]
		}
		txt = strings.Join(names, ", ")
	}
	return txt + " " + jsValueString(h["from"]) + "-" + jsValueString(h["to"]) + " (" + jsValueString(h["tz"]) + ")"
}

func rbRecipientsText(x map[string]any) string {
	var parts []string
	doms, _ := strsOf(x["domains"])
	for _, dm := range doms {
		parts = append(parts, "addresses at "+dm)
	}
	adds, _ := strsOf(x["addresses"])
	return strings.Join(append(parts, adds...), " or ")
}

var rbLikeEsc = strings.NewReplacer(`\`, `\\`, `*`, `\*`, `?`, `\?`)

// ActionCompileBusinessRules compiles a rules block for d into tighten rules and accumulators (a bad_rules error for a malformed
// block). Deterministic: the same def and rules give the same output, in the same order.
func ActionCompileBusinessRules(d map[string]any, rules any) (out map[string]any, err error) {
	msg, bad, failed := rbRun(func() { out = rbCompile(d, rules) })
	if failed {
		return nil, rbErr(msg, bad)
	}
	return out, nil
}

func rbCompile(d map[string]any, rulesV any) map[string]any {
	rbValidate(d, rulesV)
	rules := rulesV.(map[string]any)
	verb := rbVerb(d)
	rd, err := ActionBusinessRulesDigest(verb, rules)
	if err != nil {
		panic(err.Error())
	}
	dd, err := defDigest(d)
	if err != nil {
		panic(err.Error())
	}
	t := []any{}
	acc := []any{}
	out := map[string]any{"v": jsNumber(1), "verb": d["verb"], "rules_digest": rd, "def_digest": dd, "tighten": t, "accumulators": acc}
	amountR, hasAmount := rbObj(rules["amount"])
	apR, hasApproval := rbObj(rules["approval"])
	var money *rbMoney
	if hasAmount || (hasApproval && rbHas(apR, "above")) {
		m := rbMoneyOf(d)
		money = &m
	}
	unlisted := func(listed []string) any {
		switch {
		case money == nil:
			return nil
		case money.isParm:
			return map[string]any{"not": map[string]any{"field": rbP(money.param), "op": "in", "value": anyStrs(listed)}}
		case contains(listed, money.lit):
			return nil
		}
		return rbAlways(verb)
	}
	sortedKeys := func(m map[string]any) []string {
		ks := jsKeys(m)
		ks = append([]string{}, ks...)
		adSortU16(ks)
		return ks
	}
	if hasAmount {
		mx, _ := rbObj(amountR["max"])
		listed := sortedKeys(mx)
		for _, c := range listed {
			v := rbMinor(mx[c], money.exp, "rules.amount.max."+c)
			t = append(t, rbRule(rbRuleID("amount_max_"+c), rbAnd(rbCcyCond(*money, c), map[string]any{"field": rbP(money.amount), "op": "gt", "value": jsNumber(float64(v))}), "deny",
				"the amount is above the "+rbFmt(v, c, money.exp)+" ceiling"))
		}
		if u := unlisted(listed); u != nil {
			t = append(t, rbRule("amount_currency", u, "deny", "only "+strings.Join(listed, ", ")+" amounts are allowed"))
		}
	}
	if hasApproval {
		ap := map[string]any{"approvers": jsNumber(1)}
		if v, has := apR["approvers"]; has {
			ap["approvers"] = v
		}
		if v, has := apR["group"]; has {
			ap["group"] = v
		}
		out["approval"] = ap
		if rbTruthy(apR["always"]) {
			t = append(t, rbRule("approval_always", rbAlways(verb), "escalate", "this action always needs approval"))
		} else {
			ab, _ := rbObj(apR["above"])
			listed := sortedKeys(ab)
			for _, c := range listed {
				x := rbMinor(ab[c], money.exp, "rules.approval.above."+c)
				t = append(t, rbRule(rbRuleID("approval_above_"+c), rbAnd(rbCcyCond(*money, c), map[string]any{"field": rbP(money.amount), "op": "gt", "value": jsNumber(float64(x))}), "escalate",
					"amounts above "+rbFmt(x, c, money.exp)+" need approval"))
			}
			if u := unlisted(listed); u != nil {
				t = append(t, rbRule("approval_currency", u, "escalate", "amounts in a currency other than "+strings.Join(listed, ", ")+" need approval"))
			}
		}
	}
	scope, _ := rules["scope"].([]any)
	for i, s0 := range scope {
		s := s0.(map[string]any)
		ref := map[string]any{"role": s["role"]}
		if rbHas(s, "param") {
			ref = map[string]any{"param": s["param"]}
		}
		name, _ := rbResolve(d, ref, "rules.scope["+strconv.Itoa(i)+"]")
		caller := jsValueString(s["caller"])
		// `not eq`: an absent caller attribute or parameter is undecided, so the rule fires
		t = append(t, rbRule("scope_"+strconv.Itoa(i), map[string]any{"not": map[string]any{"field": rbP(name), "op": "eq", "ref": "subject." + caller}}, "deny", name+" must be the caller's own "+caller))
	}
	rate, _ := rules["rate"].([]any)
	for i, r0 := range rate {
		r := r0.(map[string]any)
		id := "rate_" + strconv.Itoa(i)
		by := "principal"
		if rbHas(r, "by") {
			by = jsValueString(r["by"])
		}
		per := jsValueString(r["per"])
		acc = append(acc, map[string]any{"id": id, "agg": "count", "sel": map[string]any{"verbs": []any{d["verb"]}}, "win": map[string]any{"kind": "sliding", "ms": jsNumber(float64(rbRatePeriods[per]))},
			"key": nil, "domain_max": r["max"], "cap": r["max"], "holder": map[string]any{"kind": "site_local"}, "scope": by})
		t = append(t, rbRule(id, map[string]any{"field": "env.acc." + id, "op": "gte", "value": r["max"]}, "deny", "at most "+jsValueString(r["max"])+" per "+per+" per "+by))
	}
	if h, ok := rbObj(rules["hours"]); ok {
		from, to := rbMins(h["from"].(string)), rbMins(h["to"].(string))
		days, _ := strsOf(h["days"])
		dows := make([]int, len(days))
		for i, x := range days {
			dows[i] = rbDayIdx(x)
		}
		sort.Ints(dows)
		nums := func(xs []int, add int) []any {
			o := make([]any, len(xs))
			for i, x := range xs {
				o[i] = jsNumber(float64((x + add) % 7))
			}
			return o
		}
		minC := func(op string, v int) any {
			return map[string]any{"field": "env.clock.min", "op": op, "value": jsNumber(float64(v))}
		}
		var inTime, day any
		if from < to {
			inTime = map[string]any{"all_of": []any{minC("gte", from), minC("lt", to)}}
			day = map[string]any{"field": "env.clock.dow", "op": "in", "value": nums(dows, 0)}
		} else {
			// an overnight window (22:00-06:00): the day named is the day the window starts
			inTime = map[string]any{"any_of": []any{minC("gte", from), minC("lt", to)}}
			day = map[string]any{"any_of": []any{
				map[string]any{"all_of": []any{map[string]any{"field": "env.clock.dow", "op": "in", "value": nums(dows, 0)}, minC("gte", from)}},
				map[string]any{"all_of": []any{map[string]any{"field": "env.clock.dow", "op": "in", "value": nums(dows, 1)}, minC("lt", to)}}}}
		}
		out["clock_tz"] = h["tz"]
		signal := "escalate"
		if h["outside"] == "deny" {
			signal = "deny"
		}
		t = append(t, rbRule("hours", map[string]any{"not": map[string]any{"all_of": []any{day, inTime}}}, signal, "outside "+rbHoursText(h)))
	}
	if x, ok := rbObj(rules["recipients"]); ok {
		name, p := rbResolve(d, rbRef(x), "rules.recipients")
		doms, _ := strsOf(x["domains"])
		adds, hasAdds := strsOf(x["addresses"])
		okAt := func(path string) any {
			alts := []any{}
			for _, dm := range doms {
				alts = append(alts, map[string]any{"field": path, "op": "like", "value": "*@" + rbLikeEsc.Replace(dm)})
			}
			if hasAdds {
				s := append([]string{}, adds...)
				adSortU16(s)
				alts = append(alts, map[string]any{"field": path, "op": "in", "value": anyStrs(s)})
			}
			return map[string]any{"any_of": alts}
		}
		var okC any
		if p["type"] == "string" {
			okC = okAt(rbP(name))
		} else {
			n := int(rbNum(p["max_items"]))
			// every present entry is allowed, and the list is no longer than max_items (index n absent)
			all := []any{}
			for i := 0; i < n; i++ {
				path := rbP(name + "." + strconv.Itoa(i))
				all = append(all, map[string]any{"any_of": []any{map[string]any{"field": path, "op": "exists", "value": false}, okAt(path)}})
			}
			all = append(all, map[string]any{"field": rbP(name + "." + strconv.Itoa(n)), "op": "exists", "value": false})
			okC = map[string]any{"all_of": all}
		}
		t = append(t, rbRule("recipients", map[string]any{"not": okC}, "deny", name+" may only name "+rbRecipientsText(x)))
	}
	req, _ := rules["required"].([]any)
	for i, nv := range req {
		n := nv.(string)
		var missing any = map[string]any{"field": rbP(n), "op": "exists", "value": false}
		if rbParamOf(d, n)["type"] == "string" {
			missing = map[string]any{"any_of": []any{missing, map[string]any{"field": rbP(n), "op": "eq", "value": ""}}}
		}
		t = append(t, rbRule("required_"+strconv.Itoa(i), missing, "deny", n+" is required"))
	}
	for _, r := range t {
		m := r.(map[string]any)
		if s := m["reason"].(string); jsLen(s) > 256 {
			m["reason"] = string(utf16.Decode(utf16Units(s)[:253])) + "..."
		}
	}
	out["tighten"], out["accumulators"] = t, acc
	return out
}

// ---- evaluation -----------------------------------------------------------------------------------------------------------

var rbRank = map[string]int{"deny": 0, "escalate": 1, "allow": 2}

func rbMeet(a, b string) string {
	ra, okA := rbRank[a]
	rb, okB := rbRank[b]
	if !okA || !okB { // an unknown decision is never an allow
		return "deny"
	}
	if ra <= rb {
		return a
	}
	return b
}

func rbContext(c, in map[string]any) map[string]any {
	env := map[string]any{}
	if tz, ok := c["clock_tz"].(string); ok {
		if k := ActionClockAt(in["now"], tz); k != nil {
			env["clock"] = k
		}
	}
	acc := map[string]any{}
	counts, _ := rbObj(in["counts"])
	accs, _ := c["accumulators"].([]any)
	for _, a := range accs {
		id := jsValueString(a.(map[string]any)["id"])
		if n, has := counts[id]; has && rbSafeInt(n) && rbNum(n) >= 0 {
			acc[id] = n
		}
	}
	env["acc"] = acc
	resource := any("")
	if r, has := in["resource"]; has && r != nil {
		resource = r
	}
	subject := any(map[string]any{})
	if s, has := in["subject"]; has && s != nil {
		subject = s
	}
	return map[string]any{"action": map[string]any{"verb": c["verb"], "resource": resource, "params": in["params"]}, "subject": subject, "env": env}
}

// ActionEvaluateBusinessRules evaluates compiled rules against {params, subject?, now, counts?, resource?}: `allow` unless a rule
// fires; a fired rule caps the decision at its signal. An evaluation failure denies (fail closed). Never panics.
func ActionEvaluateBusinessRules(c, in map[string]any) (res map[string]any) {
	defer func() {
		if r := recover(); r != nil {
			res = map[string]any{"decision": "deny", "reasons": []any{"rules: evaluation error (fail closed): " + fmt.Sprint(r)}, "fired": []any{}}
		}
	}()
	ctx := rbContext(c, in)
	decision := "allow"
	reasons, fired := []any{}, []any{}
	approval := false
	rules, isList := c["tighten"].([]any)
	if !isList {
		panic("c.tighten is not iterable")
	}
	for _, r0 := range rules {
		r := r0.(map[string]any)
		if evaluateConditionTri(r["when"], ctx, &regexBudget{}) == triFalse {
			continue
		}
		signal, _ := r["signal"].(string)
		decision = rbMeet(decision, signal)
		id := jsValueString(r["id"])
		fired = append(fired, r["id"])
		why := r["reason"]
		if why == nil {
			why = r["signal"]
		}
		reasons = append(reasons, id+": "+jsValueString(why))
		if signal == "escalate" && strings.HasPrefix(id, "approval_") {
			approval = true
		}
	}
	res = map[string]any{"decision": decision, "reasons": reasons, "fired": fired}
	if ap, has := c["approval"]; approval && has && rbTruthy(ap) {
		res["approval"] = ap
	}
	return res
}

// ActionWithBusinessRules is the decision with rules applied to a base decision: the meet, so rules never raise it.
func ActionWithBusinessRules(base string, verdict map[string]any) string {
	d, _ := verdict["decision"].(string)
	return rbMeet(base, d)
}

// ActionRunRuleExamples runs a rules block's examples: [{index, expect, got, ok, why}].
func ActionRunRuleExamples(d map[string]any, rules any) (out []any, err error) {
	msg, bad, failed := rbRun(func() { out = rbRunExamples(d, rules) })
	if failed {
		return nil, rbErr(msg, bad)
	}
	return out, nil
}

func rbRunExamples(d map[string]any, rulesV any) []any {
	c := rbCompile(d, rulesV)
	rules := rulesV.(map[string]any)
	exs, _ := rules["examples"].([]any)
	accs := c["accumulators"].([]any)
	out := []any{}
	for i, e0 := range exs {
		e := e0.(map[string]any)
		recent, _ := rbObj(e["recent"])
		counts := map[string]any{}
		for k, a := range accs {
			v, has := recent[strconv.Itoa(k)]
			if !has || v == nil {
				v = jsNumber(0)
			}
			counts[a.(map[string]any)["id"].(string)] = v
		}
		at := any(rbDefaultExampleAt)
		if v, has := e["at"]; has && v != nil {
			at = v
		}
		now, _ := rbParseUTC(at)
		in := map[string]any{"params": e["params"], "now": jsNumber(now), "counts": counts}
		if rbTruthy(e["caller"]) {
			in["subject"] = e["caller"]
		}
		v := ActionEvaluateBusinessRules(c, in)
		got := v["decision"].(string)
		why := strings.Join(rbStrs(v["reasons"]), "; ")
		if why == "" {
			why = "no rule fired"
		}
		out = append(out, map[string]any{"index": jsNumber(float64(i)), "expect": e["expect"], "got": got, "ok": got == e["expect"], "why": why})
	}
	return out
}

func rbStrs(v any) []string { s, _ := strsOf(v); return s }

// ---- plain language -------------------------------------------------------------------------------------------------------

// ActionExplainBusinessRules is one plain sentence per rule, for the policy card and the dashboard (a bad_rules error for a malformed block).
func ActionExplainBusinessRules(d map[string]any, rulesV any) (out []any, err error) {
	msg, bad, failed := rbRun(func() { out = rbExplain(d, rulesV) })
	if failed {
		return nil, rbErr(msg, bad)
	}
	return out, nil
}

func rbExplain(d map[string]any, rulesV any) []any {
	rbValidate(d, rulesV)
	rules := rulesV.(map[string]any)
	out := []any{}
	amountR, hasAmount := rbObj(rules["amount"])
	apR, hasApproval := rbObj(rules["approval"])
	var m rbMoney
	if hasAmount || (hasApproval && rbHas(apR, "above")) {
		m = rbMoneyOf(d)
	}
	list := func(mv any) string {
		mp, _ := rbObj(mv)
		ks := append([]string{}, jsKeys(mp)...)
		adSortU16(ks)
		parts := make([]string, len(ks))
		for i, c := range ks {
			parts[i] = rbFmt(rbMinor(mp[c], m.exp, c), c, m.exp)
		}
		return strings.Join(parts, ", ")
	}
	if hasAmount {
		out = append(out, "Refuses amounts above "+list(amountR["max"])+"; any other currency is refused.")
	}
	if hasApproval {
		n := any(jsNumber(1))
		if v, has := apR["approvers"]; has {
			n = v
		}
		plural := "s"
		if rbNum(n) == 1 {
			plural = ""
		}
		who := jsValueString(n) + " approver" + plural
		if rbTruthy(apR["group"]) {
			who += " from the " + jsValueString(apR["group"]) + " group"
		}
		if rbTruthy(apR["always"]) {
			out = append(out, "Always needs approval by "+who+".")
		} else {
			out = append(out, "Needs approval by "+who+" when the amount is above "+list(apR["above"])+" (or in another currency).")
		}
	}
	scope, _ := rules["scope"].([]any)
	for _, s0 := range scope {
		s := s0.(map[string]any)
		name, _ := rbResolve(d, rbRef(s), "rules.scope")
		out = append(out, "Only the caller's own records: "+name+" must be the caller's "+jsValueString(s["caller"])+".")
	}
	rate, _ := rules["rate"].([]any)
	for _, r0 := range rate {
		r := r0.(map[string]any)
		who := "principal"
		if r["by"] == "org" {
			who = "organisation"
		}
		out = append(out, "At most "+jsValueString(r["max"])+" per "+jsValueString(r["per"])+" per "+who+".")
	}
	if h, ok := rbObj(rules["hours"]); ok {
		after := "needs approval"
		if h["outside"] == "deny" {
			after = "is refused"
		}
		out = append(out, "Only "+rbHoursText(h)+"; outside those hours it "+after+".")
	}
	if x, ok := rbObj(rules["recipients"]); ok {
		name, _ := rbResolve(d, rbRef(x), "rules.recipients")
		out = append(out, name+" may only name "+rbRecipientsText(x)+".")
	}
	if req, ok := rules["required"].([]any); ok {
		names := make([]string, len(req))
		for i, n := range req {
			names[i] = jsValueString(n)
		}
		out = append(out, "Requires "+strings.Join(names, ", ")+".")
	}
	return out
}

// ---- lint -----------------------------------------------------------------------------------------------------------------

// ActionBusinessRuleLints are the rules findings (they live outside the pinned lint rule set; ids LR-*).
var ActionBusinessRuleLints = []map[string]any{
	{"id": "LR-001", "severity": "error", "title": "a rules block is malformed or names a parameter the action does not have"},
	{"id": "LR-002", "severity": "error", "title": "a contradiction: under the rules the action can never be allowed"},
	{"id": "LR-003", "severity": "warning", "title": "a rule that can never fire or that another rule already covers"},
	{"id": "LR-004", "severity": "error", "title": "a rules example does not decide as it expects"},
}

// ActionLintBusinessRules lints one action's rules (contradictions and dead rules): [{rule, severity, verb, message}].
func ActionLintBusinessRules(d map[string]any, rulesV any) (out []any) {
	f := func(rule, severity, message string) any {
		return map[string]any{"rule": rule, "severity": severity, "verb": d["verb"], "message": message}
	}
	if e := ActionBusinessRulesError(d, rulesV); e != "" {
		return []any{f("LR-001", "error", e)}
	}
	out = []any{}
	defer func() { // the checks below read a validated block; a failure is a refusal to vouch, never a pass
		if r := recover(); r != nil {
			out = append(out, f("LR-001", "error", fmt.Sprint(r)))
		}
	}()
	r := rulesV.(map[string]any)
	amountR, hasAmount := rbObj(r["amount"])
	apR, hasApproval := rbObj(r["approval"])
	var m rbMoney
	hasMoney := hasAmount || (hasApproval && rbHas(apR, "above"))
	var amt map[string]any
	var ccyValues []any
	haveValues := false
	if hasMoney {
		m = rbMoneyOf(d)
		amt = rbParamOf(d, m.amount)
		if m.isParm {
			ccyValues, haveValues = rbParamOf(d, m.param)["values"].([]any)
		} else {
			ccyValues, haveValues = []any{m.lit}, true
		}
	}
	join := func(xs []any) string {
		s := make([]string, len(xs))
		for i, x := range xs {
			s[i] = jsValueString(x)
		}
		return strings.Join(s, ", ")
	}
	if hasAmount && hasMoney {
		mx, _ := rbObj(amountR["max"])
		listed := jsKeys(mx)
		if haveValues {
			any1 := false
			for _, c := range ccyValues {
				if s, ok := c.(string); ok && contains(listed, s) {
					any1 = true
				}
			}
			if !any1 {
				out = append(out, f("LR-002", "error", "rules.amount: none of the action's currencies ("+join(ccyValues)+") has a ceiling, so every call is refused"))
			}
		}
		for _, c := range listed {
			v := rbMinor(mx[c], m.exp, c)
			if haveValues && !containsV(ccyValues, c) {
				out = append(out, f("LR-003", "warning", "rules.amount.max."+c+": the action never uses "+c))
			}
			if mn, has := amt["min"]; has && float64(v) < rbNum(mn) {
				out = append(out, f("LR-002", "error", "rules.amount.max."+c+": the ceiling "+rbFmt(v, c, m.exp)+" is below the parameter's minimum, so every "+c+" call is refused"))
			}
			if mxp, has := amt["max"]; has && float64(v) >= rbNum(mxp) {
				out = append(out, f("LR-003", "warning", "rules.amount.max."+c+": the parameter's own maximum already bounds the amount below this ceiling"))
			}
		}
	}
	if above, ok := rbObj(apR["above"]); ok && hasMoney {
		mx, _ := rbObj(amountR["max"])
		for _, c := range jsKeys(above) {
			x := rbMinor(above[c], m.exp, c)
			ceil, hasCeil := mx[c]
			if hasAmount && hasCeil && float64(x) >= float64(rbMinor(ceil, m.exp, c)) {
				out = append(out, f("LR-003", "warning", "rules.approval.above."+c+": above the amount ceiling, so the approval can never be asked for"))
			}
			if hasAmount && !hasCeil {
				out = append(out, f("LR-003", "warning", "rules.approval.above."+c+": "+c+" has no ceiling, so it is always refused before an approval"))
			}
		}
	}
	if h, ok := rbObj(r["hours"]); ok && h["from"] == h["to"] {
		what := "always escalated"
		if h["outside"] == "deny" {
			what = "always refused"
		}
		out = append(out, f("LR-002", "error", "rules.hours: the window "+jsValueString(h["from"])+"-"+jsValueString(h["to"])+" is empty, so the action is "+what))
	}
	if req, ok := r["required"].([]any); ok {
		for _, nv := range req {
			n := nv.(string)
			p := rbParamOf(d, n)
			if p["required"] != false && p["type"] != "string" {
				out = append(out, f("LR-003", "warning", "rules.required: '"+n+"' is already required by the definition"))
			}
		}
	}
	if rate, ok := r["rate"].([]any); ok {
		seen := map[string]float64{}
		for _, x0 := range rate {
			x := x0.(map[string]any)
			by := "principal"
			if rbTruthy(x["by"]) {
				by = jsValueString(x["by"])
			}
			k := jsValueString(x["per"]) + "|" + by
			mxv := rbNum(x["max"])
			if prev, has := seen[k]; has {
				out = append(out, f("LR-003", "warning", "rules.rate: two limits per "+jsValueString(x["per"])+" per "+by+"; only the lower ("+jsNumberString(math.Min(prev, mxv))+") matters"))
				seen[k] = math.Min(prev, mxv)
			} else {
				seen[k] = mxv
			}
		}
		h, hasH := seen["hour|principal"]
		dd, hasD := seen["day|principal"]
		if hasH && hasD && dd <= h {
			out = append(out, f("LR-003", "warning", "rules.rate: the daily limit is not above the hourly one, so the hourly limit never fires"))
		}
	}
	res, err := ActionRunRuleExamples(d, r)
	if err != nil {
		return append(out, f("LR-001", "error", err.Error()))
	}
	for _, x0 := range res {
		x := x0.(map[string]any)
		if x["ok"] == false {
			out = append(out, f("LR-004", "error", "rules.examples["+jsValueString(x["index"])+"]: expected "+jsValueString(x["expect"])+", got "+jsValueString(x["got"])+" ("+jsValueString(x["why"])+")"))
		}
	}
	return out
}

// ---- semantic diff --------------------------------------------------------------------------------------------------------

const (
	rbEq     = "eq"
	rbNarrow = "narrow"
	rbWiden  = "widen"
	rbInc    = "inc"
)

func rbSetRel(a, b []string) string {
	aInB, bInA := subsetS(a, b), subsetS(b, a)
	switch {
	case aInB && bInA:
		return rbEq
	case bInA:
		return rbNarrow
	case aInB:
		return rbWiden
	}
	return rbInc
}

// rbNumRel: a numeric limit where lower is stricter.
func rbNumRel(a, b float64) string {
	switch {
	case a == b:
		return rbEq
	case b < a:
		return rbNarrow
	}
	return rbWiden
}

// rbPresence: absent vs present rule: adding a rule narrows, dropping one widens ("" when both are present).
func rbPresence(a, b any) string {
	switch {
	case a == nil && b == nil:
		return rbEq
	case a == nil:
		return rbNarrow
	case b == nil:
		return rbWiden
	}
	return ""
}

func rbCombine(rs ...string) string {
	has := func(x string) bool { return contains(rs, x) }
	switch {
	case has(rbInc) || (has(rbNarrow) && has(rbWiden)):
		return rbInc
	case has(rbWiden):
		return rbWiden
	case has(rbNarrow):
		return rbNarrow
	}
	return rbEq
}

// rbFlip: for sets of restrictions (scope bindings, required fields) more is narrower.
func rbFlip(r string) string {
	switch r {
	case rbNarrow:
		return rbWiden
	case rbWiden:
		return rbNarrow
	}
	return r
}

// rbMinsJS is the reference's `Number(hhmm.slice(0, 2)) * 60 + Number(hhmm.slice(3, 5))`: a malformed time is NaN, which orders
// before and after nothing (the stretch is then empty), never a failure.
func rbMinsJS(hhmm string) float64 {
	u := utf16Units(hhmm)
	slice := func(a, b int) string {
		if a > len(u) {
			a = len(u)
		}
		if b > len(u) {
			b = len(u)
		}
		return string(utf16.Decode(u[a:b]))
	}
	return float64(jsStringToNumber(slice(0, 2))*60) + jsStringToNumber(slice(3, 5))
}

func rbMinutesOfWeek(h map[string]any) map[int]bool {
	s := map[int]bool{}
	fromF, toF := rbMinsJS(h["from"].(string)), rbMinsJS(h["to"].(string))
	if math.IsNaN(fromF) || math.IsNaN(toF) {
		return s
	}
	from, to := int(fromF), int(toF)
	days, _ := strsOf(h["days"])
	for _, day := range days {
		base := rbDayIdx(day) * 1440
		if from < to {
			for x := from; x < to; x++ {
				s[base+x] = true
			}
		} else if from > to {
			for x := from; x < 1440; x++ {
				s[base+x] = true
			}
			for x := 0; x < to; x++ {
				s[(base+1440)%10080+x] = true
			}
		}
	}
	return s
}

func rbSubset(a, b map[int]bool) bool {
	for x := range a {
		if !b[x] {
			return false
		}
	}
	return true
}

func rbRateBest(v any) map[string]float64 {
	mp := map[string]float64{}
	rs, _ := v.([]any)
	for _, x0 := range rs {
		x := x0.(map[string]any)
		by := "principal"
		if rbTruthy(x["by"]) {
			by = jsValueString(x["by"])
		}
		k := jsValueString(x["per"]) + "|" + by
		if cur, has := mp[k]; !has || rbNum(x["max"]) < cur {
			mp[k] = rbNum(x["max"])
		}
	}
	return mp
}

// ActionDiffBusinessRules is the semantic diff of two rules blocks of one action (either may be absent = nil): {class, reasons}
// with class equal | narrow | widen | incomparable. Narrow/equal can be published without a reviewer; widen and incomparable need
// a reviewer's signed rules review. Conservative: anything not ordered is incomparable.
func ActionDiffBusinessRules(d map[string]any, prev, next map[string]any) (res map[string]any, err error) {
	msg, bad, failed := rbRun(func() { res = rbDiff(d, prev, next) })
	if failed {
		return nil, rbErr(msg, bad)
	}
	return res, nil
}

func rbDiff(d map[string]any, o, n map[string]any) map[string]any {
	type rel struct{ k, r string }
	var rels []rel
	if o == nil {
		o = map[string]any{}
	}
	if n == nil {
		n = map[string]any{}
	}
	above := func(m map[string]any) any { a, _ := rbObj(m["approval"]); return a["above"] }
	var m rbMoney
	if rbTruthy(o["amount"]) || rbTruthy(n["amount"]) || rbTruthy(above(o)) || rbTruthy(above(n)) {
		m = rbMoneyOf(d)
	}
	ccyMapRel := func(av, bv any) string {
		if av == nil || bv == nil { // Object.keys(undefined | null) throws
			panic("Cannot convert undefined or null to object")
		}
		a, _ := rbObj(av)
		b, _ := rbObj(bv)
		rs := []string{rbSetRel(jsKeys(a), jsKeys(b))}
		for _, c := range jsKeys(a) {
			if rbHas(b, c) {
				rs = append(rs, rbNumRel(float64(rbMinor(a[c], m.exp, c)), float64(rbMinor(b[c], m.exp, c))))
			}
		}
		return rbCombine(rs...)
	}
	sub := func(m map[string]any, k, k2 string) any { x, _ := rbObj(m[k]); return x[k2] }
	if p := rbPresence(o["amount"], n["amount"]); p != "" {
		rels = append(rels, rel{"amount", p})
	} else {
		rels = append(rels, rel{"amount", ccyMapRel(sub(o, "amount", "max"), sub(n, "amount", "max"))})
	}
	if p := rbPresence(o["approval"], n["approval"]); p != "" {
		rels = append(rels, rel{"approval", p})
	} else {
		a, _ := rbObj(o["approval"])
		b, _ := rbObj(n["approval"])
		var rs []string
		switch {
		case rbTruthy(a["always"]) && rbTruthy(b["always"]):
			rs = append(rs, rbEq)
		case rbTruthy(a["always"]):
			rs = append(rs, rbWiden)
		case rbTruthy(b["always"]):
			rs = append(rs, rbNarrow)
		default:
			rs = append(rs, ccyMapRel(a["above"], b["above"]))
		}
		appr := func(x map[string]any) float64 {
			if v, has := x["approvers"]; has && v != nil {
				return -rbNum(v)
			}
			return -1
		}
		rs = append(rs, rbNumRel(appr(a), appr(b)))
		if jsStrictEq(a["group"], b["group"]) {
			rs = append(rs, rbEq)
		} else {
			rs = append(rs, rbInc)
		}
		rels = append(rels, rel{"approval", rbCombine(rs...)})
	}
	skeys := func(v any) []string {
		xs, _ := v.([]any)
		out := []string{}
		for _, s0 := range xs {
			s, _ := rbObj(s0)
			part := func(k string) string {
				if s[k] == nil {
					return ""
				}
				return jsValueString(s[k])
			}
			out = append(out, part("param")+"|"+part("role")+"|"+jsValueString(s["caller"]))
		}
		return out
	}
	rels = append(rels, rel{"scope", rbFlip(rbSetRel(skeys(o["scope"]), skeys(n["scope"])))})
	A, B := rbRateBest(o["rate"]), rbRateBest(n["rate"])
	var rrs []string
	for k := range A {
		if _, has := B[k]; !has {
			rrs = append(rrs, rbWiden)
		} else {
			rrs = append(rrs, rbNumRel(A[k], B[k]))
		}
	}
	for k := range B {
		if _, has := A[k]; !has {
			rrs = append(rrs, rbNarrow)
		}
	}
	rels = append(rels, rel{"rate", rbCombine(rrs...)})
	if p := rbPresence(o["hours"], n["hours"]); p != "" {
		rels = append(rels, rel{"hours", p})
	} else {
		a, _ := rbObj(o["hours"])
		b, _ := rbObj(n["hours"])
		if !jsStrictEq(a["tz"], b["tz"]) {
			rels = append(rels, rel{"hours", rbInc})
		} else {
			sa, sb := rbMinutesOfWeek(a), rbMinutesOfWeek(b)
			inner := rbInc
			switch {
			case len(sa) == len(sb) && rbSubset(sa, sb):
				inner = rbEq
			case rbSubset(sb, sa):
				inner = rbNarrow
			case rbSubset(sa, sb):
				inner = rbWiden
			}
			lvl := func(x map[string]any) float64 {
				if x["outside"] == "deny" {
					return 0
				}
				return 1
			}
			rels = append(rels, rel{"hours", rbCombine(inner, rbNumRel(lvl(a), lvl(b)))})
		}
	}
	if p := rbPresence(o["recipients"], n["recipients"]); p != "" {
		rels = append(rels, rel{"recipients", p})
	} else {
		a, _ := rbObj(o["recipients"])
		b, _ := rbObj(n["recipients"])
		if !jsStrictEq(a["param"], b["param"]) || !jsStrictEq(a["role"], b["role"]) {
			rels = append(rels, rel{"recipients", rbInc})
		} else {
			allowed := func(x map[string]any) []string {
				doms, _ := strsOf(x["domains"])
				out := []string{}
				for _, dm := range doms {
					out = append(out, "@"+dm)
				}
				adds, _ := strsOf(x["addresses"])
				return append(out, adds...)
			}
			covered := func(x string, set []string) bool {
				if contains(set, x) {
					return true
				}
				if strings.HasPrefix(x, "@") {
					return false
				}
				host := "undefined"
				if parts := strings.Split(x, "@"); len(parts) > 1 {
					host = parts[1]
				}
				return contains(set, "@"+host)
			}
			aa, ab := allowed(a), allowed(b)
			bInA, aInB := true, true
			for _, x := range ab {
				bInA = bInA && covered(x, aa)
			}
			for _, x := range aa {
				aInB = aInB && covered(x, ab)
			}
			r := rbInc
			switch {
			case bInA && aInB:
				r = rbEq
			case bInA:
				r = rbNarrow
			case aInB:
				r = rbWiden
			}
			rels = append(rels, rel{"recipients", r})
		}
	}
	or, nr := rbStrs(o["required"]), rbStrs(n["required"])
	rels = append(rels, rel{"required", rbFlip(rbSetRel(or, nr))})
	var reasons, diffs []string
	for _, x := range rels {
		if x.r != rbEq {
			word := x.r
			if word == rbInc {
				word = "incomparable"
			}
			reasons = append(reasons, "rules."+x.k+": "+word)
			diffs = append(diffs, x.r)
		}
	}
	adSortU16(reasons)
	cls := rbCombine(diffs...)
	switch cls {
	case rbEq:
		cls = "equal"
	case rbInc:
		cls = "incomparable"
	}
	rl := make([]any, len(reasons))
	for i, s := range reasons {
		rl[i] = s
	}
	return map[string]any{"class": cls, "reasons": rl}
}

// ---- the reviewer's signature over a widened rules block ---------------------------------------------------------------------

// ActionRulesReviewMessage is the domain-separated message the reviewer signs over {verb, def_digest, rules_digest, reviewer_kid, ts}.
func ActionRulesReviewMessage(b map[string]any) ([]byte, error) {
	body := map[string]any{}
	for _, k := range []string{"verb", "def_digest", "rules_digest", "reviewer_kid", "ts"} {
		v, has := b[k]
		if !has {
			return nil, errors.New("the rules review has no " + k)
		}
		body[k] = v
	}
	msg, ok := domainMessage(ActionRulesReviewDomain+"\x00", body)
	if !ok {
		return nil, errors.New("the rules review body is not canonical")
	}
	return msg, nil
}

// ActionSignRulesReview signs a rules review body with an Ed25519 seed and returns it with `sig`.
func ActionSignRulesReview(b map[string]any, seed []byte) (map[string]any, error) {
	kp, err := KeyPairFromSeed(seed)
	if err != nil {
		return nil, err
	}
	msg, err := ActionRulesReviewMessage(b)
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	for k, v := range b {
		out[k] = v
	}
	out["sig"] = b64.EncodeToString(kp.Sign(msg))
	return out, nil
}

// ActionRulesReviewError is "" iff r is a valid review of exactly these rules on exactly this def: digests match, the signer is
// pinned with the reviewer role, the time is inside the key validity, the signature verifies. A reason otherwise. Never panics.
func ActionRulesReviewError(rv any, d map[string]any, rules map[string]any, pins any) (res string) {
	defer func() {
		if r := recover(); r != nil {
			res = "malformed rules review: " + fmt.Sprint(r)
		}
	}()
	if pins == nil {
		return "no reviewer keys are pinned"
	}
	if pe := reviewerPinsError(pins); pe != "" {
		return "bad pins: " + pe
	}
	x, ok := rbObj(rv)
	if !ok {
		return "no rules review"
	}
	verb := rbVerb(d)
	if x["verb"] != d["verb"] {
		return "the rules review names another action"
	}
	dd, err := defDigest(d)
	if err != nil {
		return "malformed rules review: " + err.Error()
	}
	if x["def_digest"] != dd {
		return "the rules review covers another version of the action"
	}
	rd, err := ActionBusinessRulesDigest(verb, rules)
	if err != nil {
		return "malformed rules review: " + err.Error()
	}
	if x["rules_digest"] != rd {
		return "the rules review covers other rules"
	}
	sig, sOK := x["sig"].(string)
	kid, kOK := x["reviewer_kid"].(string)
	if !sOK || !kOK || !jsIsInt(x["ts"]) {
		return "malformed rules review"
	}
	var key map[string]any
	for _, kv := range pins.(map[string]any)["keys"].([]any) {
		if k := kv.(map[string]any); k["kid"] == kid {
			key = k
			break
		}
	}
	if key == nil {
		return "no pinned key '" + kid + "'"
	}
	if !hasRole(key, "reviewer") {
		return "key '" + jsValueString(key["kid"]) + "' does not hold the reviewer role"
	}
	ts := rbNum(x["ts"])
	if nb, has := key["not_before"]; has && ts < rbNum(nb) {
		return "the review time is outside the key validity"
	}
	if na, has := key["not_after"]; has && ts > rbNum(na) {
		return "the review time is outside the key validity"
	}
	body := map[string]any{}
	for k, v := range x {
		if k != "sig" {
			body[k] = v
		}
	}
	msg, err := ActionRulesReviewMessage(body)
	if err != nil {
		return "malformed rules review: " + err.Error()
	}
	if !verifyB64u(jsValueString(key["pk"]), msg, sig) {
		return "the rules review signature is invalid"
	}
	return ""
}

// ActionResolveParamRef is the parameter a reference ({param} or {role}) names in d: its name and definition (a bad_rules error
// when it resolves to none or to several).
func ActionResolveParamRef(d map[string]any, r any, at string) (name string, p map[string]any, err error) {
	msg, bad, failed := rbRun(func() { name, p = rbResolve(d, r, at) })
	if failed {
		return "", nil, rbErr(msg, bad)
	}
	return name, p, nil
}
