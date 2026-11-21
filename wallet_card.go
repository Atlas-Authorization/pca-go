package pca

// The trusted question card and agent-initiated clarification of the wallet (the PCA Intent Layer v2): a deterministic render from
// the wallet's own outcome space, the cell coordinates, the verified site identity, the principal's own signed statement and a
// closed-enum reason (no field for agent-authored text), its digest, the "Partly..." and typed-value checks, and the structured
// clarification request with max-information cell selection.
//
// The render input is a JSON object with the reference's member names (verb, coords, site, statementText, reversibility, units,
// action, friction, kind, reason, locale); the outcome space is passed alongside.

import (
	"errors"
	"fmt"
	"math"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf16"
)

// WalletCardDomain is the digest domain of a card.
const WalletCardDomain = "atlas-pca/intent-card/v2"

// WalletClarifyReasons is the closed reason enum of an agent clarification.
var WalletClarifyReasons = []string{"ambiguous_parameter", "multiple_options", "price_changed", "constraint_conflict", "missing_value", "other"}

// WalletReasonLabels is the fixed label the card shows for each reason.
var WalletReasonLabels = map[string]string{
	"ambiguous_parameter": "Your agent found a detail your request did not settle.",
	"multiple_options":    "Your agent found several options that match.",
	"price_changed":       "Your agent found that a price changed.",
	"constraint_conflict": "Your agent found that two parts of your request conflict.",
	"missing_value":       "Your agent needs a value your request did not give.",
	"other":               "Your agent needs a decision before it continues.",
}

// WalletMaxCandidates is the most candidates a clarification carries.
const WalletMaxCandidates = 8

const (
	walletMaxValues = 64
	walletMaxString = 256
)

var walletPathRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)*$`)

// ---- text helpers ---------------------------------------------------------------------------------------------------------

// walletUnitsToString encodes UTF-16 units as a (WTF-8) string; a lone surrogate keeps its 3-byte form.
func walletUnitsToString(us []uint16) string {
	var sb strings.Builder
	for i := 0; i < len(us); i++ {
		u := rune(us[i])
		switch {
		case u >= 0xD800 && u < 0xDC00 && i+1 < len(us) && us[i+1] >= 0xDC00 && us[i+1] < 0xE000:
			sb.WriteRune(utf16.DecodeRune(u, rune(us[i+1])))
			i++
		case u >= 0xD800 && u < 0xE000:
			sb.WriteByte(0xED)
			sb.WriteByte(byte(0x80 | (u>>6)&0x3f))
			sb.WriteByte(byte(0x80 | u&0x3f))
		default:
			sb.WriteRune(u)
		}
	}
	return sb.String()
}

// walletIsSpace is the JavaScript `\s` set (also what String.prototype.trim strips).
func walletIsSpace(u uint16) bool {
	switch {
	case u >= 0x09 && u <= 0x0D, u == 0x20, u == 0xA0, u == 0x1680, u >= 0x2000 && u <= 0x200A, u == 0x2028, u == 0x2029, u == 0x202F, u == 0x205F, u == 0x3000, u == 0xFEFF:
		return true
	}
	return false
}

func walletIsCtrl(u uint16) bool {
	return u <= 0x1F || (u >= 0x7F && u <= 0x9F) || (u >= 0x200B && u <= 0x200F) || (u >= 0x2028 && u <= 0x202E) || (u >= 0x2066 && u <= 0x2069)
}

// WalletCleanText strips control characters, collapses whitespace and caps the length (for the principal's own words and the
// site's name). A value that is not a string is refused.
func WalletCleanText(v any, max int) (string, error) {
	s, ok := v.(string)
	if !ok {
		return "", errors.New("s.replace is not a function")
	}
	out := []uint16{}
	pendingSpace := false
	for _, u := range utf16Units(s) {
		if walletIsCtrl(u) || walletIsSpace(u) {
			pendingSpace = len(out) > 0
			continue
		}
		if pendingSpace {
			out = append(out, ' ')
			pendingSpace = false
		}
		out = append(out, u)
	}
	if len(out) <= max {
		return walletUnitsToString(out), nil
	}
	end := max - 1
	if end < 0 {
		end = len(out) + end
		if end < 0 {
			end = 0
		}
	}
	return walletUnitsToString(out[:end]) + "…", nil
}

// WalletLast4 is the last four letters/digits of a string (all a card ever shows of a string the outcome space does not name).
func WalletLast4(s string) string {
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' {
			c -= 32
		}
		if c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			sb.WriteByte(c)
		}
	}
	t := sb.String()
	if len(t) > 4 {
		t = t[len(t)-4:]
	}
	return t
}

// walletGroup is the thousands grouping of a digit string (`\B(?=(\d{3})+(?!\d))` -> ",").
func walletGroup(s string) string {
	digits := 0
	for digits < len(s) && s[digits] >= '0' && s[digits] <= '9' {
		digits++
	}
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		if i > 0 && i < digits && (digits-i)%3 == 0 {
			sb.WriteByte(',')
		}
		sb.WriteByte(s[i])
	}
	return sb.String()
}

var walletCurrencySymbol = map[string]string{"USD": "$", "EUR": "€", "GBP": "£", "JPY": "¥"}

func walletIsMoney(unit any) bool {
	m, ok := unit.(map[string]any)
	return ok && m["kind"] == "money"
}

// walletExponent is Math.max(0, Math.min(6, Math.floor(unit.exponent))); ok is false for NaN.
func walletExponent(unit any) (float64, bool) {
	var raw any
	if m, ok := unit.(map[string]any); ok {
		raw = m["exponent"]
		if _, has := m["exponent"]; !has {
			return 0, false // undefined is NaN
		}
	}
	e := jsToNumber(raw)
	if math.IsNaN(e) {
		return 0, false
	}
	return math.Max(0, math.Min(6, math.Floor(e))), true
}

func walletCurrencyText(unit any) string {
	var cur any
	if m, ok := unit.(map[string]any); ok {
		cur = m["currency"]
	}
	if s, ok := cur.(string); ok {
		if sym, has := walletCurrencySymbol[s]; has {
			return sym
		}
	}
	if _, isMap := unit.(map[string]any); isMap {
		if _, has := unit.(map[string]any)["currency"]; !has {
			return "undefined "
		}
	}
	return jsValueString(cur) + " "
}

// WalletFormatNumber is thousands grouping with commas, independent of any locale data (cards render identically anywhere).
func WalletFormatNumber(x float64, unit any) string {
	sign := ""
	if x < 0 {
		sign = "-"
	}
	a := math.Abs(math.Trunc(x))
	if walletIsMoney(unit) {
		e, ok := walletExponent(unit)
		if !ok {
			return sign + walletCurrencyText(unit) + "NaN"
		}
		div := math.Pow(10, e)
		whole := walletGroup(jsNumberString(math.Floor(a / div)))
		frac := ""
		if e > 0 {
			f := jsNumberString(math.Mod(a, div))
			for len(f) < int(e) {
				f = "0" + f
			}
			frac = "." + f
		}
		return sign + walletCurrencyText(unit) + whole + frac
	}
	return sign + walletGroup(jsNumberString(a))
}

var (
	walletUnderscoreDot = strings.NewReplacer("_", " ", ".", " ")
)

func walletDimLabel(path string) string {
	if m := walletAccRe.FindStringSubmatch(path); m != nil {
		return walletUnderscoreDot.Replace(m[1]) + " (running total for this task)"
	}
	if m := walletWorldRe.FindStringSubmatch(path); m != nil {
		return walletUnderscoreDot.Replace(m[1]) + " (from a signed fact)"
	}
	if m := walletMonRe.FindStringSubmatch(path); m != nil {
		return "state of " + walletUnderscoreDot.Replace(m[1])
	}
	return WalletLabelOf(path)
}

func walletIsProvPath(p string) bool { return strings.HasPrefix(p, "env.prov.") }

func walletNumFact(d *WalletDim, ids []int, unit any, av any) string {
	cells := WalletNumCells(d)
	lo := cells[ids[0]].Lo
	hi := cells[ids[len(ids)-1]].Hi
	var rng string
	switch {
	case lo == hi:
		rng = "exactly " + WalletFormatNumber(lo, unit)
	case lo == d.Lo && hi == d.Hi:
		rng = "any value"
	case hi == d.Hi:
		rng = WalletFormatNumber(lo, unit) + " or more"
	case lo == d.Lo:
		rng = "up to " + WalletFormatNumber(hi, unit)
	default:
		rng = WalletFormatNumber(lo, unit) + " – " + WalletFormatNumber(hi, unit)
	}
	if f, ok := jsNum(av); ok && !math.IsNaN(f) && !math.IsInf(f, 0) {
		rng += " (this action: " + WalletFormatNumber(f, unit) + ")"
	}
	return rng
}

func walletCatValueText(d *WalletDim, i int) (string, error) {
	v := d.Values[i]
	switch v.Kind {
	case "exact":
		t, err := WalletCleanText(v.Value, 64)
		return "\"" + t + "\"", err
	case "prefix":
		t, err := WalletCleanText(v.Value, 64)
		return "anything starting with \"" + t + "\"", err
	}
	return "a value not named in your request", nil
}

func walletCatFact(d *WalletDim, ids []int, av any) (string, error) {
	parts := make([]string, len(ids))
	for k, i := range ids {
		t, err := walletCatValueText(d, i)
		if err != nil {
			return "", err
		}
		parts[k] = t
	}
	var set string
	switch len(parts) {
	case 0:
		set = " or undefined"
	case 1:
		set = parts[0]
	default:
		set = strings.Join(parts[:len(parts)-1], ", ") + " or " + parts[len(parts)-1]
	}
	s, ok := av.(string)
	if !ok {
		return set, nil
	}
	named := false
	for _, v := range d.Values {
		if v.Kind == "exact" && v.Value == s {
			named = true
		}
	}
	if named {
		t, err := WalletCleanText(s, 64)
		return set + " (this action: \"" + t + "\")", err
	}
	return set + " (this action: a value ending in \"" + WalletLast4(s) + "\")", nil
}

func walletBannerFor(path string, levels []any) (string, error) {
	w, err := WalletWorstProvenance(levels)
	if err != nil {
		return "", err
	}
	label := walletDimLabel(path)
	switch w {
	case "web":
		return "This " + label + " was suggested by content on a web page, not by you.", nil
	case "tool":
		return "This " + label + " came from a tool result, not from you.", nil
	case "agent":
		return "This " + label + " was chosen by your agent, not taken from your request or from the site.", nil
	}
	return "", nil
}

var walletSplitLevels = regexp.MustCompile(`[|,]`)

func walletProvLevels(d *WalletDim, ids []int) []any {
	out := []any{}
	for _, i := range ids {
		for _, p := range walletSplitLevels.Split(d.Values[i].Value, -1) {
			out = append(out, p)
		}
	}
	return out
}

// walletValuesGet is `action.values[path]`: a missing values member throws, a non-object has no members.
func walletValuesGet(action any, path string) (any, error) {
	m, _ := action.(map[string]any)
	values, has := m["values"]
	if !has || values == nil {
		return nil, errors.New("Cannot read properties of undefined")
	}
	vm, ok := values.(map[string]any)
	if !ok {
		return nil, nil
	}
	return vm[path], nil
}

func walletTypedTarget(vs *WalletVerb, action any, units any) (map[string]any, error) {
	if !jsTruthy(action) {
		return nil, nil
	}
	var nums []*WalletDim
	var dims []*WalletDim
	for i := range vs.Dims {
		if !walletIsProvPath(vs.Dims[i].Path) {
			dims = append(dims, &vs.Dims[i])
		}
	}
	for _, d := range dims {
		if d.Kind != "num" {
			continue
		}
		v, err := walletValuesGet(action, d.Path)
		if err != nil {
			return nil, err
		}
		if wIsNumber(v) {
			nums = append(nums, d)
		}
	}
	um, _ := units.(map[string]any)
	var pick *WalletDim
	for _, d := range nums {
		if walletIsMoney(um[d.Path]) {
			pick = d
			break
		}
	}
	if pick == nil && len(nums) > 0 {
		pick = nums[0]
	}
	if pick != nil {
		return map[string]any{"path": pick.Path, "mode": "number", "prompt": "To allow it, type the " + walletDimLabel(pick.Path) + " of this action shown above."}, nil
	}
	for _, d := range dims {
		if d.Kind != "cat" {
			continue
		}
		v, err := walletValuesGet(action, d.Path)
		if err != nil {
			return nil, err
		}
		if s, ok := v.(string); ok && len(WalletLast4(s)) == 4 {
			return map[string]any{"path": d.Path, "mode": "last4", "prompt": "To allow it, type the last 4 letters or digits of the " + walletDimLabel(d.Path) + "."}, nil
		}
	}
	return nil, nil
}

func walletAnswersFor(friction any) []any {
	key := ""
	switch f := friction.(type) {
	case string:
		key = f
	case []any:
		if len(f) == 1 {
			key, _ = f[0].(string)
		}
	}
	label := map[string]string{"tap": "Yes", "hold": "Press and hold to allow", "typed": "Yes, type the value to confirm", "device": "Yes, confirm with your security key"}
	yes, ok := label[key]
	if !ok {
		return nil
	}
	return []any{
		map[string]any{"id": "no", "label": "No"},
		map[string]any{"id": "partly", "label": "Partly…"},
		map[string]any{"id": "yes", "label": yes},
	}
}

var walletRevText = map[string]string{"reversible": "that can be undone", "rate_limited": "that is rate-limited", "irreversible": "that cannot be undone"}

func walletLowerFirst(s string) string {
	if s == "" || s[0] == '\n' || s[0] == '\r' {
		return s
	}
	return strings.ToLower(s[:1]) + s[1:]
}

// WalletRenderCard renders the trusted question card: {ok: true, card} or {ok: false, reason}. catalog nil is the built-in one.
func WalletRenderCard(om *WalletOmega, inp map[string]any, catalog *Catalog) (map[string]any, error) {
	refuse := func(r string) (map[string]any, error) { return map[string]any{"ok": false, "reason": r}, nil }
	loc, hasLoc := inp["locale"]
	if !hasLoc || loc == nil {
		loc = "en"
	}
	if loc != "en" {
		return refuse("unsupported locale " + jsValueString(inp["locale"]))
	}
	kind, hasKind := inp["kind"]
	reason, hasReason := inp["reason"]
	if kind == "clarification" && !hasReason {
		return refuse("a clarification card needs a reason")
	}
	if hasReason {
		rs, isS := reason.(string)
		if !isS || walletIndexOf(WalletClarifyReasons, rs) < 0 {
			return refuse("unknown clarification reason")
		}
	}
	verb, hasVerb := inp["verb"]
	if !hasVerb {
		verb = jsUndefinedValue{}
	}
	r, err := WalletResolveCoords(om, verb, inp["coords"])
	if err != nil {
		return nil, err
	}
	if !r.OK {
		return refuse(r.Reason)
	}
	vs, box := r.VS, r.Box
	action := inp["action"]
	if jsTruthy(action) {
		am, _ := action.(map[string]any)
		if av, _ := am["verb"].(string); av != vs.Verb || am["verb"] == nil {
			return refuse("the action is for another verb")
		}
	}
	if catalog == nil {
		catalog = DefaultCatalog()
	}
	site, ok := inp["site"].(map[string]any)
	if !ok {
		return nil, errors.New("Cannot read properties of undefined")
	}
	siteName, err := WalletCleanText(site["name"], 64)
	if err != nil {
		return nil, err
	}
	if siteName == "" {
		if siteName, err = WalletCleanText(site["origin"], 64); err != nil {
			return nil, err
		}
	}
	said := ""
	if st, has := inp["statementText"]; has {
		if said, err = WalletCleanText(st, 280); err != nil {
			return nil, err
		}
	}
	var header string
	switch {
	case kind == "clarification" && said != "":
		header = "Your agent needs a decision for your request \"" + said + "\""
	case kind == "clarification":
		header = "Your agent needs a decision"
	case said != "":
		header = siteName + " asks on behalf of your request \"" + said + "\""
	default:
		header = siteName + " asks for your confirmation"
	}
	var what string
	if spec, found := catalog.Get(vs.Verb); found {
		what = walletLowerFirst(strings.TrimSuffix(spec.Description, "."))
	} else {
		vt, err := WalletCleanText(vs.Verb, 64)
		if err != nil {
			return nil, err
		}
		what = "the action \"" + vt + "\" on " + siteName
	}
	var rev any = inp["reversibility"]
	if rev == nil {
		rev = vs.Reversibility
	}
	revText := "undefined"
	if rs, isS := rev.(string); isS {
		if t, has := walletRevText[rs]; has {
			revText = t
		}
	}
	sentence := "Allow " + what + ", " + revText + ", with:"
	units := inp["units"]
	facts, banners, partial := []any{}, []any{}, []any{}
	for k := range vs.Dims {
		d := &vs.Dims[k]
		ids := box[k]
		if walletIsProvPath(d.Path) {
			if d.Kind != "cat" {
				continue
			}
			b, err := walletBannerFor(strings.TrimPrefix(d.Path, "env.prov."), walletProvLevels(d, ids))
			if err != nil {
				return nil, err
			}
			if b != "" {
				banners = append(banners, b)
			}
			continue
		}
		var av any
		if action != nil {
			if av, err = walletValuesGet(action, d.Path); err != nil {
				return nil, err
			}
		}
		var unit any
		if um, isMap := units.(map[string]any); isMap {
			unit = um[d.Path]
		}
		if d.Kind == "num" {
			cells := WalletNumCells(d)
			facts = append(facts, map[string]any{"key": d.Path, "label": walletDimLabel(d.Path), "text": walletNumFact(d, ids, unit, av)})
			partial = append(partial, map[string]any{"path": d.Path, "kind": "num", "lo": jsNumber(cells[ids[0]].Lo), "hi": jsNumber(cells[ids[len(ids)-1]].Hi)})
			continue
		}
		text, err := walletCatFact(d, ids, av)
		if err != nil {
			return nil, err
		}
		facts = append(facts, map[string]any{"key": d.Path, "label": walletDimLabel(d.Path), "text": text})
		options := []any{}
		for _, i := range ids {
			if d.Values[i].Kind == "exact" {
				options = append(options, d.Values[i].Value)
			}
		}
		if len(options) > 1 {
			partial = append(partial, map[string]any{"path": d.Path, "kind": "cat", "options": options})
		}
	}
	friction, hasFriction := inp["friction"]
	var typed map[string]any
	if WalletFrictionRank(friction) >= WalletFrictionRank("typed") {
		if typed, err = walletTypedTarget(vs, action, units); err != nil {
			return nil, err
		}
	}
	origin, err := WalletCleanText(site["origin"], 256)
	if err != nil {
		return nil, err
	}
	body := map[string]any{
		"v": wN(2), "verb": verb, "coords": wPlain(inp["coords"]), "locale": "en",
		"site": map[string]any{"origin": origin, "name": siteName}, "header": header,
		"sentence": sentence, "facts": facts, "banners": banners, "partial": partial,
	}
	if hasKind {
		body["kind"] = kind
	}
	if hasReason {
		body["reason_label"] = WalletReasonLabels[reason.(string)]
	}
	if hasFriction {
		body["friction"] = friction
	}
	if answers := walletAnswersFor(friction); answers != nil {
		body["answers"] = answers
	}
	if typed != nil {
		body["typed"] = typed
	}
	digest, err := WalletCardDigest(body)
	if err != nil {
		return nil, err
	}
	card := make(map[string]any, len(body)+1)
	for k, v := range body {
		card[k] = v
	}
	card["rendered_digest"] = digest
	return map[string]any{"ok": true, "card": card}, nil
}

// WalletCardDigest is the content address of a card body (everything but rendered_digest).
func WalletCardDigest(body map[string]any) (string, error) {
	return HashCanonical(map[string]any{"d": WalletCardDomain, "c": wPlain(body)})
}

// WalletCardDigestMatches recomputes a card's digest and compares: an auditor's check that the stored card is the one hashed.
func WalletCardDigestMatches(card map[string]any) (bool, error) {
	body := make(map[string]any, len(card))
	for k, v := range card {
		if k != "rendered_digest" {
			body[k] = v
		}
	}
	d, err := WalletCardDigest(body)
	if err != nil {
		return false, err
	}
	stored, has := card["rendered_digest"]
	return has && stored == d, nil
}

// WalletCardText is the plain text of a card, line by line (what a screen reader or a text channel shows).
func WalletCardText(card map[string]any) (string, error) {
	str := func(v any) (string, error) {
		s, ok := v.(string)
		if !ok {
			return "", errors.New("card text: not a string")
		}
		return s, nil
	}
	lines := []string{}
	h, err := str(card["header"])
	if err != nil {
		return "", err
	}
	lines = append(lines, h)
	if jsTruthy(card["reason_label"]) {
		s, err := str(card["reason_label"])
		if err != nil {
			return "", err
		}
		lines = append(lines, s)
	}
	s, err := str(card["sentence"])
	if err != nil {
		return "", err
	}
	lines = append(lines, s)
	facts, ok := card["facts"].([]any)
	if !ok {
		return "", errors.New("card text: facts")
	}
	for _, f := range facts {
		fm, _ := f.(map[string]any)
		l, err1 := str(fm["label"])
		t, err2 := str(fm["text"])
		if err1 != nil || err2 != nil {
			return "", errors.New("card text: fact")
		}
		lines = append(lines, "- "+l+": "+t)
	}
	banners, ok := card["banners"].([]any)
	if !ok {
		return "", errors.New("card text: banners")
	}
	for _, b := range banners {
		bs, err := str(b)
		if err != nil {
			return "", err
		}
		lines = append(lines, bs)
	}
	if jsTruthy(card["typed"]) {
		tm, _ := card["typed"].(map[string]any)
		p, err := str(tm["prompt"])
		if err != nil {
			return "", err
		}
		lines = append(lines, p)
	}
	answers, ok := card["answers"].([]any)
	if !ok {
		return "", errors.New("card text: answers")
	}
	labels := make([]string, len(answers))
	for i, a := range answers {
		am, _ := a.(map[string]any)
		l, err := str(am["label"])
		if err != nil {
			return "", err
		}
		labels[i] = "[" + l + "]"
	}
	lines = append(lines, strings.Join(labels, " "))
	return strings.Join(lines, "\n"), nil
}

// ---- responses ----------------------------------------------------------------------------------------------------------------

// WalletPartialError validates a "Partly..." answer against the card: a structured restriction of the shown ranges and values
// only ("" when it is valid).
func WalletPartialError(card map[string]any, p map[string]any) (string, error) {
	slots, _ := card["partial"].([]any)
	var slot map[string]any
	for _, s := range slots {
		if sm, ok := s.(map[string]any); ok && jsStrictEq(sm["path"], p["path"]) {
			slot = sm
			break
		}
	}
	if slot == nil {
		return "the card has no field " + jsMemberString(p, "path"), nil
	}
	if slot["kind"] == "num" {
		lo, hi := jsF(slot["lo"]), jsF(slot["hi"])
		inRange := func(x any) bool {
			f, ok := walletIntegral(x)
			return ok && !wIsNegZero(x) && f >= lo && f <= hi
		}
		fi := func(f float64) string { return jsNumberString(f) }
		if wHas(p, "upTo") {
			if inRange(p["upTo"]) && jsF(p["upTo"]) < hi {
				return "", nil
			}
			return "upTo must be an integer in [" + fi(lo) + ", " + fi(hi-1) + "]", nil
		}
		if wHas(p, "from") {
			if inRange(p["from"]) && jsF(p["from"]) > lo {
				return "", nil
			}
			return "from must be an integer in [" + fi(lo+1) + ", " + fi(hi) + "]", nil
		}
		if wHas(p, "except") {
			switch ex := p["except"].(type) {
			case []any:
				good := len(ex) > 0
				for _, x := range ex {
					good = good && inRange(x)
				}
				if good {
					return "", nil
				}
			case nil:
				return "", errors.New("Cannot read properties of null")
			case string:
				if ex != "" {
					return "", errors.New("p.except.every is not a function")
				}
			}
			return "except values must be integers in [" + fi(lo) + ", " + fi(hi) + "]", nil
		}
		return "a numeric partly answer needs upTo, from or except", nil
	}
	if !wHas(p, "notFor") {
		return "a categorical partly answer needs notFor", nil
	}
	var items []any
	switch nf := p["notFor"].(type) {
	case []any:
		items = nf
	case string:
		for _, u := range utf16Units(nf) {
			items = append(items, walletUnitsToString([]uint16{u}))
		}
	default:
		return "", errors.New("object is not iterable")
	}
	options, _ := slot["options"].([]any)
	seen := map[string]bool{}
	allIn := true
	count := 0
	for _, it := range items {
		s, isS := it.(string)
		if !isS {
			count++
			allIn = false
			continue
		}
		if seen[s] {
			continue
		}
		seen[s] = true
		count++
		in := false
		for _, o := range options {
			if o == any(s) {
				in = true
			}
		}
		allIn = allIn && in
	}
	if count == 0 || !allIn {
		return "notFor must name values shown on the card", nil
	}
	if count == len(options) {
		return "excluding every value is a \"No\"", nil
	}
	return "", nil
}

var walletTypedRe = regexp.MustCompile(`^(-?)([0-9]+)(?:\.([0-9]+))?$`)

// WalletNormalizeTyped normalizes what the human typed for comparison with the action value (digits for numbers, minor units for
// money); ok is false when it does not parse.
func WalletNormalizeTyped(in, mode string, unit any) (string, bool, error) {
	if mode == "last4" {
		var sb strings.Builder
		for i := 0; i < len(in); i++ {
			c := in[i]
			if c >= 'a' && c <= 'z' {
				c -= 32
			}
			if c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
				sb.WriteByte(c)
			}
		}
		if t := sb.String(); len(t) == 4 {
			return t, true, nil
		}
		return "", false, nil
	}
	var sb strings.Builder
	for _, u := range utf16Units(in) {
		if walletIsSpace(u) || u == ',' || u == '$' || u == 0x20AC || u == 0xA3 || u == 0xA5 {
			continue
		}
		sb.WriteString(walletUnitsToString([]uint16{u}))
	}
	t := sb.String()
	if len(t) >= 3 && isASCIILetter(t[0]) && isASCIILetter(t[1]) && isASCIILetter(t[2]) {
		t = t[3:]
	}
	m := walletTypedRe.FindStringSubmatch(t)
	if m == nil {
		return "", false, nil
	}
	e := 0
	if walletIsMoney(unit) {
		ef, ok := walletExponent(unit)
		if !ok {
			return "", false, errors.New("Cannot convert NaN to a BigInt")
		}
		e = int(ef)
	}
	frac := m[3]
	if len(frac) > e {
		return "", false, nil
	}
	minor, _ := new(big.Int).SetString(m[2], 10)
	minor.Mul(minor, new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(e)), nil))
	if frac != "" {
		padded := frac + strings.Repeat("0", e-len(frac))
		f, _ := new(big.Int).SetString(padded, 10)
		minor.Add(minor, f)
	}
	sign := ""
	if m[1] == "-" && minor.Sign() != 0 {
		sign = "-"
	}
	return sign + minor.String(), true, nil
}

func isASCIILetter(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

// WalletExpectedTyped is the normalized value the human must type for this card and action (what a site or auditor recomputes);
// ok is false when the card asks for nothing or the value cannot be typed.
func WalletExpectedTyped(card map[string]any, action map[string]any) (string, bool, error) {
	if !jsTruthy(card["typed"]) {
		return "", false, nil
	}
	tm, _ := card["typed"].(map[string]any)
	path, _ := tm["path"].(string)
	v, err := walletValuesGet(action, path)
	if err != nil {
		return "", false, err
	}
	if tm["mode"] == "last4" {
		if s, ok := v.(string); ok && len(WalletLast4(s)) == 4 {
			return WalletLast4(s), true, nil
		}
		return "", false, nil
	}
	if jsIsSafeInteger(v) && !wIsNegZero(v) {
		f, _ := jsNum(v)
		return strconv.FormatInt(int64(f), 10), true, nil
	}
	return "", false, nil
}

// ---- agent-initiated clarification ----------------------------------------------------------------------------------------------

// WalletParseClarifyRequest is the strict parse of a clarification body: {ok: true, request} or {ok: false, error}. It never errors.
func WalletParseClarifyRequest(body any) map[string]any {
	no := func(e string) map[string]any { return map[string]any{"ok": false, "error": e} }
	bm, ok := body.(map[string]any)
	if !ok {
		return no("body must be an object")
	}
	for _, k := range wKeysOf(bm) {
		if k != "candidates" && k != "reason" {
			return no(fmt.Sprintf("unknown member \"%s\" (clarifications carry no text)", k))
		}
	}
	reason, isS := bm["reason"].(string)
	if !isS || walletIndexOf(WalletClarifyReasons, reason) < 0 {
		return no("reason must be one of " + strings.Join(WalletClarifyReasons, ", "))
	}
	cands, isL := bm["candidates"].([]any)
	if !isL || len(cands) == 0 || len(cands) > WalletMaxCandidates {
		return no(fmt.Sprintf("candidates must be 1..%d structured actions", WalletMaxCandidates))
	}
	out := []any{}
	for i, cv := range cands {
		c, ok := cv.(map[string]any)
		if !ok {
			return no(fmt.Sprintf("candidates[%d] must be an object", i))
		}
		for _, k := range wKeysOf(c) {
			if k != "verb" && k != "values" {
				return no(fmt.Sprintf("candidates[%d] has an unknown member \"%s\"", i, k))
			}
		}
		verb, isV := c["verb"].(string)
		if !isV || jsLen(verb) == 0 || jsLen(verb) > 128 {
			return no(fmt.Sprintf("candidates[%d].verb must be a non-empty string", i))
		}
		vm, ok := c["values"].(map[string]any)
		if !ok {
			return no(fmt.Sprintf("candidates[%d].values must be an object", i))
		}
		ents, _ := wEntries(vm)
		if len(ents) > walletMaxValues {
			return no(fmt.Sprintf("candidates[%d] has too many values", i))
		}
		values := map[string]any{}
		for _, e := range ents {
			if !walletPathRe.MatchString(e.k) {
				return no(fmt.Sprintf("candidates[%d] has a malformed path", i))
			}
			if !(e.k == "action.resource" || strings.HasPrefix(e.k, "action.params.")) {
				return no(fmt.Sprintf("candidates[%d].values may only name action.params.* or action.resource", i))
			}
			if wIsNumber(e.v) {
				if !jsIsSafeInteger(e.v) || wIsNegZero(e.v) {
					return no(fmt.Sprintf("candidates[%d].values.%s must be a safe integer", i, e.k))
				}
			} else if s, isStr := e.v.(string); !isStr || jsLen(s) > walletMaxString {
				return no(fmt.Sprintf("candidates[%d].values.%s must be a string (≤ %d) or an integer", i, e.k, walletMaxString))
			}
			values[e.k] = e.v
		}
		out = append(out, map[string]any{"verb": verb, "values": values})
	}
	return map[string]any{"ok": true, "request": map[string]any{"candidates": out, "reason": reason}}
}

// WalletInformationGain is the expected information gain of asking a cell with acceptance p under asymmetric noise (bits).
func WalletInformationGain(p, etaPos, etaNeg float64) float64 {
	py := p*(1-etaNeg) + (1-p)*etaPos
	return WalletBinEnt(py) - (p*WalletBinEnt(etaNeg) + (1-p)*WalletBinEnt(etaPos))
}

// WalletView is the grant view the channel reads: acceptance, vetoes and ceilings per cell, and the confirmed cells.
type WalletView struct {
	P              func(verb string, idx []int) float64
	Vetoed         func(verb string, idx []int) bool
	OutsideCeiling func(verb string, idx []int) bool
	Confirmed      func() []WalletCellRef
}

// WalletPlanInput is the input of the clarification planner. Lift (optional) maps a candidate to the outcome the wallet places.
type WalletPlanInput struct {
	Omega      *WalletOmega
	View       WalletView
	Candidates []any
	Lift       func(cand any) (any, error)
	Asked      map[string]bool
	EtaPos     float64
	EtaNeg     float64
	Harm       *WalletHarm
}

type walletPlanBest struct {
	index         int
	verb          string
	idx           []int
	p, ig, weight float64
	flat          int
}

// WalletPlanClarification gives dry-run verdicts for each candidate and the one cell worth asking, if any.
func WalletPlanClarification(in WalletPlanInput) (map[string]any, error) {
	harm := in.Harm
	if harm == nil {
		harm = WalletDefaultHarm
	}
	verdicts := []any{}
	var best *walletPlanBest
	seen := map[string]bool{}
	verdict := func(i int, v string) { verdicts = append(verdicts, map[string]any{"index": wN(i), "verdict": v}) }
	for index, cand := range in.Candidates {
		placed := cand
		if in.Lift != nil {
			var err error
			if placed, err = in.Lift(cand); err != nil {
				return nil, err
			}
		}
		vs, idx, err := WalletCellOfAction(in.Omega, placed)
		if err != nil {
			return nil, err
		}
		if vs == nil {
			verdict(index, "outside")
			continue
		}
		if in.View.OutsideCeiling(vs.Verb, idx) || in.View.Vetoed(vs.Verb, idx) {
			verdict(index, "denied")
			continue
		}
		p := in.View.P(vs.Verb, idx)
		if p <= 0 {
			verdict(index, "denied")
			continue
		}
		if p >= 1 {
			verdict(index, "admitted")
			continue
		}
		key := WalletCellKey(vs.Verb, idx)
		if in.Asked[key] {
			verdict(index, "asked")
			continue
		}
		verdict(index, "uncertain")
		if seen[key] {
			continue
		}
		seen[key] = true
		ig := WalletInformationGain(p, in.EtaPos, in.EtaNeg)
		mass, h := WalletCellStats(vs, idx, harm)
		c2 := &walletPlanBest{index: index, verb: vs.Verb, idx: idx, p: p, ig: ig, weight: mass * h, flat: WalletFlatIndex(vs, idx)}
		if best == nil || c2.ig > best.ig+1e-12 ||
			(math.Abs(c2.ig-best.ig) <= 1e-12 && (c2.weight > best.weight || (c2.weight == best.weight && c2.flat < best.flat))) {
			best = c2
		}
	}
	var ask any
	if best != nil {
		idxs := make([]any, len(best.idx))
		for i, x := range best.idx {
			idxs[i] = wN(x)
		}
		ask = map[string]any{"index": wN(best.index), "verb": best.verb, "idx": idxs, "p": best.p, "ig": best.ig}
	}
	return map[string]any{"verdicts": verdicts, "ask": ask}, nil
}
