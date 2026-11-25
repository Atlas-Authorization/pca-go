package pca

// Evaluation of AP2 open-mandate constraints against a closed mandate / checkout, following the AP2 documentation's evaluation rules.
// It is deliberately stricter than the official SDK in four places, each a fail-closed choice: a line-item requirement whose
// acceptable_items is empty matches nothing; the maximal flow must equal both the required and the carted quantity; a closed payment
// without execution_date is "immediate" (evaluated at the verification time); execution_date bounds are compared as instants.

import (
	"math"
	"regexp"
	"strconv"
)

// Ap2MerchantMatches is the merchant identity rule: ids when both carry one, else name and website.
func Ap2MerchantMatches(candidate, target any) bool {
	cid, tid := ap2Get(candidate, "id"), ap2Get(target, "id")
	if ap2Truthy(cid) && ap2Truthy(tid) {
		return ap2StrictEq(cid, tid)
	}
	cn, cw := ap2Get(candidate, "name"), ap2Get(candidate, "website")
	return ap2Truthy(cn) && ap2Truthy(cw) && ap2StrictEq(cn, ap2Get(target, "name")) && ap2StrictEq(cw, ap2Get(target, "website"))
}

func ap2SameJSON(a, b any) bool {
	if ap2IsU(b) {
		return false
	}
	return ap2StringifySorted(a) == ap2StringifySorted(b)
}

var ap2RFC3339 = regexp.MustCompile(`^(\d{4})-(\d{2})-(\d{2})(?:T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|([+-])(\d{2}):(\d{2})))?$`)

// ap2DaysFromCivil is the days since 1970-01-01 of a proleptic Gregorian date.
func ap2DaysFromCivil(y, m, d int64) int64 {
	if m <= 2 {
		y--
	}
	era := y / 400
	if y < 0 {
		era = (y - 399) / 400
	}
	yoe := y - era*400
	mp := (m + 9) % 12
	doy := (153*mp+2)/5 + d - 1
	doe := yoe*365 + yoe/4 - yoe/100 + doy
	return era*146097 + doe - 719468
}

// ap2CivilFromDays is the (year, month, day) of a day count since 1970-01-01.
func ap2CivilFromDays(z int64) (int64, int64, int64) {
	z += 719468
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
	if m > 12 {
		m -= 12
	}
	if m <= 2 {
		y++
	}
	return y, m, d
}

func ap2DaysInMonth(y, m int64) int64 {
	switch m {
	case 1, 3, 5, 7, 8, 10, 12:
		return 31
	case 4, 6, 9, 11:
		return 30
	}
	if y%4 == 0 && (y%100 != 0 || y%400 == 0) {
		return 29
	}
	return 28
}

// ap2ParseInstant is the epoch ms of an RFC 3339 instant, or ok=false. STRICT and independent of the host: YYYY-MM-DD (UTC midnight)
// or YYYY-MM-DDTHH:MM:SS[.fraction](Z|+HH:MM|-HH:MM), every component in range (real calendar day, hour <= 23, no leap second; the
// fraction is truncated to ms).
func ap2ParseInstant(v any) (float64, bool) {
	s, ok := v.(string)
	if !ok {
		return 0, false
	}
	m := ap2RFC3339.FindStringSubmatch(s)
	if m == nil {
		return 0, false
	}
	y, _ := strconv.ParseInt(m[1], 10, 64)
	mo, _ := strconv.ParseInt(m[2], 10, 64)
	d, _ := strconv.ParseInt(m[3], 10, 64)
	if mo < 1 || mo > 12 || d < 1 || d > ap2DaysInMonth(y, mo) {
		return 0, false
	}
	day := float64(ap2DaysFromCivil(y, mo, d)) * 86400000
	if m[4] == "" {
		return day, true
	}
	h, _ := strconv.ParseInt(m[4], 10, 64)
	mi, _ := strconv.ParseInt(m[5], 10, 64)
	se, _ := strconv.ParseInt(m[6], 10, 64)
	if h > 23 || mi > 59 || se > 59 {
		return 0, false
	}
	var ms int64
	if m[7] != "" {
		fr := m[7]
		if len(fr) > 3 {
			fr = fr[:3]
		}
		for len(fr) < 3 {
			fr += "0"
		}
		ms, _ = strconv.ParseInt(fr, 10, 64)
	}
	var offset int64
	if m[8] != "Z" {
		oh, _ := strconv.ParseInt(m[10], 10, 64)
		om, _ := strconv.ParseInt(m[11], 10, 64)
		if oh > 23 || om > 59 {
			return 0, false
		}
		sign := int64(-1)
		if m[9] == "+" {
			sign = 1
		}
		offset = sign * (oh*60 + om) * 60000
	}
	return day + float64(((h*60+mi)*60+se)*1000+ms-offset), true
}

// ap2PeriodStart is the start (epoch ms, UTC) of the calendar period of frequency that contains ms; NaN for an unknown frequency or
// a time outside the Date range.
func ap2PeriodStart(ms float64, frequency string) float64 {
	if math.IsNaN(ms) || math.Abs(ms) > 8.64e15 {
		return math.NaN()
	}
	t := int64(math.Trunc(ms))
	const dayMs = 86400000
	days := t / dayMs
	if t%dayMs < 0 {
		days--
	}
	y, mo, _ := ap2CivilFromDays(days)
	dateUTC := func(yy, mm int64) float64 {
		if yy >= 0 && yy <= 99 {
			yy += 1900 // Date.UTC maps the years 0..99 to 1900..1999
		}
		return float64(ap2DaysFromCivil(yy, mm, 1)) * dayMs
	}
	day := float64(float64(days) * dayMs)
	weekday := ((days+4)%7 + 7) % 7 // 0 = Sunday
	weekStart := day - float64(float64((weekday+6)%7)*dayMs)
	switch frequency {
	case "ON_DEMAND":
		return 0
	case "DAILY":
		return day
	case "WEEKLY":
		return weekStart
	case "BIWEEKLY":
		const week = 7 * dayMs
		epochMonday := float64(-3 * dayMs)
		return epochMonday + float64(math.Floor((weekStart-epochMonday)/(2*week))*2*week)
	case "MONTHLY":
		return dateUTC(y, mo)
	case "QUARTERLY":
		return dateUTC(y, (mo-1)/3*3+1)
	case "ANNUALLY":
		return dateUTC(y, 1)
	}
	return math.NaN()
}

// Ap2PaymentCheckOptions carries the verifier's view for checking a closed payment against an open one.
type Ap2PaymentCheckOptions struct {
	// OpenCheckoutHash is the sd_hash of the open checkout mandate this payment is chained to (for payment.reference).
	OpenCheckoutHash string
	// Context is the usage state (totalAmount, totalUses, lastUsedDate?); required for payment.budget and recurrence. nil = absent.
	Context map[string]any
	// Now is the verification time, epoch seconds.
	Now float64
}

// ap2ContextProblem: a usage context with a NaN, negative or fractional counter would make the cap comparisons fail open.
func ap2ContextProblem(c map[string]any) string {
	if !ap2IsNonNeg(ap2Get(c, "totalAmount")) || !ap2IsNonNeg(ap2Get(c, "totalUses")) {
		return "mandate context must carry non-negative integer totalAmount, totalUses and lastUsedDate"
	}
	if l := ap2Get(c, "lastUsedDate"); !ap2IsU(l) && !ap2IsNonNeg(l) {
		return "mandate context must carry non-negative integer totalAmount, totalUses and lastUsedDate"
	}
	return ""
}

func ap2Round(x float64) float64 {
	r := math.Floor(x)
	if x-r >= 0.5 {
		return r + 1
	}
	return r
}

func ap2Items(v any) []any {
	l, _ := v.([]any)
	return l
}

func ap2EvaluatePayment(c map[string]any, closed map[string]any, o Ap2PaymentCheckOptions) []string {
	amt := ap2Get(closed, "payment_amount")
	payee := ap2Get(closed, "payee")
	ts, _ := ap2Get(c, "type").(string)
	switch ts {
	case "payment.amount_range":
		var v []string
		if !ap2StrictEq(ap2Get(amt, "currency"), ap2Get(c, "currency")) {
			v = append(v, "currency mismatch: expected "+ap2Str(ap2Get(c, "currency"))+", got "+ap2Str(ap2Get(amt, "currency")))
		}
		if !finite(ap2N(ap2Get(amt, "amount"))) {
			v = append(v, "amount "+ap2Str(ap2Get(amt, "amount"))+" is not finite")
		}
		if mn := ap2Get(c, "min"); !ap2IsU(mn) && !(ap2N(ap2Get(amt, "amount")) >= ap2N(mn)) {
			v = append(v, "amount "+ap2Str(ap2Get(amt, "amount"))+" below minimum "+ap2Str(mn))
		}
		if !(ap2N(ap2Get(amt, "amount")) <= ap2N(ap2Get(c, "max"))) {
			v = append(v, "amount "+ap2Str(ap2Get(amt, "amount"))+" exceeds maximum "+ap2Str(ap2Get(c, "max")))
		}
		return v
	case "payment.allowed_payees":
		for _, m := range ap2Items(ap2Get(c, "allowed")) {
			if Ap2MerchantMatches(m, payee) {
				return nil
			}
		}
		return []string{"payee " + ap2Str(ap2Get(payee, "name")) + " is not in the allowed list"}
	case "payment.allowed_payment_instruments":
		inst := ap2Get(closed, "payment_instrument")
		for _, i := range ap2Items(ap2Get(c, "allowed")) {
			if ap2StrictEq(ap2Get(i, "id"), ap2Get(inst, "id")) {
				return nil
			}
		}
		return []string{"payment instrument " + ap2Str(ap2Get(inst, "id")) + " is not in the allowed list"}
	case "payment.allowed_pisps":
		p := ap2Get(closed, "pisp")
		if !ap2Truthy(p) {
			return []string{"missing PISP in the closed mandate"}
		}
		for _, a := range ap2Items(ap2Get(c, "allowed")) {
			if ap2StrictEq(ap2Get(a, "legal_name"), ap2Get(p, "legal_name")) && ap2StrictEq(ap2Get(a, "brand_name"), ap2Get(p, "brand_name")) &&
				ap2StrictEq(ap2Get(a, "domain_name"), ap2Get(p, "domain_name")) {
				return nil
			}
		}
		return []string{"PISP is not in the allowed list"}
	case "payment.reference":
		if o.OpenCheckoutHash == "" {
			return []string{"openCheckoutHash is required to evaluate a payment.reference constraint"}
		}
		if ap2StrictEq(o.OpenCheckoutHash, ap2Get(c, "conditional_transaction_id")) {
			return nil
		}
		return []string{"payment.reference does not match the open checkout mandate hash"}
	case "payment.budget":
		if !ap2StrictEq(ap2Get(amt, "currency"), ap2Get(c, "currency")) {
			return []string{"budget currency mismatch: expected " + ap2Str(ap2Get(c, "currency")) + ", got " + ap2Str(ap2Get(amt, "currency"))}
		}
		// The official SDK converts the budget with int(max * 100) for every currency; this reads it the same way, and the issuing
		// side (Ap2BudgetMax) chooses max so that this reading is never above the PCA cap.
		if o.Context == nil {
			return []string{"mandate context is required to evaluate a budget"}
		}
		if bad := ap2ContextProblem(o.Context); bad != "" {
			return []string{bad}
		}
		scaled := float64(ap2N(ap2Get(c, "max")) * 100)
		maxMinor := ap2Round(scaled)
		if !(finite(scaled) && finite(maxMinor) && math.Abs(scaled-maxMinor) <= 1e-6) {
			return []string{"budget.max is not a whole number of minor units"}
		}
		spend := ap2N(ap2Get(o.Context, "totalAmount")) + ap2N(ap2Get(amt, "amount"))
		if !(finite(spend) && finite(maxMinor) && spend <= maxMinor) {
			return []string{"cumulative spend " + jsNumberString(spend) + " exceeds budget " + jsNumberString(maxMinor) + " (past spend " + ap2Str(ap2Get(o.Context, "totalAmount")) + ")"}
		}
		return nil
	case "payment.agent_recurrence":
		var v []string
		if !ap2OneOf(Ap2Frequencies, ap2Get(c, "frequency")) {
			return []string{"unknown recurrence frequency"}
		}
		if o.Context != nil {
			if bad := ap2ContextProblem(o.Context); bad != "" {
				return []string{bad}
			}
		}
		if mo := ap2Get(c, "max_occurrences"); !ap2IsU(mo) {
			if o.Context == nil {
				return []string{"mandate context is required to evaluate recurrence limits"}
			}
			if !(ap2N(ap2Get(o.Context, "totalUses")) < ap2N(mo)) {
				v = append(v, "maximum occurrences exceeded: "+ap2Str(ap2Get(o.Context, "totalUses"))+" >= "+ap2Str(mo))
			}
		}
		if !ap2StrictEq(ap2Get(c, "frequency"), "ON_DEMAND") {
			if o.Context == nil {
				return []string{"mandate context is required to evaluate recurrence frequency"}
			}
			if last := ap2Get(o.Context, "lastUsedDate"); !ap2IsU(last) {
				freq, _ := ap2Get(c, "frequency").(string)
				if !(float64(ap2N(last)*1000) < ap2PeriodStart(float64(o.Now*1000), freq)) {
					v = append(v, "already used in the current "+ap2Str(ap2Get(c, "frequency"))+" period")
				}
			}
		}
		return v
	case "payment.execution_date":
		var at float64
		var ok bool
		if ed := ap2Get(closed, "execution_date"); !ap2IsU(ed) {
			at, ok = ap2ParseInstant(ed)
		} else {
			at, ok = float64(o.Now*1000), true
		}
		if !ok || !finite(at) {
			return []string{"execution_date " + ap2Str(ap2Get(closed, "execution_date")) + " is not a valid instant"}
		}
		var v []string
		for _, kb := range []struct {
			key    string
			before bool
		}{{"not_before", true}, {"not_after", false}} {
			bound := ap2Get(c, kb.key)
			if ap2IsU(bound) {
				continue
			}
			b, bok := ap2ParseInstant(bound)
			switch {
			case !bok:
				v = append(v, kb.key+" "+ap2Str(bound)+" is not a valid instant")
			case kb.before && !(at >= b), !kb.before && !(at <= b):
				side := "after"
				if kb.before {
					side = "before"
				}
				v = append(v, "execution date is "+side+" the allowed window ("+kb.key+" "+ap2Str(bound)+")")
			}
		}
		return v
	}
	return []string{"unknown constraint type " + ap2Str(ap2Get(c, "type"))}
}

// Ap2CheckPaymentConstraints lists the violations of the open payment mandate's constraints and pre-set claims by closed (empty =
// satisfied).
func Ap2CheckPaymentConstraints(open, closed map[string]any, o Ap2PaymentCheckOptions) []string {
	var v []string
	cpayee := ap2Get(closed, "payee")
	if op := ap2Get(open, "payee"); !ap2IsU(op) && !Ap2MerchantMatches(op, cpayee) {
		v = append(v, "pre-set payee mismatch: expected "+ap2Str(ap2Get(op, "name"))+", got "+ap2Str(ap2Get(cpayee, "name")))
	}
	if x := ap2Get(open, "payment_amount"); !ap2IsU(x) && !ap2SameJSON(x, ap2Get(closed, "payment_amount")) {
		v = append(v, "pre-set payment_amount mismatch")
	}
	if x := ap2Get(open, "payment_instrument"); !ap2IsU(x) && !ap2SameJSON(x, ap2Get(closed, "payment_instrument")) {
		v = append(v, "pre-set payment_instrument mismatch")
	}
	if x := ap2Get(open, "pisp"); !ap2IsU(x) && !ap2SameJSON(x, ap2Get(closed, "pisp")) {
		v = append(v, "pre-set pisp mismatch")
	}
	if x := ap2Get(open, "execution_date"); !ap2IsU(x) && !ap2StrictEq(x, ap2Get(closed, "execution_date")) {
		v = append(v, "pre-set execution_date mismatch")
	}
	constraints, ok := ap2Get(open, "constraints").([]any)
	if !ok {
		return append(v, "constraints: must be an array")
	}
	types := map[string]bool{}
	for _, c := range constraints {
		if t, ok := ap2Get(c, "type").(string); ok {
			types[t] = true
		}
	}
	if types["payment.agent_recurrence"] {
		if !types["payment.amount_range"] {
			v = append(v, "payment.agent_recurrence requires a payment.amount_range constraint")
		}
		if !types["payment.budget"] {
			v = append(v, "payment.agent_recurrence requires a payment.budget constraint")
		}
	}
	for _, c := range constraints {
		cm, _ := ap2Obj(c)
		v = append(v, ap2EvaluatePayment(cm, closed, o)...)
	}
	return v
}

// ---- checkout side -----------------------------------------------------------------------------------------------------

// Ap2ProjectCheckout validates and projects the checkout payload (the checkout_jwt payload) the constraints read: id, currency,
// line_items, totals and an optional merchant.
func Ap2ProjectCheckout(payload map[string]any) (map[string]any, error) {
	bad := func(m string) error { return ap2Fail("checkout_jwt payload: %s", m) }
	id, ok := ap2Get(payload, "id").(string)
	if !ok || id == "" {
		return nil, bad("id is required")
	}
	cur, ok := ap2Get(payload, "currency").(string)
	if !ok || !ap2Alpha3(cur) {
		return nil, bad("currency must be ISO 4217")
	}
	lis, ok := ap2Get(payload, "line_items").([]any)
	if !ok || len(lis) == 0 {
		return nil, bad("line_items must be a non-empty array")
	}
	tots, ok := ap2Get(payload, "totals").([]any)
	if !ok {
		return nil, bad("totals must be an array")
	}
	lines := make([]any, 0, len(lis))
	for i, x := range lis {
		is := strconv.Itoa(i)
		li, ok := ap2Obj(x)
		if !ok || !ap2IsStr(ap2Get(li, "id")) {
			return nil, bad("line_items[" + is + "] is malformed")
		}
		item, ok := ap2Obj(ap2Get(li, "item"))
		if !ok {
			return nil, bad("line_items[" + is + "] is malformed")
		}
		price := ap2Get(item, "price")
		pf, _ := jsNum(price)
		if !ap2IsStr(ap2Get(item, "id")) || !ap2IsStr(ap2Get(item, "title")) || !jsIsSafeInteger(price) || pf < 0 || (pf == 0 && math.Signbit(pf)) {
			return nil, bad("line_items[" + is + "].item needs id, title and integer minor-unit price")
		}
		q := ap2Get(li, "quantity")
		if qf, _ := jsNum(q); !jsIsSafeInteger(q) || qf < 1 {
			return nil, bad("line_items[" + is + "].quantity must be a positive integer")
		}
		lines = append(lines, ap2Map("id", li["id"], "item", ap2Map("id", item["id"], "title", item["title"], "price", price), "quantity", q))
	}
	totals := make([]any, 0, len(tots))
	for i, x := range tots {
		t, ok := ap2Obj(x)
		amount := ap2Get(t, "amount")
		af, _ := jsNum(amount)
		if !ok || !ap2IsStr(ap2Get(t, "type")) || !jsIsSafeInteger(amount) || (af == 0 && math.Signbit(af)) {
			return nil, bad("totals[" + strconv.Itoa(i) + "] is malformed")
		}
		totals = append(totals, ap2Map("type", t["type"], "amount", amount))
	}
	out := ap2New().set("id", id).set("currency", cur).set("line_items", lines).set("totals", totals)
	if mv := ap2Get(payload, "merchant"); !ap2IsU(mv) {
		m, ok := ap2Obj(mv)
		if !ok || !ap2IsStr(ap2Get(m, "id")) || !ap2IsStr(ap2Get(m, "name")) {
			return nil, bad("merchant needs id and name")
		}
		mb := ap2New().set("id", m["id"]).set("name", m["name"])
		if w, ok := ap2Get(m, "website").(string); ok {
			mb.set("website", w)
		}
		out.set("merchant", mb.done())
	}
	return out.done(), nil
}

// Ap2CheckoutTotal is the checkout's single "total" entry in minor units; ok is false when absent or ambiguous.
func Ap2CheckoutTotal(c map[string]any) (any, bool) {
	var found any
	n := 0
	for _, t := range ap2Items(ap2Get(c, "totals")) {
		if ap2StrictEq(ap2Get(t, "type"), "total") {
			found = ap2Get(t, "amount")
			n++
		}
	}
	return found, n == 1
}

// ap2LineItemViolations is a maximal-flow assignment of cart quantities to requirement slots (Edmonds-Karp on the bipartite graph of
// the documentation): satisfied iff the flow equals both the required and the carted total.
func ap2LineItemViolations(cart []any, reqs []any) []string {
	qty := map[string]float64{}
	var skus []string
	for _, li := range cart {
		id, _ := ap2Get(ap2Get(li, "item"), "id").(string)
		if _, seen := qty[id]; !seen {
			skus = append(skus, id)
		}
		qty[id] += ap2N(ap2Get(li, "quantity"))
	}
	const inf = float64(9007199254740991)
	n := len(skus)
	src, sink := 0, 1+n+len(reqs)
	cap := make([]map[int]float64, sink+1)
	for i := range cap {
		cap[i] = map[int]float64{}
	}
	add := func(u, v int, c float64) {
		cap[u][v] += c
		if _, ok := cap[v][u]; !ok {
			cap[v][u] = 0
		}
	}
	for i, s := range skus {
		add(src, 1+i, qty[s])
	}
	required := 0.0
	for j, r := range reqs {
		q := ap2N(ap2Get(r, "quantity"))
		add(1+n+j, sink, q)
		ok := map[string]bool{}
		for _, a := range ap2Items(ap2Get(r, "acceptable_items")) {
			if id, isStr := ap2Get(a, "id").(string); isStr {
				ok[id] = true
			}
		}
		for i, s := range skus {
			if ok[s] {
				add(1+i, 1+n+j, inf)
			}
		}
		required += q
	}
	flow := 0.0
	for {
		parent := map[int]int{src: src}
		queue := []int{src}
		for h := 0; h < len(queue); h++ {
			if _, found := parent[sink]; found {
				break
			}
			u := queue[h]
			for v, c := range cap[u] {
				if _, seen := parent[v]; c > 0 && !seen {
					parent[v] = u
					queue = append(queue, v)
				}
			}
		}
		if _, found := parent[sink]; !found {
			break
		}
		push := inf
		for v := sink; v != src; v = parent[v] {
			push = math.Min(push, cap[parent[v]][v])
		}
		for v := sink; v != src; v = parent[v] {
			u := parent[v]
			cap[u][v] -= push
			cap[v][u] += push
		}
		flow += push
	}
	carted := 0.0
	for _, s := range skus {
		carted += qty[s]
	}
	if flow == required && flow == carted {
		return nil
	}
	return []string{"line items do not satisfy the constraint: assigned " + jsNumberString(flow) + " of " + jsNumberString(required) + " required and " + jsNumberString(carted) + " carted units"}
}

func ap2EvaluateCheckout(c any, checkout map[string]any) []string {
	switch t := ap2Get(c, "type"); {
	case ap2StrictEq(t, "checkout.allowed_merchants"):
		m := ap2Get(checkout, "merchant")
		if !ap2Truthy(m) {
			return []string{"missing merchant in the checkout"}
		}
		for _, a := range ap2Items(ap2Get(c, "allowed")) {
			if Ap2MerchantMatches(a, m) {
				return nil
			}
		}
		return []string{"merchant " + ap2Str(ap2Get(m, "name")) + " is not in the allowed list"}
	case ap2StrictEq(t, "checkout.line_items"):
		cart := ap2Items(ap2Get(checkout, "line_items"))
		if len(cart) == 0 {
			return []string{"empty cart does not satisfy a line_items constraint"}
		}
		return ap2LineItemViolations(cart, ap2Items(ap2Get(c, "items")))
	default:
		return []string{"unknown constraint type " + ap2Str(t)}
	}
}

// Ap2CheckCheckoutConstraints lists the violations of the open checkout mandate's constraints by checkout (empty = satisfied).
func Ap2CheckCheckoutConstraints(open, checkout map[string]any) []string {
	var v []string
	for _, c := range ap2Items(ap2Get(open, "constraints")) {
		v = append(v, ap2EvaluateCheckout(c, checkout)...)
	}
	return v
}
