package pca

// OpenTelemetry-style instrumentation for PCA: wrap a verification guard so every decision emits a span and two metrics.
// Nothing from an OpenTelemetry module is imported: pass any Tracer-like and Meter-like object (small interfaces below). This
// observes, it never decides: a tracer, meter or redactor that panics never changes what the guard returned.

import (
	"math"
	"regexp"
)

const (
	OtelStatusOK    = 1
	OtelStatusError = 2
	otelMaxText     = 256
)

var (
	otelRedactJWT    = regexp.MustCompile(`\beyJ[\w-]{5,}\.[\w-]{5,}\.[\w-]*`)
	otelRedactAuth   = regexp.MustCompile(`\b(` + siemCI("authorization") + `["']?[` + siemWS + `]*[:=][` + siemWS + `]*)[^\n"']*`)
	otelRedactScheme = regexp.MustCompile(`\b(` + siemCI("bearer") + `|` + siemCI("basic") + `|` + siemCI("token") + `)[` + siemWS + `]+[\w.~+/=-]{6,}`)
	otelRedactURL    = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.-]*://)[^` + siemWS + `/@]*:[^` + siemWS + `/@]*@`)
	otelRedactKV     = regexp.MustCompile(`\b((?:` + siemCI("token") + `|` + siemCI("secret") + `|` + siemCI("password") + `|` + siemCI("passwd") + `|` + siemCI("pwd") +
		`|` + siemCI("api") + `[_-]?` + siemCI("key") + `|` + siemCI("key") + `|` + siemCI("signature") + `|` + siemCI("sig") + `|` + siemCI("credential") + `|` + siemCI("auth") +
		`)["']?[` + siemWS + `]*[:=][` + siemWS + `]*)("[^"]*"|'[^']*'|[^` + siemWS + `"'&,;]+)`)
	otelRedactRun = regexp.MustCompile(`[A-Za-z0-9_-]{32,}`)
)

// OtelRedactSecrets removes what looks like a credential from text bound for telemetry (JWTs, authorization values, Bearer /
// Basic / Token credentials, URL userinfo, name=value pairs for secret-like names, 32+ character base64url / hex runs) and cuts
// the result to 256 UTF-16 units.
func OtelRedactSecrets(text string) string {
	t := otelRedactJWT.ReplaceAllString(text, "[redacted]")
	t = otelRedactAuth.ReplaceAllString(t, "${1}[redacted]")
	t = otelRedactScheme.ReplaceAllString(t, "${1} [redacted]")
	t = otelRedactURL.ReplaceAllString(t, "${1}[redacted]@")
	t = otelRedactKV.ReplaceAllStringFunc(t, func(m string) string {
		sub := otelRedactKV.FindStringSubmatch(m)
		val := sub[2]
		q := ""
		if val != "" && (val[0] == '"' || val[0] == '\'') {
			q = val[:1]
		}
		return sub[1] + q + "[redacted]" + q
	})
	t = otelRedactRun.ReplaceAllString(t, "[redacted]")
	if jsLen(t) > otelMaxText {
		return siemSlice(t, otelMaxText) + "..."
	}
	return t
}

func otelGet(o any, k string) any {
	m, _ := o.(map[string]any)
	if m == nil {
		return nil
	}
	return m[k]
}

func otelNum(v any) (float64, bool) {
	f, ok := jsNum(v)
	return f, ok && !math.IsNaN(f) && !math.IsInf(f, 0)
}

// otelFirstReason is result?.verdict?.reasons?.[0], including JavaScript indexing into a string or an object keyed "0".
func otelFirstReason(result any) any {
	rs := otelGet(otelGet(result, "verdict"), "reasons")
	switch t := rs.(type) {
	case []any:
		if len(t) == 0 {
			return nil
		}
		return t[0]
	case string:
		u := utf16Units(t)
		if len(u) == 0 {
			return nil
		}
		return siemSlice(t, 1)
	}
	return otelGet(rs, "0")
}

func otelNumOut(f float64) any {
	if f == 0 {
		f = 0 // JSON has no negative zero
	}
	return jsNumber(f)
}

// OtelPcaSpanAttributes are the span attributes for a guard result (a parsed JSON object); absent fields are omitted and
// pca.reason is added on deny only. Anything but an explicit ok is reported as a deny. A nil redact is OtelRedactSecrets.
func OtelPcaSpanAttributes(result any, redact func(string) string) map[string]any {
	if redact == nil {
		redact = OtelRedactSecrets
	}
	ok := otelGet(result, "ok") == true
	attrs := map[string]any{"pca.decision": "deny"}
	if ok {
		attrs["pca.decision"] = "allow"
	}
	if f, isNum := otelNum(otelGet(result, "status")); isNum {
		attrs["pca.status"] = otelNumOut(f)
	}
	verdict := otelGet(result, "verdict")
	if f, isNum := otelNum(otelGet(otelGet(verdict, "requiredThreshold"), "t")); isNum {
		attrs["pca.tier"] = otelNumOut(f)
	}
	if f, isNum := otelNum(otelGet(verdict, "r")); isNum {
		attrs["pca.risk"] = otelNumOut(f)
	}
	action := otelGet(otelGet(result, "pcactn"), "action")
	if s, isStr := otelGet(action, "verb").(string); isStr {
		attrs["pca.verb"] = redact(s)
	}
	if s, isStr := otelGet(action, "resource").(string); isStr {
		attrs["pca.resource"] = redact(s)
	}
	if !ok {
		if s, isStr := otelFirstReason(result).(string); isStr {
			attrs["pca.reason"] = redact(s)
		}
	}
	return attrs
}

// OtelSpan is the slice of a tracing span the instrumentation uses. Message is nil when the status carries none.
type OtelSpan interface {
	SetAttribute(key string, value any)
	SetStatus(code int, message *string)
	RecordException(message string)
	End()
}

// OtelTracer starts spans.
type OtelTracer interface{ StartSpan(name string) OtelSpan }

// OtelCounter and OtelHistogram are the instruments the guard reports to.
type OtelCounter interface {
	Add(v float64, attrs map[string]string)
}
type OtelHistogram interface {
	Record(v float64, attrs map[string]string)
}

// OtelMeter creates instruments.
type OtelMeter interface {
	CreateCounter(name string) OtelCounter
	CreateHistogram(name string) OtelHistogram
}

// OtelOptions configures OtelInstrumentGuard; every field is optional (SpanName nil = "pca.verify").
type OtelOptions struct {
	Tracer   OtelTracer
	Meter    OtelMeter
	SpanName *string
	Redact   func(string) string
}

// OtelGuard is a verification guard: one request in, a result (the parsed JSON-like verdict object) or an error out.
type OtelGuard func(req any) (any, error)

func otelSafe(f func()) {
	defer func() { _ = recover() }() // the decision is the guard's, not the exporter's
	f()
}

// OtelInstrumentGuard wraps a guard so each decision emits a span (default name pca.verify) and metrics (a pca.verifications
// counter and a pca.verify.risk histogram, created once). The wrapper returns the guard's result unchanged and its error after
// recording a scrubbed copy on the span; with no tracer and no meter it is a transparent pass-through. Creating an instrument may
// panic (the wrap fails, as in the reference); once wrapped, nothing the exporter does can alter the outcome.
func OtelInstrumentGuard(guard OtelGuard, opts OtelOptions) OtelGuard {
	name := "pca.verify"
	if opts.SpanName != nil {
		name = *opts.SpanName
	}
	red := opts.Redact
	if red == nil {
		red = OtelRedactSecrets
	}
	var counter OtelCounter
	var histogram OtelHistogram
	if opts.Meter != nil {
		counter = opts.Meter.CreateCounter("pca.verifications")
		histogram = opts.Meter.CreateHistogram("pca.verify.risk")
	}
	start := func() OtelSpan {
		var span OtelSpan
		if opts.Tracer != nil {
			otelSafe(func() { span = opts.Tracer.StartSpan(name) })
		}
		return span
	}
	okPath := func(span OtelSpan, result any) {
		allowed := otelGet(result, "ok") == true
		if span != nil {
			otelSafe(func() {
				attrs := OtelPcaSpanAttributes(result, red)
				for _, k := range []string{"pca.decision", "pca.status", "pca.tier", "pca.risk", "pca.verb", "pca.resource", "pca.reason"} {
					if v, ok := attrs[k]; ok {
						span.SetAttribute(k, v)
					}
				}
				if allowed {
					span.SetStatus(OtelStatusOK, nil)
				} else if reason, isStr := otelFirstReason(result).(string); isStr {
					msg := red(reason)
					span.SetStatus(OtelStatusError, &msg)
				} else {
					span.SetStatus(OtelStatusError, nil)
				}
			})
		}
		decision := "deny"
		if allowed {
			decision = "allow"
		}
		if counter != nil {
			otelSafe(func() { counter.Add(1, map[string]string{"decision": decision}) })
		}
		if histogram != nil {
			if r, isNum := otelNum(otelGet(otelGet(result, "verdict"), "r")); isNum {
				otelSafe(func() { histogram.Record(r, map[string]string{"decision": decision}) })
			}
		}
	}
	errPath := func(span OtelSpan, msg string) {
		if span == nil {
			return
		}
		otelSafe(func() {
			// a fresh message: the original may carry credentials
			clean := red(msg)
			span.RecordException(clean)
			span.SetStatus(OtelStatusError, &clean)
		})
	}
	return func(req any) (res any, err error) {
		span := start()
		defer func() {
			if span != nil {
				otelSafe(span.End)
			}
		}()
		defer func() {
			if p := recover(); p != nil {
				errPath(span, otelPanicText(p))
				panic(p)
			}
		}()
		res, err = guard(req)
		if err != nil {
			errPath(span, err.Error())
			return res, err
		}
		okPath(span, res)
		return res, nil
	}
}

func otelPanicText(p any) string {
	switch t := p.(type) {
	case error:
		return t.Error()
	case string:
		return t
	}
	return "panic"
}
