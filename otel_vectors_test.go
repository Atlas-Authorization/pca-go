package pca

// Replays the OpenTelemetry instrumentation corpus: redactSecrets, pcaSpanAttributes and instrumentGuard over scripted tracers,
// meters and guards (call order of every span / metric event included).
//
// Known divergence: the "upper" redactor uses strings.ToUpper, which differs from String.toUpperCase on a few special-casing
// characters (a sharp s expands in JavaScript only).

import (
	"errors"
	"strings"
	"testing"
)

type otelRec struct {
	events []any
	tm, mm string
}

func (r *otelRec) boom(cond bool) {
	if cond {
		panic("exporter boom")
	}
}

type otelRecSpan struct{ r *otelRec }

func (s otelRecSpan) SetAttribute(k string, v any) {
	s.r.events = append(s.r.events, map[string]any{"ev": "setAttribute", "k": k, "v": v})
	s.r.boom(s.r.tm == "attrThrows")
}
func (s otelRecSpan) SetStatus(code int, msg *string) {
	e := map[string]any{"ev": "setStatus", "code": jsNumber(float64(code))}
	if msg != nil {
		e["message"] = *msg
	}
	s.r.events = append(s.r.events, e)
	s.r.boom(s.r.tm == "statusThrows")
}
func (s otelRecSpan) RecordException(m string) {
	s.r.events = append(s.r.events, map[string]any{"ev": "recordException", "message": m, "noStack": true})
	s.r.boom(s.r.tm == "recordThrows")
}
func (s otelRecSpan) End() {
	s.r.events = append(s.r.events, map[string]any{"ev": "end"})
	s.r.boom(s.r.tm == "endThrows")
}

type otelRecTracer struct{ r *otelRec }

func (t otelRecTracer) StartSpan(name string) OtelSpan {
	t.r.events = append(t.r.events, map[string]any{"ev": "startSpan", "name": name})
	t.r.boom(t.r.tm == "startThrows")
	return otelRecSpan{t.r}
}

type otelRecCounter struct{ r *otelRec }

func (c otelRecCounter) Add(v float64, a map[string]string) {
	c.r.events = append(c.r.events, map[string]any{"ev": "add", "v": jsNumber(v), "a": otelAttrsOut(a)})
	c.r.boom(c.r.mm == "addThrows")
}

type otelRecHistogram struct{ r *otelRec }

func (h otelRecHistogram) Record(v float64, a map[string]string) {
	h.r.events = append(h.r.events, map[string]any{"ev": "record", "v": jsNumber(v), "a": otelAttrsOut(a)})
	h.r.boom(h.r.mm == "recordThrows")
}

type otelRecMeter struct{ r *otelRec }

func (m otelRecMeter) CreateCounter(n string) OtelCounter {
	m.r.events = append(m.r.events, map[string]any{"ev": "createCounter", "name": n})
	m.r.boom(m.r.mm == "createThrows")
	return otelRecCounter{m.r}
}
func (m otelRecMeter) CreateHistogram(n string) OtelHistogram {
	m.r.events = append(m.r.events, map[string]any{"ev": "createHistogram", "name": n})
	return otelRecHistogram{m.r}
}

func otelAttrsOut(a map[string]string) map[string]any {
	o := map[string]any{}
	for k, v := range a {
		o[k] = v
	}
	return o
}

var otelModes = map[string]func(string) string{
	"identity": func(s string) string { return s },
	"upper":    strings.ToUpper,
	"brackets": func(s string) string { return "<" + s + ">" },
}

func otelScenario(spec map[string]any) (any, error) {
	r := &otelRec{}
	r.tm, _ = spec["tracerMode"].(string)
	r.mm, _ = spec["meterMode"].(string)
	if r.tm == "" {
		r.tm = "ok"
	}
	if r.mm == "" {
		r.mm = "ok"
	}
	g := vecObj(spec["guard"])
	guard := func(any) (any, error) {
		if m, ok := g["throws"].(string); ok {
			return nil, errors.New(m)
		}
		return g["result"], nil
	}
	opts := OtelOptions{}
	if spec["tracer"] == true {
		opts.Tracer = otelRecTracer{r}
	}
	if spec["meter"] == true {
		opts.Meter = otelRecMeter{r}
	}
	if s, ok := spec["spanName"].(string); ok {
		opts.SpanName = &s
	}
	if m, ok := spec["redact"].(string); ok {
		opts.Redact = otelModes[m]
	}
	var wrapped OtelGuard
	if p := baseCall(func() { wrapped = OtelInstrumentGuard(guard, opts) }); p != "" {
		return map[string]any{"wrap": p, "events": otelEvents(r)}, nil
	}
	res, err := wrapped("req")
	out := map[string]any{"events": otelEvents(r)}
	if err != nil {
		out["outcome"] = map[string]any{"threw": err.Error()}
	} else {
		out["outcome"] = map[string]any{"result": res}
	}
	return out, nil
}

func otelEvents(r *otelRec) []any {
	if r.events == nil {
		return []any{}
	}
	return r.events
}

func TestOtelReferenceVectors(t *testing.T) {
	replayVectors(t, "ref-otel.json.gz", map[string]vecFn{
		"redactSecrets": func(args []any) (any, error) {
			s, ok := vecArg(args, 0).(string)
			if !ok {
				return nil, vecSkip("non-string text")
			}
			return OtelRedactSecrets(s), nil
		},
		"pcaSpanAttributes": func(args []any) (any, error) {
			var red func(string) string
			if m, ok := vecArg(args, 1).(string); ok {
				red = otelModes[m]
			}
			return OtelPcaSpanAttributes(vecArg(args, 0), red), nil
		},
		"instrumentScenario": func(args []any) (any, error) { return otelScenario(vecObj(vecArg(args, 0))) },
	})
}
