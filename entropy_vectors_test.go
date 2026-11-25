package pca

// Replays the reference corpus of the entropy module: HTTP QRNG source (injected transport), health tests and cutoffs, the combiner,
// SecureSeed and the key-pair helper. The local CSPRNG, every QRNG source and every transport are injected by the case. A reference
// refusal requires an error; messages that start with "QRNG", "HttpQrngSource", "mixEntropy" or "secureSeed" are compared exactly.
// Cases whose argument is JS type confusion (a string or null where a number or bytes are needed) or a non-integer count, which a
// typed Go call cannot receive, are skipped (and still counted). An explicit 0 for a size is passed as -1, since 0 selects the default.

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"strconv"
	"strings"
	"sync"
	"testing"
)

const entropyCorpusCases = 562

type entSrc struct {
	name     string
	kind     string
	value    []byte
	msg      string
	requests []any
}

type entStrErr struct{ msg string }

func (e *entStrErr) Error() string { return e.msg }

func (s *entSrc) Name() string { return s.name }

func (s *entSrc) Fetch(n int) ([]byte, error) {
	s.requests = append(s.requests, n)
	switch s.kind {
	case "bytes":
		return s.value, nil
	case "reject", "throwSync":
		return nil, errors.New(s.msg)
	case "rejectString":
		return nil, &entStrErr{s.msg}
	}
	return nil, errors.New("unsupported source kind " + s.kind)
}

func entNum(v any) (float64, bool) {
	if m := vecObj(v); m != nil {
		switch m["$num"] {
		case "NaN":
			return math.NaN(), true
		case "Infinity":
			return math.Inf(1), true
		case "-Infinity":
			return math.Inf(-1), true
		}
		return 0, false
	}
	return jsNum(v)
}

// entSize reads a size option: ok=false for a value a Go int cannot carry (fraction, NaN, Infinity, huge, non-number); 0 becomes -1.
func entSize(v any) (int, bool) {
	f, ok := entNum(v)
	if !ok || f != math.Trunc(f) || math.Abs(f) > 1<<40 {
		return 0, false
	}
	if f == 0 {
		return -1, true
	}
	return int(f), true
}

func entNumOut(f float64) any {
	switch {
	case math.IsNaN(f):
		return map[string]any{"$num": "NaN"}
	case math.IsInf(f, 1):
		return map[string]any{"$num": "Infinity"}
	case math.IsInf(f, -1):
		return map[string]any{"$num": "-Infinity"}
	}
	return f
}

type entRes struct {
	val   any
	err   error
	extra map[string]any
}

type entRun struct {
	localRequested any
	qrngErrors     []any
	srcs           []*entSrc
}

// entSeedOpts builds SecureSeedOptions from a case's option object, recording what the library asked for.
func entSeedOpts(o map[string]any, run *entRun) (SecureSeedOptions, error) {
	var opts SecureSeedOptions
	for _, f := range []struct {
		key string
		dst *int
	}{{"length", &opts.Length}, {"localBytes", &opts.LocalBytes}, {"quantumBytes", &opts.QuantumBytes}} {
		if v, ok := o[f.key]; ok {
			n, ok := entSize(v)
			if !ok {
				return opts, vecSkip("size option a typed call cannot carry")
			}
			*f.dst = n
		}
	}
	if c, ok := o["context"]; ok {
		s, isStr := c.(string)
		if !isStr {
			return opts, vecSkip("non-string context")
		}
		opts.Context = &s
	}
	opts.RequireQuantum = o["requireQuantum"] == true
	switch ht := o["healthTest"].(type) {
	case bool:
		opts.DisableHealthTest = !ht
	case map[string]any:
		if v, ok := ht["h"]; ok {
			f, _ := entNum(v)
			opts.HealthTest.H = &f
		}
		if v, ok := ht["window"]; ok {
			f, _ := entNum(v)
			opts.HealthTest.Window = &f
		}
	}
	if s := vecObj(o["source"]); s != nil {
		src := &entSrc{name: vecStr(s, "name"), kind: vecStr(s, "kind"), value: baseBytes(s["value"]), msg: vecStr(s, "message")}
		if src.kind == "nonbytes" {
			return opts, vecSkip("a typed source cannot return non-bytes")
		}
		run.srcs = append(run.srcs, src)
		opts.Source = src
	}
	if l := vecObj(o["local"]); l != nil {
		kind := vecStr(l, "kind")
		val := baseBytes(l["value"])
		msg := vecStr(l, "message")
		opts.RandomBytes = func(n int) ([]byte, error) {
			run.localRequested = n
			switch kind {
			case "fixed":
				return val, nil
			case "throw":
				return nil, errors.New(msg)
			}
			return nil, nil // nonbytes: no bytes at all
		}
	}
	if h, _ := o["hook"].(string); h == "collect" || h == "throw" {
		opts.OnQrngError = func(err error) {
			e := map[string]any{"cls": "Error", "message": err.Error()}
			var ee *EntropyError
			var se *entStrErr
			switch {
			case errors.As(err, &ee):
				e["cls"], e["code"] = "EntropyError", ee.Code
			case errors.As(err, &se):
				e["cls"] = "string"
			}
			run.qrngErrors = append(run.qrngErrors, e)
			if h == "throw" {
				panic("hook throws")
			}
		}
	}
	return opts, nil
}

func entRunExtra(run *entRun) map[string]any {
	reqs := []any{}
	for _, s := range run.srcs {
		reqs = append(reqs, s.requests...)
	}
	errs := run.qrngErrors
	if errs == nil {
		errs = []any{}
	}
	return map[string]any{"qrngErrors": errs, "localRequested": run.localRequested, "requests": reqs}
}

func entMerge(m, extra map[string]any) map[string]any {
	for k, v := range extra {
		m[k] = v
	}
	return m
}

func entSecureSeed(a []any) entRes {
	var run entRun
	opts, err := entSeedOpts(vecObj(vecArg(a, 0)), &run)
	if err != nil {
		return entRes{err: err}
	}
	r, err := SecureSeed(opts)
	extra := entRunExtra(&run)
	if err != nil {
		return entRes{err: err, extra: extra}
	}
	var src any
	if r.Source != nil {
		src = *r.Source
	}
	return entRes{val: entMerge(map[string]any{"seed": kemBytesOut(r.Seed), "usedQuantum": r.UsedQuantum, "quantumByteCount": r.QuantumByteCount, "source": src}, extra), extra: extra}
}

func entKeyPair(a []any) entRes {
	var run entRun
	opts, err := entSeedOpts(vecObj(vecArg(a, 0)), &run)
	if err != nil {
		return entRes{err: err}
	}
	kp, err := GenerateKeyPairWithEntropy(opts)
	extra := entRunExtra(&run)
	if err != nil {
		return entRes{err: err, extra: extra}
	}
	h := sha256.Sum256(kp.SecretKey)
	if !ed25519.PublicKey(kp.PublicKey).Equal(ed25519.NewKeyFromSeed(kp.SecretKey).Public()) {
		return entRes{err: errors.New("public key does not match the seed")}
	}
	return entRes{val: entMerge(map[string]any{"publicKey": kemBytesOut(kp.PublicKey), "secretKeySha256": hex.EncodeToString(h[:]), "usedQuantum": kp.UsedQuantum}, extra)}
}

func entHealthOpts(v any) (HealthTestOptions, error) {
	var o HealthTestOptions
	if v == nil {
		return o, nil
	}
	m := vecObj(v)
	if m == nil {
		return o, vecSkip("null options")
	}
	for k, dst := range map[string]**float64{"h": &o.H, "window": &o.Window} {
		if x, ok := m[k]; ok {
			f, isNum := entNum(x)
			if !isNum {
				return o, vecSkip("non-number option")
			}
			*dst = &f
		}
	}
	return o, nil
}

func entHttp(a []any) entRes {
	cfg := vecObj(vecArg(a, 0))
	c := HttpQrngConfig{}
	c.URL, _ = cfg["url"].(string)
	c.APIKey, _ = cfg["apiKey"].(string)
	c.APIKeyHeader, _ = cfg["apiKeyHeader"].(string)
	c.Format, _ = cfg["format"].(string)
	c.LengthParam, _ = cfg["lengthParam"].(string)
	c.AllowInsecureLoopback = cfg["allowInsecureLoopback"] == true
	for _, f := range []struct {
		key string
		dst *int
	}{{"maxBytes", &c.MaxBytes}, {"timeoutMs", &c.TimeoutMs}} {
		if v, ok := cfg[f.key]; ok {
			n, ok := entSize(v)
			if !ok {
				return entRes{err: vecSkip("size option a typed call cannot carry")}
			}
			*f.dst = n
		}
	}
	if ex := vecObj(cfg["extraParams"]); ex != nil {
		for _, k := range jsKeys(ex) {
			c.ExtraParams = append(c.ExtraParams, QrngParam{k, vecStr(ex, k)})
		}
	}
	if b := vecObj(cfg["buildUrl"]); b != nil {
		suffix := vecStr(b, "suffix")
		c.BuildURL = func(base string, n int) string { return base + "/" + strconv.Itoa(n) + suffix }
	}
	n, ok := entSize(vecArg(a, 1))
	if !ok {
		return entRes{err: vecSkip("count a typed call cannot carry")}
	}
	if f, _ := entNum(vecArg(a, 1)); f == 0 {
		n = 0 // the refusal names the count it was given
	}
	var requests []any
	var mu sync.Mutex
	tr := vecObj(vecArg(a, 2))
	kind := vecStr(tr, "kind")
	if kind == "throwString" {
		return entRes{err: vecSkip("a Go transport error is always an error value")}
	}
	if kind != "none" {
		status, _ := jsNum(tr["status"])
		okFlag := status >= 200 && status <= 299
		if b, has := tr["ok"].(bool); has {
			okFlag = b
		}
		c.Transport = func(ctx context.Context, url string, headers map[string]string, redirect string) (*QrngResponse, error) {
			h := map[string]any{}
			for k, v := range headers {
				h[k] = v
			}
			mu.Lock()
			requests = append(requests, map[string]any{"url": url, "headers": h, "redirect": redirect, "signal": ctx != nil})
			mu.Unlock()
			switch kind {
			case "throw":
				return nil, errors.New(vecStr(tr, "message"))
			case "hang":
				<-ctx.Done()
				return nil, ctx.Err()
			}
			r := &QrngResponse{OK: okFlag, Status: int(status)}
			switch kind {
			case "json":
				r.JSON = func() (any, error) { return tr["body"], nil }
			case "jsonThrows":
				r.JSON = func() (any, error) { return nil, errors.New("bad json") }
			case "text":
				r.Text = func() (string, error) { return vecStr(tr, "text"), nil }
			case "textThrows":
				r.Text = func() (string, error) { return "", errors.New("read failed") }
			}
			return r, nil
		}
	}
	src, err := NewHttpQrngSource(c)
	if err != nil {
		return entRes{err: err}
	}
	b, err := src.Fetch(n)
	mu.Lock()
	reqs := append([]any{}, requests...)
	mu.Unlock()
	if err != nil {
		leaks := c.APIKey != "" && strings.Contains(err.Error(), c.APIKey)
		return entRes{err: err, extra: map[string]any{"name": src.Name(), "requests": reqs, "leaksKey": leaks}}
	}
	return entRes{val: map[string]any{"name": src.Name(), "bytes": kemBytesOut(b), "requests": reqs}}
}

func entNull(a []any, fn func(reason ...string) QrngSource) entRes {
	var src QrngSource
	if r, ok := vecArg(a, 0).(string); ok {
		src = fn(r)
	} else {
		src = fn()
	}
	_, err := src.Fetch(16)
	return entRes{val: map[string]any{"name": src.Name()}, err: err, extra: map[string]any{"name": src.Name()}}
}

func entHandle(c *baseCase) entRes {
	a := c.Args
	bytesRes := func(b []byte, err error) entRes {
		if err != nil {
			return entRes{err: err}
		}
		return entRes{val: kemBytesOut(b)}
	}
	switch c.Fn {
	case "constants":
		return entRes{val: map[string]any{"MAX_HKDF_OUTPUT": MaxHkdfOutput, "MIN_LOCAL_BYTES": MinLocalBytes, "DEFAULT_SEED_BYTES": DefaultSeedBytes,
			"DEFAULT_MAX_QRNG_BYTES": DefaultMaxQrngBytes, "DEFAULT_TIMEOUT_MS": DefaultQrngTimeoutMs}}
	case "repetitionCutoff":
		h, ok := entNum(vecArg(a, 0))
		if !ok {
			return entRes{err: vecSkip("non-number")}
		}
		return entRes{val: entNumOut(RepetitionCutoff(h))}
	case "proportionCutoff":
		h, ok1 := entNum(vecArg(a, 0))
		w, ok2 := entNum(vecArg(a, 1))
		if !ok1 || !ok2 {
			return entRes{err: vecSkip("non-number")}
		}
		c, err := ProportionCutoff(h, w)
		if err != nil {
			return entRes{err: err}
		}
		return entRes{val: entNumOut(c)}
	case "healthTestBytes":
		b := baseBytes(vecArg(a, 0))
		if b == nil {
			return entRes{err: vecSkip("null bytes")}
		}
		if len(a) > 1 && a[1] == nil { // an explicit null is read (opts.h), only an absent argument takes the defaults
			return entRes{err: errors.New("Cannot read properties of null (reading 'h')")}
		}
		o, err := entHealthOpts(vecArg(a, 1))
		if err != nil {
			return entRes{err: err}
		}
		v := HealthTestBytes(b, o)
		if v.OK {
			return entRes{val: map[string]any{"ok": true}}
		}
		return entRes{val: map[string]any{"ok": false, "test": v.Test}}
	case "parseAnuUint8":
		return bytesRes(ParseAnuUint8(vecArg(a, 0)))
	case "parseHex", "parseBase64":
		s, ok := vecArg(a, 0).(string)
		if !ok {
			return entRes{err: vecSkip("non-string")}
		}
		if c.Fn == "parseHex" {
			return bytesRes(ParseHex(s))
		}
		return bytesRes(ParseBase64(s))
	case "mixEntropy":
		local, quantum := baseBytes(vecArg(a, 0)), baseBytes(vecArg(a, 1))
		if local == nil || quantum == nil {
			return entRes{err: vecSkip("non-bytes")}
		}
		var o MixOptions
		if m := vecObj(vecArg(a, 2)); m != nil {
			if v, has := m["length"]; has && v != nil {
				n, ok := entSize(v)
				if !ok {
					return entRes{err: vecSkip("length a typed call cannot carry")}
				}
				o.Length = n
			}
			if v, has := m["context"]; has {
				s, isStr := v.(string)
				if !isStr {
					return entRes{err: vecSkip("non-string context")}
				}
				o.Context = s
			}
		}
		return bytesRes(MixEntropy(local, quantum, o))
	case "secureSeed":
		return entSecureSeed(a)
	case "generateKeyPairWithEntropy":
		return entKeyPair(a)
	case "httpQrng":
		return entHttp(a)
	case "nullQrng":
		return entNull(a, func(r ...string) QrngSource { return NewNullQrngSource(r...) })
	case "unavailableSource":
		return entNull(a, UnavailableSource)
	case "entropyError":
		code, _ := vecArg(a, 0).(string)
		msg, _ := vecArg(a, 1).(string)
		e := NewEntropyError(code, msg)
		return entRes{val: map[string]any{"name": "EntropyError", "code": e.Code, "message": e.Error(), "isError": true}}
	}
	return entRes{err: errors.New("no Go entry point for " + c.Fn)}
}

func TestEntropyReferenceVectors(t *testing.T) {
	var k baseTally
	count := 0
	exact := []string{"QRNG", "HttpQrngSource", "mixEntropy", "secureSeed"}
	baseEachOrdered(t, "ref-entropy.json.gz", func(c *baseCase) {
		count++
		var r entRes
		if p := baseCall(func() { r = entHandle(c) }); p != "" {
			k.fail(c, "panic: %s", p)
			return
		}
		var skip vecSkip
		if errors.As(r.err, &skip) {
			k.skip(c.Fn, string(skip))
			return
		}
		if strings.HasPrefix(errString(r.err), "no Go entry point") {
			k.fail(c, "%v", r.err)
			return
		}
		k.run(c.Fn)
		if throws, code := baseThrows(c.Out); throws {
			if r.err == nil {
				k.fail(c, "reference refuses (%s), Go returned %s", baseCanon(c.Out), baseCanon(vecJSON(r.val)))
				return
			}
			want := vecObj(c.Out)
			msg, _ := want["$throws"].(string)
			for _, p := range exact {
				if strings.HasPrefix(msg, p) && r.err.Error() != msg {
					k.fail(c, "message %q, want %q", r.err.Error(), msg)
				}
			}
			var ee *EntropyError
			if code != "" && !strings.HasPrefix(code, "ERR_") && (!errors.As(r.err, &ee) || ee.Code != code) {
				k.fail(c, "want code %s, got %v", code, r.err)
			}
			for key, v := range r.extra {
				if wv, ok := want[key]; ok && baseCanon(normalizeJSON(wv)) != baseCanon(vecJSON(v)) {
					k.fail(c, "%s: want %s got %s", key, baseCanon(wv), baseCanon(vecJSON(v)))
				}
			}
			if r.extra["leaksKey"] == true {
				k.fail(c, "the error leaks the API key")
			}
			return
		}
		if r.err != nil {
			k.fail(c, "Go refuses (%v), reference returned %s", r.err, baseCanon(c.Out))
			return
		}
		if w, g := baseCanon(c.Out), baseCanon(vecJSON(r.val)); w != g {
			k.fail(c, "want %s got %s", w, g)
		}
	})
	k.finish(t)
	if count != entropyCorpusCases {
		t.Fatalf("replayed %d cases, the corpus has %d", count, entropyCorpusCases)
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
