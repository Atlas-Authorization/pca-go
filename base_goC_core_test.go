package pca

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"testing"
)

func TestGoCFreshnessGateBounds(t *testing.T) {
	if DefaultFreshnessEpochMs != 60000 {
		t.Fatalf("default epoch length: %d", DefaultFreshnessEpochMs)
	}
	anchor := func(epoch string) map[string]any {
		return map[string]any{"beacon_ref": "b", "epoch": json.Number(epoch)}
	}
	const missing = "freshness anchor is missing (empty beacon_ref or non-positive epoch stub)"
	const miscfg = "freshness gate misconfigured: epochMs must be > 0 and maxAgeMs >= 0 (fail closed)"
	for name, c := range map[string]struct {
		g    *FreshnessGate
		fr   map[string]any
		now  int64
		want string
	}{
		"epoch 1 is a real anchor":   {&FreshnessGate{MaxAgeMs: 5000}, anchor("1"), 60000, ""},
		"epoch 1 one epoch past":     {&FreshnessGate{MaxAgeMs: 0}, anchor("1"), 60001, "freshness anchor is stale (older than 0 ms)"},
		"zero max age at the anchor": {&FreshnessGate{MaxAgeMs: 0}, anchor("5"), 300000, ""},
		"epoch length 1":             {&FreshnessGate{EpochMs: 1, MaxAgeMs: 5000}, anchor("1000"), 1000, ""},
		"epoch length 1 later":       {&FreshnessGate{EpochMs: 1, MaxAgeMs: 5000}, anchor("1000"), 1001, ""},
		"NaN skew counts as none":    {&FreshnessGate{MaxAgeMs: 5000, ClockSkewMs: math.NaN()}, anchor("1000"), 60_000_000 - 1, "freshness anchor is in the future"},
		"+Inf skew counts as none":   {&FreshnessGate{MaxAgeMs: 5000, ClockSkewMs: math.Inf(1)}, anchor("1000"), 60_000_000 - 1, "freshness anchor is in the future"},
		"-Inf skew counts as none":   {&FreshnessGate{MaxAgeMs: 5000, ClockSkewMs: math.Inf(-1)}, anchor("1000"), 60_000_000 - 1, "freshness anchor is in the future"},
		"skew at the boundary":       {&FreshnessGate{MaxAgeMs: 5000, ClockSkewMs: 5000}, anchor("1000"), 60_000_000 - 5000, ""},
		"skew past the boundary":     {&FreshnessGate{MaxAgeMs: 5000, ClockSkewMs: 5000}, anchor("1000"), 60_000_000 - 5001, "freshness anchor is in the future"},
		"infinite max age":           {&FreshnessGate{MaxAgeMs: math.Inf(1)}, anchor("1000"), 60_000_000, miscfg},
		"missing":                    {&FreshnessGate{MaxAgeMs: 5000}, nil, 60_000_000, missing},
	} {
		if got := freshnessGateReason(c.g, c.fr, c.now); got != c.want {
			t.Errorf("%s: %q, want %q", name, got, c.want)
		}
	}
}

func goCCoreVector(t *testing.T) (pcactn, grant map[string]any, now int64, aud string) {
	t.Helper()
	core := load(t, "vectors.json")
	for _, x := range core["vectors"].([]any) {
		if m := x.(map[string]any); m["name"] == "valid-in-plan-action" {
			ctx := m["context"].(map[string]any)
			return m["pcactn"].(map[string]any), m["grant"].(map[string]any), num(ctx["now"]), ctx["aud"].(string)
		}
	}
	t.Fatal("vector not found")
	return
}

func goCCopy(m map[string]any, over map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	for k, v := range over {
		out[k] = v
	}
	return out
}

func TestGoCCoreFreshnessAnchorPasses(t *testing.T) {
	p, g, now, aud := goCCoreVector(t)
	orig := p["freshness"].(map[string]any)
	p = goCCopy(p, map[string]any{"freshness": goCCopy(orig, map[string]any{"beacon_ref": "b", "epoch": json.Number("1000")})})
	gateNow := int64(1000*DefaultFreshnessEpochMs + 1000)
	got, err := VerifyPCActnCoreWith(p, g, now, aud, VerifyOptions{InsecureSkipPlanRootCheck: true, EnforceFreshness: &FreshnessGate{MaxAgeMs: 5000, Now: &gateNow}})
	if err != nil {
		t.Fatal(err)
	}
	if ok, has := got.Checks["freshness_anchor"]; !has || !ok {
		t.Errorf("a fresh anchor must be reported as passed: %+v", got.Checks)
	}
	stale := int64(1000*DefaultFreshnessEpochMs + 6000)
	got, _ = VerifyPCActnCoreWith(p, g, now, aud, VerifyOptions{InsecureSkipPlanRootCheck: true, EnforceFreshness: &FreshnessGate{MaxAgeMs: 5000, Now: &stale}})
	if ok, has := got.Checks["freshness_anchor"]; !has || ok {
		t.Errorf("a stale anchor must be reported as failed: %+v", got.Checks)
	}
}

func TestGoCCoreTaintGate(t *testing.T) {
	p, g, now, aud := goCCoreVector(t)
	orig := p["provenance"].(map[string]any)
	with := func(refs ...any) map[string]any {
		return goCCopy(p, map[string]any{"provenance": goCCopy(orig, map[string]any{"trusted_refs": refs})})
	}
	reg := MapTrustedInputRegistry{"r1": "trusted", "r2": "web"}
	run := func(pc map[string]any, gate *TaintGate) Verdict {
		v, err := VerifyPCActnCoreWith(pc, g, now, aud, VerifyOptions{InsecureSkipPlanRootCheck: true, EnforceTaint: gate})
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	if v := run(with("r1"), nil); func() bool { _, has := v.Checks["taint_gate"]; return has }() {
		t.Error("gate off: nothing reported")
	}
	if v := run(with("r1"), &TaintGate{Registry: reg, MaxTaint: 0}); !v.Checks["taint_gate"] {
		t.Errorf("trusted ref within the bound must pass: %+v", v.Checks)
	}
	v := run(with("r2"), &TaintGate{Registry: reg, MaxTaint: 0.5})
	if ok, has := v.Checks["taint_gate"]; !has || ok {
		t.Errorf("web ref over the bound must fail: %+v", v.Checks)
	}
}

func TestGoCRegexBudgetRefusalsCounted(t *testing.T) {
	var bad []uint16
	for _, src := range []string{"(", ")", "*", "[", "\\", "a{"} {
		if compileSafeRegex(u16(src)) == nil {
			bad = u16(src)
			break
		}
	}
	if bad == nil {
		t.Fatal("no uncompilable pattern found")
	}
	b := &regexBudget{}
	if b.charge(bad, 1) || b.refusals != 1 {
		t.Errorf("uncompilable: refusals=%d", b.refusals)
	}
	b = &regexBudget{evaluations: maxRegexEvaluationsPerDoc}
	if b.charge(u16("a"), 1) || b.refusals != 1 || b.evaluations != maxRegexEvaluationsPerDoc+1 {
		t.Errorf("over budget: refusals=%d evaluations=%d", b.refusals, b.evaluations)
	}
	b = &regexBudget{}
	if !b.charge(u16("a"), 1) || b.refusals != 0 || b.evaluations != 1 {
		t.Errorf("within budget: refusals=%d evaluations=%d", b.refusals, b.evaluations)
	}
}

func TestGoCLenientJSONCapAbsolute(t *testing.T) {
	pad := func(n int) []byte { return append(append([]byte(`"`), bytes.Repeat([]byte("a"), n-2)...), '"') }
	if _, err := jsonLenient(pad(16777216)); err != nil {
		t.Errorf("16 MiB is parsed: %v", err)
	}
	if _, err := jsonLenient(pad(16777217)); !errors.Is(err, errJSONTooLarge) {
		t.Errorf("16 MiB + 1: %v", err)
	}
}

func TestGoCOidArcGroupBound(t *testing.T) {
	oid := func(groups int) []byte {
		content := append([]byte{0x81}, bytes.Repeat([]byte{0x80}, groups-2)...)
		content = append(content, 0x01)
		return append([]byte{0x06, byte(len(content))}, content...)
	}
	b := oid(64)
	if s, err := oidToDotted(b, derTlv{tag: 0x06, start: 2, end: len(b)}); err != nil || s == "" {
		t.Errorf("an arc of 64 groups is accepted: %q %v", s, err)
	}
	b = oid(65)
	if s, err := oidToDotted(b, derTlv{tag: 0x06, start: 2, end: len(b)}); err == nil || err.Error() != "extension OID has an oversized arc" || s != "" {
		t.Errorf("an arc of 65 groups is refused: %q %v", s, err)
	}
}

func TestGoCDcapVerifierGarbageCollateral(t *testing.T) {
	f := g08NewTdx(t)
	expected := &AttestationBinding{HolderPub: "h", GrantRef: "g", Epoch: 1, Nonce: "n"}
	want, err := attestationBindingBytes(*expected)
	if err != nil || len(want) != 64 {
		t.Fatalf("binding bytes: %v %d", err, len(want))
	}
	q := f.quote(t, nil)
	copy(q[dcapHeaderLen+520:], want)
	copy(q[dcapHeaderLen+dcapTdReportLen+4:], g08Compact(t, f.akKey, q[:dcapHeaderLen+dcapTdReportLen]))
	v := &dcapVerifier{binding: "report-data", pin: f.pin, allowMissing: true}
	ev := map[string]any{"quote": base64.StdEncoding.EncodeToString(q)}
	if r := v.verify(ev, expected, g08now); !r.OK || r.HostAsserted["tcb_status"] != "unevaluated" {
		t.Fatalf("no collateral, allowed missing: %+v", r)
	}
	ev["collateral"] = "not an object"
	if r := v.verify(ev, expected, g08now); r.OK || r.Reason != "Intel collateral: collateral incomplete (fail closed)" {
		t.Errorf("garbage collateral must not be excused as missing: %+v", r)
	}
}
