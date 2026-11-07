package pca

// Guards restored after the k05 kill program deleted them (second batch): each refuses its input itself, never through a
// later check, cast or callee. Where no real input reaches a guard, a seam (identity in production) is swapped so the guard
// is the only thing that can refuse; the rest are fed the non-object inputs they refuse.

import (
	"encoding/json"
	"errors"
	"testing"
)

func gr2FailKey(*attCert) (certKey, error) { return certKey{}, errors.New("gr2 key") }

// hardware-tdx.ts: the root key is read before the pin compare; a read error is the X.509 verification error (fail closed).
func TestGr2IntelRootKeyGuard(t *testing.T) {
	defer func(old func(*attCert) (certKey, error)) { pckRootKey = old }(pckRootKey)
	rootKey := g08Key(t)
	root := g08MakeCert(t, g08CATmpl("gr2 root", 9), g08CATmpl("gr2 root", 9), &rootKey.PublicKey, rootKey)
	pin, pemRoot := g08Pin(root), g08PEM(root.Raw)
	if r := verifyIntelPckChain(pemRoot, pin, g08now); !r.ok {
		t.Fatalf("genuine root: %q", r.reason)
	}
	pckRootKey = gr2FailKey
	if r := verifyIntelPckChain(pemRoot, pin, g08now); r.ok || r.reason != "PCK chain X.509 verification error (fail closed): gr2 key" {
		t.Fatalf("unreadable root key: %+v", r)
	}
}

// hardware-sevsnp.ts: the ARK key is read before the pin compare; a read error is the chain verification error.
func TestGr2AmdArkKeyGuard(t *testing.T) {
	defer func(old func(*attCert) (certKey, error)) { amdArkKey = old }(amdArkKey)
	f := g13amdNew(t)
	if r, pub, tbs := f.chain(f.vcekDer, g13amdNow, nil); r != "" || pub == nil || tbs == nil {
		t.Fatalf("genuine chain: %q", r)
	}
	amdArkKey = gr2FailKey
	if r, pub, tbs := f.chain(f.vcekDer, g13amdNow, nil); r != "AMD chain verification error: gr2 key" || pub != nil || tbs != nil {
		t.Fatalf("unreadable ARK key: %q", r)
	}
}

// The ResponseData and responses SEQUENCEs that cannot be split into nodes are refused with the parse error, call by call.
func TestGr2OcspDataKidsGuards(t *testing.T) {
	defer func(old func([]byte, ocspNode) ([]ocspNode, error)) { ocspDataKids = old }(ocspDataKids)
	f := g02newFx(t)
	der := f.base(t).der(t)
	if got := verifyNvidiaOcspResponse(der, f.leafA, f.interA, f.chain, f.nowMs); got != g02ok("good") {
		t.Fatalf("genuine response: %+v", got)
	}
	for _, failAt := range []int{1, 2} { // 1: ResponseData, 2: responses
		calls := 0
		ocspDataKids = func(b []byte, n ocspNode) ([]ocspNode, error) {
			calls++
			if calls == failAt {
				return nil, errors.New("gr2 kids")
			}
			return ocspKids(b, n)
		}
		if got := verifyNvidiaOcspResponse(der, f.leafA, f.interA, f.chain, f.nowMs); got != g02rej("gr2 kids") {
			t.Fatalf("call %d: %+v", failAt, got)
		}
		if calls != failAt {
			t.Fatalf("call %d: %d calls", failAt, calls)
		}
	}
}

// a2a.ts verifyA2AReceipt: `if (!isRecord(r)) return false`.
func TestGr2A2AReceiptNonObject(t *testing.T) {
	for _, v := range []any{nil, "x", []any{}, json.Number("1"), map[string]string{"v": "1"}} {
		if VerifyA2AReceipt(v, "signer") {
			t.Errorf("%#v accepted", v)
		}
	}
}

// mesh.ts validHead / the inclusion-proof steps / validTrust: a non-object is refused where it is read.
func TestGr2MeshNonObjects(t *testing.T) {
	for _, v := range []any{nil, "x", []any{}, map[string]string{"domain": "d"}} {
		if m, ok := meshValidHead(v); ok || m != nil {
			t.Errorf("head %#v accepted", v)
		}
		proof := map[string]any{"size": json.Number("2"), "index": json.Number("0"), "path": []any{v}}
		if meshLeafOK("root", 2, "id", proof) {
			t.Errorf("proof step %#v accepted", v)
		}
		if _, why := meshValidTrust(v); why != "invalid trust configuration" {
			t.Errorf("trust %#v: %q", v, why)
		}
	}
}

// policy-vm.ts agentNativeCaveatEvaluator: a non-object caveat is refused before any evaluator runs.
func TestGr2AgentCaveatNonObjectGuard(t *testing.T) {
	defer func(old func(any, map[string]any) (bool, []string)) { agentStockCaveats = old }(agentStockCaveats)
	agentStockCaveats = func(any, map[string]any) (bool, []string) { return true, nil }
	if !agentCaveatSatisfied(map[string]any{"type": "gr2"}, nil, nil, nil, &regexBudget{}) {
		t.Fatal("seam not reached")
	}
	for _, v := range []any{nil, "x", []any{}, map[string]string{"type": "gr2"}} {
		if agentCaveatSatisfied(v, nil, nil, nil, &regexBudget{}) {
			t.Errorf("%#v accepted", v)
		}
	}
}

// A TCB component that is not a record is refused (the reference's isRecord check), wherever it sits.
func TestGr2SvnListNonRecord(t *testing.T) {
	comps := make([]any, 16)
	for i := range comps {
		comps[i] = map[string]any{"svn": float64(i)}
	}
	if out, ok := svnList(comps); !ok || len(out) != 16 {
		t.Fatalf("genuine list: %v %v", out, ok)
	}
	for _, at := range []int{0, 15} {
		bad := append([]any{}, comps...)
		bad[at] = "x"
		if out, ok := svnList(bad); ok || out != nil {
			t.Errorf("non-record at %d accepted: %v", at, out)
		}
	}
}
