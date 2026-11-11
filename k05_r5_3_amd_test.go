package pca

import (
	"encoding/json"
	"testing"
)

func TestR5N3AmdBindingNamesAMissingSplExtension(t *testing.T) {
	r := &snpReport{chipID: g13amdChip, reportedTcb: g13amdTcb}
	spl := func(k byte, v byte) []byte { return g09dExt(g13amdSplOI(k), false, []byte{0x02, 0x01, v}) }
	hw := g09dExt(g13amdHwOID, false, g13amdChip)
	all := [][]byte{spl(1, 1), spl(2, 2), spl(3, 7), spl(8, 8)}
	for i, name := range []string{"bootloader", "tee", "snp", "microcode"} {
		exts := [][]byte{hw}
		for j, e := range all {
			if j != i {
				exts = append(exts, e)
			}
		}
		want := "VCEK certificate has no " + name + " SPL extension"
		if got := checkVcekReportBinding(g13amdExtTbs(exts...), r); got != want {
			t.Errorf("missing %s: %q, want %q", name, got, want)
		}
	}
}

func TestR5N3AmdAnyValueText(t *testing.T) {
	for _, c := range []struct {
		v    any
		want string
	}{
		{json.Number("1e21"), "1e+21"}, // String(1e21)
		{true, "true"}, {false, "false"}, {"x", "x"}, {float64(3), "3"}, {json.Number("1234567.5"), "1234567.5"},
	} {
		if got := jsAnyString(c.v); got != c.want {
			t.Errorf("jsAnyString(%#v) = %q, want %q", c.v, got, c.want)
		}
	}
}

func TestR5N3AmdBigIntRefusals(t *testing.T) {
	n, err := parseJSBigInt(nil)
	if n != nil || err == nil || err.Error() != "Cannot convert null to a BigInt" {
		t.Errorf("null: %v %v", n, err)
	}
	for _, v := range []any{[]any{}, map[string]any{}} { // not a JSON scalar: refused (the reference throws for an object)
		if n, err := parseJSBigInt(v); n != nil || err == nil {
			t.Errorf("%v: %v %v", v, n, err)
		}
	}
}
