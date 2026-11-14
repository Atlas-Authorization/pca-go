package pca

// Final-run harvest (42709333483): survivors that depend on map iteration order are killed by repeating the call until a wrong order
// cannot hide, and the read of a string's content is pinned at its depth and its offset.

import (
	"fmt"
	"testing"
)

// attest_nvidia_rim.go: the NVDEC block is skipped with `continue`; a `break` would end the walk at a random point of the map.
func TestR9_NvdecSkipDoesNotEndTheMismatchCount(t *testing.T) {
	const n = 60
	var gs []rimGolden
	var ms []spdmMeasurement
	for i := 0; i < n; i++ {
		gs = append(gs, g12Golden(i, true, 1, "aa"))
		ms = append(ms, spdmMeasurement{index: i + 1, digest: []byte{0xbb}})
	}
	rep := &spdmReport{measurements: ms, opaque: map[int][]byte{11: {0x55}}}
	want := fmt.Sprintf("runtime measurements differ from the golden RIM values at %d index(es)", n-1)
	for i := 0; i < 60; i++ {
		if got := compareReportToRims(rep, g12Rims(gs...), g12Rims()); got != want {
			t.Fatalf("round %d: %q, want %q", i, got, want)
		}
	}
}

// decision.go sortedMapKeys: the first mismatching unit tag in sorted order is the one reported.
func TestR9_DecideUnitsReportsTheFirstPathInOrder(t *testing.T) {
	units, params := map[string]any{}, map[string]any{}
	for i := 0; i < 40; i++ {
		p := fmt.Sprintf("action.params.k%02d", i)
		units[p] = map[string]any{"kind": "money"}
		params[p] = map[string]any{"unit": "u"}
	}
	in := map[string]any{"units": units, "verb": "v", "schema_units": map[string]any{"u": map[string]any{"kind": "count"}}, "verb_params": params}
	want := "'action.params.k00' is declared as count by the action schema but the policy term is tagged money (unit confusion)"
	for i := 0; i < 40; i++ {
		if ok, why := DecideUnits(in); ok || why != want {
			t.Fatalf("round %d: %v %q", i, ok, why)
		}
	}
}

// attest_nvidia_ocsp.go ocspWrapped: the nested read starts one level below the string (99 SEQUENCEs fit, 100 do not); a read that
// fails clears the pending exception, one that succeeds keeps it.
func TestR9_OcspWrappedDepth(t *testing.T) {
	nest := func(k int) []byte {
		c := derTLV(5)
		for i := 0; i < k; i++ {
			c = derTLV(0x30, c)
		}
		return c
	}
	for k, want := range map[int]string{98: "x", 99: "x", 100: "", 101: ""} {
		st := &ocspBERState{threw: "x"}
		ocspWrapped(nest(k), 0, st)
		if st.threw != want {
			t.Errorf("%d SEQUENCEs: threw %q, want %q", k, st.threw, want)
		}
	}
}

// attest_nvidia_ocsp.go ocspBER: the content of a BIT STRING with no unused bits is read after the unused-bits byte.
func TestR9_OcspBitStringContentStartsAfterTheUnusedByte(t *testing.T) {
	st := &ocspBERState{threw: "x"}
	if end, kind, ok := ocspBER([]byte{0x03, 0x02, 0x00, 0x05}, 0, 4, 0, st); end != 4 || kind != 3 || !ok {
		t.Fatalf("BIT STRING: %d %d %v", end, kind, ok)
	}
	if st.threw != "" {
		t.Errorf("the one-byte content {05} does not read as an element, so the pending exception is cleared: %q", st.threw)
	}
	st = &ocspBERState{threw: "x"}
	if _, _, ok := ocspBER([]byte{0x03, 0x03, 0x00, 0x05, 0x00}, 0, 5, 0, st); !ok || st.threw != "x" {
		t.Errorf("content {05 00} reads as a NULL and keeps the exception: ok %v threw %q", ok, st.threw)
	}
}
