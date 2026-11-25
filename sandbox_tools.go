package pca

// The reference WebAssembly tools of the sandbox: hand-assembled core modules (and the component text) that talk to the host only
// through `pca:act`. They exist so a host can be exercised end to end; the bytes are exactly what the reference assembles.

import (
	"strings"
)

func sbxULEB(n int64) []byte {
	var out []byte
	for {
		b := byte(n & 0x7F)
		n /= 128
		if n > 0 {
			b |= 0x80
		}
		out = append(out, b)
		if n <= 0 {
			return out
		}
	}
}

// sbxStr is a length-prefixed name: the prefix counts UTF-16 code units, the bytes are UTF-8 (as the reference writes it).
func sbxStr(x string) []byte {
	return append(sbxULEB(int64(jsLen(x))), []byte(strings.ToValidUTF8(x, "�"))...)
}

func sbxSection(i byte, body []byte) []byte {
	return append(append([]byte{i}, sbxULEB(int64(len(body)))...), body...)
}

func sbxVec(items ...[]byte) []byte {
	out := sbxULEB(int64(len(items)))
	for _, it := range items {
		out = append(out, it...)
	}
	return out
}

func sbxSLEB(n int64) []byte {
	n = int64(int32(n)) // the reference shifts int32 values
	var out []byte
	for {
		b := byte(n & 0x7F)
		n >>= 7
		if (n == 0 && b&0x40 == 0) || (n == -1 && b&0x40 != 0) {
			return append(out, b)
		}
		out = append(out, b|0x80)
	}
}

func sbxI32c(n int64) []byte { return append([]byte{0x41}, sbxSLEB(n)...) }

func sbxCat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func sbxInt(v any, def int64) int64 {
	if f, ok := sbxIsInt(v); ok {
		return int64(f)
	}
	return def
}

// BuildTool is a hand-assembled core-WebAssembly module that calls `pca:act.invoke(handle, ptr, cap)` for each given call and
// returns either the last call's return code or the first byte of linear memory. spec: {calls: [{handle, ptr, cap}], returns?:
// "last" | "byte0", extraImports?: [{module, name}], memory?: {min, max}, spin?: bool}.
func BuildTool(spec map[string]any) []byte {
	extra, _ := spec["extraImports"].([]any)
	types := sbxVec([]byte{0x60, 3, 0x7F, 0x7F, 0x7F, 1, 0x7F}, []byte{0x60, 0, 1, 0x7F}, []byte{0x60, 4, 0x7F, 0x7F, 0x7F, 0x7F, 1, 0x7F})
	imps := [][]byte{sbxCat(sbxStr("pca:act"), sbxStr("invoke"), []byte{0, 0})}
	for _, e := range extra {
		m, _ := e.(map[string]any)
		mod, _ := m["module"].(string)
		name, _ := m["name"].(string)
		imps = append(imps, sbxCat(sbxStr(mod), sbxStr(name), []byte{0, 2}))
	}
	imports := sbxVec(imps...)
	mem := map[string]any{"min": sbxOneNum(), "max": sbxOneNum()}
	if m, ok := spec["memory"].(map[string]any); ok && sbxTruthy(m, true) {
		mem = m
	}
	var memBody []byte
	if mx, present := mem["max"]; sbxNullish(mx, present) {
		memBody = append([]byte{0}, sbxULEB(sbxInt(mem["min"], 0))...)
	} else {
		memBody = sbxCat([]byte{1}, sbxULEB(sbxInt(mem["min"], 0)), sbxULEB(sbxInt(mx, 0)))
	}
	memory := sbxVec(memBody)
	runIndex := int64(1 + len(extra))
	calls, _ := spec["calls"].([]any)
	returns := "last"
	if r, ok := spec["returns"].(string); ok && r != "" {
		returns = r
	}
	body := []byte{0}
	for i, ci := range calls {
		c, _ := ci.(map[string]any)
		body = sbxCat(body, sbxI32c(sbxInt(c["handle"], 0)), sbxI32c(sbxInt(c["ptr"], 0)), sbxI32c(sbxInt(c["cap"], 0)), []byte{0x10, 0})
		if !(i == len(calls)-1 && returns == "last") {
			body = append(body, 0x1A)
		}
	}
	if sp, present := spec["spin"]; sbxTruthy(sp, present) {
		body = append(body, 0x03, 0x40, 0x0C, 0x00, 0x0B)
	}
	if spec["returns"] == "byte0" {
		body = sbxCat(body, sbxI32c(0), []byte{0x2D, 0, 0})
	}
	if len(calls) == 0 {
		body = append(body, sbxI32c(0)...)
	}
	body = append(body, 0x0B)
	return sbxCat([]byte{0, 0x61, 0x73, 0x6D, 1, 0, 0, 0}, sbxSection(1, types), sbxSection(2, imports), sbxSection(3, sbxVec([]byte{1})), sbxSection(5, memory),
		sbxSection(7, sbxVec(sbxCat(sbxStr("memory"), []byte{2, 0}), sbxCat(sbxStr("run"), []byte{0}, sbxULEB(runIndex)))),
		sbxSection(10, sbxVec(append(sbxULEB(int64(len(body))), body...))))
}

func sbxOneNum() any { return jsNumber(1) }

// BuildProbeTool is a tool that asks the table what it holds: it returns `handle_count() * 256 + first byte of handle 1's verb`.
func BuildProbeTool(cap int64) []byte {
	types := sbxVec([]byte{0x60, 3, 0x7F, 0x7F, 0x7F, 1, 0x7F}, []byte{0x60, 0, 1, 0x7F})
	imports := sbxVec(sbxCat(sbxStr("pca:act"), sbxStr("invoke"), []byte{0, 0}), sbxCat(sbxStr("pca:act"), sbxStr("handle_count"), []byte{0, 1}),
		sbxCat(sbxStr("pca:act"), sbxStr("handle_verb"), []byte{0, 0}))
	body := sbxCat([]byte{0}, sbxI32c(1), sbxI32c(0), sbxI32c(cap), []byte{0x10, 2, 0x1A, 0x10, 1}, sbxI32c(256), []byte{0x6C}, sbxI32c(0), []byte{0x2D, 0, 0, 0x6A, 0x0B})
	return sbxCat([]byte{0, 0x61, 0x73, 0x6D, 1, 0, 0, 0}, sbxSection(1, types), sbxSection(2, imports), sbxSection(3, sbxVec([]byte{1})),
		sbxSection(5, sbxVec([]byte{1, 1, 1})), sbxSection(7, sbxVec(sbxCat(sbxStr("memory"), []byte{2, 0}), sbxCat(sbxStr("run"), []byte{0, 3}))),
		sbxSection(10, sbxVec(append(sbxULEB(int64(len(body))), body...))))
}

// ReferenceComponentWat is the reference tool as a component in the WebAssembly text format: it imports only
// `pca:act/invoke@0.1.0` and exports `run: func() -> s32`. Options: {handle?: default 1, spin?: loop forever, extraImport?: an
// import the host must refuse}.
func ReferenceComponentWat(o map[string]any) string {
	imp, hasImp := o["extraImport"]
	extra := ""
	if sbxTruthy(imp, hasImp) {
		extra = `(import "` + jsValueString(imp) + `" (instance (export "get-arguments" (func (result (list string))))))`
	}
	handle := "1"
	if h, present := o["handle"]; !sbxNullish(h, present) {
		handle = jsValueString(h)
	}
	var body string
	if sp, present := o["spin"]; sbxTruthy(sp, present) {
		body = "(loop $l (br $l)) (i32.const 0)"
	} else {
		body = "(call $invoke (i32.const " + handle + ") (i32.const 16))\n" +
			"       (if (result i32) (i32.load8_u (i32.const 16))\n" +
			"         (then (i32.load (i32.const 20)))\n" +
			"         (else (i32.load8_u (i32.load (i32.const 20)))))"
	}
	return "(component\n" +
		`  (import "pca:act/invoke@0.1.0" (instance $inv` + "\n" +
		`    (export "handle-count" (func (result u32)))` + "\n" +
		`    (export "invoke" (func (param "handle" u32) (result (result (list u8) (error s32)))))))` + "\n" +
		"  " + extra + "\n" +
		"  (core module $libc\n" +
		`    (memory (export "memory") 1 1)` + "\n" +
		"    (global $bump (mut i32) (i32.const 1024))\n" +
		`    (func (export "realloc") (param $old i32) (param $oldsz i32) (param $align i32) (param $new i32) (result i32)` + "\n" +
		"      (local $p i32)\n" +
		"      (local.set $p (global.get $bump))\n" +
		"      (global.set $bump (i32.add (local.get $p) (local.get $new)))\n" +
		"      (local.get $p)))\n" +
		"  (core instance $libc (instantiate $libc))\n" +
		`  (alias core export $libc "memory" (core memory $mem))` + "\n" +
		`  (alias core export $libc "realloc" (core func $realloc))` + "\n" +
		`  (core func $count (canon lower (func $inv "handle-count")))` + "\n" +
		`  (core func $invoke (canon lower (func $inv "invoke") (memory $mem) (realloc $realloc)))` + "\n" +
		"  (core module $main\n" +
		`    (import "libc" "memory" (memory 1))` + "\n" +
		`    (import "host" "count" (func $count (result i32)))` + "\n" +
		`    (import "host" "invoke" (func $invoke (param i32 i32)))` + "\n" +
		`    (func (export "run") (result i32)` + "\n" +
		"      " + body + "))\n" +
		`  (core instance $host (export "count" (func $count)) (export "invoke" (func $invoke)))` + "\n" +
		`  (core instance $main (instantiate $main (with "libc" (instance $libc)) (with "host" (instance $host))))` + "\n" +
		`  (alias core export $main "run" (core func $run))` + "\n" +
		"  (func $lifted (result s32) (canon lift (core func $run)))\n" +
		`  (export "run" (func $lifted)))` + "\n"
}
