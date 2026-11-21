package pca

// WebAssembly host support that needs no engine: the memory-section parser shared with the in-process core host (package
// wasmhost, a separate opt-in module so this package stays dependency-free and cgo-free) and the component host, which runs a
// component in the pinned reference wasmtime host binary as a subprocess.

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"sync/atomic"
	"time"
)

// SandboxRunResult is the outcome of a wasm run: OK with Value, or !OK with a Reason. FuelUsed is set by the component host only.
type SandboxRunResult struct {
	OK       bool
	Value    int64
	FuelUsed int64
	Reason   string
}

// SandboxRunFail is a refused or failed run.
func SandboxRunFail(reason string) SandboxRunResult { return SandboxRunResult{Reason: reason} }

// SandboxBadFuel reports whether fuel is not a positive safe integer: a budget is a decision, so there is no default.
func SandboxBadFuel(fuel int64) bool { return fuel < 1 || fuel > 1<<53-1 }

// SandboxMemoryInfo is the first memory of a module. Min is huge and Shared true for a flag above 3 (memory64 and newer), which is refused.
type SandboxMemoryInfo struct {
	Count, Min, Max int64
	HasMax, Shared  bool
}

// SandboxMemoryLimits parses ONLY the memory section (it also sees non-exported memories). info nil = no memory section; ok false =
// unparseable.
func SandboxMemoryLimits(b []byte) (info *SandboxMemoryInfo, ok bool) {
	if len(b) < 8 || b[0] != 0 || string(b[1:4]) != "asm" {
		return nil, false
	}
	o := 8
	leb := func() (int64, bool) {
		var r int64
		for shift := uint(0); shift < 35; shift += 7 {
			if o >= len(b) {
				return 0, false
			}
			x := b[o]
			o++
			r += int64(x&0x7F) << shift
			if x&0x80 == 0 {
				return r, true
			}
		}
		return 0, false
	}
	for o < len(b) {
		sid := b[o]
		o++
		size, good := leb()
		if !good || int64(o)+size > int64(len(b)) {
			return nil, false
		}
		end := o + int(size)
		if sid != 5 {
			o = end
			continue
		}
		count, good := leb()
		if !good {
			return nil, false
		}
		if count == 0 {
			return nil, true
		}
		if o >= len(b) {
			return nil, false
		}
		flag := b[o]
		o++
		if flag > 3 {
			return &SandboxMemoryInfo{Count: count, Min: math.MaxInt64, Shared: true}, true
		}
		mn, good := leb()
		if !good {
			return nil, false
		}
		in := &SandboxMemoryInfo{Count: count, Min: mn, Shared: flag&2 != 0}
		if flag&1 != 0 {
			if in.Max, good = leb(); !good {
				return nil, false
			}
			in.HasMax = true
		}
		return in, true
	}
	return nil, true
}

// ComponentOptions configures RunComponent. Host and ExpectedSHA256 come from configuration only (env fallbacks
// PCA_WASMTIME_HOST and PCA_WASMTIME_HOST_SHA256), never from the component or a request.
type ComponentOptions struct {
	Fuel           int64  // required, positive
	TimeoutMs      int    // 0 = 10000
	Host           string // path of the reference host binary
	ExpectedSHA256 string // 64 hex chars
	MaxResultBytes int    // 0 = 1 MiB
}

// RunComponent runs a component (binary or WAT text) in the pinned reference wasmtime host, as a subprocess, under an instruction
// budget. The binary is read, compared (constant time) with the pin, then the VERIFIED BYTES are written to a fresh 0700 temp dir and
// that copy is executed, so the file cannot change between the hash and the exec. The child has an empty environment, no shell and no
// stderr. Every handle use goes through table.
func RunComponent(table *HandleTable, component []byte, o ComponentOptions) SandboxRunResult {
	if SandboxBadFuel(o.Fuel) {
		return SandboxRunFail("bad_fuel")
	}
	host := o.Host
	if host == "" {
		host = os.Getenv("PCA_WASMTIME_HOST")
	}
	if host == "" {
		return SandboxRunFail("host_missing")
	}
	binary, err := os.ReadFile(host)
	if err != nil {
		return SandboxRunFail("host_missing")
	}
	pin := o.ExpectedSHA256
	if pin == "" {
		pin = os.Getenv("PCA_WASMTIME_HOST_SHA256")
	}
	pinBytes, derr := hex.DecodeString(pin)
	if derr != nil || len(pin) != 64 {
		return SandboxRunFail("host_unpinned")
	}
	if sum := sha256.Sum256(binary); subtle.ConstantTimeCompare(sum[:], pinBytes) != 1 {
		return SandboxRunFail("host_hash_mismatch")
	}
	timeout := time.Duration(o.TimeoutMs) * time.Millisecond
	if o.TimeoutMs <= 0 {
		timeout = 10 * time.Second
	}
	maxResult := o.MaxResultBytes
	if maxResult <= 0 {
		maxResult = 1 << 20
	}

	dir, err := os.MkdirTemp("", "pca-comp-") // 0700
	if err != nil {
		return SandboxRunFail("host_unavailable")
	}
	defer os.RemoveAll(dir)
	exeName := "host"
	if runtime.GOOS == "windows" {
		exeName += ".exe" // Windows starts only a file with an executable extension
	}
	exe, comp := filepath.Join(dir, exeName), filepath.Join(dir, "tool.component")
	if os.WriteFile(exe, binary, 0o700) != nil || os.WriteFile(comp, component, 0o600) != nil {
		return SandboxRunFail("host_unavailable")
	}
	cmd := exec.Command(exe, comp, strconv.FormatInt(o.Fuel, 10)) // no shell
	cmd.Env = []string{}                                          // non-nil and empty: no inherited secrets
	cmd.Dir = dir
	stdin, e1 := cmd.StdinPipe()
	stdout, e2 := cmd.StdoutPipe()
	if e1 != nil || e2 != nil || cmd.Start() != nil {
		return SandboxRunFail("host_unavailable")
	}
	var timedOut atomic.Bool
	kill := time.AfterFunc(timeout, func() { timedOut.Store(true); _ = cmd.Process.Kill() }) // also unblocks a stuck pipe write
	defer func() { kill.Stop(); _ = cmd.Process.Kill(); _ = stdin.Close(); _ = cmd.Wait() }()
	fail := func(reason string) SandboxRunResult {
		if timedOut.Load() {
			return SandboxRunFail("timeout")
		}
		return SandboxRunFail(reason)
	}

	rd := bufio.NewReader(io.LimitReader(stdout, 64<<20))
	reply := func(v any) bool {
		b, _ := json.Marshal(v)
		_, werr := stdin.Write(append(b, '\n'))
		return werr == nil
	}
	for {
		line, rerr := rd.ReadBytes('\n')
		if len(bytes.TrimSpace(line)) == 0 && rerr != nil {
			return fail("host_exit")
		}
		var m map[string]any
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.UseNumber()
		if dec.Decode(&m) != nil || m == nil {
			return fail("host_protocol")
		}
		if s, isStr := m["fail"].(string); isStr {
			return SandboxRunFail(s)
		}
		if d, isNum := m["done"].(json.Number); isNum {
			r := SandboxRunResult{OK: true, Value: numInt(d)}
			if fu, has := m["fuel_used"].(json.Number); has {
				r.FuelUsed = numInt(fu)
			}
			return r
		}
		var h any = 0
		if hn, isNum := m["h"].(json.Number); isNum {
			h = hn
		}
		switch m["op"] {
		case "count":
			if !reply(map[string]any{"n": table.Size()}) {
				return fail("host_exit")
			}
		case "verb":
			v, known := table.VerbOf(h)
			rep := map[string]any{"ok": v}
			if !known {
				rep = map[string]any{"err": SandboxUseErr["unknown_handle"]}
			}
			if !reply(rep) {
				return fail("host_exit")
			}
		case "invoke":
			r, uerr := table.Use(h)
			var rep map[string]any
			switch {
			case uerr != nil:
				rep = map[string]any{"err": SandboxUseErr["executor_error"]}
			case r["ok"] != true:
				rep = map[string]any{"err": SandboxUseErr[r["reason"].(string)]}
			default:
				res, _ := r["result"].([]byte)
				if len(res) > maxResult {
					rep = map[string]any{"err": SandboxUseErr["out_too_small"]}
				} else {
					ints := make([]int, len(res))
					for i, c := range res {
						ints[i] = int(c)
					}
					rep = map[string]any{"ok": ints}
				}
			}
			if !reply(rep) {
				return fail("host_exit")
			}
		default:
			return fail("host_protocol")
		}
	}
}

func numInt(n json.Number) int64 {
	if i, err := n.Int64(); err == nil {
		return i
	}
	f, _ := n.Float64()
	return int64(f)
}
