package pca

// Policy logic of the PCA sandbox: runtime classes and signed runtime claims, the receipt hash chain, the capability handle
// table, the egress admission policy, the OS-profile generators (seccomp / Landlock / macOS) and the private-address rule.
// Values are JSON-like (maps, slices, json.Number) so a hostile shape is judged the way the reference judges it.
//
// Not here: the WebAssembly / component hosts, the egress proxy server and the attestation-verifier glue (each needs a runtime
// this package does not carry). A class is a claim by the host operator; nothing here proves an OS profile was applied.

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"regexp"
	"strings"
)

// Sandbox module constants.
const (
	SandboxImportModule = "pca:act"
	SandboxGenesis      = "genesis"
	// RuntimeClaimDomain is the signing domain of a runtime-class claim.
	RuntimeClaimDomain = "atlas-pca/runtime-class-claim/v1\x00"
)

// SandboxAllowedImports are the host functions a sandboxed tool may import.
var SandboxAllowedImports = []string{"invoke", "handle_count", "handle_verb"}

// SandboxUseErr are the negative return codes of the invoke import.
var SandboxUseErr = map[string]int{"unknown_handle": -1, "spent": -2, "out_too_small": -3, "bad_memory": -4, "executor_error": -5, "no_executor": -6}

// RuntimeClasses are the runtime classes, weakest first.
var RuntimeClasses = []string{"none", "os_confined", "egress_default_deny", "wasi_no_ambient"}

// ---- JS helpers ------------------------------------------------------------------------------------------------------------------

// sbxGet reads member k of a JSON object; ok is false for a missing member or a non-object (JS undefined).
func sbxGet(o any, k string) (any, bool) {
	m, isMap := o.(map[string]any)
	if !isMap {
		return nil, false
	}
	v, ok := m[k]
	return v, ok
}

func sbxTruthy(v any, present bool) bool {
	if !present || v == nil {
		return false
	}
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return t != ""
	}
	if f, ok := jsNum(v); ok {
		return f != 0 && !math.IsNaN(f)
	}
	return true
}

func sbxNullish(v any, present bool) bool { return !present || v == nil }

func sbxIsInt(v any) (float64, bool) {
	f, ok := jsNum(v)
	if !ok || math.IsNaN(f) || math.IsInf(f, 0) || f != math.Trunc(f) {
		return 0, false
	}
	return f, true
}

func sbxText(v any, present bool) string {
	if !present {
		return "undefined"
	}
	return jsValueString(v)
}

func sbxSort(xs []string) []string { return jsSortStrings(xs) }

func sbxAnyList(xs []string) []any { return connAnyList(xs) }

// ---- runtime classes / receipts ----------------------------------------------------------------------------------------------------

func sbxClassIndex(v any) int {
	s, ok := v.(string)
	if !ok {
		return -1
	}
	for i, c := range RuntimeClasses {
		if c == s {
			return i
		}
	}
	return -1
}

// SatisfiesRuntimeClass is true only when both names are known and attested is at least required. An unknown name never satisfies.
func SatisfiesRuntimeClass(attested, required any) bool {
	a, r := sbxClassIndex(attested), sbxClassIndex(required)
	return a >= 0 && r >= 0 && a >= r
}

// SandboxReceiptLog is an append-only hash chain of use receipts: every handle use and every egress decision, refusals included.
type SandboxReceiptLog struct {
	Entries []map[string]any
	now     func() float64
	sign    func(digest string) string
}

// NewSandboxReceiptLog builds a log; now nil = the wall clock, sign nil = unsigned entries.
func NewSandboxReceiptLog(now func() float64, sign func(digest string) string) *SandboxReceiptLog {
	if now == nil {
		now = func() float64 { return connNow(nil) }
	}
	return &SandboxReceiptLog{now: now, sign: sign}
}

// Append adds an entry; body members override the chain members (as in the reference). It fails, appending nothing, when the entry
// is outside the strict canonical profile.
func (l *SandboxReceiptLog) Append(runtimeClass string, body map[string]any) (map[string]any, error) {
	prev := SandboxGenesis
	if n := len(l.Entries); n > 0 {
		prev, _ = l.Entries[n-1]["digest"].(string)
	}
	unsigned := map[string]any{"v": sbxOne(), "seq": jsNumber(float64(len(l.Entries))), "prev": prev, "at": jsNumber(l.now()), "runtime_class": runtimeClass}
	for k, v := range body {
		unsigned[k] = v
	}
	digest, err := HashCanonical(unsigned)
	if err != nil {
		return nil, err
	}
	r := map[string]any{}
	for k, v := range unsigned {
		r[k] = v
	}
	r["digest"] = digest
	if l.sign != nil {
		r["sig"] = l.sign(digest)
	}
	l.Entries = append(l.Entries, r)
	return r, nil
}

func sbxOne() any { return jsNumber(1) }

// VerifyReceiptChain recomputes the chain. It fails on a bad digest, a broken link, a gap, a reorder, or (with verifySig) a bad
// signature; the result is {"ok":true} or {"ok":false,"at":i,"reason":...}. A non-list or a null entry is an error.
func VerifyReceiptChain(receipts any, verifySig func(digest string, sig any) bool) (map[string]any, error) {
	list, ok := receipts.([]any)
	if !ok {
		return nil, errors.New("receipts is not iterable")
	}
	prev := SandboxGenesis
	for i, r := range list {
		if r == nil {
			return nil, errors.New("receipt is null")
		}
		fail := func(reason string) map[string]any {
			return map[string]any{"ok": false, "at": jsNumber(float64(i)), "reason": reason}
		}
		v, hasV := sbxGet(r, "v")
		seq, hasSeq := sbxGet(r, "seq")
		vf, vOK := jsNum(v)
		sf, sOK := jsNum(seq)
		if !hasV || !hasSeq || !vOK || vf != 1 || !sOK || sf != float64(i) {
			return fail("bad_seq"), nil
		}
		p, _ := sbxGet(r, "prev")
		if ps, isStr := p.(string); !isStr || ps != prev {
			return fail("broken_link"), nil
		}
		m := r.(map[string]any)
		digest, isStr := m["digest"].(string)
		sig, hasSig := m["sig"]
		rest := map[string]any{}
		for k, x := range m {
			if k != "digest" && k != "sig" {
				rest[k] = x
			}
		}
		if !isStr {
			return fail("bad_digest"), nil
		}
		h, err := HashCanonical(rest)
		if err != nil {
			return nil, err
		}
		if h != digest {
			return fail("bad_digest"), nil
		}
		if verifySig != nil {
			if _, isS := sig.(string); !hasSig || !isS || !verifySig(digest, sig) {
				return fail("bad_sig"), nil
			}
		}
		prev = digest
	}
	return map[string]any{"ok": true}, nil
}

// ---- authorized operations ----------------------------------------------------------------------------------------------------------

// SandboxIsAuthorizedFor is true only if result allowed exactly this operation (verb, resource, params digest). result is any object
// with `allow` (or `ok`) and a bound `operation` {verb, resource, params_digest}.
func SandboxIsAuthorizedFor(result, operation any) bool {
	allow, hasAllow := sbxGet(result, "allow")
	ok, hasOk := allow, hasAllow
	if !hasAllow {
		ok, hasOk = sbxGet(result, "ok")
	}
	bound, hasBound := sbxGet(result, "operation")
	o, isMap := operation.(map[string]any)
	valid := false
	if isMap {
		verb, _ := o["verb"].(string)
		res, _ := o["resource"].(string)
		_, params := o["params"].(map[string]any)
		valid = verb != "" && res != "" && params
	}
	if !sbxTruthy(ok, hasOk) || !sbxTruthy(bound, hasBound) || !valid {
		return false
	}
	want, err := HashCanonical(o["params"])
	if err != nil {
		return false
	}
	bv, _ := sbxGet(bound, "verb")
	br, _ := sbxGet(bound, "resource")
	bd, _ := sbxGet(bound, "params_digest")
	return bv == o["verb"] && br == o["resource"] && bd == want
}

// ---- OS policy ---------------------------------------------------------------------------------------------------------------------------

var (
	sbxPathRx = regexp.MustCompile(`^/[A-Za-z0-9._+@=,:~ /-]*$`)
	sbxHostRx = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$`)
)

func sbxCheckPath(v any) (string, error) {
	p, ok := v.(string)
	if !ok || !sbxPathRx.MatchString(p) || strings.Contains(p, "//") || (len(p) > 1 && strings.HasSuffix(p, "/")) {
		return "", errors.New("bad_path")
	}
	for _, s := range strings.Split(p, "/") {
		if s == "." || s == ".." {
			return "", errors.New("bad_path")
		}
	}
	return p, nil
}

// sbxIterate is `for (const v of x ?? [])`: an array iterates, "" iterates nothing, any other value is not iterable here.
func sbxIterate(x any, present bool) ([]any, error) {
	if sbxNullish(x, present) {
		return nil, nil
	}
	switch t := x.(type) {
	case []any:
		return t, nil
	case string:
		if t == "" {
			return nil, nil
		}
	}
	return nil, errors.New("not iterable")
}

// PolicyFromNeeds validates, merges and sorts the needs of the authorized operations into a sandbox policy {v, fs: {read, write,
// exec}, net: {proxy, hosts}}. `write` implies read of the same path; network access exists only through the egress proxy
// (proxyPort nil = none).
func PolicyFromNeeds(needs any, proxyPort any) (map[string]any, error) {
	list, ok := needs.([]any)
	if !ok {
		return nil, errors.New("needs is not iterable")
	}
	read, write, ex, hosts := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, n := range list {
		if n == nil {
			return nil, errors.New("need is null")
		}
		fsV, fsP := sbxGet(n, "fs")
		files, err := sbxIterate(fsV, fsP)
		if err != nil {
			return nil, err
		}
		for _, f := range files {
			if f == nil {
				return nil, errors.New("fs entry is null")
			}
			pv, _ := sbxGet(f, "path")
			p, err := sbxCheckPath(pv)
			if err != nil {
				return nil, err
			}
			mode, _ := sbxGet(f, "mode")
			switch mode {
			case "x":
				ex[p] = true
			case "r", "rw":
				read[p] = true
				if mode == "rw" {
					write[p] = true
				}
			default:
				return nil, errors.New("bad_mode")
			}
		}
		netV, netP := sbxGet(n, "net")
		nets, err := sbxIterate(netV, netP)
		if err != nil {
			return nil, err
		}
		for _, h := range nets {
			if h == nil {
				return nil, errors.New("net entry is null")
			}
			host, hostP := sbxGet(h, "host")
			port, _ := sbxGet(h, "port")
			text := sbxText(host, hostP)
			pf, isInt := sbxIsInt(port)
			if !sbxHostRx.MatchString(text) || !isInt || pf < 1 || pf > 65535 {
				return nil, errors.New("bad_net_need")
			}
			hosts[text+":"+jsValueString(port)] = true
		}
	}
	if len(hosts) > 0 && proxyPort == nil {
		return nil, errors.New("net_needs_proxy: network access exists only through the egress proxy; pass its port")
	}
	var proxy any
	if proxyPort != nil {
		pf, isInt := sbxIsInt(proxyPort)
		if !isInt || pf < 1 || pf > 65535 {
			return nil, errors.New("bad_proxy_port")
		}
		proxy = map[string]any{"host": "127.0.0.1", "port": proxyPort}
	}
	keys := func(m map[string]bool) []any {
		out := make([]string, 0, len(m))
		for k := range m {
			out = append(out, k)
		}
		return sbxAnyList(sbxSort(out))
	}
	return map[string]any{"v": sbxOne(), "fs": map[string]any{"read": keys(read), "write": keys(write), "exec": keys(ex)},
		"net": map[string]any{"proxy": proxy, "hosts": keys(hosts)}}, nil
}

// SandboxCompileItem is an authorized operation: the authorization result and the operation it allowed.
type SandboxCompileItem struct{ Result, Operation any }

// SandboxCompilePolicy compiles the OS policy from what was actually authorized: only operations SandboxIsAuthorizedFor allows contribute;
// needsOf is the tool author's mapping (a falsy value contributes nothing).
func SandboxCompilePolicy(items []SandboxCompileItem, needsOf func(operation any) any, proxyPort any) (map[string]any, error) {
	needs := []any{}
	for _, it := range items {
		if !SandboxIsAuthorizedFor(it.Result, it.Operation) {
			return nil, errors.New("not_authorized: result does not allow exactly this operation")
		}
		if n := needsOf(it.Operation); sbxTruthy(n, true) {
			needs = append(needs, n)
		}
	}
	return PolicyFromNeeds(needs, proxyPort)
}

type sbxPolicy struct {
	read, write, exec []string
	proxy             map[string]any
}

func sbxPolicyOf(p map[string]any) (*sbxPolicy, error) {
	fs, _ := p["fs"].(map[string]any)
	net, _ := p["net"].(map[string]any)
	if fs == nil || net == nil {
		return nil, errors.New("bad policy")
	}
	out := &sbxPolicy{}
	for _, f := range []struct {
		k   string
		dst *[]string
	}{{"read", &out.read}, {"write", &out.write}, {"exec", &out.exec}} {
		l, ok := connStrList(fs[f.k])
		if !ok {
			return nil, errors.New("bad policy")
		}
		*f.dst = l
	}
	if pr, isMap := net["proxy"].(map[string]any); isMap {
		out.proxy = pr
	}
	return out, nil
}

var (
	sbxBase = []string{"read", "write", "close", "fstat", "newfstatat", "statx", "lseek", "mmap", "mprotect", "munmap", "mremap", "brk", "madvise",
		"rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "sigaltstack", "pread64", "pwrite64", "readv", "writev", "openat", "getdents64",
		"fcntl", "getcwd", "readlink", "readlinkat", "dup", "dup3", "pipe2", "poll", "ppoll", "epoll_create1", "epoll_ctl", "epoll_pwait",
		"eventfd2", "futex", "set_tid_address", "set_robust_list", "rseq", "arch_prctl", "prlimit64", "sched_yield", "nanosleep",
		"clock_nanosleep", "clock_gettime", "gettimeofday", "getrandom", "getpid", "gettid", "getuid", "geteuid", "getgid", "getegid",
		"uname", "tgkill", "exit", "exit_group"}
	sbxNet  = []string{"connect", "getsockopt", "setsockopt", "getsockname", "getpeername", "sendto", "recvfrom", "sendmsg", "recvmsg", "shutdown"}
	sbxExec = []string{"execve", "execveat"}
)

// SeccompProfile is a Docker / OCI-format seccomp profile: deny by default; network syscalls only when the policy has a proxy;
// `socket` only for AF_INET / AF_INET6; exec only when the grant names a binary. seccomp cannot see paths or addresses: pair it
// with Landlock.
func SeccompProfile(p map[string]any) (map[string]any, error) {
	pol, err := sbxPolicyOf(p)
	if err != nil {
		return nil, err
	}
	sys := []any{map[string]any{"names": sbxAnyList(sbxSort(sbxBase)), "action": "SCMP_ACT_ALLOW"}}
	if pol.proxy != nil {
		sys = append(sys, map[string]any{"names": sbxAnyList(sbxSort(sbxNet)), "action": "SCMP_ACT_ALLOW"})
		for _, d := range []int{2, 10} {
			sys = append(sys, map[string]any{"names": []any{"socket"}, "action": "SCMP_ACT_ALLOW",
				"args": []any{map[string]any{"index": 0, "value": d, "op": "SCMP_CMP_EQ"}}})
		}
	}
	if len(pol.exec) > 0 {
		sys = append(sys, map[string]any{"names": sbxAnyList(sbxExec), "action": "SCMP_ACT_ALLOW"})
	}
	return map[string]any{"defaultAction": "SCMP_ACT_ERRNO", "defaultErrnoRet": 1,
		"archMap": []any{map[string]any{"architecture": "SCMP_ARCH_X86_64", "subArchitectures": []any{}},
			map[string]any{"architecture": "SCMP_ARCH_AARCH64", "subArchitectures": []any{}}},
		"syscalls": sys}, nil
}

var sbxFSHandled = []string{"EXECUTE", "WRITE_FILE", "READ_FILE", "READ_DIR", "REMOVE_DIR", "REMOVE_FILE", "MAKE_CHAR", "MAKE_DIR", "MAKE_REG",
	"MAKE_SOCK", "MAKE_FIFO", "MAKE_BLOCK", "MAKE_SYM", "REFER", "TRUNCATE"}

// LandlockRuleset is a Landlock ruleset (access-right names from the kernel UAPI; network rules need ABI 4): handle every right,
// allow only what the grant names.
func LandlockRuleset(p map[string]any) (map[string]any, error) {
	pol, err := sbxPolicyOf(p)
	if err != nil {
		return nil, err
	}
	in := func(xs []string, s string) bool { return connInList(xs, s) }
	all := map[string]bool{}
	for _, l := range [][]string{pol.read, pol.write, pol.exec} {
		for _, s := range l {
			all[s] = true
		}
	}
	paths := make([]string, 0, len(all))
	for s := range all {
		paths = append(paths, s)
	}
	fs := []any{}
	for _, path := range sbxSort(paths) {
		var access []string
		if in(pol.exec, path) {
			access = append(access, "EXECUTE", "READ_FILE") // execve opens the binary for reading, so the kernel also demands READ_FILE
		}
		if in(pol.read, path) {
			access = append(access, "READ_FILE", "READ_DIR")
		}
		if in(pol.write, path) {
			access = append(access, "WRITE_FILE", "TRUNCATE", "MAKE_REG", "MAKE_DIR", "REMOVE_FILE", "REMOVE_DIR")
		}
		names := []any{}
		for _, x := range connDedup(access) {
			names = append(names, "LANDLOCK_ACCESS_FS_"+x)
		}
		fs = append(fs, map[string]any{"path": path, "access": names})
	}
	handled := []any{}
	for _, x := range sbxFSHandled {
		handled = append(handled, "LANDLOCK_ACCESS_FS_"+x)
	}
	netRules := []any{}
	if pol.proxy != nil {
		netRules = append(netRules, map[string]any{"port": pol.proxy["port"], "access": []any{"LANDLOCK_ACCESS_NET_CONNECT_TCP"}})
	}
	return map[string]any{"v": sbxOne(), "abi_min": 4, "handled_access_fs": handled,
		"handled_access_net": []any{"LANDLOCK_ACCESS_NET_BIND_TCP", "LANDLOCK_ACCESS_NET_CONNECT_TCP"},
		"rules":              map[string]any{"fs": fs, "net": netRules}}, nil
}

// MacosProfile is a macOS sandbox profile (SBPL for sandbox-exec(1)): deny by default; paths were validated to need no escaping.
func MacosProfile(p map[string]any) (string, error) {
	pol, err := sbxPolicyOf(p)
	if err != nil {
		return "", err
	}
	q := func(s string) string { return `"` + s + `"` }
	lines := []string{"(version 1)", "(deny default)", "(allow sysctl-read)", "(allow process-fork)", "(allow mach-lookup)", "(allow file-read-metadata)",
		`(allow file-read* (literal "/") (literal "/dev/null") (literal "/dev/urandom") (subpath "/usr/lib") ` +
			`(subpath "/System/Library") (subpath "/private/var/db/dyld") (subpath "/System/Volumes/Preboot/Cryptexes"))`}
	for _, x := range pol.exec {
		lines = append(lines, "(allow process-exec (literal "+q(x)+"))", "(allow file-read* (literal "+q(x)+"))")
	}
	for _, r := range pol.read {
		lines = append(lines, "(allow file-read* (subpath "+q(r)+"))")
	}
	for _, w := range pol.write {
		lines = append(lines, "(allow file-write* (subpath "+q(w)+"))")
	}
	if pol.proxy != nil {
		lines = append(lines, "(allow network-outbound (remote tcp "+q("localhost:"+jsValueString(pol.proxy["port"]))+"))")
	}
	return strings.Join(lines, "\n") + "\n", nil
}

// ConfineArgs flattens the generated seccomp and Landlock profiles into the flags of a reference `pca-confine <flags> -- <command>`
// helper, so what the helper enforces is exactly what the generators produced.
func ConfineArgs(policy map[string]any) ([]string, error) {
	pol, err := sbxPolicyOf(policy)
	if err != nil {
		return nil, err
	}
	ll, err := LandlockRuleset(policy)
	if err != nil {
		return nil, err
	}
	sc, err := SeccompProfile(policy)
	if err != nil {
		return nil, err
	}
	short := func(n string) string { return strings.TrimPrefix(n, "LANDLOCK_ACCESS_") }
	joinShort := func(l any) string {
		var out []string
		for _, x := range l.([]any) {
			out = append(out, short(x.(string)))
		}
		return strings.Join(out, ",")
	}
	rules := ll["rules"].(map[string]any)
	netRules := rules["net"].([]any)
	args := []string{"--fs-handled", joinShort(ll["handled_access_fs"])}
	if len(netRules) > 0 || pol.proxy != nil {
		args = append(args, "--net-handled", joinShort(ll["handled_access_net"]))
	}
	for _, r := range rules["fs"].([]any) {
		m := r.(map[string]any)
		args = append(args, "--fs", m["path"].(string)+":"+joinShort(m["access"]))
	}
	for _, r := range netRules {
		m := r.(map[string]any)
		args = append(args, "--net", jsValueString(m["port"])+":"+joinShort(m["access"]))
	}
	for _, s := range sc["syscalls"].([]any) {
		m := s.(map[string]any)
		names := m["names"].([]any)
		if as, ok := m["args"].([]any); ok && len(as) > 0 {
			for _, a := range as {
				am := a.(map[string]any)
				for _, n := range names {
					args = append(args, "--allow-arg", fmt.Sprintf("%s:%d:%d", n, am["index"], am["value"]))
				}
			}
		} else {
			for _, n := range names {
				args = append(args, "--allow", n.(string))
			}
		}
	}
	return args, nil
}

// ---- runtime claims --------------------------------------------------------------------------------------------------------------------

var sbxClaimKeys = []string{"v", "class", "passport_digest", "evidence_digest", "iat", "exp", "attestor", "sig"}

func sbxClaimBody(c map[string]any) ([]byte, error) {
	b, err := canonBytes(c)
	if err != nil {
		return nil, err
	}
	return append([]byte(RuntimeClaimDomain), b...), nil
}

// SignRuntimeClaim is a signed statement that a sandbox runs at `class`, bound to the signed passport (by digest) of the agent it
// contains. The signer is an attestor the verifier pins; publicKey is its base64url key. It signs domain || canonical(claim
// without sig) with Ed25519 and fails on a seed that is not 32 bytes or a claim outside the strict canonical profile.
func SignRuntimeClaim(seed []byte, publicKey string, c map[string]any) (map[string]any, error) {
	kp, err := KeyPairFromSeed(seed)
	if err != nil {
		return nil, err
	}
	unsigned := map[string]any{"v": sbxOne()}
	for k, v := range c {
		unsigned[k] = v
	}
	unsigned["attestor"] = publicKey
	body, err := sbxClaimBody(unsigned)
	if err != nil {
		return nil, err
	}
	unsigned["sig"] = b64.EncodeToString(kp.Sign(body))
	return unsigned, nil
}

func sbxIncludes(coll any, x string) (bool, error) {
	switch t := coll.(type) {
	case []any:
		for _, y := range t {
			if s, ok := y.(string); ok && s == x {
				return true, nil
			}
		}
		return false, nil
	case string:
		return strings.Contains(t, x), nil
	}
	return false, errors.New("includes is not a function")
}

func sbxNat(v any) (float64, bool) {
	f, ok := sbxIsInt(v)
	if !ok || (f == 0 && math.Signbit(f)) || f < 0 || f > 9007199254740991 {
		return 0, false
	}
	return f, true
}

func sbxStr128(v any) bool {
	s, ok := v.(string)
	return ok && s != "" && jsLen(s) <= 128
}

// SandboxVerifiedRuntimeClass is the class the claim proves, or "none" for anything missing, unsigned, unpinned, expired, for another
// passport, over evidence nobody verified, or malformed. trust is {pinnedAttestors, passportDigest, verifiedEvidenceDigests, now}.
// Total.
func SandboxVerifiedRuntimeClass(claim, trust any) string {
	c, ok := claim.(map[string]any)
	if !ok || len(c) != len(sbxClaimKeys) {
		return "none"
	}
	for k := range c {
		if !connInList(sbxClaimKeys, k) {
			return "none"
		}
	}
	if vf, ok := jsNum(c["v"]); !ok || vf != 1 || sbxClassIndex(c["class"]) < 0 {
		return "none"
	}
	sig, sigOK := c["sig"].(string)
	if !sigOK || !sbxStr128(c["attestor"]) || !sbxStr128(c["passport_digest"]) || !sbxStr128(c["evidence_digest"]) {
		return "none"
	}
	pinned, _ := sbxGet(trust, "pinnedAttestors")
	if in, err := sbxIncludes(pinned, c["attestor"].(string)); err != nil || !in {
		return "none"
	}
	nowV, _ := sbxGet(trust, "now")
	pd, _ := sbxGet(trust, "passportDigest")
	iat, iatOK := sbxNat(c["iat"])
	exp, expOK := sbxNat(c["exp"])
	now, nowOK := sbxNat(nowV)
	if c["passport_digest"] != pd || !iatOK || !expOK || !nowOK || now < iat || now >= exp {
		return "none"
	}
	ev, _ := sbxGet(trust, "verifiedEvidenceDigests")
	if in, err := sbxIncludes(ev, c["evidence_digest"].(string)); err != nil || !in || !b64uOK(c["attestor"], 32) || !b64uOK(sig, 64) {
		return "none"
	}
	rest := map[string]any{}
	for k, x := range c {
		if k != "sig" {
			rest[k] = x
		}
	}
	body, err := sbxClaimBody(rest)
	if err != nil || !verifyB64u(c["attestor"].(string), body, sig) {
		return "none"
	}
	return c["class"].(string)
}

// PassportDigest is the digest of a signed passport.
func PassportDigest(signedPassport any) (string, error) { return HashCanonical(signedPassport) }

// ---- capability handles ----------------------------------------------------------------------------------------------------------------

// HandleExecutor runs an authorized operation (a private copy) and returns the result bytes.
type HandleExecutor func(op map[string]any) ([]byte, error)

type sbxSlot struct {
	op        map[string]any
	paramsDig string
	opID      any
	uses      float64
	expiresAt float64
	revoked   bool
	children  []int
}

// HandleTable is a per-sandbox capability table: indices are small integers meaningful only inside one table, like file
// descriptors. A slot exists only because a verified PCActn authorized exactly that operation, derivation is monotone (a child
// can only hold what the parent gave up) and revoking a slot revokes everything derived from it.
type HandleTable struct {
	RuntimeClass string
	log          *SandboxReceiptLog
	executors    map[string]HandleExecutor
	now          func() float64
	slots        []*sbxSlot
}

// NewHandleTable builds a table; now nil = the wall clock.
func NewHandleTable(runtimeClass string, log *SandboxReceiptLog, executors map[string]HandleExecutor, now func() float64) *HandleTable {
	if now == nil {
		now = func() float64 { return connNow(nil) }
	}
	return &HandleTable{RuntimeClass: runtimeClass, log: log, executors: executors, now: now}
}

func sbxDeepCopy(v any) any { return normalizeJSONKeep(v) }

// normalizeJSONKeep deep-copies a JSON value, keeping numbers as they are.
func normalizeJSONKeep(v any) any {
	switch t := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(t))
		for k, x := range t {
			m[k] = normalizeJSONKeep(x)
		}
		recordKeyOrder(m, jsKeys(t)) // the copy keeps the member order the operation was given in (an executor serializes it)
		return m
	case []any:
		a := make([]any, len(t))
		for i, x := range t {
			a[i] = normalizeJSONKeep(x)
		}
		return a
	}
	return v
}

func sbxOptNum(opts map[string]any, k string, def float64) (float64, error) {
	v, present := opts[k]
	if sbxNullish(v, present) {
		return def, nil
	}
	f, ok := jsNum(v)
	if !ok {
		return 0, errors.New("bad " + k)
	}
	return f, nil
}

// Mint mints a handle for the operation result allowed. It fails closed if result does not allow exactly operation. opts:
// requires (a runtime class), uses (default 1), expiresAt.
func (t *HandleTable) Mint(result any, operation any, opts map[string]any) (int, error) {
	if req, has := opts["requires"]; has && req != nil && !SatisfiesRuntimeClass(t.RuntimeClass, req) {
		return 0, fmt.Errorf("runtime_class_too_weak: table is %s, grant requires %s", t.RuntimeClass, jsValueString(req))
	}
	if !SandboxIsAuthorizedFor(result, operation) {
		return 0, errors.New("not_authorized: result does not allow exactly this operation")
	}
	bound, _ := sbxGet(result, "operation")
	o := operation.(map[string]any)
	uses, err := sbxOptNum(opts, "uses", 1)
	if err != nil {
		return 0, err
	}
	if f, isInt := sbxIsInt(uses); !isInt || f < 1 || f > 1_000_000 {
		return 0, errors.New("bad_uses")
	}
	expires, err := sbxOptNum(opts, "expiresAt", math.Inf(1))
	if err != nil {
		return 0, err
	}
	op := map[string]any{"verb": o["verb"], "resource": o["resource"], "params": sbxDeepCopy(o["params"])}
	recordKeyOrder(op, []string{"verb", "resource", "params"})
	d, err := HashCanonical(op["params"])
	if err != nil {
		return 0, err
	}
	bid, hasID := sbxGet(bound, "id")
	var opID any = ""
	if !sbxNullish(bid, hasID) {
		opID = bid
	}
	return t.push(&sbxSlot{op: op, paramsDig: d, opID: opID, uses: uses, expiresAt: expires}), nil
}

func (t *HandleTable) push(s *sbxSlot) int {
	t.slots = append(t.slots, s)
	return len(t.slots)
}

func (t *HandleTable) slot(index any) *sbxSlot {
	f, ok := sbxIsInt(index)
	if !ok || f < 1 || f > float64(len(t.slots)) {
		return nil
	}
	return t.slots[int(f)-1]
}

func (t *HandleTable) live(index any) *sbxSlot {
	s := t.slot(index)
	if s != nil && !s.revoked && s.uses > 0 {
		if tn := t.now(); finite(tn) && tn < s.expiresAt { // a -Infinity clock is before every expiry
			return s
		}
	}
	return nil
}

// Attenuate derives a narrower handle: it takes `uses` from the parent (never more than it has) and an expiry no later than its.
func (t *HandleTable) Attenuate(index any, narrower map[string]any) (int, error) {
	p := t.live(index)
	if p == nil {
		return 0, errors.New("unknown_handle")
	}
	uses, err := sbxOptNum(narrower, "uses", p.uses)
	if err != nil {
		return 0, err
	}
	if f, isInt := sbxIsInt(uses); !isInt || f < 1 || f > p.uses {
		return 0, errors.New("attenuate_widens")
	}
	expires, err := sbxOptNum(narrower, "expiresAt", p.expiresAt)
	if err != nil || !(expires <= p.expiresAt) {
		return 0, errors.New("attenuate_widens")
	}
	p.uses -= uses
	child := t.push(&sbxSlot{op: sbxDeepCopy(p.op).(map[string]any), paramsDig: p.paramsDig, opID: p.opID, uses: uses, expiresAt: expires})
	p.children = append(p.children, child)
	return child, nil
}

// Revoke revokes a handle and, transitively, every handle derived from it.
func (t *HandleTable) Revoke(index any) {
	s := t.slot(index)
	if s == nil || s.revoked {
		return
	}
	s.revoked = true
	for _, c := range s.children {
		t.Revoke(jsNumber(float64(c)))
	}
}

// Size is the number of slots ever minted.
func (t *HandleTable) Size() int { return len(t.slots) }

// VerbOf is the verb of a handle, or ok=false for an unknown handle.
func (t *HandleTable) VerbOf(index any) (string, bool) {
	s := t.slot(index)
	if s == nil {
		return "", false
	}
	v, _ := s.op["verb"].(string)
	return v, true
}

func (t *HandleTable) finish(s *sbxSlot, ok bool, reason string, result []byte) (map[string]any, error) {
	outcome := "refused"
	switch {
	case ok:
		outcome = "ok"
	case reason == "executor_error":
		outcome = "error"
	}
	logReason := reason
	if ok {
		logReason = "used"
	}
	if _, err := t.log.Append(t.RuntimeClass, map[string]any{"kind": "handle_use", "subject": map[string]any{"op_id": s.opID, "verb": s.op["verb"],
		"resource": s.op["resource"], "params_digest": s.paramsDig}, "outcome": outcome, "reason": logReason}); err != nil {
		return nil, err
	}
	if ok {
		return map[string]any{"ok": true, "result": result}, nil
	}
	return map[string]any{"ok": false, "reason": reason}, nil
}

// Use runs the executor on the authorized operation and records a receipt. A use is consumed before the executor runs and stays
// consumed if it fails (a failed side effect needs a new authorization, not a retry on the old one). The result is {ok:true,
// result: bytes} or {ok:false, reason}.
func (t *HandleTable) Use(index any) (map[string]any, error) {
	s := t.slot(index)
	if s == nil {
		if _, err := t.log.Append(t.RuntimeClass, map[string]any{"kind": "handle_use", "subject": map[string]any{"op_id": "", "verb": "", "resource": "", "params_digest": ""},
			"outcome": "refused", "reason": "unknown_handle"}); err != nil {
			return nil, err
		}
		return map[string]any{"ok": false, "reason": "unknown_handle"}, nil
	}
	live := t.live(index)
	if live == nil {
		return t.finish(s, false, "spent", nil)
	}
	verb, _ := s.op["verb"].(string)
	ex := t.executors[verb]
	if ex == nil {
		return t.finish(s, false, "no_executor", nil)
	}
	live.uses--
	res, err := ex(sbxDeepCopy(s.op).(map[string]any))
	if err != nil || res == nil {
		return t.finish(s, false, "executor_error", nil)
	}
	return t.finish(s, true, "", res)
}

// ---- egress ------------------------------------------------------------------------------------------------------------------------------

var (
	sbxDefaultPort  = map[string]float64{"http": 80, "https": 443}
	sbxEgressHostRx = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$`)
	sbxV4Seg        = `(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])`
	sbxV4           = `(?:` + sbxV4Seg + `\.){3}` + sbxV4Seg
	sbxV4Rx         = regexp.MustCompile(`^` + sbxV4 + `$`)
	sbxV6Seg        = `(?:[0-9a-fA-F]{1,4})`
	sbxV6Rx         = regexp.MustCompile(`^(?:` + strings.NewReplacer("S", sbxV6Seg, "V", sbxV4).Replace(
		`(?:S:){7}(?:S|:)|`+
			`(?:S:){6}(?:V|:S|:)|`+
			`(?:S:){5}(?:(?::V)|(?::S){1,2}|:)|`+
			`(?:S:){4}(?:(?::S){0,1}:V|(?::S){1,3}|:)|`+
			`(?:S:){3}(?:(?::S){0,2}:V|(?::S){1,4}|:)|`+
			`(?:S:){2}(?:(?::S){0,3}:V|(?::S){1,5}|:)|`+
			`(?:S:){1}(?:(?::S){0,4}:V|(?::S){1,6}|:)|`+
			`(?::(?:(?::S){0,5}:V|(?::S){1,7}|:))`) + `)(?:%[0-9a-zA-Z.:-]{1,})?$`)
	sbxEncPathRx     = regexp.MustCompile(`(?i)%2e|%2f|%5c|\\`)
	sbxBadTemplateRx = regexp.MustCompile(`(?i)[?#\\]|%2e|%2f|%5c|(?:^|/)\.\.?(?:/|$)`)
	sbxConnectRx     = regexp.MustCompile(`^(?i)([a-z0-9.-]+|\[[0-9a-f:]+\]):([0-9]{1,5})$`)
	sbxMethodRx      = regexp.MustCompile(`^[A-Z]+$`)
)

func sbxIsPrivateV4(a, b int) bool {
	return a == 0 || a == 10 || a == 127 || (a == 169 && b == 254) || (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168) ||
		(a == 100 && b >= 64 && b <= 127) || a >= 224
}

// IsPrivateAddress is true for loopback, link-local, private, CGNAT, multicast, reserved and unspecified addresses, classified on
// the parsed address, not its spelling. IPv6: only global unicast (2000::/3) is public; an IPv4-mapped, IPv4-compatible or NAT64
// (64:ff9b::/96) address follows its embedded IPv4 address; a zoned address (`%id`) is link-scoped, so private. Anything that is
// not an IP literal (or not a string) counts as private (refused).
func IsPrivateAddress(ip any) bool {
	s, ok := ip.(string)
	if !ok {
		return true
	}
	if sbxV4Rx.MatchString(s) {
		parts := strings.Split(s, ".")
		var a, b int
		fmt.Sscanf(parts[0], "%d", &a)
		fmt.Sscanf(parts[1], "%d", &b)
		return sbxIsPrivateV4(a, b)
	}
	if strings.Contains(s, "%") || !sbxV6Rx.MatchString(s) {
		return true
	}
	addr, err := netip.ParseAddr(s)
	if err != nil || !addr.Is6() {
		return true
	}
	g := addr.As16()
	var w [8]int
	for i := range w {
		w[i] = int(g[2*i])<<8 | int(g[2*i+1])
	}
	zero80 := w[0] == 0 && w[1] == 0 && w[2] == 0 && w[3] == 0 && w[4] == 0
	nat64 := w[0] == 0x64 && w[1] == 0xff9b && w[2] == 0 && w[3] == 0 && w[4] == 0 && w[5] == 0
	if (zero80 && (w[5] == 0 || w[5] == 0xffff)) || nat64 {
		return sbxIsPrivateV4(w[6]>>8, w[6]&0xff)
	}
	return w[0] < 0x2000 || w[0] >= 0x4000
}

func sbxIsIP(h string) bool { return sbxV4Rx.MatchString(h) || sbxV6Rx.MatchString(h) }

type sbxAdmission struct {
	opID      any
	op        map[string]any
	template  map[string]any
	uses      float64
	expiresAt float64
}

// EgressPolicy is default deny: the only way a request is allowed is by matching a template admitted from a verified operation.
// A template is the one outbound request an operation maps to: {method, scheme, host, port?, path, path_prefix?, query?,
// body_sha256?, tunnel?}, exact host, port and method; the path exact unless path_prefix; the query must equal `query` (absent =
// none); a request with a body must match body_sha256; `tunnel` admits a CONNECT to host:port instead.
type EgressPolicy struct {
	admissions []*sbxAdmission
	now        func() float64
}

// NewEgressPolicy builds a policy; now nil = the wall clock.
func NewEgressPolicy(now func() float64) *EgressPolicy {
	if now == nil {
		now = func() float64 { return connNow(nil) }
	}
	return &EgressPolicy{now: now}
}

// Admit admits the request operation maps to (toRequest returns the template). It fails unless result allows exactly operation
// and the template is well formed.
func (p *EgressPolicy) Admit(result, operation any, toRequest func(operation any) any, opts map[string]any) error {
	if !SandboxIsAuthorizedFor(result, operation) {
		return errors.New("not_authorized: result does not allow exactly this operation")
	}
	tv := toRequest(operation)
	if !sbxTruthy(tv, true) {
		return errors.New("no_egress_for_operation")
	}
	t, isMap := tv.(map[string]any)
	if !isMap {
		return errors.New("template is not an object")
	}
	host, isStr := t["host"].(string)
	if !isStr {
		return errors.New("host.toLowerCase is not a function")
	}
	if !(sbxIsIP(host) || sbxEgressHostRx.MatchString(host)) || host != strings.ToLower(host) {
		return errors.New("bad_template_host")
	}
	scheme, _ := t["scheme"].(string)
	if scheme != "http" && scheme != "https" {
		return errors.New("bad_template_scheme")
	}
	port := sbxDefaultPort[scheme]
	if pv, present := t["port"]; !sbxNullish(pv, present) {
		f, ok := sbxIsInt(pv)
		if !ok {
			return errors.New("bad_template_port")
		}
		port = f
	}
	if port < 1 || port > 65535 {
		return errors.New("bad_template_port")
	}
	if m, ok := t["method"].(string); !ok || !sbxMethodRx.MatchString(m) {
		return errors.New("bad_template_method")
	}
	path, isStr := t["path"].(string)
	if !isStr {
		return errors.New("t.path.startsWith is not a function")
	}
	if !strings.HasPrefix(path, "/") || sbxBadTemplateRx.MatchString(path) {
		return errors.New("bad_template_path")
	}
	uses, err := sbxOptNum(opts, "uses", 1)
	if err != nil {
		return err
	}
	if f, isInt := sbxIsInt(uses); !isInt || f < 1 {
		return errors.New("bad_uses")
	}
	expires, err := sbxOptNum(opts, "expiresAt", math.Inf(1))
	if err != nil {
		return err
	}
	bound, _ := sbxGet(result, "operation")
	bid, hasID := sbxGet(bound, "id")
	var opID any = ""
	if !sbxNullish(bid, hasID) {
		opID = bid
	}
	tt := map[string]any{}
	for k, v := range t {
		tt[k] = v
	}
	tt["host"], tt["port"] = host, port
	p.admissions = append(p.admissions, &sbxAdmission{opID: opID, op: operation.(map[string]any), template: tt, uses: uses, expiresAt: expires})
	return nil
}

type sbxTarget struct {
	connect             bool
	scheme, host        string
	port                float64
	path, query, reason string
}

func sbxParseTarget(method, urlText string) sbxTarget {
	if method == "CONNECT" {
		m := sbxConnectRx.FindStringSubmatch(urlText)
		if m == nil {
			return sbxTarget{reason: "bad_connect_target"}
		}
		host := strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(m[1], "["), "]"))
		var port int
		fmt.Sscanf(m[2], "%d", &port)
		return sbxTarget{connect: true, scheme: "https", host: host, port: float64(port)}
	}
	p, err := whatwgParse(urlText)
	if err != nil {
		return sbxTarget{reason: "not_absolute_url"}
	}
	if p.scheme != "http" && p.scheme != "https" {
		return sbxTarget{reason: "bad_url"}
	}
	u, err := connParseURL(urlText)
	if err != nil || u.username != "" || u.password != "" || u.hash != "" {
		return sbxTarget{reason: "bad_url"}
	}
	if sbxEncPathRx.MatchString(p.pathname) {
		return sbxTarget{reason: "encoded_path"}
	}
	hostport := p.host
	var host, portText string
	if strings.HasPrefix(hostport, "[") {
		end := strings.Index(hostport, "]")
		host, portText = hostport[1:end], strings.TrimPrefix(hostport[end+1:], ":")
	} else {
		host, portText, _ = strings.Cut(hostport, ":")
	}
	port := sbxDefaultPort[p.scheme]
	if portText != "" {
		var n int
		fmt.Sscanf(portText, "%d", &n)
		port = float64(n)
	}
	return sbxTarget{scheme: p.scheme, host: strings.ToLower(host), port: port, path: p.pathname, query: u.query}
}

// Claim decides and, if allowed, spends one use of the matching admission. Anything not matched is denied with a reason. method
// and urlText are the request's method and URL as the reference prints them; body may be nil.
func (p *EgressPolicy) Claim(method, urlText string, body []byte) map[string]any {
	method = strings.ToUpper(method)
	parsed := sbxParseTarget(method, urlText)
	if parsed.reason != "" {
		return map[string]any{"allow": false, "reason": parsed.reason}
	}
	why := "no_admission"
	for _, a := range p.admissions {
		t := a.template
		if parsed.connect != (t["tunnel"] == true) {
			continue
		}
		if tm, _ := t["method"].(string); tm != method && !parsed.connect {
			continue
		}
		if ts, _ := t["scheme"].(string); parsed.scheme != ts && !parsed.connect {
			continue
		}
		if th, _ := t["host"].(string); parsed.host != th || parsed.port != t["port"].(float64) {
			continue
		}
		if !parsed.connect {
			tp, _ := t["path"].(string)
			var ok bool
			if pp, present := t["path_prefix"]; sbxTruthy(pp, present) {
				prefix := tp
				if !strings.HasSuffix(tp, "/") {
					prefix = tp + "/"
				}
				ok = parsed.path == tp || strings.HasPrefix(parsed.path, prefix)
			} else {
				ok = parsed.path == tp
			}
			if !ok {
				continue
			}
			wantQ := ""
			if qv, present := t["query"]; !sbxNullish(qv, present) {
				if qs, isStr := qv.(string); isStr {
					wantQ = qs
				} else {
					wantQ = "\x00non-string"
				}
			}
			if parsed.query != wantQ {
				why = "query_mismatch"
				continue
			}
			bh, hasBH := t["body_sha256"]
			sum := sha256.Sum256(body)
			got := b64.EncodeToString(sum[:])
			if len(body) > 0 && (!hasBH || got != bh) {
				why = "body_mismatch"
				continue
			}
			if len(body) == 0 && hasBH && bh != got {
				why = "body_mismatch"
				continue
			}
		}
		if tn := p.now(); a.uses < 1 || !(finite(tn) && tn < a.expiresAt) { // reported only when the request would otherwise have matched
			why = "spent"
			continue
		}
		a.uses--
		pd, err := HashCanonical(a.op["params"])
		if err != nil {
			return map[string]any{"allow": false, "reason": "no_admission"}
		}
		return map[string]any{"allow": true, "op_id": a.opID, "admission": map[string]any{"verb": a.op["verb"], "resource": a.op["resource"], "params_digest": pd}}
	}
	return map[string]any{"allow": false, "reason": why}
}

// SandboxTrustFromAttestation runs a hardware attestation verifier over the evidence document and admits the evidence's digest into
// the trust only when it says ok AND bound; anything else (a panic, an unbound answer, a failure) leaves the verified-digest list
// empty, so every claim is "none". The result is the trust SandboxVerifiedRuntimeClass takes:
// {pinnedAttestors, passportDigest, verifiedEvidenceDigests, now}.
func SandboxTrustFromAttestation(document, ctx map[string]any, verifier AttestationHardwareVerifier, expected ExpectedAttestationBinding, nowMs int64, pinnedAttestors []string, passportDigest string) map[string]any {
	ok := false
	func() {
		defer func() {
			if recover() != nil {
				ok = false
			}
		}()
		if verifier != nil {
			h := verifier.VerifyHardware(document, ctx, nowMs, expected)
			ok = h.OK && h.Bound
		}
	}()
	digests := []any{}
	if ok {
		if d, err := HashCanonical(document); err == nil {
			digests = append(digests, d)
		}
	}
	pins := make([]any, len(pinnedAttestors))
	for i, p := range pinnedAttestors {
		pins[i] = p
	}
	return map[string]any{"pinnedAttestors": pins, "passportDigest": passportDigest, "verifiedEvidenceDigests": digests, "now": jsNumber(float64(nowMs))}
}
