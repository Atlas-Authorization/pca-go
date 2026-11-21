package pca

// Crash-safe, tamper-evident, multi-process-safe persistent key/value state (it needs hard links, fsync and a process
// liveness probe). The on-disk format and the lock/fence protocol are byte-compatible with the other implementations: a
// directory written by one opens in another.
//
// LAYOUT (a directory you own, mode 0700): state.journal (hash-chained records, one JSON object per line), state.head (seq +
// hash of the last record, written AFTER the journal), state.lock.<g> (the generation lock), state.fence* (operator-recovery
// cuts).
//
// GUARANTEES
//   - Crash safety: every mutation is write-temp, fsync(file), rename, fsync(directory). The head trails the journal by at
//     most one record and is repaired by the next writer.
//   - No lost updates: every mutation runs under an exclusive lock made of immutable numbered generation files created with
//     link(2); a lock is taken over only from a provably dead holder on this host and PID namespace, never by age; the
//     generation is re-checked right before the journal rename and right before every head rename.
//   - Fencing against a paused holder: every record and the head carry the writer's lock generation; RecoverDurableState
//     takes the lock, cuts and fences the released generation, then releases. On load a record below a fence that covers it,
//     below an earlier record's generation, or below the generation that wrote the head is refused (corrupt).
//   - Tamper / truncation evidence: records are hash-chained; truncation or an older copy is caught by the head and by the
//     highest (seq, hash) this handle has seen; with an HMAC key every record and the head are tagged.
//   - Fail closed: corrupt or rolled-back state makes every operation fail with a *DurableStateError; the only way past is
//     the explicit RecoverFromCorruption option, which quarantines the files (never deletes) and starts from genesis.
//
// NOT GUARANTEED: one host and one PID namespace per directory; a LOCAL filesystem with working hard links (open probes it
// and fails with link-unsupported); a stalled live holder blocks until it dies (waiters fail with lock-timeout).

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
)

// DurableStateErrorCode is the failure class of a *DurableStateError.
type DurableStateErrorCode string

// The failure classes of the durable store.
const (
	DurableCorrupt         DurableStateErrorCode = "corrupt"
	DurableRollback        DurableStateErrorCode = "rollback"
	DurableLockTimeout     DurableStateErrorCode = "lock-timeout"
	DurableLockLost        DurableStateErrorCode = "lock-lost"
	DurableLinkUnsupported DurableStateErrorCode = "link-unsupported"
	DurableKeyMismatch     DurableStateErrorCode = "key-mismatch"
	DurableInvalid         DurableStateErrorCode = "invalid"
	DurableTooLarge        DurableStateErrorCode = "too-large"
	// DurableIO is an operating-system error the reference lets escape as a raw exception.
	DurableIO DurableStateErrorCode = "io"
)

// DurableStateError is an error of the durable store. Error() is "<code>: <detail>", exactly as the reference formats it.
type DurableStateError struct {
	Code    DurableStateErrorCode
	Message string
}

// Error implements error.
func (e *DurableStateError) Error() string { return e.Message }

func dsErr(code DurableStateErrorCode, format string, a ...any) *DurableStateError {
	return &DurableStateError{Code: code, Message: string(code) + ": " + fmt.Sprintf(format, a...)}
}

func dsIO(err error) error {
	if err == nil {
		return nil
	}
	return dsErr(DurableIO, "%s", err.Error())
}

// DurableStateKv is the persistence interface the allowlist / key-trust modules use. Values must be JSON-serialisable; a
// json.RawMessage value is stored verbatim (member order preserved).
type DurableStateKv interface {
	// Get returns the value under key (decoded JSON); ok is false when absent.
	Get(key string) (value any, ok bool, err error)
	// Set is an unconditional write (still serialised and hash-chained). Prefer Update for monotone state.
	Set(key string, value any) error
	// Update is an atomic read-modify-write: fn receives the current value and returns the next, or write=false to leave the
	// key unchanged. It returns the value now stored. fn runs under the cross-process lock and must be quick.
	Update(key string, fn func(prev any, ok bool) (next any, write bool)) (value any, ok bool, err error)
	// Keys lists every key in UTF-16 code-unit order.
	Keys() ([]string, error)
}

// DurableCrashAt names a TEST-ONLY crash point of a commit.
type DurableCrashAt string

// The crash points a test can ask for (the process SIGKILLs itself there).
const (
	DurableCrashAfterTempWrite     DurableCrashAt = "after-temp-write"
	DurableCrashAfterJournalRename DurableCrashAt = "after-journal-rename"
)

// DurableRecoverCrashEnv is honoured only with PCA_DURABLE_TEST=1: the point at which operator recovery (or the takeover of a
// crashed recovery) SIGKILLs itself.
const DurableRecoverCrashEnv = "PCA_DURABLE_TEST_RECOVER_CRASH_AT"

// DurableStateOptions configures OpenDurableState. A zero numeric field means "the default".
type DurableStateOptions struct {
	// Dir is the directory holding the state (created 0700 if missing).
	Dir string
	// HmacKey is an optional >= 32-byte key: records and head are tagged; forging or re-chaining then needs the key.
	HmacKey []byte
	// RecoverFromCorruption quarantines corrupt / rolled-back files and starts from genesis. Default false (fail closed).
	RecoverFromCorruption bool
	// LockTimeoutMs gives up acquiring the lock after this long (default 10000).
	LockTimeoutMs int64
	// CompactEvery compacts the journal into a checkpoint every N records (default 256, minimum 2).
	CompactEvery int
	// MaxValueBytes caps the serialised value size in UTF-16 code units (default 1 MiB).
	MaxValueBytes int
	// Now is the clock for record timestamps (default: milliseconds since the epoch). Lock-file bodies always use real time.
	Now func() int64
	// TestCrashAt is TEST ONLY.
	TestCrashAt DurableCrashAt
}

// DurableLockHolder is the holder record of a lock file an operator has confirmed dead (copy it from the lock-timeout error
// or the state.lock.N file).
type DurableLockHolder struct {
	Host string
	Pid  float64
	// Nonce is the per-acquisition nonce in the lock file: a match proves the operator looked at THIS lock.
	Nonce string
}

// RecoverDurableStateOptions configures RecoverDurableState.
type RecoverDurableStateOptions struct {
	Dir string
	// Force must be true: this is an out-of-band operator action, never automatic.
	Force bool
	// ExpectedHolder is the complete holder record copied exactly.
	ExpectedHolder *DurableLockHolder
	// ExpectedUnreadable stands for the reference's 'unreadable': the top lock file is unreadable or INCOMPLETE.
	ExpectedUnreadable bool
	// LegacyLock releases the LEGACY single-file state.lock of an older version (moved to state.lock.legacy-recovered-<time>-<rand>).
	LegacyLock bool
}

// RecoverDurableStateResult is what RecoverDurableState did.
type RecoverDurableStateResult struct {
	Released bool
	// Reason is "not-held" or "released".
	Reason string
	// LockFile is the lock file that was superseded ("" when none).
	LockFile string
}

// DurableFence says: records after journal Seq must come from lock generation >= Gen; H is the hash of the record at Seq.
type DurableFence struct {
	Gen int64
	Seq int64
	H   string
}

// DurablePosition is the highest chain position a handle has observed.
type DurablePosition struct {
	Seq  int64
	Hash string
}

const (
	dsFenceFile = "state.fence"
	dsDomain    = "pca-durable-state/v1\n"
	dsGenesis   = "0000000000000000000000000000000000000000000000000000000000000000"
	dsMaxKey    = 256
	dsMaxSafe   = 9007199254740991.0
)

// ---- small helpers ----

func dsNowMs() int64 { return time.Now().UnixMilli() }

func dsRandHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t := uint64(time.Now().UnixNano())
		for i := range b {
			b[i] = byte(t>>(uint(i%8)*8)) ^ byte(i*31)
		}
	}
	return hex.EncodeToString(b)
}

func dsSha(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func dsIsHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// dsJS is JSON.stringify of a string: escape " \ \b \f \n \r \t, other controls < 0x20 as \u00xx, nothing else.
func dsJS(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(&b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

func dsUtf16Len(s string) int { return len(utf16.Encode([]rune(s))) }

func dsCmp16(a, b string) int {
	x, y := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(x) && i < len(y); i++ {
		if x[i] != y[i] {
			if x[i] < y[i] {
				return -1
			}
			return 1
		}
	}
	return len(x) - len(y)
}

// dsParse is JSON.parse: one value, numbers kept as json.Number.
func dsParse(text string) (any, bool) {
	d := json.NewDecoder(strings.NewReader(text))
	d.UseNumber()
	var v any
	if d.Decode(&v) != nil {
		return nil, false
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, false
	}
	return v, true
}

// dsSafeInt is Number.isSafeInteger over a parsed JSON value: (integer, isNegativeZero, ok).
func dsSafeInt(v any) (int64, bool, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false, false
	}
	f, err := strconv.ParseFloat(string(n), 64)
	if err != nil || math.IsInf(f, 0) || math.IsNaN(f) || f != math.Trunc(f) || math.Abs(f) > dsMaxSafe {
		return 0, false, false
	}
	return int64(f), f == 0 && math.Signbit(f), true
}

func dsIsGen(v any) bool {
	g, _, ok := dsSafeInt(v)
	return ok && g >= 1
}

func dsReadText(p string) (string, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return "", dsIO(err)
	}
	return strings.ToValidUTF8(string(b), "�"), nil
}

func dsExists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

func dsMac(key []byte, msg string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(msg))
	return hex.EncodeToString(m.Sum(nil))
}

func dsMacEq(a, b string) bool { return hmac.Equal([]byte(a), []byte(b)) }

func dsHostname() string {
	h, _ := os.Hostname()
	return h
}

var dsBootID = dsRandHex(12)

// dsJsNum is a number as JavaScript prints it in a template string.
func dsJsNum(f float64) string {
	if math.IsNaN(f) {
		return "NaN"
	}
	if f == math.Trunc(f) && math.Abs(f) < 1e21 {
		return strconv.FormatFloat(f, 'f', -1, 64)
	}
	return strconv.FormatFloat(f, 'g', -1, 64)
}

// dsProcStart is the process start time (field 22 of /proc/<pid>/stat); "" off Linux or when gone.
func dsProcStart(pid float64) string {
	b, err := os.ReadFile("/proc/" + dsJsNum(pid) + "/stat")
	if err != nil {
		return ""
	}
	st := string(b)
	at := strings.LastIndex(st, ")")
	if at < 0 || at+2 > len(st) {
		return ""
	}
	parts := strings.Split(st[at+2:], " ")
	if len(parts) < 20 {
		return ""
	}
	return parts[19]
}

func dsMyNs() string {
	p, err := os.Readlink("/proc/self/ns/pid")
	if err != nil {
		return ""
	}
	return p
}

func dsKillSelfIf(point string) {
	if os.Getenv("PCA_DURABLE_TEST") == "1" && os.Getenv(DurableRecoverCrashEnv) == point {
		dsKillSelf()
	}
}

func dsAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func dsLockNameGen(name string) (uint64, bool) {
	d, ok := strings.CutPrefix(name, "state.lock.")
	if !ok || !dsAllDigits(d) {
		return 0, false
	}
	g, err := strconv.ParseUint(d, 10, 64)
	if err != nil {
		return math.MaxUint64, true
	}
	return g, true
}

func dsFenceEntry(name string) (float64, bool) {
	rest, ok := strings.CutPrefix(name, "state.fence.")
	if !ok {
		return 0, false
	}
	g, tag, ok := strings.Cut(rest, "-")
	if !ok || !dsAllDigits(g) || tag == "" {
		return 0, false
	}
	for i := 0; i < len(tag); i++ {
		c := tag[i]
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
			return 0, false
		}
	}
	f, _ := strconv.ParseFloat(g, 64)
	return f, true
}

func dsListDir(dir string) ([]string, error) {
	es, err := os.ReadDir(dir)
	if err != nil {
		return nil, dsIO(err)
	}
	out := make([]string, 0, len(es))
	for _, e := range es {
		out = append(out, e.Name())
	}
	return out, nil
}

func dsWriteExcl(path, data string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return dsIO(err)
	}
	if err := RestrictToOwner(path); err != nil {
		f.Close()
		return dsIO(err)
	}
	if _, err := f.WriteString(data); err != nil {
		f.Close()
		return dsIO(err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return dsIO(err)
	}
	return dsIO(f.Close())
}

// dsAtomicWrite is temp file -> fsync -> [beforeRename check] -> rename -> fsync(directory).
func dsAtomicWrite(path, data string, crashAfterTemp bool, beforeRename func() error) error {
	tmp := fmt.Sprintf("%s.tmp-%d-%s", path, os.Getpid(), dsRandHex(6))
	if err := dsWriteExcl(tmp, data); err != nil {
		return err
	}
	if crashAfterTemp {
		dsKillSelf()
	}
	if beforeRename != nil {
		if err := beforeRename(); err != nil {
			_ = os.Remove(tmp) // best effort: the orphan temp is harmless
			return err
		}
	}
	if err := os.Rename(tmp, path); err != nil {
		return dsIO(err)
	}
	return dsFsyncDir(filepath.Dir(path))
}

// ---- fences ----

func dsParseFence(f any, whence string) (DurableFence, error) {
	bad := func() error { return dsErr(DurableCorrupt, "%s has an invalid entry", whence) }
	o, ok := f.(map[string]any)
	if !ok {
		return DurableFence{}, bad()
	}
	gen, _, ok := dsSafeInt(o["gen"])
	if !ok || gen < 1 {
		return DurableFence{}, bad()
	}
	seq, nz, ok := dsSafeInt(o["seq"])
	if !ok || seq < 0 {
		return DurableFence{}, bad()
	}
	h, ok := o["h"].(string)
	if !ok || !dsIsHex64(h) || nz {
		return DurableFence{}, bad()
	}
	return DurableFence{Gen: gen, Seq: seq, H: h}, nil
}

func dsIsV1(o any) bool {
	m, ok := o.(map[string]any)
	if !ok {
		return false
	}
	n, ok := m["v"].(json.Number)
	if !ok {
		return false
	}
	f, err := strconv.ParseFloat(string(n), 64)
	return err == nil && f == 1
}

// ReadDurableFences returns every fence of a state directory: the list in state.fence (absent = none) then each
// state.fence.<gen>-<rand> by generation. A malformed one is a corrupt error.
func ReadDurableFences(dir string) ([]DurableFence, error) {
	var out []DurableFence
	p := filepath.Join(dir, dsFenceFile)
	if dsExists(p) {
		txt, err := dsReadText(p)
		if err != nil {
			return nil, err
		}
		o, ok := dsParse(txt)
		if !ok {
			return nil, dsErr(DurableCorrupt, "state.fence is not valid JSON")
		}
		var fences []any
		if dsIsV1(o) {
			fences, _ = o.(map[string]any)["fences"].([]any)
		}
		if fences == nil {
			return nil, dsErr(DurableCorrupt, "state.fence has an invalid shape")
		}
		for _, f := range fences {
			pf, err := dsParseFence(f, "state.fence")
			if err != nil {
				return nil, err
			}
			out = append(out, pf)
		}
	}
	names, err := dsListDir(dir)
	if err != nil {
		return nil, err
	}
	type ent struct {
		name string
		gen  float64
	}
	var entries []ent
	for _, n := range names {
		if g, ok := dsFenceEntry(n); ok {
			entries = append(entries, ent{n, g})
		}
	}
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].gen != entries[j].gen {
			return entries[i].gen < entries[j].gen
		}
		return entries[i].name < entries[j].name
	})
	for _, e := range entries {
		txt, err := dsReadText(filepath.Join(dir, e.name))
		if err != nil {
			return nil, err
		}
		o, ok := dsParse(txt)
		if !ok {
			return nil, dsErr(DurableCorrupt, "%s is not valid JSON", e.name)
		}
		if !dsIsV1(o) {
			return nil, dsErr(DurableCorrupt, "%s has an invalid shape", e.name)
		}
		f, err := dsParseFence(o.(map[string]any)["fence"], e.name)
		if err != nil {
			return nil, err
		}
		if float64(f.Gen) != e.gen {
			return nil, dsErr(DurableCorrupt, "%s names generation %s but holds %d", e.name, dsJsNum(e.gen), f.Gen)
		}
		out = append(out, f)
	}
	return out, nil
}

// dsJournalTail is (seq, hash) of the last journal record as it is on disk right now; absent or unparsable gives (0, zeros).
func dsJournalTail(dir string) (int64, string) {
	txt, err := dsReadText(filepath.Join(dir, "state.journal"))
	if err != nil {
		return 0, dsGenesis
	}
	last := ""
	for _, l := range strings.Split(txt, "\n") {
		if l != "" {
			last = l
		}
	}
	o, ok := dsParse(last)
	m, isMap := o.(map[string]any)
	if !ok || !isMap {
		return 0, dsGenesis
	}
	s, _, sok := dsSafeInt(m["seq"])
	h, hok := m["h"].(string)
	if sok && hok && s >= 1 && dsIsHex64(h) {
		return s, h
	}
	return 0, dsGenesis
}

// dsWriteFence writes the operator's CUT: called while recovery itself holds generation g+1.
func dsWriteFence(dir string, g int64, beforeRename func() error) error {
	if _, err := ReadDurableFences(dir); err != nil { // an unreadable fence set fails closed here too
		return err
	}
	seq, h := dsJournalTail(dir)
	fence := fmt.Sprintf(`{"gen":%d,"seq":%d,"h":%s,"from":%d,"t":%d}`, g+1, seq, dsJS(h), g, dsNowMs())
	path := filepath.Join(dir, fmt.Sprintf("%s.%d-%s", dsFenceFile, g+1, dsRandHex(6)))
	return dsAtomicWrite(path, fmt.Sprintf("{\"v\":1,\"fence\":%s}\n", fence), false, beforeRename)
}

// ---- lock files ----

type dsLockBody struct {
	held       bool
	pid        float64
	hasPid     bool
	host       string
	hasHost    bool
	nonce      string
	hasNonce   bool
	start      string
	ns         string
	hasNs      bool
	recovering int64
	hasRecov   bool
}

func dsBodyOfMap(m map[string]any) *dsLockBody {
	b := &dsLockBody{}
	if s, ok := m["st"].(string); !ok || s != "free" {
		b.held = true
	}
	if n, ok := m["pid"].(json.Number); ok {
		if f, err := strconv.ParseFloat(string(n), 64); err == nil {
			b.pid, b.hasPid = f, true
		}
	}
	b.host, b.hasHost = m["host"].(string)
	b.nonce, b.hasNonce = m["nonce"].(string)
	b.start, _ = m["start"].(string)
	b.ns, b.hasNs = m["ns"].(string)
	if r, _, ok := dsSafeInt(m["recovering"]); ok {
		b.recovering, b.hasRecov = r, true
	}
	return b
}

// dsReadBody is nil when the file is unreadable or not an object/array.
func dsReadBody(path string) *dsLockBody {
	txt, err := dsReadText(path)
	if err != nil {
		return nil
	}
	o, ok := dsParse(txt)
	if !ok {
		return nil
	}
	switch v := o.(type) {
	case map[string]any:
		return dsBodyOfMap(v)
	case []any:
		return &dsLockBody{held: true}
	}
	return nil
}

// dsHolderAliveHere: is the recorded holder demonstrably ALIVE here? Judged by PID-namespace identity when the record names
// one, else by hostname.
func dsHolderAliveHere(b *dsLockBody) bool {
	if !b.hasPid {
		return false
	}
	var judgeable bool
	if b.hasNs {
		judgeable = dsMyNs() == b.ns && b.ns != ""
	} else {
		judgeable = b.hasHost && b.host == dsHostname()
	}
	if !judgeable || !dsPidAlive(b.pid) {
		return false
	}
	if b.start != "" {
		if cur := dsProcStart(b.pid); cur != "" && cur != b.start {
			return false // the pid was reused by a different process
		}
	}
	return true
}

type dsClass int

const (
	dsUnreadable dsClass = iota
	dsFree
	dsIncomplete
	dsComplete
)

type dsClassified struct {
	kind dsClass
	raw  any
	body *dsLockBody
}

// dsClassify: a holder record is COMPLETE only with a numeric pid, a string host and a non-empty nonce.
func dsClassify(path string) dsClassified {
	txt, err := dsReadText(path)
	if err != nil {
		return dsClassified{kind: dsUnreadable}
	}
	o, ok := dsParse(txt)
	if !ok {
		return dsClassified{kind: dsUnreadable}
	}
	switch v := o.(type) {
	case map[string]any:
		if s, _ := v["st"].(string); s == "free" {
			return dsClassified{kind: dsFree}
		}
		_, pidOk := v["pid"].(json.Number)
		_, hostOk := v["host"].(string)
		n, _ := v["nonce"].(string)
		if pidOk && hostOk && n != "" {
			return dsClassified{kind: dsComplete, raw: o, body: dsBodyOfMap(v)}
		}
		return dsClassified{kind: dsIncomplete, raw: o}
	case []any:
		return dsClassified{kind: dsIncomplete, raw: o}
	}
	return dsClassified{kind: dsUnreadable}
}

func dsViewOf(raw any) *dsLockBody {
	if m, ok := raw.(map[string]any); ok {
		return dsBodyOfMap(m)
	}
	return &dsLockBody{}
}

func dsSlice16(s string, n int) string {
	used := 0
	var b strings.Builder
	for _, r := range s {
		w := 1
		if r > 0xFFFF {
			w = 2
		}
		used += w
		if used > n {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

// dsMarshal is JSON.stringify of a decoded value (no HTML escaping, numbers as written).
func dsMarshal(v any) string {
	var buf bytes.Buffer
	e := json.NewEncoder(&buf)
	e.SetEscapeHTML(false)
	if e.Encode(v) != nil {
		return ""
	}
	return strings.TrimSuffix(buf.String(), "\n")
}

func dsConfirmHolder(c dsClassified, opts *RecoverDurableStateOptions, path string) error {
	switch c.kind {
	case dsUnreadable:
		if !opts.ExpectedUnreadable {
			return dsErr(DurableInvalid, "%s is unreadable; pass expectedHolder: 'unreadable' to release it", path)
		}
	case dsIncomplete:
		if !opts.ExpectedUnreadable {
			return dsErr(DurableInvalid, "%s has an incomplete holder record (%s); after confirming its holder is gone, pass expectedHolder: 'unreadable' to release it", path, dsSlice16(dsMarshal(c.raw), 160))
		}
		if dsHolderAliveHere(dsViewOf(c.raw)) {
			pid := "undefined"
			if m, ok := c.raw.(map[string]any); ok {
				if v, has := m["pid"]; has {
					if x, isStr := v.(string); isStr {
						pid = x
					} else {
						pid = dsMarshal(v)
					}
				}
			}
			return dsErr(DurableInvalid, "the holder of %s (pid %s) is alive in this PID namespace; refusing to release a live holder", path, pid)
		}
	case dsComplete:
		b := c.body
		e := opts.ExpectedHolder
		if e == nil || opts.ExpectedUnreadable {
			return dsErr(DurableInvalid, "%s is readable (holder pid=%s host=%s); expectedHolder 'unreadable' does not match", path, dsJsNum(b.pid), b.host)
		}
		if b.host != e.Host || b.pid != e.Pid || b.nonce != e.Nonce {
			return dsErr(DurableInvalid, "expectedHolder does not match the holder recorded in %s (recorded pid=%s host=%s nonce=%s); nothing was changed", path, dsJsNum(b.pid), b.host, b.nonce)
		}
		if dsHolderAliveHere(b) {
			return dsErr(DurableInvalid, "the holder of %s (pid %s) is alive in this PID namespace; refusing to release a live holder", path, dsJsNum(b.pid))
		}
	}
	return nil
}

func dsTopGenIn(dir string) (uint64, error) {
	names, err := dsListDir(dir)
	if err != nil {
		return 0, err
	}
	var top uint64
	for _, n := range names {
		if g, ok := dsLockNameGen(n); ok && g > top {
			top = g
		}
	}
	return top, nil
}

// RecoverDurableState is the operator recovery for a lock whose holder cannot be judged dead automatically (another PID
// namespace, a changed hostname, an unreadable or incomplete top lock file, or a legacy single-file state.lock).
//
// The order matters: TAKE the lock as generation g+1 (EEXIST: the holder released, abort), CUT (read the journal tail under
// that lock), FENCE (records after the cut need generation >= g+1), RELEASE (generation g+2 "free"). Recovery may itself
// crash after any step; its lock is marked recovering, so whoever takes it over cuts and fences first.
func RecoverDurableState(opts RecoverDurableStateOptions) (RecoverDurableStateResult, error) {
	if !opts.Force {
		return RecoverDurableStateResult{}, dsErr(DurableInvalid, "recoverDurableState requires force: true")
	}
	if !opts.ExpectedUnreadable && (opts.ExpectedHolder == nil || opts.ExpectedHolder.Nonce == "") {
		return RecoverDurableStateResult{}, dsErr(DurableInvalid, "expectedHolder must be { host, pid, nonce } as recorded in the lock file, or 'unreadable'")
	}
	dir := opts.Dir
	g, err := dsTopGenIn(dir)
	if err != nil {
		return RecoverDurableStateResult{}, err
	}
	path := filepath.Join(dir, fmt.Sprintf("state.lock.%d", g))
	var top *dsClassified
	if g != 0 {
		c := dsClassify(path)
		top = &c
	}
	legacyPath := filepath.Join(dir, "state.lock")
	notHeld := func(f string) (RecoverDurableStateResult, error) {
		return RecoverDurableStateResult{Released: false, Reason: "not-held", LockFile: f}, nil
	}
	if opts.LegacyLock {
		if top != nil && top.kind != dsFree {
			return RecoverDurableStateResult{}, dsErr(DurableInvalid, "legacyLock: true, but the blocking lock is the generation lock %s; call recoverDurableState without legacyLock", path)
		}
		if !dsExists(legacyPath) {
			return notHeld("")
		}
		legacy := dsClassify(legacyPath)
		if legacy.kind == dsFree {
			return notHeld(legacyPath)
		}
		if err := dsConfirmHolder(legacy, &opts, legacyPath); err != nil {
			return RecoverDurableStateResult{}, err
		}
		// A legacy writer stamps no generation (reads as 0): every record after the cut needs >= g + 1 >= 1.
		if err := dsWriteFence(dir, int64(g), nil); err != nil {
			return RecoverDurableStateResult{}, err
		}
		if err := os.Rename(legacyPath, filepath.Join(dir, fmt.Sprintf("state.lock.legacy-recovered-%d-%s", dsNowMs(), dsRandHex(3)))); err != nil {
			return RecoverDurableStateResult{}, dsIO(err)
		}
		if err := dsFsyncDir(dir); err != nil {
			return RecoverDurableStateResult{}, err
		}
		return RecoverDurableStateResult{Released: true, Reason: "released", LockFile: legacyPath}, nil
	}
	if top == nil || top.kind == dsFree {
		if dsExists(legacyPath) {
			lb := dsClassify(legacyPath)
			who := "free holder record"
			switch lb.kind {
			case dsComplete:
				who = fmt.Sprintf("holder pid=%s host=%s nonce=%s", dsJsNum(lb.body.pid), lb.body.host, lb.body.nonce)
			case dsUnreadable:
				who = "unreadable holder record"
			case dsIncomplete:
				who = "incomplete holder record"
			}
			return RecoverDurableStateResult{}, dsErr(DurableInvalid, "the blocking lock is the legacy single-file %s (%s); after confirming that holder is gone, pass legacyLock: true with its expectedHolder (or 'unreadable')", legacyPath, who)
		}
		if top == nil {
			return notHeld("")
		}
		return notHeld(path)
	}
	if err := dsConfirmHolder(*top, &opts, path); err != nil {
		return RecoverDurableStateResult{}, err
	}
	linkBody := func(gen uint64, body string, crashPoint string) error {
		tmp := filepath.Join(dir, fmt.Sprintf("state.lock.tmp-%d-%s", os.Getpid(), dsRandHex(6)))
		if err := dsWriteExcl(tmp, body); err != nil {
			return err
		}
		dsKillSelfIf(crashPoint)
		lerr := os.Link(tmp, filepath.Join(dir, fmt.Sprintf("state.lock.%d", gen)))
		_ = os.Remove(tmp)
		switch {
		case lerr == nil:
			return nil
		case errors.Is(lerr, os.ErrExist):
			return dsErr(DurableInvalid, "%s was superseded while recovering; re-read the lock state and retry", path)
		}
		return dsIO(lerr)
	}
	dsKillSelfIf("before-lock")
	var held strings.Builder
	fmt.Fprintf(&held, `{"st":"held","pid":%d,"host":%s,"nonce":%s,"boot":%s`, os.Getpid(), dsJS(dsHostname()), dsJS(dsRandHex(12)), dsJS(dsBootID))
	if ns := dsMyNs(); ns != "" {
		fmt.Fprintf(&held, `,"ns":%s`, dsJS(ns))
	}
	if s := dsProcStart(float64(os.Getpid())); s != "" {
		fmt.Fprintf(&held, `,"start":%s`, dsJS(s))
	}
	fmt.Fprintf(&held, `,"recovering":%d,"t":%d}`, g, dsNowMs())
	if err := linkBody(g+1, held.String(), "after-lock-temp"); err != nil {
		return RecoverDurableStateResult{}, err
	}
	dsKillSelfIf("after-lock")
	if err := dsWriteFence(dir, int64(g), func() error {
		dsKillSelfIf("after-fence-temp")
		return nil
	}); err != nil {
		return RecoverDurableStateResult{}, err
	}
	dsKillSelfIf("after-fence")
	if err := linkBody(g+2, fmt.Sprintf(`{"st":"free","t":%d,"recoveredFrom":%d}`, dsNowMs(), g), "after-release-temp"); err != nil {
		return RecoverDurableStateResult{}, err
	}
	dsKillSelfIf("after-release")
	return RecoverDurableStateResult{Released: true, Reason: "released", LockFile: path}, nil
}

// RecoverDurableStateValue is the dynamic entry point (a CLI or a JSON harness): opts is the decoded JSON object
// {force, expectedHolder, legacyLock?}. Validation happens in the reference's order: force first, then expectedHolder.
func RecoverDurableStateValue(dir string, opts map[string]any) (RecoverDurableStateResult, error) {
	if f, _ := opts["force"].(bool); !f {
		return RecoverDurableStateResult{}, dsErr(DurableInvalid, "recoverDurableState requires force: true")
	}
	o := RecoverDurableStateOptions{Dir: dir, Force: true}
	if l, _ := opts["legacyLock"].(bool); l {
		o.LegacyLock = true
	}
	switch e := opts["expectedHolder"].(type) {
	case string:
		if e == "unreadable" {
			o.ExpectedUnreadable = true
		}
	case map[string]any:
		h, hok := e["host"].(string)
		n, nok := e["nonce"].(string)
		var pid float64
		pok := false
		switch p := e["pid"].(type) {
		case float64:
			pid, pok = p, true
		case json.Number:
			f, err := strconv.ParseFloat(string(p), 64)
			pid, pok = f, err == nil
		case int:
			pid, pok = float64(p), true
		case int64:
			pid, pok = float64(p), true
		}
		if hok && nok && pok && n != "" {
			o.ExpectedHolder = &DurableLockHolder{Host: h, Pid: pid, Nonce: n}
		}
	}
	return RecoverDurableState(o)
}

// ---- records, head, the store ----

type dsRec struct {
	seq     int64
	prev    string
	op      string
	payload string
	ts      int64
	gen     int64
	hasGen  bool
	h       string
	mac     string
	hasMac  bool
}

type dsHead struct {
	seq    int64
	h      string
	gen    int64
	hasGen bool
}

func dsRecHash(seq int64, prev, op, payload string, ts int64, gen int64, hasGen bool) string {
	var arr string
	if !hasGen {
		arr = fmt.Sprintf("[%d,%s,%s,%s,%d]", seq, dsJS(prev), dsJS(op), dsJS(payload), ts)
	} else {
		arr = fmt.Sprintf("[%d,%s,%s,%s,%d,%d]", seq, dsJS(prev), dsJS(op), dsJS(payload), ts, gen)
	}
	return dsSha(dsDomain + arr)
}

func dsHeadMsg(seq int64, h string, gen int64, hasGen bool) string {
	if !hasGen {
		return fmt.Sprintf("head\n%d\n%s", seq, h)
	}
	return fmt.Sprintf("head\n%d\n%s\n%d", seq, h, gen)
}

func dsRecLine(r dsRec) string {
	s := fmt.Sprintf(`{"seq":%d,"prev":%s,"op":%s,"payload":%s,"ts":%d`, r.seq, dsJS(r.prev), dsJS(r.op), dsJS(r.payload), r.ts)
	if r.hasGen {
		s += fmt.Sprintf(`,"gen":%d`, r.gen)
	}
	s += fmt.Sprintf(`,"h":%s`, dsJS(r.h))
	if r.hasMac {
		s += fmt.Sprintf(`,"mac":%s`, dsJS(r.mac))
	}
	return s + "}"
}

type dsLoaded struct {
	recs  []dsRec
	state map[string]string
	head  *dsHead
}

// DurableState is an open durable state. All operations take the cross-process lock; one handle may be shared between
// goroutines. It implements DurableStateKv.
type DurableState struct {
	dir          string
	key          []byte
	lockTimeout  int64
	compactEvery int
	maxValue     int
	now          func() int64
	recoverCorr  bool
	crashAt      DurableCrashAt
	myNs         string
	myStart      string

	mu        sync.Mutex
	seenSeq   int64
	seenHash  string
	recovered bool
	heldNonce string
	holding   bool
	myGen     int64
}

// OpenDurableState opens (creating if needed) a durable state directory. It fails with a *DurableStateError on corrupt or
// rolled-back state unless RecoverFromCorruption is set.
func OpenDurableState(opts DurableStateOptions) (*DurableState, error) {
	if opts.Dir == "" {
		return nil, dsErr(DurableInvalid, "dir is required")
	}
	if opts.HmacKey != nil && len(opts.HmacKey) < 32 {
		return nil, dsErr(DurableInvalid, "hmacKey must be at least 32 bytes")
	}
	if err := os.MkdirAll(opts.Dir, 0o700); err != nil {
		return nil, dsIO(err)
	}
	_ = os.Chmod(opts.Dir, 0o700) // not ours to chmod (e.g. a shared parent): keep going
	st := &DurableState{
		dir:          opts.Dir,
		key:          opts.HmacKey,
		lockTimeout:  10_000,
		compactEvery: 256,
		maxValue:     1_048_576,
		now:          dsNowMs,
		recoverCorr:  opts.RecoverFromCorruption,
		crashAt:      opts.TestCrashAt,
		myNs:         dsMyNs(),
		myStart:      dsProcStart(float64(os.Getpid())),
		seenHash:     dsGenesis,
		myGen:        -1,
	}
	if opts.LockTimeoutMs != 0 {
		st.lockTimeout = opts.LockTimeoutMs
	}
	if opts.CompactEvery != 0 {
		st.compactEvery = opts.CompactEvery
	}
	if st.compactEvery < 2 {
		st.compactEvery = 2
	}
	if opts.MaxValueBytes != 0 {
		st.maxValue = opts.MaxValueBytes
	}
	if opts.Now != nil {
		st.now = opts.Now
	}
	if err := st.probeLinks(); err != nil {
		return nil, err
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	// Initial open: verify under the lock (so a half-finished writer is not mistaken for corruption), repair the head.
	err := st.withLock(func() error {
		l, err := st.loadOrRecover()
		if err != nil {
			return err
		}
		st.observe(l)
		if n := len(l.recs); n > 0 {
			last := l.recs[n-1]
			if l.head == nil || l.head.seq != last.seq {
				return st.writeHead(last, "nothing was written")
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return st, nil
}

func (s *DurableState) journalPath() string { return filepath.Join(s.dir, "state.journal") }
func (s *DurableState) headPath() string    { return filepath.Join(s.dir, "state.head") }

// Recovered reports whether this open quarantined corrupt state (see RecoverFromCorruption).
func (s *DurableState) Recovered() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.recovered
}

// Position returns the highest chain position this handle has observed.
func (s *DurableState) Position() DurablePosition {
	s.mu.Lock()
	defer s.mu.Unlock()
	return DurablePosition{Seq: s.seenSeq, Hash: s.seenHash}
}

// Verify re-checks the chain from disk now; it fails on any problem.
func (s *DurableState) Verify() (DurablePosition, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var pos DurablePosition
	err := s.withLock(func() error {
		l, err := s.load()
		if err != nil {
			return err
		}
		s.observe(l)
		pos = DurablePosition{Seq: s.seenSeq, Hash: s.seenHash}
		return nil
	})
	if err != nil {
		return DurablePosition{}, err
	}
	return pos, nil
}

func (s *DurableState) encode(value any) (string, error) {
	txt, err := dsMemEncode(value)
	if err != nil {
		return "", err
	}
	if dsUtf16Len(txt) > s.maxValue {
		return "", dsErr(DurableTooLarge, "value exceeds maxValueBytes=%d", s.maxValue)
	}
	return txt, nil
}

func dsCheckKey(k string) error {
	if k == "" || dsUtf16Len(k) > dsMaxKey || strings.Contains(k, "\n") {
		return dsErr(DurableInvalid, "key must be 1..256 chars without newlines")
	}
	return nil
}

func (s *DurableState) readHead() (*dsHead, error) {
	p := s.headPath()
	if !dsExists(p) {
		return nil, nil
	}
	txt, err := dsReadText(p)
	if err != nil {
		return nil, err
	}
	o, ok := dsParse(txt)
	if !ok {
		return nil, dsErr(DurableCorrupt, "state.head is not valid JSON")
	}
	shape := dsErr(DurableCorrupt, "state.head has an invalid shape")
	r, ok := o.(map[string]any)
	if !ok {
		return nil, shape
	}
	seq, nz, ok := dsSafeInt(r["seq"])
	if !ok || seq < 0 {
		return nil, shape
	}
	h, ok := r["h"].(string)
	if !ok || !dsIsHex64(h) {
		return nil, shape
	}
	if _, has := r["gen"]; nz || (has && !dsIsGen(r["gen"])) {
		return nil, shape
	}
	head := &dsHead{seq: seq, h: h}
	if g, _, ok := dsSafeInt(r["gen"]); ok {
		head.gen, head.hasGen = g, true
	}
	if s.key != nil {
		mac, _ := r["mac"].(string)
		if mac == "" || !dsMacEq(mac, dsMac(s.key, dsHeadMsg(head.seq, head.h, head.gen, head.hasGen))) {
			return nil, dsErr(DurableKeyMismatch, "state.head MAC does not verify (wrong key or forged head)")
		}
	}
	return head, nil
}

func (s *DurableState) load() (*dsLoaded, error) {
	head, err := s.readHead()
	if err != nil {
		return nil, err
	}
	fences, err := ReadDurableFences(s.dir)
	if err != nil {
		return nil, err
	}
	jp := s.journalPath()
	if !dsExists(jp) {
		if head != nil && head.seq > 0 {
			return nil, dsErr(DurableRollback, "state.journal is missing but state.head records seq %d", head.seq)
		}
		for _, f := range fences {
			if f.Seq > 0 {
				return nil, dsErr(DurableRollback, "state.journal is missing but operator recovery cut it at seq %d", f.Seq)
			}
		}
		if s.seenSeq > 0 {
			return nil, dsErr(DurableRollback, "state was deleted while open")
		}
		return &dsLoaded{state: map[string]string{}, head: head}, nil
	}
	text, err := dsReadText(jp)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(text, "\n")
	if lines[len(lines)-1] != "" {
		return nil, dsErr(DurableCorrupt, "journal does not end with a newline (torn or truncated)")
	}
	lines = lines[:len(lines)-1]
	var recs []dsRec
	state := map[string]string{}
	prevHash := dsGenesis
	var prevSeq, prevGen int64
	for i, line := range lines {
		n := i + 1
		o, ok := dsParse(line)
		if !ok {
			return nil, dsErr(DurableCorrupt, "journal line %d is not valid JSON", n)
		}
		shape := dsErr(DurableCorrupt, "journal line %d has an invalid shape", n)
		r, ok := o.(map[string]any)
		if !ok {
			return nil, shape
		}
		seq, _, ok := dsSafeInt(r["seq"])
		if !ok {
			return nil, shape
		}
		prev, ok := r["prev"].(string)
		if !ok || !dsIsHex64(prev) {
			return nil, shape
		}
		op, _ := r["op"].(string)
		if op != "set" && op != "checkpoint" {
			return nil, shape
		}
		payload, ok := r["payload"].(string)
		if !ok {
			return nil, shape
		}
		ts, tsNz, ok := dsSafeInt(r["ts"])
		if !ok {
			return nil, shape
		}
		h, ok := r["h"].(string)
		if !ok || !dsIsHex64(h) {
			return nil, shape
		}
		_, hasGenKey := r["gen"]
		if tsNz || (hasGenKey && !dsIsGen(r["gen"])) {
			return nil, shape
		}
		rec := dsRec{seq: seq, prev: prev, op: op, payload: payload, ts: ts, h: h}
		if g, _, ok := dsSafeInt(r["gen"]); ok {
			rec.gen, rec.hasGen = g, true
		}
		if m, ok := r["mac"].(string); ok {
			rec.mac, rec.hasMac = m, true
		}
		if i == 0 {
			if rec.op == "set" && (rec.seq != 1 || rec.prev != dsGenesis) {
				return nil, dsErr(DurableCorrupt, "journal does not start at genesis")
			}
			if rec.op == "checkpoint" && rec.seq < 1 {
				return nil, dsErr(DurableCorrupt, "bad checkpoint seq")
			}
		} else {
			if rec.seq != prevSeq+1 {
				return nil, dsErr(DurableCorrupt, "journal line %d: sequence gap", n)
			}
			if rec.prev != prevHash {
				return nil, dsErr(DurableCorrupt, "journal line %d: hash chain broken", n)
			}
		}
		if dsRecHash(rec.seq, rec.prev, rec.op, rec.payload, rec.ts, rec.gen, rec.hasGen) != rec.h {
			return nil, dsErr(DurableCorrupt, "journal line %d: record hash mismatch (edited)", n)
		}
		switch {
		case s.key != nil:
			if !rec.hasMac || !dsMacEq(rec.mac, dsMac(s.key, rec.h)) {
				return nil, dsErr(DurableKeyMismatch, "journal line %d: MAC does not verify (wrong key or forged record)", n)
			}
		case rec.hasMac:
			return nil, dsErr(DurableKeyMismatch, "journal is MAC-tagged but no hmacKey was supplied")
		}
		// Generation fencing (the record is authentic here: hash and MAC verified above).
		rg := rec.gen
		if rg < prevGen {
			return nil, dsErr(DurableCorrupt, "journal line %d (seq %d) was written by lock generation %d, older than generation %d of an earlier record: a stale writer's record (refused)", n, rec.seq, rg, prevGen)
		}
		for _, f := range fences {
			if rec.seq > f.Seq && rg < f.Gen {
				return nil, dsErr(DurableCorrupt, "journal line %d (seq %d) was written by lock generation %d, but operator recovery fenced generations below %d after seq %d: a holder paused across recoverDurableState resumed and replaced the journal late (refused; records committed after the recovery may be lost; recoverFromCorruption quarantines the files)", n, rec.seq, rg, f.Gen, f.Seq)
			}
		}
		prevGen = rg
		if rec.op == "checkpoint" {
			entries, ok := dsParse(rec.payload)
			if !ok {
				return nil, dsErr(DurableCorrupt, "checkpoint payload is not JSON")
			}
			arr, ok := entries.([]any)
			if !ok {
				return nil, dsErr(DurableCorrupt, "checkpoint payload is not an array")
			}
			state = map[string]string{}
			for _, e := range arr {
				pair, _ := e.([]any)
				if len(pair) != 2 {
					return nil, dsErr(DurableCorrupt, "checkpoint entry is malformed")
				}
				k, kok := pair[0].(string)
				v, vok := pair[1].(string)
				if !kok || !vok {
					return nil, dsErr(DurableCorrupt, "checkpoint entry is malformed")
				}
				state[k] = v
			}
		} else {
			nl := strings.IndexByte(rec.payload, '\n')
			if nl < 1 {
				return nil, dsErr(DurableCorrupt, "journal line %d: malformed payload", n)
			}
			state[rec.payload[:nl]] = rec.payload[nl+1:]
		}
		prevHash = rec.h
		prevSeq = rec.seq
		recs = append(recs, rec)
	}
	var last *dsRec
	var lastSeq int64
	if n := len(recs); n > 0 {
		last = &recs[n-1]
		lastSeq = last.seq
	}
	// The journal must EXTEND the exact journal each recovery cut at (it reaches the cut, and the record at the cut is the one
	// the operator saw, unless a later generation compacted past it).
	for _, f := range fences {
		if lastSeq < f.Seq {
			return nil, dsErr(DurableRollback, "journal is at seq %d but operator recovery cut it at seq %d (truncation, or a stale writer replaced it)", lastSeq, f.Seq)
		}
		if f.Seq > 0 {
			for _, r := range recs {
				if r.seq == f.Seq {
					if r.h != f.H {
						return nil, dsErr(DurableCorrupt, "journal record at seq %d is not the record operator recovery cut at: a stale writer replaced the journal (refused; recoverFromCorruption quarantines the files)", f.Seq)
					}
					break
				}
			}
		}
	}
	if head != nil {
		var hg int64
		if head.hasGen {
			hg = head.gen
		}
		if lastSeq < head.seq {
			return nil, dsErr(DurableRollback, "journal is at seq %d but state.head recorded seq %d (truncation or older copy)", lastSeq, head.seq)
		}
		// The head is written by the lock holder of generation hg; any record AFTER it, or a different record AT its position,
		// from a LOWER generation was written by a writer that had already lost the lock to hg.
		if last != nil {
			if last.gen < hg && (lastSeq == head.seq+1 || (lastSeq == head.seq && last.h != head.h)) {
				return nil, dsErr(DurableCorrupt, "journal tail (seq %d) was written by lock generation %d, older than generation %d that wrote state.head: a stale writer replaced the journal (refused)", lastSeq, last.gen, hg)
			}
		}
		// A stale LATE head: a holder paused between its journal rename and its head rename resumed after operator recovery and
		// wrote a head for ITS record while newer generations extended the journal past the cut. Recognised exactly, repaired by
		// the next writer.
		staleHead := false
		if lastSeq > head.seq+1 {
			cut := false
			for _, f := range fences {
				if hg < f.Gen && head.seq <= f.Seq && lastSeq > f.Seq {
					cut = true
					break
				}
			}
			has := false
			for _, r := range recs {
				if r.seq == head.seq && r.h == head.h {
					has = true
					break
				}
			}
			staleHead = cut && has
		}
		if lastSeq > head.seq+1 && !staleHead {
			return nil, dsErr(DurableCorrupt, "journal (seq %d) is more than one record ahead of state.head (seq %d)", lastSeq, head.seq)
		}
		if last != nil {
			if lastSeq == head.seq && last.h != head.h {
				return nil, dsErr(DurableCorrupt, "journal tail does not match state.head")
			}
			if lastSeq == head.seq+1 && last.prev != head.h {
				return nil, dsErr(DurableCorrupt, "journal tail is not chained from state.head")
			}
		}
	} else if lastSeq > 1 {
		return nil, dsErr(DurableRollback, "state.head is missing but the journal is at seq %d", lastSeq)
	}
	if last != nil {
		if last.seq < s.seenSeq {
			return nil, dsErr(DurableRollback, "state moved backwards from seq %d to %d while open", s.seenSeq, last.seq)
		}
		if last.seq == s.seenSeq && last.h != s.seenHash {
			return nil, dsErr(DurableRollback, "state forked at seq %d while open", last.seq)
		}
	} else if s.seenSeq > 0 {
		return nil, dsErr(DurableRollback, "state was emptied while open")
	}
	return &dsLoaded{recs: recs, state: state, head: head}, nil
}

func (s *DurableState) quarantine() error {
	tag := fmt.Sprintf("%d-%s", s.now(), dsRandHex(3))
	// a writer that lost the lock must not move a newer holder's files aside
	if err := s.assertLockHeld("nothing was written"); err != nil {
		return err
	}
	// After an operator recovery the journal restarts from genesis, so the old cuts no longer describe it. The fence list is
	// replaced (old one kept aside) by "every record from genesis on needs generation >= mine".
	fencePath := filepath.Join(s.dir, dsFenceFile)
	names, err := dsListDir(s.dir)
	if err != nil {
		return err
	}
	var oldEntries []string
	for _, n := range names {
		if _, ok := dsFenceEntry(n); ok {
			oldEntries = append(oldEntries, n)
		}
	}
	if dsExists(fencePath) || len(oldEntries) > 0 {
		if dsExists(fencePath) {
			if err := os.Link(fencePath, fencePath+".quarantine-"+tag); err != nil {
				return dsIO(err)
			}
		}
		g := s.myGen
		body := fmt.Sprintf("{\"v\":1,\"fences\":[{\"gen\":%d,\"seq\":0,\"h\":%s,\"from\":%d,\"t\":%d}]}\n", g, dsJS(dsGenesis), g-1, s.now())
		if err := dsAtomicWrite(fencePath, body, false, nil); err != nil {
			return err
		}
		for _, name := range oldEntries {
			if err := os.Rename(filepath.Join(s.dir, name), filepath.Join(s.dir, name+".quarantine-"+tag)); err != nil {
				return dsIO(err)
			}
		}
	}
	for _, p := range []string{s.journalPath(), s.headPath()} {
		if dsExists(p) {
			if err := os.Rename(p, p+".quarantine-"+tag); err != nil {
				return dsIO(err)
			}
		}
	}
	if err := dsFsyncDir(s.dir); err != nil {
		return err
	}
	s.seenSeq = 0
	s.seenHash = dsGenesis
	s.recovered = true
	return nil
}

func (s *DurableState) loadOrRecover() (*dsLoaded, error) {
	l, err := s.load()
	if err == nil {
		return l, nil
	}
	var de *DurableStateError
	if s.recoverCorr && errors.As(err, &de) && de.Code != DurableIO {
		if err := s.quarantine(); err != nil {
			return nil, err
		}
		return s.load()
	}
	return nil, err
}

func (s *DurableState) observe(l *dsLoaded) {
	if n := len(l.recs); n > 0 {
		last := l.recs[n-1]
		if last.seq >= s.seenSeq {
			s.seenSeq = last.seq
			s.seenHash = last.h
		}
	}
}

// ---- the lock: immutable, numbered generation files ----

func (s *DurableState) lockFile(g uint64) string {
	return filepath.Join(s.dir, fmt.Sprintf("state.lock.%d", g))
}

// topLock is the highest numbered generation: (g, body); g = 0 and no body when there is none; body nil = unreadable.
func (s *DurableState) topLock() (uint64, *dsLockBody, error) {
	g, err := dsTopGenIn(s.dir)
	if err != nil {
		return 0, nil, err
	}
	if g >= 1 {
		return g, dsReadBody(s.lockFile(g)), nil
	}
	return 0, nil, nil
}

func (s *DurableState) holderDead(b *dsLockBody, legacyAgeMs float64) bool {
	if b == nil {
		return legacyAgeMs > 1000 // an unreadable legacy file (torn by an old version) older than 1 s
	}
	if !b.hasPid {
		return false
	}
	if !b.hasHost || b.host != dsHostname() {
		return false // another host: cannot judge, never break
	}
	if b.hasNs && b.ns != s.myNs {
		return false // another PID namespace (container) or unknowable: cannot judge, never break
	}
	if !dsPidAlive(b.pid) {
		return true
	}
	if b.start != "" {
		if now := dsProcStart(b.pid); now != "" && now != b.start {
			return true // the pid was reused by a different process
		}
	}
	return false
}

// createGen creates generation g atomically; body is a JSON object text without its closing brace (the lock-file clock is
// real time). False means somebody else created it first.
func (s *DurableState) createGen(g uint64, body string) (bool, error) {
	tmp := filepath.Join(s.dir, fmt.Sprintf("state.lock.tmp-%d-%s", os.Getpid(), dsRandHex(6)))
	if err := dsWriteExcl(tmp, fmt.Sprintf("%s,\"t\":%d}", body, dsNowMs())); err != nil {
		return false, err
	}
	lerr := os.Link(tmp, s.lockFile(g))
	_ = os.Remove(tmp)
	switch {
	case lerr == nil:
		return true, nil
	case errors.Is(lerr, os.ErrExist):
		return false, nil
	}
	return false, dsErr(DurableInvalid, "the state directory's filesystem cannot create the lock atomically (link: %s)", dsErrnoName(lerr))
}

func (s *DurableState) gcLocks(keepFrom int64) {
	names, err := dsListDir(s.dir)
	if err != nil {
		return
	}
	for _, f := range names {
		if g, ok := dsLockNameGen(f); ok {
			if g < math.MaxInt64 && int64(g) < keepFrom {
				if os.Remove(filepath.Join(s.dir, f)) != nil {
					return
				}
			}
		} else if rest, ok := strings.CutPrefix(f, "state.lock.tmp-"); ok {
			pid, _ := strconv.ParseFloat(strings.SplitN(rest, "-", 2)[0], 64)
			if pid != 0 && !dsPidAlive(pid) && os.Remove(filepath.Join(s.dir, f)) != nil {
				return
			}
		}
	}
}

// probeLinks fails closed at open time when this filesystem cannot give the lock its atomic hard-link semantics.
func (s *DurableState) probeLinks() error {
	a := filepath.Join(s.dir, fmt.Sprintf("state.probe-%d-%s", os.Getpid(), dsRandHex(6)))
	b := a + ".lnk"
	code := func() string {
		f, err := os.OpenFile(a, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return dsErrnoName(err)
		}
		_, werr := f.WriteString("probe")
		f.Close()
		if werr != nil {
			return dsErrnoName(werr)
		}
		if err := os.Link(a, b); err != nil {
			return dsErrnoName(err)
		}
		second := errors.Is(os.Link(a, b), os.ErrExist)
		fi, err := os.Stat(a)
		if err != nil {
			return dsErrnoName(err)
		}
		nlink, ok := dsLinkCount(a, fi)
		if !second || !ok || nlink != 2 {
			return "link(2) is not atomic/exclusive here"
		}
		return ""
	}()
	_ = os.Remove(a)
	_ = os.Remove(b)
	if code != "" {
		return dsErr(DurableLinkUnsupported, "the state directory's filesystem does not provide working hard links with exclusive-create semantics (%s); use a local filesystem (ext4, xfs, btrfs, tmpfs, APFS), not NFS/SMB/FUSE", code)
	}
	return nil
}

func (s *DurableState) holderDesc(b *dsLockBody) string {
	if b == nil {
		return "an unreadable holder record"
	}
	if b.hasPid && b.hasHost && b.hasNonce && b.nonce != "" {
		other := ""
		if b.hasNs && b.ns != s.myNs {
			other = " (another PID namespace)"
		}
		return fmt.Sprintf("holder pid=%s host=%s nonce=%s%s", dsJsNum(b.pid), b.host, b.nonce, other)
	}
	pid, host, nonce := "?", "?", "?"
	if b.hasPid {
		pid = dsJsNum(b.pid)
	}
	if b.hasHost {
		host = b.host
	}
	if b.hasNonce && b.nonce != "" {
		nonce = b.nonce
	}
	return fmt.Sprintf("an incomplete holder record (pid=%s host=%s nonce=%s); release it with expectedHolder: 'unreadable'", pid, host, nonce)
}

// withLock runs f under the cross-process lock; the caller holds s.mu.
func (s *DurableState) withLock(f func() error) error {
	nonce := dsRandHex(12)
	mustFence := false
	deadline := dsNowMs() + s.lockTimeout
	legacyLock := filepath.Join(s.dir, "state.lock")
acquire:
	for {
		topG, topBody, err := s.topLock()
		if err != nil {
			return err
		}
		// A single-file state.lock left by (or still used by) an older version counts as a holder too: wait for it unless its
		// owner is provably dead. We never delete or rename it.
		legacyBlocks := false
		if dsExists(legacyLock) {
			age := 0.0
			if fi, err := os.Stat(legacyLock); err == nil {
				age = float64(time.Since(fi.ModTime()).Milliseconds())
			}
			legacyBlocks = !s.holderDead(dsReadBody(legacyLock), age)
		}
		free := topG == 0 || (topBody != nil && !topBody.held)
		if !legacyBlocks && (free || s.holderDead(topBody, 0)) {
			// Taking over a DEAD holder whose lock is marked recovering: carry the mark and cut + fence before loading.
			var recovering *int64
			if !free && topBody != nil && topBody.hasRecov {
				r := topBody.recovering
				recovering = &r
			}
			body := fmt.Sprintf(`{"st":"held","pid":%d,"host":%s,"nonce":%s,"boot":%s`, os.Getpid(), dsJS(dsHostname()), dsJS(nonce), dsJS(dsBootID))
			if s.myNs != "" {
				body += fmt.Sprintf(`,"ns":%s`, dsJS(s.myNs))
			}
			if s.myStart != "" {
				body += fmt.Sprintf(`,"start":%s`, dsJS(s.myStart))
			}
			if recovering != nil {
				body += fmt.Sprintf(`,"recovering":%d`, *recovering)
			}
			won, err := s.createGen(topG+1, body)
			if err != nil {
				return err
			}
			if won {
				// The generation must still be the HIGHEST one (an ABA grab of a collected generation is buried, not a lock).
				g2, _, err := s.topLock()
				if err != nil {
					return err
				}
				if g2 != topG+1 {
					continue
				}
				s.myGen = int64(topG + 1)
				mustFence = recovering != nil
				break acquire
			}
			continue // lost the race for that generation: look again immediately
		}
		if dsNowMs() > deadline {
			dir := s.dir
			if legacyBlocks && (free || s.holderDead(topBody, 0)) {
				return dsErr(DurableLockTimeout, "could not acquire the state lock in %s within %d ms; blocked by %s (legacy single-file lock of an older version; %s). If that holder is provably gone, an operator can release it with recoverDurableState({ dir, force: true, legacyLock: true, expectedHolder }) after confirming the holder is dead; see the durable-state docs", dir, s.lockTimeout, legacyLock, s.holderDesc(dsReadBody(legacyLock)))
			}
			return dsErr(DurableLockTimeout, "could not acquire the state lock in %s within %d ms; blocked by %s (%s). If that holder is provably gone (e.g. a crashed container in another PID namespace), an operator can release it with recoverDurableState({ dir, force: true, expectedHolder }) after confirming the holder is dead; see the durable-state docs", dir, s.lockTimeout, s.lockFile(topG), s.holderDesc(topBody))
		}
		var r [1]byte
		_, _ = rand.Read(r[:])
		time.Sleep(time.Duration(5+int(r[0])%15) * time.Millisecond)
	}
	s.heldNonce = nonce
	s.holding = true
	s.gcLocks(s.myGen - 16)
	result := func() error {
		if mustFence {
			// The recovery we took over may have died before (or after) writing its fence; cut and fence now, under OUR
			// generation, before anything is loaded.
			dsKillSelfIf("takeover-after-lock")
			if err := dsWriteFence(s.dir, s.myGen-1, func() error {
				dsKillSelfIf("takeover-after-fence-temp")
				return nil
			}); err != nil {
				return err
			}
		}
		return f()
	}()
	s.holding = false
	s.heldNonce = ""
	// release; a live holder is never superseded, so this cannot lose a race
	if _, err := s.createGen(uint64(s.myGen+1), `{"st":"free"`); err == nil {
		s.gcLocks(s.myGen - 15)
	}
	return result
}

// assertLockHeld runs immediately before EVERY rename this writer makes (journal, head, quarantine): this handle's generation
// must still be the highest and must still name us. It is NOT sufficient alone (a holder paused between the check and the
// rename still renames): that window is closed on the READ side by the generation in every record and the fence (see load).
func (s *DurableState) assertLockHeld(outcome string) error {
	topG, topBody, err := s.topLock()
	if err != nil {
		return err
	}
	ok := s.holding && topBody != nil && int64(topG) == s.myGen && topBody.held && topBody.hasNonce && topBody.nonce == s.heldNonce
	if !ok {
		st := "unreadable"
		if topBody != nil {
			st = "free"
			if topBody.held {
				st = "held"
			}
		}
		return dsErr(DurableLockLost, "the state lock is no longer held by this writer (generation %d, highest %d %s); %s", s.myGen, topG, st, outcome)
	}
	return nil
}

// writeHead writes the head stamped with this writer's generation, guarded by the same lock re-check as the journal.
func (s *DurableState) writeHead(tail dsRec, outcome string) error {
	g := s.myGen
	txt := fmt.Sprintf(`{"seq":%d,"h":%s,"gen":%d`, tail.seq, dsJS(tail.h), g)
	if s.key != nil {
		txt += fmt.Sprintf(`,"mac":%s`, dsJS(dsMac(s.key, dsHeadMsg(tail.seq, tail.h, g, true))))
	}
	txt += "}\n"
	return dsAtomicWrite(s.headPath(), txt, false, func() error { return s.assertLockHeld(outcome) })
}

func (s *DurableState) newRec(seq int64, prev, op, payload string, ts int64) dsRec {
	r := dsRec{seq: seq, prev: prev, op: op, payload: payload, ts: ts, gen: s.myGen, hasGen: true}
	r.h = dsRecHash(seq, prev, op, payload, ts, s.myGen, true)
	if s.key != nil {
		r.mac, r.hasMac = dsMac(s.key, r.h), true
	}
	return r
}

func (s *DurableState) commit(l *dsLoaded, key, valueJSON string) error {
	seq := int64(1)
	prev := dsGenesis
	if n := len(l.recs); n > 0 {
		seq = l.recs[n-1].seq + 1
		prev = l.recs[n-1].h
	}
	payload := key + "\n" + valueJSON
	rec := s.newRec(seq, prev, "set", payload, s.now())
	all := append(append([]dsRec(nil), l.recs...), rec)
	if len(all) > s.compactEvery {
		// Compact: ONE checkpoint at the same seq the new record would have, chained from the current tail and carrying the
		// full state (including the new value). Head lag stays at most one record.
		next := make(map[string]string, len(l.state)+1)
		for k, v := range l.state {
			next[k] = v
		}
		next[key] = valueJSON
		keys := make([]string, 0, len(next))
		for k := range next {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return dsCmp16(keys[i], keys[j]) < 0 })
		parts := make([]string, len(keys))
		for i, k := range keys {
			parts[i] = "[" + dsJS(k) + "," + dsJS(next[k]) + "]"
		}
		cpPayload := "[" + strings.Join(parts, ",") + "]"
		all = []dsRec{s.newRec(seq, prev, "checkpoint", cpPayload, s.now())}
	}
	tail := all[len(all)-1]
	// Journal first (atomic), head second (atomic). A crash between leaves the head one record behind: repaired by the next
	// writer. The lock re-check runs AFTER the temp file is written and fsynced, i.e. as close to the rename as possible.
	lines := make([]string, len(all))
	for i, r := range all {
		lines[i] = dsRecLine(r)
	}
	if err := dsAtomicWrite(s.journalPath(), strings.Join(lines, "\n")+"\n", s.crashAt == DurableCrashAfterTempWrite, func() error { return s.assertLockHeld("nothing was written") }); err != nil {
		return err
	}
	if s.crashAt == DurableCrashAfterJournalRename {
		dsKillSelf()
	}
	if err := s.writeHead(tail, fmt.Sprintf("the journal record (seq %d) was renamed into place but state.head was not written; whether it counts depends on whether operator recovery cut before it (re-read the value)", tail.seq)); err != nil {
		return err
	}
	s.seenSeq = tail.seq
	s.seenHash = tail.h
	return nil
}

func (s *DurableState) repairHead(l *dsLoaded) error {
	if n := len(l.recs); n > 0 {
		last := l.recs[n-1]
		if l.head == nil || l.head.seq != last.seq {
			return s.writeHead(last, "nothing was written")
		}
	}
	return nil
}

// dsDecodeValue decodes stored JSON with float64 numbers (the conventional Go shape); nil when it does not parse.
func dsDecodeValue(txt string) any {
	var v any
	if json.Unmarshal([]byte(txt), &v) != nil {
		return nil
	}
	return v
}

// Get implements DurableStateKv.
func (s *DurableState) Get(key string) (any, bool, error) {
	if err := dsCheckKey(key); err != nil {
		return nil, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out any
	found := false
	err := s.withLock(func() error {
		l, err := s.load()
		if err != nil {
			return err
		}
		s.observe(l)
		if v, ok := l.state[key]; ok {
			out, found = dsDecodeValue(v), true
		}
		return nil
	})
	return out, found, err
}

// Keys implements DurableStateKv.
func (s *DurableState) Keys() ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var keys []string
	err := s.withLock(func() error {
		l, err := s.load()
		if err != nil {
			return err
		}
		s.observe(l)
		keys = make([]string, 0, len(l.state))
		for k := range l.state {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return dsCmp16(keys[i], keys[j]) < 0 })
		return nil
	})
	return keys, err
}

// Set implements DurableStateKv.
func (s *DurableState) Set(key string, value any) error {
	if err := dsCheckKey(key); err != nil {
		return err
	}
	vj, err := s.encode(value)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.withLock(func() error {
		l, err := s.load()
		if err != nil {
			return err
		}
		if err := s.repairHead(l); err != nil {
			return err
		}
		return s.commit(l, key, vj)
	})
}

// Update implements DurableStateKv.
func (s *DurableState) Update(key string, fn func(prev any, ok bool) (next any, write bool)) (any, bool, error) {
	if err := dsCheckKey(key); err != nil {
		return nil, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out any
	found := false
	err := s.withLock(func() error {
		l, err := s.load()
		if err != nil {
			return err
		}
		if err := s.repairHead(l); err != nil {
			return err
		}
		curJSON, has := l.state[key]
		var cur any
		if has {
			cur = dsDecodeValue(curJSON)
		}
		next, write := fn(cur, has)
		if !write {
			out, found = cur, has
			return nil
		}
		vj, err := s.encode(next)
		if err != nil {
			return err
		}
		if !has || curJSON != vj {
			if err := s.commit(l, key, vj); err != nil {
				return err
			}
		}
		out, found = dsDecodeValue(vj), true
		return nil
	})
	return out, found, err
}

// ---- in-memory implementation ----

// MemoryDurableKv is the in-memory DurableStateKv (tests, single process): the same semantics, no durability.
type MemoryDurableKv struct {
	mu sync.Mutex
	m  map[string]string
}

// CreateMemoryDurableKv returns an empty in-memory DurableStateKv.
func CreateMemoryDurableKv() *MemoryDurableKv { return &MemoryDurableKv{m: map[string]string{}} }

func dsMemEncode(v any) (string, error) {
	var buf bytes.Buffer
	e := json.NewEncoder(&buf)
	e.SetEscapeHTML(false)
	if err := e.Encode(v); err != nil {
		return "", dsErr(DurableInvalid, "value is not JSON-serialisable")
	}
	return strings.TrimSuffix(buf.String(), "\n"), nil
}

// Snapshot returns a decoded copy of every entry.
func (m *MemoryDurableKv) Snapshot() map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]any, len(m.m))
	for k, v := range m.m {
		out[k] = dsDecodeValue(v)
	}
	return out
}

// Get implements DurableStateKv.
func (m *MemoryDurableKv) Get(key string) (any, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.m[key]
	if !ok {
		return nil, false, nil
	}
	return dsDecodeValue(v), true, nil
}

// Set implements DurableStateKv.
func (m *MemoryDurableKv) Set(key string, value any) error {
	s, err := dsMemEncode(value)
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.m[key] = s
	m.mu.Unlock()
	return nil
}

// Update implements DurableStateKv.
func (m *MemoryDurableKv) Update(key string, fn func(prev any, ok bool) (next any, write bool)) (any, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	curJSON, has := m.m[key]
	var cur any
	if has {
		cur = dsDecodeValue(curJSON)
	}
	if next, write := fn(cur, has); write {
		s, err := dsMemEncode(next)
		if err != nil {
			return nil, false, err
		}
		m.m[key] = s
	}
	v, ok := m.m[key]
	if !ok {
		return nil, false, nil
	}
	return dsDecodeValue(v), true, nil
}

// Keys implements DurableStateKv.
func (m *MemoryDurableKv) Keys() ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	keys := make([]string, 0, len(m.m))
	for k := range m.m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return dsCmp16(keys[i], keys[j]) < 0 })
	return keys, nil
}

// ---- the atomic key/value seam ----

// DurableAtomicKV adapts a DurableStateKv to AtomicKV (values are stored as the JSON of the bytes given) and lists its keys.
type DurableAtomicKV struct{ kv DurableStateKv }

// NewDurableAtomicKV adapts a DurableStateKv (a *DurableState, or the in-memory one) to the AtomicKV seam the operation
// records and the plan registry are built on. The bytes handed to Update must be one JSON value.
func NewDurableAtomicKV(kv DurableStateKv) DurableAtomicKV { return DurableAtomicKV{kv} }

// Get implements AtomicKV.
func (d DurableAtomicKV) Get(key string) ([]byte, bool, error) {
	v, ok, err := d.kv.Get(key)
	if err != nil || !ok {
		return nil, false, err
	}
	b, err := json.Marshal(v)
	return b, err == nil, err
}

// Keys lists every key in UTF-16 code-unit order.
func (d DurableAtomicKV) Keys() ([]string, error) { return d.kv.Keys() }

// Update implements AtomicKV.
func (d DurableAtomicKV) Update(key string, fn func(prev []byte) []byte) error {
	var ferr error
	_, _, err := d.kv.Update(key, func(prev any, ok bool) (any, bool) {
		var pb []byte
		if ok {
			b, e := json.Marshal(prev)
			if e != nil {
				ferr = e
				return nil, false
			}
			pb = b
		}
		next := fn(pb)
		if next == nil {
			return nil, false
		}
		return json.RawMessage(next), true
	})
	if err != nil {
		return err
	}
	return ferr
}

// DurableOperationStore is the reference durableOperationStore(kv): an OperationStore over a DurableStateKv (a durable-state
// directory is crash-safe and multi-process-safe on one host). prefix namespaces the keys ("" is "pca-op:"). It has no
// ListOpen; recover a known id with RecoverOperation.
func DurableOperationStore(kv DurableStateKv, prefix string) *KVOperationStore {
	return NewKVOperationStore(NewDurableAtomicKV(kv), prefix)
}
