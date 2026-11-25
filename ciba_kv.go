package pca

// A shared-store ApprovalStore built on a tiny durable key-value interface that needs ONE primitive, a compare-and-swap on a string.
// Redis (a Lua script or WATCH/MULTI), DynamoDB (a conditional put), SQL (UPDATE ... WHERE value = ?) and etcd (a transaction) all
// provide it; a directory implementation covers several processes on one host.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// DurableKv is a durable string key-value store with compare-and-swap. PutIfEquals writes next only if the stored value is exactly
// expected (nil: the key must be absent) and reports whether it wrote. It MUST be atomic across every process sharing the store, and
// a write MUST be durable before it returns. Any failure must be an error: never report true for a write that may be lost.
type DurableKv interface {
	Get(key string) (value string, found bool, err error)
	PutIfEquals(key string, expected *string, next string) (bool, error)
}

// ApprovalStoreErr codes of the KV implementations; the broker treats any error from a store as "no approval".
const (
	ApprovalCorruptRecord = "corrupt_record"
	ApprovalLockTimeout   = "lock_timeout"
	ApprovalBadKey        = "bad_key"
)

func cibaKVDecode(raw string) (ApprovalVersioned, error) {
	var rec map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &rec); err != nil {
		return ApprovalVersioned{}, &CodedError{Code: ApprovalCorruptRecord, Msg: "ciba: stored approval record is not valid JSON"}
	}
	var version float64
	value, hasValue := rec["value"]
	if err := json.Unmarshal(rec["version"], &version); err != nil || version != math.Trunc(version) || version < 1 || version > 1<<53 || !hasValue {
		return ApprovalVersioned{}, &CodedError{Code: ApprovalCorruptRecord, Msg: "ciba: stored approval record has no valid version"}
	}
	var v any
	if err := json.Unmarshal(value, &v); err != nil {
		return ApprovalVersioned{}, &CodedError{Code: ApprovalCorruptRecord, Msg: "ciba: stored approval record is not valid JSON"}
	}
	return ApprovalVersioned{Version: int(version), Value: v}, nil
}

type kvApprovalStore struct{ kv DurableKv }

// NewKvApprovalStore is an ApprovalStore over kv. Each key holds {"version","value"} as JSON; Cas re-reads the raw string, checks the
// version and swaps only if the raw string is still the one it read, so two processes racing on one expected version cannot both
// win. A stored value that is not a valid versioned record is an error (corrupt_record).
func NewKvApprovalStore(kv DurableKv) (ApprovalStore, error) {
	if kv == nil {
		return nil, errors.New("NewKvApprovalStore: kv is required")
	}
	return &kvApprovalStore{kv: kv}, nil
}

func (s *kvApprovalStore) Get(key string) (*ApprovalVersioned, error) {
	raw, found, err := s.kv.Get(key)
	if err != nil || !found {
		return nil, err
	}
	v, err := cibaKVDecode(raw)
	if err != nil {
		return nil, err
	}
	return &v, nil
}

func (s *kvApprovalStore) Cas(key string, expectedVersion int, value any) (bool, error) {
	raw, found, err := s.kv.Get(key)
	if err != nil {
		return false, err
	}
	current := 0
	var expected *string
	if found {
		v, derr := cibaKVDecode(raw)
		if derr != nil {
			return false, derr
		}
		current, expected = v.Version, &raw
	}
	if current != expectedVersion {
		return false, nil
	}
	vb, err := json.Marshal(value)
	if err != nil {
		return false, err
	}
	return s.kv.PutIfEquals(key, expected, fmt.Sprintf(`{"version":%d,"value":%s}`, expectedVersion+1, vb))
}

type dirKv struct {
	dir     string
	timeout time.Duration
}

// NewDirectoryKv is a DurableKv on a directory, safe for several processes on ONE host (and one filesystem with atomic exclusive
// create and rename). One file per key (named by the SHA-256 of the key, so no key can escape the directory); each swap takes a
// per-key lock file (exclusive create), compares, writes a fsynced temp file and renames it over the key. A process that dies holding
// the lock leaves it behind: every later swap on that key then fails with lock_timeout (fail closed) until an operator removes the
// .lock file. A zero lockTimeout means 5 s. For several hosts use a database-backed DurableKv.
func NewDirectoryKv(dir string, lockTimeout time.Duration) (DurableKv, error) {
	if lockTimeout < 0 {
		return nil, errors.New("NewDirectoryKv: lockTimeout must be positive")
	}
	if lockTimeout == 0 {
		lockTimeout = 5 * time.Second
	}
	if err := MkdirAllOwnerOnly(dir); err != nil {
		return nil, err
	}
	return &dirKv{dir: dir, timeout: lockTimeout}, nil
}

func (d *dirKv) fileOf(key string) (string, error) {
	if key == "" {
		return "", &CodedError{Code: ApprovalBadKey, Msg: "ciba: store key must be a non-empty string"}
	}
	h := sha256.Sum256([]byte(key))
	return filepath.Join(d.dir, hex.EncodeToString(h[:])), nil
}

func readKvFile(f string) (string, bool, error) {
	b, err := os.ReadFile(f)
	if errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	}
	return string(b), err == nil, err
}

func (d *dirKv) Get(key string) (string, bool, error) {
	f, err := d.fileOf(key)
	if err != nil {
		return "", false, err
	}
	return readKvFile(f)
}

func (d *dirKv) PutIfEquals(key string, expected *string, next string) (bool, error) {
	f, err := d.fileOf(key)
	if err != nil {
		return false, err
	}
	lock := f + ".lock"
	deadline := time.Now().Add(d.timeout)
	for {
		fd, err := CreateOwnerOnly(lock, os.O_CREATE|os.O_EXCL|os.O_WRONLY)
		if err == nil {
			fd.Close()
			break
		}
		if !errors.Is(err, os.ErrExist) {
			return false, err
		}
		if !time.Now().Before(deadline) {
			return false, &CodedError{Code: ApprovalLockTimeout, Msg: "ciba: could not take the store lock in time"}
		}
		time.Sleep(2 * time.Millisecond)
	}
	defer os.Remove(lock)
	cur, found, err := readKvFile(f)
	if err != nil {
		return false, err
	}
	if found != (expected != nil) || (found && cur != *expected) {
		return false, nil
	}
	tmp := fmt.Sprintf("%s.%d.tmp", f, os.Getpid())
	t, err := CreateOwnerOnly(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY)
	if err != nil {
		return false, err
	}
	_, werr := t.WriteString(next)
	if werr == nil {
		werr = t.Sync() // durable before the rename publishes it
	}
	if cerr := t.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		os.Remove(tmp)
		return false, werr
	}
	if err := os.Rename(tmp, f); err != nil {
		os.Remove(tmp)
		return false, err
	}
	return true, nil
}

type memoryKv struct {
	mu sync.Mutex
	m  map[string]string
}

// CreateMemoryKv is a single-process DurableKv for tests of code that takes a KV. It is NOT durable.
func CreateMemoryKv() DurableKv { return &memoryKv{m: map[string]string{}} }

func (k *memoryKv) Get(key string) (string, bool, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	v, ok := k.m[key]
	return v, ok, nil
}

func (k *memoryKv) PutIfEquals(key string, expected *string, next string) (bool, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	cur, has := k.m[key]
	if (expected == nil) != !has || (expected != nil && *expected != cur) {
		return false, nil
	}
	k.m[key] = next
	return true, nil
}
