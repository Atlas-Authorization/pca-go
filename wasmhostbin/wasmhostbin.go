// Package wasmhostbin carries the reference wasmtime host (pca-wasmtime-host) that the core module's RunComponent runs as a pinned
// subprocess, so the sandbox component host works with nothing to build or install. It is pure Go (no cgo): a tagged release embeds
// the host built for linux and macOS (amd64, arm64) and windows amd64 (only the binary for the target platform is compiled in). A source checkout
// and other platforms carry no host; Options then reports that, and the PCA_WASMTIME_HOST / PCA_WASMTIME_HOST_SHA256 settings still work (and win over the packaged host).
package wasmhostbin

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	pca "github.com/Atlas-Authorization/pca-go"
)

// ErrNoHost: this build carries no packaged host.
var ErrNoHost = errors.New("wasmhostbin: no packaged host for this platform (set ComponentOptions.Host and ExpectedSHA256, or PCA_WASMTIME_HOST and PCA_WASMTIME_HOST_SHA256)")

// Options returns o with Host and ExpectedSHA256 resolved in this order: an explicit option or the PCA_WASMTIME_HOST /
// PCA_WASMTIME_HOST_SHA256 settings win (o is returned for RunComponent to apply); then the packaged host; then a pca-wasmtime-host on
// PATH, which is only used with a pin you supply (a binary pinned by its own digest would pin nothing). The packaged host is written once
// to the user cache directory under its own digest (private, 0700) and re-written if the file there does not match.
func Options(o pca.ComponentOptions) (pca.ComponentOptions, error) {
	return resolve(o, os.Getenv, exec.LookPath, hostBinary)
}

func resolve(o pca.ComponentOptions, getenv func(string) string, lookPath func(string) (string, error), packaged []byte) (pca.ComponentOptions, error) {
	if o.Host != "" || getenv("PCA_WASMTIME_HOST") != "" {
		return o, nil
	}
	if len(packaged) > 0 {
		sum := sha256.Sum256(packaged)
		pin := hex.EncodeToString(sum[:]) // the pin of the packaged bytes themselves; a pin meant for another host is not applied
		path, err := writeHost(packaged, sum)
		if err != nil {
			return o, err
		}
		o.Host, o.ExpectedSHA256 = path, pin
		return o, nil
	}
	if p, err := lookPath("pca-wasmtime-host"); err == nil && (o.ExpectedSHA256 != "" || getenv("PCA_WASMTIME_HOST_SHA256") != "") {
		o.Host = p
		return o, nil
	}
	return o, ErrNoHost
}

func writeHost(b []byte, sum [32]byte) (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		base = os.TempDir()
	}
	name := "pca-wasmtime-host"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	dir := filepath.Join(base, "pca-wasmtime-host", hex.EncodeToString(sum[:]))
	path := filepath.Join(dir, name)
	if cur, err := os.ReadFile(path); err == nil && sha256.Sum256(cur) == sum {
		return path, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(dir, "host-*")
	if err != nil {
		return "", err
	}
	_, werr := tmp.Write(b)
	cerr := tmp.Close()
	if werr != nil || cerr != nil || os.Chmod(tmp.Name(), 0o700) != nil || os.Rename(tmp.Name(), path) != nil {
		os.Remove(tmp.Name())
		return "", errors.New("wasmhostbin: cannot write the packaged host to the cache directory")
	}
	return path, nil
}
