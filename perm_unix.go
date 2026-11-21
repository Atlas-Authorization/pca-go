//go:build !windows

package pca

import (
	"errors"
	"os"
)

// RestrictToOwner leaves a secret file readable by its owner only (the file is created 0600; the mode is set again in case umask
// or an existing file said otherwise).
func RestrictToOwner(path string) error { return os.Chmod(path, 0o600) }

// OwnerOnly reports whether the file is readable and writable by its owner alone.
func OwnerOnly(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if fi.Mode().Perm() != 0o600 {
		return errors.New("mode is not 0600")
	}
	return nil
}
