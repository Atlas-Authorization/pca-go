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
	want := os.FileMode(0o600)
	if fi.IsDir() {
		want = 0o700
	}
	if fi.Mode().Perm() != want {
		return errors.New("mode is not " + want.String()[1:])
	}
	return nil
}

// CreateOwnerOnly opens a file for the flags of os.OpenFile, created readable and writable by its owner alone from the first instant.
func CreateOwnerOnly(path string, flag int) (*os.File, error) { return os.OpenFile(path, flag, 0o600) }

// MkdirAllOwnerOnly creates a directory (and any missing parent) accessible to its owner alone.
func MkdirAllOwnerOnly(path string) error { return os.MkdirAll(path, 0o700) }
