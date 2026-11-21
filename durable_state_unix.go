//go:build unix

package pca

import (
	"errors"
	"math"
	"os"
	"syscall"
)

func dsFsyncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return dsIO(err)
	}
	defer f.Close()
	return dsIO(f.Sync())
}

func dsErrnoName(err error) string {
	var en syscall.Errno
	if errors.As(err, &en) {
		switch en {
		case syscall.EPERM:
			return "EPERM"
		case syscall.ENOENT:
			return "ENOENT"
		case syscall.EIO:
			return "EIO"
		case syscall.EACCES:
			return "EACCES"
		case syscall.EEXIST:
			return "EEXIST"
		case syscall.EXDEV:
			return "EXDEV"
		case syscall.EROFS:
			return "EROFS"
		case syscall.EMLINK:
			return "EMLINK"
		case syscall.ENOSYS:
			return "ENOSYS"
		case syscall.ENOTSUP:
			return "ENOTSUP"
		}
	}
	return "error"
}

// dsPidAlive is kill(pid, 0): the process exists (or exists but is not ours: EPERM).
func dsPidAlive(pid float64) bool {
	if !(pid == math.Trunc(pid) && math.Abs(pid) <= math.MaxInt32) {
		return false
	}
	err := syscall.Kill(int(pid), 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

func dsKillSelf() { _ = syscall.Kill(os.Getpid(), syscall.SIGKILL) }

// dsLinkCount is the hard-link count of the file just stat-ed.
func dsLinkCount(_ string, fi os.FileInfo) (uint64, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint64(st.Nlink), true
}
