//go:build windows

package pca

import (
	"errors"
	"math"
	"os"
	"syscall"
	"time"
)

// dsFsyncDir is a no-op: Windows has no directory fsync, and NTFS journals directory entries itself.
func dsFsyncDir(string) error { return nil }

func dsErrnoName(err error) string {
	var en syscall.Errno
	if errors.As(err, &en) {
		switch en {
		case syscall.ERROR_FILE_NOT_FOUND, syscall.ERROR_PATH_NOT_FOUND:
			return "ENOENT"
		case syscall.ERROR_ACCESS_DENIED:
			return "EACCES"
		case syscall.ERROR_ALREADY_EXISTS, syscall.ERROR_FILE_EXISTS:
			return "EEXIST"
		case 17: // ERROR_NOT_SAME_DEVICE (not exported by package syscall)
			return "EXDEV"
		case 50, 120: // ERROR_NOT_SUPPORTED, ERROR_CALL_NOT_IMPLEMENTED
			return "ENOSYS"
		}
	}
	return "error"
}

const dsStillActive = 259

// dsPidAlive opens the process and checks that it has not exited; access denied means it exists but is not ours.
func dsPidAlive(pid float64) bool {
	if !(pid == math.Trunc(pid) && pid > 0 && pid <= math.MaxInt32) {
		return false
	}
	h, err := syscall.OpenProcess(syscall.PROCESS_QUERY_INFORMATION, false, uint32(pid))
	if err != nil {
		return errors.Is(err, syscall.ERROR_ACCESS_DENIED)
	}
	defer syscall.CloseHandle(h)
	var code uint32
	if syscall.GetExitCodeProcess(h, &code) != nil {
		return true
	}
	return code == dsStillActive
}

func dsKillSelf() {
	if p, err := os.FindProcess(os.Getpid()); err == nil {
		_ = p.Kill()
	}
	// TerminateProcess returns before the process is gone: never return past the crash point.
	for {
		time.Sleep(time.Hour)
	}
}

// dsLinkCount reads NumberOfLinks from the file's handle information.
func dsLinkCount(path string, _ os.FileInfo) (uint64, bool) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, false
	}
	h, err := syscall.CreateFile(p, 0, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE, nil, syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return 0, false
	}
	defer syscall.CloseHandle(h)
	var info syscall.ByHandleFileInformation
	if syscall.GetFileInformationByHandle(h, &info) != nil {
		return 0, false
	}
	return uint64(info.NumberOfLinks), true
}
