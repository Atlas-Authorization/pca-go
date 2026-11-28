//go:build windows

package pca

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// The Windows-only helpers of the durable store (durable_state_windows.go). durable_state_test.go is unix-only (SIGKILL, file modes),
// so these run here and are the oracle of the Windows mutation shard.

func TestWinDsErrnoName(t *testing.T) {
	for _, c := range []struct {
		err  error
		want string
	}{
		{syscall.ERROR_FILE_NOT_FOUND, "ENOENT"}, {syscall.ERROR_PATH_NOT_FOUND, "ENOENT"},
		{syscall.ERROR_ACCESS_DENIED, "EACCES"},
		{syscall.ERROR_ALREADY_EXISTS, "EEXIST"}, {syscall.ERROR_FILE_EXISTS, "EEXIST"},
		{syscall.Errno(17), "EXDEV"}, {syscall.Errno(50), "ENOSYS"}, {syscall.Errno(120), "ENOSYS"},
		{syscall.Errno(6), "error"}, {errors.New("plain"), "error"}, {nil, "error"},
		{fmt.Errorf("wrapped: %w", syscall.ERROR_ACCESS_DENIED), "EACCES"},
	} {
		if got := dsErrnoName(c.err); got != c.want {
			t.Errorf("dsErrnoName(%v) = %q, want %q", c.err, got, c.want)
		}
	}
}

func TestWinDsFsyncDirIsNoOp(t *testing.T) {
	if err := dsFsyncDir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if err := dsFsyncDir(filepath.Join(t.TempDir(), "absent")); err != nil {
		t.Fatalf("no directory fsync on Windows, so never an error: %v", err)
	}
}

func TestWinDsLinkCount(t *testing.T) {
	d := t.TempDir()
	a, b := filepath.Join(d, "a"), filepath.Join(d, "b")
	if err := os.WriteFile(a, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(a)
	if n, ok := dsLinkCount(a, fi); !ok || n != 1 {
		t.Fatalf("one name: got %d, %v", n, ok)
	}
	if err := os.Link(a, b); err != nil {
		t.Skipf("hard links unavailable here: %v", err)
	}
	if n, ok := dsLinkCount(a, fi); !ok || n != 2 {
		t.Fatalf("two names: got %d, %v", n, ok)
	}
	if n, ok := dsLinkCount(filepath.Join(d, "absent"), fi); ok || n != 0 {
		t.Fatalf("absent file: got %d, %v", n, ok)
	}
	if n, ok := dsLinkCount("bad\x00name", fi); ok || n != 0 {
		t.Fatalf("name with NUL: got %d, %v", n, ok)
	}
}

func TestWinDsPidAlive(t *testing.T) {
	if !dsPidAlive(float64(os.Getpid())) {
		t.Fatal("this process is alive")
	}
	for _, p := range []float64{0, -1, 1.5, math.NaN(), math.Inf(1), math.MaxInt32 + 1, float64(math.MaxInt32)} {
		if dsPidAlive(p) {
			t.Errorf("pid %v must not be alive", p)
		}
	}
	// a live child, then the same child after it exited
	c := exec.Command(os.Args[0], "-test.run=^TestWinSleepChild$")
	c.Env = append(os.Environ(), "PCA_WIN_SLEEP_CHILD=1")
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	pid := float64(c.Process.Pid)
	if !dsPidAlive(pid) {
		t.Error("a running child is alive")
	}
	_ = c.Process.Kill()
	_ = c.Wait()
	if dsPidAlive(pid) {
		t.Error("an exited child is not alive")
	}
}

func TestWinSleepChild(t *testing.T) {
	if os.Getenv("PCA_WIN_SLEEP_CHILD") == "" {
		t.Skip("child of TestWinDsPidAlive")
	}
	time.Sleep(time.Minute)
}

func TestWinDsKillSelf(t *testing.T) {
	if os.Getenv("PCA_WIN_KILL_CHILD") != "" {
		dsKillSelf()
		os.Exit(0) // never reached: dsKillSelf does not return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestWinDsKillSelf$")
	c.Env = append(os.Environ(), "PCA_WIN_KILL_CHILD=1")
	err := c.Run()
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ctx.Err() != nil {
		t.Fatalf("the child must die by TerminateProcess before the deadline, got %v (ctx %v)", err, ctx.Err())
	}
	if ee.ExitCode() != 1 {
		t.Fatalf("TerminateProcess through Process.Kill exits with 1, got %d", ee.ExitCode())
	}
}
