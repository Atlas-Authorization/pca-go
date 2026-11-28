//go:build windows

package pca

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// The failure branches and flag handling of perm_windows.go (perm_writers_test.go covers the happy path of every writer).

func setDACL(t *testing.T, path string, protected bool, sids ...*windows.SID) {
	t.Helper()
	var acl *windows.ACL
	if len(sids) > 0 {
		var ea []windows.EXPLICIT_ACCESS
		for _, s := range sids {
			ea = append(ea, windows.EXPLICIT_ACCESS{AccessPermissions: windows.GENERIC_ALL, AccessMode: windows.GRANT_ACCESS,
				Trustee: windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_UNKNOWN, TrusteeValue: windows.TrusteeValueFromSID(s)}})
		}
		var err error
		if acl, err = windows.ACLFromEntries(ea, nil); err != nil {
			t.Fatal(err)
		}
	}
	info := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION)
	if protected {
		info |= windows.PROTECTED_DACL_SECURITY_INFORMATION
	} else {
		info |= windows.UNPROTECTED_DACL_SECURITY_INFORMATION
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, info, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
}

func TestWinOwnerOnlyRejectsEveryOtherShape(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "f")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	me, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	everyone, _ := windows.StringToSid("S-1-1-0")
	setDACL(t, p, false, me.User.Sid)
	if OwnerOnly(p) == nil {
		t.Error("an access list that inherits from the folder is not owner-only")
	}
	setDACL(t, p, true)
	if OwnerOnly(p) == nil {
		t.Error("no access list (everyone) is not owner-only")
	}
	setDACL(t, p, true, me.User.Sid, everyone)
	if OwnerOnly(p) == nil {
		t.Error("two entries are not owner-only")
	}
	setDACL(t, p, true, everyone)
	if OwnerOnly(p) == nil {
		t.Error("one entry for another account is not owner-only")
	}
	if err := RestrictToOwner(p); err != nil {
		t.Fatal(err)
	}
	if err := OwnerOnly(p); err != nil {
		t.Fatalf("restricted: %v", err)
	}
	if OwnerOnly(filepath.Join(d, "absent")) == nil || RestrictToOwner(filepath.Join(d, "absent")) == nil {
		t.Error("an absent file is an error")
	}
}

func TestWinCreateOwnerOnlyFlags(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "f")
	f, err := CreateOwnerOnly(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("abc"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Read(make([]byte, 1)); err == nil {
		t.Error("write-only handle read")
	}
	f.Close()
	if err := OwnerOnly(p); err != nil {
		t.Fatalf("created file: %v", err)
	}
	if g, err := CreateOwnerOnly(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL); err == nil {
		g.Close()
		t.Fatal("O_EXCL on an existing file must fail")
	}
	f, err = CreateOwnerOnly(p, os.O_WRONLY|os.O_APPEND)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("def")
	f.Close()
	if b, _ := os.ReadFile(p); string(b) != "abcdef" {
		t.Fatalf("append: %q", b)
	}
	f, err = CreateOwnerOnly(p, os.O_RDWR)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 3)
	if n, err := f.Read(buf); err != nil || string(buf[:n]) != "abc" {
		t.Fatalf("read-write read: %q %v", buf[:n], err)
	}
	if _, err := f.WriteString("X"); err != nil {
		t.Fatalf("read-write write: %v", err)
	}
	f.Close()
	f, err = CreateOwnerOnly(p, os.O_RDONLY)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("Y"); err == nil {
		t.Error("read-only handle wrote")
	}
	f.Close()
	f, err = CreateOwnerOnly(p, os.O_WRONLY|os.O_TRUNC)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if b, _ := os.ReadFile(p); len(b) != 0 {
		t.Fatalf("O_TRUNC left %q", b)
	}
	f, err = CreateOwnerOnly(p, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("new")
	f.Close()
	if b, _ := os.ReadFile(p); string(b) != "new" {
		t.Fatalf("create+trunc: %q", b)
	}
	// a file that existed before (inherited list) is restricted by the call
	q := filepath.Join(d, "pre")
	os.WriteFile(q, []byte("x"), 0o600)
	f, err = CreateOwnerOnly(q, os.O_RDWR|os.O_CREATE)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := OwnerOnly(q); err != nil {
		t.Fatalf("pre-existing file not restricted: %v", err)
	}
	// O_CREATE of a new file without O_EXCL
	r := filepath.Join(d, "fresh")
	f, err = CreateOwnerOnly(r, os.O_RDWR|os.O_CREATE)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := OwnerOnly(r); err != nil {
		t.Fatal(err)
	}
	if g, err := CreateOwnerOnly(filepath.Join(d, "absent"), os.O_RDONLY); err == nil {
		g.Close()
		t.Fatal("opening an absent file without O_CREATE must fail")
	}
	if g, err := CreateOwnerOnly("bad\x00name", os.O_RDONLY); err == nil {
		g.Close()
		t.Fatal("NUL in the name")
	}
}

func TestWinMkdirAllOwnerOnly(t *testing.T) {
	d := t.TempDir()
	deep := filepath.Join(d, "a", "b", "c")
	if err := MkdirAllOwnerOnly(deep); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{filepath.Join(d, "a"), filepath.Join(d, "a", "b"), deep} {
		if err := OwnerOnly(p); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
	if err := MkdirAllOwnerOnly(deep); err != nil {
		t.Fatalf("existing directory: %v", err)
	}
	f := filepath.Join(d, "file")
	os.WriteFile(f, nil, 0o600)
	if MkdirAllOwnerOnly(f) == nil || MkdirAllOwnerOnly(filepath.Join(f, "sub")) == nil {
		t.Error("a file where a directory is wanted must fail")
	}
	if MkdirAllOwnerOnly("bad\x00name") == nil {
		t.Error("NUL in the name")
	}
}
