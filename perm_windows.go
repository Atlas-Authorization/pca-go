//go:build windows

package pca

import (
	"errors"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// RestrictToOwner replaces the file's access list with one entry for the current user and stops it inheriting the folder's list:
// Windows has no permission bits, so this is what keeps a private key from being readable by other accounts.
func RestrictToOwner(path string) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(user.User.Sid),
		},
	}}, nil)
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}

// OwnerOnly reports whether the file's access list is protected and holds one entry, for the current user.
func OwnerOnly(path string) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	control, _, err := sd.Control()
	if err != nil {
		return err
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return errors.New("the access list inherits from the folder")
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return errors.New("no access list")
	}
	if dacl.AceCount != 1 {
		return errors.New("the access list holds more than one entry")
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, 0, &ace); err != nil {
		return err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	if !(*windows.SID)(unsafe.Pointer(&ace.SidStart)).Equals(user.User.Sid) {
		return errors.New("the entry is not for the current user")
	}
	return nil
}

// ownerAttributes is the security attributes of an object created for the current user alone: a protected access list with one
// entry, passed at creation so that no other process can open the object before it is restricted.
func ownerAttributes() (*windows.SecurityAttributes, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		return nil, err
	}
	return &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}, nil
}

// CreateOwnerOnly opens a file for the flags of os.OpenFile (read/write mode, O_CREATE, O_EXCL, O_TRUNC, O_APPEND), created with an
// owner-only protected access list set atomically by CreateFile. An existing file keeps its list, so one that was not created
// here is restricted afterwards.
func CreateOwnerOnly(path string, flag int) (*os.File, error) {
	sa, err := ownerAttributes()
	if err != nil {
		return nil, err
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	var access uint32
	switch {
	case flag&os.O_APPEND != 0:
		access = windows.FILE_APPEND_DATA
	case flag&os.O_WRONLY != 0:
		access = windows.GENERIC_WRITE
	case flag&os.O_RDWR != 0:
		access = windows.GENERIC_READ | windows.GENERIC_WRITE
	default:
		access = windows.GENERIC_READ
	}
	var disposition uint32
	switch {
	case flag&os.O_CREATE != 0 && flag&os.O_EXCL != 0:
		disposition = windows.CREATE_NEW
	case flag&os.O_CREATE != 0 && flag&os.O_TRUNC != 0:
		disposition = windows.CREATE_ALWAYS
	case flag&os.O_CREATE != 0:
		disposition = windows.OPEN_ALWAYS
	case flag&os.O_TRUNC != 0:
		disposition = windows.TRUNCATE_EXISTING
	default:
		disposition = windows.OPEN_EXISTING
	}
	h, err := windows.CreateFile(p, access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, sa, disposition, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	if flag&os.O_EXCL == 0 {
		if rerr := RestrictToOwner(path); rerr != nil { // the file may have existed before: its list was not set by this call
			windows.CloseHandle(h)
			return nil, rerr
		}
	}
	return os.NewFile(uintptr(h), path), nil
}

// MkdirAllOwnerOnly creates a directory (and any missing parent) with an owner-only protected access list set by CreateDirectory.
func MkdirAllOwnerOnly(path string) error {
	if fi, err := os.Stat(path); err == nil {
		if !fi.IsDir() {
			return &os.PathError{Op: "mkdir", Path: path, Err: errors.New("not a directory")}
		}
		return nil
	}
	if parent := filepath.Dir(path); parent != path {
		if err := MkdirAllOwnerOnly(parent); err != nil {
			return err
		}
	}
	sa, err := ownerAttributes()
	if err != nil {
		return err
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	if err := windows.CreateDirectory(p, sa); err != nil && err != windows.ERROR_ALREADY_EXISTS {
		return &os.PathError{Op: "mkdir", Path: path, Err: err}
	}
	return nil
}
