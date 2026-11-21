//go:build less && cgo

package pca

import "testing"

// lessCat1VerifyRawErrno reports the C verdict as a bool: a valid signature is true, another key's is false.
func TestR5N3LessRawErrnoVerdict(t *testing.T) {
	f := lessWrapperFixture(t)
	ok, _ := lessCat1VerifyRawErrno(lessPtr(f.pk), uint64(len(f.pk)), lessPtr(f.msg), uint64(len(f.msg)), lessPtr(f.sig), uint64(len(f.sig)))
	if !ok {
		t.Error("a valid signature was refused")
	}
	ok, _ = lessCat1VerifyRawErrno(lessPtr(f.pkOther), uint64(len(f.pkOther)), lessPtr(f.msg), uint64(len(f.msg)), lessPtr(f.sig), uint64(len(f.sig)))
	if ok {
		t.Error("a signature under another key was accepted")
	}
}
