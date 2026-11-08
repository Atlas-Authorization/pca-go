package pca

import "testing"

// A PRIMITIVE-encoded universal SEQUENCE / SET (tag 0x10 / 0x11, constructed bit clear) is still walked as a container: its
// content is parsed as TLVs, so a content byte that is no valid TLV fails the whole parse. The `univ && (num == 16 || num == 17)`
// term of the container test carries that alone (cons is false here).
func TestR8N0_PrimitiveSequenceAndSetAreWalkedAsContainers(t *testing.T) {
	for _, tag := range []byte{0x10, 0x11} {
		b := []byte{tag, 0x01, 0xFF}
		var ok bool
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("tag %#x: panic %v", tag, r)
				}
			}()
			_, _, _, ok = ocspBER(b, 0, len(b), 0, &ocspBERState{})
		}()
		if ok {
			t.Errorf("tag %#x: a primitive SEQUENCE/SET with an invalid child parsed ok", tag)
		}
	}
}
