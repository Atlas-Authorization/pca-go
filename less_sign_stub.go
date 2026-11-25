//go:build !(less && cgo)

package pca

// LessCat1Keygen is unavailable in this build: it returns ErrLessUnavailable.
func LessCat1Keygen(seed []byte) (publicKey, secretKey []byte, err error) {
	return nil, nil, ErrLessUnavailable
}

// LessCat1Sign is unavailable in this build: it returns ErrLessUnavailable.
func LessCat1Sign(secretKey, msg, seed []byte) ([]byte, error) { return nil, ErrLessUnavailable }
