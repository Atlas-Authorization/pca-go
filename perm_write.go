package pca

import "os"

// WriteFileOwnerOnly writes data to a file created for its owner alone (see CreateOwnerOnly), truncating an existing one.
func WriteFileOwnerOnly(path string, data []byte) error {
	f, err := CreateOwnerOnly(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	return werr
}
