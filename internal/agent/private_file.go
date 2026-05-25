package agent

import (
	"os"
)

const (
	privateStateDirMode  os.FileMode = 0o700
	privateStateFileMode os.FileMode = 0o600
)

func ensurePrivateStateDir(dir string) error {
	if err := os.MkdirAll(dir, privateStateDirMode); err != nil {
		return err
	}
	return os.Chmod(dir, privateStateDirMode)
}

func createPrivateStateTempFile(dir, pattern string) (*os.File, string, error) {
	tmp, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return nil, "", err
	}
	tmpName := tmp.Name()
	if err := tmp.Chmod(privateStateFileMode); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return nil, "", err
	}
	return tmp, tmpName, nil
}
