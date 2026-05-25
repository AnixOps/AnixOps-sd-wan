package auth

import (
	"fmt"
	"os"
	"runtime"
)

func validatePrivateAuthFile(path, name string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat %s: %w", name, err)
	}
	if info.IsDir() {
		return fmt.Errorf("%s must be a file", name)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return fmt.Errorf("%s must not be group/world accessible; got mode %o", name, mode)
	}
	return nil
}
