//go:build !fyne

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "anix-ui requires the fyne build tag: go run -tags fyne ./cmd/anix-ui")
	os.Exit(2)
}
