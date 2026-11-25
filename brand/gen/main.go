// Command gen writes the CSS custom-properties copies of brand/tokens.json.
// Run it from the repository root after editing tokens.json:
//
//	go run ./brand/gen
//
// brand.TestCopiesMatch fails until the copies are regenerated.
package main

import (
	"fmt"
	"os"

	"github.com/peleduri/gop/brand"
)

// Targets are the generated files, relative to the repository root.
var targets = []string{"brand/tokens.css", "site/brand.css"}

func main() {
	css := []byte(brand.CSS())
	for _, p := range targets {
		if err := os.WriteFile(p, css, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "brand/gen:", err)
			os.Exit(1)
		}
		fmt.Println("brand/gen: wrote", p)
	}
}
