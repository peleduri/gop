// Command gen writes the generated CSS of brand/tokens.json: the custom
// properties to brand/tokens.css, and the site's @font-face rules plus the
// custom properties to site/brand.css.
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

// targets are the generated files, relative to the repository root.
var targets = map[string]func() string{"brand/tokens.css": brand.TokensCSS, "site/brand.css": brand.SiteCSS}

func main() {
	for _, p := range []string{"brand/tokens.css", "site/brand.css"} {
		if err := os.WriteFile(p, []byte(targets[p]()), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "brand/gen:", err)
			os.Exit(1)
		}
		fmt.Println("brand/gen: wrote", p)
	}
}
