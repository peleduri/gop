// Package logo embeds the PNG exports of the gop mark that distribution
// artifacts ship (the MCPB extension icons). The SVG sources and every PNG
// size live next to this file; BRAND.md lists where each one is used.
package logo

import _ "embed"

// Mark512 is png/gop-mark-512.png.
//
//go:embed png/gop-mark-512.png
var Mark512 []byte

// Mark1024 is png/gop-mark-1024.png.
//
//go:embed png/gop-mark-1024.png
var Mark1024 []byte
