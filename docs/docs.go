// Package docs embeds the reference pages that gop serves at runtime.
package docs

import _ "embed"

// Schema is docs/schema.md: node ID conventions and edge semantics of the
// graph. The MCP server serves it as the gop://graph/schema resource.
//
//go:embed schema.md
var Schema string
