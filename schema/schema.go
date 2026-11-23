// Package schema publishes the JSON Schema for graph.json. The Go source of
// truth stays internal/graph/types.go; this file documents the serialized form
// and is what `gop validate` checks against.
package schema

import _ "embed"

// GraphV1 is the JSON Schema (draft 2020-12) for gop.graph/v1.
//
//go:embed gop.graph.v1.schema.json
var GraphV1 []byte
