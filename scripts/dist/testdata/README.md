# Vendored schemas

Copies of published JSON Schemas, so the tests check gop's distribution files
offline. Refresh them when the upstream version changes, and update the
`$schema` / `manifest_version` the files use.

| File | Source (fetched 2026-11-24) | License |
|---|---|---|
| `server.schema.2025-12-11.json` | https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json (MCP Registry `server.json`) | MIT / Apache-2.0 (modelcontextprotocol/registry) |
| `mcpb-manifest-v0.3.schema.json` | https://github.com/modelcontextprotocol/mcpb/blob/main/schemas/mcpb-manifest-v0.3.schema.json (MCPB manifest 0.3) | MIT / Apache-2.0 (modelcontextprotocol/mcpb) |
