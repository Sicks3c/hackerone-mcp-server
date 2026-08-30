# hackerone-mcp-server

## Conventions

- **Version bump on every update**: whenever the server code is modified, bump the version in BOTH places and keep them in sync:
  - `package.json` → `"version"`
  - `src/index.ts` → `new McpServer({ version: ... })`
- After any source change, run `npm run build` so `dist/` stays in sync (the MCP client runs `dist/index.js`).
