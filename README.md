# bardscan

`bardscan` is a TypeScript-focused dependency vulnerability scanner for JavaScript/TypeScript projects.

## Security Model

`bardscan` is secure-by-default:

- `scan` is offline by default (no network)
- `scan` is offline-only; advisory fetching happens via `db update`
- advisory refresh is split into a dedicated command (`db update`)
- strict privacy mode is the default (`--privacy strict`)

## Features

- Parses `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, and Bun lockfiles (`bun.lock` / `bun.lockb`)
- OSV advisory lookups with local caching
- Optional fallback severity enrichment (OSV detail, CVE/NVD, GHSA)
- Optional import evidence extraction
- JSON / Markdown / SARIF output
- Severity-based CI exit codes

## Quickstart

```bash
corepack pnpm install
corepack pnpm build

# 1) refresh advisory cache (network)
node ./packages/cli/dist/index.js db update .

# 2) scan using cache only (default behavior)
node ./packages/cli/dist/index.js scan . --format both

# optional one-command convenience (update + offline scan)
node ./packages/cli/dist/index.js scan . --update-db --format both
```

Package-run examples:

```bash
npx bardscan scan .
pnpm dlx bardscan scan .
bunx bardscan scan .
```

## CLI

### `bardscan scan [path]`

Defaults:

- `--privacy strict`
- offline scan (`--online` is not enabled)
- output directory: `/tmp/bardscan`

Flags:

- `--format json|md|sarif|both` (default: `both`)
- `--out-dir <dir>` (default: `/tmp/bardscan`)
- `--fail-on critical|high|medium|low|none` (default: `high`)
- `--fail-on-unknown` (default: `false`; fail when unresolved findings exist)
- `--privacy strict|standard` (default: `strict`)
- `--online` (deprecated; scan is offline-only and will error)
- `--offline` (force cache-only scanning)
- `--unknown-as critical|high|medium|low|unknown` (default: `unknown`)
- `--refresh-cache` (bypass cache reads)
- `--update-db` (run `db update` before scan)
- `--osv-url <url>` (custom OSV API base URL)
- `--fallback-calls` (allow extra network lookups for unresolved severities)
- `--redact-paths` (redact target/evidence paths in report outputs)
- `--evidence none|imports`
- `--telemetry off|on` (strict mode rejects `on`)
- `--list-findings none|critical-high|medium-up|all` (default: `none`)
- `--findings-json <path>`

### `bardscan db update [path]`

Refreshes advisory cache using the lockfile dependency set.

Flags:

- `--out-dir <dir>` (default: `/tmp/bardscan`)
- `--refresh-cache`
- `--osv-url <url>`
- `--fallback-calls`

## Privacy Presets

- `strict` (default): offline, no fallback calls, path redaction on, evidence defaults to `none`, telemetry must be off
- `standard`: offline by default, fallback calls enabled by default, path redaction off, evidence defaults to `imports`

To refresh advisory freshness:

```bash
bardscan db update .
bardscan scan .
```

## Data Handling

### Read locally

- lockfiles (`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock`, `bun.lockb`)
- source files only when `--evidence imports` is enabled

### Sent over network (only when online/update enabled)

- package name
- package version
- ecosystem (`npm`)
- optional advisory IDs for detail/fallback lookups

### Not sent

- source code contents
- full lockfile contents
- absolute project paths
- local file contents outside advisory query metadata

### Example outbound OSV payload

```json
{
  "queries": [
    {
      "package": { "name": "lodash", "ecosystem": "npm" },
      "version": "4.17.19"
    }
  ]
}
```

### Cache/retention

- cache location: `<out-dir>/.cache/osv`
- TTL: 24h

## Exit Codes

- `0`: no findings at/above threshold
- `1`: findings at/above threshold
- `2`: tool error

## Testing

```bash
corepack pnpm test
```

## Demo Project

Demo fixture: `examples/vulnerable-demo`

Deterministic offline demo cache: `examples/vulnerable-demo/.bardscan/.cache/osv`

```bash
corepack pnpm demo:scan
```
