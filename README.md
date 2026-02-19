# secscan

`secscan` is a TypeScript-focused dependency vulnerability scanner for npm projects.

## Features (v1)

- Node 20+ / TypeScript / pnpm workspace monorepo
- Parses `package-lock.json` only
- Queries vulnerabilities via OSV.dev batch API
- Collects import evidence from `.ts`, `.tsx`, and `.vue`
- Produces deterministic JSON and Markdown reports
- CI-friendly severity threshold exit codes

## Quickstart

```bash
corepack pnpm install
corepack pnpm build
node ./packages/cli/dist/index.js scan . --format both --out-dir ./.secscan --fail-on high
```

## Testing

```bash
corepack pnpm test
```

Coverage includes:
- lockfile parsing (direct/transitive and scoped packages)
- deterministic finding sort order
- OSV fallback/cache behavior and severity mapping
- evidence collection from `.ts`/`.tsx`/`.vue`
- scan orchestration confidence/severity outcomes
- CLI output format and exit code behavior

## Demo Project

There is a ready-to-scan example project at:

`examples/vulnerable-demo`

It pins older package versions that have known historical advisories, so it is useful for demos. Advisory severity can change over time as OSV data is updated.

Run the demo scan:

```bash
corepack pnpm build
corepack pnpm demo:scan
```

Or run directly:

```bash
node ./packages/cli/dist/index.js scan ./examples/vulnerable-demo --format both --out-dir ./examples/vulnerable-demo/.secscan --fail-on none --offline
```

The demo is deterministic in offline mode because cache fixtures are committed under:
`examples/vulnerable-demo/.secscan/.cache/osv`

## CLI

```bash
secscan scan [path]
```

Flags:

- `--format json|md|both` (default: `both`)
- `--out-dir <dir>` (default: `./.secscan`)
- `--fail-on critical|high|medium|low|none` (default: `high`)
- `--offline` (cache only; missing entries become unknown)

Exit codes:

- `0`: no findings at/above threshold
- `1`: findings at/above threshold
- `2`: tool error

## Cache

OSV responses are cached at:

```text
<out-dir>/.cache/osv
```

Cache TTL is 24h.

When online OSV calls fail or time out, secscan continues and marks affected entries as `unknown` rather than crashing (exit code behavior still applies).

## GitHub Actions example

```yaml
name: secscan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'pnpm'
      - run: corepack pnpm install
      - run: corepack pnpm build
      - run: node ./packages/cli/dist/index.js scan . --format both --out-dir ./.secscan --fail-on high

## Release

1. Run `corepack pnpm install`
2. Run `corepack pnpm lint && corepack pnpm test && corepack pnpm build`
3. Run `corepack pnpm release:dry-run`
4. Commit release notes in `CHANGELOG.md`
5. Tag `v0.1.0` and push tag
```
