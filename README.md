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
pnpm install
pnpm build
pnpm --filter secscan exec secscan scan . --format both --out-dir ./.secscan --fail-on high
```

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
      - run: pnpm install --frozen-lockfile
      - run: pnpm build
      - run: pnpm --filter secscan exec secscan scan . --format both --out-dir ./.secscan --fail-on high
```
