# bardcheck

`bardcheck` is a TypeScript-focused dependency vulnerability scanner for JavaScript/TypeScript projects, including React and Next.js codebases.

## Features (v1)

- Node 20+ / TypeScript / pnpm workspace monorepo
- Parses `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, and Bun lockfiles (`bun.lock` / `bun.lockb`) with best-effort dependency resolution
- Queries vulnerabilities via OSV.dev batch API
- Enriches missing OSV severities with OSV advisory detail and CVE alias CVSS fallback (NVD), when available
- Adds GHSA severity fallback and marks source/reason for unresolved severities
- Collects import evidence from `.ts`, `.tsx`, `.js`, `.jsx`, `.mjs`, `.cjs`, and `.vue`
- Produces deterministic JSON and Markdown reports
- Produces SARIF output for code-scanning integrations
- CI-friendly severity threshold exit codes

## Quickstart

```bash
corepack pnpm install
corepack pnpm build
node ./packages/cli/dist/index.js scan . --format both --out-dir ./.bardcheck --fail-on high
```

Run without local install:

```bash
npx bardcheck scan .
pnpm dlx bardcheck scan .
bunx bardcheck scan .
```

## Testing

```bash
corepack pnpm test
```

Coverage includes:
- lockfile parsing (direct/transitive and scoped packages)
- deterministic finding sort order
- OSV fallback/cache behavior and severity mapping
- evidence collection from TS/JS/Vue files (including React/Next.js style imports)
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
node ./packages/cli/dist/index.js scan ./examples/vulnerable-demo --format both --out-dir ./examples/vulnerable-demo/.bardcheck --fail-on none --offline
```

The demo is deterministic in offline mode because cache fixtures are committed under:
`examples/vulnerable-demo/.bardcheck/.cache/osv`

## Lockfile Examples

The repository also includes one example per lockfile type:

- npm: `examples/npm-demo` (`package-lock.json`)
- Yarn: `examples/yarn-demo` (`yarn.lock`)
- pnpm: `examples/pnpm-demo` (`pnpm-lock.yaml`)
- Bun: `examples/bun-demo` (`bun.lock`)

Run scans against each:

```bash
node ./packages/cli/dist/index.js scan ./examples/npm-demo --format both --out-dir ./examples/npm-demo/.bardcheck --fail-on none
node ./packages/cli/dist/index.js scan ./examples/yarn-demo --format both --out-dir ./examples/yarn-demo/.bardcheck --fail-on none
node ./packages/cli/dist/index.js scan ./examples/pnpm-demo --format both --out-dir ./examples/pnpm-demo/.bardcheck --fail-on none
node ./packages/cli/dist/index.js scan ./examples/bun-demo --format both --out-dir ./examples/bun-demo/.bardcheck --fail-on none
```

## CLI

```bash
bardcheck scan [path]
```

Flags:

- `--format json|md|sarif|both` (default: `both`)
- `--out-dir <dir>` (default: `./.bardcheck`)
- `--fail-on critical|high|medium|low|none` (default: `high`)
- `--offline` (cache only; missing entries become unknown)
- `--unknown-as critical|high|medium|low|unknown` (default: `unknown`)
- `--refresh-cache` (ignore cached advisory data and refetch)
- `--list-findings none|critical-high|medium-up|all` (default: `none`; prints finding details in terminal)
- `--findings-json <path>` (write filtered findings list as JSON, using current `--list-findings` mode)

Exit codes:

- `0`: no findings at/above threshold
- `1`: findings at/above threshold
- `2`: tool error

Examples:

```bash
# Print only critical/high finding details in CLI output
bardcheck scan . --list-findings critical-high

# Print medium/high/critical finding details in CLI output
bardcheck scan . --list-findings medium-up

# Print all finding details in CLI output
bardcheck scan . --list-findings all

# Write machine-friendly filtered findings JSON
bardcheck scan . --list-findings critical-high --findings-json ./.bardcheck/findings.critical-high.json
```

Real project triage example:

```bash
bardcheck scan /Users/solinarmac/Documents/dev/portfolio \
  --format both \
  --out-dir /tmp/bardcheck-portfolio \
  --fail-on none \
  --list-findings critical-high \
  --findings-json /tmp/bardcheck-portfolio/findings.critical-high.json
```

## Cache

OSV responses are cached at:

```text
<out-dir>/.cache/osv
```

Cache TTL is 24h.

When online OSV calls fail or time out, bardcheck continues and marks affected entries as `unknown` rather than crashing (exit code behavior still applies).

## GitHub Actions example

```yaml
name: bardcheck
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
      - run: node ./packages/cli/dist/index.js scan . --format both --out-dir ./.bardcheck --fail-on high
```

## Release

1. Run `corepack pnpm install`
2. Run `corepack pnpm lint && corepack pnpm test && corepack pnpm build`
3. Run `corepack pnpm release:dry-run`
4. Commit release notes in `CHANGELOG.md`
5. Tag `v0.1.0` and push tag

### Automated release on `main`

`/Users/solinarmac/Documents/dev/depscanner/tsdepscanner/.github/workflows/release.yml` is configured to:
- run on pushes to `main`
- bump `packages/cli/package.json` patch version
- commit the bump, create a `vX.Y.Z` tag, push both
- publish `bardcheck` to npm

Required repository secret:
- `NPM_TOKEN`: npm automation token with publish access to `bardcheck`
```
