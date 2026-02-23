# Changelog

All notable changes to this project are documented in this file.

## [0.1.0] - 2026-02-19

### Added
- Initial `bardscan` monorepo scaffold with `@bardscan/core` and `bardscan` CLI packages.
- `bardscan scan [path]` command with JSON/Markdown output, severity threshold exit codes, and offline mode.
- `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, and Bun lockfile support with best-effort direct/transitive classification.
- OSV batch querying client with 24h cache support.
- Evidence collection from `.ts`, `.tsx`, `.js`, `.jsx`, `.mjs`, `.cjs`, and `.vue` imports/requires.
- Deterministic JSON/Markdown reports and SARIF output.
- Deterministic demo/fixture coverage for npm, yarn, pnpm, and bun lockfile managers.
- Colorized CLI summary output with severity/confidence breakdown.
- Deterministic demo fixture at `examples/vulnerable-demo` with seeded offline OSV cache.

### Changed
- Root scripts switched to `corepack pnpm` execution to avoid nested `pnpm` shell dependency issues.
- CI hardened for clean-run conditions by tracking root `pnpm-lock.yaml`, using portable test globs, and building `@bardscan/core` before CLI tests.
