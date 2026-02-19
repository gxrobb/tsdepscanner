# Changelog

All notable changes to this project are documented in this file.

## [0.1.0] - 2026-02-19

### Added
- Initial `secscan` monorepo scaffold with `@secscan/core` and `secscan` CLI packages.
- `secscan scan [path]` command with JSON/Markdown output, severity threshold exit codes, and offline mode.
- `package-lock.json` parser with direct/transitive dependency classification.
- OSV batch querying client with 24h cache support.
- Evidence collection from `.ts`, `.tsx`, and `.vue` imports/requires.
- Deterministic reporting and core unit/integration test coverage.
- Deterministic demo fixture at `examples/vulnerable-demo` with seeded offline OSV cache.

### Changed
- Root scripts switched to `corepack pnpm` execution to avoid nested `pnpm` shell dependency issues.
