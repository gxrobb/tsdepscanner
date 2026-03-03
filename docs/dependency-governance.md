# Dependency Governance Defaults

This document defines baseline governance for dependency automation rollouts.

## 1) Branch Protection Defaults

Apply these settings to `main` (or your default protected branch):

- Require pull requests before merge.
- Require status checks to pass before merge.
- Require branches to be up to date before merging.
- Require approval for major dependency updates.
- Restrict who can bypass pull request requirements.

Recommended required checks:

- `CI / validate`
- `Dependabot PR Policy / policy`
- `Dependency Monitor / monitor` (for scheduled/manual scans)

## 2) Alert Deduplication Defaults

Use one active threshold issue per repository to prevent daily issue spam.

Standard markers:

- issue marker: `<!-- bardscan-threshold-issue -->`
- dedup marker: `<!-- bardscan-dedup-key:<hash> -->`

Dedup key algorithm:

- Input: `repo + sorted(package@version:vulnId)` for findings at threshold.
- Output: SHA-256 hash (first 16 chars).
- Storage: issue body + metrics artifact (`.bardscan/remediation-metrics.json`).

Behavior:

- If a matching active issue exists, update it.
- If no active issue exists, create one.
- Keep the issue title stable: `[bardscan] Dependency security threshold breach`.

## 3) Remediation Metrics Defaults

Generated artifact: `.bardscan/remediation-metrics.json`

Default fields:

- `generatedAt`
- `repository`
- `runId`
- `thresholdHit`
- `findingsAtThreshold`
- `bySeverity`
- `directDependencyFindings`
- `transitiveDependencyFindings`
- `fixableFindings`
- `dedupKey`

Minimum reporting cadence:

- Daily scan metrics from scheduled workflow.
- Weekly rollup in your engineering/security channel.
- Monthly dependency hygiene review with trend snapshots.

## 4) Operational SLO Defaults

- High/critical findings: triage within 1 business day.
- Fixable high/critical findings: merged within 3 business days.
- Major upgrades: reviewed manually before merge.
- Patch/minor updates: auto-merge only after all required checks pass.

## 5) Rollout Order

1. Enable workflows in one pilot repo.
2. Validate signal quality for one week.
3. Enforce required checks.
4. Scale to additional repos using templates and reusable workflows.
