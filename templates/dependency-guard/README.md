# Dependency Guard Template

Use this template to bootstrap dependency scanning and auto-remediation in a new repository.

## Files

- `dependabot.yml`: daily Dependabot update policy with grouped updates.
- `dependency-guard-workflow.yml`: daily + PR workflow that calls reusable bardscan workflow.
- `branch-protection-defaults.md`: required checks and protection defaults.

## Setup

1. Copy `dependabot.yml` to `.github/dependabot.yml`.
2. Copy `dependency-guard-workflow.yml` to `.github/workflows/dependency-guard.yml`.
3. Replace `your-org/your-repo` with your reusable-workflow repository.
4. Ensure your repo contains `scripts/bardscan-ci.sh` and `bardscan` is available.
5. Add branch protection rules so dependency checks are required before merge.

## Optional

- Add `.github/workflows/dependabot-pr-policy.yml` to auto-label and auto-merge safe patch/minor PRs.
- Add scheduled notification workflow for issue creation when thresholds are breached.
