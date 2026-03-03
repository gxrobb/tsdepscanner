# Branch Protection Defaults

Apply these defaults to your protected branch (`main` or equivalent):

- Require pull request before merge.
- Require at least 1 approving review for major dependency updates.
- Require status checks to pass before merge.
- Require branches to be up to date before merge.
- Disable direct pushes except for admins/security maintainers.

Suggested required checks:

- `CI / validate`
- `Dependabot PR Policy / policy`
- `Dependency Monitor / monitor`
