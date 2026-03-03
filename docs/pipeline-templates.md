# Pipeline Templates

This playbook standardizes dependency security checks across CI systems using `scripts/bardscan-ci.sh`.

## Runner Contract

Run from repository root:

```bash
./scripts/bardscan-ci.sh
```

Environment variables:

- `PROJECT_PATH` (default: `.`)
- `OUT_DIR` (default: `.bardscan`)
- `FAIL_ON` (default: `high`)
- `FAIL_ON_UNKNOWN` (default: `true`)
- `UPDATE_DB` (default: `true`)
- `FALLBACK_CALLS` (default: `true`)
- `LIST_FINDINGS` (default: `medium-up`)
- `PRIVACY` (default: `strict`)
- `EVIDENCE` (default: `none`)
- `BARDSCAN_BIN` (optional override for CLI command)

Exit behavior:

- `0`: no findings at threshold
- `1`: findings at/above threshold
- `2`: tool/runtime error

Stable artifacts:

- `${OUT_DIR}/report.json`
- `${OUT_DIR}/report.md`
- `${OUT_DIR}/report.sarif`
- `${OUT_DIR}/findings.json`
- `${OUT_DIR}/findings-threshold.json`
- `${OUT_DIR}/ci-summary.json`

---

## GitHub Actions

```yaml
name: Dependency Guard

on:
  pull_request:
  schedule:
    - cron: "17 4 * * *"
  workflow_dispatch:

permissions:
  contents: read
  security-events: write

jobs:
  bardscan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v4
      - uses: actions/setup-node@v4
        with:
          node-version: "20"
          cache: "pnpm"
      - run: corepack pnpm install
      - run: corepack pnpm build
      - name: Run bardscan runner
        run: ./scripts/bardscan-ci.sh
        env:
          FAIL_ON: high
          FAIL_ON_UNKNOWN: "true"
          LIST_FINDINGS: medium-up
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: bardscan-${{ github.run_id }}
          path: ./.bardscan
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: ./.bardscan/report.sarif
          category: bardscan
```

---

## GitLab CI

```yaml
stages:
  - dependency-security

dependency_security:
  stage: dependency-security
  image: node:20
  variables:
    FAIL_ON: "high"
    FAIL_ON_UNKNOWN: "true"
    LIST_FINDINGS: "medium-up"
    OUT_DIR: ".bardscan"
  before_script:
    - corepack enable
    - corepack prepare pnpm@9.0.0 --activate
    - pnpm install
    - pnpm build
  script:
    - ./scripts/bardscan-ci.sh
  artifacts:
    when: always
    paths:
      - .bardscan/
    expire_in: 14 days
```

---

## Jenkins (Declarative Pipeline)

```groovy
pipeline {
  agent any
  environment {
    FAIL_ON = "high"
    FAIL_ON_UNKNOWN = "true"
    LIST_FINDINGS = "medium-up"
    OUT_DIR = ".bardscan"
  }
  stages {
    stage('Checkout') {
      steps {
        checkout scm
      }
    }
    stage('Install') {
      steps {
        sh 'corepack pnpm install'
      }
    }
    stage('Build') {
      steps {
        sh 'corepack pnpm build'
      }
    }
    stage('Dependency Security') {
      steps {
        sh './scripts/bardscan-ci.sh'
      }
    }
  }
  post {
    always {
      archiveArtifacts artifacts: '.bardscan/**', allowEmptyArchive: true
    }
  }
}
```

---

## CircleCI

```yaml
version: 2.1

jobs:
  dependency_guard:
    docker:
      - image: cimg/node:20.11
    environment:
      FAIL_ON: "high"
      FAIL_ON_UNKNOWN: "true"
      LIST_FINDINGS: "medium-up"
      OUT_DIR: ".bardscan"
    steps:
      - checkout
      - run: corepack pnpm install
      - run: corepack pnpm build
      - run: ./scripts/bardscan-ci.sh
      - store_artifacts:
          path: .bardscan
          destination: bardscan

workflows:
  dependency_guard:
    jobs:
      - dependency_guard
```

---

## Azure Pipelines

```yaml
trigger:
  branches:
    include:
      - main

schedules:
  - cron: "17 4 * * *"
    displayName: Daily dependency scan
    branches:
      include:
        - main
    always: true

pool:
  vmImage: "ubuntu-latest"

variables:
  FAIL_ON: "high"
  FAIL_ON_UNKNOWN: "true"
  LIST_FINDINGS: "medium-up"
  OUT_DIR: ".bardscan"

steps:
  - checkout: self
  - task: NodeTool@0
    inputs:
      versionSpec: "20.x"
  - script: corepack pnpm install
    displayName: Install dependencies
  - script: corepack pnpm build
    displayName: Build packages
  - script: ./scripts/bardscan-ci.sh
    displayName: Run dependency guard
  - task: PublishBuildArtifacts@1
    condition: always()
    inputs:
      PathtoPublish: ".bardscan"
      ArtifactName: "bardscan"
```

---

## Rollout Guidance

- Keep `FAIL_ON=high` at first for manageable signal.
- Enable daily schedule before enforcing required status checks.
- Upload SARIF where supported so results appear in native security dashboards.
- Start with one pilot repository, then scale via shared templates/reusable workflows.
