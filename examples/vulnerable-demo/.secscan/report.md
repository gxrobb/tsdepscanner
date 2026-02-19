# secscan summary

- Target: /Users/solinarmac/Documents/dev/depscanner/tsdepscanner/examples/vulnerable-demo
- Generated: 2026-02-19T23:41:58.903Z
- Dependencies: 2
- Findings: 2

## Findings

- **lodash@4.17.19** | severity: medium | confidence: high | direct: true
  - GHSA-35jh-r3h4-6jhm: Command injection in lodash template helper
  - evidence: src/index.ts
- **node-forge@0.9.0** | severity: low | confidence: high | direct: true
  - GHSA-5rrq-pxf6-6jx5: Prototype pollution in node-forge util.setPath
  - evidence: src/index.ts