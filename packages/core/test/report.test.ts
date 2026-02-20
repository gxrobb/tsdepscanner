import test from 'node:test';
import assert from 'node:assert/strict';
import { buildMarkdownReport, buildSarifReport } from '../src/report.js';
import { ScanReport } from '../src/types.js';

test('buildMarkdownReport renders empty findings message', () => {
  const report: ScanReport = {
    targetPath: '/tmp/project',
    generatedAt: '2026-02-19T00:00:00.000Z',
    failOn: 'high',
    summary: {
      dependencyCount: 3,
      scannedFiles: 2,
      findingsCount: 0,
      bySeverity: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 },
      byConfidence: { high: 0, medium: 0, low: 0, unknown: 0 }
    },
    findings: []
  };

  const markdown = buildMarkdownReport(report);
  assert.match(markdown, /# bardcheck summary/);
  assert.match(markdown, /No vulnerable dependencies found\./);
});

test('buildMarkdownReport renders vulnerabilities and evidence lines', () => {
  const report: ScanReport = {
    targetPath: '/tmp/project',
    generatedAt: '2026-02-19T00:00:00.000Z',
    failOn: 'high',
    summary: {
      dependencyCount: 3,
      scannedFiles: 2,
      findingsCount: 1,
      bySeverity: { critical: 0, high: 1, medium: 0, low: 0, unknown: 0 },
      byConfidence: { high: 1, medium: 0, low: 0, unknown: 0 }
    },
    findings: [
      {
        packageName: 'lodash',
        version: '4.17.21',
        direct: true,
        severity: 'high',
        severitySource: 'osv_label',
        confidence: 'high',
        source: 'osv',
        vulnerabilities: [
          {
            id: 'OSV-123',
            severity: 'high',
            severitySource: 'osv_label',
            summary: 'Prototype pollution',
            fixedVersion: '4.17.22',
            references: ['https://example.com/advisory']
          }
        ],
        evidence: ['src/main.ts']
      }
    ]
  };

  const markdown = buildMarkdownReport(report);
  assert.match(markdown, /\*\*lodash@4\.17\.21\*\*/);
  assert.match(markdown, /severity: high \(osv_label\)/);
  assert.match(markdown, /\[OSV-123\]\(https:\/\/osv.dev\/vulnerability\/OSV-123\): Prototype pollution/);
  assert.match(markdown, /remediation: upgrade to lodash@4.17.22 or later/);
  assert.match(markdown, /references: https:\/\/example.com\/advisory/);
  assert.match(markdown, /evidence: src\/main\.ts/);
});

test('buildSarifReport emits a SARIF run with rules and results', () => {
  const report: ScanReport = {
    targetPath: '/tmp/project',
    generatedAt: '2026-02-19T00:00:00.000Z',
    failOn: 'high',
    summary: {
      dependencyCount: 1,
      scannedFiles: 1,
      findingsCount: 1,
      bySeverity: { critical: 0, high: 1, medium: 0, low: 0, unknown: 0 },
      byConfidence: { high: 1, medium: 0, low: 0, unknown: 0 }
    },
    findings: [
      {
        packageName: 'lodash',
        version: '4.17.21',
        direct: true,
        severity: 'high',
        severitySource: 'osv_label',
        confidence: 'high',
        source: 'osv',
        evidence: ['src/main.ts'],
        vulnerabilities: [{ id: 'GHSA-1234-5678-9abc', severity: 'high', severitySource: 'ghsa_label' }]
      }
    ]
  };

  const sarif = buildSarifReport(report) as { runs: Array<{ results: unknown[]; tool: { driver: { rules: unknown[] } } }> };
  assert.equal(Array.isArray(sarif.runs), true);
  assert.equal(sarif.runs[0]?.results.length, 1);
  assert.equal(sarif.runs[0]?.tool.driver.rules.length, 1);
});
