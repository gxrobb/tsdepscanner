import test from 'node:test';
import assert from 'node:assert/strict';
import { buildMarkdownReport } from '../src/report.js';
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
  assert.match(markdown, /# secscan summary/);
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
        vulnerabilities: [{ id: 'OSV-123', severity: 'high', severitySource: 'osv_label', summary: 'Prototype pollution' }],
        evidence: ['src/main.ts']
      }
    ]
  };

  const markdown = buildMarkdownReport(report);
  assert.match(markdown, /\*\*lodash@4\.17\.21\*\*/);
  assert.match(markdown, /severity: high \(osv_label\)/);
  assert.match(markdown, /OSV-123: Prototype pollution/);
  assert.match(markdown, /evidence: src\/main\.ts/);
});
