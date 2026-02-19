import test from 'node:test';
import assert from 'node:assert/strict';
import { sortFindings } from '../src/report.js';
import { Finding } from '../src/types.js';

test('sortFindings is stable and deterministic', () => {
  const findings: Finding[] = [
    {
      packageName: 'b',
      version: '1.0.0',
      direct: true,
      severity: 'medium',
      confidence: 'medium',
      evidence: [],
      vulnerabilities: [{ id: 'OSV-1', severity: 'medium' }],
      source: 'osv'
    },
    {
      packageName: 'a',
      version: '1.0.0',
      direct: true,
      severity: 'high',
      confidence: 'medium',
      evidence: [],
      vulnerabilities: [{ id: 'OSV-2', severity: 'high' }],
      source: 'osv'
    }
  ];

  const out = sortFindings(findings);
  assert.equal(out[0]?.packageName, 'a');
  assert.equal(out[1]?.packageName, 'b');
});
