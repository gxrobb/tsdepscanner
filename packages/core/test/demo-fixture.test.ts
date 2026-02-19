import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { runScan } from '../src/scan.js';

const thisDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(thisDir, '../../..');
const demoPath = path.join(repoRoot, 'examples', 'vulnerable-demo');
const demoOutDir = path.join(demoPath, '.secscan');

test('demo fixture produces deterministic offline findings from seeded cache', async () => {
  const report = await runScan({
    projectPath: demoPath,
    outDir: demoOutDir,
    failOn: 'low',
    offline: true
  });

  assert.equal(report.summary.dependencyCount, 2);
  assert.equal(report.summary.scannedFiles, 1);
  assert.equal(report.summary.findingsCount, 2);
  assert.deepEqual(report.summary.bySeverity, {
    critical: 0,
    high: 0,
    medium: 1,
    low: 1,
    unknown: 0
  });
  assert.deepEqual(report.summary.byConfidence, {
    high: 2,
    medium: 0,
    low: 0,
    unknown: 0
  });

  assert.equal(report.findings[0]?.packageName, 'lodash');
  assert.equal(report.findings[0]?.severity, 'medium');
  assert.equal(report.findings[0]?.source, 'cache');
  assert.equal(report.findings[1]?.packageName, 'node-forge');
  assert.equal(report.findings[1]?.severity, 'low');
  assert.equal(report.findings[1]?.source, 'cache');
});
