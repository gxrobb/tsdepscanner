import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { runScan } from '../src/scan.js';

test('runScan computes severity/confidence and deterministic summary counts', async () => {
  const projectDir = await mkdtemp(path.join(os.tmpdir(), 'secscan-project-'));
  const outDir = path.join(projectDir, '.secscan');
  await mkdir(path.join(projectDir, 'src'), { recursive: true });

  const lock = {
    lockfileVersion: 2,
    packages: {
      '': {},
      'node_modules/lodash': { version: '4.17.21' },
      'node_modules/chalk': { version: '5.0.0' },
      'node_modules/chalk/node_modules/ansi-styles': { version: '6.2.1' }
    }
  };

  await writeFile(path.join(projectDir, 'package-lock.json'), JSON.stringify(lock));
  await writeFile(
    path.join(projectDir, 'src', 'main.ts'),
    "import lodash from 'lodash';\nimport 'ansi-styles';\nconsole.log(lodash);\n"
  );

  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async () =>
    ({
      ok: true,
      json: async () => ({
        results: [
          {
            vulns: [
              {
                id: 'OSV-LODASH',
                summary: 'Lodash issue',
                severity: [{ type: 'CVSS_V3', score: '9.8' }]
              }
            ]
          },
          { vulns: [] },
          {
            vulns: [
              {
                id: 'OSV-ANSI',
                summary: 'Ansi issue',
                database_specific: { severity: 'medium' }
              }
            ]
          }
        ]
      })
    }) as Response) as typeof fetch;

  try {
    const report = await runScan({
      projectPath: projectDir,
      outDir,
      failOn: 'high',
      offline: false
    });

    assert.equal(report.summary.dependencyCount, 3);
    assert.equal(report.summary.scannedFiles, 1);
    assert.equal(report.summary.findingsCount, 2);
    assert.deepEqual(report.summary.bySeverity, {
      critical: 1,
      high: 0,
      medium: 1,
      low: 0,
      unknown: 0
    });
    assert.deepEqual(report.summary.byConfidence, {
      high: 1,
      medium: 0,
      low: 1,
      unknown: 0
    });

    assert.equal(report.findings[0]?.packageName, 'lodash');
    assert.equal(report.findings[0]?.severity, 'critical');
    assert.equal(report.findings[0]?.confidence, 'high');
    assert.equal(report.findings[1]?.packageName, 'ansi-styles');
    assert.equal(report.findings[1]?.severity, 'medium');
    assert.equal(report.findings[1]?.confidence, 'low');
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('runScan marks offline missing cache entries as unknown findings', async () => {
  const projectDir = await mkdtemp(path.join(os.tmpdir(), 'secscan-offline-'));
  const outDir = path.join(projectDir, '.secscan');

  const lock = {
    lockfileVersion: 2,
    packages: {
      '': {},
      'node_modules/lodash': { version: '4.17.21' },
      'node_modules/chalk': { version: '5.0.0' }
    }
  };

  await writeFile(path.join(projectDir, 'package-lock.json'), JSON.stringify(lock));

  const report = await runScan({
    projectPath: projectDir,
    outDir,
    failOn: 'high',
    offline: true
  });

  assert.equal(report.summary.findingsCount, 2);
  assert.deepEqual(report.summary.bySeverity, {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    unknown: 2
  });
  assert.equal(report.findings.every((f) => f.source === 'unknown'), true);
  assert.equal(report.findings.every((f) => f.confidence === 'unknown'), true);
});
