import assert from 'node:assert/strict';
import { mkdtemp } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { runScan } from '../src/scan.js';

const thisDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(thisDir, '../../..');

const fixtures = [
  { name: 'npm', projectPath: path.join(repoRoot, 'examples', 'npm-demo') },
  { name: 'yarn', projectPath: path.join(repoRoot, 'examples', 'yarn-demo') },
  { name: 'pnpm', projectPath: path.join(repoRoot, 'examples', 'pnpm-demo') },
  { name: 'bun', projectPath: path.join(repoRoot, 'examples', 'bun-demo') }
];

for (const fixture of fixtures) {
  test(`runScan supports ${fixture.name} fixture project`, async () => {
    const outDir = await mkdtemp(path.join(os.tmpdir(), `bardcheck-${fixture.name}-`));
    const report = await runScan({
      projectPath: fixture.projectPath,
      outDir,
      failOn: 'none',
      offline: true,
      unknownAs: 'unknown',
      refreshCache: false
    });

    assert.ok(report.summary.dependencyCount > 0);
    assert.equal(report.summary.findingsCount, report.summary.dependencyCount);
    assert.equal(report.findings.every((f) => f.severity === 'unknown'), true);
  });
}
