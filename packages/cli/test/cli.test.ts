import assert from 'node:assert/strict';
import { mkdtemp } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { CliDeps, runCli } from '../src/index.js';

function makeReport(severity: 'critical' | 'high' | 'medium' | 'low' | 'unknown') {
  return {
    targetPath: '/tmp/project',
    generatedAt: '2026-02-19T00:00:00.000Z',
    failOn: 'high',
    summary: {
      dependencyCount: 1,
      scannedFiles: 1,
      findingsCount: 1,
      bySeverity: {
        critical: severity === 'critical' ? 1 : 0,
        high: severity === 'high' ? 1 : 0,
        medium: severity === 'medium' ? 1 : 0,
        low: severity === 'low' ? 1 : 0,
        unknown: severity === 'unknown' ? 1 : 0
      },
      byConfidence: { high: 1, medium: 0, low: 0, unknown: 0 }
    },
    findings: [
      {
        packageName: 'lodash',
        version: '4.17.21',
        direct: true,
        severity,
        severitySource: 'osv_label',
        confidence: 'high',
        evidence: ['src/index.ts'],
        vulnerabilities: [{ id: 'OSV-1', severity, severitySource: 'osv_label' }],
        source: 'osv'
      }
    ]
  };
}

test('runCli writes only JSON report and returns exit code 1 on threshold match', async () => {
  const outDir = await mkdtemp(path.join(os.tmpdir(), 'bardcheck-cli-json-'));
  const writes: string[] = [];
  const stdout: string[] = [];
  const stderr: string[] = [];
  const deps: CliDeps = {
    mkdir: async () => undefined,
    writeFile: async (filePath) => {
      writes.push(String(filePath));
    },
    runScan: async () => makeReport('high'),
    buildMarkdownReport: () => '# report',
    buildSarifReport: () => ({ version: '2.1.0', runs: [] }),
    shouldFail: (failOn, findingSeverity) => failOn === findingSeverity,
    stdout: { write: (text: string) => stdout.push(text) },
    stderr: { write: (text: string) => stderr.push(text) }
  };

  const code = await runCli(['scan', '.', '--format', 'json', '--out-dir', outDir, '--fail-on', 'high'], deps);

  assert.equal(code, 1);
  assert.equal(stderr.length, 0);
  assert.equal(writes.length, 1);
  assert.equal(writes[0], path.resolve(outDir, 'report.json'));
  assert.match(stdout.join(''), /report\.json/);
  assert.doesNotMatch(stdout.join(''), /report\.md/);
  assert.match(stdout.join(''), /bardcheck summary/);
  assert.match(stdout.join(''), /threshold hit: yes/);
});

test('runCli writes only Markdown report and returns exit code 0 for fail-on none', async () => {
  const outDir = await mkdtemp(path.join(os.tmpdir(), 'bardcheck-cli-md-'));
  const writes: string[] = [];
  const stdout: string[] = [];
  const deps: CliDeps = {
    mkdir: async () => undefined,
    writeFile: async (filePath) => {
      writes.push(String(filePath));
    },
    runScan: async () => makeReport('critical'),
    buildMarkdownReport: () => '# markdown-report',
    buildSarifReport: () => ({ version: '2.1.0', runs: [] }),
    shouldFail: () => true,
    stdout: { write: (text: string) => stdout.push(text) },
    stderr: { write: () => undefined }
  };

  const code = await runCli(['scan', '.', '--format', 'md', '--out-dir', outDir, '--fail-on', 'none'], deps);

  assert.equal(code, 0);
  assert.equal(writes.length, 1);
  assert.equal(writes[0], path.resolve(outDir, 'report.md'));
  assert.match(stdout.join(''), /report\.md/);
  assert.doesNotMatch(stdout.join(''), /report\.json/);
  assert.match(stdout.join(''), /bardcheck summary/);
  assert.match(stdout.join(''), /threshold hit: no/);
});

test('runCli returns exit code 2 and writes to stderr on tool errors', async () => {
  const outDir = await mkdtemp(path.join(os.tmpdir(), 'bardcheck-cli-err-'));
  const stderr: string[] = [];
  const deps: CliDeps = {
    mkdir: async () => undefined,
    writeFile: async () => undefined,
    runScan: async () => {
      throw new Error('boom');
    },
    buildMarkdownReport: () => '# report',
    buildSarifReport: () => ({ version: '2.1.0', runs: [] }),
    shouldFail: () => false,
    stdout: { write: () => undefined },
    stderr: { write: (text: string) => stderr.push(text) }
  };

  const code = await runCli(['scan', '.', '--format', 'both', '--out-dir', outDir], deps);

  assert.equal(code, 2);
  assert.match(stderr.join(''), /boom/);
});

test('runCli writes SARIF report when format is sarif', async () => {
  const outDir = await mkdtemp(path.join(os.tmpdir(), 'bardcheck-cli-sarif-'));
  const writes: string[] = [];
  const deps: CliDeps = {
    mkdir: async () => undefined,
    writeFile: async (filePath) => {
      writes.push(String(filePath));
    },
    runScan: async () => makeReport('medium'),
    buildMarkdownReport: () => '# report',
    buildSarifReport: () => ({ version: '2.1.0', runs: [{ tool: { driver: { name: 'bardcheck' } }, results: [] }] }),
    shouldFail: () => false,
    stdout: { write: () => undefined },
    stderr: { write: () => undefined }
  };

  const code = await runCli(['scan', '.', '--format', 'sarif', '--out-dir', outDir, '--fail-on', 'none'], deps);
  assert.equal(code, 0);
  assert.equal(writes.length, 1);
  assert.equal(writes[0], path.resolve(outDir, 'report.sarif'));
});

test('runCli colorizes summary output when stdout is a TTY', async () => {
  const outDir = await mkdtemp(path.join(os.tmpdir(), 'bardcheck-cli-color-'));
  const stdout: string[] = [];
  const previousNoColor = process.env.NO_COLOR;
  delete process.env.NO_COLOR;
  const deps: CliDeps = {
    mkdir: async () => undefined,
    writeFile: async () => undefined,
    runScan: async () => makeReport('high'),
    buildMarkdownReport: () => '# report',
    buildSarifReport: () => ({ version: '2.1.0', runs: [] }),
    shouldFail: (failOn, findingSeverity) => failOn === findingSeverity,
    stdout: { write: (text: string) => stdout.push(text), isTTY: true },
    stderr: { write: () => undefined }
  };

  try {
    const code = await runCli(['scan', '.', '--format', 'json', '--out-dir', outDir, '--fail-on', 'high'], deps);
    assert.equal(code, 1);
    const output = stdout.join('');
    assert.equal(output.includes('\u001b[36mbardcheck summary\u001b[0m'), true);
    assert.equal(output.includes('\u001b[31myes\u001b[0m'), true);
  } finally {
    if (previousNoColor === undefined) {
      delete process.env.NO_COLOR;
    } else {
      process.env.NO_COLOR = previousNoColor;
    }
  }
});
