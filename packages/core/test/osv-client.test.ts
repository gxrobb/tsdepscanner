import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { mkdtemp } from 'node:fs/promises';
import { OsvClient } from '../src/osv-client.js';

test('OsvClient returns unknown results when online query fails', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'secscan-cache-'));
  const client = new OsvClient(dir, false);

  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async () => {
    throw new Error('network down');
  }) as typeof fetch;

  try {
    const result = await client.batchQuery([{ name: 'lodash', version: '4.17.21' }]);
    const finding = result.get('lodash@4.17.21');
    assert.equal(finding?.source, 'unknown');
    assert.deepEqual(finding?.vulnerabilities, []);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('OsvClient maps severities and then serves cached entries without network', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'secscan-cache-'));
  const client = new OsvClient(dir, false);
  const pkgs = [
    { name: 'critical-pkg', version: '1.0.0' },
    { name: 'high-pkg', version: '1.0.0' },
    { name: 'medium-pkg', version: '1.0.0' },
    { name: 'low-pkg', version: '1.0.0' },
    { name: 'unknown-pkg', version: '1.0.0' }
  ];

  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async () =>
    ({
      ok: true,
      json: async () => ({
        results: [
          { vulns: [{ id: 'OSV-C', severity: [{ type: 'CVSS_V3', score: '9.1' }] }] },
          { vulns: [{ id: 'OSV-H', severity: [{ type: 'CVSS_V3', score: '8.2' }] }] },
          { vulns: [{ id: 'OSV-M', database_specific: { severity: 'moderate' } }] },
          { vulns: [{ id: 'OSV-L', severity: [{ type: 'CVSS_V3', score: '2.0' }] }] },
          { vulns: [{ id: 'OSV-U' }] }
        ]
      })
    }) as Response) as typeof fetch;

  try {
    const first = await client.batchQuery(pkgs);
    assert.equal(first.get('critical-pkg@1.0.0')?.vulnerabilities[0]?.severity, 'critical');
    assert.equal(first.get('high-pkg@1.0.0')?.vulnerabilities[0]?.severity, 'high');
    assert.equal(first.get('medium-pkg@1.0.0')?.vulnerabilities[0]?.severity, 'medium');
    assert.equal(first.get('low-pkg@1.0.0')?.vulnerabilities[0]?.severity, 'low');
    assert.equal(first.get('unknown-pkg@1.0.0')?.vulnerabilities[0]?.severity, 'unknown');
    assert.equal(first.get('critical-pkg@1.0.0')?.source, 'osv');
  } finally {
    globalThis.fetch = originalFetch;
  }

  globalThis.fetch = (async () => {
    throw new Error('network down');
  }) as typeof fetch;
  try {
    const second = await client.batchQuery(pkgs);
    assert.equal(second.get('critical-pkg@1.0.0')?.source, 'cache');
    assert.equal(second.get('high-pkg@1.0.0')?.source, 'cache');
    assert.equal(second.get('medium-pkg@1.0.0')?.source, 'cache');
    assert.equal(second.get('low-pkg@1.0.0')?.source, 'cache');
    assert.equal(second.get('unknown-pkg@1.0.0')?.source, 'cache');
  } finally {
    globalThis.fetch = originalFetch;
  }
});
