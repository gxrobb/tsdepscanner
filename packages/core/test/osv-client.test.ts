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
  globalThis.fetch = (async (input, init) => {
    const url = String(input);
    const method = (init?.method ?? 'GET').toUpperCase();
    if (url.endsWith('/v1/querybatch') && method === 'POST') {
      return {
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
      } as Response;
    }
    if (url.endsWith('/v1/vulns/OSV-U') && method === 'GET') {
      return {
        ok: true,
        json: async () => ({ id: 'OSV-U', database_specific: { severity: 'high' } })
      } as Response;
    }
    throw new Error(`unexpected request: ${method} ${url}`);
  }) as typeof fetch;

  try {
    const first = await client.batchQuery(pkgs);
    assert.equal(first.get('critical-pkg@1.0.0')?.vulnerabilities[0]?.severity, 'critical');
    assert.equal(first.get('high-pkg@1.0.0')?.vulnerabilities[0]?.severity, 'high');
    assert.equal(first.get('medium-pkg@1.0.0')?.vulnerabilities[0]?.severity, 'medium');
    assert.equal(first.get('low-pkg@1.0.0')?.vulnerabilities[0]?.severity, 'low');
    assert.equal(first.get('unknown-pkg@1.0.0')?.vulnerabilities[0]?.severity, 'high');
    assert.equal(first.get('unknown-pkg@1.0.0')?.vulnerabilities[0]?.severitySource, 'osv_detail_label');
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
    assert.equal(second.get('unknown-pkg@1.0.0')?.vulnerabilities[0]?.severity, 'high');
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('OsvClient annotates unknown reason when detail lookup fails', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'secscan-cache-'));
  const client = new OsvClient(dir, false);
  const originalFetch = globalThis.fetch;

  globalThis.fetch = (async (input, init) => {
    const url = String(input);
    const method = (init?.method ?? 'GET').toUpperCase();
    if (url.endsWith('/v1/querybatch') && method === 'POST') {
      return {
        ok: true,
        json: async () => ({ results: [{ vulns: [{ id: 'OSV-NO-DETAIL' }] }] })
      } as Response;
    }
    throw new Error('detail down');
  }) as typeof fetch;

  try {
    const result = await client.batchQuery([{ name: 'pkg', version: '1.0.0' }]);
    const vuln = result.get('pkg@1.0.0')?.vulnerabilities[0];
    assert.equal(vuln?.severity, 'unknown');
    assert.equal(vuln?.severitySource, 'unknown');
    assert.equal(vuln?.unknownReason, 'lookup_failed');
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('OsvClient falls back to CVE alias CVSS via NVD when OSV lacks severity', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'secscan-cache-'));
  const client = new OsvClient(dir, false);
  const originalFetch = globalThis.fetch;

  globalThis.fetch = (async (input, init) => {
    const url = String(input);
    const method = (init?.method ?? 'GET').toUpperCase();
    if (url.endsWith('/v1/querybatch') && method === 'POST') {
      return {
        ok: true,
        json: async () => ({ results: [{ vulns: [{ id: 'OSV-ALIAS', aliases: ['CVE-2024-9999'] }] }] })
      } as Response;
    }
    if (url.endsWith('/v1/vulns/OSV-ALIAS') && method === 'GET') {
      return {
        ok: true,
        json: async () => ({ id: 'OSV-ALIAS', aliases: ['CVE-2024-9999'] })
      } as Response;
    }
    if (url.includes('services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-9999') && method === 'GET') {
      return {
        ok: true,
        json: async () => ({
          vulnerabilities: [{ cve: { metrics: { cvssMetricV31: [{ cvssData: { baseScore: 9.8 } }] } } }]
        })
      } as Response;
    }
    throw new Error(`unexpected request: ${method} ${url}`);
  }) as typeof fetch;

  try {
    const result = await client.batchQuery([{ name: 'pkg', version: '1.0.0' }]);
    const vuln = result.get('pkg@1.0.0')?.vulnerabilities[0];
    assert.equal(vuln?.severity, 'critical');
    assert.equal(vuln?.severitySource, 'alias_cvss');
    assert.equal(vuln?.unknownReason, undefined);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('OsvClient falls back to GHSA advisory severity when no CVE score exists', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'secscan-cache-'));
  const client = new OsvClient(dir, false);
  const originalFetch = globalThis.fetch;

  globalThis.fetch = (async (input, init) => {
    const url = String(input);
    const method = (init?.method ?? 'GET').toUpperCase();
    if (url.endsWith('/v1/querybatch') && method === 'POST') {
      return {
        ok: true,
        json: async () => ({ results: [{ vulns: [{ id: 'GHSA-aaaa-bbbb-cccc' }] }] })
      } as Response;
    }
    if (url.endsWith('/v1/vulns/GHSA-aaaa-bbbb-cccc') && method === 'GET') {
      return {
        ok: true,
        json: async () => ({ id: 'GHSA-aaaa-bbbb-cccc' })
      } as Response;
    }
    if (url.includes('api.github.com/advisories/GHSA-aaaa-bbbb-cccc') && method === 'GET') {
      return {
        ok: true,
        json: async () => ({ ghsa_id: 'GHSA-aaaa-bbbb-cccc', severity: 'high' })
      } as Response;
    }
    throw new Error(`unexpected request: ${method} ${url}`);
  }) as typeof fetch;

  try {
    const result = await client.batchQuery([{ name: 'pkg', version: '1.0.0' }]);
    const vuln = result.get('pkg@1.0.0')?.vulnerabilities[0];
    assert.equal(vuln?.severity, 'high');
    assert.equal(vuln?.severitySource, 'ghsa_label');
  } finally {
    globalThis.fetch = originalFetch;
  }
});
