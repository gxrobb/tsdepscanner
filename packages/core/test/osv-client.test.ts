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
