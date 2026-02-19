import { mkdtemp, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import assert from 'node:assert/strict';
import { parsePackageLock } from '../src/lock-parser.js';

test('parsePackageLock resolves direct and transitive dependencies for lockfile v2', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'secscan-'));
  const lock = {
    lockfileVersion: 2,
    packages: {
      '': {},
      'node_modules/lodash': { version: '4.17.21' },
      'node_modules/chalk': { version: '5.0.0' },
      'node_modules/lodash/node_modules/ansi-styles': { version: '6.2.1' }
    }
  };
  await writeFile(path.join(dir, 'package-lock.json'), JSON.stringify(lock));
  const parsed = await parsePackageLock(dir);

  assert.equal(parsed.dependencies.length, 3);
  const lodash = parsed.dependencies.find((d) => d.name === 'lodash');
  const nested = parsed.dependencies.find((d) => d.name === 'ansi-styles');
  assert.equal(lodash?.direct, true);
  assert.equal(nested?.direct, false);
});

test('parsePackageLock correctly handles scoped package paths and direct classification', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'secscan-'));
  const lock = {
    lockfileVersion: 2,
    packages: {
      '': {},
      'node_modules/@types/node': { version: '22.10.2' },
      'node_modules/eslint/node_modules/@types/json-schema': { version: '7.0.15' }
    }
  };

  await writeFile(path.join(dir, 'package-lock.json'), JSON.stringify(lock));
  const parsed = await parsePackageLock(dir);

  const directScoped = parsed.dependencies.find((d) => d.name === '@types/node');
  const nestedScoped = parsed.dependencies.find((d) => d.name === '@types/json-schema');

  assert.equal(directScoped?.direct, true);
  assert.equal(nestedScoped?.direct, false);
});
