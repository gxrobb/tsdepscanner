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

test('parsePackageLock parses pnpm-lock.yaml with direct dependency classification', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'secscan-'));
  await writeFile(
    path.join(dir, 'package.json'),
    JSON.stringify({
      dependencies: { lodash: '^4.17.21' }
    })
  );
  await writeFile(
    path.join(dir, 'pnpm-lock.yaml'),
    [
      'lockfileVersion: "9.0"',
      'importers:',
      '  .:',
      '    dependencies:',
      '      lodash:',
      '        specifier: ^4.17.21',
      '        version: 4.17.21',
      'packages:',
      '  lodash@4.17.21: {}',
      '  ansi-styles@6.2.1: {}'
    ].join('\n')
  );

  const parsed = await parsePackageLock(dir);
  const lodash = parsed.dependencies.find((d) => d.name === 'lodash');
  const ansi = parsed.dependencies.find((d) => d.name === 'ansi-styles');

  assert.equal(lodash?.direct, true);
  assert.equal(ansi?.direct, false);
});

test('parsePackageLock parses yarn.lock with direct dependency classification', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'secscan-'));
  await writeFile(
    path.join(dir, 'package.json'),
    JSON.stringify({
      dependencies: { lodash: '^4.17.19' }
    })
  );
  await writeFile(
    path.join(dir, 'yarn.lock'),
    ['"lodash@^4.17.19":', '  version "4.17.21"', '"ansi-styles@^6.2.1":', '  version "6.2.1"'].join(
      '\n'
    )
  );

  const parsed = await parsePackageLock(dir);
  const lodash = parsed.dependencies.find((d) => d.name === 'lodash');
  const ansi = parsed.dependencies.find((d) => d.name === 'ansi-styles');

  assert.equal(lodash?.version, '4.17.21');
  assert.equal(lodash?.direct, true);
  assert.equal(ansi?.direct, false);
});

test('parsePackageLock falls back to package.json direct deps for bun lockfiles', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'secscan-'));
  await writeFile(
    path.join(dir, 'package.json'),
    JSON.stringify({
      dependencies: { react: '^18.3.1' },
      devDependencies: { next: '14.2.0' },
      optionalDependencies: { chalk: '~5.3.0' }
    })
  );
  await writeFile(path.join(dir, 'bun.lockb'), '');

  const parsed = await parsePackageLock(dir);
  const react = parsed.dependencies.find((d) => d.name === 'react');
  const next = parsed.dependencies.find((d) => d.name === 'next');
  const chalk = parsed.dependencies.find((d) => d.name === 'chalk');

  assert.equal(react?.version, '18.3.1');
  assert.equal(next?.version, '14.2.0');
  assert.equal(chalk?.version, '5.3.0');
  assert.equal(parsed.dependencies.every((d) => d.direct), true);
});
