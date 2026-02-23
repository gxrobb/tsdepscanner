import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { collectEvidence } from '../src/evidence.js';

test('collectEvidence indexes imports across TS/JS/Vue files and ignores local paths', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'bardscan-evidence-'));
  await mkdir(path.join(dir, 'src'), { recursive: true });

  await writeFile(
    path.join(dir, 'src', 'main.ts'),
    "import lodash from 'lodash';\nimport x from './local';\nconst chalk = require('chalk');\n"
  );
  await writeFile(path.join(dir, 'src', 'feature.tsx'), "import '@types/node';\n");
  await writeFile(path.join(dir, 'src', 'Widget.vue'), "<script setup lang=\"ts\">import 'chalk';</script>\n");
  await writeFile(
    path.join(dir, 'src', 'page.jsx'),
    "import React from 'react';\nconst Comp = () => import('next/dynamic');\nexport default Comp;\n"
  );
  await writeFile(path.join(dir, 'src', 'next.config.mjs'), "import 'next';\n");

  const out = await collectEvidence(dir);

  assert.equal(out.scannedFiles, 5);
  assert.deepEqual(out.byPackage.get('lodash'), ['src/main.ts']);
  assert.deepEqual(out.byPackage.get('chalk'), ['src/Widget.vue', 'src/main.ts']);
  assert.deepEqual(out.byPackage.get('@types/node'), ['src/feature.tsx']);
  assert.deepEqual(out.byPackage.get('react'), ['src/page.jsx']);
  assert.deepEqual(out.byPackage.get('next'), ['src/next.config.mjs', 'src/page.jsx']);
  assert.equal(out.byPackage.has('./local'), false);
});

test('collectEvidence ignores node_modules, dist, and .next folders', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'bardscan-evidence-ignore-'));
  await mkdir(path.join(dir, 'src'), { recursive: true });
  await mkdir(path.join(dir, 'dist'), { recursive: true });
  await mkdir(path.join(dir, '.next'), { recursive: true });
  await mkdir(path.join(dir, 'node_modules', 'x'), { recursive: true });

  await writeFile(path.join(dir, 'src', 'index.ts'), "import 'axios';\n");
  await writeFile(path.join(dir, 'dist', 'bundle.ts'), "import 'ignored-dist';\n");
  await writeFile(path.join(dir, '.next', 'cache.js'), "import 'ignored-next-build';\n");
  await writeFile(path.join(dir, 'node_modules', 'x', 'index.ts'), "import 'ignored-node-modules';\n");

  const out = await collectEvidence(dir);

  assert.equal(out.scannedFiles, 1);
  assert.deepEqual([...out.byPackage.keys()], ['axios']);
});
