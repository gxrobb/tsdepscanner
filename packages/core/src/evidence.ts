import fg from 'fast-glob';
import { readFile } from 'node:fs/promises';
import path from 'node:path';

const IMPORT_RE = /(?:import\s+(?:[^'";]+\s+from\s+)?|require\()\s*['"]([^'"]+)['"]/g;

export interface EvidenceIndex {
  scannedFiles: number;
  byPackage: Map<string, string[]>;
}

export async function collectEvidence(projectPath: string): Promise<EvidenceIndex> {
  const files = await fg(['**/*.{ts,tsx,vue}'], {
    cwd: projectPath,
    absolute: true,
    ignore: ['**/node_modules/**', '**/dist/**']
  });

  const byPackage = new Map<string, Set<string>>();

  await Promise.all(
    files.map(async (file) => {
      const text = await readFile(file, 'utf8');
      const rel = path.relative(projectPath, file);
      for (const match of text.matchAll(IMPORT_RE)) {
        const spec = normalizePackageName(match[1]);
        if (!spec) continue;
        const existing = byPackage.get(spec) ?? new Set<string>();
        existing.add(rel);
        byPackage.set(spec, existing);
      }
    })
  );

  return {
    scannedFiles: files.length,
    byPackage: new Map([...byPackage.entries()].map(([k, v]) => [k, [...v].sort()]))
  };
}

function normalizePackageName(specifier: string): string | null {
  if (specifier.startsWith('.') || specifier.startsWith('/')) return null;
  if (specifier.startsWith('@')) {
    const [scope, name] = specifier.split('/');
    return scope && name ? `${scope}/${name}` : null;
  }
  return specifier.split('/')[0] ?? null;
}
