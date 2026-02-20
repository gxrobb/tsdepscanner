import fg from 'fast-glob';
import { readFile } from 'node:fs/promises';
import path from 'node:path';

const EVIDENCE_PATTERNS = ['**/*.{ts,tsx,js,jsx,mjs,cjs,vue}'];
const STATIC_IMPORT_RE = /(?:import\s+(?:[^'";]+\s+from\s+)?|require\()\s*['"]([^'"]+)['"]/g;
const DYNAMIC_IMPORT_RE = /import\(\s*['"]([^'"]+)['"]\s*\)/g;

export interface EvidenceIndex {
  scannedFiles: number;
  byPackage: Map<string, string[]>;
}

export async function collectEvidence(projectPath: string): Promise<EvidenceIndex> {
  const files = await fg(EVIDENCE_PATTERNS, {
    cwd: projectPath,
    absolute: true,
    ignore: ['**/node_modules/**', '**/dist/**', '**/.next/**']
  });

  const byPackage = new Map<string, Set<string>>();

  await Promise.all(
    files.map(async (file) => {
      const text = await readFile(file, 'utf8');
      const rel = path.relative(projectPath, file);
      for (const specifier of collectSpecifiers(text)) {
        const spec = normalizePackageName(specifier);
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

function collectSpecifiers(text: string): string[] {
  const specs: string[] = [];
  for (const match of text.matchAll(STATIC_IMPORT_RE)) {
    if (match[1]) specs.push(match[1]);
  }
  for (const match of text.matchAll(DYNAMIC_IMPORT_RE)) {
    if (match[1]) specs.push(match[1]);
  }
  return specs;
}

function normalizePackageName(specifier: string): string | null {
  if (specifier.startsWith('.') || specifier.startsWith('/')) return null;
  if (specifier.startsWith('@')) {
    const [scope, name] = specifier.split('/');
    return scope && name ? `${scope}/${name}` : null;
  }
  return specifier.split('/')[0] ?? null;
}
