import path from 'node:path';
import { readJson } from './utils.js';
import { DependencyNode, ParsedLock } from './types.js';

interface PackageLock {
  lockfileVersion?: number;
  packages?: Record<string, { version?: string; dev?: boolean }>;
  dependencies?: Record<string, LegacyDep>;
}

interface LegacyDep {
  version: string;
  dependencies?: Record<string, LegacyDep>;
}

export async function parsePackageLock(projectPath: string): Promise<ParsedLock> {
  const lockPath = path.join(projectPath, 'package-lock.json');
  const lock = await readJson<PackageLock>(lockPath);

  const map = new Map<string, DependencyNode>();

  if (lock.packages && lock.lockfileVersion && lock.lockfileVersion >= 2) {
    for (const [pkgPath, meta] of Object.entries(lock.packages)) {
      const name = getPackageNameFromPath(pkgPath);
      if (!name || !meta.version) continue;

      const direct = isDirectPackagePath(pkgPath);
      const key = `${name}@${meta.version}`;
      const existing = map.get(key);
      if (!existing) {
        map.set(key, { name, version: meta.version, direct });
      } else if (direct && !existing.direct) {
        map.set(key, { ...existing, direct: true });
      }
    }
  }

  if (map.size === 0 && lock.dependencies) {
    traverseLegacy(lock.dependencies, true, map);
  }

  return {
    dependencies: [...map.values()]
  };
}

function getPackageNameFromPath(pkgPath: string): string | null {
  if (!pkgPath.startsWith('node_modules/')) return null;

  const lastNodeModules = pkgPath.lastIndexOf('node_modules/');
  const candidate = pkgPath.slice(lastNodeModules + 'node_modules/'.length);
  if (!candidate) return null;

  const parts = candidate.split('/');
  if (parts[0]?.startsWith('@')) {
    if (!parts[1]) return null;
    return `${parts[0]}/${parts[1]}`;
  }

  return parts[0] ?? null;
}

function isDirectPackagePath(pkgPath: string): boolean {
  if (!pkgPath.startsWith('node_modules/')) return false;
  const rel = pkgPath.slice('node_modules/'.length);
  if (!rel) return false;

  const segments = rel.split('/');
  if (segments[0]?.startsWith('@')) {
    return segments.length === 2;
  }

  return segments.length === 1;
}

function traverseLegacy(
  deps: Record<string, LegacyDep>,
  direct: boolean,
  map: Map<string, DependencyNode>
): void {
  for (const [name, dep] of Object.entries(deps)) {
    if (!dep.version) continue;
    const key = `${name}@${dep.version}`;
    const existing = map.get(key);
    if (!existing) {
      map.set(key, { name, version: dep.version, direct });
    } else if (direct && !existing.direct) {
      map.set(key, { ...existing, direct: true });
    }

    if (dep.dependencies) {
      traverseLegacy(dep.dependencies, false, map);
    }
  }
}
