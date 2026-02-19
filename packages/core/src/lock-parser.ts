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
      if (!pkgPath || !meta.version) continue;
      const name = pkgPath.startsWith('node_modules/') ? pkgPath.slice('node_modules/'.length) : null;
      if (!name) continue;
      const direct = pkgPath.split('/').length === 2;
      map.set(`${name}@${meta.version}`, { name, version: meta.version, direct });
    }
  }

  if (map.size === 0 && lock.dependencies) {
    traverseLegacy(lock.dependencies, true, map);
  }

  return {
    dependencies: [...map.values()]
  };
}

function traverseLegacy(
  deps: Record<string, LegacyDep>,
  direct: boolean,
  map: Map<string, DependencyNode>
): void {
  for (const [name, dep] of Object.entries(deps)) {
    if (!dep.version) continue;
    map.set(`${name}@${dep.version}`, { name, version: dep.version, direct });
    if (dep.dependencies) {
      traverseLegacy(dep.dependencies, false, map);
    }
  }
}
