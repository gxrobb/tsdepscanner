import { access, readFile } from 'node:fs/promises';
import path from 'node:path';
import fg from 'fast-glob';
import YAML from 'yaml';
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
  if (await fileExists(path.join(projectPath, 'package-lock.json'))) {
    return parseNpmLock(projectPath);
  }
  if (await fileExists(path.join(projectPath, 'pnpm-lock.yaml'))) {
    return parsePnpmLock(projectPath);
  }
  if (await fileExists(path.join(projectPath, 'yarn.lock'))) {
    return parseYarnLock(projectPath);
  }
  if (
    (await fileExists(path.join(projectPath, 'bun.lock'))) ||
    (await fileExists(path.join(projectPath, 'bun.lockb')))
  ) {
    return parseBunManifest(projectPath);
  }

  throw new Error(
    'No supported lockfile found. Expected one of: package-lock.json, pnpm-lock.yaml, yarn.lock, bun.lock, bun.lockb'
  );
}

async function parseNpmLock(projectPath: string): Promise<ParsedLock> {
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

async function parsePnpmLock(projectPath: string): Promise<ParsedLock> {
  const lockPath = path.join(projectPath, 'pnpm-lock.yaml');
  const text = await readFile(lockPath, 'utf8');
  const lock = YAML.parse(text) as {
    packages?: Record<string, unknown>;
    importers?: Record<
      string,
      {
        dependencies?: Record<string, string>;
        devDependencies?: Record<string, string>;
        optionalDependencies?: Record<string, string>;
      }
    >;
  };

  const directNames = new Set<string>();
  for (const importer of Object.values(lock.importers ?? {})) {
    for (const deps of [importer.dependencies, importer.devDependencies, importer.optionalDependencies]) {
      for (const name of Object.keys(deps ?? {})) directNames.add(name);
    }
  }

  const map = new Map<string, DependencyNode>();
  for (const key of Object.keys(lock.packages ?? {})) {
    const parsed = parsePnpmPackageKey(key);
    if (!parsed) continue;

    const depKey = `${parsed.name}@${parsed.version}`;
    const direct = directNames.has(parsed.name);
    upsertDependency(map, depKey, parsed.name, parsed.version, direct);
  }

  return { dependencies: [...map.values()] };
}

async function parseYarnLock(projectPath: string): Promise<ParsedLock> {
  const directNames = await collectWorkspaceDirectNames(projectPath);

  const lockPath = path.join(projectPath, 'yarn.lock');
  const text = await readFile(lockPath, 'utf8');
  const lines = text.split('\n');
  const map = new Map<string, DependencyNode>();

  let currentKey: string | null = null;
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    if (!line.startsWith(' ') && trimmed.endsWith(':')) {
      currentKey = trimmed.slice(0, -1);
      continue;
    }

    if (!currentKey) continue;
    if (!trimmed.startsWith('version')) continue;

    const version = parseYarnVersionLine(trimmed);
    if (!version) continue;

    const selectors = currentKey.split(',').map((s) => s.trim()).filter(Boolean);
    for (const selector of selectors) {
      const name = packageNameFromSelector(selector);
      if (!name) continue;
      const depKey = `${name}@${version}`;
      const direct = directNames.has(name);
      upsertDependency(map, depKey, name, version, direct);
    }
  }

  return { dependencies: [...map.values()] };
}

async function parseBunManifest(projectPath: string): Promise<ParsedLock> {
  const manifests = await readWorkspaceManifests(projectPath);
  const map = new Map<string, DependencyNode>();

  for (const manifest of manifests) {
    for (const deps of [manifest.dependencies, manifest.devDependencies, manifest.optionalDependencies]) {
      for (const [name, spec] of Object.entries(deps ?? {})) {
        const version = normalizeManifestVersion(spec);
        const depKey = `${name}@${version}`;
        upsertDependency(map, depKey, name, version, true);
      }
    }
  }

  return { dependencies: [...map.values()] };
}

async function readPackageManifest(projectPath: string): Promise<{
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  workspaces?: string[] | { packages?: string[] };
}> {
  const manifestPath = path.join(projectPath, 'package.json');
  return readJson(manifestPath);
}

async function collectWorkspaceDirectNames(projectPath: string): Promise<Set<string>> {
  const manifests = await readWorkspaceManifests(projectPath);
  const names = new Set<string>();
  for (const manifest of manifests) {
    for (const deps of [manifest.dependencies, manifest.devDependencies, manifest.optionalDependencies]) {
      for (const name of Object.keys(deps ?? {})) names.add(name);
    }
  }
  return names;
}

async function readWorkspaceManifests(projectPath: string): Promise<
  Array<{
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
    optionalDependencies?: Record<string, string>;
    workspaces?: string[] | { packages?: string[] };
  }>
> {
  const root = await readPackageManifest(projectPath);
  const workspacePatterns = getWorkspacePatterns(root);
  if (workspacePatterns.length === 0) return [root];

  const files = await fg(workspacePatterns.map((p) => `${p}/package.json`), {
    cwd: projectPath,
    absolute: true,
    ignore: ['**/node_modules/**']
  });

  const manifests = await Promise.all(
    files.map(async (file) => {
      return readJson<{
        dependencies?: Record<string, string>;
        devDependencies?: Record<string, string>;
        optionalDependencies?: Record<string, string>;
      }>(file);
    })
  );

  return [root, ...manifests];
}

function getWorkspacePatterns(manifest: { workspaces?: string[] | { packages?: string[] } }): string[] {
  if (!manifest.workspaces) return [];
  if (Array.isArray(manifest.workspaces)) return manifest.workspaces;
  if (Array.isArray(manifest.workspaces.packages)) return manifest.workspaces.packages;
  return [];
}

function upsertDependency(
  map: Map<string, DependencyNode>,
  key: string,
  name: string,
  version: string,
  direct: boolean
) {
  const existing = map.get(key);
  if (!existing) {
    map.set(key, { name, version, direct });
  } else if (direct && !existing.direct) {
    map.set(key, { ...existing, direct: true });
  }
}

async function fileExists(filePath: string): Promise<boolean> {
  try {
    await access(filePath);
    return true;
  } catch {
    return false;
  }
}

function parsePnpmPackageKey(key: string): { name: string; version: string } | null {
  const noPrefix = key.startsWith('/') ? key.slice(1) : key;
  const raw = noPrefix.split('(')[0] ?? noPrefix;
  const splitAt = raw.lastIndexOf('@');
  if (splitAt <= 0) return null;
  const name = raw.slice(0, splitAt);
  const version = raw.slice(splitAt + 1);
  if (!name || !version) return null;
  return { name, version };
}

function parseYarnVersionLine(line: string): string | null {
  const quoted = line.match(/^version\s+"([^"]+)"$/);
  if (quoted?.[1]) return quoted[1];

  const yamlStyle = line.match(/^version:\s*"?([^"]+)"?$/);
  if (yamlStyle?.[1]) return yamlStyle[1];

  return null;
}

function packageNameFromSelector(selector: string): string | null {
  const cleaned = selector.replace(/^"|"$/g, '').replace(/^'|'$/g, '');
  const npmProtocolSplit = cleaned.indexOf('@npm:');
  const normalized = npmProtocolSplit >= 0 ? cleaned.slice(0, npmProtocolSplit) : cleaned;

  const match = normalized.match(/^(@[^/]+\/[^@]+|[^@]+)@/);
  return match?.[1] ?? null;
}

function normalizeManifestVersion(spec: string): string {
  const exact = spec.match(/\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?/);
  if (exact?.[0]) return exact[0];
  return spec;
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
