import { mkdir, readdir, readFile, stat, unlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { OsvVulnerability, Severity, SeveritySource } from './types.js';
import { hashObject } from './utils.js';

const TTL_MS = 24 * 60 * 60 * 1000;
const FETCH_TIMEOUT_MS = 15000;
const ENRICH_CONCURRENCY = 6;

interface OsvBatchResponse {
  results: Array<{ vulns?: OsvRawVuln[] }>;
}

interface OsvRawVuln {
  id: string;
  summary?: string;
  aliases?: string[];
  modified?: string;
  severity?: Array<{ type: string; score: string }>;
  database_specific?: { severity?: string };
  references?: Array<{ url?: string }>;
  affected?: Array<{
    ranges?: Array<{
      events?: Array<{ fixed?: string; introduced?: string; last_affected?: string }>;
    }>;
  }>;
}

interface NvdResponse {
  vulnerabilities?: Array<{
    cve?: {
      metrics?: {
        cvssMetricV31?: Array<{ cvssData?: { baseScore?: number } }>;
        cvssMetricV30?: Array<{ cvssData?: { baseScore?: number } }>;
        cvssMetricV2?: Array<{ cvssData?: { baseScore?: number } }>;
      };
    };
  }>;
}

interface GhsaResponse {
  ghsa_id?: string;
  severity?: string;
  cvss?: { score?: number };
}

export interface OsvLookupResult {
  source: 'osv' | 'cache' | 'unknown';
  vulnerabilities: OsvVulnerability[];
}

export class OsvClient {
  private readonly cacheDir: string;
  private readonly offline: boolean;
  private readonly refreshCache: boolean;
  private readonly osvUrl: string;
  private readonly enableNetworkFallbacks: boolean;

  constructor(
    cacheDir: string,
    options:
      | boolean
      | {
          offline: boolean;
          refreshCache?: boolean;
          osvUrl?: string;
          enableNetworkFallbacks?: boolean;
        },
    refreshCache: boolean = false
  ) {
    this.cacheDir = cacheDir;
    if (typeof options === 'boolean') {
      this.offline = options;
      this.refreshCache = refreshCache;
      this.osvUrl = 'https://api.osv.dev';
      this.enableNetworkFallbacks = true;
      return;
    }
    this.offline = options.offline;
    this.refreshCache = options.refreshCache ?? false;
    this.osvUrl = (options.osvUrl ?? 'https://api.osv.dev').replace(/\/+$/, '');
    this.enableNetworkFallbacks = options.enableNetworkFallbacks ?? true;
  }

  async batchQuery(packages: Array<{ name: string; version: string }>): Promise<Map<string, OsvLookupResult>> {
    await mkdir(this.cacheDir, { recursive: true });
    if (!this.offline) {
      await this.pruneExpiredCache(this.cacheDir);
    }
    const response = new Map<string, OsvLookupResult>();
    const toFetch: Array<{ name: string; version: string }> = [];

    for (const pkg of packages) {
      const cached = await this.readCache(pkg);
      const key = `${pkg.name}@${pkg.version}`;
      if (cached) {
        response.set(key, { source: 'cache', vulnerabilities: cached });
      } else if (this.offline) {
        response.set(key, { source: 'unknown', vulnerabilities: [] });
      } else {
        toFetch.push(pkg);
      }
    }

    if (toFetch.length > 0) {
      const fetched = await this.fetchBatch(toFetch);
      for (const [k, vulns] of fetched.entries()) {
        response.set(k, { source: 'osv', vulnerabilities: vulns });
      }
    }

    for (const pkg of toFetch) {
      const key = `${pkg.name}@${pkg.version}`;
      if (!response.has(key)) {
        response.set(key, { source: 'unknown', vulnerabilities: [] });
      }
    }

    return response;
  }

  private async fetchBatch(packages: Array<{ name: string; version: string }>) {
    const body = {
      queries: packages.map((pkg) => ({ package: { name: pkg.name, ecosystem: 'npm' }, version: pkg.version }))
    };

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

    try {
      const res = await fetch(`${this.osvUrl}/v1/querybatch`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
        signal: controller.signal
      });

      if (!res.ok) {
        throw new Error(`OSV query failed: ${res.status}`);
      }

      const json = (await res.json()) as OsvBatchResponse;
      const map = new Map<string, OsvVulnerability[]>();
      const unknownById = new Map<string, string[]>();

      for (let i = 0; i < packages.length; i += 1) {
        const pkg = packages[i];
        const raw = json.results[i]?.vulns ?? [];
        const vulns = raw.map((v) => normalizeVuln(v, 'osv'));
        for (let idx = 0; idx < vulns.length; idx += 1) {
          const vuln = vulns[idx];
          const rawVuln = raw[idx];
          if (vuln.severity === 'unknown' && vuln.id) {
            unknownById.set(vuln.id, rawVuln?.aliases ?? []);
          }
        }
        map.set(`${pkg.name}@${pkg.version}`, vulns);
      }

      if (unknownById.size > 0 && this.enableNetworkFallbacks) {
        const enriched = await this.enrichUnknownVulns(
          [...unknownById.entries()].map(([id, aliases]) => ({ id, aliases }))
        );
        for (const [key, vulns] of map.entries()) {
          const patched = vulns.map((v) => {
            if (v.severity !== 'unknown') return v;
            const resolved = enriched.get(v.id);
            if (!resolved) {
              return { ...v, unknownReason: 'lookup_failed' as const };
            }
            if (resolved.severity === 'unknown') {
              return { ...v, ...resolved };
            }
            return { ...v, ...resolved, unknownReason: undefined };
          });
          map.set(key, patched);
        }
      }

      for (let i = 0; i < packages.length; i += 1) {
        const pkg = packages[i];
        const key = `${pkg.name}@${pkg.version}`;
        await this.writeCache(pkg, map.get(key) ?? []);
      }

      return map;
    } catch {
      return new Map<string, OsvVulnerability[]>();
    } finally {
      clearTimeout(timeout);
    }
  }

  private cachePath(pkg: { name: string; version: string }): string {
    return path.join(this.cacheDir, `${hashObject(pkg)}.json`);
  }

  private async readCache(pkg: { name: string; version: string }): Promise<OsvVulnerability[] | null> {
    if (this.refreshCache) return null;
    const filePath = this.cachePath(pkg);
    try {
      const fileStat = await stat(filePath);
      if (Date.now() - fileStat.mtimeMs > TTL_MS) return null;
      const data = JSON.parse(await readFile(filePath, 'utf8')) as OsvVulnerability[];
      return data.map(normalizeCachedVuln);
    } catch {
      return null;
    }
  }

  private async writeCache(pkg: { name: string; version: string }, vulns: OsvVulnerability[]): Promise<void> {
    const filePath = this.cachePath(pkg);
    await writeFile(filePath, JSON.stringify(vulns, null, 2));
  }

  private detailCachePath(id: string): string {
    return path.join(this.cacheDir, 'details', `${hashObject({ id })}.json`);
  }

  private async readDetailCache(id: string): Promise<OsvRawVuln | null> {
    if (this.refreshCache) return null;
    const filePath = this.detailCachePath(id);
    try {
      const fileStat = await stat(filePath);
      if (Date.now() - fileStat.mtimeMs > TTL_MS) return null;
      return JSON.parse(await readFile(filePath, 'utf8')) as OsvRawVuln;
    } catch {
      return null;
    }
  }

  private async writeDetailCache(id: string, vuln: OsvRawVuln): Promise<void> {
    const filePath = this.detailCachePath(id);
    await mkdir(path.dirname(filePath), { recursive: true });
    await writeFile(filePath, JSON.stringify(vuln, null, 2));
  }

  private async fetchVulnDetail(id: string): Promise<OsvRawVuln> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
    try {
      const res = await fetch(`${this.osvUrl}/v1/vulns/${encodeURIComponent(id)}`, {
        method: 'GET',
        signal: controller.signal
      });
      if (!res.ok) throw new Error(`OSV detail query failed: ${res.status}`);
      return (await res.json()) as OsvRawVuln;
    } finally {
      clearTimeout(timeout);
    }
  }

  private nvdCachePath(cveId: string): string {
    return path.join(this.cacheDir, 'nvd', `${hashObject({ cveId })}.json`);
  }

  private async readNvdCache(cveId: string): Promise<number | null> {
    if (this.refreshCache) return null;
    const filePath = this.nvdCachePath(cveId);
    try {
      const fileStat = await stat(filePath);
      if (Date.now() - fileStat.mtimeMs > TTL_MS) return null;
      const value = JSON.parse(await readFile(filePath, 'utf8')) as { score?: number };
      return typeof value.score === 'number' ? value.score : null;
    } catch {
      return null;
    }
  }

  private async writeNvdCache(cveId: string, score: number): Promise<void> {
    const filePath = this.nvdCachePath(cveId);
    await mkdir(path.dirname(filePath), { recursive: true });
    await writeFile(filePath, JSON.stringify({ score }, null, 2));
  }

  private async fetchNvdCvss(cveId: string): Promise<number | null> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
    try {
      const res = await fetch(
        `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cveId)}`,
        { method: 'GET', signal: controller.signal }
      );
      if (!res.ok) return null;
      const data = (await res.json()) as NvdResponse;
      return extractNvdBaseScore(data);
    } finally {
      clearTimeout(timeout);
    }
  }

  private ghsaCachePath(ghsaId: string): string {
    return path.join(this.cacheDir, 'ghsa', `${hashObject({ ghsaId })}.json`);
  }

  private async readGhsaCache(
    ghsaId: string
  ): Promise<Pick<OsvVulnerability, 'severity' | 'severitySource'> | null> {
    if (this.refreshCache) return null;
    const filePath = this.ghsaCachePath(ghsaId);
    try {
      const fileStat = await stat(filePath);
      if (Date.now() - fileStat.mtimeMs > TTL_MS) return null;
      const data = JSON.parse(await readFile(filePath, 'utf8')) as {
        severity?: Severity;
        severitySource?: SeveritySource;
      };
      if (!data.severity || !data.severitySource || data.severity === 'unknown') return null;
      return { severity: data.severity, severitySource: data.severitySource };
    } catch {
      return null;
    }
  }

  private async writeGhsaCache(
    ghsaId: string,
    severity: Pick<OsvVulnerability, 'severity' | 'severitySource'>
  ): Promise<void> {
    const filePath = this.ghsaCachePath(ghsaId);
    await mkdir(path.dirname(filePath), { recursive: true });
    await writeFile(filePath, JSON.stringify(severity, null, 2));
  }

  private async fetchGhsaSeverity(
    ghsaId: string
  ): Promise<Pick<OsvVulnerability, 'severity' | 'severitySource'> | null> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
    try {
      const res = await fetch(`https://api.github.com/advisories/${encodeURIComponent(ghsaId)}`, {
        method: 'GET',
        headers: {
          Accept: 'application/vnd.github+json',
          'User-Agent': 'bardscan'
        },
        signal: controller.signal
      });
      if (!res.ok) return null;
      const data = (await res.json()) as GhsaResponse;
      const cvssScore = data.cvss?.score;
      if (typeof cvssScore === 'number') return { severity: cvssToSeverity(cvssScore), severitySource: 'ghsa_cvss' };
      const label = data.severity?.toLowerCase();
      if (label === 'critical' || label === 'high' || label === 'medium' || label === 'low') {
        return { severity: label, severitySource: 'ghsa_label' };
      }
      return null;
    } finally {
      clearTimeout(timeout);
    }
  }

  private async resolveGhsaSeverity(
    ghsaId: string
  ): Promise<Pick<OsvVulnerability, 'severity' | 'severitySource'> | null> {
    const cached = await this.readGhsaCache(ghsaId);
    if (cached) return cached;
    const fetched = await this.fetchGhsaSeverity(ghsaId);
    if (fetched) {
      await this.writeGhsaCache(ghsaId, fetched);
      return fetched;
    }
    return null;
  }

  private async enrichUnknownVulns(
    unresolved: Array<{ id: string; aliases: string[] }>
  ): Promise<Map<string, Pick<OsvVulnerability, 'severity' | 'severitySource' | 'unknownReason'>>> {
    const resolvedEntries = await mapWithConcurrency(unresolved, ENRICH_CONCURRENCY, async ({ id, aliases }) => {
      try {
        let raw = await this.readDetailCache(id);
        if (!raw) {
          raw = await this.fetchVulnDetail(id);
          await this.writeDetailCache(id, raw);
        }
        const mapped = mapSeverity(raw, 'osv_detail');
        if (mapped.severity !== 'unknown') return [id, mapped] as const;

        const cveAliases = (raw.aliases ?? aliases).filter((alias) => alias.startsWith('CVE-'));
        for (const cveId of cveAliases) {
          let score = await this.readNvdCache(cveId);
          if (score === null) {
            score = await this.fetchNvdCvss(cveId);
            if (score !== null) await this.writeNvdCache(cveId, score);
          }
          if (score !== null) {
            return [id, { severity: cvssToSeverity(score), severitySource: 'alias_cvss' as const }] as const;
          }
        }

        const ghsaIds = new Set<string>();
        if (id.startsWith('GHSA-')) ghsaIds.add(id);
        for (const alias of raw.aliases ?? aliases) {
          if (alias.startsWith('GHSA-')) ghsaIds.add(alias);
        }
        for (const ghsaId of ghsaIds) {
          const ghsaSeverity = await this.resolveGhsaSeverity(ghsaId);
          if (ghsaSeverity) return [id, ghsaSeverity] as const;
        }

        return [id, mapped] as const;
      } catch {
        return [
          id,
          { severity: 'unknown' as const, severitySource: 'unknown' as const, unknownReason: 'lookup_failed' as const }
        ] as const;
      }
    });

    return new Map(resolvedEntries);
  }

  private async pruneExpiredCache(dirPath: string): Promise<void> {
    let entries;
    try {
      entries = await readdir(dirPath, { withFileTypes: true });
    } catch {
      return;
    }
    const now = Date.now();
    await Promise.all(
      entries.map(async (entry) => {
        const fullPath = path.join(dirPath, String(entry.name));
        if (entry.isDirectory()) {
          await this.pruneExpiredCache(fullPath);
          return;
        }
        try {
          const info = await stat(fullPath);
          if (now - info.mtimeMs > TTL_MS) await unlink(fullPath);
        } catch {
          // Best-effort pruning.
        }
      })
    );
  }
}

function normalizeVuln(vuln: OsvRawVuln, source: 'osv' | 'osv_detail' = 'osv'): OsvVulnerability {
  const mapped = mapSeverity(vuln, source);
  return {
    id: vuln.id,
    summary: vuln.summary,
    aliases: vuln.aliases,
    modified: vuln.modified,
    severity: mapped.severity,
    severitySource: mapped.severitySource,
    unknownReason: mapped.unknownReason,
    references: extractReferences(vuln),
    fixedVersion: extractFixedVersion(vuln)
  };
}

function normalizeCachedVuln(vuln: OsvVulnerability): OsvVulnerability {
  if (vuln.severitySource) return vuln;
  return {
    ...vuln,
    severitySource: vuln.severity === 'unknown' ? 'unknown' : 'osv_label',
    unknownReason: vuln.severity === 'unknown' ? vuln.unknownReason ?? 'missing_score' : undefined
  };
}

function mapSeverity(
  vuln: OsvRawVuln,
  source: 'osv' | 'osv_detail'
): Pick<OsvVulnerability, 'severity' | 'severitySource' | 'unknownReason'> {
  const cvss = vuln.severity?.find((x) => x.type.toLowerCase().includes('cvss'));
  if (cvss) {
    const value = Number.parseFloat(cvss.score.split('/').pop() ?? cvss.score);
    if (!Number.isNaN(value)) {
      if (value >= 9) return { severity: 'critical', severitySource: withSource(source, 'cvss') };
      if (value >= 7) return { severity: 'high', severitySource: withSource(source, 'cvss') };
      if (value >= 4) return { severity: 'medium', severitySource: withSource(source, 'cvss') };
      return { severity: 'low', severitySource: withSource(source, 'cvss') };
    }
  }

  const label = vuln.database_specific?.severity?.toLowerCase();
  if (label?.includes('critical')) return { severity: 'critical', severitySource: withSource(source, 'label') };
  if (label?.includes('high')) return { severity: 'high', severitySource: withSource(source, 'label') };
  if (label?.includes('medium') || label?.includes('moderate'))
    return { severity: 'medium', severitySource: withSource(source, 'label') };
  if (label?.includes('low')) return { severity: 'low', severitySource: withSource(source, 'label') };

  return { severity: 'unknown', severitySource: 'unknown', unknownReason: 'missing_score' };
}

function withSource(source: 'osv' | 'osv_detail', kind: 'cvss' | 'label'): SeveritySource {
  if (source === 'osv' && kind === 'cvss') return 'osv_cvss';
  if (source === 'osv' && kind === 'label') return 'osv_label';
  if (source === 'osv_detail' && kind === 'cvss') return 'osv_detail_cvss';
  return 'osv_detail_label';
}

function cvssToSeverity(value: number): Severity {
  if (value >= 9) return 'critical';
  if (value >= 7) return 'high';
  if (value >= 4) return 'medium';
  return 'low';
}

function extractNvdBaseScore(data: NvdResponse): number | null {
  const metrics = data.vulnerabilities?.[0]?.cve?.metrics;
  const v31 = metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore;
  if (typeof v31 === 'number') return v31;
  const v30 = metrics?.cvssMetricV30?.[0]?.cvssData?.baseScore;
  if (typeof v30 === 'number') return v30;
  const v2 = metrics?.cvssMetricV2?.[0]?.cvssData?.baseScore;
  if (typeof v2 === 'number') return v2;
  return null;
}

function extractReferences(vuln: OsvRawVuln): string[] | undefined {
  const refs = vuln.references?.map((r) => r.url).filter((u): u is string => Boolean(u));
  if (!refs?.length) return undefined;
  return [...new Set(refs)];
}

function extractFixedVersion(vuln: OsvRawVuln): string | undefined {
  const fixed = vuln.affected
    ?.flatMap((a) => a.ranges ?? [])
    .flatMap((r) => r.events ?? [])
    .map((e) => e.fixed)
    .filter((v): v is string => Boolean(v))
    .sort()[0];
  return fixed;
}

async function mapWithConcurrency<T, R>(
  items: T[],
  concurrency: number,
  worker: (item: T) => Promise<R>
): Promise<R[]> {
  const out = new Array<R>(items.length);
  let next = 0;
  const run = async () => {
    while (next < items.length) {
      const index = next;
      next += 1;
      out[index] = await worker(items[index]);
    }
  };
  const workers = Array.from({ length: Math.max(1, Math.min(concurrency, items.length)) }, () => run());
  await Promise.all(workers);
  return out;
}
