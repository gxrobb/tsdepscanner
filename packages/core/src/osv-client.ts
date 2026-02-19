import { mkdir, readFile, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { OsvVulnerability, Severity } from './types.js';
import { hashObject } from './utils.js';

const TTL_MS = 24 * 60 * 60 * 1000;

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
}

export interface OsvLookupResult {
  source: 'osv' | 'cache' | 'unknown';
  vulnerabilities: OsvVulnerability[];
}

export class OsvClient {
  constructor(private readonly cacheDir: string, private readonly offline: boolean) {}

  async batchQuery(packages: Array<{ name: string; version: string }>): Promise<Map<string, OsvLookupResult>> {
    await mkdir(this.cacheDir, { recursive: true });
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

    return response;
  }

  private async fetchBatch(packages: Array<{ name: string; version: string }>) {
    const body = {
      queries: packages.map((pkg) => ({ package: { name: pkg.name, ecosystem: 'npm' }, version: pkg.version }))
    };

    const res = await fetch('https://api.osv.dev/v1/querybatch', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body)
    });

    if (!res.ok) {
      throw new Error(`OSV query failed: ${res.status}`);
    }

    const json = (await res.json()) as OsvBatchResponse;
    const map = new Map<string, OsvVulnerability[]>();
    for (let i = 0; i < packages.length; i += 1) {
      const pkg = packages[i];
      const raw = json.results[i]?.vulns ?? [];
      const vulns = raw.map(normalizeVuln);
      const key = `${pkg.name}@${pkg.version}`;
      map.set(key, vulns);
      await this.writeCache(pkg, vulns);
    }
    return map;
  }

  private cachePath(pkg: { name: string; version: string }): string {
    return path.join(this.cacheDir, `${hashObject(pkg)}.json`);
  }

  private async readCache(pkg: { name: string; version: string }): Promise<OsvVulnerability[] | null> {
    const filePath = this.cachePath(pkg);
    try {
      const fileStat = await stat(filePath);
      if (Date.now() - fileStat.mtimeMs > TTL_MS) {
        return null;
      }
      const data = JSON.parse(await readFile(filePath, 'utf8')) as OsvVulnerability[];
      return data;
    } catch {
      return null;
    }
  }

  private async writeCache(pkg: { name: string; version: string }, vulns: OsvVulnerability[]): Promise<void> {
    const filePath = this.cachePath(pkg);
    await writeFile(filePath, JSON.stringify(vulns, null, 2));
  }
}

function normalizeVuln(vuln: OsvRawVuln): OsvVulnerability {
  return {
    id: vuln.id,
    summary: vuln.summary,
    aliases: vuln.aliases,
    modified: vuln.modified,
    severity: mapSeverity(vuln)
  };
}

function mapSeverity(vuln: OsvRawVuln): Severity {
  const cvss = vuln.severity?.find((x) => x.type.toLowerCase().includes('cvss'));
  if (cvss) {
    const value = Number.parseFloat(cvss.score.split('/').pop() ?? cvss.score);
    if (!Number.isNaN(value)) {
      if (value >= 9) return 'critical';
      if (value >= 7) return 'high';
      if (value >= 4) return 'medium';
      return 'low';
    }
  }

  const label = vuln.database_specific?.severity?.toLowerCase();
  if (label?.includes('critical')) return 'critical';
  if (label?.includes('high')) return 'high';
  if (label?.includes('medium') || label?.includes('moderate')) return 'medium';
  if (label?.includes('low')) return 'low';

  return 'unknown';
}
