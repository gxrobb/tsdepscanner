import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

export const SEVERITY_RANK: Record<string, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  unknown: 1,
  none: 0
};

export function stableSortBy<T>(items: T[], key: (item: T) => string): T[] {
  return items
    .map((item, idx) => ({ item, idx }))
    .sort((a, b) => {
      const ka = key(a.item);
      const kb = key(b.item);
      if (ka < kb) return -1;
      if (ka > kb) return 1;
      return a.idx - b.idx;
    })
    .map(({ item }) => item);
}

export function shouldFail(failOn: string, findingSeverity: string): boolean {
  return SEVERITY_RANK[findingSeverity] >= SEVERITY_RANK[failOn];
}

export async function readJson<T>(filePath: string): Promise<T> {
  const text = await readFile(filePath, 'utf8');
  return JSON.parse(text) as T;
}

export async function writeJson(filePath: string, data: unknown): Promise<void> {
  await mkdir(path.dirname(filePath), { recursive: true });
  await writeFile(filePath, JSON.stringify(data, null, 2));
}

export function hashObject(data: unknown): string {
  return createHash('sha256').update(JSON.stringify(data)).digest('hex');
}
