import path from 'node:path';
import { collectEvidence } from './evidence.js';
import { parsePackageLock } from './lock-parser.js';
import { OsvClient } from './osv-client.js';
import { sortFindings } from './report.js';
import { Confidence, Finding, ScanOptions, ScanReport, Severity, SeveritySource, UnknownReason } from './types.js';

export async function runScan(options: ScanOptions): Promise<ScanReport> {
  const parsed = await parsePackageLock(options.projectPath);
  const evidence = await collectEvidence(options.projectPath);
  const osv = new OsvClient(path.join(options.outDir, '.cache', 'osv'), options.offline);
  const osvResults = await osv.batchQuery(parsed.dependencies.map((d) => ({ name: d.name, version: d.version })));

  const findings: Finding[] = [];

  for (const dep of parsed.dependencies) {
    const key = `${dep.name}@${dep.version}`;
    const result = osvResults.get(key);
    if (!result) continue;

    const evidenceFiles = evidence.byPackage.get(dep.name) ?? [];
    const hasEvidence = evidenceFiles.length > 0;

    if (result.source === 'unknown') {
      findings.push({
        packageName: dep.name,
        version: dep.version,
        direct: dep.direct,
        severity: 'unknown',
        severitySource: 'unknown',
        unknownReason: 'lookup_failed',
        confidence: 'unknown',
        evidence: evidenceFiles,
        vulnerabilities: [],
        source: 'unknown'
      });
      continue;
    }

    if (result.vulnerabilities.length === 0) continue;

    const top = highestSeverity(result.vulnerabilities);
    const confidence = determineConfidence(dep.direct, hasEvidence);

    findings.push({
      packageName: dep.name,
      version: dep.version,
      direct: dep.direct,
      severity: top.severity,
      severitySource: top.severitySource,
      unknownReason: top.unknownReason,
      confidence,
      evidence: evidenceFiles,
      vulnerabilities: result.vulnerabilities,
      source: result.source
    });
  }

  const sorted = sortFindings(findings);

  const report: ScanReport = {
    targetPath: options.projectPath,
    generatedAt: new Date().toISOString(),
    failOn: options.failOn,
    summary: {
      dependencyCount: parsed.dependencies.length,
      scannedFiles: evidence.scannedFiles,
      findingsCount: sorted.length,
      bySeverity: countBySeverity(sorted),
      byConfidence: countByConfidence(sorted)
    },
    findings: sorted
  };

  return report;
}

function determineConfidence(direct: boolean, hasEvidence: boolean): Confidence {
  if (direct && hasEvidence) return 'high';
  if (direct && !hasEvidence) return 'medium';
  if (!direct && hasEvidence) return 'low';
  return 'unknown';
}

function highestSeverity(
  vulnerabilities: Array<{ severity: Severity; severitySource: SeveritySource; unknownReason?: UnknownReason }>
): { severity: Severity; severitySource: SeveritySource; unknownReason?: UnknownReason } {
  const rank: Record<Severity, number> = { critical: 5, high: 4, medium: 3, low: 2, unknown: 1 };
  const sorted = [...vulnerabilities].sort((a, b) => rank[b.severity] - rank[a.severity]);
  return sorted[0] ?? { severity: 'unknown', severitySource: 'unknown', unknownReason: 'missing_score' };
}

function countBySeverity(findings: Finding[]): Record<Severity, number> {
  const out: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    unknown: 0
  };
  for (const f of findings) out[f.severity] += 1;
  return out;
}

function countByConfidence(findings: Finding[]): Record<Confidence, number> {
  const out: Record<Confidence, number> = {
    high: 0,
    medium: 0,
    low: 0,
    unknown: 0
  };
  for (const f of findings) out[f.confidence] += 1;
  return out;
}
