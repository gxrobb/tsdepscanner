import { Finding, ScanReport, Severity } from './types.js';
import { stableSortBy } from './utils.js';

export function buildMarkdownReport(report: ScanReport): string {
  const lines = [
    '# secscan summary',
    '',
    `- Target: ${report.targetPath}`,
    `- Generated: ${report.generatedAt}`,
    `- Dependencies: ${report.summary.dependencyCount}`,
    `- Findings: ${report.summary.findingsCount}`,
    '',
    '## Findings',
    ''
  ];

  if (report.findings.length === 0) {
    lines.push('No vulnerable dependencies found.');
    return lines.join('\n');
  }

  for (const finding of report.findings) {
    lines.push(
      `- **${finding.packageName}@${finding.version}** | severity: ${finding.severity} | confidence: ${finding.confidence} | direct: ${finding.direct}`
    );
    for (const vuln of finding.vulnerabilities) {
      lines.push(`  - ${vuln.id}${vuln.summary ? `: ${vuln.summary}` : ''}`);
    }
    if (finding.evidence.length > 0) {
      lines.push(`  - evidence: ${finding.evidence.join(', ')}`);
    }
  }

  return lines.join('\n');
}

export function sortFindings(findings: Finding[]): Finding[] {
  const sevRank: Record<Severity, number> = {
    critical: 5,
    high: 4,
    medium: 3,
    low: 2,
    unknown: 1
  };

  return stableSortBy([...findings], (f) => {
    const inv = 9 - sevRank[f.severity];
    return `${inv}:${f.packageName}:${f.version}:${f.vulnerabilities.map((v) => v.id).join(',')}`;
  });
}
