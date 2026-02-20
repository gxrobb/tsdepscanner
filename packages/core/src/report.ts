import { Finding, ScanReport, Severity } from './types.js';
import { stableSortBy } from './utils.js';

export function buildMarkdownReport(report: ScanReport): string {
  const lines = [
    '# bardcheck summary',
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
      `- **${finding.packageName}@${finding.version}** | severity: ${finding.severity} (${finding.severitySource}) | confidence: ${finding.confidence} | direct: ${finding.direct}`
    );
    if (finding.severity === 'unknown' && finding.unknownReason) {
      lines.push(`  - severity unresolved: ${finding.unknownReason}`);
    }
    for (const vuln of finding.vulnerabilities) {
      lines.push(`  - ${formatAdvisoryLink(vuln.id)}${vuln.summary ? `: ${vuln.summary}` : ''}`);
      if (vuln.fixedVersion) {
        lines.push(`    - remediation: upgrade to ${finding.packageName}@${vuln.fixedVersion} or later`);
      }
      if (vuln.references?.length) {
        lines.push(`    - references: ${vuln.references.slice(0, 3).join(', ')}`);
      }
    }
    if (finding.evidence.length > 0) {
      lines.push(`  - evidence: ${finding.evidence.join(', ')}`);
    }
  }

  return lines.join('\n');
}

export function buildSarifReport(report: ScanReport): object {
  const rules = new Map<string, { id: string; name: string; helpUri: string }>();
  const results: Array<Record<string, unknown>> = [];

  for (const finding of report.findings) {
    for (const vuln of finding.vulnerabilities) {
      const ruleId = vuln.id;
      if (!rules.has(ruleId)) {
        rules.set(ruleId, {
          id: ruleId,
          name: ruleId,
          helpUri: advisoryUrl(ruleId)
        });
      }

      const location = finding.evidence[0]
        ? {
            physicalLocation: {
              artifactLocation: { uri: finding.evidence[0] }
            }
          }
        : undefined;

      results.push({
        ruleId,
        level: sarifLevel(finding.severity),
        message: {
          text: `${finding.packageName}@${finding.version}: ${vuln.summary ?? 'Dependency vulnerability detected'}`
        },
        ...(location ? { locations: [location] } : {}),
        properties: {
          packageName: finding.packageName,
          packageVersion: finding.version,
          severity: finding.severity,
          severitySource: finding.severitySource,
          direct: finding.direct,
          fixedVersion: vuln.fixedVersion
        }
      });
    }
  }

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'bardcheck',
            informationUri: 'https://github.com',
            rules: [...rules.values()]
          }
        },
        results
      }
    ]
  };
}

function advisoryUrl(id: string): string {
  if (id.startsWith('GHSA-')) return `https://github.com/advisories/${id}`;
  if (id.startsWith('CVE-')) return `https://nvd.nist.gov/vuln/detail/${id}`;
  return `https://osv.dev/vulnerability/${id}`;
}

function formatAdvisoryLink(id: string): string {
  return `[${id}](${advisoryUrl(id)})`;
}

function sarifLevel(severity: Severity): 'error' | 'warning' | 'note' {
  if (severity === 'critical' || severity === 'high') return 'error';
  if (severity === 'medium' || severity === 'low') return 'warning';
  return 'note';
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
