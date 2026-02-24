#!/usr/bin/env node
import { mkdir, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import yargs from 'yargs';
import { hideBin } from 'yargs/helpers';
import * as core from '@bardscan/core';
import { Severity } from '@bardscan/core';

export interface CliDeps {
  mkdir: typeof mkdir;
  writeFile: typeof writeFile;
  runScan: typeof core.runScan;
  updateAdvisoryDb: typeof core.updateAdvisoryDb;
  buildMarkdownReport: typeof core.buildMarkdownReport;
  buildSarifReport: (report: Awaited<ReturnType<typeof core.runScan>>) => object;
  shouldFail: typeof core.shouldFail;
  redactReportPaths: typeof core.redactReportPaths;
  stdout: { write: (text: string) => void; isTTY?: boolean };
  stderr: { write: (text: string) => void };
}

type FailOn = Severity | 'none';
type ListFindingsMode = 'none' | 'critical-high' | 'medium-up' | 'all';
type PrivacyMode = 'strict' | 'standard';
type EvidenceMode = 'none' | 'imports';

const defaultDeps: CliDeps = {
  mkdir,
  writeFile,
  runScan: core.runScan,
  updateAdvisoryDb: core.updateAdvisoryDb,
  buildMarkdownReport: core.buildMarkdownReport,
  buildSarifReport: (report) =>
    typeof (core as { buildSarifReport?: (r: typeof report) => object }).buildSarifReport === 'function'
      ? (core as { buildSarifReport: (r: typeof report) => object }).buildSarifReport(report)
      : {
          version: '2.1.0',
          runs: []
        },
  shouldFail: core.shouldFail,
  redactReportPaths: core.redactReportPaths,
  stdout: process.stdout,
  stderr: process.stderr
};

export async function runCli(rawArgs: string[], deps: CliDeps = defaultDeps): Promise<number> {
  let exitCode = 0;

  const parser = yargs(rawArgs)
    .scriptName('bardscan')
    .command(
      'scan [path]',
      'Scan a TypeScript project for vulnerable npm dependencies',
      (cmd) =>
        cmd
          .positional('path', {
            type: 'string',
            default: '.',
            describe: 'Project path to scan'
          })
          .option('format', {
            choices: ['json', 'md', 'sarif', 'both'] as const,
            default: 'both'
          })
          .option('out-dir', {
            type: 'string',
            default: path.join(os.tmpdir(), 'bardscan')
          })
          .option('fail-on', {
            choices: ['critical', 'high', 'medium', 'low', 'none'] as const,
            default: 'high'
          })
          .option('fail-on-unknown', {
            type: 'boolean',
            default: false,
            describe: 'Fail when unresolved findings exist (unknown severity/lookup)'
          })
          .option('privacy', {
            choices: ['strict', 'standard'] as const,
            default: 'strict',
            describe: 'Privacy preset that controls network and output defaults'
          })
          .option('online', {
            type: 'boolean',
            default: false,
            describe: 'Deprecated: scan is offline-only; use "db update" to fetch advisories'
          })
          .option('offline', {
            type: 'boolean',
            describe: 'Force cache-only scan mode'
          })
          .option('unknown-as', {
            choices: ['critical', 'high', 'medium', 'low', 'unknown'] as const,
            default: 'unknown'
          })
          .option('refresh-cache', {
            type: 'boolean',
            default: false
          })
          .option('update-db', {
            type: 'boolean',
            default: false,
            describe: 'Run db update before offline scan (single-command workflow)'
          })
          .option('osv-url', {
            type: 'string',
            describe: 'Custom OSV API base URL (for mirrors/proxies)'
          })
          .option('fallback-calls', {
            type: 'boolean',
            describe: 'Allow secondary network fallbacks for unresolved severities'
          })
          .option('redact-paths', {
            type: 'boolean',
            describe: 'Redact target path and evidence paths in outputs'
          })
          .option('evidence', {
            choices: ['none', 'imports'] as const,
            describe: 'Evidence collection mode'
          })
          .option('telemetry', {
            choices: ['off', 'on'] as const,
            describe: 'Reserved telemetry mode (default off)'
          })
          .option('list-findings', {
            choices: ['none', 'critical-high', 'medium-up', 'all'] as const,
            default: 'none',
            describe: 'Print finding details in CLI output'
          })
          .option('findings-json', {
            type: 'string',
            describe: 'Write filtered finding details as JSON'
          }),
      async (argv) => {
        try {
          const projectPath = path.resolve(String(argv.path));
          const outDir = path.resolve(String(argv.outDir));
          const settings = resolveScanSettings({
            privacy: argv.privacy as PrivacyMode,
            online: Boolean(argv.online),
            offline: argv.offline,
            fallbackCalls: argv.fallbackCalls,
            redactPaths: argv.redactPaths,
            evidence: argv.evidence as EvidenceMode | undefined,
            telemetry: argv.telemetry as 'off' | 'on' | undefined
          });

          await deps.mkdir(outDir, { recursive: true });

          if (Boolean(argv.updateDb)) {
            const update = await deps.updateAdvisoryDb({
              projectPath,
              outDir,
              refreshCache: Boolean(argv.refreshCache),
              osvUrl: argv.osvUrl ? String(argv.osvUrl) : undefined,
              enableNetworkFallbacks: settings.enableNetworkFallbacks
            });
            deps.stdout.write(buildDbUpdateSummary(update, useColor(deps.stdout)));
          }

          const report = await deps.runScan({
            projectPath,
            outDir,
            failOn: argv.failOn as FailOn,
            offline: settings.offline,
            unknownAs: argv.unknownAs as Severity,
            refreshCache: Boolean(argv.refreshCache),
            osvUrl: argv.osvUrl ? String(argv.osvUrl) : undefined,
            enableNetworkFallbacks: settings.enableNetworkFallbacks,
            evidenceMode: settings.evidenceMode
          });

          const redact = typeof deps.redactReportPaths === 'function' ? deps.redactReportPaths : (r: typeof report) => r;
          const displayReport = settings.redactPaths ? redact(report) : report;
          const jsonPath = path.join(outDir, 'report.json');
          const mdPath = path.join(outDir, 'report.md');
          const sarifPath = path.join(outDir, 'report.sarif');

          if (argv.format === 'json' || argv.format === 'both') {
            await deps.writeFile(jsonPath, JSON.stringify(displayReport, null, 2));
            deps.stdout.write(`${jsonPath}\n`);
          }
          if (argv.format === 'md' || argv.format === 'both') {
            await deps.writeFile(mdPath, deps.buildMarkdownReport(displayReport));
            deps.stdout.write(`${mdPath}\n`);
          }
          if (argv.format === 'sarif') {
            await deps.writeFile(sarifPath, JSON.stringify(deps.buildSarifReport(displayReport), null, 2));
            deps.stdout.write(`${sarifPath}\n`);
          }

          const thresholdHit =
            argv.failOn !== 'none' &&
            report.findings.some((f) => deps.shouldFail(argv.failOn as FailOn, f.severity));
          const unknownHit =
            Boolean(argv.failOnUnknown) &&
            report.findings.some((f) => f.severity === 'unknown' || typeof f.unknownReason === 'string');
          deps.stdout.write(
            buildCliSummary(displayReport, String(argv.failOn), thresholdHit, unknownHit, useColor(deps.stdout))
          );
          deps.stdout.write(buildFindingsList(displayReport, argv.listFindings as ListFindingsMode, useColor(deps.stdout)));
          if (argv.findingsJson) {
            const findingsJsonPath = path.resolve(String(argv.findingsJson));
            const filteredFindings = filterFindings(displayReport, argv.listFindings as ListFindingsMode);
            await deps.writeFile(findingsJsonPath, JSON.stringify(filteredFindings, null, 2));
            deps.stdout.write(`${findingsJsonPath}\n`);
          }

          if (thresholdHit || unknownHit) {
            exitCode = 1;
            return;
          }
          exitCode = 0;
        } catch (error) {
          deps.stderr.write(`${(error as Error).message}\n`);
          exitCode = 2;
        }
      }
    )
    .command(
      'db update [path]',
      'Refresh advisory cache for dependencies in the project lockfile',
      (cmd) =>
        cmd
          .positional('path', {
            type: 'string',
            default: '.',
            describe: 'Project path to index dependencies from'
          })
          .option('out-dir', {
            type: 'string',
            default: path.join(os.tmpdir(), 'bardscan')
          })
          .option('refresh-cache', {
            type: 'boolean',
            default: false
          })
          .option('osv-url', {
            type: 'string',
            describe: 'Custom OSV API base URL (for mirrors/proxies)'
          })
          .option('fallback-calls', {
            type: 'boolean',
            default: true,
            describe: 'Allow secondary network fallbacks for unresolved severities'
          }),
      async (argv) => {
        try {
          const projectPath = path.resolve(String(argv.path));
          const outDir = path.resolve(String(argv.outDir));
          await deps.mkdir(outDir, { recursive: true });

          const update = await deps.updateAdvisoryDb({
            projectPath,
            outDir,
            refreshCache: Boolean(argv.refreshCache),
            osvUrl: argv.osvUrl ? String(argv.osvUrl) : undefined,
            enableNetworkFallbacks: Boolean(argv.fallbackCalls)
          });

          deps.stdout.write(buildDbUpdateSummary(update, useColor(deps.stdout)));
          exitCode = 0;
        } catch (error) {
          deps.stderr.write(`${(error as Error).message}\n`);
          exitCode = 2;
        }
      }
    )
    .demandCommand(1)
    .strict()
    .help();

  await parser.parseAsync();
  return exitCode;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  void runCli(hideBin(process.argv)).then((code) => {
    process.exitCode = code;
  });
}

function resolveScanSettings(input: {
  privacy: PrivacyMode;
  online: boolean;
  offline: boolean | undefined;
  fallbackCalls: boolean | undefined;
  redactPaths: boolean | undefined;
  evidence: EvidenceMode | undefined;
  telemetry: 'off' | 'on' | undefined;
}): {
  offline: boolean;
  enableNetworkFallbacks: boolean;
  redactPaths: boolean;
  evidenceMode: EvidenceMode;
} {
  const preset =
    input.privacy === 'strict'
      ? {
          offline: true,
          enableNetworkFallbacks: false,
          redactPaths: true,
          evidenceMode: 'none' as EvidenceMode,
          telemetry: 'off' as const
        }
      : {
          offline: true,
          enableNetworkFallbacks: true,
          redactPaths: false,
          evidenceMode: 'imports' as EvidenceMode,
          telemetry: 'off' as const
        };

  let offline = preset.offline;
  if (input.online) {
    throw new Error('scan is offline-only. Run "bardscan db update <path>" first, then run "bardscan scan".');
  }
  if (typeof input.offline === 'boolean') offline = input.offline;

  if (!offline) {
    throw new Error('scan is offline-only. Remove online settings and refresh advisories via "bardscan db update".');
  }
  if ((input.telemetry ?? preset.telemetry) === 'on' && input.privacy === 'strict') {
    throw new Error('privacy strict disallows telemetry.');
  }

  return {
    offline,
    enableNetworkFallbacks: input.fallbackCalls ?? preset.enableNetworkFallbacks,
    redactPaths: input.redactPaths ?? preset.redactPaths,
    evidenceMode: input.evidence ?? preset.evidenceMode
  };
}

function buildCliSummary(
  report: Awaited<ReturnType<typeof core.runScan>>,
  failOn: string,
  thresholdHit: boolean,
  unknownHit: boolean,
  color: boolean
): string {
  const sev = report.summary.bySeverity;
  const conf = report.summary.byConfidence;
  const lines = [
    '',
    colorize('bardscan summary', 'cyan', color),
    `target: ${report.targetPath}`,
    `dependencies: ${report.summary.dependencyCount}`,
    `findings: ${report.summary.findingsCount}`,
    `severity: critical=${colorize(String(sev.critical), 'magenta', color)} high=${colorize(String(sev.high), 'red', color)} medium=${colorize(String(sev.medium), 'yellow', color)} low=${colorize(String(sev.low), 'green', color)} unknown=${colorize(String(sev.unknown), 'gray', color)}`,
    `confidence: high=${colorize(String(conf.high), 'green', color)} medium=${colorize(String(conf.medium), 'yellow', color)} low=${colorize(String(conf.low), 'red', color)} unknown=${colorize(String(conf.unknown), 'gray', color)}`,
    `fail-on: ${failOn}`,
    `threshold hit: ${thresholdHit ? colorize('yes', 'red', color) : colorize('no', 'green', color)}`,
    `unknown hit: ${unknownHit ? colorize('yes', 'red', color) : colorize('no', 'green', color)}`
  ];
  return `${lines.join('\n')}\n`;
}

function buildDbUpdateSummary(update: Awaited<ReturnType<typeof core.updateAdvisoryDb>>, color: boolean): string {
  const lines = [
    '',
    colorize('bardscan db update', 'cyan', color),
    `target: ${update.projectPath}`,
    `dependencies: ${update.dependencyCount}`,
    `queried: ${update.queriedCount}`,
    `sources: osv=${colorize(String(update.bySource.osv), 'green', color)} cache=${colorize(String(update.bySource.cache), 'yellow', color)} unknown=${colorize(String(update.bySource.unknown), 'red', color)}`
  ];
  return `${lines.join('\n')}\n`;
}

function buildFindingsList(
  report: Awaited<ReturnType<typeof core.runScan>>,
  mode: ListFindingsMode,
  color: boolean
): string {
  if (mode === 'none') return '';

  const filtered = filterFindings(report, mode);

  if (filtered.length === 0) {
    return `\n${colorize('finding details', 'cyan', color)}\n(no matching findings)\n`;
  }

  const lines = ['', colorize('finding details', 'cyan', color)];
  for (const finding of filtered) {
    const vulnIds = finding.vulnerabilities.slice(0, 3).map((v) => v.id).join(', ');
    const evidenceCount = finding.evidence.length;
    const unknownReason = finding.unknownReason ? ` unknown-reason=${finding.unknownReason}` : '';
    lines.push(
      `- ${colorize(finding.severity, severityColor(finding.severity), color)} ${finding.packageName}@${finding.version}` +
        ` confidence=${finding.confidence} direct=${finding.direct ? 'yes' : 'no'} evidence=${evidenceCount}` +
        ` source=${finding.source}${unknownReason} ids=${vulnIds || 'n/a'}`
    );
  }
  return `${lines.join('\n')}\n`;
}

function filterFindings(
  report: Awaited<ReturnType<typeof core.runScan>>,
  mode: ListFindingsMode
): Awaited<ReturnType<typeof core.runScan>>['findings'] {
  if (mode === 'all') return report.findings;
  if (mode === 'critical-high') {
    return report.findings.filter((f) => f.severity === 'critical' || f.severity === 'high');
  }
  if (mode === 'medium-up') {
    return report.findings.filter((f) => f.severity === 'critical' || f.severity === 'high' || f.severity === 'medium');
  }
  return [];
}

function severityColor(severity: Severity): 'magenta' | 'red' | 'yellow' | 'green' | 'gray' {
  if (severity === 'critical') return 'magenta';
  if (severity === 'high') return 'red';
  if (severity === 'medium') return 'yellow';
  if (severity === 'low') return 'green';
  return 'gray';
}

function useColor(stdout: { isTTY?: boolean }): boolean {
  return Boolean(stdout.isTTY && !process.env.NO_COLOR);
}

function colorize(text: string, color: 'red' | 'yellow' | 'green' | 'cyan' | 'magenta' | 'gray', enabled: boolean): string {
  if (!enabled) return text;
  const code: Record<typeof color, number> = {
    red: 31,
    yellow: 33,
    green: 32,
    cyan: 36,
    magenta: 35,
    gray: 90
  };
  return `\u001b[${code[color]}m${text}\u001b[0m`;
}
