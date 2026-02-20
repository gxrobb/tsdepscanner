#!/usr/bin/env node
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import yargs from 'yargs';
import { hideBin } from 'yargs/helpers';
import * as core from '@bardcheck/core';
import { Severity } from '@bardcheck/core';

export interface CliDeps {
  mkdir: typeof mkdir;
  writeFile: typeof writeFile;
  runScan: typeof core.runScan;
  buildMarkdownReport: typeof core.buildMarkdownReport;
  buildSarifReport: (report: Awaited<ReturnType<typeof core.runScan>>) => object;
  shouldFail: typeof core.shouldFail;
  stdout: { write: (text: string) => void; isTTY?: boolean };
  stderr: { write: (text: string) => void };
}

type FailOn = Severity | 'none';

const defaultDeps: CliDeps = {
  mkdir,
  writeFile,
  runScan: core.runScan,
  buildMarkdownReport: core.buildMarkdownReport,
  buildSarifReport: (report) =>
    typeof (core as { buildSarifReport?: (r: typeof report) => object }).buildSarifReport === 'function'
      ? (core as { buildSarifReport: (r: typeof report) => object }).buildSarifReport(report)
      : {
          version: '2.1.0',
          runs: []
        },
  shouldFail: core.shouldFail,
  stdout: process.stdout,
  stderr: process.stderr
};

export async function runCli(rawArgs: string[], deps: CliDeps = defaultDeps): Promise<number> {
  let exitCode = 0;

  const parser = yargs(rawArgs)
    .scriptName('bardcheck')
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
            default: './.bardcheck'
          })
          .option('fail-on', {
            choices: ['critical', 'high', 'medium', 'low', 'none'] as const,
            default: 'high'
          })
          .option('offline', {
            type: 'boolean',
            default: false
          })
          .option('unknown-as', {
            choices: ['critical', 'high', 'medium', 'low', 'unknown'] as const,
            default: 'unknown'
          })
          .option('refresh-cache', {
            type: 'boolean',
            default: false
          }),
      async (argv) => {
        try {
          const projectPath = path.resolve(String(argv.path));
          const outDir = path.resolve(String(argv.outDir));
          await deps.mkdir(outDir, { recursive: true });

          const report = await deps.runScan({
            projectPath,
            outDir,
            failOn: argv.failOn as FailOn,
            offline: Boolean(argv.offline),
            unknownAs: argv.unknownAs as Severity,
            refreshCache: Boolean(argv.refreshCache)
          });

          const jsonPath = path.join(outDir, 'report.json');
          const mdPath = path.join(outDir, 'report.md');
          const sarifPath = path.join(outDir, 'report.sarif');

          if (argv.format === 'json' || argv.format === 'both') {
            await deps.writeFile(jsonPath, JSON.stringify(report, null, 2));
            deps.stdout.write(`${jsonPath}\n`);
          }
          if (argv.format === 'md' || argv.format === 'both') {
            await deps.writeFile(mdPath, deps.buildMarkdownReport(report));
            deps.stdout.write(`${mdPath}\n`);
          }
          if (argv.format === 'sarif') {
            await deps.writeFile(sarifPath, JSON.stringify(deps.buildSarifReport(report), null, 2));
            deps.stdout.write(`${sarifPath}\n`);
          }

          const thresholdHit =
            argv.failOn !== 'none' &&
            report.findings.some((f) => deps.shouldFail(argv.failOn as FailOn, f.severity));
          deps.stdout.write(buildCliSummary(report, String(argv.failOn), thresholdHit, useColor(deps.stdout)));

          if (
            thresholdHit
          ) {
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

function buildCliSummary(
  report: Awaited<ReturnType<typeof core.runScan>>,
  failOn: string,
  thresholdHit: boolean,
  color: boolean
): string {
  const sev = report.summary.bySeverity;
  const conf = report.summary.byConfidence;
  const lines = [
    '',
    colorize('bardcheck summary', 'cyan', color),
    `target: ${report.targetPath}`,
    `dependencies: ${report.summary.dependencyCount}`,
    `findings: ${report.summary.findingsCount}`,
    `severity: critical=${colorize(String(sev.critical), 'magenta', color)} high=${colorize(String(sev.high), 'red', color)} medium=${colorize(String(sev.medium), 'yellow', color)} low=${colorize(String(sev.low), 'green', color)} unknown=${colorize(String(sev.unknown), 'gray', color)}`,
    `confidence: high=${colorize(String(conf.high), 'green', color)} medium=${colorize(String(conf.medium), 'yellow', color)} low=${colorize(String(conf.low), 'red', color)} unknown=${colorize(String(conf.unknown), 'gray', color)}`,
    `fail-on: ${failOn}`,
    `threshold hit: ${thresholdHit ? colorize('yes', 'red', color) : colorize('no', 'green', color)}`
  ];
  return `${lines.join('\n')}\n`;
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
