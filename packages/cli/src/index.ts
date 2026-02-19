#!/usr/bin/env node
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import yargs from 'yargs';
import { hideBin } from 'yargs/helpers';
import { buildMarkdownReport, runScan, shouldFail, Severity } from '@secscan/core';

export interface CliDeps {
  mkdir: typeof mkdir;
  writeFile: typeof writeFile;
  runScan: typeof runScan;
  buildMarkdownReport: typeof buildMarkdownReport;
  shouldFail: typeof shouldFail;
  stdout: { write: (text: string) => void };
  stderr: { write: (text: string) => void };
}

type FailOn = Severity | 'none';

const defaultDeps: CliDeps = {
  mkdir,
  writeFile,
  runScan,
  buildMarkdownReport,
  shouldFail,
  stdout: process.stdout,
  stderr: process.stderr
};

export async function runCli(rawArgs: string[], deps: CliDeps = defaultDeps): Promise<number> {
  let exitCode = 0;

  const parser = yargs(rawArgs)
    .scriptName('secscan')
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
            choices: ['json', 'md', 'both'] as const,
            default: 'both'
          })
          .option('out-dir', {
            type: 'string',
            default: './.secscan'
          })
          .option('fail-on', {
            choices: ['critical', 'high', 'medium', 'low', 'none'] as const,
            default: 'high'
          })
          .option('offline', {
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
            offline: Boolean(argv.offline)
          });

          const jsonPath = path.join(outDir, 'report.json');
          const mdPath = path.join(outDir, 'report.md');

          if (argv.format === 'json' || argv.format === 'both') {
            await deps.writeFile(jsonPath, JSON.stringify(report, null, 2));
            deps.stdout.write(`${jsonPath}\n`);
          }
          if (argv.format === 'md' || argv.format === 'both') {
            await deps.writeFile(mdPath, deps.buildMarkdownReport(report));
            deps.stdout.write(`${mdPath}\n`);
          }

          if (
            argv.failOn !== 'none' &&
            report.findings.some((f) => deps.shouldFail(argv.failOn as FailOn, f.severity))
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
