#!/usr/bin/env node
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import yargs from 'yargs';
import { hideBin } from 'yargs/helpers';
import { buildMarkdownReport, runScan, shouldFail } from '@secscan/core';

const parser = yargs(hideBin(process.argv))
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
        await mkdir(outDir, { recursive: true });

        const report = await runScan({
          projectPath,
          outDir,
          failOn: argv.failOn,
          offline: Boolean(argv.offline)
        });

        const jsonPath = path.join(outDir, 'report.json');
        const mdPath = path.join(outDir, 'report.md');

        if (argv.format === 'json' || argv.format === 'both') {
          await writeFile(jsonPath, JSON.stringify(report, null, 2));
          process.stdout.write(`${jsonPath}\n`);
        }
        if (argv.format === 'md' || argv.format === 'both') {
          await writeFile(mdPath, buildMarkdownReport(report));
          process.stdout.write(`${mdPath}\n`);
        }

        if (
          argv.failOn !== 'none' &&
          report.findings.some((f) => shouldFail(argv.failOn, f.severity))
        ) {
          process.exitCode = 1;
          return;
        }
        process.exitCode = 0;
      } catch (error) {
        process.stderr.write(`${(error as Error).message}\n`);
        process.exitCode = 2;
      }
    }
  )
  .demandCommand(1)
  .strict()
  .help();

void parser.parseAsync();
