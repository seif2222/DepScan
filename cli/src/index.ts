import { writeFileSync } from 'node:fs';

import {
  CORE_PACKAGE_NAME,
  SEVERITIES,
  analyze,
  compareSeverity,
  isSeverity,
  type Report,
  type Severity,
} from '@depscan/core';

import { formatReport } from './format.js';

export type OutputWriter = (line: string) => void;

export interface RunContext {
  readonly write: OutputWriter;
  readonly writeFile: (path: string, contents: string) => void;
  readonly now: () => Date;
  readonly cwd: string;
}

const SEVERITY_ORDER: readonly Severity[] = SEVERITIES;

const defaultContext: RunContext = {
  write: (line) => console.log(line),
  writeFile: (path, contents) => writeFileSync(path, contents, 'utf8'),
  now: () => new Date(),
  cwd: process.cwd(),
};

export function usage(): string {
  return [
    'Usage: depscan <command> [options]',
    '',
    'Commands:',
    '  analyze <dir>   Scan a project directory and print the findings',
    '  help            Show this message',
    '',
    'Options for analyze:',
    '  --json          Print report.json to stdout instead of the summary',
    '  --out <file>    Also write report.json to <file>',
    '  --offline       Use the local osv.dev cache only; fail on a miss',
    '  --fail-on <sev> Exit 2 when a finding at or above <sev> is present',
    `                  (${SEVERITY_ORDER.join(' > ')})`,
    '',
    `Engine: ${CORE_PACKAGE_NAME}`,
  ].join('\n');
}

interface ParsedArgs {
  readonly dir: string;
  readonly json: boolean;
  readonly offline: boolean;
  readonly out: string | null;
  readonly failOn: Severity | null;
}

type ParseResult = { readonly ok: true; readonly args: ParsedArgs } | { readonly ok: false; readonly error: string };

/** Parses `analyze` options. Pure and total: every failure returns a message, never throws. */
export function parseArgs(argv: readonly string[]): ParseResult {
  const positional: string[] = [];
  let json = false;
  let offline = false;
  let out: string | null = null;
  let failOn: Severity | null = null;

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i] ?? '';
    if (arg === '--json') {
      json = true;
    } else if (arg === '--offline') {
      offline = true;
    } else if (arg === '--out') {
      const value = argv[i + 1];
      if (value === undefined) return { ok: false, error: '--out requires a file path' };
      out = value;
      i += 1;
    } else if (arg === '--fail-on') {
      const value = argv[i + 1];
      if (value === undefined) return { ok: false, error: '--fail-on requires a severity' };
      if (!isSeverity(value)) {
        return { ok: false, error: `--fail-on must be one of ${SEVERITY_ORDER.join(', ')}` };
      }
      failOn = value;
      i += 1;
    } else if (arg.startsWith('--')) {
      return { ok: false, error: `Unknown option: ${arg}` };
    } else {
      positional.push(arg);
    }
  }

  const [dir, ...extra] = positional;
  if (dir === undefined) return { ok: false, error: 'analyze requires a directory' };
  if (extra.length > 0) return { ok: false, error: `Unexpected argument: ${extra.join(' ')}` };

  return { ok: true, args: { dir, json, offline, out, failOn } };
}

/** Exit 2 when any finding is at least as severe as the threshold. */
function thresholdHit(report: Report, failOn: Severity): boolean {
  return report.vulnerabilities.some((v) => compareSeverity(v.severity, failOn) <= 0);
}

/** Runs the CLI and returns the process exit code. 0 ok, 1 usage/parse error, 2 threshold. */
export async function runCli(
  argv: readonly string[],
  context: RunContext = defaultContext,
): Promise<number> {
  const { write } = context;
  const [command = 'help', ...rest] = argv;

  if (command === 'help' || command === '--help' || command === '-h') {
    write(usage());
    return 0;
  }

  if (command !== 'analyze') {
    write(`Unknown command: ${command}`);
    write(usage());
    return 1;
  }

  const parsed = parseArgs(rest);
  if (!parsed.ok) {
    write(parsed.error);
    write(usage());
    return 1;
  }

  const { dir, json, offline, out, failOn } = parsed.args;
  let report: Report;
  try {
    report = await analyze(dir, { offline, generatedAt: context.now().toISOString() });
  } catch (error) {
    write(error instanceof Error ? error.message : 'analysis failed');
    return 1;
  }

  const serialised = `${JSON.stringify(report, null, 2)}\n`;

  if (out !== null) {
    context.writeFile(out, serialised);
  }

  if (json) {
    write(serialised.trimEnd());
  } else {
    for (const line of formatReport(report)) write(line);
    if (out !== null) write(`\nWrote report.json to ${out}`);
  }

  return failOn !== null && thresholdHit(report, failOn) ? 2 : 0;
}
