import { describe, expect, it } from 'vitest';

import { runCli, usage } from './index.js';

function harness(output?: unknown) {
  const lines: string[] = [];
  const files: Record<string, string> = {};
  return {
    lines,
    files,
    write: (line: string) => lines.push(line),
    writeFile: (path: string, contents: string) => {
      files[path] = contents;
    },
    now: () => new Date('2026-10-08T00:00:00.000Z'),
    cwd: process.cwd(),
    output,
  };
}

async function cli(argv: readonly string[]) {
  const h = harness();
  const code = await runCli(argv, h);
  return { ...h, code };
}

describe('runCli', () => {
  it('prints usage and exits successfully for help', async () => {
    const { lines, code } = await cli(['help']);

    expect(code).toBe(0);
    expect(lines).toEqual([usage()]);
  });

  it('defaults to help when no arguments are given', async () => {
    const { lines, code } = await cli([]);

    expect(code).toBe(0);
    expect(lines[0]).toContain('Usage: depscan');
  });

  it('fails on unknown commands', async () => {
    const { lines, code } = await cli(['audit']);

    expect(code).toBe(1);
    expect(lines[0]).toBe('Unknown command: audit');
  });

  it('requires a directory for analyze', async () => {
    const { lines, code } = await cli(['analyze']);

    expect(code).toBe(1);
    expect(lines[0]).toBe('analyze requires a directory');
  });

  it('rejects a second positional argument for analyze', async () => {
    const { lines, code } = await cli(['analyze', 'one', 'two']);

    expect(code).toBe(1);
    expect(lines[0]).toBe('Unexpected argument: two');
  });

  it('rejects an unknown option', async () => {
    const { lines, code } = await cli(['analyze', 'dir', '--nope']);

    expect(code).toBe(1);
    expect(lines[0]).toBe('Unknown option: --nope');
  });

  it('rejects a --fail-on that is not a severity', async () => {
    const { lines, code } = await cli(['analyze', 'dir', '--fail-on', 'severe']);

    expect(code).toBe(1);
    expect(lines[0]).toContain('--fail-on must be one of');
  });

  it('reports a missing manifest as a usage failure, not a crash', async () => {
    const { lines, code } = await cli(['analyze', 'no-such-dir']);

    expect(code).toBe(1);
    expect(lines[0]).toContain('missing-manifest');
  });

  it('lists analyze as the command that runs the engine', () => {
    expect(usage()).toContain('analyze <dir>');
    expect(usage()).toContain('--fail-on');
  });

  it('no longer accepts the old scan command name', async () => {
    const { lines, code } = await cli(['scan']);

    expect(code).toBe(1);
    expect(lines[0]).toBe('Unknown command: scan');
  });

  it('surfaces the engine package name it delegates to', () => {
    expect(usage()).toContain('Analysis engine: @depscan/core');
  });
});
