import { describe, expect, it } from 'vitest';

import { analyze } from './analyze.js';
import { validateReport } from './validate-report.js';
import { loadOsvRecordings, projectFixtureDir, recordingHttp } from './test-helpers.js';

const GENERATED_AT = '2026-10-08T00:00:00.000Z';

function options() {
  return { generatedAt: GENERATED_AT, http: recordingHttp(loadOsvRecordings()) };
}

describe('analyze', () => {
  it('reports no findings for a project whose packages are all clean', async () => {
    const report = await analyze(projectFixtureDir('clean-npm'), options());

    expect(report.stats.totalPackages).toBe(12);
    expect(report.stats.directPackages).toBe(4);
    expect(report.stats.transitivePackages).toBe(8);
    expect(report.stats.totalVulnerabilities).toBe(0);
  });

  it('keeps two installed versions of one package apart', async () => {
    const report = await analyze(projectFixtureDir('clean-npm'), options());
    const ms = report.packages.filter((entry) => entry.name === 'ms').map((e) => e.version);

    expect(ms).toEqual(['2.1.2', '2.1.3']);
  });

  it('produces a report that satisfies its own schema and invariants', async () => {
    const report = await analyze(projectFixtureDir('clean-npm'), options());

    expect(validateReport(report)).toMatchObject({ ok: true });
  });

  it('names the engine, the manifest and the injected timestamp in meta', async () => {
    const report = await analyze(projectFixtureDir('clean-npm'), options());

    expect(report.meta.tool.name).toBe('depscan');
    expect(report.meta.generatedAt).toBe(GENERATED_AT);
    expect(report.meta.ecosystem).toBe('npm');
    expect(report.meta.manifestPath).toBe('package.json');
    expect(report.schemaVersion).toBe(2);
  });

  it('writes no risk or suggestions until scoring and the LLM layer exist', async () => {
    const report = await analyze(projectFixtureDir('clean-npm'), options());

    expect(report.risk).toEqual([]);
    expect(report.suggestions).toEqual([]);
  });

  it('refuses to scan without an injected timestamp', async () => {
    await expect(analyze(projectFixtureDir('clean-npm'), {})).rejects.toThrow(TypeError);
  });

  it('throws a typed parse error when no manifest is present', async () => {
    await expect(
      analyze(projectFixtureDir('clean-npm'), { generatedAt: GENERATED_AT, ecosystem: 'pypi' }),
    ).rejects.toMatchObject({ name: 'ProjectParseError', code: 'missing-requirements' });
  });
});
