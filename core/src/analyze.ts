import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { ProjectParseError } from './errors.js';
import { matchVulnerabilities } from './match.js';
import { parseNpm } from './npm-parse.js';
import { parsePython } from './python-parse.js';
import { computeStats } from './stats.js';
import { REPORT_SCHEMA_VERSION, TOOL_NAME, type Ecosystem, type Report } from './types.js';
import type { OsvCache } from './osv-cache.js';
import type { OsvHttp } from './osv-http.js';

export interface AnalyzeOptions {
  readonly ecosystem?: Ecosystem;
  readonly http?: OsvHttp;
  readonly cache?: OsvCache;
  readonly offline?: boolean;
  readonly generatedAt?: string;
}

export async function analyze(dir: string, o: AnalyzeOptions = {}): Promise<Report> {
  if (o.generatedAt === undefined) throw new TypeError('analyze needs generatedAt');
  const ecosystem = o.ecosystem ?? detect(dir);
  const p = ecosystem === 'npm' ? { ...parseNpm(dir), unresolved: [] } : parsePython(dir);
  const warnings = [...p.warnings];
  const vulnerabilities = await matchVulnerabilities(p.packages, {
    ecosystem,
    http: o.http,
    cache: o.cache,
    offline: o.offline,
    onUnidentifiedAdvisory: (i) => warnings.push('unidentified advisory ' + (i.recordId ?? '?')),
  });
  return {
    schemaVersion: REPORT_SCHEMA_VERSION,
    meta: {
      tool: { name: TOOL_NAME, version: '0.1.0' },
      generatedAt: o.generatedAt,
      projectName: p.projectName,
      ecosystem,
      manifestPath: p.manifestPath,
      unresolved: p.unresolved,
      warnings,
    },
    packages: p.packages,
    vulnerabilities,
    risk: [],
    suggestions: [],
    stats: computeStats(p.packages, vulnerabilities, p.unresolved.length),
  };
}

function detect(dir: string): Ecosystem {
  if (existsSync(join(dir, 'package.json'))) return 'npm';
  if (existsSync(join(dir, 'requirements.txt'))) return 'pypi';
  throw new ProjectParseError('missing-manifest', dir, 'no manifest');
}
