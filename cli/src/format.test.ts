import { describe, expect, it } from 'vitest';

import type { Report } from '@depscan/core';

import { formatReport } from './format.js';

function report(overrides: Partial<Report> = {}): Report {
  const base: Report = {
    schemaVersion: 2,
    meta: {
      tool: { name: 'depscan', version: '0.1.0' },
      generatedAt: '2026-10-08T00:00:00.000Z',
      projectName: 'demo',
      ecosystem: 'npm',
      manifestPath: 'package.json',
      unresolved: [],
      warnings: [],
    },
    packages: [],
    vulnerabilities: [],
    risk: [],
    suggestions: [],
    stats: {
      totalPackages: 0,
      directPackages: 0,
      transitivePackages: 0,
      totalVulnerabilities: 0,
      bySeverity: { critical: 0, high: 0, medium: 0, low: 0 },
      unresolvedCount: 0,
    },
  };
  return { ...base, ...overrides };
}

describe('formatReport', () => {
  it('prints the project, ecosystem and manifest header', () => {
    const text = formatReport(report()).join('\n');

    expect(text).toContain('depscan — demo (npm)');
    expect(text).toContain('manifest   package.json');
  });

  it('always lists every severity, including zeros', () => {
    const text = formatReport(report()).join('\n');

    for (const severity of ['critical', 'high', 'medium', 'low']) {
      expect(text).toContain(severity);
    }
  });

  it('says so explicitly when there are no findings', () => {
    expect(formatReport(report()).join('\n')).toContain('No known vulnerabilities found.');
  });

  it('confirms completeness when nothing was unresolved', () => {
    expect(formatReport(report()).join('\n')).toContain('Scan complete');
  });

  it('flags an incomplete scan when requirements were unresolved', () => {
    const withUnresolved = report({
      meta: {
        ...report().meta,
        unresolved: [
          { raw: 'flask>=2', name: 'flask', specifier: '>=2', line: 1, reason: 'not-pinned' },
        ],
      },
    });
    const text = formatReport(withUnresolved).join('\n');

    expect(text).toContain('not checked');
    expect(text).toContain('1 requirement(s) could not be checked');
    expect(text).not.toContain('Scan complete');
  });

  it('renders the most severe finding first', () => {
    const listed = report({
      vulnerabilities: [
        {
          id: 'CVE-2',
          aliases: [],
          package: 'b',
          installedVersion: '1.0.0',
          severity: 'low',
          cvss: null,
          summary: 'low one',
          affectedRange: '<2',
          fixedVersion: '2.0.0',
          advisoryUrl: null,
          source: 'osv.dev',
        },
        {
          id: 'CVE-1',
          aliases: [],
          package: 'a',
          installedVersion: '1.0.0',
          severity: 'critical',
          cvss: null,
          summary: 'critical one',
          affectedRange: '<2',
          fixedVersion: '2.0.0',
          advisoryUrl: null,
          source: 'osv.dev',
        },
      ],
      stats: {
        totalPackages: 2,
        directPackages: 2,
        transitivePackages: 0,
        totalVulnerabilities: 2,
        bySeverity: { critical: 1, high: 0, medium: 0, low: 1 },
        unresolvedCount: 0,
      },
    });
    const text = formatReport(listed).join('\n');

    expect(text.indexOf('CVE-1')).toBeLessThan(text.indexOf('CVE-2'));
    expect(text).toContain('fixed-in 2.0.0');
  });
});
