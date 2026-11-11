import { describe, expect, it } from 'vitest';

import type { Report } from '@depscan/core';

import { escapeHtml, renderDashboard } from './render.js';

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
    packages: [
      { name: 'a', version: '1.0.0', isDirect: true, depth: 0, parents: [], isDev: false },
      { name: 'b', version: '2.0.0', isDirect: false, depth: 1, parents: ['a@1.0.0'], isDev: false },
    ],
    vulnerabilities: [],
    risk: [],
    suggestions: [],
    stats: {
      totalPackages: 2,
      directPackages: 1,
      transitivePackages: 1,
      totalVulnerabilities: 0,
      bySeverity: { critical: 0, high: 0, medium: 0, low: 0 },
      unresolvedCount: 0,
    },
  };
  return { ...base, ...overrides };
}

describe('escapeHtml', () => {
  it('neutralises markup characters', () => {
    expect(escapeHtml('<img src=x onerror=alert(1)>')).toBe(
      '&lt;img src=x onerror=alert(1)&gt;',
    );
  });

  it('escapes quotes and ampersands', () => {
    expect(escapeHtml(`a & "b" 'c'`)).toBe('a &amp; &quot;b&quot; &#39;c&#39;');
  });
});

describe('renderDashboard', () => {
  it('produces a complete HTML document', () => {
    const html = renderDashboard(report());

    expect(html.startsWith('<!doctype html>')).toBe(true);
    expect(html).toContain('</html>');
    expect(html).toContain('depscan — demo');
  });

  it('shows the project totals as KPI values', () => {
    const html = renderDashboard(report());

    expect(html).toContain('totalPackages');
    expect(html).toContain('>2<');
  });

  it('states plainly when there are no findings', () => {
    expect(renderDashboard(report())).toContain('No known vulnerabilities found.');
  });

  it('warns loudly when the scan is incomplete', () => {
    const incomplete = report({
      meta: {
        ...report().meta,
        unresolved: [
          { raw: 'flask>=2', name: 'flask', specifier: '>=2', line: 1, reason: 'not-pinned' },
        ],
      },
      stats: { ...report().stats, unresolvedCount: 1 },
    });
    const html = renderDashboard(incomplete);

    expect(html).toContain('incomplete');
    expect(html).not.toContain('Scan complete');
  });

  it('escapes a hostile package name instead of rendering it', () => {
    const hostile = report({
      vulnerabilities: [
        {
          id: 'CVE-1',
          aliases: [],
          package: '<script>alert(1)</script>',
          installedVersion: '1.0.0',
          severity: 'high',
          cvss: null,
          summary: 'x',
          affectedRange: '<2',
          fixedVersion: '2.0.0',
          advisoryUrl: null,
          source: 'osv.dev',
        },
      ],
      stats: {
        ...report().stats,
        totalVulnerabilities: 1,
        bySeverity: { critical: 0, high: 1, medium: 0, low: 0 },
      },
    });
    const html = renderDashboard(hostile);

    expect(html).not.toContain('<script>alert(1)</script>');
    expect(html).toContain('&lt;script&gt;');
  });

  it('renders the dependency tree with direct and transitive markers', () => {
    const html = renderDashboard(report());

    expect(html).toContain('Dependency tree');
    expect(html).toContain('● a@1.0.0');
    expect(html).toContain('○ b@2.0.0');
  });
});
