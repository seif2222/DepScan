import { buildTree, isSeverity, sortVulnerabilitiesBySeverity, type Report } from '@depscan/core';

/** Escapes text for HTML so a package name from a manifest cannot inject markup. */
export function escapeHtml(value: string): string {
  return value
    .replace(/&/gu, '&amp;')
    .replace(/</gu, '&lt;')
    .replace(/>/gu, '&gt;')
    .replace(/"/gu, '&quot;')
    .replace(/'/gu, '&#39;');
}

function severityClass(value: string): string {
  return isSeverity(value) ? `sev-${value}` : 'sev-unknown';
}

function kpi(label: string, value: number, tone: string): string {
  return `<div class="kpi ${tone}"><span class="kpi-value">${value}</span><span class="kpi-label">${escapeHtml(label)}</span></div>`;
}

function findingRow(v: Report['vulnerabilities'][number]): string {
  const advisory =
    v.advisoryUrl === null
      ? ''
      : ` <a href="${escapeHtml(v.advisoryUrl)}" rel="noreferrer noopener">advisory</a>`;
  return [
    '<tr>',
    `<td>${escapeHtml(v.id)}</td>`,
    `<td><span class="pill ${severityClass(v.severity)}">${escapeHtml(v.severity)}</span></td>`,
    `<td>${escapeHtml(v.package)}@${escapeHtml(v.installedVersion)}</td>`,
    `<td>${escapeHtml(v.affectedRange)}</td>`,
    `<td>${v.fixedVersion === null ? '<em>no fix</em>' : escapeHtml(v.fixedVersion)}</td>`,
    `<td>${escapeHtml(v.summary)}${advisory}</td>`,
    '</tr>',
  ].join('');
}

function treeLines(report: Report): string[] {
  const tree = buildTree(report.packages);
  const lines: string[] = [];
  const walk = (id: string, depth: number, seen: ReadonlySet<string>): void => {
    const node = tree.nodes.get(id);
    if (node === undefined || seen.has(id)) return;
    const mark = node.isDirect ? '●' : '○';
    lines.push(`${'  '.repeat(depth)}${mark} ${node.name}@${node.version}`);
    const next = new Set(seen).add(id);
    for (const childId of node.childIds) walk(childId, depth + 1, next);
  };
  for (const id of tree.rootIds) walk(id, 0, new Set());
  return lines;
}

/**
 * Renders a report as one self-contained HTML page. This is a viewer: it reads the report,
 * sorts and formats it, and never re-analyses, re-scores or re-ranks anything.
 */
export function renderDashboard(report: Report): string {
  const { meta, stats } = report;
  const findings = sortVulnerabilitiesBySeverity(report.vulnerabilities);
  const unresolved = meta.unresolved;

  const completeness =
    unresolved.length > 0
      ? `<p class="alert">${unresolved.length} requirement(s) could not be checked — this scan is <strong>incomplete</strong>. Do not treat it as clean.</p>`
      : '<p class="ok">Scan complete: every requirement was checked.</p>';

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>depscan — ${escapeHtml(meta.projectName)}</title>
<style>
  :root { color-scheme: dark; }
  body { margin: 0; font: 15px/1.5 ui-sans-serif, system-ui, sans-serif; background: #0f1115; color: #e6e8eb; }
  main { max-width: 1080px; margin: 0 auto; padding: 32px 20px 64px; }
  h1 { font-size: 22px; margin: 0 0 4px; }
  .sub { color: #9aa4b2; margin: 0 0 24px; }
  .kpis { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin-bottom: 24px; }
  .kpi { background: #171a21; border: 1px solid #242a34; border-radius: 10px; padding: 14px; display: flex; flex-direction: column; }
  .kpi-value { font-size: 26px; font-weight: 700; }
  .kpi-label { color: #9aa4b2; font-size: 13px; }
  table { width: 100%; border-collapse: collapse; background: #171a21; border-radius: 10px; overflow: hidden; }
  th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid #242a34; vertical-align: top; }
  th { background: #1d222b; font-size: 13px; color: #9aa4b2; }
  .pill { padding: 2px 8px; border-radius: 999px; font-size: 12px; font-weight: 600; }
  .sev-critical { background: #6b1220; color: #ffd7de; }
  .sev-high { background: #6b3312; color: #ffe3cf; }
  .sev-medium { background: #5c4a12; color: #fff2c4; }
  .sev-low { background: #1d3b52; color: #d3ecff; }
  .sev-unknown { background: #2a2f38; color: #cbd5e1; }
  pre { background: #171a21; border: 1px solid #242a34; border-radius: 10px; padding: 14px; overflow: auto; }
  a { color: #7cc4ff; }
  .alert { background: #3a2412; border: 1px solid #6b4a12; padding: 10px 12px; border-radius: 8px; }
  .ok { color: #7fd6a0; }
  .empty { color: #9aa4b2; padding: 16px; background: #171a21; border-radius: 10px; }
  section { margin-top: 28px; }
  h2 { font-size: 16px; }
</style>
</head>
<body>
<main>
  <h1>depscan — ${escapeHtml(meta.projectName)}</h1>
  <p class="sub">${escapeHtml(meta.ecosystem)} · ${escapeHtml(meta.manifestPath)} · generated ${escapeHtml(meta.generatedAt)} · ${escapeHtml(meta.tool.name)} ${escapeHtml(meta.tool.version)}</p>
  ${completeness}
  <section class="kpis">
    ${kpi('Packages', stats.totalPackages, '')}
    ${kpi('Direct', stats.directPackages, '')}
    ${kpi('Transitive', stats.transitivePackages, '')}
    ${kpi('Critical', stats.bySeverity.critical, 'sev-critical')}
    ${kpi('High', stats.bySeverity.high, 'sev-high')}
    ${kpi('Medium', stats.bySeverity.medium, 'sev-medium')}
    ${kpi('Low', stats.bySeverity.low, 'sev-low')}
    ${kpi('Unresolved', stats.unresolvedCount, '')}
  </section>
  <section>
    <h2>Findings (${findings.length})</h2>
    ${
      findings.length === 0
        ? '<p class="empty">No known vulnerabilities found.</p>'
        : `<table><thead><tr><th>Id</th><th>Severity</th><th>Package</th><th>Affected</th><th>Fixed in</th><th>Summary</th></tr></thead><tbody>${findings
            .map(findingRow)
            .join('')}</tbody></table>`
    }
  </section>
  <section>
    <h2>Dependency tree</h2>
    <pre>${escapeHtml(treeLines(report).join('\n'))}</pre>
  </section>
  ${
    unresolved.length === 0
      ? ''
      : `<section><h2>Unresolved requirements</h2><pre>${escapeHtml(
          unresolved.map((u) => `line ${u.line}  ${u.reason}  ${u.raw}`).join('\n'),
        )}</pre></section>`
  }
  ${
    meta.warnings.length === 0
      ? ''
      : `<section><h2>Warnings</h2><pre>${escapeHtml(meta.warnings.join('\n'))}</pre></section>`
  }
</main>
</body>
</html>
`;
}
