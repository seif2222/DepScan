import { SEVERITIES, sortVulnerabilitiesBySeverity, type Report, type Severity } from '@depscan/core';

const RULE = '─'.repeat(64);

function pad(value: string, width: number): string {
  return value.length >= width ? value : value + ' '.repeat(width - value.length);
}

/** One line per severity, zero counts included, so an empty scan still shows the shape. */
function severityTable(bySeverity: Readonly<Record<Severity, number>>): string[] {
  return SEVERITIES.map((severity) => `  ${pad(severity, 10)}${bySeverity[severity]}`);
}

function findingLines(report: Report): string[] {
  if (report.vulnerabilities.length === 0) {
    return ['No known vulnerabilities found.'];
  }

  return sortVulnerabilitiesBySeverity(report.vulnerabilities).flatMap((v) => {
    const lines = [
      `  ${v.severity.toUpperCase()}  ${v.id}  ${v.package}@${v.installedVersion}`,
      `      affected ${v.affectedRange}   fixed-in ${v.fixedVersion ?? 'no fix published'}`,
      `      ${v.summary}`,
    ];
    if (v.advisoryUrl !== null) lines.push(`      ${v.advisoryUrl}`);
    return lines;
  });
}

function unresolvedLines(report: Report): string[] {
  const unresolved = report.meta.unresolved;
  if (unresolved.length === 0) return [];

  return [
    '',
    `Unresolved requirements (${unresolved.length}) — not checked:`,
    ...unresolved.map((u) => `  line ${u.line}  ${u.reason}  ${u.raw}`),
  ];
}

function warningLines(report: Report): string[] {
  if (report.meta.warnings.length === 0) return [];
  return ['', `Warnings (${report.meta.warnings.length}):`, ...report.meta.warnings.map((w) => `  ${w}`)];
}

/**
 * Renders a report as plain terminal text. Presentation only: every number comes from the
 * report and nothing is recomputed, per PROJECT_RULES 1.2.
 */
export function formatReport(report: Report): string[] {
  const { meta, stats } = report;
  const unresolvedNote =
    meta.unresolved.length > 0
      ? `${stats.unresolvedCount} requirement(s) could not be checked — this scan is incomplete.`
      : 'Scan complete: every requirement was checked.';

  return [
    `depscan — ${meta.projectName} (${meta.ecosystem})`,
    RULE,
    `  manifest   ${meta.manifestPath}`,
    `  generated  ${meta.generatedAt}`,
    `  tool       ${meta.tool.name} ${meta.tool.version}`,
    `  packages   ${stats.totalPackages} (${stats.directPackages} direct, ${stats.transitivePackages} transitive)`,
    '',
    `Vulnerabilities: ${stats.totalVulnerabilities}`,
    ...severityTable(stats.bySeverity),
    '',
    'Findings',
    RULE,
    ...findingLines(report),
    ...unresolvedLines(report),
    ...warningLines(report),
    '',
    unresolvedNote,
  ];
}
