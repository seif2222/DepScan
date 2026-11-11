import { SEVERITIES, sortVulnerabilitiesBySeverity, type Report, type Severity } from '@depscan/core';

const RULE = '─'.repeat(64);

/** One line per severity, zero counts included. */
function severityTable(bySeverity: Readonly<Record<Severity, number>>): string[] {
  return SEVERITIES.map((severity) => `  ${severity.padEnd(10)}${bySeverity[severity]}`);
}

function findingLines(report: Report): string[] {
  if (report.vulnerabilities.length === 0) return ['No known vulnerabilities found.'];

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
  if (report.meta.unresolved.length === 0) return [];
  return [
    '',
    `Unresolved requirements (${report.meta.unresolved.length}) — not checked:`,
    ...report.meta.unresolved.map((u) => `  line ${u.line}  ${u.reason}  ${u.raw}`),
  ];
}

/**
 * Renders a report as plain terminal text. Presentation only: every number comes from the
 * report and nothing is recomputed, per PROJECT_RULES 1.2.
 */
export function formatReport(report: Report): string[] {
  const { meta, stats } = report;
  const completeness =
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
    '',
    completeness,
  ];
}
