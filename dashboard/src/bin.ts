#!/usr/bin/env node
import { writeFileSync } from 'node:fs';

import { loadReport, renderDashboard } from './index.js';

const [reportPath, outPath] = process.argv.slice(2);

if (reportPath === undefined) {
  console.error('Usage: depscan-dashboard <report.json> [out.html]');
  process.exitCode = 1;
} else {
  const loaded = loadReport(reportPath);
  if (!loaded.ok) {
    console.error(loaded.error);
    process.exitCode = 1;
  } else {
    const html = renderDashboard(loaded.report);
    if (outPath === undefined) {
      process.stdout.write(html);
    } else {
      writeFileSync(outPath, html, 'utf8');
      console.log(`Wrote dashboard to ${outPath}`);
    }
  }
}
