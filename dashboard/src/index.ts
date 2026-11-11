import { readFileSync } from 'node:fs';

import { validateReport, type Report } from '@depscan/core';

export { renderDashboard, escapeHtml } from './render.js';

export type LoadResult =
  | { readonly ok: true; readonly report: Report }
  | { readonly ok: false; readonly error: string };

/**
 * Reads and validates a report.json produced by the engine. The dashboard refuses to render
 * anything that fails validation, so a malformed report is reported instead of drawn wrong.
 */
export function loadReport(path: string): LoadResult {
  let text: string;
  try {
    text = readFileSync(path, 'utf8');
  } catch (error) {
    const detail = error instanceof Error ? error.message : 'cannot read file';
    return { ok: false, error: `cannot read ${path}: ${detail}` };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(text) as unknown;
  } catch (error) {
    const detail = error instanceof Error ? error.message : 'invalid JSON';
    return { ok: false, error: `${path} is not valid JSON: ${detail}` };
  }

  const result = validateReport(parsed);
  if (!result.ok) {
    const first = result.issues[0];
    const where = first === undefined ? '' : ` at ${first.path}: ${first.message}`;
    return { ok: false, error: `${path} failed report validation${where}` };
  }

  return { ok: true, report: result.report };
}
