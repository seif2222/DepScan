# P06 — Complete the CLI terminal and the dashboard

## Summary

The empty `core/src/analyze.ts` now orchestrates the deterministic pipeline (parse, match,
stats) into a `Report`, and it is exported from `@depscan/core`. The CLI stub was replaced by
a real `depscan analyze <dir>` command with `--json`, `--out`, `--offline` and `--fail-on`,
plus severity-threshold exit code 2. The dashboard package, previously a placeholder, now
loads and validates a `report.json` and renders a self-contained HTML viewer with KPI tiles,
a findings table and a dependency tree. No analysis logic was added outside `core`.

## Files created/changed

| Path | Status | Purpose |
| ---- | ------ | ------- |
| `core/src/analyze.ts` | changed | Parse → match → stats pipeline returning a `Report` |
| `core/src/analyze.test.ts` | created | Pipeline tests driven by the recorded OSV fixtures |
| `core/src/index.ts` | changed | Exports `analyze` and `AnalyzeOptions` |
| `cli/src/index.ts` | changed | `analyze` command, argument parsing, exit codes |
| `cli/src/format.ts` | created | Terminal rendering of a report |
| `cli/src/index.test.ts` | changed | Argument and failure-path tests |
| `cli/src/format.test.ts` | created | Formatter tests |
| `cli/src/bin.ts` | changed | Awaits the now-async `runCli` |
| `dashboard/package.json` | changed | Real package with build/test/render scripts |
| `dashboard/src/render.ts` | created | Self-contained HTML viewer |
| `dashboard/src/index.ts` | created | Loads and validates a report before rendering |
| `dashboard/src/bin.ts` | created | `depscan-dashboard <report.json> [out.html]` |
| `dashboard/src/render.test.ts` | created | Rendering and escaping tests |
| `dashboard/tsconfig.json`, `tsconfig.build.json`, `vitest.config.ts` | created | Build and test config |
| `tsconfig.json` | changed | Adds the dashboard to the root build |

## Decisions made and why

- **`analyze` requires an injected timestamp.** §1.5 forbids reading the clock in engine
  code, so `generatedAt` (or `now`) is mandatory and a missing value throws `TypeError`.
- **`risk` and `suggestions` stay empty.** No deterministic scoring rule exists yet and
  `suggestions[].provider` is engine-forbidden, so both sections are empty, which
  `docs/p05-decisions.md` explicitly permits.
- **The dashboard validates before rendering.** A report that fails `validateReport` is
  reported, not drawn; the viewer never re-analyses, re-scores or re-ranks.
- **`cli/src/index.test.ts` was updated.** The old test asserted `analyze extra` returned 1;
  that command was a stub, and `extra` is now an unexpected second positional. The new test
  keeps the same rejection with `analyze one two`.
- **An unidentified advisory becomes a warning, not a failure.** `p05-decisions` §2 requires a
  documented exception rather than an invented id or a failed run.

## How to verify

These commands are provided but were **not executed in this environment** (no shell access).
Run them before merging; do not treat the expected results below as observed output.

```bash
pnpm install
pnpm build     # tsc -b must compile core, cli and dashboard
pnpm test      # all suites pass
pnpm lint      # zero errors

node ./cli/dist/bin.js analyze ./fixtures/projects/clean-npm/spec  # see note
pnpm --filter @depscan/cli start analyze ./fixtures/projects/clean-npm
pnpm --filter @depscan/dashboard render ./report.json ./dashboard.html
```

## Test results

Not run here. `core/src/analyze.test.ts` expects `clean-npm` to yield 12 packages, 4 direct,
8 transitive, 0 findings, and to keep `ms@2.1.2` and `ms@2.1.3` apart, matching
`fixtures/projects/clean-npm/EXPECTED.md`. CLI and dashboard suites assert parsing, exit
codes, formatting, KPI output and HTML escaping.

## Problems or deviations from the prompt

- **No command output could be captured.** `PROJECT_RULES` §3.1 requires real, copied output;
  this environment has no shell, so the section above is unexecuted. This is the one
  outstanding §3 requirement.
- **Stray probe files remain on the branch** — `.depscan-write-probe*.txt` and
  `.depscan-write-probe-*.ts` — left over from diagnosing a write failure. Delete them before
  merging.
- **The `vulnerable-npm` fixture is still missing**, so the 10-row and PyPI merge cases from
  `p05-decisions` §3 are not yet covered end to end by a committed project.
- `--fail-on` compares with `compareSeverity`, which ranks by label; it does not consult
  `risk`, which is unpopulated.

## Ready for P07? (yes, with conditions)

yes — the pipeline, CLI and viewer are implemented and test-backed. Before P07: run
`pnpm verify`, delete the probe files, and decide whether the dashboard should gain an
interactive filter (currently a static, dependency-free page).
