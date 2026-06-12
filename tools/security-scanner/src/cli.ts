#!/usr/bin/env node
// Standalone command-line scanner — the headless twin of the VS Code extension.
// Shares the exact same analysis core (AST + regex + ML), so CI results match
// what developers see in their editor. Used by the GitHub Action and the
// pre-commit hook. Does NOT import `vscode`.
//
//   owasp-checker [paths...] [options]
//
//   --sarif <file>          write SARIF 2.1.0 report
//   --min-severity <sev>    critical|high|medium|low (default: low)
//   --fail-on <sev>         fail (exit 1) if a finding ≥ this severity (default: high)
//   --no-ml                 disable the ML false-positive classifier
//   --include-suppressed    also list ML-suppressed findings
//   --json                  print findings as JSON
//   --quiet                 only print the summary line
//   --help                  show this help

import * as fs from 'fs';
import * as path from 'path';
import { analyze } from './core/engine';
import type { Finding, Severity } from './core/types';
import { SEVERITY_ORDER } from './rules';

const EXT_TO_LANG: Record<string, string> = {
  '.js': 'javascript', '.mjs': 'javascript', '.cjs': 'javascript',
  '.jsx': 'javascriptreact',
  '.ts': 'typescript', '.mts': 'typescript', '.cts': 'typescript',
  '.tsx': 'typescriptreact',
  '.py': 'python',
  '.java': 'java',
  '.go': 'go',
  '.php': 'php',
  '.c': 'c', '.h': 'c',
  '.cpp': 'cpp', '.cc': 'cpp', '.cxx': 'cpp', '.hpp': 'cpp', '.hh': 'cpp',
};

const DEFAULT_EXCLUDES = new Set([
  'node_modules', '.git', 'dist', 'build', 'out', 'vendor', '.next', 'coverage',
]);

interface CliOptions {
  paths: string[];
  sarif?: string;
  minSeverity: Severity;
  failOn: Severity;
  useMl: boolean;
  includeSuppressed: boolean;
  json: boolean;
  quiet: boolean;
}

function parseArgs(argv: string[]): CliOptions | 'help' {
  const opts: CliOptions = {
    paths: [],
    minSeverity: 'low',
    failOn: 'high',
    useMl: true,
    includeSuppressed: false,
    json: false,
    quiet: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case '--help': case '-h': return 'help';
      case '--sarif': opts.sarif = argv[++i]; break;
      case '--min-severity': opts.minSeverity = argv[++i] as Severity; break;
      case '--fail-on': opts.failOn = argv[++i] as Severity; break;
      case '--no-ml': opts.useMl = false; break;
      case '--include-suppressed': opts.includeSuppressed = true; break;
      case '--json': opts.json = true; break;
      case '--quiet': opts.quiet = true; break;
      default:
        if (a.startsWith('--')) {
          console.error(`Unknown option: ${a}`);
          return 'help';
        }
        opts.paths.push(a);
    }
  }
  if (opts.paths.length === 0) { opts.paths.push('.'); }
  return opts;
}

function walk(target: string, acc: string[]): void {
  let stat: fs.Stats;
  try { stat = fs.statSync(target); } catch { return; }
  if (stat.isDirectory()) {
    if (DEFAULT_EXCLUDES.has(path.basename(target))) { return; }
    for (const entry of fs.readdirSync(target)) {
      walk(path.join(target, entry), acc);
    }
  } else if (stat.isFile()) {
    if (EXT_TO_LANG[path.extname(target).toLowerCase()]) { acc.push(target); }
  }
}

interface FileFindings { file: string; findings: Finding[]; }

function scan(opts: CliOptions): FileFindings[] {
  const files: string[] = [];
  for (const p of opts.paths) { walk(p, files); }

  const out: FileFindings[] = [];
  for (const file of files) {
    const languageId = EXT_TO_LANG[path.extname(file).toLowerCase()];
    let code: string;
    try { code = fs.readFileSync(file, 'utf8'); } catch { continue; }
    const findings = analyze(
      { code, languageId, filePath: file },
      {
        useMl: opts.useMl,
        minSeverity: opts.minSeverity,
        includeSuppressed: opts.includeSuppressed,
      },
    );
    if (findings.length > 0) { out.push({ file, findings }); }
  }
  return out;
}

const SEV_LABEL: Record<Severity, string> = {
  critical: '\x1b[31mCRITICAL\x1b[0m',
  high: '\x1b[33mHIGH\x1b[0m',
  medium: '\x1b[36mMEDIUM\x1b[0m',
  low: '\x1b[34mLOW\x1b[0m',
};

const SARIF_LEVEL: Record<Severity, string> = {
  critical: 'error', high: 'error', medium: 'warning', low: 'note',
};

function buildSarif(results: FileFindings[]): string {
  const sarifResults = results.flatMap(({ file, findings }) =>
    findings.map((f) => ({
      ruleId: f.ruleId,
      level: SARIF_LEVEL[f.severity],
      message: { text: f.message },
      locations: [{
        physicalLocation: {
          artifactLocation: { uri: file.replace(/\\/g, '/') },
          region: {
            startLine: f.line + 1,
            startColumn: f.column + 1,
            endLine: f.endLine + 1,
            endColumn: f.endColumn + 1,
          },
        },
      }],
      properties: {
        severity: f.severity,
        cwe: f.cwe,
        owasp: f.owasp,
        confidence: Math.round(f.confidence * 100) / 100,
        engine: f.engine,
        suppressed: f.suppressed,
      },
    })),
  );

  return JSON.stringify({
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'OWASP Security Checker',
          informationUri: 'https://owasp.org/Top10/',
          version: '0.2.0',
          rules: [],
        },
      },
      results: sarifResults,
    }],
  }, null, 2);
}

function printHelp(): void {
  console.log(`OWASP Security Checker — CLI

Usage: owasp-checker [paths...] [options]

  --sarif <file>          write SARIF 2.1.0 report
  --min-severity <sev>    critical|high|medium|low (default: low)
  --fail-on <sev>         exit 1 if a finding ≥ this severity (default: high)
  --no-ml                 disable the ML false-positive classifier
  --include-suppressed    also list ML-suppressed findings
  --json                  print findings as JSON
  --quiet                 only print the summary line
  --help                  show this help`);
}

function main(): void {
  const parsed = parseArgs(process.argv.slice(2));
  if (parsed === 'help') { printHelp(); process.exit(0); }
  const opts = parsed;

  const results = scan(opts);

  if (opts.sarif) {
    fs.writeFileSync(opts.sarif, buildSarif(results), 'utf8');
  }

  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  let total = 0;
  for (const { findings } of results) {
    for (const f of findings) { counts[f.severity]++; total++; }
  }

  if (opts.json) {
    console.log(JSON.stringify(results, null, 2));
  } else if (!opts.quiet) {
    for (const { file, findings } of results) {
      console.log(`\n\x1b[1m${file}\x1b[0m`);
      for (const f of findings) {
        const conf = f.confidence < 1 ? ` (conf ${Math.round(f.confidence * 100)}%)` : '';
        console.log(
          `  ${f.line + 1}:${f.column + 1}  ${SEV_LABEL[f.severity]}  ${f.cwe} ${f.ruleId}  [${f.engine}]${conf}\n      ${f.message}`,
        );
      }
    }
  }

  console.log(
    `\n${total === 0 ? '\x1b[32m✓ No findings\x1b[0m' : `Found ${total}`} ` +
    `(critical: ${counts.critical}, high: ${counts.high}, medium: ${counts.medium}, low: ${counts.low})` +
    `${opts.sarif ? `  ·  SARIF → ${opts.sarif}` : ''}`,
  );

  const failOrder = SEVERITY_ORDER[opts.failOn];
  let shouldFail = false;
  for (const sev of Object.keys(counts) as Severity[]) {
    if (counts[sev] > 0 && SEVERITY_ORDER[sev] <= failOrder) { shouldFail = true; }
  }
  process.exit(shouldFail ? 1 : 0);
}

main();
