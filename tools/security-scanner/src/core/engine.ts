// Analysis engine: picks the right analyzer per language, then applies the
// ML false-positive classifier. This is the single entry point used by both
// the VS Code providers and the standalone CLI — neither imports `vscode`
// transitively through here.

import { SEVERITY_ORDER, getRulesForLanguage } from '../rules';
import { Finding, AnalyzeInput, EngineOptions, Severity } from './types';
import { computeLineStarts, findCommentRanges } from './text';
import { runRegexRules } from './regexAnalyzer';
import { analyzeJsTs, getCommentRanges, SEMANTIC_RULE_IDS } from './astAnalyzer';
import { classify } from './ml/classifier';

const JS_TS_LANGS = new Set([
  'javascript', 'typescript', 'javascriptreact', 'typescriptreact',
]);

function baseLanguage(languageId: string): string {
  if (languageId === 'typescriptreact') { return 'typescript'; }
  if (languageId === 'javascriptreact') { return 'javascript'; }
  return languageId;
}

/**
 * Analyze one document and return findings. JS/TS use the AST analyzer for the
 * core rules plus a comment-masked regex fallback for the rest; every other
 * language uses the regex analyzer. The ML classifier then scores each finding
 * and (unless `includeSuppressed`) drops likely false positives.
 */
export function analyze(input: AnalyzeInput, options: EngineOptions = {}): Finding[] {
  const { code, languageId, filePath } = input;
  const useMl = options.useMl !== false;
  const threshold = options.mlThreshold ?? 0.5;
  const minOrder = SEVERITY_ORDER[options.minSeverity ?? 'low'];
  const disabled = options.disabledRules ?? new Set<string>();
  const enabled = options.enabledRules ?? new Set<string>();
  const includeSuppressed = options.includeSuppressed ?? false;

  const lineStarts = computeLineStarts(code);

  const ruleAllowed = (id: string, severity: Severity): boolean => {
    if (disabled.has(id)) { return false; }
    if (enabled.size > 0 && !enabled.has(id)) { return false; }
    if (SEVERITY_ORDER[severity] > minOrder) { return false; }
    return true;
  };

  let raw: Finding[] = [];

  if (JS_TS_LANGS.has(languageId)) {
    const semantic = analyzeJsTs(code, languageId, lineStarts).filter((f) =>
      ruleAllowed(f.ruleId, f.severity),
    );

    const commentRanges = getCommentRanges(code, languageId);
    const fallbackRules = getRulesForLanguage(baseLanguage(languageId)).filter(
      (r) => !SEMANTIC_RULE_IDS.has(r.id) && ruleAllowed(r.id, r.severity),
    );
    const fallback = runRegexRules(code, lineStarts, fallbackRules, commentRanges);

    raw = [...semantic, ...fallback];
  } else {
    const commentRanges = findCommentRanges(code, languageId);
    const rules = getRulesForLanguage(languageId).filter((r) => ruleAllowed(r.id, r.severity));
    raw = runRegexRules(code, lineStarts, rules, commentRanges);
  }

  // --- ML scoring -----------------------------------------------------------
  const lines = code.split(/\r?\n/);
  const results: Finding[] = [];

  for (const f of raw) {
    let confidence = 1;
    let suppressed = false;

    if (useMl) {
      const lineText = lines[f.line] ?? '';
      const c = classify(
        { ruleId: f.ruleId, severity: f.severity, matchedText: f.matchedText, lineText, filePath },
        threshold,
      );
      confidence = c.confidence;
      suppressed = !c.isVulnerable;
    }

    if (suppressed && !includeSuppressed) { continue; }
    results.push({ ...f, confidence, suppressed });
  }

  results.sort((a, b) => a.line - b.line || a.column - b.column);
  return results;
}
