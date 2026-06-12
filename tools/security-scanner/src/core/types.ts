// Shared, framework-agnostic types for the analysis core.
// Nothing here may import the `vscode` module, so the core can run
// both inside the extension and as a standalone Node CLI (CI / GitHub Action).

import type { Severity, OwaspCategory } from '../rules';

export type { Severity, OwaspCategory };

/** Which analysis engine produced a finding. */
export type Engine = 'ast' | 'regex';

/**
 * A single security finding, expressed with plain (0-based) line/column
 * coordinates so it can be mapped to a `vscode.Diagnostic` or serialised
 * to SARIF without depending on the editor API.
 */
export interface Finding {
  ruleId: string;
  name: string;
  message: string;
  severity: Severity;
  owasp: OwaspCategory;
  cwe: string;
  recommendation: string;
  /** 0-based start position. */
  line: number;
  column: number;
  /** 0-based end position. */
  endLine: number;
  endColumn: number;
  /** Exact source text the rule matched. */
  matchedText: string;
  /** Engine that produced the finding. */
  engine: Engine;
  /** ML-estimated probability that this is a real vulnerability (0..1). */
  confidence: number;
  /** True if the ML classifier judged this a likely false positive. */
  suppressed: boolean;
}

/** Input document for the engine. */
export interface AnalyzeInput {
  code: string;
  /** VS Code-style languageId: javascript, typescript, python, java, go, php, c, cpp. */
  languageId: string;
  /** Optional path — used by the ML classifier as a contextual feature. */
  filePath?: string;
}

export interface EngineOptions {
  /** Run the ML false-positive classifier (default: true). */
  useMl?: boolean;
  /** Findings with confidence below this threshold are suppressed (default: 0.5). */
  mlThreshold?: number;
  /** Lowest severity to report (default: 'low' = everything). */
  minSeverity?: Severity;
  /** Rule ids to skip entirely. */
  disabledRules?: Set<string>;
  /** If non-empty, only these rule ids run. */
  enabledRules?: Set<string>;
  /** Keep suppressed findings in the result (marked `suppressed: true`). Default: false. */
  includeSuppressed?: boolean;
}
