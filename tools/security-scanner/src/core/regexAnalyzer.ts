// Regex-based analyzer. Used for languages without a dedicated AST pass
// (Python, Java, Go, PHP, C/C++) and as a comment-masked fallback for the
// JS/TS rules that are not covered by a semantic AST detector.

import type { SecurityRule } from '../rules';
import type { Finding } from './types';
import { offsetToPosition, isInsideRanges, Range } from './text';

/**
 * Run the given rules over `code`, skipping any match that begins inside a
 * comment range. Returns raw findings (engine = 'regex'); ML scoring is
 * applied later by the engine.
 */
export function runRegexRules(
  code: string,
  lineStarts: number[],
  rules: SecurityRule[],
  commentRanges: Range[],
): Finding[] {
  const findings: Finding[] = [];

  for (const rule of rules) {
    // Defensive: ensure the regex is global so exec() advances.
    const flags = rule.pattern.flags.includes('g') ? rule.pattern.flags : rule.pattern.flags + 'g';
    const re = new RegExp(rule.pattern.source, flags);

    let match: RegExpExecArray | null;
    while ((match = re.exec(code)) !== null) {
      // Guard against zero-length matches causing an infinite loop.
      if (match[0].length === 0) {
        re.lastIndex++;
        continue;
      }

      const startOffset = match.index;
      if (isInsideRanges(startOffset, commentRanges)) {
        continue;
      }

      const endOffset = startOffset + match[0].length;
      const start = offsetToPosition(lineStarts, startOffset);
      const end = offsetToPosition(lineStarts, endOffset);

      findings.push({
        ruleId: rule.id,
        name: rule.name,
        message: rule.message,
        severity: rule.severity,
        owasp: rule.owasp,
        cwe: rule.cwe,
        recommendation: rule.recommendation,
        line: start.line,
        column: start.column,
        endLine: end.line,
        endColumn: end.column,
        matchedText: match[0],
        engine: 'regex',
        confidence: 1,
        suppressed: false,
      });
    }
  }

  return findings;
}
