// Small, dependency-free text utilities shared by the analyzers.

export interface Position {
  line: number; // 0-based
  column: number; // 0-based
}

export interface Range {
  start: number; // offset
  end: number; // offset (exclusive)
}

/** Precompute the offset at which each line starts, for fast offset→position. */
export function computeLineStarts(text: string): number[] {
  const starts = [0];
  for (let i = 0; i < text.length; i++) {
    if (text.charCodeAt(i) === 10 /* \n */) {
      starts.push(i + 1);
    }
  }
  return starts;
}

/** Convert a character offset to a 0-based {line, column} using a binary search. */
export function offsetToPosition(lineStarts: number[], offset: number): Position {
  let lo = 0;
  let hi = lineStarts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (lineStarts[mid] <= offset) {
      lo = mid;
    } else {
      hi = mid - 1;
    }
  }
  return { line: lo, column: offset - lineStarts[lo] };
}

export function isInsideRanges(offset: number, ranges: Range[]): boolean {
  for (const r of ranges) {
    if (offset >= r.start && offset < r.end) {
      return true;
    }
  }
  return false;
}

/**
 * A tiny, language-aware lexer that returns the offset ranges of comments.
 * It tracks string state (', ", `) so that a `#` or `//` inside a string is
 * not mistaken for a comment. This is a deliberate, lightweight replacement
 * for the previous "line starts with // or #" heuristic and is used for the
 * non-JS/TS languages (JS/TS get a real TypeScript-parser pass instead).
 */
export function findCommentRanges(code: string, languageId: string): Range[] {
  const ranges: Range[] = [];
  const hashLanguages = new Set(['python', 'php', 'ruby', 'shellscript', 'yaml']);
  const allowHash = hashLanguages.has(languageId);

  let i = 0;
  const n = code.length;
  let stringChar = '';

  while (i < n) {
    const c = code[i];
    const next = i + 1 < n ? code[i + 1] : '';

    // Inside a string literal: skip until the matching unescaped quote.
    if (stringChar) {
      if (c === '\\') {
        i += 2;
        continue;
      }
      if (c === stringChar) {
        stringChar = '';
      }
      i++;
      continue;
    }

    // Start of a string literal.
    if (c === '"' || c === "'" || c === '`') {
      stringChar = c;
      i++;
      continue;
    }

    // Line comment: // (most langs) or # (python/php/shell/...).
    if ((c === '/' && next === '/') || (allowHash && c === '#')) {
      const start = i;
      while (i < n && code[i] !== '\n') {
        i++;
      }
      ranges.push({ start, end: i });
      continue;
    }

    // Block comment: /* ... */
    if (c === '/' && next === '*') {
      const start = i;
      i += 2;
      while (i < n && !(code[i] === '*' && code[i + 1] === '/')) {
        i++;
      }
      i = Math.min(i + 2, n);
      ranges.push({ start, end: i });
      continue;
    }

    i++;
  }

  return ranges;
}
