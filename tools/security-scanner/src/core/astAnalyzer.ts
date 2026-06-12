// AST-based analyzer for JavaScript / TypeScript.
//
// This replaces brittle regular expressions with a real parse tree produced by
// the TypeScript Compiler API (`ts.createSourceFile`). Working on the AST gives
// two concrete advantages over the regex engine:
//
//   1. Comments and string literals are real tokens, so vulnerable-looking text
//      inside a `// comment` or a log message string never produces a finding.
//   2. Detectors match *semantic shapes* (a call to `createHash` whose first
//      argument is the string "md5") rather than character patterns, which is
//      far more precise and resistant to formatting differences.
//
// Rules that have a semantic detector here are listed in SEMANTIC_RULE_IDS.
// All other JS/TS rules are run by the regex engine, but only over code that is
// NOT inside a comment range (the comment ranges are extracted from the same
// TypeScript scanner), which removes the most common class of regex false
// positives without re-implementing every rule.

import * as ts from 'typescript';
import { getRuleById } from '../rules';
import type { Finding } from './types';
import { offsetToPosition, Range } from './text';

/** Rule ids handled by a dedicated semantic detector below. */
export const SEMANTIC_RULE_IDS = new Set<string>([
  'crypto-md5-hash',
  'crypto-sha1-hash',
  'crypto-md5-require',
  'crypto-math-random',
  'crypto-hardcoded-secret',
  'crypto-ssl-no-verify',
  'crypto-node-tls-reject',
  'crypto-http-url',
  'jwt-alg-none',
  'auth-cors-wildcard',
  'auth-cookie-httponly',
  'auth-cookie-secure',
]);

const SECRET_NAME_RE =
  /(password|passwd|secret|api_?key|apikey|auth_?token|private_?key|jwt_?secret)/i;

function scriptKindFor(languageId: string): ts.ScriptKind {
  switch (languageId) {
    case 'typescriptreact': return ts.ScriptKind.TSX;
    case 'javascriptreact': return ts.ScriptKind.JSX;
    case 'javascript': return ts.ScriptKind.JS;
    default: return ts.ScriptKind.TS;
  }
}

/** Collect comment token ranges using the TypeScript scanner. */
export function getCommentRanges(code: string, languageId: string): Range[] {
  const variant =
    languageId === 'typescriptreact' || languageId === 'javascriptreact'
      ? ts.LanguageVariant.JSX
      : ts.LanguageVariant.Standard;
  const scanner = ts.createScanner(ts.ScriptTarget.Latest, /* skipTrivia */ false, variant, code);
  const ranges: Range[] = [];
  let token: ts.SyntaxKind;
  while ((token = scanner.scan()) !== ts.SyntaxKind.EndOfFileToken) {
    if (
      token === ts.SyntaxKind.SingleLineCommentTrivia ||
      token === ts.SyntaxKind.MultiLineCommentTrivia
    ) {
      ranges.push({ start: scanner.getTokenStart(), end: scanner.getTextPos() });
    }
  }
  return ranges;
}

function getStringValue(node: ts.Expression): string | undefined {
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
    return node.text;
  }
  return undefined;
}

/** Run the semantic detectors over the JS/TS source. */
export function analyzeJsTs(code: string, languageId: string, lineStarts: number[]): Finding[] {
  const sourceFile = ts.createSourceFile(
    'input',
    code,
    ts.ScriptTarget.Latest,
    /* setParentNodes */ true,
    scriptKindFor(languageId),
  );

  const findings: Finding[] = [];

  function emit(ruleId: string, start: number, end: number, matchedText: string): void {
    const rule = getRuleById(ruleId);
    if (!rule) { return; }
    const s = offsetToPosition(lineStarts, start);
    const e = offsetToPosition(lineStarts, end);
    findings.push({
      ruleId: rule.id,
      name: rule.name,
      message: rule.message,
      severity: rule.severity,
      owasp: rule.owasp,
      cwe: rule.cwe,
      recommendation: rule.recommendation,
      line: s.line,
      column: s.column,
      endLine: e.line,
      endColumn: e.column,
      matchedText,
      engine: 'ast',
      confidence: 1,
      suppressed: false,
    });
  }

  function visit(node: ts.Node): void {
    // --- Hash algorithms: createHash('md5' | 'sha1') --------------------
    if (ts.isCallExpression(node)) {
      const callee = node.expression;

      // crypto.createHash('md5') / createHash('sha1')
      if (
        ts.isPropertyAccessExpression(callee) &&
        callee.name.text === 'createHash' &&
        node.arguments.length > 0
      ) {
        const alg = getStringValue(node.arguments[0])?.toLowerCase();
        if (alg === 'md5') {
          emit('crypto-md5-hash', node.getStart(sourceFile), node.getEnd(), node.getText(sourceFile));
        } else if (alg === 'sha1') {
          emit('crypto-sha1-hash', node.getStart(sourceFile), node.getEnd(), node.getText(sourceFile));
        }
      }

      // require('md5')
      if (
        ts.isIdentifier(callee) &&
        callee.text === 'require' &&
        node.arguments.length > 0 &&
        getStringValue(node.arguments[0])?.toLowerCase() === 'md5'
      ) {
        emit('crypto-md5-require', node.getStart(sourceFile), node.getEnd(), node.getText(sourceFile));
      }

      // Math.random()
      if (
        ts.isPropertyAccessExpression(callee) &&
        ts.isIdentifier(callee.expression) &&
        callee.expression.text === 'Math' &&
        callee.name.text === 'random'
      ) {
        emit('crypto-math-random', node.getStart(sourceFile), node.getEnd(), node.getText(sourceFile));
      }

      // res.cookie(name, value, { ... }) — flag missing HttpOnly / Secure flags.
      if (ts.isPropertyAccessExpression(callee) && callee.name.text === 'cookie') {
        const last = node.arguments[node.arguments.length - 1];
        let hasHttpOnly = false;
        let hasSecure = false;
        if (last && ts.isObjectLiteralExpression(last)) {
          for (const prop of last.properties) {
            if (ts.isPropertyAssignment(prop)) {
              const key = ts.isIdentifier(prop.name) || ts.isStringLiteral(prop.name) ? prop.name.text : '';
              if (key.toLowerCase() === 'httponly' && prop.initializer.kind === ts.SyntaxKind.TrueKeyword) {
                hasHttpOnly = true;
              }
              if (key.toLowerCase() === 'secure' && prop.initializer.kind === ts.SyntaxKind.TrueKeyword) {
                hasSecure = true;
              }
            }
          }
        }
        if (!hasHttpOnly) {
          emit('auth-cookie-httponly', node.getStart(sourceFile), node.getEnd(), node.getText(sourceFile));
        }
        if (!hasSecure) {
          emit('auth-cookie-secure', node.getStart(sourceFile), node.getEnd(), node.getText(sourceFile));
        }
      }

      // res.setHeader('Access-Control-Allow-Origin', '*')
      if (
        ts.isPropertyAccessExpression(callee) &&
        callee.name.text === 'setHeader' &&
        node.arguments.length >= 2 &&
        getStringValue(node.arguments[0])?.toLowerCase() === 'access-control-allow-origin' &&
        getStringValue(node.arguments[1]) === '*'
      ) {
        emit('auth-cors-wildcard', node.getStart(sourceFile), node.getEnd(), node.getText(sourceFile));
      }
    }

    // --- JWT alg:none and CORS origin:'*' object properties --------------
    if (ts.isPropertyAssignment(node) && (ts.isIdentifier(node.name) || ts.isStringLiteral(node.name))) {
      const key = node.name.text.toLowerCase();

      if ((key === 'alg' || key === 'algorithm') && getStringValue(node.initializer)?.toLowerCase() === 'none') {
        emit('jwt-alg-none', node.getStart(sourceFile), node.getEnd(), node.getText(sourceFile));
      }
      // algorithms: ['none']
      if (key === 'algorithms' && ts.isArrayLiteralExpression(node.initializer)) {
        const hasNone = node.initializer.elements.some(
          (el) => getStringValue(el)?.toLowerCase() === 'none',
        );
        if (hasNone) {
          emit('jwt-alg-none', node.getStart(sourceFile), node.getEnd(), node.getText(sourceFile));
        }
      }
      // origin: '*'
      if (key === 'origin' && getStringValue(node.initializer) === '*') {
        emit('auth-cors-wildcard', node.getStart(sourceFile), node.getEnd(), node.getText(sourceFile));
      }
    }

    // --- Hardcoded secrets: const SECRET = "literal" -------------------
    if (ts.isVariableDeclaration(node) && node.initializer && ts.isIdentifier(node.name)) {
      const value = getStringValue(node.initializer);
      if (value !== undefined && value.length >= 8 && SECRET_NAME_RE.test(node.name.text)) {
        emit(
          'crypto-hardcoded-secret',
          node.initializer.getStart(sourceFile),
          node.initializer.getEnd(),
          node.initializer.getText(sourceFile),
        );
      }
    }

    // PropertyAssignment: { apiKey: "literal" }
    if (ts.isPropertyAssignment(node) && (ts.isIdentifier(node.name) || ts.isStringLiteral(node.name))) {
      const key = ts.isIdentifier(node.name) ? node.name.text : node.name.text;
      const value = getStringValue(node.initializer);
      if (value !== undefined && value.length >= 8 && SECRET_NAME_RE.test(key)) {
        emit(
          'crypto-hardcoded-secret',
          node.initializer.getStart(sourceFile),
          node.initializer.getEnd(),
          node.initializer.getText(sourceFile),
        );
      }
    }

    // --- Assignments: x = literal --------------------------------------
    if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
      const lhs = node.left;
      // process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'
      if (ts.isPropertyAccessExpression(lhs) && lhs.name.text === 'NODE_TLS_REJECT_UNAUTHORIZED') {
        const v = getStringValue(node.right);
        if (v === '0' || (ts.isNumericLiteral(node.right) && node.right.text === '0')) {
          emit('crypto-node-tls-reject', node.getStart(sourceFile), node.getEnd(), node.getText(sourceFile));
        }
      }
      // SECRET = "literal" (bare assignment, not declaration)
      const name = ts.isIdentifier(lhs)
        ? lhs.text
        : ts.isPropertyAccessExpression(lhs)
          ? lhs.name.text
          : undefined;
      if (name && SECRET_NAME_RE.test(name)) {
        const value = getStringValue(node.right);
        if (value !== undefined && value.length >= 8) {
          emit(
            'crypto-hardcoded-secret',
            node.right.getStart(sourceFile),
            node.right.getEnd(),
            node.right.getText(sourceFile),
          );
        }
      }
    }

    // --- rejectUnauthorized: false -------------------------------------
    if (
      ts.isPropertyAssignment(node) &&
      ts.isIdentifier(node.name) &&
      node.name.text === 'rejectUnauthorized' &&
      node.initializer.kind === ts.SyntaxKind.FalseKeyword
    ) {
      emit('crypto-ssl-no-verify', node.getStart(sourceFile), node.getEnd(), node.getText(sourceFile));
    }

    // --- http:// string literals ---------------------------------------
    if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
      const v = node.text;
      const m = /^http:\/\/([^/\s]+)/i.exec(v);
      if (m) {
        const host = m[1].toLowerCase();
        const isLocal =
          host.startsWith('localhost') ||
          host.startsWith('127.0.0.1') ||
          host.startsWith('0.0.0.0');
        if (!isLocal) {
          emit('crypto-http-url', node.getStart(sourceFile), node.getEnd(), node.getText(sourceFile));
        }
      }
    }

    ts.forEachChild(node, visit);
  }

  visit(sourceFile);
  return findings;
}
