// Feature extraction for the false-positive classifier.
//
// Each candidate finding is turned into a small, fixed-length numeric vector
// describing its *context* (where it is, what value it touches, how "real" the
// value looks). The classifier in `classifier.ts` maps this vector to a
// probability that the finding is a genuine vulnerability.
//
// Value-bearing features are deliberately *rule-scoped* so that the same token
// ("example.com") can be a placeholder for a hardcoded secret yet a legitimate
// finding for a cleartext-http URL without giving the model contradictory
// training signals.

export const FEATURE_NAMES = [
  'bias',
  'rule_is_secret',
  'rule_is_http',
  'severity',
  'in_test_path',
  'secret_entropy',
  'secret_length',
  'secret_placeholder',
  'secret_low_diversity',
  'secret_example_host',
  'env_lookup',
  'http_namespace_url',
] as const;

export interface FeatureContext {
  ruleId: string;
  severity: string;
  matchedText: string;
  /** The source line the finding sits on. */
  lineText: string;
  filePath?: string;
}

const SEVERITY_SCORE: Record<string, number> = {
  critical: 1,
  high: 0.66,
  medium: 0.33,
  low: 0,
};

const PLACEHOLDER_RE =
  /(example|sample|dummy|changeme|change_me|placeholder|replace[-_ ]?with|your[-_ ]?|xxx+|<[^>]*>|redacted|todo|fixme|foo|bar|baz|secret[-_ ]?here|key[-_ ]?here|test[-_ ]?key|0{4,}|123456|password123|none|null|undefined|(.)\2{5,})/i;

const TEST_PATH_RE =
  /(^|[\\/])(tests?|__tests__|specs?|mocks?|__mocks__|fixtures?|stub)([\\/]|\.)|\.(test|spec)\./i;

const ENV_LOOKUP_RE =
  /(process\.env|os\.environ|getenv|import\.meta\.env|dotenv|config\.get|vault|secretsmanager)/i;

const EXAMPLE_HOST_RE = /(example\.(com|org|net)|your-?domain|dummy\.|test\.local)/i;

// Well-known non-network http:// URIs (XML namespaces, schemas, DTDs) — these
// are a classic regex false positive: they are identifiers, not connections.
const NAMESPACE_URL_RE =
  /(w3\.org|xmlns|\/svg|schemas\.|sopa|\.xsd|\.dtd|purl\.org|ns\.adobe|xml\.apache)/i;

function stripQuotes(s: string): string {
  const t = s.trim();
  if (t.length >= 2 && /^['"`]/.test(t) && /['"`]$/.test(t[t.length - 1])) {
    return t.slice(1, -1);
  }
  const m = /['"`]([^'"`]*)['"`]/.exec(t);
  return m ? m[1] : t;
}

/** Shannon entropy (bits/char) of a string. */
export function shannonEntropy(s: string): number {
  if (!s) { return 0; }
  const counts: Record<string, number> = {};
  for (const ch of s) { counts[ch] = (counts[ch] || 0) + 1; }
  let h = 0;
  for (const k in counts) {
    const p = counts[k] / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

export function extractFeatures(ctx: FeatureContext): number[] {
  const ruleIsSecret = /hardcoded-secret/.test(ctx.ruleId) ? 1 : 0;
  const ruleIsHttp = /http-url/.test(ctx.ruleId) ? 1 : 0;

  // Secret-scoped value (empty for non-secret rules → neutral features).
  const secretValue = ruleIsSecret ? stripQuotes(ctx.matchedText) : '';
  const distinct = new Set(secretValue).size;
  const lowDiversity = secretValue.length >= 6 && distinct <= 2 ? 1 : 0;

  // Http-scoped value.
  const httpValue = ruleIsHttp ? stripQuotes(ctx.matchedText) : '';

  return [
    1, // bias
    ruleIsSecret,
    ruleIsHttp,
    SEVERITY_SCORE[ctx.severity] ?? 0,
    TEST_PATH_RE.test(ctx.filePath ?? '') ? 1 : 0,
    Math.min(shannonEntropy(secretValue) / 6, 1),
    Math.min(secretValue.length / 40, 1),
    ruleIsSecret && PLACEHOLDER_RE.test(secretValue) ? 1 : 0,
    lowDiversity,
    ruleIsSecret && EXAMPLE_HOST_RE.test(secretValue) ? 1 : 0,
    ruleIsSecret && ENV_LOOKUP_RE.test(ctx.lineText) ? 1 : 0,
    ruleIsHttp && NAMESPACE_URL_RE.test(httpValue) ? 1 : 0,
  ];
}
