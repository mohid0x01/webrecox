/* WebRecox — AST-based JS Analyzer
   Walks acorn AST to extract REAL endpoints from fetch/axios/XHR calls
   and template literals, separating them from random string literals.
   Also detects secrets and security bugs with severity classification.
*/

import { parse } from 'acorn';
import { simple as walkSimple } from 'acorn-walk';

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type Category = 'endpoint' | 'secret' | 'bug' | 'info';

export interface JSAnalysisFinding {
  category: Category;
  severity: Severity;
  type: string;
  value: string;
  context?: string;
  file?: string;
  line?: number;
  confidence: 'high' | 'medium' | 'low';
}

export interface JSAnalysisResult {
  file: string;
  endpoints: JSAnalysisFinding[];
  secrets: JSAnalysisFinding[];
  bugs: JSAnalysisFinding[];
  info: JSAnalysisFinding[];
  parseError?: string;
  totalLOC: number;
}

// ── Network call detection ──
const NET_CALLEES = new Set([
  'fetch', 'axios', '$.ajax', '$.get', '$.post', 'request', 'got',
  'XMLHttpRequest', 'superagent', 'wretch', 'ky',
]);
const AXIOS_METHODS = new Set(['get', 'post', 'put', 'delete', 'patch', 'head', 'options', 'request']);

// ── False-positive filters for endpoint paths ──
const FP_EXT = /\.(?:css|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|webp|mp[34]|wav|pdf|zip|gz|tar)(\?|$)/i;
const FP_PATTERN = [
  /^[a-z]+$/i,                        // single word
  /^\d+$/,                             // pure digits
  /^[#@%&]/,                           // CSS-like
  /^use\s/i,                           // 'use strict'
  /^\s*$/,                             // whitespace
];

function isLikelyEndpoint(s: string): { ok: boolean; confidence: 'high' | 'medium' | 'low' } {
  if (!s || s.length < 2 || s.length > 500) return { ok: false, confidence: 'low' };
  if (FP_EXT.test(s)) return { ok: false, confidence: 'low' };
  if (FP_PATTERN.some(re => re.test(s))) return { ok: false, confidence: 'low' };

  // High confidence: starts with /api/, /v1/, etc., or full URL
  if (/^https?:\/\/[a-z0-9.\-]+\/[a-z0-9_\-./?=&{}%]+/i.test(s)) return { ok: true, confidence: 'high' };
  if (/^\/(api|v\d|graphql|rest|gateway|service|admin|user|auth|login|account)\b/i.test(s)) return { ok: true, confidence: 'high' };

  // Medium: looks like a path with slashes and segments
  if (/^\/[a-z0-9_\-./{}%]+$/i.test(s) && s.includes('/') && s.length >= 4) {
    // Reject if it looks like an HTML/SVG path-d attribute
    if (/[MLHVCSQTAZ\d.,\s\-]{20,}/.test(s) && /[MLHVCSQTAZ]/.test(s)) return { ok: false, confidence: 'low' };
    return { ok: true, confidence: 'medium' };
  }

  return { ok: false, confidence: 'low' };
}

// ── Secret patterns (high precision) ──
const SECRET_PATTERNS: { name: string; sev: Severity; re: RegExp }[] = [
  { name: 'AWS Access Key', sev: 'CRITICAL', re: /\bAKIA[0-9A-Z]{16}\b/g },
  { name: 'AWS Secret Key (40 char b64)', sev: 'CRITICAL', re: /(?:aws_secret|aws_secret_access_key|secret_key)\s*[:=]\s*["']([A-Za-z0-9/+=]{40})["']/gi },
  { name: 'Google API Key', sev: 'HIGH', re: /\bAIza[0-9A-Za-z\-_]{35}\b/g },
  { name: 'Slack Token', sev: 'CRITICAL', re: /\bxox[abprs]-[A-Za-z0-9-]{10,48}\b/g },
  { name: 'GitHub Token', sev: 'CRITICAL', re: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b/g },
  { name: 'Stripe Live Key', sev: 'CRITICAL', re: /\b(?:sk|rk)_live_[0-9a-zA-Z]{20,}\b/g },
  { name: 'Stripe Test Key', sev: 'MEDIUM', re: /\b(?:sk|rk|pk)_test_[0-9a-zA-Z]{20,}\b/g },
  { name: 'Generic Bearer Token', sev: 'HIGH', re: /Bearer\s+[A-Za-z0-9\-_=.+/]{30,}/g },
  { name: 'JWT', sev: 'MEDIUM', re: /\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b/g },
  { name: 'API Key (generic)', sev: 'HIGH', re: /(?:api[_-]?key|apikey|api_secret|access[_-]?token|auth[_-]?token)\s*[:=]\s*["']([A-Za-z0-9_\-]{20,})["']/gi },
  { name: 'Firebase URL', sev: 'MEDIUM', re: /https?:\/\/[a-z0-9-]+\.firebaseio\.com/gi },
  { name: 'Mailgun API Key', sev: 'HIGH', re: /\bkey-[0-9a-zA-Z]{32}\b/g },
  { name: 'Twilio SID', sev: 'HIGH', re: /\bAC[a-z0-9]{32}\b/g },
  { name: 'Private Key', sev: 'CRITICAL', re: /-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP)?\s*PRIVATE KEY-----/g },
];

// ── Bug patterns ──
const BUG_PATTERNS: { name: string; sev: Severity; re: RegExp; desc: string }[] = [
  { name: 'eval()', sev: 'CRITICAL', re: /\beval\s*\(\s*[^"')]/g, desc: 'Dynamic eval enables arbitrary code execution.' },
  { name: 'new Function()', sev: 'CRITICAL', re: /\bnew\s+Function\s*\(/g, desc: 'Function constructor is equivalent to eval.' },
  { name: 'innerHTML sink', sev: 'HIGH', re: /\.innerHTML\s*=\s*[^"`'<]/g, desc: 'Dynamic innerHTML can lead to DOM XSS.' },
  { name: 'document.write', sev: 'HIGH', re: /document\.write(?:ln)?\s*\(/g, desc: 'document.write is a known XSS sink.' },
  { name: 'dangerouslySetInnerHTML', sev: 'HIGH', re: /dangerouslySetInnerHTML/g, desc: 'React XSS escape hatch.' },
  { name: 'postMessage(*)', sev: 'HIGH', re: /\.postMessage\s*\([^,)]+,\s*['"]\*['"]\s*\)/g, desc: 'Wildcard origin enables cross-frame leaks.' },
  { name: 'localStorage credential', sev: 'HIGH', re: /(?:local|session)Storage\.\s*(?:setItem|getItem)\s*\(\s*["'`](?:token|password|secret|api[_-]?key|jwt|auth|credential)/gi, desc: 'Sensitive data in web storage.' },
  { name: 'Disabled SSL verify', sev: 'HIGH', re: /(?:rejectUnauthorized|verifySsl|sslVerify|insecure)\s*[:=]\s*false/gi, desc: 'SSL/TLS verification disabled.' },
  { name: 'CORS wildcard', sev: 'MEDIUM', re: /access-control-allow-origin\s*[:=]\s*["']\*["']/gi, desc: 'CORS wildcard in code.' },
  { name: 'Hardcoded password', sev: 'HIGH', re: /(?:password|passwd|pwd)\s*[:=]\s*["'][^"']{4,}["']/gi, desc: 'Plaintext password literal.' },
  { name: 'Console logs sensitive', sev: 'LOW', re: /console\.(?:log|error|warn|info)\s*\([^)]*(?:password|token|secret|jwt|apikey)/gi, desc: 'Sensitive value logged.' },
  { name: 'Debug enabled', sev: 'LOW', re: /\b(?:debug|DEBUG)\s*[:=]\s*(?:true|1)\b/g, desc: 'Debug flag in client code.' },
  { name: 'TODO/FIXME', sev: 'INFO', re: /\/\/\s*(?:TODO|FIXME|HACK|XXX):\s*[^\n]{4,120}/g, desc: 'Developer note in production code.' },
  { name: 'Source map exposed', sev: 'LOW', re: /\/\/[#@]\s*sourceMappingURL\s*=\s*[^\s]+/g, desc: 'Source map reference reveals original code.' },
];

function lineOf(text: string, idx: number): number {
  let line = 1;
  for (let i = 0; i < idx && i < text.length; i++) if (text[i] === '\n') line++;
  return line;
}

function dedupe(arr: JSAnalysisFinding[]): JSAnalysisFinding[] {
  const seen = new Set<string>();
  const out: JSAnalysisFinding[] = [];
  for (const f of arr) {
    const k = `${f.category}|${f.type}|${f.value}`;
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(f);
  }
  return out;
}

/** Walks acorn AST to extract endpoints from CallExpressions (fetch, axios, XHR.open) */
function extractEndpointsAST(code: string, file: string): JSAnalysisFinding[] {
  const out: JSAnalysisFinding[] = [];
  let ast: any;
  try {
    ast = parse(code, { ecmaVersion: 'latest', sourceType: 'module', allowReturnOutsideFunction: true, allowAwaitOutsideFunction: true, allowImportExportEverywhere: true });
  } catch {
    try {
      ast = parse(code, { ecmaVersion: 'latest', sourceType: 'script', allowReturnOutsideFunction: true });
    } catch { return out; }
  }

  const stringFromNode = (n: any): string | null => {
    if (!n) return null;
    if (n.type === 'Literal' && typeof n.value === 'string') return n.value;
    if (n.type === 'TemplateLiteral') {
      // join quasis; replace ${} with placeholder
      return n.quasis.map((q: any, i: number) => q.value.cooked + (n.expressions[i] ? '${…}' : '')).join('');
    }
    return null;
  };

  walkSimple(ast, {
    CallExpression(node: any) {
      const c = node.callee;
      let calleeName = '';
      if (c.type === 'Identifier') calleeName = c.name;
      else if (c.type === 'MemberExpression') {
        const obj = c.object?.name || c.object?.property?.name || '';
        const prop = c.property?.name || '';
        calleeName = `${obj}.${prop}`;
      }

      const isFetch = calleeName === 'fetch';
      const isAxiosCall = /^axios(\.[a-z]+)?$/i.test(calleeName) || (c.type === 'MemberExpression' && c.object?.name === 'axios' && AXIOS_METHODS.has(c.property?.name));
      const isXhrOpen = c.type === 'MemberExpression' && c.property?.name === 'open';
      const isJqAjax = /^\$\.(ajax|get|post|getJSON)$/.test(calleeName);

      if (isFetch || isAxiosCall || isJqAjax) {
        const arg0 = node.arguments[0];
        const url = stringFromNode(arg0);
        if (url) {
          const det = isLikelyEndpoint(url);
          if (det.ok || /^https?:\/\//.test(url)) {
            out.push({
              category: 'endpoint',
              severity: 'INFO',
              type: `${calleeName}() call`,
              value: url,
              file,
              line: lineOf(code, node.start || 0),
              confidence: 'high',
            });
          }
        }
      } else if (isXhrOpen) {
        // XHR.open(method, url, ...)
        const arg1 = node.arguments[1];
        const url = stringFromNode(arg1);
        if (url) {
          const det = isLikelyEndpoint(url);
          if (det.ok) {
            out.push({
              category: 'endpoint', severity: 'INFO',
              type: 'XMLHttpRequest.open',
              value: url, file,
              line: lineOf(code, node.start || 0),
              confidence: 'high',
            });
          }
        }
      }
    },
    // Also collect string literals that look like real endpoints (medium confidence)
    Literal(node: any) {
      if (typeof node.value !== 'string') return;
      const det = isLikelyEndpoint(node.value);
      if (det.ok && det.confidence !== 'low') {
        out.push({
          category: 'endpoint',
          severity: det.confidence === 'high' ? 'LOW' : 'INFO',
          type: 'String literal endpoint',
          value: node.value,
          file,
          line: lineOf(code, node.start || 0),
          confidence: det.confidence,
        });
      }
    },
  });

  return out;
}

export function analyzeJS(code: string, file = 'inline.js'): JSAnalysisResult {
  const endpoints: JSAnalysisFinding[] = [];
  const secrets: JSAnalysisFinding[] = [];
  const bugs: JSAnalysisFinding[] = [];
  const info: JSAnalysisFinding[] = [];
  let parseError: string | undefined;

  // 1. AST endpoint extraction
  try {
    endpoints.push(...extractEndpointsAST(code, file));
  } catch (e: any) {
    parseError = e?.message || 'AST parse failed';
  }

  // 2. Regex pass for secrets
  for (const pat of SECRET_PATTERNS) {
    const re = new RegExp(pat.re.source, pat.re.flags);
    let m: RegExpExecArray | null;
    while ((m = re.exec(code)) !== null) {
      const value = (m[1] || m[0]).slice(0, 200);
      secrets.push({
        category: 'secret',
        severity: pat.sev,
        type: pat.name,
        value,
        file,
        line: lineOf(code, m.index),
        confidence: 'high',
      });
      if (secrets.length > 5000) break;
    }
  }

  // 3. Regex pass for bugs
  for (const pat of BUG_PATTERNS) {
    const re = new RegExp(pat.re.source, pat.re.flags);
    let m: RegExpExecArray | null;
    while ((m = re.exec(code)) !== null) {
      const value = m[0].slice(0, 200);
      const cat: Category = pat.sev === 'INFO' ? 'info' : 'bug';
      const target = cat === 'info' ? info : bugs;
      target.push({
        category: cat,
        severity: pat.sev,
        type: pat.name,
        value,
        context: pat.desc,
        file,
        line: lineOf(code, m.index),
        confidence: 'high',
      });
      if (bugs.length + info.length > 5000) break;
    }
  }

  return {
    file,
    endpoints: dedupe(endpoints),
    secrets: dedupe(secrets),
    bugs: dedupe(bugs),
    info: dedupe(info),
    parseError,
    totalLOC: code.split('\n').length,
  };
}

/** Severity priority for sorting */
export const SEV_ORDER: Record<Severity, number> = {
  CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4,
};

export function groupBySeverity(findings: JSAnalysisFinding[]): Record<Severity, JSAnalysisFinding[]> {
  const g: Record<Severity, JSAnalysisFinding[]> = { CRITICAL: [], HIGH: [], MEDIUM: [], LOW: [], INFO: [] };
  for (const f of findings) g[f.severity].push(f);
  return g;
}

/** Aggregate multiple file analyses into one consolidated result */
export function aggregateAnalyses(results: JSAnalysisResult[]): {
  totalFiles: number;
  totalLOC: number;
  endpoints: JSAnalysisFinding[];
  secrets: JSAnalysisFinding[];
  bugs: JSAnalysisFinding[];
  info: JSAnalysisFinding[];
  bySeverity: Record<Severity, JSAnalysisFinding[]>;
} {
  const all = {
    endpoints: results.flatMap(r => r.endpoints),
    secrets: results.flatMap(r => r.secrets),
    bugs: results.flatMap(r => r.bugs),
    info: results.flatMap(r => r.info),
  };
  const everything = [...all.secrets, ...all.bugs, ...all.endpoints, ...all.info];
  return {
    totalFiles: results.length,
    totalLOC: results.reduce((a, r) => a + r.totalLOC, 0),
    ...all,
    bySeverity: groupBySeverity(everything),
  };
}

/* ──────────────────────────────────────────────────────────────────────────
   Enhanced regex fallback — catches dynamic/concatenated/minified endpoints.
   ────────────────────────────────────────────────────────────────────────── */

const REGEX_ENDPOINT_PATTERNS: RegExp[] = [
  /["'`](\/(?:api|v\d+|graphql|rest|gateway|service|admin|user|auth|account|oauth|public|internal|private|backend)\/[A-Za-z0-9_\-./{}%?=&]+)["'`]/g,
  /["'`](https?:\/\/[A-Za-z0-9.\-]+\/[A-Za-z0-9_\-./{}%?=&]*)["'`]/g,
  /(?:url|endpoint|path|uri|baseURL|baseUrl|apiUrl|apiBase)\s*[:=]\s*["'`]([^"'`]{2,200})["'`]/gi,
  /["'`](\/[a-z0-9_\-./]{3,})["'`]\s*\+/gi,
];

export function extractEndpointsRegex(code: string, file = 'inline.js'): JSAnalysisFinding[] {
  const out: JSAnalysisFinding[] = [];
  for (const re of REGEX_ENDPOINT_PATTERNS) {
    const r = new RegExp(re.source, re.flags);
    let m: RegExpExecArray | null;
    while ((m = r.exec(code)) !== null) {
      const v = (m[1] || m[0]).slice(0, 400);
      const det = isLikelyEndpoint(v);
      if (!det.ok) continue;
      out.push({
        category: 'endpoint',
        severity: det.confidence === 'high' ? 'LOW' : 'INFO',
        type: 'Regex-extracted endpoint',
        value: v, file,
        line: lineOf(code, m.index),
        confidence: det.confidence,
      });
      if (out.length > 5000) break;
    }
  }
  return dedupe(out);
}

export function extractAllEndpoints(code: string, file = 'inline.js'): JSAnalysisFinding[] {
  const fromAst = (() => { try { return extractEndpointsAST(code, file); } catch { return [] as JSAnalysisFinding[]; } })();
  const fromRegex = extractEndpointsRegex(code, file);
  return dedupe([...fromAst, ...fromRegex]);
}

/* ── External JS crawler ── */

async function fetchJsBody(url: string, timeoutMs = 12000): Promise<string | null> {
  const proxies = [
    (u: string) => u,
    (u: string) => `https://api.allorigins.win/raw?url=${encodeURIComponent(u)}`,
    (u: string) => `https://corsproxy.io/?url=${encodeURIComponent(u)}`,
  ];
  for (const p of proxies) {
    try {
      const r = await fetch(p(url), { signal: AbortSignal.timeout(timeoutMs) });
      if (r.ok) {
        const t = await r.text();
        if (t && t.length > 0) return t;
      }
    } catch { /* try next */ }
  }
  return null;
}

export async function discoverScriptUrls(targetUrl: string): Promise<string[]> {
  const html = await fetchJsBody(targetUrl, 15000);
  if (!html) return [];
  const out = new Set<string>();
  let base: URL;
  try { base = new URL(targetUrl); } catch { return []; }
  const re = /<script[^>]+src\s*=\s*["']([^"']+)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null) {
    try {
      const abs = new URL(m[1], base).toString();
      if (/\.js(\?|#|$)/.test(abs) || abs.endsWith('.js')) out.add(abs);
    } catch { /* ignore */ }
  }
  const re2 = /<link[^>]+rel=["'](?:preload|modulepreload)["'][^>]+href\s*=\s*["']([^"']+\.js[^"']*)["']/gi;
  while ((m = re2.exec(html)) !== null) {
    try { out.add(new URL(m[1], base).toString()); } catch { /* ignore */ }
  }
  return [...out].slice(0, 200);
}

export async function crawlAndAnalyze(targetUrl: string, opts?: { maxFiles?: number }): Promise<JSAnalysisResult[]> {
  const max = opts?.maxFiles ?? 100;
  const urls = (await discoverScriptUrls(targetUrl)).slice(0, max);
  const out: JSAnalysisResult[] = [];
  for (const u of urls) {
    const body = await fetchJsBody(u);
    if (!body) {
      out.push({ file: u, endpoints: [], secrets: [], bugs: [], info: [], totalLOC: 0, parseError: 'fetch failed' });
      continue;
    }
    const r = analyzeJS(body, u);
    const extra = extractEndpointsRegex(body, u);
    r.endpoints = dedupe([...r.endpoints, ...extra]);
    out.push(r);
  }
  return out;
}
