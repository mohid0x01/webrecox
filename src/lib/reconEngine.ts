/* ══════════════════════════════════════════════════════
   TeamCyberOps Recon v14 — Client-Side Scanning Engine
   Ported from v14.html — All scanning logic
   @mohidqx · github.com/mohidqx
══════════════════════════════════════════════════════ */

// ── TYPES ──
export interface SubdomainEntry {
  subdomain: string; ip: string; status: string; source: string;
  ports: number[]; geo: string; cname: string; tko: boolean;
  httpStatus: number; alive: boolean;
}
export interface EndpointEntry { url: string; status: string; source: string; }
export interface DNSRecord { val: string; ttl: number; src: string; }
export interface SecretFinding { type: string; sev: string; value: string; file: string; line: number; }
export interface CORSFinding { host: string; type: string; acao: string; acac: string; origin: string; sev: string; }
export interface NucleiFinding { template: string; host: string; url: string; sev: string; status: number; cve: string; confirmed: boolean; }
export interface ContentFinding { path: string; host: string; url: string; status: number; size: number; sev: string; sensitive: boolean; }
export interface DarkWebFinding { source: string; type: string; severity: string; title: string; detail: string; date?: string; url: string; }
export interface DOMXSSFinding { sink: string; sev: string; count: number; file: string; }
export interface CookieFinding { host: string; name: string; issues: { issue: string; desc: string; sev: string; }[]; }
export interface VulnFinding { type: string; sev: string; url: string; param: string; desc: string; test: string; }
export interface ProbeFinding { host: string; url: string; status: number; alive: boolean; title: string; tech: string[]; redirected: boolean; final_url: string; error?: string; }

export interface ScanState {
  domain: string; scanning: boolean;
  subs: SubdomainEntry[]; ips: Record<string, any>;
  dns: Record<string, DNSRecord[]>;
  eps: EndpointEntry[]; js: EndpointEntry[]; params: Record<string, number>;
  hdrs: any[]; tech: string[]; waf: string;
  ssl: any[]; whois: any; takeover: any[];
  otx: { p: number; m: number; u: number; pdns: any[]; };
  github: { orgs: any[]; repos: any[]; };
  cloud: { s3: any[]; asn: any; };
  secrets: SecretFinding[];
  corsFindings: CORSFinding[];
  nucleiFindings: NucleiFinding[];
  contentFindings: ContentFinding[];
  darkWebFindings: DarkWebFinding[];
  domXss: DOMXSSFinding[];
  cookieFindings: CookieFinding[];
  vulns: VulnFinding[];
  probes: ProbeFinding[];
  ghLeaks: any[];
  uscan: any[];
}

export function createScanState(): ScanState {
  return {
    domain: '', scanning: false,
    subs: [], ips: {},
    dns: { A: [], AAAA: [], MX: [], NS: [], TXT: [], CNAME: [], SOA: [], CAA: [], EMAIL: [] },
    eps: [], js: [], params: {},
    hdrs: [], tech: [], waf: 'unknown',
    ssl: [], whois: {}, takeover: [],
    otx: { p: 0, m: 0, u: 0, pdns: [] },
    github: { orgs: [], repos: [] },
    cloud: { s3: [], asn: {} },
    secrets: [], corsFindings: [], nucleiFindings: [],
    contentFindings: [], darkWebFindings: [], domXss: [],
    cookieFindings: [], vulns: [], probes: [], ghLeaks: [], uscan: [],
  };
}

// ── PROXY FETCH ──
const PROXIES = [
  (u: string) => u,
  (u: string) => `https://api.allorigins.win/raw?url=${encodeURIComponent(u)}`,
  (u: string) => `https://corsproxy.io/?url=${encodeURIComponent(u)}`,
  (u: string) => `https://api.codetabs.com/v1/proxy?quest=${encodeURIComponent(u)}`,
];

export async function pFetch(url: string, ms = 20000): Promise<Response> {
  for (const proxy of PROXIES) {
    try {
      const r = await fetch(proxy(url), { signal: AbortSignal.timeout(Math.min(ms, 15000)) });
      if (r.ok) return r;
    } catch { /* next */ }
  }
  return new Response('', { status: 0 }) as any;
}

async function sf(url: string, opts?: RequestInit, ms = 15000) {
  try {
    return await fetch(url, { ...opts, signal: AbortSignal.timeout(ms) });
  } catch {
    return { ok: false, status: 0, json: async () => ({}), text: async () => '', headers: { get: () => null } } as any;
  }
}

function sleep(ms: number) { return new Promise(r => setTimeout(r, ms)); }

export function isValidSub(s: string, domain: string) {
  if (!s) return false;
  s = s.trim().toLowerCase();
  if (s.includes('@') || s.includes('/') || s.includes(':') || s.startsWith('*')) return false;
  if (!/^[a-z0-9][a-z0-9.\-]*[a-z0-9]$/.test(s)) return false;
  if (s === domain || !s.endsWith('.' + domain)) return false;
  return true;
}

function normUrl(u: string) { return u.replace(/^(https?:\/\/[^/]+):80(\/|$)/, '$1$2').replace(/^(https?:\/\/[^/]+):443(\/|$)/, '$1$2'); }
function isJunkUrl(u: string) { return !u || u.length > 1200 || /data:(image|text|application)/i.test(u) || u.includes('<') || u.includes('>'); }
function urlKey(u: string) { try { const p = new URL(u); return p.host + p.pathname + (p.search || ''); } catch { return u.split('#')[0]; } }
const JUNK = /\.(png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot|mp[34]|avi|mov|webp|webm|pdf|zip|tar|gz|css)(\?|$)/i;

// ══════════════════════════════════════════
//  SUBDOMAIN SOURCES — 15+ Sources
// ══════════════════════════════════════════

export async function fetchCrtSh(domain: string): Promise<{ subdomain: string; ip: string; source: string }[]> {
  try {
    const r = await pFetch(`https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`, 40000);
    const data = await r.json();
    if (!Array.isArray(data)) return [];
    const seen = new Set<string>();
    return data.flatMap((e: any) => (e.name_value || '').split('\n')
      .map((n: string) => n.trim().toLowerCase().replace(/^\*\./, ''))
      .filter((s: string) => isValidSub(s, domain) && !seen.has(s) && seen.add(s))
      .map((s: string) => ({ subdomain: s, ip: '', source: 'crt.sh' }))
    );
  } catch { return []; }
}

export async function fetchHT(domain: string) {
  try {
    const r = await pFetch(`https://api.hackertarget.com/hostsearch/?q=${domain}`, 15000);
    const text = await r.text();
    if (text.includes('API count') || text.startsWith('error') || text.startsWith('<')) return [];
    return text.trim().split('\n').map(l => { const [h, ip] = l.split(','); return { subdomain: h?.trim().toLowerCase(), ip: ip || '', source: 'HackerTarget' }; }).filter(s => isValidSub(s.subdomain, domain));
  } catch { return []; }
}

export async function fetchAnubis(domain: string) {
  try {
    const r = await pFetch(`https://jldc.me/anubis/subdomains/${domain}`, 15000);
    const data = await r.json();
    return Array.isArray(data) ? data.filter((s: string) => isValidSub(s, domain)).map((s: string) => ({ subdomain: s, ip: '', source: 'AnubisDB' })) : [];
  } catch { return []; }
}

export async function fetchRapidDNS(domain: string) {
  try {
    const r = await pFetch(`https://rapiddns.io/subdomain/${domain}?full=1`, 20000);
    const html = await r.text();
    const matches = html.match(/(?:target="_blank">)([a-z0-9.\-]+\.[a-z]+)(?:<\/a>)/gi) || [];
    const seen = new Set<string>();
    return matches.map(m => (m.match(/>([^<]+)</) || [])[1]?.toLowerCase()).filter((s): s is string => !!s && isValidSub(s, domain) && !seen.has(s) && !!seen.add(s)).map(s => ({ subdomain: s, ip: '', source: 'RapidDNS' }));
  } catch { return []; }
}

export async function fetchCertSpotter(domain: string) {
  try {
    const r = await pFetch(`https://api.certspotter.com/v1/issuances?domain=${domain}&include_subdomains=true&expand=dns_names`, 15000);
    const data = await r.json();
    if (!Array.isArray(data)) return [];
    const seen = new Set<string>();
    return data.flatMap((e: any) => (e.dns_names || []).filter((s: string) => isValidSub(s, domain) && !seen.has(s) && seen.add(s)).map((s: string) => ({ subdomain: s, ip: '', source: 'CertSpotter' })));
  } catch { return []; }
}

export async function fetchOTXSubs(domain: string) {
  try {
    const r = await pFetch(`https://otx.alienvault.com/api/v1/indicators/domain/${domain}/passive_dns?limit=500`, 20000);
    const data = await r.json();
    const seen = new Set<string>();
    return (data.passive_dns || []).filter((e: any) => isValidSub(e.hostname, domain) && !seen.has(e.hostname) && seen.add(e.hostname)).map((e: any) => ({ subdomain: e.hostname, ip: e.address || '', source: 'OTX' }));
  } catch { return []; }
}

export async function fetchURLScanSubs(domain: string) {
  try {
    const r = await pFetch(`https://urlscan.io/api/v1/search/?q=domain:${domain}&size=200`, 15000);
    const data = await r.json();
    const seen = new Set<string>();
    return (data.results || []).map((e: any) => e.page?.domain).filter((s: string) => s && isValidSub(s, domain) && !seen.has(s) && seen.add(s)).map((s: string) => ({ subdomain: s, ip: '', source: 'URLScan' }));
  } catch { return []; }
}

export async function fetchThreatMiner(domain: string) {
  try {
    const r = await pFetch(`https://api.threatminer.org/v2/domain.php?q=${domain}&rt=5`, 15000);
    const data = await r.json();
    return (data.results || []).filter((s: string) => isValidSub(s, domain)).map((s: string) => ({ subdomain: s, ip: '', source: 'ThreatMiner' }));
  } catch { return []; }
}

export async function fetchSonar(domain: string) {
  try {
    const r = await pFetch(`https://sonar.omnisint.io/subdomains/${domain}`, 15000);
    const data = await r.json();
    return Array.isArray(data) ? data.filter((s: string) => isValidSub(s, domain)).map((s: string) => ({ subdomain: s, ip: '', source: 'Sonar' })) : [];
  } catch { return []; }
}

export async function fetchWBSubs(domain: string) {
  try {
    const r = await pFetch(`https://web.archive.org/cdx/search/cdx?url=*.${domain}&output=json&fl=original&collapse=urlkey&limit=3000`, 30000);
    const data = await r.json();
    if (!Array.isArray(data) || data.length < 2) return [];
    const seen = new Set<string>();
    return data.slice(1).map((row: any) => { try { return new URL(row[0]).hostname.toLowerCase(); } catch { return ''; } }).filter((s: string) => isValidSub(s, domain) && !seen.has(s) && seen.add(s)).map((s: string) => ({ subdomain: s, ip: '', source: 'Wayback' }));
  } catch { return []; }
}

export async function fetchVirusTotal(domain: string) {
  try {
    const r = await pFetch(`https://www.virustotal.com/vtapi/v2/domain/report?domain=${domain}`, 15000);
    const data = await r.json();
    return (data.subdomains || []).filter((s: string) => isValidSub(s, domain)).map((s: string) => ({ subdomain: s, ip: '', source: 'VirusTotal' }));
  } catch { return []; }
}

// ── DNS RESOLUTION ──
export async function resolveHost(host: string): Promise<string> {
  try {
    const r = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(host)}&type=A`, { signal: AbortSignal.timeout(5000) });
    const d = await r.json();
    return d.Answer?.[0]?.data || '';
  } catch { return ''; }
}

export async function apiDNS(domain: string, type: string): Promise<{ data: string; ttl: number }[]> {
  try {
    const r = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${type}`, { signal: AbortSignal.timeout(8000) });
    const d = await r.json();
    return (d.Answer || []).map((a: any) => ({ data: a.data, ttl: a.TTL || 0 }));
  } catch { return []; }
}

// ── SHODAN InternetDB ──
export async function apiIDB(ip: string) {
  try {
    const r = await fetch(`https://internetdb.shodan.io/${ip}`, { signal: AbortSignal.timeout(8000) });
    if (!r.ok) return null;
    return await r.json();
  } catch { return null; }
}

// ── IP GEO ──
export async function fetchGeo(ip: string) {
  try {
    const r = await fetch(`https://ipapi.co/${ip}/json/`, { signal: AbortSignal.timeout(5000) });
    return await r.json();
  } catch { return null; }
}

// ── WHOIS/RDAP ──
export async function apiRDAP(domain: string) {
  try {
    const r = await pFetch(`https://rdap.org/domain/${domain}`, 15000);
    const d = await r.json();
    return {
      name: d.ldhName || domain,
      status: d.status || [],
      nameservers: (d.nameservers || []).map((ns: any) => ns.ldhName || ns.objectClassName || ''),
      events: (d.events || []).map((e: any) => ({ action: e.eventAction, date: e.eventDate })),
      source: 'RDAP',
    };
  } catch { return null; }
}

// ══════════════════════════════════════════
//  ENDPOINT SOURCES
// ══════════════════════════════════════════

export async function fetchWBUrls(domain: string): Promise<EndpointEntry[]> {
  const all: EndpointEntry[] = [];
  const seen = new Set<string>();
  try {
    const r = await pFetch(`https://web.archive.org/cdx/search/cdx?url=*.${domain}/*&output=json&fl=original,statuscode&collapse=urlkey&limit=5000`, 40000);
    const data = await r.json();
    if (Array.isArray(data)) {
      for (let i = 1; i < data.length; i++) {
        const u = normUrl(data[i][0]);
        if (isJunkUrl(u) || JUNK.test(u)) continue;
        const k = urlKey(u);
        if (seen.has(k)) continue; seen.add(k);
        all.push({ url: u, status: data[i][1] || '-', source: 'Wayback' });
      }
    }
  } catch { /* */ }
  return all;
}

export async function fetchOTXUrls(domain: string): Promise<EndpointEntry[]> {
  const all: EndpointEntry[] = [];
  const seen = new Set<string>();
  try {
    for (let page = 1; page <= 5; page++) {
      const r = await pFetch(`https://otx.alienvault.com/api/v1/indicators/domain/${domain}/url_list?limit=500&page=${page}`, 15000);
      const d = await r.json();
      if (d.detail || d.error) break;
      (d.url_list || []).forEach((e: any) => {
        const u = e.url;
        if (!u || seen.has(urlKey(u))) return;
        seen.add(urlKey(u));
        all.push({ url: u, status: '-', source: 'OTX' });
      });
      if (!d.has_next) break;
      await sleep(200);
    }
  } catch { /* */ }
  return all;
}

export async function fetchCC(domain: string): Promise<EndpointEntry[]> {
  const all: EndpointEntry[] = [];
  const seen = new Set<string>();
  try {
    const r = await pFetch(`https://index.commoncrawl.org/CC-MAIN-2024-10-index?url=*.${domain}&output=json&limit=3000`, 30000);
    const text = await r.text();
    text.trim().split('\n').forEach(line => {
      try {
        const d = JSON.parse(line);
        const u = normUrl(d.url || '');
        if (isJunkUrl(u) || JUNK.test(u) || seen.has(urlKey(u))) return;
        seen.add(urlKey(u));
        all.push({ url: u, status: d.status || '-', source: 'CommonCrawl' });
      } catch { /* */ }
    });
  } catch { /* */ }
  return all;
}

export async function fetchURLScanUrls(domain: string): Promise<EndpointEntry[]> {
  const all: EndpointEntry[] = [];
  const seen = new Set<string>();
  try {
    const r = await pFetch(`https://urlscan.io/api/v1/search/?q=domain:${domain}&size=200`, 15000);
    const d = await r.json();
    (d.results || []).forEach((e: any) => {
      const u = e.page?.url;
      if (!u || seen.has(urlKey(u))) return;
      seen.add(urlKey(u));
      all.push({ url: u, status: String(e.page?.status || '-'), source: 'URLScan' });
    });
  } catch { /* */ }
  return all;
}

export async function fetchSitemap(domain: string): Promise<EndpointEntry[]> {
  const all: EndpointEntry[] = [];
  const seen = new Set<string>();
  try {
    const r = await pFetch(`https://${domain}/sitemap.xml`, 10000);
    const xml = await r.text();
    const locs = xml.match(/<loc>([^<]+)<\/loc>/gi) || [];
    locs.forEach(m => {
      const u = (m.match(/<loc>([^<]+)/) || [])[1];
      if (u && !seen.has(urlKey(u))) { seen.add(urlKey(u)); all.push({ url: u, status: '-', source: 'Sitemap' }); }
    });
  } catch { /* */ }
  return all;
}

export async function fetchRobotsTxt(domain: string): Promise<EndpointEntry[]> {
  const all: EndpointEntry[] = [];
  try {
    const r = await pFetch(`https://${domain}/robots.txt`, 8000);
    const text = await r.text();
    text.split('\n').forEach(line => {
      const m = line.match(/(?:Allow|Disallow|Sitemap):\s*(.+)/i);
      if (m) {
        let path = m[1].trim();
        if (path.startsWith('/')) path = `https://${domain}${path}`;
        if (path.startsWith('http')) all.push({ url: path, status: '-', source: 'robots.txt' });
      }
    });
  } catch { /* */ }
  return all;
}

// ══════════════════════════════════════════
//  JS SECRET SCANNING
// ══════════════════════════════════════════

const JS_SECRET_PATTERNS = [
  { name: 'AWS Access Key', sev: 'CRITICAL', re: /AKIA[0-9A-Z]{16}/g },
  { name: 'Google API Key', sev: 'HIGH', re: /AIza[0-9A-Za-z\-_]{35}/g },
  { name: 'Firebase URL', sev: 'HIGH', re: /[a-z0-9-]+\.firebaseio\.com/gi },
  { name: 'GitHub Token', sev: 'CRITICAL', re: /gh[pousr]_[A-Za-z0-9_]{36}/g },
  { name: 'Stripe Live Key', sev: 'CRITICAL', re: /sk_live_[0-9a-zA-Z]{24,}/g },
  { name: 'Stripe Test Key', sev: 'MEDIUM', re: /sk_test_[0-9a-zA-Z]{24,}/g },
  { name: 'Twilio SID', sev: 'HIGH', re: /AC[0-9a-fA-F]{32}/g },
  { name: 'Slack Token', sev: 'HIGH', re: /xox[baprs]-[0-9A-Za-z\-]{10,}/g },
  { name: 'Private Key', sev: 'CRITICAL', re: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/g },
  { name: 'JWT Token', sev: 'MEDIUM', re: /eyJ[A-Za-z0-9\-_]{10,}\.eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]+/g },
  { name: 'Database URL', sev: 'CRITICAL', re: /(?:mongodb|postgres|postgresql|mysql|redis):\/\/[^\s"'<>]+/gi },
  { name: 'SendGrid Key', sev: 'HIGH', re: /SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}/g },
  { name: 'Hardcoded Password', sev: 'HIGH', re: /(?:password|passwd|pwd)\s*[:=]\s*["']([^"'\s]{8,})/gi },
  { name: 'Bearer Token', sev: 'MEDIUM', re: /[Bb]earer\s+([A-Za-z0-9\-_\.]{20,})/g },
  { name: 'OpenAI API Key', sev: 'CRITICAL', re: /sk-[A-Za-z0-9]{48}/g },
  { name: 'Discord Token', sev: 'HIGH', re: /[MN][A-Za-z0-9]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}/g },
  { name: 'Shopify Token', sev: 'HIGH', re: /shpss_[a-fA-F0-9]{32}|shpat_[a-fA-F0-9]{32}/g },
];

export async function scanJSSecrets(jsFiles: EndpointEntry[]): Promise<SecretFinding[]> {
  const secrets: SecretFinding[] = [];
  const total = Math.min(jsFiles.length, 80);
  for (let i = 0; i < total; i++) {
    try {
      const r = await pFetch(jsFiles[i].url, 15000);
      if (!r.ok) continue;
      let text = await r.text();
      if (text.length > 500000) continue;
      text = text.replace(/\\x([0-9a-f]{2})/gi, (_, h) => { try { return String.fromCharCode(parseInt(h, 16)); } catch { return _; } });
      JS_SECRET_PATTERNS.forEach(pat => {
        const re = new RegExp(pat.re.source, pat.re.flags);
        let m;
        let count = 0;
        while ((m = re.exec(text)) !== null && count < 5) {
          const val = m[1] || m[0];
          if (val && val.length > 6 && val.length < 300 && !/^[0]+$/.test(val) && !/^[a-z_]+$/.test(val)) {
            secrets.push({ type: pat.name, sev: pat.sev, value: val.slice(0, 120), file: jsFiles[i].url, line: (text.substring(0, text.indexOf(val)).match(/\n/g) || []).length + 1 });
            count++;
          }
        }
      });
    } catch { /* */ }
    if (i % 10 === 0) await sleep(50);
  }
  return secrets;
}

// ══════════════════════════════════════════
//  DOM XSS SINK SCANNING
// ══════════════════════════════════════════

const DOM_XSS_SINKS = [
  { re: /\.innerHTML\s*=/g, name: '.innerHTML', sev: 'CRITICAL' },
  { re: /\.outerHTML\s*=/g, name: '.outerHTML', sev: 'CRITICAL' },
  { re: /document\.write\s*\(/g, name: 'document.write', sev: 'CRITICAL' },
  { re: /document\.writeln\s*\(/g, name: 'document.writeln', sev: 'CRITICAL' },
  { re: /eval\s*\(/g, name: 'eval()', sev: 'CRITICAL' },
  { re: /setTimeout\s*\(\s*['"]/g, name: 'setTimeout(string)', sev: 'HIGH' },
  { re: /setInterval\s*\(\s*['"]/g, name: 'setInterval(string)', sev: 'HIGH' },
  { re: /\.insertAdjacentHTML\s*\(/g, name: 'insertAdjacentHTML', sev: 'HIGH' },
  { re: /location\s*=|location\.href\s*=/g, name: 'location assign', sev: 'MEDIUM' },
  { re: /window\.open\s*\(/g, name: 'window.open', sev: 'MEDIUM' },
];

export async function scanDOMXSS(jsFiles: EndpointEntry[]): Promise<DOMXSSFinding[]> {
  const findings: DOMXSSFinding[] = [];
  for (const js of jsFiles.slice(0, 60)) {
    try {
      const r = await pFetch(js.url, 15000);
      if (!r.ok) continue;
      const text = await r.text();
      DOM_XSS_SINKS.forEach(sink => {
        const count = (text.match(sink.re) || []).length;
        if (count > 0) findings.push({ sink: sink.name, sev: sink.sev, count, file: js.url });
      });
    } catch { /* */ }
    await sleep(20);
  }
  return findings;
}

// ══════════════════════════════════════════
//  CORS MISCONFIGURATION SCANNER
// ══════════════════════════════════════════

export async function scanCORS(hosts: string[]): Promise<CORSFinding[]> {
  const findings: CORSFinding[] = [];
  for (const host of hosts.slice(0, 30)) {
    const origins = ['https://evil.com', 'null', `https://${host}.evil.com`];
    for (const origin of origins) {
      try {
        const r = await sf(`https://${host}`, { headers: { 'Origin': origin } }, 5000);
        const acao = r.headers.get('access-control-allow-origin') || '';
        const acac = r.headers.get('access-control-allow-credentials') || '';
        if (acao === '*') {
          findings.push({ host, type: 'Wildcard CORS', acao, acac, origin, sev: acac === 'true' ? 'HIGH' : 'MEDIUM' });
        } else if (acao === origin) {
          findings.push({ host, type: 'Reflected Origin', acao, acac, origin, sev: 'HIGH' });
        } else if (acao === 'null') {
          findings.push({ host, type: 'Null Origin Accepted', acao, acac, origin, sev: 'MEDIUM' });
        }
      } catch { /* */ }
    }
    await sleep(100);
  }
  return findings;
}

// ══════════════════════════════════════════
//  CONTENT DISCOVERY
// ══════════════════════════════════════════

const CONTENT_PATHS = [
  '/.git/HEAD', '/.git/config', '/.env', '/.env.local', '/.env.production',
  '/wp-admin/', '/wp-login.php', '/wp-config.php.bak', '/wp-json/wp/v2/users',
  '/phpinfo.php', '/info.php', '/server-status', '/server-info',
  '/actuator', '/actuator/env', '/actuator/health', '/actuator/beans',
  '/swagger-ui.html', '/swagger.json', '/api-docs', '/openapi.json',
  '/.DS_Store', '/Thumbs.db', '/crossdomain.xml', '/.well-known/security.txt',
  '/backup.sql', '/dump.sql', '/db.sql', '/database.sql',
  '/admin', '/administrator', '/phpmyadmin', '/adminer.php',
  '/debug', '/trace', '/console', '/shell',
  '/graphql', '/api/graphql', '/graphiql',
  '/.htaccess', '/.htpasswd', '/web.config',
  '/config.yml', '/config.json', '/settings.json',
  '/docker-compose.yml', '/Dockerfile', '/kubernetes.yml',
  '/.aws/credentials', '/id_rsa', '/id_rsa.pub',
  '/api/v1/users', '/api/v1/admin', '/api/debug', '/api/config',
  '/telescope', '/horizon', '/nova',
  '/rails/info', '/debug/pprof/',
];

export async function contentDiscovery(domain: string, hosts: string[]): Promise<ContentFinding[]> {
  const findings: ContentFinding[] = [];
  const targets = hosts.slice(0, 5);
  const sensitiveExts = ['.git', '.env', '.sql', '.bak', 'id_rsa', 'credentials', 'config.php', 'docker-compose'];
  for (const host of targets) {
    for (const path of CONTENT_PATHS) {
      try {
        const url = `https://${host}${path}`;
        const r = await sf(url, {}, 5000);
        if (r.status === 200 || r.status === 403) {
          const text = await r.text();
          const sensitive = sensitiveExts.some(e => path.includes(e));
          const sev = sensitive && r.status === 200 ? 'CRITICAL' : r.status === 403 ? 'LOW' : 'MEDIUM';
          if (r.status === 200 && text.length > 50) {
            findings.push({ path, host, url, status: r.status, size: text.length, sev, sensitive });
          }
        }
      } catch { /* */ }
      await sleep(50);
    }
  }
  return findings;
}

// ══════════════════════════════════════════
//  NUCLEI TEMPLATE MATCHING
// ══════════════════════════════════════════

const NUCLEI_TEMPLATES = [
  { path: '/.git/HEAD', match: 'ref:', template: 'git-config', sev: 'CRITICAL', cve: '' },
  { path: '/.env', match: /DB_|APP_KEY|SECRET|PASSWORD/i, template: 'env-file', sev: 'CRITICAL', cve: '' },
  { path: '/phpinfo.php', match: 'phpinfo()', template: 'phpinfo', sev: 'HIGH', cve: '' },
  { path: '/actuator/env', match: /"propertySources"/, template: 'spring-actuator', sev: 'CRITICAL', cve: 'CVE-2022-22965' },
  { path: '/swagger-ui.html', match: /swagger/i, template: 'swagger-ui', sev: 'MEDIUM', cve: '' },
  { path: '/graphql', match: /__schema/i, template: 'graphql-introspection', sev: 'HIGH', cve: '' },
  { path: '/wp-json/wp/v2/users', match: /"slug":/i, template: 'wp-user-enum', sev: 'MEDIUM', cve: '' },
];

export async function nucleiScan(hosts: string[]): Promise<NucleiFinding[]> {
  const findings: NucleiFinding[] = [];
  for (const host of hosts.slice(0, 5)) {
    for (const tmpl of NUCLEI_TEMPLATES) {
      try {
        const url = `https://${host}${tmpl.path}`;
        const r = await sf(url, {}, 5000);
        if (r.status === 200) {
          const text = await r.text();
          const matched = typeof tmpl.match === 'string' ? text.includes(tmpl.match) : tmpl.match.test(text);
          if (matched) {
            findings.push({ template: tmpl.template, host, url, sev: tmpl.sev, status: r.status, cve: tmpl.cve, confirmed: true });
          }
        }
      } catch { /* */ }
      await sleep(30);
    }
  }
  return findings;
}

// ══════════════════════════════════════════
//  HTTP PROBE
// ══════════════════════════════════════════

export async function probeHost(host: string): Promise<ProbeFinding> {
  const result: ProbeFinding = { host, url: `https://${host}`, status: 0, alive: false, title: '', tech: [], redirected: false, final_url: '', error: '' };
  for (const scheme of ['https://', 'http://']) {
    try {
      const r = await sf(`${scheme}${host}`, {}, 8000);
      const text = await r.text();
      result.status = r.status;
      result.alive = r.status > 0;
      result.url = `${scheme}${host}`;
      result.title = (text.match(/<title[^>]*>([^<]{1,200})<\/title>/i) || [])[1] || '';
      // Tech detection from headers
      const server = r.headers.get('server') || '';
      const powered = r.headers.get('x-powered-by') || '';
      if (server) result.tech.push(server);
      if (powered) result.tech.push(powered);
      if (/wp-content|wordpress/i.test(text)) result.tech.push('WordPress');
      if (/react/i.test(text)) result.tech.push('React');
      if (/next/i.test(text) || r.headers.get('x-nextjs-cache')) result.tech.push('Next.js');
      if (/angular/i.test(text)) result.tech.push('Angular');
      if (/vue/i.test(text)) result.tech.push('Vue.js');
      if (result.alive) break;
    } catch { /* */ }
  }
  return result;
}

// ══════════════════════════════════════════
//  DARK WEB OSINT (clearnet APIs)
// ══════════════════════════════════════════

export async function checkHIBP(domain: string): Promise<DarkWebFinding[]> {
  const findings: DarkWebFinding[] = [];
  try {
    const r = await pFetch('https://haveibeenpwned.com/api/v3/breaches', 20000);
    const breaches = await r.json();
    if (!Array.isArray(breaches)) return findings;
    breaches.filter((b: any) => (b.Domain || '').toLowerCase() === domain.toLowerCase()).forEach((b: any) => {
      findings.push({
        source: 'HaveIBeenPwned', type: 'breach', severity: 'CRITICAL',
        title: `${b.Name} Data Breach`,
        detail: `${(b.PwnCount || 0).toLocaleString()} accounts · ${(b.DataClasses || []).slice(0, 5).join(', ')}`,
        date: b.BreachDate, url: `https://haveibeenpwned.com/PwnedWebsites#${b.Name}`,
      });
    });
  } catch { /* */ }
  return findings;
}

export async function checkHudsonRock(domain: string): Promise<DarkWebFinding[]> {
  const findings: DarkWebFinding[] = [];
  try {
    const r = await pFetch(`https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain=${encodeURIComponent(domain)}`, 15000);
    const d = await r.json();
    const total = (d.employees || []).length + (d.users || []).length;
    if (total > 0) {
      findings.push({
        source: 'Hudson Rock', type: 'infostealer_log', severity: 'CRITICAL',
        title: `${total} infostealer-compromised accounts found`,
        detail: `${(d.employees || []).length} employees · ${(d.users || []).length} users`,
        url: 'https://www.hudsonrock.com/threat-intelligence-cybercrime-tools',
      });
    }
  } catch { /* */ }
  return findings;
}

export async function checkRansomWatch(domain: string): Promise<DarkWebFinding[]> {
  const findings: DarkWebFinding[] = [];
  try {
    const r = await pFetch('https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json', 20000);
    const posts = await r.json();
    const domainBase = domain.replace(/^www\./, '').split('.')[0].toLowerCase();
    posts.filter((p: any) => (p.post_title || '').toLowerCase().includes(domainBase)).forEach((p: any) => {
      findings.push({
        source: 'RansomWatch', type: 'ransomware_victim', severity: 'CRITICAL',
        title: `⚠️ Possible ransomware victim: ${p.post_title || ''}`,
        detail: `Gang: ${p.group_name || '?'} · Date: ${p.discovered || '?'}`,
        url: 'https://ransomwatch.telemetry.ltd/#/profiles',
      });
    });
  } catch { /* */ }
  return findings;
}

export async function searchLeakIX(domain: string): Promise<DarkWebFinding[]> {
  const findings: DarkWebFinding[] = [];
  try {
    const r = await pFetch(`https://leakix.net/search?scope=leak&q=${encodeURIComponent(domain)}`, 15000);
    const html = await r.text();
    const count = (html.match(/class="event-/g) || []).length;
    if (count > 0) {
      findings.push({
        source: 'LeakIX', type: 'leak', severity: 'HIGH',
        title: `${count} potential leaks/exposures found`,
        detail: `Check LeakIX for details`, url: `https://leakix.net/search?scope=leak&q=${encodeURIComponent(domain)}`,
      });
    }
  } catch { /* */ }
  return findings;
}

// ══════════════════════════════════════════
//  VULN DETECTION FROM ENDPOINTS
// ══════════════════════════════════════════

export function detectVulns(eps: EndpointEntry[], params: Record<string, number>): VulnFinding[] {
  const findings: VulnFinding[] = [];
  const highRisk = Object.keys(params).filter(p => /^(id|user|admin|key|token|url|redirect|file|path|cmd|exec|query|sql|debug|template|callback)$/i.test(p));

  eps.forEach(ep => {
    try {
      const u = new URL(ep.url);
      for (const [k, v] of u.searchParams.entries()) {
        const kl = k.toLowerCase();
        if (/^(url|redirect|next|return|goto|dest|href)$/.test(kl)) {
          findings.push({ type: 'Open Redirect', sev: 'HIGH', url: ep.url, param: k, desc: `Redirect param found`, test: ep.url.replace(`${k}=${v}`, `${k}=https://evil.com`) });
        }
        if (/^(url|host|api|fetch|proxy|load|server)$/.test(kl)) {
          findings.push({ type: 'Potential SSRF', sev: 'CRITICAL', url: ep.url, param: k, desc: 'SSRF-prone parameter', test: ep.url.replace(`${k}=${v}`, `${k}=http://169.254.169.254/`) });
        }
        if (/^(id|uid|user_id|product_id)$/.test(kl)) {
          findings.push({ type: 'Potential SQLi', sev: 'HIGH', url: ep.url, param: k, desc: 'Numeric ID parameter', test: ep.url.replace(`${k}=${v}`, `${k}=1'`) });
        }
        if (/^(file|path|page|include|template)$/.test(kl)) {
          findings.push({ type: 'Potential LFI', sev: 'CRITICAL', url: ep.url, param: k, desc: 'File path parameter', test: ep.url.replace(`${k}=${v}`, `${k}=../../../etc/passwd`) });
        }
      }
    } catch { /* */ }
  });

  // Deduplicate
  const seen = new Set<string>();
  return findings.filter(f => { const key = f.type + f.param + f.url; if (seen.has(key)) return false; seen.add(key); return true; });
}

// ══════════════════════════════════════════
//  TECH CVE MAPPING
// ══════════════════════════════════════════

const TECH_CVE_MAP: Record<string, string[]> = {
  'WordPress': ['CVE-2022-21661 (SQL injection)', 'CVE-2021-29447 (XXE)'],
  'Drupal': ['CVE-2018-7600 (Drupalgeddon2)', 'CVE-2019-6340 (RCE)'],
  'Apache': ['CVE-2021-41773 (Path Traversal)', 'CVE-2021-42013 (RCE)'],
  'Nginx': ['CVE-2019-11043 (PHP RCE)', 'CVE-2021-23017 (1-byte heap OOB)'],
  'Next.js': ['CVE-2022-21721 (Open Redirect)', 'CVE-2023-46298 (DoS)'],
  'Spring': ['CVE-2022-22965 (Spring4Shell RCE)'],
  'Grafana': ['CVE-2021-43798 (Path Traversal)'],
  'Jenkins': ['CVE-2024-23897 (Arbitrary file read)'],
  'GitLab': ['CVE-2021-22205 (RCE via ExifTool)'],
};

export function mapTechCVEs(techList: string[]) {
  const findings: { tech: string; cves: string[] }[] = [];
  techList.forEach(t => {
    Object.entries(TECH_CVE_MAP).forEach(([tech, cves]) => {
      if (t.toLowerCase().includes(tech.toLowerCase())) findings.push({ tech, cves });
    });
  });
  return findings;
}

// ══════════════════════════════════════════
//  AUTH SURFACE MAPPING
// ══════════════════════════════════════════

export function mapAuthSurface(eps: EndpointEntry[]) {
  const surface: Record<string, string[]> = { login: [], oauth: [], apikey: [], jwt: [], registration: [], password_reset: [], mfa: [], admin: [] };
  eps.forEach(ep => {
    const u = ep.url.toLowerCase();
    if (/\/login|\/sign[-_]?in|\/auth\/login/.test(u)) surface.login.push(ep.url);
    if (/\/oauth|\/authorize|\/callback|\/token/.test(u)) surface.oauth.push(ep.url);
    if (/api[-_]?key|\/api\/.*key/.test(u)) surface.apikey.push(ep.url);
    if (/jwt|bearer|\.token/.test(u)) surface.jwt.push(ep.url);
    if (/\/register|\/sign[-_]?up/.test(u)) surface.registration.push(ep.url);
    if (/password[-_]?reset|forgot[-_]?password/.test(u)) surface.password_reset.push(ep.url);
    if (/\/2fa|\/mfa|\/totp|\/otp/.test(u)) surface.mfa.push(ep.url);
    if (/\/admin|\/dashboard|\/panel/.test(u)) surface.admin.push(ep.url);
  });
  return surface;
}

// ══════════════════════════════════════════
//  SCAN DNS BRUTE FORCE
// ══════════════════════════════════════════

const BF_WORDS = ['www', 'mail', 'ftp', 'smtp', 'pop', 'imap', 'webmail', 'ns1', 'ns2', 'dns', 'mx', 'vpn', 'remote', 'dev', 'staging', 'test', 'beta', 'api', 'app', 'admin', 'portal', 'blog', 'shop', 'store', 'cdn', 'img', 'images', 'static', 'assets', 'media', 'upload', 'files', 'docs', 'wiki', 'support', 'help', 'status', 'monitor', 'grafana', 'jenkins', 'gitlab', 'jira', 'confluence', 'git', 'ci', 'cd', 'deploy', 'build', 'stage', 'uat', 'prod', 'demo', 'sandbox', 'internal', 'intranet', 'corp', 'private', 'secure', 'auth', 'sso', 'login', 'signup', 'register', 'dashboard', 'panel', 'console', 'manage', 'cms', 'crm', 'erp', 'hr', 'finance', 'billing', 'pay', 'payment', 'checkout', 'cart', 'order', 'track', 'analytics', 'metrics', 'log', 'elk', 'kibana', 'elastic', 'redis', 'mongo', 'mysql', 'postgres', 'db', 'database', 'backup', 'bak', 'old', 'new', 'v2', 'v3', 'api2', 'api-v2', 'm', 'mobile', 'ws', 'socket', 'realtime', 'live', 'stream', 'video', 'chat', 'forum', 'community'];

export async function dnsBruteforce(domain: string, onFound: (item: { subdomain: string; ip: string }) => void) {
  for (let i = 0; i < BF_WORDS.length; i += 20) {
    const batch = BF_WORDS.slice(i, i + 20);
    await Promise.all(batch.map(async word => {
      const sub = `${word}.${domain}`;
      const ip = await resolveHost(sub);
      if (ip) onFound({ subdomain: sub, ip });
    }));
    await sleep(30);
  }
}

// ══════════════════════════════════════════
//  COOKIE ANALYSIS
// ══════════════════════════════════════════

export async function analyzeCookies(hosts: string[]): Promise<CookieFinding[]> {
  const findings: CookieFinding[] = [];
  for (const host of hosts.slice(0, 10)) {
    try {
      const r = await sf(`https://${host}`, {}, 5000);
      const cookies = r.headers.get('set-cookie') || '';
      if (!cookies) continue;
      cookies.split(',').forEach(cookie => {
        const name = (cookie.split('=')[0] || '').trim();
        if (!name) return;
        const issues: { issue: string; desc: string; sev: string }[] = [];
        if (!cookie.toLowerCase().includes('httponly')) issues.push({ issue: 'Missing HttpOnly', desc: 'Cookie accessible via JavaScript', sev: 'HIGH' });
        if (!cookie.toLowerCase().includes('secure')) issues.push({ issue: 'Missing Secure flag', desc: 'Cookie sent over HTTP', sev: 'HIGH' });
        if (!cookie.toLowerCase().includes('samesite')) issues.push({ issue: 'Missing SameSite', desc: 'CSRF vulnerability risk', sev: 'MEDIUM' });
        if (issues.length) findings.push({ host, name, issues });
      });
    } catch { /* */ }
  }
  return findings;
}

// ══════════════════════════════════════════
//  FULL SCAN ORCHESTRATOR
// ══════════════════════════════════════════

export type ModuleStatus = 'pending' | 'running' | 'done' | 'error' | 'skip';
export type ModuleCallback = (name: string, status: ModuleStatus, detail?: string) => void;
export type ProgressCallback = (pct: number, label: string) => void;
export type DataCallback = (state: Partial<ScanState>) => void;

export async function safeRun<T>(name: string, fn: () => Promise<T>, onModule: ModuleCallback, opts?: { retries?: number; timeout?: number }): Promise<T | null> {
  const maxRetries = opts?.retries ?? 1;
  const timeout = opts?.timeout ?? 60000;
  onModule(name, 'running');
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      const result = await Promise.race([fn(), new Promise<never>((_, reject) => setTimeout(() => reject(new Error('Timeout')), timeout))]);
      onModule(name, 'done');
      return result;
    } catch (e: any) {
      if (attempt < maxRetries) await sleep(1000 * (attempt + 1));
      else { onModule(name, 'error', e.message); return null; }
    }
  }
  return null;
}

export async function runFullScan(
  domain: string,
  sources: Record<string, boolean>,
  onModule: ModuleCallback,
  onProgress: ProgressCallback,
  onData: DataCallback,
) {
  const state = createScanState();
  state.domain = domain;
  state.scanning = true;

  // ── Phase 1: Subdomain Collection ──
  onProgress(5, '🌐 Subdomain Collection…');
  const subSources: { name: string; fn: () => Promise<{ subdomain: string; ip: string; source: string }[]>; id: string }[] = [
    { name: 'crt.sh', fn: () => fetchCrtSh(domain), id: 'crt' },
    { name: 'HackerTarget', fn: () => fetchHT(domain), id: 'ht' },
    { name: 'AnubisDB', fn: () => fetchAnubis(domain), id: 'jldc' },
    { name: 'RapidDNS', fn: () => fetchRapidDNS(domain), id: 'rapiddns' },
    { name: 'CertSpotter', fn: () => fetchCertSpotter(domain), id: 'certspot' },
    { name: 'OTX PassiveDNS', fn: () => fetchOTXSubs(domain), id: 'otxsub' },
    { name: 'URLScan', fn: () => fetchURLScanSubs(domain), id: 'urlscan' },
    { name: 'ThreatMiner', fn: () => fetchThreatMiner(domain), id: 'threatminer' },
    { name: 'Sonar', fn: () => fetchSonar(domain), id: 'sonar' },
    { name: 'Wayback Subs', fn: () => fetchWBSubs(domain), id: 'wbsubs' },
    { name: 'VirusTotal', fn: () => fetchVirusTotal(domain), id: 'virus' },
  ];

  const subJobs = subSources.filter(s => sources[s.id] !== false).map(s =>
    safeRun(s.name, async () => {
      const res = await s.fn();
      res.forEach(item => {
        if (!state.subs.find(e => e.subdomain === item.subdomain)) {
          state.subs.push({ subdomain: item.subdomain, ip: item.ip || '', status: item.ip ? 'resolved' : 'unknown', source: item.source, ports: [], geo: '', cname: '', tko: false, httpStatus: 0, alive: false });
        }
      });
      onData({ subs: [...state.subs] });
      return res.length;
    }, onModule, { retries: 2, timeout: 40000 })
  );
  await Promise.allSettled(subJobs);

  // ── Phase 2: DNS Resolution ──
  onProgress(25, '🔍 DNS Resolution…');
  await safeRun('DNS Resolution', async () => {
    const unres = state.subs.filter(s => !s.ip).slice(0, 300);
    for (let i = 0; i < unres.length; i += 20) {
      const batch = unres.slice(i, i + 20);
      await Promise.all(batch.map(async sub => {
        const ip = await resolveHost(sub.subdomain);
        if (ip) {
          sub.ip = ip; sub.status = 'resolved';
          if (!state.ips[ip]) state.ips[ip] = { hosts: [], ports: [], cves: [], vulns: [], geo: null };
          state.ips[ip].hosts.push(sub.subdomain);
        } else sub.status = 'unresolved';
      }));
      await sleep(20);
    }
    onData({ subs: [...state.subs], ips: { ...state.ips } });
  }, onModule, { retries: 1, timeout: 120000 });

  // ── DNS Bruteforce ──
  if (sources.brute !== false) {
    await safeRun('DNS Bruteforce', async () => {
      await dnsBruteforce(domain, item => {
        if (!state.subs.find(s => s.subdomain === item.subdomain)) {
          state.subs.push({ subdomain: item.subdomain, ip: item.ip, status: 'resolved', source: 'bruteforce', ports: [], geo: '', cname: '', tko: false, httpStatus: 0, alive: false });
          if (!state.ips[item.ip]) state.ips[item.ip] = { hosts: [], ports: [], cves: [], vulns: [], geo: null };
          state.ips[item.ip].hosts.push(item.subdomain);
        }
      });
      onData({ subs: [...state.subs] });
    }, onModule, { retries: 0, timeout: 120000 });
  } else onModule('DNS Bruteforce', 'skip');

  // ── Phase 3: DNS Records ──
  onProgress(35, '📡 DNS Records…');
  await safeRun('DNS Records', async () => {
    for (const type of ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'CAA'] as const) {
      const recs = await apiDNS(domain, type);
      state.dns[type] = recs.map(r => ({ val: r.data, ttl: r.ttl, src: '' }));
    }
    state.dns.EMAIL = state.dns.TXT.filter(r => /v=spf1|v=DMARC1|v=DKIM/i.test(r.val));
    onData({ dns: { ...state.dns } });
  }, onModule, { retries: 2, timeout: 30000 });

  // ── Phase 4: Shodan IDB ──
  onProgress(45, '🔌 Shodan IDB + Ports…');
  await safeRun('Shodan InternetDB', async () => {
    const ips = Object.keys(state.ips).slice(0, 60);
    for (let i = 0; i < ips.length; i += 10) {
      const batch = ips.slice(i, i + 10);
      await Promise.all(batch.map(async ip => {
        const d = await apiIDB(ip);
        if (!d) return;
        state.ips[ip].ports = d.ports || [];
        state.ips[ip].cves = d.cves || [];
        (d.hostnames || []).forEach((h: string) => {
          if (isValidSub(h, domain) && !state.subs.find(s => s.subdomain === h)) {
            state.subs.push({ subdomain: h, ip, status: 'resolved', source: 'Shodan', ports: d.ports || [], geo: '', cname: '', tko: false, httpStatus: 0, alive: false });
          }
        });
        state.ips[ip].hosts.forEach((h: string) => {
          const sub = state.subs.find(s => s.subdomain === h);
          if (sub) sub.ports = d.ports || [];
        });
      }));
      await sleep(80);
    }
    onData({ subs: [...state.subs], ips: { ...state.ips } });
  }, onModule, { retries: 1, timeout: 60000 });

  // ── Phase 5: HTTP Probe ──
  onProgress(55, '⚡ HTTP Probe…');
  await safeRun('HTTP Probe', async () => {
    const live = state.subs.filter(s => s.status === 'resolved').slice(0, 80);
    for (let i = 0; i < live.length; i += 10) {
      const batch = live.slice(i, i + 10);
      const res = await Promise.all(batch.map(sub => probeHost(sub.subdomain)));
      res.forEach(r => {
        state.probes.push(r);
        const sub = state.subs.find(s => s.subdomain === r.host);
        if (sub) { sub.httpStatus = r.status; sub.alive = r.alive; }
      });
      onProgress(55 + Math.round((i / live.length) * 10));
    }
    // Extract tech from probes
    state.probes.forEach(p => p.tech.forEach(t => { if (!state.tech.includes(t)) state.tech.push(t); }));
    onData({ probes: [...state.probes], subs: [...state.subs], tech: [...state.tech] });
  }, onModule, { retries: 1, timeout: 120000 });

  // ── Phase 6: Endpoint Collection ──
  onProgress(65, '🔗 Endpoint Collection…');
  const epSeen = new Set<string>();
  const addEp = (item: EndpointEntry) => {
    const u = normUrl(item.url);
    if (!u || isJunkUrl(u) || JUNK.test(u)) return;
    const k = urlKey(u);
    if (epSeen.has(k)) return;
    epSeen.add(k);
    state.eps.push({ url: u, status: item.status, source: item.source });
    try { new URL(u).searchParams.forEach((v, k) => { if (v && v.length < 60) state.params[k] = (state.params[k] || 0) + 1; }); } catch { /* */ }
  };

  const epSources = [
    { name: 'Wayback CDX', fn: () => fetchWBUrls(domain), id: 'wb' },
    { name: 'OTX URLs', fn: () => fetchOTXUrls(domain), id: 'otxurl' },
    { name: 'CommonCrawl', fn: () => fetchCC(domain), id: 'cc' },
    { name: 'URLScan URLs', fn: () => fetchURLScanUrls(domain), id: 'uscan' },
    { name: 'Sitemap', fn: () => fetchSitemap(domain), id: 'sitemap' },
    { name: 'Robots.txt', fn: () => fetchRobotsTxt(domain), id: 'robotstxt' },
  ];

  const epJobs = epSources.filter(s => sources[s.id] !== false).map(s =>
    safeRun(s.name, async () => {
      const res = await s.fn();
      res.forEach(addEp);
      state.js = state.eps.filter(r => /\.js(\?|$)/i.test(r.url));
      onData({ eps: [...state.eps], js: [...state.js], params: { ...state.params } });
      return res.length;
    }, onModule, { retries: 2, timeout: 60000 })
  );
  await Promise.allSettled(epJobs);

  // ── Phase 7: Security Headers ──
  onProgress(72, '📡 Security Headers…');
  await safeRun('Security Headers', async () => {
    try {
      const r = await sf(`https://${domain}`, {}, 10000);
      const hdrs: Record<string, string> = {};
      r.headers.forEach((v: string, k: string) => { hdrs[k] = v; });
      state.hdrs = Object.entries(hdrs).map(([k, v]) => ({ key: k, value: v }));
      // WAF detection
      const wafSigs: Record<string, RegExp> = { Cloudflare: /cloudflare/i, Akamai: /akamai/i, AWS_WAF: /awselb|amazon/i, Incapsula: /incap/i, Sucuri: /sucuri/i, F5: /bigip/i };
      const server = hdrs['server'] || '';
      const via = hdrs['via'] || '';
      for (const [name, re] of Object.entries(wafSigs)) { if (re.test(server) || re.test(via)) { state.waf = name; break; } }
    } catch { /* */ }
    onData({ hdrs: [...state.hdrs], waf: state.waf });
  }, onModule, { retries: 2, timeout: 15000 });

  // ── Phase 8: WHOIS ──
  onProgress(75, '📋 WHOIS/RDAP…');
  await safeRun('WHOIS/RDAP', async () => {
    state.whois = await apiRDAP(domain) || {};
    onData({ whois: state.whois });
  }, onModule, { retries: 2, timeout: 20000 });

  // ── Phase 9: JS Secret Scan ──
  if (state.js.length > 0 && sources.jsfind !== false) {
    onProgress(78, '🔑 JS Secret Scan…');
    await safeRun('JS Secret Scan', async () => {
      state.secrets = await scanJSSecrets(state.js);
      onData({ secrets: [...state.secrets] });
      return state.secrets.length;
    }, onModule, { retries: 1, timeout: 120000 });
  } else onModule('JS Secret Scan', 'skip');

  // ── Phase 10: DOM XSS ──
  if (state.js.length > 0) {
    await safeRun('DOM XSS Scan', async () => {
      state.domXss = await scanDOMXSS(state.js);
      onData({ domXss: [...state.domXss] });
    }, onModule, { retries: 1, timeout: 120000 });
  }

  // ── Phase 11: CORS Scan ──
  if (sources.cors !== false) {
    onProgress(82, '🌐 CORS Scan…');
    await safeRun('CORS Scanner', async () => {
      const liveHosts = state.subs.filter(s => s.alive).map(s => s.subdomain);
      state.corsFindings = await scanCORS(liveHosts.length ? liveHosts : [domain]);
      onData({ corsFindings: [...state.corsFindings] });
    }, onModule, { retries: 1, timeout: 60000 });
  } else onModule('CORS Scanner', 'skip');

  // ── Phase 12: Content Discovery ──
  if (sources.content !== false) {
    onProgress(85, '📂 Content Discovery…');
    await safeRun('Content Discovery', async () => {
      const hosts = state.subs.filter(s => s.alive).map(s => s.subdomain).slice(0, 3);
      if (!hosts.length) hosts.push(domain);
      state.contentFindings = await contentDiscovery(domain, hosts);
      onData({ contentFindings: [...state.contentFindings] });
    }, onModule, { retries: 1, timeout: 120000 });
  } else onModule('Content Discovery', 'skip');

  // ── Phase 13: Nuclei Templates ──
  if (sources.nuclei !== false) {
    await safeRun('Nuclei Templates', async () => {
      const hosts = state.subs.filter(s => s.alive).map(s => s.subdomain).slice(0, 3);
      if (!hosts.length) hosts.push(domain);
      state.nucleiFindings = await nucleiScan(hosts);
      onData({ nucleiFindings: [...state.nucleiFindings] });
    }, onModule, { retries: 1, timeout: 60000 });
  } else onModule('Nuclei Templates', 'skip');

  // ── Phase 14: Cookie Analysis ──
  await safeRun('Cookie Analysis', async () => {
    const hosts = state.subs.filter(s => s.alive).map(s => s.subdomain).slice(0, 10);
    if (!hosts.length) hosts.push(domain);
    state.cookieFindings = await analyzeCookies(hosts);
    onData({ cookieFindings: [...state.cookieFindings] });
  }, onModule, { retries: 1, timeout: 30000 });

  // ── Phase 15: Vuln Detection ──
  onProgress(90, '🚨 Vulnerability Detection…');
  state.vulns = detectVulns(state.eps, state.params);
  onData({ vulns: [...state.vulns] });
  onModule('Vuln Detection', 'done');

  // ── Phase 16: Dark Web OSINT ──
  onProgress(93, '🌑 Dark Web OSINT…');
  await safeRun('Dark Web OSINT', async () => {
    const [hibp, hudson, ransom, leakix] = await Promise.allSettled([
      checkHIBP(domain), checkHudsonRock(domain), checkRansomWatch(domain), searchLeakIX(domain),
    ]);
    state.darkWebFindings = [
      ...(hibp.status === 'fulfilled' ? hibp.value : []),
      ...(hudson.status === 'fulfilled' ? hudson.value : []),
      ...(ransom.status === 'fulfilled' ? ransom.value : []),
      ...(leakix.status === 'fulfilled' ? leakix.value : []),
    ];
    onData({ darkWebFindings: [...state.darkWebFindings] });
  }, onModule, { retries: 1, timeout: 60000 });

  // ── Phase 17: IP Geolocation ──
  onProgress(96, '🌍 IP Geolocation…');
  if (sources.geo !== false) {
    await safeRun('IP Geolocation', async () => {
      const ips = Object.keys(state.ips).slice(0, 30);
      for (let i = 0; i < ips.length; i += 6) {
        const batch = ips.slice(i, i + 6);
        await Promise.all(batch.map(async ip => {
          const g = await fetchGeo(ip);
          if (g) {
            state.ips[ip].geo = g;
            state.ips[ip].hosts.forEach((h: string) => {
              const sub = state.subs.find(s => s.subdomain === h);
              if (sub) sub.geo = `${g.city ? g.city + ', ' : ''}${g.country_code || ''}${g.org ? ' · ' + g.org : ''}`;
            });
          }
        }));
        await sleep(150);
      }
      onData({ subs: [...state.subs], ips: { ...state.ips } });
    }, onModule, { retries: 1, timeout: 60000 });
  } else onModule('IP Geolocation', 'skip');

  onProgress(100, '✅ Scan Complete');
  state.scanning = false;
  onData(state);
  return state;
}

// ══════════════════════════════════════════
//  EXPORT HELPERS
// ══════════════════════════════════════════

export function generateMarkdownReport(state: ScanState): string {
  const ts = new Date().toISOString();
  let md = `# TeamCyberOps Recon Report — ${state.domain}\n\n`;
  md += `**Generated:** ${ts} | **Tool:** TeamCyberOps Recon v14 | **github.com/mohidqx**\n\n---\n\n`;
  md += `## Summary\n| Metric | Count |\n|--------|-------|\n`;
  md += `| Subdomains | ${state.subs.length} |\n| Live Hosts | ${state.subs.filter(s => s.alive).length} |\n| Unique IPs | ${Object.keys(state.ips).length} |\n| Endpoints | ${state.eps.length} |\n| JS Files | ${state.js.length} |\n| Parameters | ${Object.keys(state.params).length} |\n| Secrets | ${state.secrets.length} |\n| CORS Issues | ${state.corsFindings.length} |\n| Dark Web | ${state.darkWebFindings.length} |\n\n`;
  md += `## Subdomains (${state.subs.length})\n\`\`\`\n`;
  state.subs.slice(0, 100).forEach(s => { md += `${s.subdomain}${s.ip ? ' → ' + s.ip : ''}\n`; });
  md += `\`\`\`\n\n---\n*Generated by TeamCyberOps Recon v14*\n`;
  return md;
}

export function generateBurpXML(eps: EndpointEntry[]): string {
  let xml = `<?xml version="1.0"?>\n<items burpVersion="2023.1" exportTime="${new Date().toISOString()}">\n`;
  eps.forEach(e => { xml += `  <item>\n    <url><![CDATA[${e.url}]]></url>\n  </item>\n`; });
  xml += '</items>';
  return xml;
}

export function generateNucleiTargets(subs: SubdomainEntry[]): string {
  return subs.filter(s => s.status === 'resolved').map(s => `https://${s.subdomain}`).join('\n');
}
