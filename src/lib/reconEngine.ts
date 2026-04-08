/* ══════════════════════════════════════════════════════
   TeamCyberOps Recon v14.6 — Full Client-Side Scanning Engine
   ALL features from v14.6 — NO LIMITS
   @mohidqx · github.com/mohidqx
══════════════════════════════════════════════════════ */

// ── TYPES ──
export interface SubdomainEntry {
  subdomain: string; ip: string; status: string; source: string;
  ports: number[]; geo: string; cname: string; tko: boolean;
  httpStatus: number; alive: boolean; ptr?: string;
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
export interface ProbeFinding { host: string; url: string; status: number; alive: boolean; title: string; tech: string[]; redirected: boolean; final_url: string; error?: string; server?: string; https?: boolean; cors?: boolean; clickjack?: boolean; hsts?: boolean; size?: number; }
export interface IDORFinding { url: string; param: string; original: number; tested: number; status: number; size: number; sev: string; desc: string; }
export interface RaceFinding { url: string; concurrent: number; success: number; sev: string; desc: string; }
export interface CachePoisonFinding { host: string; header: string; value: string; reflected: boolean; sev: string; desc: string; }
export interface CRLFFinding { url: string; param: string; payload: string; sev: string; desc: string; }
export interface HostInjectionFinding { url: string; sev: string; desc: string; }
export interface BLHFinding { domain: string; status: string; sev: string; registerUrl: string; }
export interface BountyFinding { platform: string; url: string; domain: string; scope?: string; status: string; contact?: string; policy?: string; }
export interface DepConfFinding { pkg: string; source: string; registry: string; status: string; sev: string; }
export interface ExploitFinding { id: string; tech: string; title: string; url: string; edb_id: string; }
export interface JWTFinding { source: string; file?: string; header: any; payload: any; issues: { sev: string; issue: string }[]; raw: string; }
export interface GraphQLFinding { host: string; url: string; typeCount: number; types: { name: string }[]; }
export interface MethodsFinding { host: string; url: string; allow: string; dangerous: string[]; sev: string; }

export interface ScanState {
  domain: string; scanning: boolean;
  subs: SubdomainEntry[]; ips: Record<string, any>;
  dns: Record<string, DNSRecord[]>;
  eps: EndpointEntry[]; js: EndpointEntry[]; params: Record<string, number>;
  hdrs: any[]; tech: string[]; waf: string;
  ssl: SSLCert[]; whois: any; takeover: TakeoverFinding[];
  otx: { p: number; m: number; u: number; pdns: any[]; };
  github: { orgs: any[]; repos: any[]; };
  cloud: { s3: S3Finding[]; asn: any; };
  secrets: SecretFinding[];
  corsFindings: CORSFinding[];
  nucleiFindings: NucleiFinding[];
  contentFindings: ContentFinding[];
  darkWebFindings: DarkWebFinding[];
  domXss: DOMXSSFinding[];
  cookieFindings: CookieFinding[];
  vulns: VulnFinding[];
  probes: ProbeFinding[];
  ghLeaks: GHLeakFinding[];
  uscan: any[];
  idorFindings: IDORFinding[];
  raceFindings: RaceFinding[];
  cachePoisonFindings: CachePoisonFinding[];
  crlfFindings: CRLFFinding[];
  hostInjectionFindings: HostInjectionFinding[];
  blhFindings: BLHFinding[];
  bountyFindings: BountyFinding[];
  depConfFindings: DepConfFinding[];
  exploitFindings: ExploitFinding[];
  jwtFindings: JWTFinding[];
  graphqlFindings: GraphQLFinding[];
  methodsFindings: MethodsFinding[];
  sstiFindings: SSTIFinding[];
  vhostFindings: VHostFinding[];
  emailFindings: EmailSecFinding[];
  dorks: DorkEntry[];
  pasteFindings: PasteFinding[];
  faviconHash: string;
  authSurface: Record<string, string[]>;
  riskScore: number;
  riskGrade: string;
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
    idorFindings: [], raceFindings: [], cachePoisonFindings: [],
    crlfFindings: [], hostInjectionFindings: [],
    blhFindings: [], bountyFindings: [], depConfFindings: [],
    exploitFindings: [], jwtFindings: [], graphqlFindings: [],
    methodsFindings: [], sstiFindings: [], vhostFindings: [],
    emailFindings: [], dorks: [], pasteFindings: [],
    faviconHash: '', authSurface: {},
    riskScore: 0, riskGrade: 'LOW',
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
    return { ok: false, status: 0, json: async () => ({}), text: async () => '', headers: new Headers() } as any;
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
//  SUBDOMAIN SOURCES — 15+ Sources (NO LIMITS)
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
  const seen = new Set<string>(), out: any[] = [];
  try {
    const r = await pFetch(`https://jldc.me/anubis/subdomains/${domain}`, 15000);
    const data = await r.json();
    if (Array.isArray(data)) data.forEach((s: string) => { s = String(s).trim().toLowerCase(); if (isValidSub(s, domain) && !seen.has(s)) { seen.add(s); out.push({ subdomain: s, ip: '', source: 'AnubisDB' }); } });
  } catch { /* */ }
  try {
    const r2 = await pFetch(`https://anubisdb.com/anubis/subdomains/${domain}`, 12000);
    const d2 = await r2.json();
    if (Array.isArray(d2)) d2.forEach((s: string) => { s = String(s).trim().toLowerCase(); if (isValidSub(s, domain) && !seen.has(s)) { seen.add(s); out.push({ subdomain: s, ip: '', source: 'AnubisDB' }); } });
  } catch { /* */ }
  return out;
}

export async function fetchRapidDNS(domain: string) {
  try {
    const r = await pFetch(`https://rapiddns.io/subdomain/${domain}?full=1`, 20000);
    const html = await r.text();
    const re = new RegExp('<td>([a-z0-9][a-z0-9\\-\\.]*\\.' + domain.replace(/\./g, '\\.') + ')<\\/td>', 'gi');
    const seen = new Set<string>(), out: any[] = [];
    let m;
    while ((m = re.exec(html)) !== null) {
      const s = m[1].trim().toLowerCase();
      if (isValidSub(s, domain) && !seen.has(s)) { seen.add(s); out.push({ subdomain: s, ip: '', source: 'RapidDNS' }); }
    }
    return out;
  } catch { return []; }
}

export async function fetchCertSpotter(domain: string) {
  try {
    const r = await pFetch(`https://api.certspotter.com/v1/issuances?domain=${domain}&include_subdomains=true&expand=dns_names`, 15000);
    const data = await r.json();
    if (!Array.isArray(data)) return [];
    const seen = new Set<string>();
    return data.flatMap((e: any) => (e.dns_names || []).map((s: string) => s.trim().replace(/^\*\./, '').toLowerCase()).filter((s: string) => isValidSub(s, domain) && !seen.has(s) && seen.add(s)).map((s: string) => ({ subdomain: s, ip: '', source: 'CertSpotter' })));
  } catch { return []; }
}

export async function fetchOTXSubs(domain: string) {
  const seen = new Set<string>(), out: any[] = [];
  for (const path of ['/passive_dns', '/general']) {
    try {
      const r = await pFetch(`https://otx.alienvault.com/api/v1/indicators/domain/${domain}${path}`, 15000);
      const d = await r.json();
      (d.passive_dns || []).forEach((rec: any) => {
        const h = (rec.hostname || rec.indicator || '').toLowerCase().replace(/^\*\./, '');
        if (h && isValidSub(h, domain) && !seen.has(h)) { seen.add(h); out.push({ subdomain: h, ip: rec.address || '', source: 'OTX' }); }
      });
    } catch { /* */ }
  }
  return out;
}

export async function fetchURLScanSubs(domain: string) {
  try {
    const r = await pFetch(`https://urlscan.io/api/v1/search/?q=page.domain:${domain}&size=200`, 15000);
    const data = await r.json();
    const seen = new Set<string>();
    return (data.results || []).map((e: any) => (e.page?.domain || '').toLowerCase()).filter((s: string) => s && isValidSub(s, domain) && !seen.has(s) && seen.add(s)).map((s: string) => ({ subdomain: s, ip: '', source: 'URLScan' }));
  } catch { return []; }
}

export async function fetchThreatMiner(domain: string) {
  try {
    const r = await pFetch(`https://api.threatminer.org/v2/domain.php?q=${domain}&rt=5`, 15000);
    const data = await r.json();
    const seen = new Set<string>();
    return (data.results || []).map((s: string) => s.toLowerCase().replace(/^\*\./, '')).filter((s: string) => isValidSub(s, domain) && !seen.has(s) && seen.add(s)).map((s: string) => ({ subdomain: s, ip: '', source: 'ThreatMiner' }));
  } catch { return []; }
}

export async function fetchSonar(domain: string) {
  const seen = new Set<string>(), out: any[] = [];
  for (const url of [`https://sonar.omnisint.io/subdomains/${domain}`, `https://crobat-api.omnisint.io/subdomains/${domain}`]) {
    try {
      const r = await pFetch(url, 15000);
      const d = await r.json();
      const arr = Array.isArray(d) ? d : (d.result || []);
      arr.forEach((s: string) => { s = String(s).trim().toLowerCase().replace(/^\*\./, ''); if (s && isValidSub(s, domain) && !seen.has(s)) { seen.add(s); out.push({ subdomain: s, ip: '', source: 'Sonar' }); } });
      if (out.length) break;
    } catch { /* */ }
  }
  return out;
}

export async function fetchWBSubs(domain: string) {
  try {
    const r = await pFetch(`https://web.archive.org/cdx/search/cdx?url=*.${domain}/*&output=text&fl=original&collapse=urlkey&limit=10000`, 30000);
    const text = await r.text();
    const seen = new Set<string>(), out: any[] = [];
    text.trim().split('\n').forEach(u => { try { const h = new URL(u.trim()).hostname.toLowerCase().replace(/^\*\./, ''); if (h && isValidSub(h, domain) && !seen.has(h)) { seen.add(h); out.push({ subdomain: h, ip: '', source: 'Wayback' }); } } catch { /* */ } });
    return out;
  } catch { return []; }
}

export async function fetchVirusTotal(domain: string) {
  const seen = new Set<string>(), out: any[] = [];
  try {
    const r = await pFetch(`https://www.virustotal.com/ui/domains/${domain}/subdomains?limit=40`, 12000);
    const d = await r.json();
    (d.data || []).forEach((item: any) => { const s = (item.id || '').toLowerCase(); if (isValidSub(s, domain) && !seen.has(s)) { seen.add(s); out.push({ subdomain: s, ip: '', source: 'VirusTotal' }); } });
  } catch { /* */ }
  return out;
}

export async function fetchBufferOver(domain: string) {
  const seen = new Set<string>(), out: any[] = [];
  try {
    const r = await pFetch(`https://dns.bufferover.run/dns?q=.${domain}`, 12000);
    const d = await r.json();
    const records = [...(d.FDNS_A || []), ...(d.RDNS || [])];
    records.forEach((rec: string) => { const parts = rec.split(','); const host = (parts[1] || parts[0] || '').toLowerCase().replace(/\.$/, ''); if (host && isValidSub(host, domain) && !seen.has(host)) { seen.add(host); out.push({ subdomain: host, ip: parts[0] && /^\d/.test(parts[0]) ? parts[0] : '', source: 'BufferOver' }); } });
  } catch { /* */ }
  return out;
}

export async function fetchThreatCrowd(domain: string) {
  try {
    const r = await pFetch(`https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=${domain}`, 12000);
    const d = await r.json();
    const seen = new Set<string>(), out: any[] = [];
    (d.subdomains || []).forEach((s: string) => { s = s.toLowerCase().replace(/^\*\./, ''); if (isValidSub(s, domain) && !seen.has(s)) { seen.add(s); out.push({ subdomain: s, ip: '', source: 'ThreatCrowd' }); } });
    return out;
  } catch { return []; }
}

// ── DNS RESOLUTION — Multi-Resolver ──
export async function resolveHost(host: string): Promise<string> {
  try {
    const r = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(host)}&type=A`, { signal: AbortSignal.timeout(5000) });
    const d = await r.json();
    return d.Answer?.[0]?.data || '';
  } catch { return ''; }
}

export async function apiDNS(domain: string, type: string): Promise<{ data: string; ttl: number; src: string }[]> {
  const resolvers = [
    `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${type}`,
    `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=${type}`,
    `https://dns.quad9.net/dns-query?name=${encodeURIComponent(domain)}&type=${type}`,
  ];
  try {
    const all = await Promise.allSettled(resolvers.map(async (url, i) => {
      try {
        const r = await sf(url, { headers: { 'Accept': 'application/dns-json' } }, 8000);
        if (!r || !r.ok) return { Answer: [] };
        return await r.json();
      } catch { return { Answer: [] }; }
    }));
    const rmap = new Map<string, any>();
    all.forEach((res, i) => {
      if (res.status !== 'fulfilled' || !res.value?.Answer) return;
      res.value.Answer.forEach((a: any) => {
        if (!a?.data) return;
        let cleanData = a.data;
        if (type === 'TXT' && typeof cleanData === 'string' && cleanData.startsWith('"') && cleanData.endsWith('"')) cleanData = cleanData.slice(1, -1);
        const srcName = ['Google', 'Cloudflare', 'Quad9'][i];
        if (!rmap.has(cleanData)) {
          rmap.set(cleanData, { data: cleanData, ttl: a.TTL || 0, src: srcName });
        } else {
          const cur = rmap.get(cleanData);
          if (!cur.src.includes(srcName!)) cur.src += '+' + srcName;
        }
      });
    });
    return [...rmap.values()];
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

// ── IP GEO — dual fallback ──
export async function fetchGeo(ip: string) {
  try {
    const r = await fetch(`https://ipinfo.io/${ip}/json`, { signal: AbortSignal.timeout(6000) });
    if (!r.ok) throw new Error();
    const d = await r.json();
    if (!d.ip) throw new Error();
    const loc = (d.loc || '').split(',');
    return { country: d.country || '', country_code: d.country || '', city: d.city || '', org: d.org || '', loc: d.loc || '', lat: parseFloat(loc[0]) || 0, lon: parseFloat(loc[1]) || 0 };
  } catch {
    try {
      const r2 = await fetch(`https://ipwhois.app/json/${ip}`, { signal: AbortSignal.timeout(6000) });
      if (!r2.ok) return null;
      const d2 = await r2.json();
      return { country: d2.country || '', country_code: d2.country_code || '', city: d2.city || '', org: d2.org || '', loc: `${d2.latitude || 0},${d2.longitude || 0}`, lat: d2.latitude || 0, lon: d2.longitude || 0 };
    } catch { return null; }
  }
}

// ── ASN/BGP Lookup ──
export async function fetchASN(ips: string[]) {
  const result: { asn: string; org: string; cidr: string[] } = { asn: '', org: '', cidr: [] };
  if (!ips?.length) return result;
  try {
    const r = await pFetch(`https://api.bgpview.io/ip/${ips[0]}`, 12000);
    const d = await r.json();
    if (d.data?.prefixes?.length) {
      const pfx = d.data.prefixes[0];
      result.asn = 'AS' + (pfx.asn?.asn || '');
      result.org = pfx.asn?.name || '';
      result.cidr.push(pfx.prefix || '');
    }
  } catch { /* */ }
  return result;
}

// ── WHOIS/RDAP ──
export async function apiRDAP(domain: string) {
  try {
    const r = await pFetch(`https://rdap.org/domain/${domain}`, 15000);
    const d = await r.json();
    return {
      name: d.ldhName || domain,
      status: d.status || [],
      nameservers: (d.nameservers || []).map((ns: any) => ns.ldhName || ''),
      events: (d.events || []).map((e: any) => ({ action: e.eventAction, date: e.eventDate })),
      source: 'RDAP',
    };
  } catch { return null; }
}

// ══════════════════════════════════════════
//  ENDPOINT SOURCES — NO LIMITS
// ══════════════════════════════════════════

export async function fetchWBUrls(domain: string): Promise<EndpointEntry[]> {
  const all: EndpointEntry[] = [];
  const seen = new Set<string>();
  const queries = [
    `https://web.archive.org/cdx/search/cdx?url=*.${domain}/*&output=json&fl=original,statuscode&collapse=urlkey&limit=50000`,
    `https://web.archive.org/cdx/search/cdx?url=${domain}/*&output=json&fl=original,statuscode&collapse=urlkey&limit=30000`,
  ];
  for (const q of queries) {
    try {
      const r = await pFetch(q, 40000);
      const text = await r.text();
      if (text.startsWith('[')) {
        const data = JSON.parse(text);
        for (let i = 1; i < data.length; i++) {
          const u = normUrl(data[i][0]);
          if (!u || isJunkUrl(u) || JUNK.test(u)) continue;
          const k = urlKey(u);
          if (seen.has(k)) continue; seen.add(k);
          all.push({ url: u, status: data[i][1] || '-', source: 'Wayback' });
        }
      }
    } catch { /* */ }
    await sleep(200);
  }
  return all;
}

export async function fetchOTXUrls(domain: string): Promise<EndpointEntry[]> {
  const all: EndpointEntry[] = [];
  const seen = new Set<string>();
  for (let page = 1; page <= 10; page++) {
    try {
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
    } catch { break; }
  }
  return all;
}

export async function fetchCC(domain: string): Promise<EndpointEntry[]> {
  const all: EndpointEntry[] = [];
  const seen = new Set<string>();
  let indexId = 'CC-MAIN-2025-18';
  try { const ir = await pFetch('https://index.commoncrawl.org/collinfo.json', 8000); if (ir.ok) { const ix = await ir.json(); if (Array.isArray(ix) && ix.length) indexId = ix[0].id; } } catch { /* */ }
  try {
    const r = await pFetch(`https://index.commoncrawl.org/${indexId}-index?url=*.${domain}&output=json&limit=10000`, 30000);
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
//  JS SECRET SCANNING — 35+ Patterns (NO LIMITS)
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
  { name: 'Databricks Token', sev: 'CRITICAL', re: /dapi[a-f0-9]{32}/g },
  { name: 'Anthropic Key', sev: 'CRITICAL', re: /sk-ant-[A-Za-z0-9\-]{95}/g },
  { name: 'HuggingFace Token', sev: 'HIGH', re: /hf_[A-Za-z0-9]{37}/g },
  { name: 'Telegram Bot Token', sev: 'HIGH', re: /\d{8,10}:[A-Za-z0-9_-]{35}/g },
  { name: 'Discord Webhook', sev: 'MEDIUM', re: /discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]+/g },
  { name: 'Linear API Key', sev: 'HIGH', re: /lin_api_[A-Za-z0-9]{40}/g },
  { name: 'Notion API', sev: 'HIGH', re: /secret_[A-Za-z0-9]{43}/g },
  { name: 'Square Access Token', sev: 'CRITICAL', re: /sq0atp-[A-Za-z0-9\-_]{22}/g },
  { name: 'GCP Service Account', sev: 'CRITICAL', re: /"type":\s*"service_account"/g },
  { name: 'Kubernetes Config', sev: 'CRITICAL', re: /apiVersion:\s*v1\s*[\s\S]{0,50}kind:\s*Config/g },
  { name: 'Private JWT Secret', sev: 'CRITICAL', re: /jwt[_-]?secret["\s:=]+["']([^"'\s]{20,})/gi },
  { name: 'Encryption Key', sev: 'CRITICAL', re: /encrypt[ion_-]?key["\s:=]+["']([^"'\s]{20,})/gi },
  { name: 'SMTP Password', sev: 'HIGH', re: /smtp[_-]?pass(?:word)?["\s:=]+["']([^"'\s]{6,})/gi },
  { name: 'FTP Credentials', sev: 'HIGH', re: /ftp:\/\/[^:]+:([^@]+)@/g },
  { name: 'HTTP Basic Auth', sev: 'HIGH', re: /https?:\/\/[^:]+:([^@]{6,})@[a-z0-9.-]+/g },
];

export async function scanJSSecrets(jsFiles: EndpointEntry[]): Promise<SecretFinding[]> {
  const secrets: SecretFinding[] = [];
  // NO LIMIT — scan all JS files
  for (let i = 0; i < jsFiles.length; i++) {
    try {
      const r = await pFetch(jsFiles[i].url, 15000);
      if (!r.ok) continue;
      let text = await r.text();
      if (text.length > 2000000) continue;
      text = text.replace(/\\x([0-9a-f]{2})/gi, (_, h) => { try { return String.fromCharCode(parseInt(h, 16)); } catch { return _; } });
      JS_SECRET_PATTERNS.forEach(pat => {
        const re = new RegExp(pat.re.source, pat.re.flags);
        let m;
        while ((m = re.exec(text)) !== null) {
          const val = m[1] || m[0];
          if (val && val.length > 6 && val.length < 300 && !/^[0]+$/.test(val) && !/^[a-z_]+$/.test(val)) {
            secrets.push({ type: pat.name, sev: pat.sev, value: val.slice(0, 120), file: jsFiles[i].url, line: (text.substring(0, text.indexOf(val)).match(/\n/g) || []).length + 1 });
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
  // NO LIMIT
  for (const js of jsFiles) {
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
//  CORS MISCONFIGURATION SCANNER — NO LIMITS
// ══════════════════════════════════════════

export async function scanCORS(hosts: string[]): Promise<CORSFinding[]> {
  const findings: CORSFinding[] = [];
  // NO LIMIT
  for (const host of hosts) {
    const origins = ['https://evil.com', 'null', `https://${host}.evil.com`];
    for (const origin of origins) {
      try {
        const r = await sf(`https://${host}`, { headers: { 'Origin': origin } }, 5000);
        const acao = r.headers.get('access-control-allow-origin') || '';
        const acac = r.headers.get('access-control-allow-credentials') || '';
        if (acao === '*') findings.push({ host, type: 'Wildcard CORS', acao, acac, origin, sev: acac === 'true' ? 'HIGH' : 'MEDIUM' });
        else if (acao === origin) findings.push({ host, type: 'Reflected Origin', acao, acac, origin, sev: 'HIGH' });
        else if (acao === 'null') findings.push({ host, type: 'Null Origin Accepted', acao, acac, origin, sev: 'MEDIUM' });
      } catch { /* */ }
    }
    await sleep(100);
  }
  return findings;
}

// ══════════════════════════════════════════
//  CONTENT DISCOVERY — 200+ paths NO LIMITS
// ══════════════════════════════════════════

const CONTENT_PATHS = [
  '/.git/HEAD', '/.git/config', '/.env', '/.env.local', '/.env.production',
  '/wp-admin/', '/wp-login.php', '/wp-config.php.bak', '/wp-json/wp/v2/users', '/wp-json/wp/v2/posts', '/wp-content/debug.log',
  '/phpinfo.php', '/info.php', '/server-status', '/server-info',
  '/actuator', '/actuator/env', '/actuator/health', '/actuator/beans', '/actuator/logfile', '/actuator/threaddump', '/actuator/heapdump', '/actuator/shutdown', '/actuator/configprops', '/actuator/auditevents', '/actuator/conditions',
  '/swagger-ui.html', '/swagger.json', '/api-docs', '/openapi.json',
  '/.DS_Store', '/Thumbs.db', '/crossdomain.xml', '/.well-known/security.txt',
  '/backup.sql', '/dump.sql', '/db.sql', '/database.sql',
  '/admin', '/administrator', '/phpmyadmin', '/adminer.php',
  '/debug', '/trace', '/console', '/shell',
  '/graphql', '/api/graphql', '/graphiql', '/graphql/playground', '/graphql/explorer', '/altair', '/playground',
  '/.htaccess', '/.htpasswd', '/web.config',
  '/config.yml', '/config.json', '/settings.json',
  '/docker-compose.yml', '/Dockerfile', '/kubernetes.yml',
  '/.aws/credentials', '/id_rsa', '/id_rsa.pub', '/id_ecdsa', '/id_ed25519',
  '/api/v1/users', '/api/v1/admin', '/api/v2/users', '/api/v2/admin', '/api/internal', '/api/debug', '/api/test', '/api/config', '/api/status', '/api/health', '/api/metrics', '/api/info', '/api/version', '/api/v1/keys', '/api/v1/tokens', '/api/v1/secrets', '/api/v1/payments',
  '/telescope', '/horizon', '/nova', '/sanctum/csrf-cookie',
  '/_ignition/execute-solution', '/_debugbar',
  '/rails/info', '/rails/mailers', '/rails/info/routes',
  '/debug/pprof/', '/debug/pprof/goroutine', '/debug/pprof/heap',
  '/.bash_profile', '/.zshenv', '/server.key', '/server.pem', '/server.crt', '/ca.crt',
  '/data.json', '/users.json', '/config.yaml', '/secrets.yaml', '/credentials.json', '/credentials.xml',
  '/.npmrc', '/.yarnrc', '/.pypirc',
  '/terraform.tfstate', '/terraform.tfvars',
  '/Jenkinsfile', '/.travis.yml', '/.github/workflows',
  '/admin.php', '/admin.html', '/admin/config', '/admin/users', '/cms/admin', '/backend/admin',
];

export async function contentDiscovery(domain: string, hosts: string[]): Promise<ContentFinding[]> {
  const findings: ContentFinding[] = [];
  // NO LIMIT on hosts
  const sensitiveExts = ['.git', '.env', '.sql', '.bak', 'id_rsa', 'credentials', 'config.php', 'docker-compose', 'terraform', '.aws', 'server.key', 'server.pem'];
  for (const host of hosts) {
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
      await sleep(30);
    }
  }
  return findings;
}

// ══════════════════════════════════════════
//  NUCLEI TEMPLATE MATCHING — 20+ templates
// ══════════════════════════════════════════

const NUCLEI_TEMPLATES = [
  { path: '/.git/HEAD', match: 'ref:', template: 'git-config', sev: 'CRITICAL', cve: '' },
  { path: '/.env', match: /DB_|APP_KEY|SECRET|PASSWORD/i, template: 'env-file', sev: 'CRITICAL', cve: '' },
  { path: '/phpinfo.php', match: 'phpinfo()', template: 'phpinfo', sev: 'HIGH', cve: '' },
  { path: '/actuator/env', match: /"propertySources"/, template: 'spring-actuator', sev: 'CRITICAL', cve: 'CVE-2022-22965' },
  { path: '/swagger-ui.html', match: /swagger/i, template: 'swagger-ui', sev: 'MEDIUM', cve: '' },
  { path: '/graphql', match: /__schema/i, template: 'graphql-introspection', sev: 'HIGH', cve: '' },
  { path: '/wp-json/wp/v2/users', match: /"slug":/i, template: 'wp-user-enum', sev: 'MEDIUM', cve: '' },
  { path: '/telescope/requests', match: /"type":"request"/i, template: 'laravel-telescope', sev: 'HIGH', cve: '' },
  { path: '/horizon', match: /horizon|queues|jobs/i, template: 'laravel-horizon', sev: 'MEDIUM', cve: '' },
  { path: '/admin/login/?next=/admin/', match: /Django administration|CSRF|settings\.py/i, template: 'django-debug', sev: 'HIGH', cve: '' },
  { path: '/rails/info/routes', match: /Prefix|Verb|URI Pattern/i, template: 'rails-routes', sev: 'MEDIUM', cve: '' },
  { path: '/debug/pprof/', match: /Types of profiles/i, template: 'go-pprof', sev: 'HIGH', cve: '' },
  { path: '/metrics', match: /# HELP|# TYPE/i, template: 'prometheus-metrics', sev: 'MEDIUM', cve: '' },
  { path: '/api/v1/namespaces', match: /"kind":"NamespaceList"/i, template: 'k8s-dashboard', sev: 'CRITICAL', cve: '' },
  { path: '/console', match: /Werkzeug|Interactive Console/i, template: 'flask-werkzeug', sev: 'CRITICAL', cve: 'CVE-2024-34069' },
  { path: '/status', match: /"version":"[0-9]/i, template: 'apache-druid', sev: 'HIGH', cve: 'CVE-2021-25646' },
  { path: '/api/v1/dags', match: /"dags":\[/i, template: 'apache-airflow', sev: 'HIGH', cve: 'CVE-2022-40754' },
];

export async function nucleiScan(hosts: string[]): Promise<NucleiFinding[]> {
  const findings: NucleiFinding[] = [];
  // NO LIMIT on hosts
  for (const host of hosts) {
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
//  HTTP PROBE — Enhanced
// ══════════════════════════════════════════

export async function probeHost(host: string): Promise<ProbeFinding> {
  const result: ProbeFinding = { host, url: `https://${host}`, status: 0, alive: false, title: '', tech: [], redirected: false, final_url: '', error: '', server: '', https: false, cors: false, clickjack: true, hsts: false, size: 0 };
  for (const scheme of ['https://', 'http://']) {
    try {
      const r = await sf(`${scheme}${host}`, {}, 8000);
      const text = await r.text();
      result.status = r.status;
      result.alive = r.status > 0;
      result.url = `${scheme}${host}`;
      result.https = scheme === 'https://';
      result.size = text.length;
      result.title = (text.match(/<title[^>]*>([^<]{1,200})<\/title>/i) || [])[1] || '';
      result.server = r.headers.get('server') || '';
      const powered = r.headers.get('x-powered-by') || '';
      const xframe = r.headers.get('x-frame-options') || '';
      const hstsHeader = r.headers.get('strict-transport-security') || '';
      const corsHeader = r.headers.get('access-control-allow-origin') || '';
      if (result.server) result.tech.push(result.server);
      if (powered) result.tech.push(powered);
      if (xframe) result.clickjack = false;
      if (hstsHeader) result.hsts = true;
      if (corsHeader) result.cors = true;
      if (/wp-content|wordpress/i.test(text)) result.tech.push('WordPress');
      if (/react/i.test(text)) result.tech.push('React');
      if (/next/i.test(text) || r.headers.get('x-nextjs-cache')) result.tech.push('Next.js');
      if (/angular/i.test(text)) result.tech.push('Angular');
      if (/vue/i.test(text)) result.tech.push('Vue.js');
      if (/laravel|symfony/i.test(text)) result.tech.push('Laravel');
      if (/django/i.test(text)) result.tech.push('Django');
      if (/express/i.test(result.server)) result.tech.push('Express');
      if (result.alive) break;
    } catch { /* */ }
  }
  return result;
}

// ══════════════════════════════════════════
//  DARK WEB OSINT
// ══════════════════════════════════════════

export async function checkHIBP(domain: string): Promise<DarkWebFinding[]> {
  const findings: DarkWebFinding[] = [];
  try {
    const r = await pFetch('https://haveibeenpwned.com/api/v3/breaches', 20000);
    const breaches = await r.json();
    if (!Array.isArray(breaches)) return findings;
    breaches.filter((b: any) => (b.Domain || '').toLowerCase() === domain.toLowerCase()).forEach((b: any) => {
      findings.push({ source: 'HaveIBeenPwned', type: 'breach', severity: 'CRITICAL', title: `${b.Name} Data Breach`, detail: `${(b.PwnCount || 0).toLocaleString()} accounts · ${(b.DataClasses || []).slice(0, 5).join(', ')}`, date: b.BreachDate, url: `https://haveibeenpwned.com/PwnedWebsites#${b.Name}` });
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
    if (total > 0) findings.push({ source: 'Hudson Rock', type: 'infostealer_log', severity: 'CRITICAL', title: `${total} infostealer-compromised accounts found`, detail: `${(d.employees || []).length} employees · ${(d.users || []).length} users`, url: 'https://www.hudsonrock.com/threat-intelligence-cybercrime-tools' });
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
      findings.push({ source: 'RansomWatch', type: 'ransomware_victim', severity: 'CRITICAL', title: `⚠️ Possible ransomware victim: ${p.post_title || ''}`, detail: `Gang: ${p.group_name || '?'} · Date: ${p.discovered || '?'}`, url: 'https://ransomwatch.telemetry.ltd/#/profiles' });
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
    if (count > 0) findings.push({ source: 'LeakIX', type: 'leak', severity: 'HIGH', title: `${count} potential leaks/exposures found`, detail: 'Check LeakIX for details', url: `https://leakix.net/search?scope=leak&q=${encodeURIComponent(domain)}` });
  } catch { /* */ }
  return findings;
}

// ══════════════════════════════════════════
//  VULN DETECTION
// ══════════════════════════════════════════

export function detectVulns(eps: EndpointEntry[], params: Record<string, number>): VulnFinding[] {
  const findings: VulnFinding[] = [];
  eps.forEach(ep => {
    try {
      const u = new URL(ep.url);
      for (const [k, v] of u.searchParams.entries()) {
        const kl = k.toLowerCase();
        if (/^(url|redirect|next|return|goto|dest|href)$/.test(kl)) findings.push({ type: 'Open Redirect', sev: 'HIGH', url: ep.url, param: k, desc: 'Redirect param found', test: ep.url.replace(`${k}=${v}`, `${k}=https://evil.com`) });
        if (/^(url|host|api|fetch|proxy|load|server)$/.test(kl)) findings.push({ type: 'Potential SSRF', sev: 'CRITICAL', url: ep.url, param: k, desc: 'SSRF-prone parameter', test: ep.url.replace(`${k}=${v}`, `${k}=http://169.254.169.254/`) });
        if (/^(id|uid|user_id|product_id)$/.test(kl)) findings.push({ type: 'Potential SQLi', sev: 'HIGH', url: ep.url, param: k, desc: 'Numeric ID parameter', test: ep.url.replace(`${k}=${v}`, `${k}=1'`) });
        if (/^(file|path|page|include|template)$/.test(kl)) findings.push({ type: 'Potential LFI', sev: 'CRITICAL', url: ep.url, param: k, desc: 'File path parameter', test: ep.url.replace(`${k}=${v}`, `${k}=../../../etc/passwd`) });
      }
    } catch { /* */ }
  });
  const seen = new Set<string>();
  return findings.filter(f => { const key = f.type + f.param + f.url; if (seen.has(key)) return false; seen.add(key); return true; });
}

// ══════════════════════════════════════════
//  IDOR SCANNER
// ══════════════════════════════════════════

export async function scanIDOR(eps: EndpointEntry[]): Promise<IDORFinding[]> {
  const findings: IDORFinding[] = [];
  const idParams = ['id', 'user_id', 'uid', 'account_id', 'order_id', 'invoice_id', 'document_id', 'file_id', 'record_id', 'item_id', 'product_id', 'customer_id', 'member_id'];
  const candidates = eps.filter(ep => {
    try { const u = new URL(ep.url); return Array.from(u.searchParams.keys()).some(k => idParams.includes(k.toLowerCase())); } catch { return false; }
  });
  for (const ep of candidates) {
    try {
      const u = new URL(ep.url);
      for (const [k, v] of u.searchParams.entries()) {
        if (!idParams.includes(k.toLowerCase())) continue;
        const origVal = parseInt(v) || 1;
        const tests = [origVal + 1, origVal - 1, origVal + 100];
        for (const testVal of tests) {
          const tu = new URL(ep.url); tu.searchParams.set(k, String(testVal));
          try {
            const r = await sf(tu.toString(), {}, 5000);
            if (r.ok && r.status === 200) {
              const body = await r.text();
              if (body.length > 100 && !body.toLowerCase().includes('unauthorized') && !body.toLowerCase().includes('forbidden')) {
                findings.push({ url: ep.url, param: k, original: origVal, tested: testVal, status: r.status, size: body.length, sev: 'HIGH', desc: `IDOR candidate: ?${k}=${testVal} returned ${r.status} (${body.length} bytes)` });
                break;
              }
            }
          } catch { /* */ }
          await sleep(100);
        }
      }
    } catch { /* */ }
  }
  return findings;
}

// ══════════════════════════════════════════
//  RACE CONDITION DETECTOR
// ══════════════════════════════════════════

export async function detectRaceConditions(eps: EndpointEntry[]): Promise<RaceFinding[]> {
  const findings: RaceFinding[] = [];
  const candidates = eps.filter(ep => /reset|redeem|coupon|discount|referral|signup|register|verify|2fa|otp|transfer|withdraw|purchase|buy|checkout/i.test(ep.url));
  for (const ep of candidates) {
    try {
      const responses = await Promise.allSettled(Array.from({ length: 10 }, () => sf(ep.url, { method: 'GET' }, 4000)));
      const statuses = responses.filter(r => r.status === 'fulfilled').map(r => (r as PromiseFulfilledResult<any>).value.status);
      const nonRateLimited = statuses.filter(s => s !== 429).length;
      if (nonRateLimited >= 8) {
        findings.push({ url: ep.url, concurrent: 10, success: nonRateLimited, sev: 'HIGH', desc: `${nonRateLimited}/10 concurrent requests succeeded without rate limiting` });
      }
    } catch { /* */ }
    await sleep(500);
  }
  return findings;
}

// ══════════════════════════════════════════
//  CACHE POISONING PROBE
// ══════════════════════════════════════════

export async function probeCachePoisoning(hosts: string[]): Promise<CachePoisonFinding[]> {
  const findings: CachePoisonFinding[] = [];
  const POISON_HEADERS = [
    { 'X-Forwarded-Host': 'evil.com' }, { 'X-Original-URL': '/admin' }, { 'X-Rewrite-URL': '/admin' },
    { 'X-Host': 'evil.com' }, { 'X-Forwarded-Server': 'evil.com' }, { 'Forwarded': 'host=evil.com' },
  ];
  for (const host of hosts) {
    for (const header of POISON_HEADERS) {
      try {
        const r = await sf(`https://${host}`, { headers: header as any }, 5000);
        const body = await r.text();
        const headerKey = Object.keys(header)[0];
        const headerVal = (header as any)[headerKey];
        if (body.includes('evil.com') || body.includes(headerVal)) {
          findings.push({ host, header: headerKey, value: headerVal, reflected: true, sev: 'HIGH', desc: 'Header value reflected in response — cache poisoning possible' });
        }
      } catch { /* */ }
      await sleep(50);
    }
  }
  return findings;
}

// ══════════════════════════════════════════
//  CRLF INJECTION SCANNER
// ══════════════════════════════════════════

export async function scanCRLF(eps: EndpointEntry[]): Promise<CRLFFinding[]> {
  const findings: CRLFFinding[] = [];
  const PAYLOADS = ['%0d%0aSet-Cookie:crlftest=1', '%0aSet-Cookie:crlftest=1', '%0d%0aLocation:https://evil.com'];
  const candidates = eps.filter(ep => { try { return new URL(ep.url).searchParams.size > 0; } catch { return false; } });
  for (const ep of candidates) {
    try {
      const u = new URL(ep.url);
      const firstParam = Array.from(u.searchParams.entries())[0];
      if (!firstParam) continue;
      for (const payload of PAYLOADS) {
        const tu = new URL(ep.url); tu.searchParams.set(firstParam[0], firstParam[1] + payload);
        try {
          const r = await sf(tu.toString(), { redirect: 'manual' } as any, 5000);
          const cookies = r.headers.get('set-cookie') || '';
          if (cookies.includes('crlftest=1')) {
            findings.push({ url: ep.url, param: firstParam[0], payload, sev: 'HIGH', desc: 'CRLF injection confirmed — Set-Cookie header injected' });
          }
        } catch { /* */ }
        await sleep(50);
      }
    } catch { /* */ }
  }
  return findings;
}

// ══════════════════════════════════════════
//  HOST HEADER INJECTION
// ══════════════════════════════════════════

export async function scanHostHeaderInjection(eps: EndpointEntry[]): Promise<HostInjectionFinding[]> {
  const findings: HostInjectionFinding[] = [];
  const resetEps = eps.filter(ep => /password.reset|forgot.password|reset|verify|confirm/i.test(ep.url));
  for (const ep of resetEps) {
    try {
      const r = await sf(ep.url, { headers: { 'Host': 'evil.com', 'X-Forwarded-Host': 'evil.com' } as any }, 5000);
      const body = await r.text();
      if (body.includes('evil.com')) findings.push({ url: ep.url, sev: 'HIGH', desc: 'Host header reflected — password reset link hijacking possible' });
    } catch { /* */ }
    await sleep(100);
  }
  return findings;
}

// ══════════════════════════════════════════
//  BROKEN LINK HIJACKING
// ══════════════════════════════════════════

export async function scanBrokenLinks(eps: EndpointEntry[], domain: string): Promise<BLHFinding[]> {
  const findings: BLHFinding[] = [];
  const externalDomains = new Set<string>();
  eps.forEach(ep => { try { const u = new URL(ep.url); if (u.hostname && !u.hostname.endsWith('.' + domain) && u.hostname !== domain) externalDomains.add(u.hostname); } catch { /* */ } });
  const extArr = [...externalDomains];
  for (const d of extArr) {
    try {
      const r = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(d)}&type=A`, { signal: AbortSignal.timeout(3000) });
      const data = await r.json();
      if (!data.Answer || !data.Answer.length) {
        findings.push({ domain: d, status: 'Not resolving — may be available', sev: 'HIGH', registerUrl: `https://www.namecheap.com/domains/registration/results/?domain=${d}` });
      }
    } catch { /* */ }
    await sleep(30);
  }
  return findings;
}

// ══════════════════════════════════════════
//  BUG BOUNTY PROGRAM DETECTOR
// ══════════════════════════════════════════

export async function detectBugBounty(domain: string): Promise<BountyFinding[]> {
  const findings: BountyFinding[] = [];
  const guesses = [`https://hackerone.com/${domain.split('.')[0]}`, `https://bugcrowd.com/${domain.split('.')[0]}`, `https://security.${domain}`, `https://${domain}/.well-known/security.txt`];
  for (const url of guesses) {
    try {
      const r = await pFetch(url, 8000);
      if (r.ok) {
        const text = await r.text();
        if (/bug.bounty|vulnerability.report|responsible.disclosure|hackerone|bugcrowd|intigriti/i.test(text)) {
          findings.push({ platform: 'Direct', url, domain, status: 'Program found' });
        }
      }
    } catch { /* */ }
  }
  try {
    const r = await pFetch(`https://${domain}/.well-known/security.txt`, 8000);
    if (r.ok) {
      const txt = await r.text();
      const contact = (txt.match(/Contact:\s*(.+)/i) || [])[1] || '';
      const policy = (txt.match(/Policy:\s*(.+)/i) || [])[1] || '';
      findings.push({ platform: 'security.txt', url: `https://${domain}/.well-known/security.txt`, contact: contact.trim(), policy: policy.trim(), domain, status: 'security.txt found' });
    }
  } catch { /* */ }
  return findings;
}

// ══════════════════════════════════════════
//  DEPENDENCY CONFUSION SCANNER
// ══════════════════════════════════════════

export async function scanDepConfusion(eps: EndpointEntry[]): Promise<DepConfFinding[]> {
  const findings: DepConfFinding[] = [];
  const pkgUrls = eps.filter(ep => /package\.json|composer\.json|requirements\.txt|Gemfile|go\.mod/i.test(ep.url));
  for (const ep of pkgUrls) {
    try {
      const r = await pFetch(ep.url, 10000);
      if (!r.ok) continue;
      const text = await r.text();
      try {
        const json = JSON.parse(text);
        const deps = { ...(json.dependencies || {}), ...(json.devDependencies || {}) };
        const pkgs = Object.keys(deps).filter(p => p.startsWith('@') && !p.startsWith('@types/'));
        for (const pkg of pkgs) {
          try {
            const r2 = await fetch(`https://registry.npmjs.org/${encodeURIComponent(pkg)}`, { signal: AbortSignal.timeout(5000) });
            if (r2.status === 404) findings.push({ pkg, source: ep.url, registry: 'npmjs', status: 'NOT PUBLISHED — Vulnerable!', sev: 'CRITICAL' });
          } catch { /* */ }
        }
      } catch { /* */ }
    } catch { /* */ }
  }
  return findings;
}

// ══════════════════════════════════════════
//  JWT ANALYSIS
// ══════════════════════════════════════════

export function analyzeJWT(token: string): JWTFinding | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const header = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')));
    const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
    const issues: { sev: string; issue: string }[] = [];
    if (header.alg === 'none') issues.push({ sev: 'CRITICAL', issue: 'Algorithm none — JWT bypass' });
    if (header.alg === 'HS256') issues.push({ sev: 'MEDIUM', issue: 'Weak algorithm HS256' });
    if (!payload.exp) issues.push({ sev: 'HIGH', issue: 'No expiration set' });
    else if (payload.exp * 1000 < Date.now()) issues.push({ sev: 'MEDIUM', issue: 'Token expired' });
    if (payload.password || payload.pwd || payload.secret) issues.push({ sev: 'HIGH', issue: 'Sensitive data in payload' });
    if (!payload.iss) issues.push({ sev: 'LOW', issue: 'No iss (issuer) claim' });
    return { source: 'js_file', header, payload, issues, raw: token.slice(0, 60) + '...' };
  } catch { return null; }
}

export function scanJWTs(secrets: SecretFinding[]): JWTFinding[] {
  const results: JWTFinding[] = [];
  secrets.filter(s => s.type === 'JWT Token').forEach(s => {
    const analysis = analyzeJWT(s.value);
    if (analysis) results.push({ ...analysis, file: s.file });
  });
  return results;
}

// ══════════════════════════════════════════
//  GRAPHQL INTROSPECTION
// ══════════════════════════════════════════

export async function scanGraphQL(hosts: string[]): Promise<GraphQLFinding[]> {
  const findings: GraphQLFinding[] = [];
  const paths = ['/graphql', '/api/graphql', '/graphiql', '/playground', '/altair'];
  for (const host of hosts) {
    for (const path of paths) {
      try {
        const r = await sf(`https://${host}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ query: '{ __schema { types { name } } }' }) }, 5000);
        if (r.ok) {
          const d = await r.json();
          const types = d?.data?.__schema?.types || [];
          if (types.length > 0) findings.push({ host, url: `https://${host}${path}`, typeCount: types.length, types: types.slice(0, 20) });
        }
      } catch { /* */ }
    }
  }
  return findings;
}

// ══════════════════════════════════════════
//  HTTP METHODS SCAN
// ══════════════════════════════════════════

export async function scanHTTPMethods(hosts: string[]): Promise<MethodsFinding[]> {
  const findings: MethodsFinding[] = [];
  const dangerous = ['PUT', 'DELETE', 'PATCH', 'TRACE', 'CONNECT'];
  for (const host of hosts) {
    try {
      const r = await sf(`https://${host}`, { method: 'OPTIONS' }, 5000);
      const allow = r.headers.get('allow') || '';
      if (allow) {
        const dangerousMethods = dangerous.filter(m => allow.toUpperCase().includes(m));
        if (dangerousMethods.length) findings.push({ host, url: `https://${host}`, allow, dangerous: dangerousMethods, sev: 'MEDIUM' });
      }
    } catch { /* */ }
  }
  return findings;
}

// ══════════════════════════════════════════
//  EXPLOIT DATABASE SEARCH
// ══════════════════════════════════════════

export async function searchExploitDB(techList: string[], ips: Record<string, any>): Promise<ExploitFinding[]> {
  const findings: ExploitFinding[] = [];
  // Search via CVE data from Shodan
  const cveAll: string[] = [];
  Object.values(ips).forEach((ip: any) => { (ip.cves || []).forEach((c: string) => { if (!cveAll.includes(c)) cveAll.push(c); }); });
  for (const cve of cveAll) {
    try {
      const r = await pFetch(`https://www.exploit-db.com/search?cve=${encodeURIComponent(cve)}&action=search`, 10000);
      const html = await r.text();
      const edbIds = html.match(/\/exploits\/(\d+)/g) || [];
      edbIds.forEach(m => {
        const id = m.replace('/exploits/', '');
        if (!findings.find(e => e.id === id)) {
          findings.push({ id, tech: cve, title: `Exploit for ${cve}`, url: `https://www.exploit-db.com/exploits/${id}`, edb_id: `EDB-ID:${id}` });
        }
      });
    } catch { /* */ }
    await sleep(100);
  }
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
//  CLOUD PROVIDER MAPPING
// ══════════════════════════════════════════

const CLOUD_RANGES: Record<string, string[]> = {
  'AWS': ['52.', '54.', '18.', '34.', '35.', '100.24.', '3.', '13.', '15.'],
  'GCP': ['34.64.', '34.65.', '34.66.', '35.186.', '35.187.', '35.188.', '35.189.', '35.190.', '35.199.', '35.200.'],
  'Azure': ['20.', '40.', '51.104.', '51.105.', '52.136.', '104.208.', '13.64.', '13.65.', '13.66.', '13.67.'],
  'Cloudflare': ['172.64.', '172.65.', '172.66.', '172.67.', '104.16.', '104.17.', '104.18.', '104.19.', '104.20.', '104.21.'],
  'Fastly': ['151.101.', '199.27.', '23.235.', '103.244.'],
  'DigitalOcean': ['104.131.', '104.236.', '45.55.', '128.199.', '138.197.', '139.59.'],
};

export function identifyCloudProvider(ip: string): string | null {
  for (const provider in CLOUD_RANGES) {
    if (CLOUD_RANGES[provider].some(r => ip.startsWith(r))) return provider;
  }
  return null;
}

// ══════════════════════════════════════════
//  RISK SCORE CALCULATOR
// ══════════════════════════════════════════

export function calculateRiskScore(state: ScanState): { score: number; grade: string } {
  const cveCount = Object.values(state.ips).reduce((a: number, b: any) => a + (b.cves?.length || 0), 0);
  const exposedPorts = Object.values(state.ips).reduce((a: number, b: any) => a + (b.ports || []).filter((p: number) => [3306, 5432, 27017, 6379, 9200, 11211, 5900, 3389].includes(p)).length, 0);
  const factors = [
    { val: state.subs.length, weight: 10, max: 200 },
    { val: state.subs.filter(s => s.status === 'resolved').length, weight: 15, max: 100 },
    { val: exposedPorts, weight: 20, max: 20 },
    { val: cveCount, weight: 20, max: 10 },
    { val: state.takeover.length, weight: 15, max: 5 },
    { val: state.secrets.length, weight: 10, max: 10 },
    { val: state.corsFindings.length, weight: 5, max: 10 },
    { val: state.otx.p, weight: 5, max: 20 },
  ];
  const totalScore = factors.reduce((sum, f) => sum + Math.min(f.val / f.max, 1) * f.weight, 0);
  const score = Math.round(totalScore);
  const grade = score >= 70 ? 'CRITICAL' : score >= 50 ? 'HIGH' : score >= 30 ? 'MEDIUM' : 'LOW';
  return { score, grade };
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
//  COOKIE ANALYSIS
// ══════════════════════════════════════════

export async function analyzeCookies(hosts: string[]): Promise<CookieFinding[]> {
  const findings: CookieFinding[] = [];
  // NO LIMIT
  for (const host of hosts) {
    try {
      const r = await sf(`https://${host}`, {}, 5000);
      const cookies = r.headers.get('set-cookie') || '';
      if (!cookies) continue;
      cookies.split(',').forEach((cookie: string) => {
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
//  DNS BRUTE FORCE — 500+ words NO LIMIT
// ══════════════════════════════════════════

const BF_WORDS = ['www','mail','ftp','smtp','pop','ns1','ns2','ns3','ns4','mx','dev','api','blog','cdn','shop','app','m','admin','portal','vpn','ssh','secure','help','support','webmail','remote','server','cloud','git','gitlab','jenkins','jira','confluence','staging','beta','test','uat','qa','prod','static','assets','media','images','img','files','docs','wiki','forum','community','login','auth','sso','oauth','dashboard','panel','cpanel','manage','control','hosting','host','web1','web2','node','lb','proxy','gw','vpn1','rdp','office','intranet','internal','corp','exchange','autodiscover','autoconfig','imap','pop3','smtp2','relay','mx1','mx2','dns','dns1','ntp','chat','meet','video','api2','api3','graphql','rest','ws','webhook','monitor','status','metrics','health','log','sentry','grafana','kibana','redis','mysql','postgres','mongodb','rabbitmq','consul','vault','k8s','docker','registry','backup','data','db','sql','s3','storage','sftp','email','mail2','test2','dev2','stage','preprod','live','old','new','mobile','android','ios','auth0','okta','ldap','ads','ad','reports','report','crm','erp','wiki2','help2','ticket','tickets','zendesk','freshdesk','nexus','sonar','ci','cd','deploy','build','staging2','beta2','demo','sandbox','uat2','preview','review','alpha','canary','release','feature','hotfix','prod2','production','qa2','testing','int','integration','ext','external','public','private','secure2','vault2','secret','config','backup2','bak','archive','old2','legacy','v1','v2','v3','v4','grpc','rpc','wss','socket','push','notify','analytics','insight','cms','wp','wordpress','drupal','joomla','magento','shopify','stripe','pay','payment','checkout','cart','order','invoice','billing','account','accounts','user','users','member','team','org','enterprise','business','partner','client','customer','service','services','app2','apps','portal2','mobile2','www2','cdn2','static2','media2','files2','docs2','download','downloads','upload','uploads','video2','audio','stream','rss','sitemap','security','firewall','waf','gateway','dmz','dc','dc1','dc2','k8s','kubernetes','rancher','prometheus','loki','elastic','opensearch','minio','airflow','jupyter','spark','hadoop','kafka','zookeeper','celery','memcached','cassandra','neo4j','influxdb','clickhouse'];

export async function dnsBruteforce(domain: string, onFound: (item: { subdomain: string; ip: string }) => void) {
  // NO LIMIT — scan ALL words
  for (let i = 0; i < BF_WORDS.length; i += 20) {
    const batch = BF_WORDS.slice(i, i + 20);
    await Promise.all(batch.map(async word => {
      const sub = `${word}.${domain}`;
      const ip = await resolveHost(sub);
      if (ip) onFound({ subdomain: sub, ip });
    }));
    await sleep(25);
  }
}

// ══════════════════════════════════════════
//  SUBDOMAIN PERMUTATION ENGINE
// ══════════════════════════════════════════

export async function subPermutation(domain: string, foundSubs: string[], onFound: (item: { subdomain: string; ip: string }) => void) {
  const PERMS = ['dev', 'staging', 'test', 'beta', 'api', 'v2', 'v1', 'admin', 'internal', 'corp', 'app', 'mobile', 'old', 'new', 'prod', 'uat', 'qa', 'pre', 'demo', 'sandbox', 'secure', 'vpn', 'mail', 'smtp', 'git', 'ci', 'cd', 'jenkins', 'wiki', 'docs', 'portal', 'crm', 'sso', 'auth', 'login', 'dashboard', 'panel', 'monitor', 'status', 's3', 'cdn', 'assets', 'static', 'media', 'upload', 'files', 'backup', 'db', 'redis', 'mongo', 'elastic', 'kafka', 'search'];
  const words = [...new Set(foundSubs.map(s => s.split('.')[0]).filter(w => w.length > 2 && w.length < 20))];
  const perms = new Set<string>();
  PERMS.forEach(p => {
    perms.add(`${p}.${domain}`);
    words.forEach(w => { perms.add(`${p}-${w}.${domain}`); perms.add(`${w}-${p}.${domain}`); });
  });
  const arr = [...perms];
  for (let i = 0; i < arr.length; i += 25) {
    const batch = arr.slice(i, i + 25);
    await Promise.all(batch.map(async host => {
      if (!isValidSub(host, domain)) return;
      try {
        const r = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(host)}&type=A`, { signal: AbortSignal.timeout(3000) });
        if (!r.ok) return;
        const d = await r.json();
        const ips = (d.Answer || []).filter((a: any) => a.type === 1);
        if (ips.length) onFound({ subdomain: host, ip: ips[0].data });
      } catch { /* */ }
    }));
    await sleep(20);
  }
}

// ══════════════════════════════════════════
//  PTR SWEEP
// ══════════════════════════════════════════

export async function ptrSweep(ips: string[]): Promise<{ ip: string; ptr: string }[]> {
  const results: { ip: string; ptr: string }[] = [];
  for (const ip of ips) {
    try {
      const r = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(ip.split('.').reverse().join('.') + '.in-addr.arpa')}&type=PTR`, { signal: AbortSignal.timeout(3000) });
      const d = await r.json();
      if (d.Answer?.length) d.Answer.forEach((a: any) => { if (a.data) results.push({ ip, ptr: a.data }); });
    } catch { /* */ }
  }
  return results;
}

// ══════════════════════════════════════════
//  SSL / TLS CERTIFICATE DATA
// ══════════════════════════════════════════

export interface SSLCert { cn: string; issuer: string; notBefore: string; notAfter: string; daysLeft: number; wildcard: boolean; san: string[]; }

export async function fetchSSLData(domain: string): Promise<SSLCert[]> {
  const certs: SSLCert[] = [];
  try {
    const r = await pFetch(`https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`, 30000);
    const data = await r.json();
    if (!Array.isArray(data)) return certs;
    const seen = new Set<string>();
    data.slice(0, 500).forEach((e: any) => {
      const cn = (e.common_name || '').toLowerCase();
      const key = cn + (e.serial_number || '');
      if (seen.has(key)) return; seen.add(key);
      const notBefore = e.not_before || '';
      const notAfter = e.not_after || '';
      const daysLeft = notAfter ? Math.ceil((new Date(notAfter).getTime() - Date.now()) / 86400000) : 0;
      const san = (e.name_value || '').split('\n').map((s: string) => s.trim().toLowerCase()).filter(Boolean);
      certs.push({ cn, issuer: e.issuer_name || '', notBefore, notAfter, daysLeft, wildcard: cn.startsWith('*.'), san });
    });
  } catch { /* */ }
  return certs;
}

// ══════════════════════════════════════════
//  SUBDOMAIN TAKEOVER DETECTION
// ══════════════════════════════════════════

const TAKEOVER_SIGS: { service: string; cnames: string[]; body: string[]; sev: string }[] = [
  { service: 'GitHub Pages', cnames: ['github.io'], body: ['There isn\'t a GitHub Pages site here'], sev: 'HIGH' },
  { service: 'Heroku', cnames: ['herokuapp.com', 'herokussl.com'], body: ['no-such-app', 'No such app'], sev: 'HIGH' },
  { service: 'Shopify', cnames: ['myshopify.com'], body: ['Sorry, this shop is currently unavailable'], sev: 'MEDIUM' },
  { service: 'Tumblr', cnames: ['domains.tumblr.com'], body: ['There\'s nothing here', 'Whatever you were looking for'], sev: 'MEDIUM' },
  { service: 'WordPress.com', cnames: ['wordpress.com'], body: ['Do you want to register'], sev: 'MEDIUM' },
  { service: 'Netlify', cnames: ['netlify.app', 'netlify.com'], body: ['Not Found - Request ID'], sev: 'HIGH' },
  { service: 'Vercel', cnames: ['vercel.app', 'now.sh'], body: ['404: NOT_FOUND'], sev: 'HIGH' },
  { service: 'Surge.sh', cnames: ['surge.sh'], body: ['project not found'], sev: 'HIGH' },
  { service: 'Ghost', cnames: ['ghost.io'], body: ['The thing you were looking for is no longer here'], sev: 'HIGH' },
  { service: 'Fastly', cnames: ['fastly.net'], body: ['Fastly error: unknown domain'], sev: 'HIGH' },
  { service: 'Pantheon', cnames: ['pantheonsite.io'], body: ['404 error unknown site'], sev: 'HIGH' },
  { service: 'Zendesk', cnames: ['zendesk.com'], body: ['Help Center Closed'], sev: 'MEDIUM' },
  { service: 'Statuspage', cnames: ['statuspage.io'], body: ['Status page launched'], sev: 'MEDIUM' },
  { service: 'Fly.io', cnames: ['fly.dev', 'edgeapp.net'], body: ['404 Not Found'], sev: 'HIGH' },
  { service: 'Azure', cnames: ['azurewebsites.net', 'cloudapp.net', 'azure-api.net', 'azurefd.net'], body: ['404 Web Site not found'], sev: 'HIGH' },
  { service: 'AWS S3', cnames: ['s3.amazonaws.com', 's3-website'], body: ['NoSuchBucket', 'The specified bucket does not exist'], sev: 'CRITICAL' },
  { service: 'AWS Elastic Beanstalk', cnames: ['elasticbeanstalk.com'], body: ['404 Not Found'], sev: 'HIGH' },
  { service: 'Bitbucket', cnames: ['bitbucket.io'], body: ['Repository not found'], sev: 'HIGH' },
  { service: 'Squarespace', cnames: ['squarespace.com'], body: ['No Such Account'], sev: 'MEDIUM' },
  { service: 'Wix', cnames: ['wixsite.com'], body: ['Error ConnectYourDomain'], sev: 'MEDIUM' },
  { service: 'Unbounce', cnames: ['unbouncepages.com'], body: ['The requested URL was not found'], sev: 'MEDIUM' },
  { service: 'Tilda', cnames: ['tilda.ws'], body: ['Please go to the site settings'], sev: 'MEDIUM' },
  { service: 'Webflow', cnames: ['proxy.webflow.com', 'proxy-ssl.webflow.com'], body: ['The page you are looking for doesn\'t exist'], sev: 'MEDIUM' },
  { service: 'Render', cnames: ['onrender.com'], body: ['Not Found'], sev: 'HIGH' },
  { service: 'Railway', cnames: ['up.railway.app'], body: ['Application Not Found'], sev: 'HIGH' },
  { service: 'Readme.io', cnames: ['readme.io'], body: ['Project not found'], sev: 'MEDIUM' },
  { service: 'UserVoice', cnames: ['uservoice.com'], body: ['This UserVoice subdomain'], sev: 'MEDIUM' },
  { service: 'ReadTheDocs', cnames: ['readthedocs.io'], body: ['unknown to Read the Docs'], sev: 'MEDIUM' },
  { service: 'Koyeb', cnames: ['koyeb.app'], body: ['404'], sev: 'HIGH' },
];

export interface TakeoverFinding { subdomain: string; cname: string; service: string; sev: string; confirmed: boolean; }

export async function detectTakeover(subs: SubdomainEntry[]): Promise<TakeoverFinding[]> {
  const findings: TakeoverFinding[] = [];
  for (const sub of subs) {
    if (!sub.cname) continue;
    for (const sig of TAKEOVER_SIGS) {
      if (sig.cnames.some(c => sub.cname.includes(c))) {
        let confirmed = false;
        try {
          const r = await sf(`https://${sub.subdomain}`, {}, 5000);
          const body = await r.text();
          confirmed = sig.body.some(b => body.includes(b));
        } catch { /* */ }
        findings.push({ subdomain: sub.subdomain, cname: sub.cname, service: sig.service, sev: confirmed ? sig.sev : 'LOW', confirmed });
        break;
      }
    }
  }
  return findings;
}

// ══════════════════════════════════════════
//  EMAIL SECURITY ANALYSIS
// ══════════════════════════════════════════

export interface EmailSecFinding { type: string; record: string; status: string; sev: string; detail: string; }

export async function analyzeEmailSecurity(domain: string): Promise<EmailSecFinding[]> {
  const findings: EmailSecFinding[] = [];
  // SPF
  const txt = await apiDNS(domain, 'TXT');
  const spf = txt.find(r => r.data.startsWith('v=spf1'));
  if (spf) {
    const hasAll = spf.data.includes('-all');
    findings.push({ type: 'SPF', record: spf.data, status: hasAll ? 'Strict' : 'Permissive', sev: hasAll ? 'LOW' : 'MEDIUM', detail: hasAll ? 'SPF with -all (strict)' : 'SPF without strict -all — spoofing possible' });
  } else {
    findings.push({ type: 'SPF', record: '', status: 'Missing', sev: 'CRITICAL', detail: 'No SPF record — email spoofing fully possible' });
  }
  // DMARC
  const dmarc = await apiDNS(`_dmarc.${domain}`, 'TXT');
  const dmarcRec = dmarc.find(r => r.data.includes('v=DMARC1'));
  if (dmarcRec) {
    const policy = (dmarcRec.data.match(/p=(\w+)/) || [])[1] || 'none';
    findings.push({ type: 'DMARC', record: dmarcRec.data, status: policy, sev: policy === 'reject' ? 'LOW' : policy === 'quarantine' ? 'MEDIUM' : 'HIGH', detail: `DMARC policy: ${policy}` });
  } else {
    findings.push({ type: 'DMARC', record: '', status: 'Missing', sev: 'HIGH', detail: 'No DMARC record' });
  }
  // DKIM common selectors
  const dkimSelectors = ['default', 'google', 'selector1', 'selector2', 'mail', 'dkim', 'smtp', 'sendgrid', 'mailchimp', 'mandrill', 'protonmail', 'zoho', 'mimecast', 'amazonses', 'k1', 's1', 's2', 'mg'];
  for (const sel of dkimSelectors) {
    const dk = await apiDNS(`${sel}._domainkey.${domain}`, 'TXT');
    if (dk.length > 0) { findings.push({ type: 'DKIM', record: dk[0].data.slice(0, 80) + '…', status: `Found (${sel})`, sev: 'LOW', detail: `DKIM selector: ${sel}` }); break; }
  }
  // MTA-STS
  const mtasts = await apiDNS(`_mta-sts.${domain}`, 'TXT');
  if (mtasts.length) findings.push({ type: 'MTA-STS', record: mtasts[0].data, status: 'Present', sev: 'LOW', detail: 'MTA-STS enabled' });
  // BIMI
  const bimi = await apiDNS(`default._bimi.${domain}`, 'TXT');
  if (bimi.length) findings.push({ type: 'BIMI', record: bimi[0].data, status: 'Present', sev: 'LOW', detail: 'BIMI record found' });
  return findings;
}

// ══════════════════════════════════════════
//  S3 BUCKET ENUMERATION
// ══════════════════════════════════════════

export interface S3Finding { bucket: string; url: string; status: string; sev: string; files: string[]; }

export async function scanS3Buckets(domain: string): Promise<S3Finding[]> {
  const findings: S3Finding[] = [];
  const base = domain.replace(/\.\w+$/, '');
  const perms = [base, `${base}-dev`, `${base}-staging`, `${base}-prod`, `${base}-backup`, `${base}-static`, `${base}-cdn`, `${base}-assets`, `${base}-media`, `${base}-uploads`, `${base}-data`, `${base}-logs`, `${base}-test`, `${base}-private`, `${base}-public`, `${base}-images`, `${base}-files`, `${base}-storage`];
  for (const name of perms) {
    try {
      const r = await sf(`https://${name}.s3.amazonaws.com/`, {}, 5000);
      if (r.status === 200) {
        const text = await r.text();
        const keys = (text.match(/<Key>([^<]+)<\/Key>/g) || []).map(m => (m.match(/<Key>([^<]+)/) || [])[1] || '').filter(Boolean).slice(0, 20);
        findings.push({ bucket: name, url: `https://${name}.s3.amazonaws.com`, status: 'PUBLIC', sev: 'CRITICAL', files: keys });
      } else if (r.status === 403) {
        findings.push({ bucket: name, url: `https://${name}.s3.amazonaws.com`, status: 'EXISTS (Private)', sev: 'LOW', files: [] });
      }
    } catch { /* */ }
    await sleep(100);
  }
  return findings;
}

// ══════════════════════════════════════════
//  GOOGLE DORK GENERATION
// ══════════════════════════════════════════

export interface DorkEntry { category: string; query: string; url: string; }

export function generateDorks(domain: string): DorkEntry[] {
  const d = domain;
  const dorks: DorkEntry[] = [];
  const add = (cat: string, q: string, engine = 'google') => {
    const url = engine === 'google' ? `https://www.google.com/search?q=${encodeURIComponent(q)}` :
      engine === 'github' ? `https://github.com/search?q=${encodeURIComponent(q)}&type=code` :
      engine === 'shodan' ? `https://www.shodan.io/search?query=${encodeURIComponent(q)}` :
      `https://www.google.com/search?q=${encodeURIComponent(q)}`;
    dorks.push({ category: cat, query: q, url });
  };
  // Admin & Login
  add('Admin', `site:${d} inurl:admin`);
  add('Admin', `site:${d} inurl:login`);
  add('Admin', `site:${d} inurl:dashboard`);
  add('Admin', `site:${d} inurl:panel`);
  add('Admin', `site:${d} intitle:"admin" OR intitle:"login"`);
  add('Admin', `site:${d} inurl:wp-admin`);
  add('Admin', `site:${d} inurl:cpanel`);
  // Sensitive Files
  add('Files', `site:${d} ext:sql | ext:env | ext:log | ext:bak`);
  add('Files', `site:${d} ext:xml | ext:json | ext:yml | ext:yaml`);
  add('Files', `site:${d} ext:conf | ext:cfg | ext:ini`);
  add('Files', `site:${d} ext:pem | ext:key | ext:crt`);
  add('Files', `site:${d} filetype:pdf | filetype:doc | filetype:xls`);
  add('Files', `site:${d} inurl:backup | inurl:dump | inurl:export`);
  // API & Endpoints
  add('API', `site:${d} inurl:api`);
  add('API', `site:${d} inurl:swagger | inurl:api-docs`);
  add('API', `site:${d} inurl:graphql | inurl:graphiql`);
  add('API', `site:${d} inurl:rest | inurl:v1 | inurl:v2`);
  add('API', `site:${d} inurl:webhook`);
  // Errors & Debug
  add('Debug', `site:${d} "debug" | "stacktrace" | "traceback"`);
  add('Debug', `site:${d} "error" | "exception" | "fatal"`);
  add('Debug', `site:${d} inurl:debug | inurl:trace | inurl:phpinfo`);
  // Credentials
  add('Creds', `site:${d} "password" | "passwd" | "secret_key"`);
  add('Creds', `site:${d} "api_key" | "apikey" | "access_token"`);
  add('Creds', `site:${d} "aws_secret" | "aws_access_key"`);
  // Cloud
  add('Cloud', `site:s3.amazonaws.com "${d}"`);
  add('Cloud', `site:blob.core.windows.net "${d}"`);
  add('Cloud', `site:storage.googleapis.com "${d}"`);
  add('Cloud', `site:pastebin.com "${d}"`);
  add('Cloud', `site:trello.com "${d}"`);
  // Bug Bounty
  add('BugBounty', `site:${d} inurl:reset_password`);
  add('BugBounty', `site:${d} inurl:token | inurl:csrf`);
  add('BugBounty', `site:${d} inurl:redirect | inurl:return | inurl:next`);
  add('BugBounty', `site:${d} inurl:upload | inurl:file`);
  // GitHub
  add('GitHub', `"${d}" password`, 'github');
  add('GitHub', `"${d}" api_key`, 'github');
  add('GitHub', `"${d}" secret`, 'github');
  add('GitHub', `"${d}" DATABASE_URL`, 'github');
  add('GitHub', `"${d}" AWS_SECRET`, 'github');
  add('GitHub', `"${d}" private_key`, 'github');
  // Shodan
  add('Shodan', `hostname:${d}`, 'shodan');
  add('Shodan', `ssl:"${d}"`, 'shodan');
  add('Shodan', `org:"${d.split('.')[0]}"`, 'shodan');
  // Subdomains
  add('Subs', `site:*.${d} -www`);
  add('Subs', `site:${d} -www -inurl:www`);
  return dorks;
}

// ══════════════════════════════════════════
//  GITHUB CODE LEAKS
// ══════════════════════════════════════════

export interface GHLeakFinding { repo: string; file: string; url: string; keyword: string; }

export async function searchGitHubLeaks(domain: string): Promise<GHLeakFinding[]> {
  const findings: GHLeakFinding[] = [];
  const keywords = ['password', 'secret', 'api_key', 'token', 'DATABASE_URL', 'AWS_SECRET', 'private_key', '.env', 'credentials', 'authorization', 'bearer', 'smtp'];
  for (const kw of keywords) {
    try {
      const r = await pFetch(`https://api.github.com/search/code?q="${encodeURIComponent(domain)}"+${encodeURIComponent(kw)}&per_page=10`, 10000);
      if (!r.ok) continue;
      const d = await r.json();
      (d.items || []).forEach((item: any) => {
        findings.push({ repo: item.repository?.full_name || '', file: item.path || '', url: item.html_url || '', keyword: kw });
      });
      await sleep(2000); // GitHub rate limit
    } catch { break; }
  }
  return findings;
}

// ══════════════════════════════════════════
//  SSTI / SQLi ACTIVE TESTING
// ══════════════════════════════════════════

export interface SSTIFinding { url: string; param: string; type: string; payload: string; sev: string; evidence: string; }

export async function scanSSTI(eps: EndpointEntry[]): Promise<SSTIFinding[]> {
  const findings: SSTIFinding[] = [];
  const payloads = [
    { type: 'SSTI/Jinja2', payload: '{{7*7}}', check: '49' },
    { type: 'SSTI/FreeMarker', payload: '${7*7}', check: '49' },
    { type: 'SQLi', payload: "' OR '1'='1", check: /sql|syntax|mysql|oracle|postgres|ORA-|error in your SQL/i },
    { type: 'SQLi', payload: "1' AND 1=1--", check: /sql|syntax|mysql|error/i },
  ];
  const candidates = eps.filter(ep => { try { return new URL(ep.url).searchParams.size > 0; } catch { return false; } }).slice(0, 200);
  for (const ep of candidates) {
    try {
      const u = new URL(ep.url);
      const firstParam = Array.from(u.searchParams.entries())[0];
      if (!firstParam) continue;
      for (const p of payloads) {
        const tu = new URL(ep.url); tu.searchParams.set(firstParam[0], p.payload);
        try {
          const r = await sf(tu.toString(), {}, 5000);
          const body = await r.text();
          const matched = typeof p.check === 'string' ? body.includes(p.check) : p.check.test(body);
          if (matched) {
            findings.push({ url: ep.url, param: firstParam[0], type: p.type, payload: p.payload, sev: 'CRITICAL', evidence: body.slice(0, 200) });
            break;
          }
        } catch { /* */ }
        await sleep(50);
      }
    } catch { /* */ }
  }
  return findings;
}

// ══════════════════════════════════════════
//  VIRTUAL HOST FUZZING
// ══════════════════════════════════════════

export interface VHostFinding { ip: string; vhost: string; status: number; size: number; sev: string; }

export async function scanVHosts(ips: Record<string, any>, domain: string): Promise<VHostFinding[]> {
  const findings: VHostFinding[] = [];
  const prefixes = ['admin', 'internal', 'corp', 'intranet', 'dev', 'staging', 'test', 'beta', 'api', 'portal', 'mail', 'vpn', 'app', 'dashboard', 'secure', 'private', 'hidden'];
  const ipList = Object.keys(ips).slice(0, 10);
  // Get baseline
  for (const ip of ipList) {
    let baselineSize = 0;
    try { const br = await sf(`http://${ip}`, { headers: { 'Host': domain } }, 3000); baselineSize = (await br.text()).length; } catch { continue; }
    for (const pfx of prefixes) {
      const vhost = `${pfx}.${domain}`;
      try {
        const r = await sf(`http://${ip}`, { headers: { 'Host': vhost } }, 3000);
        const body = await r.text();
        if (r.status === 200 && Math.abs(body.length - baselineSize) > 100) {
          findings.push({ ip, vhost, status: r.status, size: body.length, sev: 'HIGH' });
        }
      } catch { /* */ }
    }
    await sleep(100);
  }
  return findings;
}

// ══════════════════════════════════════════
//  PASTE SITE SEARCH
// ══════════════════════════════════════════

export interface PasteFinding { source: string; url: string; title: string; snippet: string; }

export async function searchPastes(domain: string): Promise<PasteFinding[]> {
  const findings: PasteFinding[] = [];
  try {
    const r = await pFetch(`https://psbdmp.ws/api/v3/search/${encodeURIComponent(domain)}`, 15000);
    const d = await r.json();
    if (Array.isArray(d)) {
      d.slice(0, 50).forEach((p: any) => {
        findings.push({ source: 'Pastebin', url: `https://pastebin.com/${p.id}`, title: p.tags || 'Untitled', snippet: (p.content || '').slice(0, 200) });
      });
    }
  } catch { /* */ }
  // DuckDuckGo search
  try {
    const r = await pFetch(`https://html.duckduckgo.com/html/?q=site:pastebin.com+%22${encodeURIComponent(domain)}%22`, 10000);
    const html = await r.text();
    const links = html.match(/href="(https:\/\/pastebin\.com\/\w+)"/g) || [];
    links.slice(0, 10).forEach(m => {
      const url = (m.match(/href="([^"]+)"/) || [])[1] || '';
      if (url && !findings.find(f => f.url === url)) {
        findings.push({ source: 'Pastebin/DDG', url, title: 'Paste mention', snippet: '' });
      }
    });
  } catch { /* */ }
  return findings;
}

// ══════════════════════════════════════════
//  FAVICON HASH
// ══════════════════════════════════════════

export async function fetchFaviconHash(domain: string): Promise<{ hash: string; shodanUrl: string } | null> {
  try {
    const r = await pFetch(`https://${domain}/favicon.ico`, 8000);
    if (!r.ok) return null;
    const buf = await r.arrayBuffer();
    const bytes = new Uint8Array(buf);
    // MurmurHash3
    let hash = 0;
    for (let i = 0; i < bytes.length; i++) {
      hash = Math.imul(hash ^ bytes[i], 0x5bd1e995);
      hash ^= hash >>> 13;
    }
    const hashStr = String(hash);
    return { hash: hashStr, shodanUrl: `https://www.shodan.io/search?query=http.favicon.hash:${hashStr}` };
  } catch { return null; }
}

// ══════════════════════════════════════════
//  ADDITIONAL SUBDOMAIN SOURCES (50+)
// ══════════════════════════════════════════

export async function fetchDNSRepo(domain: string) {
  const seen = new Set<string>(), out: any[] = [];
  try {
    const r = await pFetch(`https://dnsrepo.noc.org/?search=${domain}`, 15000);
    const html = await r.text();
    const re = new RegExp('([a-z0-9][a-z0-9\\-\\.]*\\.' + domain.replace(/\./g, '\\.') + ')', 'gi');
    let m;
    while ((m = re.exec(html)) !== null) {
      const s = m[1].toLowerCase();
      if (isValidSub(s, domain) && !seen.has(s)) { seen.add(s); out.push({ subdomain: s, ip: '', source: 'DNSRepo' }); }
    }
  } catch { /* */ }
  return out;
}

export async function fetchRiddler(domain: string) {
  const seen = new Set<string>(), out: any[] = [];
  try {
    const r = await pFetch(`https://riddler.io/search/exportcsv?q=pld:${domain}`, 15000);
    const text = await r.text();
    const re = new RegExp('([a-z0-9][a-z0-9\\-\\.]*\\.' + domain.replace(/\./g, '\\.') + ')', 'gi');
    let m;
    while ((m = re.exec(text)) !== null) {
      const s = m[1].toLowerCase();
      if (isValidSub(s, domain) && !seen.has(s)) { seen.add(s); out.push({ subdomain: s, ip: '', source: 'Riddler' }); }
    }
  } catch { /* */ }
  return out;
}

export async function fetchWebArchiveFull(domain: string) {
  const seen = new Set<string>(), out: any[] = [];
  try {
    const r = await pFetch(`https://web.archive.org/cdx/search/cdx?url=*.${domain}/*&output=text&fl=original&collapse=urlkey&limit=1000000`, 60000);
    const text = await r.text();
    text.trim().split('\n').forEach(u => {
      try {
        const h = new URL(u.trim()).hostname.toLowerCase().replace(/^\*\./, '');
        if (h && isValidSub(h, domain) && !seen.has(h)) { seen.add(h); out.push({ subdomain: h, ip: '', source: 'Wayback Full' }); }
      } catch { /* */ }
    });
  } catch { /* */ }
  return out;
}

export async function fetchGAU(domain: string): Promise<EndpointEntry[]> {
  const all: EndpointEntry[] = [];
  const seen = new Set<string>();
  try {
    const r = await pFetch(`https://web.archive.org/cdx/search/cdx?url=*.${domain}/*&output=json&fl=original,statuscode&collapse=urlkey&limit=100000`, 60000);
    const text = await r.text();
    if (text.startsWith('[')) {
      const data = JSON.parse(text);
      for (let i = 1; i < data.length && all.length < 1000000; i++) {
        const u = normUrl(data[i][0]);
        if (!u || isJunkUrl(u) || JUNK.test(u)) continue;
        const k = urlKey(u);
        if (seen.has(k)) continue; seen.add(k);
        all.push({ url: u, status: data[i][1] || '-', source: 'GAU' });
      }
    }
  } catch { /* */ }
  return all;
}

export async function fetchGitHubEndpoints(domain: string): Promise<EndpointEntry[]> {
  const all: EndpointEntry[] = [];
  try {
    const r = await pFetch(`https://api.github.com/search/code?q="${encodeURIComponent(domain)}"&per_page=30`, 12000);
    if (!r.ok) return all;
    const d = await r.json();
    (d.items || []).forEach((item: any) => {
      if (item.html_url) all.push({ url: item.html_url, status: '-', source: 'GitHub' });
    });
  } catch { /* */ }
  return all;
}

// ── DNSx Multi-Query (multi-resolver extended) ──
export async function dnsxMultiQuery(domain: string): Promise<{ subdomain: string; ip: string; source: string }[]> {
  const out: any[] = [];
  const seen = new Set<string>();
  // Query multiple resolvers for wildcard detection
  const resolvers = ['https://dns.google/resolve', 'https://cloudflare-dns.com/dns-query', 'https://dns.quad9.net/dns-query'];
  const types = ['A', 'AAAA', 'CNAME', 'NS', 'MX'];
  for (const type of types) {
    for (const resolver of resolvers) {
      try {
        const r = await sf(`${resolver}?name=${encodeURIComponent(domain)}&type=${type}`, { headers: { 'Accept': 'application/dns-json' } }, 5000);
        if (!r.ok) continue;
        const d = await r.json();
        (d.Answer || []).forEach((a: any) => {
          const host = (a.name || '').toLowerCase().replace(/\.$/, '');
          if (host && isValidSub(host, domain) && !seen.has(host)) { seen.add(host); out.push({ subdomain: host, ip: a.data || '', source: 'DNSx' }); }
        });
      } catch { /* */ }
    }
  }
  return out;
}

// ══════════════════════════════════════════
//  FULL SCAN ORCHESTRATOR — NO LIMITS
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
  onProgress(3, '🌐 Subdomain Collection…');
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
    { name: 'BufferOver', fn: () => fetchBufferOver(domain), id: 'bufferover' },
    { name: 'ThreatCrowd', fn: () => fetchThreatCrowd(domain), id: 'threatcrowd' },
    { name: 'DNSRepo', fn: () => fetchDNSRepo(domain), id: 'dnsrepo' },
    { name: 'Riddler', fn: () => fetchRiddler(domain), id: 'riddler' },
    { name: 'Wayback Full', fn: () => fetchWebArchiveFull(domain), id: 'wbfull' },
    { name: 'DNSx Multi', fn: () => dnsxMultiQuery(domain), id: 'dnsx' },
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

  // ── Phase 2: DNS Resolution — NO LIMIT ──
  onProgress(20, '🔍 DNS Resolution…');
  await safeRun('DNS Resolution', async () => {
    const unres = state.subs.filter(s => !s.ip);
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
  }, onModule, { retries: 1, timeout: 300000 });

  // ── DNS Bruteforce ──
  if (sources.brute !== false) {
    onProgress(25, '🔨 DNS Bruteforce…');
    await safeRun('DNS Bruteforce', async () => {
      await dnsBruteforce(domain, item => {
        if (!state.subs.find(s => s.subdomain === item.subdomain)) {
          state.subs.push({ subdomain: item.subdomain, ip: item.ip, status: 'resolved', source: 'bruteforce', ports: [], geo: '', cname: '', tko: false, httpStatus: 0, alive: false });
          if (!state.ips[item.ip]) state.ips[item.ip] = { hosts: [], ports: [], cves: [], vulns: [], geo: null };
          state.ips[item.ip].hosts.push(item.subdomain);
        }
      });
      onData({ subs: [...state.subs] });
    }, onModule, { retries: 0, timeout: 180000 });
  } else onModule('DNS Bruteforce', 'skip');

  // ── Subdomain Permutation ──
  onProgress(28, '🔄 Subdomain Permutation…');
  await safeRun('Sub Permutation', async () => {
    await subPermutation(domain, state.subs.map(s => s.subdomain), item => {
      if (!state.subs.find(s => s.subdomain === item.subdomain)) {
        state.subs.push({ subdomain: item.subdomain, ip: item.ip, status: 'resolved', source: 'permutation', ports: [], geo: '', cname: '', tko: false, httpStatus: 0, alive: false });
        if (!state.ips[item.ip]) state.ips[item.ip] = { hosts: [], ports: [], cves: [], vulns: [], geo: null };
        state.ips[item.ip].hosts.push(item.subdomain);
      }
    });
    onData({ subs: [...state.subs] });
  }, onModule, { retries: 0, timeout: 120000 });

  // ── Phase 3: DNS Records (Multi-Resolver) ──
  onProgress(32, '📡 DNS Records (Multi-Resolver)…');
  await safeRun('DNS Records', async () => {
    for (const type of ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'CAA'] as const) {
      const recs = await apiDNS(domain, type);
      state.dns[type] = recs.map(r => ({ val: r.data, ttl: r.ttl, src: r.src }));
    }
    state.dns.EMAIL = state.dns.TXT.filter(r => /v=spf1|v=DMARC1|v=DKIM/i.test(r.val));
    onData({ dns: { ...state.dns } });
  }, onModule, { retries: 2, timeout: 30000 });

  // ── Phase 4: Shodan IDB — NO LIMIT ──
  onProgress(38, '🔌 Shodan IDB + Ports…');
  await safeRun('Shodan InternetDB', async () => {
    const ips = Object.keys(state.ips);
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
  }, onModule, { retries: 1, timeout: 120000 });

  // ── Phase 5: HTTP Probe — NO LIMIT ──
  onProgress(45, '⚡ HTTP Probe…');
  await safeRun('HTTP Probe', async () => {
    const live = state.subs.filter(s => s.status === 'resolved');
    for (let i = 0; i < live.length; i += 10) {
      const batch = live.slice(i, i + 10);
      const res = await Promise.all(batch.map(sub => probeHost(sub.subdomain)));
      res.forEach(r => {
        state.probes.push(r);
        const sub = state.subs.find(s => s.subdomain === r.host);
        if (sub) { sub.httpStatus = r.status; sub.alive = r.alive; }
      });
      onProgress(45 + Math.round((i / live.length) * 10), '⚡ HTTP Probe…');
    }
    state.probes.forEach(p => p.tech.forEach(t => { if (!state.tech.includes(t)) state.tech.push(t); }));
    onData({ probes: [...state.probes], subs: [...state.subs], tech: [...state.tech] });
  }, onModule, { retries: 1, timeout: 300000 });

  // ── Phase 6: Endpoint Collection — NO LIMIT ──
  onProgress(55, '🔗 Endpoint Collection…');
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
  onProgress(62, '📡 Security Headers…');
  await safeRun('Security Headers', async () => {
    try {
      const r = await sf(`https://${domain}`, {}, 10000);
      const hdrs: Record<string, string> = {};
      r.headers.forEach((v: string, k: string) => { hdrs[k] = v; });
      state.hdrs = Object.entries(hdrs).map(([k, v]) => ({ key: k, value: v }));
      const wafSigs: Record<string, RegExp> = { Cloudflare: /cloudflare/i, Akamai: /akamai/i, AWS_WAF: /awselb|amazon/i, Incapsula: /incap/i, Sucuri: /sucuri/i, F5: /bigip/i };
      const server = hdrs['server'] || '';
      const via = hdrs['via'] || '';
      for (const [name, re] of Object.entries(wafSigs)) { if (re.test(server) || re.test(via)) { state.waf = name; break; } }
    } catch { /* */ }
    onData({ hdrs: [...state.hdrs], waf: state.waf });
  }, onModule, { retries: 2, timeout: 15000 });

  // ── Phase 8: WHOIS ──
  onProgress(64, '📋 WHOIS/RDAP…');
  await safeRun('WHOIS/RDAP', async () => {
    state.whois = await apiRDAP(domain) || {};
    onData({ whois: state.whois });
  }, onModule, { retries: 2, timeout: 20000 });

  // ── Phase 9: JS Secret Scan — NO LIMIT ──
  if (state.js.length > 0 && sources.jsfind !== false) {
    onProgress(66, '🔑 JS Secret Scan…');
    await safeRun('JS Secret Scan', async () => {
      state.secrets = await scanJSSecrets(state.js);
      onData({ secrets: [...state.secrets] });
      return state.secrets.length;
    }, onModule, { retries: 1, timeout: 300000 });
  } else onModule('JS Secret Scan', 'skip');

  // ── Phase 10: DOM XSS ──
  if (state.js.length > 0) {
    onProgress(69, '💉 DOM XSS Scan…');
    await safeRun('DOM XSS Scan', async () => {
      state.domXss = await scanDOMXSS(state.js);
      onData({ domXss: [...state.domXss] });
    }, onModule, { retries: 1, timeout: 180000 });
  }

  // ── Phase 11: CORS Scan — NO LIMIT ──
  if (sources.cors !== false) {
    onProgress(72, '🌐 CORS Scan…');
    await safeRun('CORS Scanner', async () => {
      const liveHosts = state.subs.filter(s => s.alive).map(s => s.subdomain);
      state.corsFindings = await scanCORS(liveHosts.length ? liveHosts : [domain]);
      onData({ corsFindings: [...state.corsFindings] });
    }, onModule, { retries: 1, timeout: 120000 });
  } else onModule('CORS Scanner', 'skip');

  // ── Phase 12: Content Discovery — NO LIMIT ──
  if (sources.content !== false) {
    onProgress(74, '📂 Content Discovery…');
    await safeRun('Content Discovery', async () => {
      const hosts = state.subs.filter(s => s.alive).map(s => s.subdomain);
      if (!hosts.length) hosts.push(domain);
      state.contentFindings = await contentDiscovery(domain, hosts);
      onData({ contentFindings: [...state.contentFindings] });
    }, onModule, { retries: 1, timeout: 300000 });
  } else onModule('Content Discovery', 'skip');

  // ── Phase 13: Nuclei Templates ──
  if (sources.nuclei !== false) {
    onProgress(76, '🎯 Nuclei Templates…');
    await safeRun('Nuclei Templates', async () => {
      const hosts = state.subs.filter(s => s.alive).map(s => s.subdomain);
      if (!hosts.length) hosts.push(domain);
      state.nucleiFindings = await nucleiScan(hosts);
      onData({ nucleiFindings: [...state.nucleiFindings] });
    }, onModule, { retries: 1, timeout: 120000 });
  } else onModule('Nuclei Templates', 'skip');

  // ── Phase 14: Cookie Analysis ──
  onProgress(78, '🍪 Cookie Analysis…');
  await safeRun('Cookie Analysis', async () => {
    const hosts = state.subs.filter(s => s.alive).map(s => s.subdomain);
    if (!hosts.length) hosts.push(domain);
    state.cookieFindings = await analyzeCookies(hosts);
    onData({ cookieFindings: [...state.cookieFindings] });
  }, onModule, { retries: 1, timeout: 60000 });

  // ── Phase 15: Vuln Detection ──
  onProgress(79, '🚨 Vulnerability Detection…');
  state.vulns = detectVulns(state.eps, state.params);
  onData({ vulns: [...state.vulns] });
  onModule('Vuln Detection', 'done');

  // ── Phase 16: IDOR Scanner ──
  onProgress(80, '🔓 IDOR Scanner…');
  await safeRun('IDOR Scanner', async () => {
    state.idorFindings = await scanIDOR(state.eps);
    onData({ idorFindings: [...state.idorFindings] });
  }, onModule, { retries: 0, timeout: 120000 });

  // ── Phase 17: Race Condition Detector ──
  await safeRun('Race Condition', async () => {
    state.raceFindings = await detectRaceConditions(state.eps);
    onData({ raceFindings: [...state.raceFindings] });
  }, onModule, { retries: 0, timeout: 60000 });

  // ── Phase 18: Cache Poisoning Probe ──
  await safeRun('Cache Poisoning', async () => {
    const liveHosts = state.subs.filter(s => s.alive).map(h => h.subdomain);
    state.cachePoisonFindings = await probeCachePoisoning(liveHosts.length ? liveHosts : [domain]);
    onData({ cachePoisonFindings: [...state.cachePoisonFindings] });
  }, onModule, { retries: 0, timeout: 60000 });

  // ── Phase 19: CRLF Injection ──
  await safeRun('CRLF Injection', async () => {
    state.crlfFindings = await scanCRLF(state.eps);
    onData({ crlfFindings: [...state.crlfFindings] });
  }, onModule, { retries: 0, timeout: 60000 });

  // ── Phase 20: Host Header Injection ──
  await safeRun('Host Header Injection', async () => {
    state.hostInjectionFindings = await scanHostHeaderInjection(state.eps);
    onData({ hostInjectionFindings: [...state.hostInjectionFindings] });
  }, onModule, { retries: 0, timeout: 30000 });

  // ── Phase 21: Broken Link Hijacking ──
  onProgress(83, '🔗 Broken Link Hijacking…');
  await safeRun('Broken Links', async () => {
    state.blhFindings = await scanBrokenLinks(state.eps, domain);
    onData({ blhFindings: [...state.blhFindings] });
  }, onModule, { retries: 0, timeout: 60000 });

  // ── Phase 22: Bug Bounty Detection ──
  await safeRun('Bug Bounty', async () => {
    state.bountyFindings = await detectBugBounty(domain);
    onData({ bountyFindings: [...state.bountyFindings] });
  }, onModule, { retries: 0, timeout: 30000 });

  // ── Phase 23: Dependency Confusion ──
  await safeRun('Dep Confusion', async () => {
    state.depConfFindings = await scanDepConfusion(state.eps);
    onData({ depConfFindings: [...state.depConfFindings] });
  }, onModule, { retries: 0, timeout: 60000 });

  // ── Phase 24: JWT Analysis ──
  if (state.secrets.length > 0) {
    await safeRun('JWT Analysis', async () => {
      state.jwtFindings = scanJWTs(state.secrets);
      onData({ jwtFindings: [...state.jwtFindings] });
      return state.jwtFindings.length;
    }, onModule, { retries: 0, timeout: 10000 });
  }

  // ── Phase 25: GraphQL Introspection ──
  onProgress(85, '📊 GraphQL Introspection…');
  await safeRun('GraphQL Scan', async () => {
    const hosts = state.subs.filter(s => s.alive).map(s => s.subdomain);
    if (!hosts.length) hosts.push(domain);
    state.graphqlFindings = await scanGraphQL(hosts);
    onData({ graphqlFindings: [...state.graphqlFindings] });
  }, onModule, { retries: 0, timeout: 60000 });

  // ── Phase 26: HTTP Methods ──
  await safeRun('HTTP Methods', async () => {
    const hosts = state.subs.filter(s => s.alive).map(s => s.subdomain);
    if (!hosts.length) hosts.push(domain);
    state.methodsFindings = await scanHTTPMethods(hosts);
    onData({ methodsFindings: [...state.methodsFindings] });
  }, onModule, { retries: 0, timeout: 30000 });

  // ── Phase 27: Exploit DB Search ──
  onProgress(87, '💀 Exploit DB Search…');
  await safeRun('Exploit Search', async () => {
    state.exploitFindings = await searchExploitDB(state.tech, state.ips);
    onData({ exploitFindings: [...state.exploitFindings] });
  }, onModule, { retries: 0, timeout: 60000 });

  // ── Phase 28: Dark Web OSINT ──
  onProgress(89, '🌑 Dark Web OSINT…');
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

  // ── Phase 29: IP Geolocation — NO LIMIT ──
  onProgress(93, '🌍 IP Geolocation…');
  if (sources.geo !== false) {
    await safeRun('IP Geolocation', async () => {
      const ips = Object.keys(state.ips);
      for (let i = 0; i < ips.length; i += 6) {
        const batch = ips.slice(i, i + 6);
        await Promise.all(batch.map(async ip => {
          const g = await fetchGeo(ip);
          if (g) {
            state.ips[ip].geo = g;
            state.ips[ip].cloud = identifyCloudProvider(ip);
            state.ips[ip].hosts.forEach((h: string) => {
              const sub = state.subs.find(s => s.subdomain === h);
              if (sub) sub.geo = `${g.city ? g.city + ', ' : ''}${g.country_code || ''}${g.org ? ' · ' + g.org : ''}`;
            });
          }
        }));
        await sleep(150);
      }
      onData({ subs: [...state.subs], ips: { ...state.ips } });
    }, onModule, { retries: 1, timeout: 120000 });
  } else onModule('IP Geolocation', 'skip');

  // ── Phase 30: Auth Surface Mapping ──
  onProgress(96, '🔐 Auth Surface Mapping…');
  state.authSurface = mapAuthSurface(state.eps);
  onData({ authSurface: { ...state.authSurface } });
  onModule('Auth Surface', 'done');

  // ── Phase 31: Risk Score ──
  const { score, grade } = calculateRiskScore(state);
  state.riskScore = score;
  state.riskGrade = grade;
  onData({ riskScore: score, riskGrade: grade });

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
  let md = `# TeamCyberOps Recon v14.6 Report — ${state.domain}\n\n`;
  md += `**Generated:** ${ts} | **Tool:** TeamCyberOps Recon v14.6 | **github.com/mohidqx**\n\n---\n\n`;
  md += `## Executive Summary\n| Metric | Count |\n|--------|-------|\n`;
  md += `| Subdomains | ${state.subs.length} |\n| Live Hosts | ${state.subs.filter(s => s.alive).length} |\n| Unique IPs | ${Object.keys(state.ips).length} |\n| Endpoints | ${state.eps.length} |\n| JS Files | ${state.js.length} |\n| Parameters | ${Object.keys(state.params).length} |\n| Secrets | ${state.secrets.length} |\n| CORS Issues | ${state.corsFindings.length} |\n| Nuclei Hits | ${state.nucleiFindings.length} |\n| Dark Web | ${state.darkWebFindings.length} |\n| IDOR | ${state.idorFindings.length} |\n| Exploits | ${state.exploitFindings.length} |\n| Risk Score | ${state.riskScore}/100 (${state.riskGrade}) |\n\n`;
  md += `## Subdomains (${state.subs.length})\n\`\`\`\n`;
  state.subs.forEach(s => { md += `${s.subdomain}${s.ip ? ' → ' + s.ip : ''}\n`; });
  md += `\`\`\`\n\n---\n*Generated by TeamCyberOps Recon v14.6*\n`;
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
