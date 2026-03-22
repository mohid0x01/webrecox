import "https://deno.land/x/xhr@0.1.0/mod.ts";
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

async function pFetch(url: string, timeout = 15000) {
  const proxies = [
    (u: string) => u, // direct first
    (u: string) => `https://api.allorigins.win/raw?url=${encodeURIComponent(u)}`,
  ];
  for (const proxy of proxies) {
    try {
      const controller = new AbortController();
      const tid = setTimeout(() => controller.abort(), timeout);
      const res = await fetch(proxy(url), { signal: controller.signal });
      clearTimeout(tid);
      if (res.ok) return res;
    } catch { /* try next */ }
  }
  throw new Error('All fetch attempts failed for ' + url);
}

function isValidSub(s: string, domain: string) {
  if (!s || s.includes('@') || s.includes('/') || s.startsWith('*')) return false;
  s = s.trim().toLowerCase().replace(/^\*\./, '');
  if (s === domain || !s.endsWith('.' + domain)) return false;
  if (!/^[a-z0-9][a-z0-9.\-]*[a-z0-9]$/.test(s)) return false;
  return true;
}

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const { tool, target } = await req.json();
    if (!target || !tool) {
      return new Response(JSON.stringify({ error: 'Missing tool or target' }), {
        status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    let results: any = null;

    switch (tool) {
      // ─── SUBDOMAIN DISCOVERY (10+ sources) ───
      case 'subdomain_discovery': {
        const domain = target.toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*/, '');
        const allSubs = new Map<string, { subdomain: string; ip: string; source: string }>();

        const addSub = (s: string, ip: string, source: string) => {
          s = s.trim().toLowerCase().replace(/^\*\./, '');
          if (!isValidSub(s, domain)) return;
          if (allSubs.has(s)) {
            const ex = allSubs.get(s)!;
            if (ip && !ex.ip) ex.ip = ip;
            if (!ex.source.includes(source)) ex.source += ', ' + source;
          } else {
            allSubs.set(s, { subdomain: s, ip: ip || '', source });
          }
        };

        // 1. crt.sh
        try {
          const r = await pFetch(`https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`, 40000);
          const data = await r.json();
          for (const entry of data) {
            for (const name of (entry.name_value || '').split('\n')) {
              addSub(name, '', 'crt.sh');
            }
          }
        } catch { /* skip */ }

        // 2. HackerTarget
        try {
          const r = await pFetch(`https://api.hackertarget.com/hostsearch/?q=${domain}`, 15000);
          const text = await r.text();
          if (!text.includes('API count exceeded') && !text.startsWith('error') && !text.startsWith('<')) {
            for (const line of text.trim().split('\n')) {
              const [host, ip] = line.split(',');
              if (host) addSub(host, ip || '', 'HackerTarget');
            }
          }
        } catch { /* skip */ }

        // 3. AnubisDB
        try {
          const r = await pFetch(`https://jldc.me/anubis/subdomains/${domain}`, 15000);
          const data = await r.json();
          if (Array.isArray(data)) data.forEach((s: string) => addSub(s, '', 'AnubisDB'));
        } catch { /* skip */ }

        // 4. CertSpotter
        try {
          const r = await pFetch(`https://api.certspotter.com/v1/issuances?domain=${domain}&include_subdomains=true&expand=dns_names`, 15000);
          const data = await r.json();
          if (Array.isArray(data)) {
            for (const cert of data) {
              for (const name of (cert.dns_names || [])) addSub(name, '', 'CertSpotter');
            }
          }
        } catch { /* skip */ }

        // 5. OTX PassiveDNS
        try {
          const r = await pFetch(`https://otx.alienvault.com/api/v1/indicators/domain/${domain}/passive_dns`, 15000);
          const data = await r.json();
          for (const rec of (data.passive_dns || [])) {
            addSub(rec.hostname || rec.indicator || '', rec.address || '', 'OTX');
          }
        } catch { /* skip */ }

        // 6. URLScan
        try {
          const r = await pFetch(`https://urlscan.io/api/v1/search/?q=page.domain:${domain}&size=100`, 15000);
          const data = await r.json();
          for (const res of (data.results || [])) {
            const sub = res.page?.domain || '';
            addSub(sub, res.page?.ip || '', 'URLScan');
          }
        } catch { /* skip */ }

        // 7. ThreatMiner
        try {
          const r = await pFetch(`https://api.threatminer.org/v2/domain.php?q=${domain}&rt=5`, 15000);
          const data = await r.json();
          for (const s of (data.results || [])) addSub(s, '', 'ThreatMiner');
        } catch { /* skip */ }

        // 8. Wayback Subs
        try {
          const r = await pFetch(`https://web.archive.org/cdx/search/cdx?url=*.${domain}/*&output=text&fl=original&collapse=urlkey&limit=5000`, 30000);
          const text = await r.text();
          for (const u of text.trim().split('\n')) {
            try {
              const h = new URL(u.trim()).hostname.toLowerCase().replace(/^\*\./, '');
              addSub(h, '', 'Wayback');
            } catch { /* skip */ }
          }
        } catch { /* skip */ }

        // 9. RapidDNS
        try {
          const r = await pFetch(`https://rapiddns.io/subdomain/${domain}?full=1`, 15000);
          const html = await r.text();
          const re = new RegExp(`<td>([a-z0-9][a-z0-9\\-\\.]*\\.${domain.replace(/\./g, '\\.')})<\\/td>`, 'gi');
          let m;
          while ((m = re.exec(html)) !== null) addSub(m[1], '', 'RapidDNS');
        } catch { /* skip */ }

        // 10. DNS Bruteforce (top 100 common prefixes)
        const BF_WORDS = ['www','mail','ftp','smtp','pop','ns1','ns2','mx','dev','api','blog','cdn','shop','app','m','admin','portal','vpn','ssh','secure','help','support','webmail','remote','server','cloud','git','gitlab','jenkins','jira','staging','beta','test','uat','qa','prod','static','assets','media','images','files','docs','wiki','forum','login','auth','sso','dashboard','panel','cpanel','manage','web1','web2','proxy','gw','office','intranet','internal','corp','exchange','autodiscover','imap','dns','chat','meet','api2','graphql','ws','monitor','status','metrics','health','log','sentry','grafana','redis','mysql','postgres','mongodb','backup','data','db','s3','storage','sftp','email','mobile','android','ios','reports','crm','erp','ticket','nexus','ci','cd','deploy','build'];
        
        for (let i = 0; i < BF_WORDS.length; i += 20) {
          const batch = BF_WORDS.slice(i, i + 20);
          await Promise.all(batch.map(async (w) => {
            try {
              const r = await fetch(`https://dns.google/resolve?name=${w}.${domain}&type=A`, { signal: AbortSignal.timeout(4000) });
              const d = await r.json();
              const ips = (d.Answer || []).filter((a: any) => a.type === 1).map((a: any) => a.data);
              if (ips.length) addSub(`${w}.${domain}`, ips[0], 'Bruteforce');
            } catch { /* skip */ }
          }));
        }

        // Resolve unresolved (batch, top 100)
        const unresolved = [...allSubs.values()].filter(s => !s.ip).slice(0, 100);
        for (let i = 0; i < unresolved.length; i += 15) {
          const batch = unresolved.slice(i, i + 15);
          await Promise.all(batch.map(async (sub) => {
            try {
              const r = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(sub.subdomain)}&type=A`, { signal: AbortSignal.timeout(4000) });
              const d = await r.json();
              const ip = ((d.Answer || []).find((a: any) => a.type === 1) || {}).data || '';
              if (ip) sub.ip = ip;
            } catch { /* skip */ }
          }));
        }

        const subdomains = [...allSubs.values()].sort((a, b) => {
          if (!!a.ip !== !!b.ip) return a.ip ? -1 : 1;
          return a.subdomain.localeCompare(b.subdomain);
        });

        results = {
          subdomains,
          count: subdomains.length,
          live: subdomains.filter(s => s.ip).length,
          sources: [...new Set(subdomains.flatMap(s => s.source.split(', ')))],
        };
        break;
      }

      case 'endpoint_discovery': {
        const domain = target.toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*/, '');
        const epSeen = new Set<string>();
        const endpoints: { url: string; status: string; source: string }[] = [];

        const addEp = (url: string, status: string, source: string) => {
          if (!url || url.length > 1200) return;
          if (/\.(ico|png|jpg|jpeg|gif|css|woff|woff2|ttf|eot|mp4|mp3|webp|zip|gz|map)(\?|$)/i.test(url)) return;
          const key = url.split('#')[0];
          if (epSeen.has(key)) return;
          epSeen.add(key);
          endpoints.push({ url, status, source });
        };

        // Wayback CDX
        try {
          const r = await pFetch(`https://web.archive.org/cdx/search/cdx?url=*.${domain}/*&output=json&fl=original,statuscode&collapse=urlkey&limit=10000`, 30000);
          const data = await r.json();
          if (Array.isArray(data)) {
            for (let i = 1; i < data.length; i++) {
              addEp(data[i][0], data[i][1] || '-', 'Wayback');
            }
          }
        } catch { /* skip */ }

        // OTX URLs
        try {
          const r = await pFetch(`https://otx.alienvault.com/api/v1/indicators/domain/${domain}/url_list?limit=500&page=1`, 15000);
          const data = await r.json();
          for (const entry of (data.url_list || [])) {
            const st = entry.result?.urlworker?.http_code ? String(entry.result.urlworker.http_code) : '-';
            addEp(entry.url, st, 'OTX');
          }
        } catch { /* skip */ }

        // URLScan
        try {
          const r = await pFetch(`https://urlscan.io/api/v1/search/?q=page.domain:${domain}&size=100`, 15000);
          const data = await r.json();
          for (const res of (data.results || [])) {
            addEp(res.page?.url || '', String(res.page?.status || '-'), 'URLScan');
          }
        } catch { /* skip */ }

        const jsFiles = endpoints.filter(e => /\.js(\?|$)/i.test(e.url));
        const withParams = endpoints.filter(e => e.url.includes('?'));

        results = {
          endpoints,
          count: endpoints.length,
          jsCount: jsFiles.length,
          paramCount: withParams.length,
          sources: [...new Set(endpoints.map(e => e.source))],
        };
        break;
      }

      case 'certificate_analysis': {
        const res = await pFetch(`https://crt.sh/?q=${encodeURIComponent(target)}&output=json`, 30000);
        const data = await res.json();
        const certs = data.slice(0, 30).map((entry: any) => ({
          issuer: entry.issuer_name,
          common_name: entry.common_name,
          name_value: entry.name_value,
          not_before: entry.not_before,
          not_after: entry.not_after,
          serial_number: entry.serial_number,
        }));
        results = { certificates: certs, count: certs.length, source: 'crt.sh' };
        break;
      }

      case 'dns_lookup': {
        const types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'CAA'];
        const records: Record<string, any[]> = {};
        // Use multiple resolvers
        const resolvers = ['https://dns.google/resolve', 'https://cloudflare-dns.com/dns-query'];
        for (const type of types) {
          for (const resolver of resolvers) {
            try {
              const url = resolver === resolvers[1]
                ? `${resolver}?name=${encodeURIComponent(target)}&type=${type}`
                : `${resolver}?name=${encodeURIComponent(target)}&type=${type}`;
              const headers: Record<string, string> = resolver.includes('cloudflare') ? { Accept: 'application/dns-json' } : {};
              const res = await fetch(url, { headers, signal: AbortSignal.timeout(5000) });
              const data = await res.json();
              if (data.Answer) {
                if (!records[type]) records[type] = [];
                for (const a of data.Answer) {
                  const exists = records[type].some(r => r.data === a.data);
                  if (!exists) records[type].push({ name: a.name, data: a.data, ttl: a.TTL, resolver: resolver.includes('google') ? 'Google' : 'Cloudflare' });
                }
              }
              break; // got answer from this resolver
            } catch { /* try next */ }
          }
        }
        results = { records, source: 'Google DNS + Cloudflare' };
        break;
      }

      case 'http_probe': {
        const probes: any[] = [];
        for (const protocol of ['https', 'http']) {
          try {
            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), 8000);
            const res = await fetch(`${protocol}://${target}`, { method: 'GET', redirect: 'follow', signal: controller.signal });
            clearTimeout(timeout);
            const html = await res.text();
            const titleMatch = html.match(/<title[^>]*>([^<]{0,200})<\/title>/i);
            const server = res.headers.get('server') || '';
            const powered = res.headers.get('x-powered-by') || '';
            const techs: string[] = [];
            if (server) techs.push(server);
            if (powered) techs.push(powered);
            if (html.includes('wp-content')) techs.push('WordPress');
            if (html.includes('__next')) techs.push('Next.js');
            if (html.includes('__nuxt')) techs.push('Nuxt.js');
            if (html.includes('react') || html.includes('data-reactroot')) techs.push('React');
            if (html.includes('ng-version')) techs.push('Angular');
            probes.push({
              url: `${protocol}://${target}`,
              status: res.status,
              status_text: res.statusText,
              redirected: res.redirected,
              final_url: res.url,
              title: titleMatch ? titleMatch[1].trim() : '',
              tech: techs,
              size: html.length,
            });
          } catch (e: any) {
            probes.push({ url: `${protocol}://${target}`, status: 'error', error: e.message });
          }
        }
        results = { probes, source: 'Direct HTTP Probe' };
        break;
      }

      case 'security_headers': {
        try {
          const res = await fetch(`https://${target}`, { method: 'HEAD', signal: AbortSignal.timeout(8000) });
          const importantHeaders = [
            'strict-transport-security', 'content-security-policy', 'x-frame-options',
            'x-content-type-options', 'referrer-policy', 'permissions-policy',
            'x-xss-protection', 'access-control-allow-origin', 'server',
            'x-powered-by', 'set-cookie', 'cache-control',
          ];
          const found: Record<string, string> = {};
          const missing: string[] = [];
          for (const h of importantHeaders) {
            const val = res.headers.get(h);
            if (val) found[h] = val; else if (!['server', 'x-powered-by', 'set-cookie', 'cache-control'].includes(h)) missing.push(h);
          }
          // WAF detection
          let waf = 'Unknown';
          const allHeaders = Object.entries(found).map(([k, v]) => `${k}: ${v}`).join('\n').toLowerCase();
          if (allHeaders.includes('cloudflare')) waf = 'Cloudflare';
          else if (allHeaders.includes('akamai')) waf = 'Akamai';
          else if (allHeaders.includes('sucuri')) waf = 'Sucuri';
          else if (allHeaders.includes('imperva') || allHeaders.includes('incapsula')) waf = 'Imperva/Incapsula';
          else if (allHeaders.includes('aws')) waf = 'AWS WAF';

          results = { found, missing, status: res.status, waf, source: 'HTTPS Header Analysis' };
        } catch (e: any) {
          results = { error: e.message, source: 'HTTPS Header Analysis' };
        }
        break;
      }

      case 'whois_lookup': {
        try {
          const res = await pFetch(`https://rdap.org/domain/${encodeURIComponent(target)}`, 15000);
          const data = await res.json();
          results = {
            name: data.ldhName,
            status: data.status,
            events: data.events?.map((e: any) => ({ action: e.eventAction, date: e.eventDate })),
            nameservers: data.nameservers?.map((ns: any) => ns.ldhName),
            entities: data.entities?.slice(0, 5).map((e: any) => ({
              role: e.roles?.join(', '),
              name: e.vcardArray?.[1]?.find((v: any) => v[0] === 'fn')?.[3] || '',
            })),
            source: 'RDAP',
          };
        } catch (e: any) {
          results = { error: e.message, source: 'RDAP' };
        }
        break;
      }

      case 'tech_detection': {
        try {
          const res = await fetch(`https://${target}`, { signal: AbortSignal.timeout(8000) });
          const html = await res.text();
          const techs: string[] = [];
          const server = res.headers.get('server');
          if (server) techs.push(`Server: ${server}`);
          const powered = res.headers.get('x-powered-by');
          if (powered) techs.push(`Powered-By: ${powered}`);
          if (html.includes('wp-content') || html.includes('wp-includes')) techs.push('WordPress');
          if (html.includes('next/static') || html.includes('__next')) techs.push('Next.js');
          if (html.includes('__nuxt')) techs.push('Nuxt.js');
          if (html.includes('react') || html.includes('data-reactroot')) techs.push('React');
          if (html.includes('ng-version') || html.includes('angular')) techs.push('Angular');
          if (html.includes('vue')) techs.push('Vue.js');
          if (html.includes('cloudflare')) techs.push('Cloudflare');
          if (html.includes('jquery') || html.includes('jQuery')) techs.push('jQuery');
          if (html.includes('bootstrap')) techs.push('Bootstrap');
          if (html.includes('tailwind')) techs.push('Tailwind CSS');
          if (html.includes('google-analytics') || html.includes('gtag')) techs.push('Google Analytics');
          if (html.includes('recaptcha')) techs.push('reCAPTCHA');
          if (html.includes('shopify')) techs.push('Shopify');
          if (html.includes('laravel')) techs.push('Laravel');
          if (html.includes('django')) techs.push('Django');
          if (html.includes('express')) techs.push('Express.js');
          results = { technologies: [...new Set(techs)], source: 'Response Analysis' };
        } catch (e: any) {
          results = { error: e.message, source: 'Response Analysis' };
        }
        break;
      }

      case 'port_scan': {
        // Use Shodan InternetDB
        try {
          // First resolve to IP
          const dnsRes = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(target)}&type=A`, { signal: AbortSignal.timeout(5000) });
          const dnsData = await dnsRes.json();
          const ip = ((dnsData.Answer || []).find((a: any) => a.type === 1) || {}).data;
          if (!ip) { results = { error: 'Could not resolve IP', source: 'Shodan InternetDB' }; break; }
          
          const r = await fetch(`https://internetdb.shodan.io/${ip}`, { signal: AbortSignal.timeout(8000) });
          const data = await r.json();
          results = {
            ip,
            ports: data.ports || [],
            cpes: data.cpes || [],
            hostnames: data.hostnames || [],
            vulns: data.vulns || [],
            tags: data.tags || [],
            source: 'Shodan InternetDB',
          };
        } catch (e: any) {
          results = { error: e.message, source: 'Shodan InternetDB' };
        }
        break;
      }

      case 'ip_geolocation': {
        try {
          const dnsRes = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(target)}&type=A`, { signal: AbortSignal.timeout(5000) });
          const dnsData = await dnsRes.json();
          const ip = ((dnsData.Answer || []).find((a: any) => a.type === 1) || {}).data;
          if (!ip) { results = { error: 'Could not resolve IP', source: 'ipinfo.io' }; break; }

          const r = await fetch(`https://ipinfo.io/${ip}/json`, { signal: AbortSignal.timeout(8000) });
          const data = await r.json();
          results = {
            ip: data.ip,
            hostname: data.hostname,
            city: data.city,
            region: data.region,
            country: data.country,
            loc: data.loc,
            org: data.org,
            postal: data.postal,
            timezone: data.timezone,
            source: 'ipinfo.io',
          };
        } catch (e: any) {
          results = { error: e.message, source: 'ipinfo.io' };
        }
        break;
      }

      case 'crawl_rules': {
        const urls: Record<string, string> = {};
        for (const file of ['robots.txt', 'security.txt', '.well-known/security.txt', 'sitemap.xml']) {
          try {
            const r = await fetch(`https://${target}/${file}`, { signal: AbortSignal.timeout(5000) });
            if (r.ok) {
              const text = await r.text();
              urls[file] = text.slice(0, 5000);
            }
          } catch { /* skip */ }
        }
        results = { files: urls, source: 'Direct Fetch' };
        break;
      }

      default:
        return new Response(JSON.stringify({ error: `Unknown tool: ${tool}` }), {
          status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
    }

    return new Response(JSON.stringify({ success: true, tool, target, results }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  } catch (error: any) {
    console.error('Scan error:', error);
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }
});
