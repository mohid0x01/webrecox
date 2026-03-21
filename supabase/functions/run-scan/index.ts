import "https://deno.land/x/xhr@0.1.0/mod.ts";
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const { tool, target } = await req.json();

    if (!target || !tool) {
      return new Response(JSON.stringify({ error: 'Missing tool or target' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    let results: any = null;

    switch (tool) {
      case 'subdomain_discovery': {
        // Use crt.sh certificate transparency API
        const res = await fetch(`https://crt.sh/?q=%25.${encodeURIComponent(target)}&output=json`);
        if (!res.ok) throw new Error(`crt.sh returned ${res.status}`);
        const data = await res.json();
        const subdomains = [...new Set(
          data.map((entry: any) => entry.name_value)
            .flatMap((name: string) => name.split('\n'))
            .filter((name: string) => name.includes(target))
            .map((name: string) => name.replace(/^\*\./, ''))
        )].sort();
        results = { subdomains, count: subdomains.length, source: 'crt.sh (Certificate Transparency)' };
        break;
      }

      case 'certificate_analysis': {
        // Fetch SSL cert info via crt.sh
        const res = await fetch(`https://crt.sh/?q=${encodeURIComponent(target)}&output=json`);
        if (!res.ok) throw new Error(`crt.sh returned ${res.status}`);
        const data = await res.json();
        const certs = data.slice(0, 20).map((entry: any) => ({
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
        // Use Google DNS-over-HTTPS
        const types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA'];
        const records: Record<string, any[]> = {};
        for (const type of types) {
          try {
            const res = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(target)}&type=${type}`);
            const data = await res.json();
            if (data.Answer) {
              records[type] = data.Answer.map((a: any) => ({ name: a.name, data: a.data, ttl: a.TTL }));
            }
          } catch { /* skip failed type */ }
        }
        results = { records, source: 'Google Public DNS' };
        break;
      }

      case 'http_probe': {
        // Check HTTP/HTTPS status and headers
        const probes: any[] = [];
        for (const protocol of ['https', 'http']) {
          try {
            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), 8000);
            const res = await fetch(`${protocol}://${target}`, {
              method: 'HEAD',
              redirect: 'follow',
              signal: controller.signal,
            });
            clearTimeout(timeout);
            probes.push({
              url: `${protocol}://${target}`,
              status: res.status,
              status_text: res.statusText,
              redirected: res.redirected,
              final_url: res.url,
            });
          } catch (e: any) {
            probes.push({
              url: `${protocol}://${target}`,
              status: 'error',
              error: e.message,
            });
          }
        }
        results = { probes, source: 'Direct HTTP Probe' };
        break;
      }

      case 'security_headers': {
        // Analyze security headers
        try {
          const controller = new AbortController();
          const timeout = setTimeout(() => controller.abort(), 8000);
          const res = await fetch(`https://${target}`, {
            method: 'HEAD',
            signal: controller.signal,
          });
          clearTimeout(timeout);

          const importantHeaders = [
            'strict-transport-security', 'content-security-policy', 'x-frame-options',
            'x-content-type-options', 'referrer-policy', 'permissions-policy',
            'x-xss-protection', 'access-control-allow-origin', 'server',
          ];

          const found: Record<string, string> = {};
          const missing: string[] = [];

          for (const h of importantHeaders) {
            const val = res.headers.get(h);
            if (val) {
              found[h] = val;
            } else {
              missing.push(h);
            }
          }

          results = { found, missing, status: res.status, source: 'HTTPS Header Analysis' };
        } catch (e: any) {
          results = { error: e.message, source: 'HTTPS Header Analysis' };
        }
        break;
      }

      case 'whois_lookup': {
        // Use a public RDAP API
        try {
          const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(target)}`);
          if (!res.ok) throw new Error(`RDAP returned ${res.status}`);
          const data = await res.json();
          results = {
            name: data.ldhName,
            status: data.status,
            events: data.events?.map((e: any) => ({ action: e.eventAction, date: e.eventDate })),
            nameservers: data.nameservers?.map((ns: any) => ns.ldhName),
            source: 'RDAP',
          };
        } catch (e: any) {
          results = { error: e.message, source: 'RDAP' };
        }
        break;
      }

      case 'tech_detection': {
        // Detect technologies via response headers and HTML
        try {
          const controller = new AbortController();
          const timeout = setTimeout(() => controller.abort(), 8000);
          const res = await fetch(`https://${target}`, { signal: controller.signal });
          clearTimeout(timeout);
          const html = await res.text();
          const techs: string[] = [];

          // Server
          const server = res.headers.get('server');
          if (server) techs.push(`Server: ${server}`);
          const powered = res.headers.get('x-powered-by');
          if (powered) techs.push(`Powered-By: ${powered}`);

          // Framework detection from HTML
          if (html.includes('wp-content') || html.includes('wp-includes')) techs.push('WordPress');
          if (html.includes('next/static') || html.includes('__next')) techs.push('Next.js');
          if (html.includes('__nuxt')) techs.push('Nuxt.js');
          if (html.includes('react')) techs.push('React (detected)');
          if (html.includes('angular')) techs.push('Angular (detected)');
          if (html.includes('vue')) techs.push('Vue.js (detected)');
          if (html.includes('cloudflare')) techs.push('Cloudflare');
          if (html.includes('jquery') || html.includes('jQuery')) techs.push('jQuery');
          if (html.includes('bootstrap')) techs.push('Bootstrap');
          if (html.includes('tailwind')) techs.push('Tailwind CSS');
          if (html.includes('google-analytics') || html.includes('gtag')) techs.push('Google Analytics');
          if (html.includes('recaptcha')) techs.push('reCAPTCHA');

          results = { technologies: [...new Set(techs)], source: 'Response Analysis' };
        } catch (e: any) {
          results = { error: e.message, source: 'Response Analysis' };
        }
        break;
      }

      default:
        return new Response(JSON.stringify({ error: `Unknown tool: ${tool}` }), {
          status: 400,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
    }

    return new Response(JSON.stringify({ success: true, tool, target, results }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  } catch (error: any) {
    console.error('Scan error:', error);
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }
});
