import { useState, useCallback } from 'react';
import { Search, Download, FileJson, FileText, Printer, Loader2, CheckCircle, AlertCircle, Globe, Radar, Activity, Cpu, Shield, Server, Link, Key, Bug, Eye } from 'lucide-react';
import { supabase } from '@/integrations/supabase/client';
import { exportCSV, exportJSON, exportTXT, exportPDF } from '@/lib/exportUtils';

type ScanTab = 'subdomains' | 'endpoints' | 'dns' | 'headers' | 'tech' | 'whois' | 'ports' | 'probe';

const SCAN_TOOLS: { tab: ScanTab; tool: string; label: string; icon: any }[] = [
  { tab: 'subdomains', tool: 'subdomain_discovery', label: 'Subdomains', icon: Globe },
  { tab: 'endpoints', tool: 'endpoint_discovery', label: 'Endpoints', icon: Link },
  { tab: 'dns', tool: 'dns_lookup', label: 'DNS', icon: Radar },
  { tab: 'headers', tool: 'security_headers', label: 'Headers/WAF', icon: Shield },
  { tab: 'tech', tool: 'tech_detection', label: 'Tech Stack', icon: Cpu },
  { tab: 'whois', tool: 'whois_lookup', label: 'WHOIS', icon: Server },
  { tab: 'ports', tool: 'port_scan', label: 'Ports/CVE', icon: Bug },
  { tab: 'probe', tool: 'http_probe', label: 'HTTP Probe', icon: Activity },
];

const Index = () => {
  const [target, setTarget] = useState('');
  const [activeTab, setActiveTab] = useState<ScanTab>('subdomains');
  const [scanning, setScanning] = useState<Record<string, boolean>>({});
  const [results, setResults] = useState<Record<string, any>>({});
  const [errors, setErrors] = useState<Record<string, string>>({});

  const runScan = useCallback(async (tool: string) => {
    if (!target || scanning[tool]) return;
    setScanning(prev => ({ ...prev, [tool]: true }));
    setErrors(prev => ({ ...prev, [tool]: '' }));
    try {
      const { data, error } = await supabase.functions.invoke('run-scan', { body: { tool, target } });
      if (error) throw error;
      if (data?.error) throw new Error(data.error);
      setResults(prev => ({ ...prev, [tool]: data.results }));
    } catch (e: any) {
      setErrors(prev => ({ ...prev, [tool]: e.message || 'Scan failed' }));
    } finally {
      setScanning(prev => ({ ...prev, [tool]: false }));
    }
  }, [target, scanning]);

  const runFullScan = async () => {
    if (!target) return;
    for (const { tool } of SCAN_TOOLS) {
      runScan(tool);
    }
  };

  const handleExport = (format: 'csv' | 'json' | 'pdf' | 'txt') => {
    const domain = target || 'scan';
    if (format === 'json') {
      exportJSON(results, `${domain}_report`);
    } else if (format === 'csv') {
      const subData = results.subdomain_discovery?.subdomains || [];
      if (subData.length) exportCSV(subData, `${domain}_subdomains`);
      else exportCSV([{ info: 'No data' }], `${domain}_report`);
    } else if (format === 'txt') {
      const lines: string[] = [`TeamCyberOps Recon Report — ${domain}`, `Generated: ${new Date().toISOString()}`, ''];
      const subs = results.subdomain_discovery?.subdomains || [];
      if (subs.length) { lines.push(`SUBDOMAINS (${subs.length}):`); subs.forEach((s: any) => lines.push(`  ${s.subdomain} ${s.ip ? '→ ' + s.ip : ''} [${s.source}]`)); lines.push(''); }
      exportTXT(lines, `${domain}_report`);
    } else if (format === 'pdf') {
      const sections: { heading: string; content: string }[] = [];
      const subs = results.subdomain_discovery?.subdomains || [];
      if (subs.length) sections.push({ heading: `Subdomains (${subs.length})`, content: subs.map((s: any) => `${s.subdomain}  ${s.ip || '—'}  [${s.source}]`).join('\n') });
      const dns = results.dns_lookup?.records;
      if (dns) sections.push({ heading: 'DNS Records', content: Object.entries(dns).map(([t, recs]) => `${t}:\n${(recs as any[]).map(r => `  ${r.data}`).join('\n')}`).join('\n\n') });
      const hdrs = results.security_headers;
      if (hdrs?.found) sections.push({ heading: 'Security Headers', content: `Present:\n${Object.entries(hdrs.found).map(([k, v]) => `  ✓ ${k}: ${v}`).join('\n')}\n\nMissing:\n${(hdrs.missing || []).map((h: string) => `  ✗ ${h}`).join('\n')}\n\nWAF: ${hdrs.waf || 'Unknown'}` });
      if (!sections.length) sections.push({ heading: 'No Data', content: 'Run a scan first to generate a report.' });
      exportPDF(`Recon Report — ${domain}`, sections);
    }
  };

  const r = results;

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="sticky top-0 z-50 border-b border-border bg-background/95 backdrop-blur-sm">
        <div className="max-w-full mx-auto px-5 h-[52px] flex items-center gap-3">
          <a href="/" className="flex items-center gap-2.5 no-underline shrink-0">
            <img src="https://github.com/mohidqx.png" alt="TeamCyberOps" className="w-[30px] h-[30px] rounded-full border-2 border-[hsl(var(--warning))]/40 shadow-[0_0_10px_hsl(var(--warning)/0.3)]" />
            <span className="text-sm font-bold text-foreground">Team<span className="text-[hsl(var(--warning))]">CyberOps</span></span>
            <span className="font-mono text-[8px] px-1.5 py-0.5 rounded-full bg-[hsl(var(--warning))]/10 border border-border text-[hsl(var(--warning))] tracking-widest">RECON v8</span>
          </a>

          {/* Search in header */}
          <div className="flex-1 max-w-md mx-4 relative">
            <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" />
            <input
              type="text" value={target} onChange={e => setTarget(e.target.value)}
              placeholder="target domain — e.g. tesla.com"
              onKeyDown={e => e.key === 'Enter' && runFullScan()}
              className="w-full pl-9 pr-3 py-1.5 bg-[hsl(var(--warning))]/5 border border-border rounded-lg font-mono text-xs text-foreground placeholder:text-muted-foreground focus:outline-none focus:border-[hsl(var(--warning))]/40 transition-all"
            />
          </div>

          <button onClick={runFullScan} disabled={!target || Object.values(scanning).some(Boolean)} className="shrink-0 px-4 py-1.5 bg-gradient-to-r from-amber-800/90 to-[hsl(var(--warning))]/85 border border-[hsl(var(--warning))]/50 rounded-lg text-xs font-bold text-amber-950 hover:shadow-[0_4px_20px_hsl(var(--warning)/0.3)] transition-all disabled:opacity-40 cursor-pointer active:scale-[0.97]">
            {Object.values(scanning).some(Boolean) ? '⟳ Scanning…' : '⟳ Full Scan'}
          </button>

          {/* Export */}
          <div className="flex gap-1 shrink-0">
            <button onClick={() => handleExport('json')} className="px-2 py-1.5 border border-border rounded text-[10px] text-muted-foreground hover:text-foreground transition-colors cursor-pointer" title="Export JSON"><FileJson size={12}/></button>
            <button onClick={() => handleExport('csv')} className="px-2 py-1.5 border border-border rounded text-[10px] text-muted-foreground hover:text-foreground transition-colors cursor-pointer" title="Export CSV"><Download size={12}/></button>
            <button onClick={() => handleExport('txt')} className="px-2 py-1.5 border border-border rounded text-[10px] text-muted-foreground hover:text-foreground transition-colors cursor-pointer" title="Export TXT"><FileText size={12}/></button>
            <button onClick={() => handleExport('pdf')} className="px-2 py-1.5 border border-border rounded text-[10px] text-muted-foreground hover:text-foreground transition-colors cursor-pointer" title="Export PDF"><Printer size={12}/></button>
          </div>

          <a href="/oneliners" className="shrink-0 px-3 py-1.5 border border-blue-400/20 bg-blue-400/5 rounded text-[10px] text-blue-400 hover:bg-blue-400/10 transition-colors no-underline">⚡ Oneliners</a>
        </div>
      </header>

      <div className="max-w-full mx-auto px-5 py-4">
        {/* Tab buttons */}
        <div className="flex flex-wrap gap-1 mb-4">
          {SCAN_TOOLS.map(({ tab, tool, label, icon: Icon }) => {
            const hasData = !!results[tool];
            const isScanning = scanning[tool];
            return (
              <button key={tab} onClick={() => { setActiveTab(tab); if (!hasData && !isScanning && target) runScan(tool); }}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md border text-xs font-medium transition-all cursor-pointer active:scale-[0.97] ${activeTab === tab ? 'bg-[hsl(var(--warning))]/10 border-[hsl(var(--warning))]/30 text-[hsl(var(--warning))]' : 'border-border text-muted-foreground hover:text-foreground'}`}>
                {isScanning ? <Loader2 size={12} className="animate-spin" /> : <Icon size={12} />}
                {label}
                {hasData && <span className="bg-[hsl(var(--warning))]/15 text-[hsl(var(--warning))] px-1 rounded font-mono text-[8px]">✓</span>}
              </button>
            );
          })}
        </div>

        {/* Results Panel */}
        <div className="bg-card border border-border rounded-xl overflow-hidden">
          <div className="px-4 py-2.5 border-b border-border bg-[hsl(var(--warning))]/[0.02] flex items-center justify-between">
            <span className="font-mono text-[10px] text-muted-foreground tracking-wider uppercase">{activeTab}</span>
            {!scanning[SCAN_TOOLS.find(s => s.tab === activeTab)?.tool || ''] && (
              <button onClick={() => { const t = SCAN_TOOLS.find(s => s.tab === activeTab); if (t && target) runScan(t.tool); }}
                className="text-[10px] font-mono text-[hsl(var(--warning))] hover:underline cursor-pointer">🔄 Re-scan</button>
            )}
          </div>

          <div className="p-4 min-h-[400px] max-h-[70vh] overflow-y-auto scrollbar-thin font-mono text-xs">
            {(() => {
              const tool = SCAN_TOOLS.find(s => s.tab === activeTab)?.tool || '';
              const isLoading = scanning[tool];
              const error = errors[tool];
              const data = results[tool];

              if (isLoading) return <div className="flex items-center gap-2 text-[hsl(var(--warning))]"><Loader2 size={14} className="animate-spin" /> Scanning {target}…</div>;
              if (error) return <div className="flex items-center gap-2 text-destructive"><AlertCircle size={14} /> {error}</div>;
              if (!data) return <div className="text-muted-foreground text-center py-16">Enter a domain and run a scan to see results.</div>;

              // SUBDOMAINS
              if (activeTab === 'subdomains' && data.subdomains) {
                return (
                  <div>
                    <div className="flex gap-3 mb-4 flex-wrap">
                      <Stat label="SUBDOMAINS" value={data.count} color="var(--warning)" />
                      <Stat label="LIVE HOSTS" value={data.live} color="hsl(142,71%,45%)" />
                      <Stat label="SOURCES" value={data.sources?.length || 0} color="hsl(210,100%,56%)" />
                    </div>
                    <table className="w-full text-xs"><thead><tr className="text-muted-foreground text-left"><th className="pb-2 font-semibold">#</th><th className="pb-2 font-semibold">SUBDOMAIN</th><th className="pb-2 font-semibold">IP</th><th className="pb-2 font-semibold">SOURCE</th></tr></thead>
                    <tbody>{data.subdomains.slice(0, 500).map((s: any, i: number) => (
                      <tr key={i} className="border-t border-border/50 hover:bg-[hsl(var(--warning))]/[0.02]">
                        <td className="py-1.5 text-muted-foreground">{i + 1}</td>
                        <td className="py-1.5"><a href={`https://${s.subdomain}`} target="_blank" className="text-[hsl(var(--warning))] no-underline hover:underline">{s.subdomain}</a></td>
                        <td className="py-1.5">{s.ip ? <span className="bg-card border border-border rounded px-1.5 py-0.5 text-[10px]">{s.ip}</span> : <span className="text-muted-foreground">—</span>}</td>
                        <td className="py-1.5 text-muted-foreground">{s.source}</td>
                      </tr>
                    ))}</tbody></table>
                    {data.count > 500 && <div className="text-center py-3 text-muted-foreground">Showing 500 of {data.count} — Export for full list</div>}
                  </div>
                );
              }

              // ENDPOINTS
              if (activeTab === 'endpoints' && data.endpoints) {
                return (
                  <div>
                    <div className="flex gap-3 mb-4 flex-wrap">
                      <Stat label="ENDPOINTS" value={data.count} color="var(--warning)" />
                      <Stat label="JS FILES" value={data.jsCount} color="hsl(38,92%,50%)" />
                      <Stat label="WITH PARAMS" value={data.paramCount} color="hsl(280,70%,60%)" />
                    </div>
                    {data.endpoints.slice(0, 300).map((ep: any, i: number) => (
                      <div key={i} className="flex items-center gap-2 py-1 border-b border-border/30 hover:bg-[hsl(var(--warning))]/[0.02]">
                        <span className="text-muted-foreground w-8 text-right shrink-0">{i + 1}</span>
                        <StatusBadge status={ep.status} />
                        <a href={ep.url} target="_blank" className="text-blue-400 no-underline hover:underline truncate">{ep.url}</a>
                        <span className="ml-auto text-muted-foreground text-[9px] shrink-0">{ep.source}</span>
                      </div>
                    ))}
                  </div>
                );
              }

              // DNS
              if (activeTab === 'dns' && data.records) {
                return (
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                    {Object.entries(data.records).map(([type, recs]) => (
                      <div key={type} className="bg-background border border-border rounded-lg overflow-hidden">
                        <div className="px-3 py-2 bg-[hsl(var(--warning))]/[0.03] border-b border-border flex justify-between">
                          <span className="text-[hsl(var(--warning))] font-semibold">{type}</span>
                          <span className="text-muted-foreground text-[9px]">{(recs as any[]).length}</span>
                        </div>
                        {(recs as any[]).map((r, i) => (
                          <div key={i} className="px-3 py-1.5 border-b border-border/30 hover:bg-[hsl(var(--warning))]/[0.02]">
                            <span className="text-foreground/80 break-all">{r.data}</span>
                            <span className="text-muted-foreground text-[9px] ml-2">TTL:{r.ttl}</span>
                          </div>
                        ))}
                      </div>
                    ))}
                  </div>
                );
              }

              // HEADERS
              if (activeTab === 'headers' && (data.found || data.error)) {
                if (data.error) return <div className="text-destructive">{data.error}</div>;
                return (
                  <div>
                    {data.waf && data.waf !== 'Unknown' && (
                      <div className="mb-4 p-3 rounded-lg border border-destructive/30 bg-destructive/5 flex items-center gap-2">
                        <Shield size={14} className="text-destructive" /> <span className="text-destructive font-semibold">WAF Detected: {data.waf}</span>
                      </div>
                    )}
                    <div className="mb-4"><h3 className="text-[hsl(142,71%,45%)] text-sm font-semibold mb-2">✓ Present Headers</h3>
                      {Object.entries(data.found).map(([h, v]) => (
                        <div key={h} className="flex gap-2 py-1 border-b border-border/30">
                          <span className="text-[hsl(142,71%,45%)] shrink-0 w-56">{h}</span>
                          <span className="text-foreground/70 break-all">{String(v)}</span>
                        </div>
                      ))}
                    </div>
                    {data.missing?.length > 0 && (
                      <div><h3 className="text-destructive text-sm font-semibold mb-2">✗ Missing Headers</h3>
                        {data.missing.map((h: string) => <div key={h} className="py-1 text-destructive/80">✗ {h}</div>)}
                      </div>
                    )}
                  </div>
                );
              }

              // TECH
              if (activeTab === 'tech' && data.technologies) {
                return (
                  <div className="flex flex-wrap gap-2">
                    {data.technologies.map((t: string, i: number) => (
                      <span key={i} className="px-3 py-1.5 bg-[hsl(var(--warning))]/10 border border-[hsl(var(--warning))]/20 rounded-md text-[hsl(var(--warning))] text-sm">{t}</span>
                    ))}
                    {data.technologies.length === 0 && <span className="text-muted-foreground">No technologies detected.</span>}
                  </div>
                );
              }

              // WHOIS
              if (activeTab === 'whois' && (data.name || data.error)) {
                if (data.error) return <div className="text-destructive">{data.error}</div>;
                return (
                  <div className="space-y-2">
                    <Row label="Domain" value={data.name} />
                    <Row label="Status" value={data.status?.join(', ')} />
                    {data.nameservers?.map((ns: string, i: number) => <Row key={i} label={`NS ${i + 1}`} value={ns} />)}
                    {data.events?.map((e: any, i: number) => <Row key={i} label={e.action} value={e.date} />)}
                  </div>
                );
              }

              // PORTS
              if (activeTab === 'ports' && (data.ports || data.error)) {
                if (data.error) return <div className="text-destructive">{data.error}</div>;
                return (
                  <div>
                    <Row label="IP" value={data.ip} />
                    <div className="mt-3"><span className="text-muted-foreground text-sm">Open Ports:</span>
                      <div className="flex flex-wrap gap-1.5 mt-2">
                        {(data.ports || []).map((p: number) => <span key={p} className="px-2 py-1 bg-[hsl(var(--warning))]/10 border border-[hsl(var(--warning))]/20 rounded text-[hsl(var(--warning))]">{p}</span>)}
                      </div>
                    </div>
                    {data.vulns?.length > 0 && (
                      <div className="mt-4"><span className="text-destructive text-sm font-semibold">CVEs ({data.vulns.length}):</span>
                        <div className="flex flex-wrap gap-1.5 mt-2">
                          {data.vulns.map((v: string) => <a key={v} href={`https://nvd.nist.gov/vuln/detail/${v}`} target="_blank" className="px-2 py-1 bg-destructive/10 border border-destructive/20 rounded text-destructive no-underline hover:bg-destructive/20">{v}</a>)}
                        </div>
                      </div>
                    )}
                  </div>
                );
              }

              // HTTP PROBE
              if (activeTab === 'probe' && data.probes) {
                return data.probes.map((p: any, i: number) => (
                  <div key={i} className="mb-3 p-3 bg-background border border-border rounded-lg">
                    <div className="flex items-center gap-2 mb-1">
                      <StatusBadge status={String(p.status)} />
                      <a href={p.url} target="_blank" className="text-[hsl(var(--warning))] no-underline hover:underline">{p.url}</a>
                    </div>
                    {p.title && <div className="text-foreground/70 text-sm ml-6">Title: {p.title}</div>}
                    {p.tech?.length > 0 && <div className="ml-6 flex gap-1 mt-1">{p.tech.map((t: string, j: number) => <span key={j} className="text-[9px] px-1.5 py-0.5 bg-muted rounded">{t}</span>)}</div>}
                    {p.redirected && <div className="text-muted-foreground ml-6">→ {p.final_url}</div>}
                    {p.error && <div className="text-destructive ml-6">{p.error}</div>}
                  </div>
                ));
              }

              return <pre className="text-foreground/70 whitespace-pre-wrap">{JSON.stringify(data, null, 2)}</pre>;
            })()}
          </div>
        </div>
      </div>

      <footer className="border-t border-border py-4 text-center font-mono text-[10px] text-muted-foreground">
        © 2025 TeamCyberOps — <a href="https://github.com/mohidqx" className="text-[hsl(var(--warning))] no-underline">github.com/mohidqx</a> — For authorized security testing only.
      </footer>
    </div>
  );
};

const Stat = ({ label, value, color }: { label: string; value: number; color: string }) => (
  <div className="bg-background border border-border rounded-lg px-4 py-2.5">
    <div className="font-mono text-[8px] text-muted-foreground tracking-widest mb-1">{label}</div>
    <div className="text-2xl font-bold font-mono" style={{ color }}>{value}</div>
  </div>
);

const Row = ({ label, value }: { label: string; value?: string }) => (
  <div className="flex gap-3 py-1.5 border-b border-border/30">
    <span className="text-muted-foreground w-40 shrink-0">{label}</span>
    <span className="text-foreground/80 break-all">{value || '—'}</span>
  </div>
);

const StatusBadge = ({ status }: { status: string }) => {
  const code = parseInt(status);
  const cls = code >= 200 && code < 300 ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
    : code >= 300 && code < 400 ? 'bg-amber-400/10 text-amber-400 border-amber-400/20'
    : code >= 400 ? 'bg-red-400/10 text-red-400 border-red-400/20'
    : 'bg-muted text-muted-foreground border-border';
  return <span className={`px-1.5 py-0.5 rounded text-[9px] border font-mono ${cls}`}>{status}</span>;
};

export default Index;
