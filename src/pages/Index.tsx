import { useState, useCallback, useRef, useEffect } from 'react';
import { Search, Download, FileJson, FileText, Printer, Loader2, CheckCircle, AlertCircle, Globe, Radar, Activity, Cpu, Shield, Server, Link, Key, Bug, Eye, Terminal, ChevronDown, Copy, ExternalLink, Zap, Lock, Code, Database, Map, FileCode, AlertTriangle, Skull, Cookie, Layers, GitBranch, Crosshair, Wifi } from 'lucide-react';
import { supabase } from '@/integrations/supabase/client';
import { exportCSV, exportJSON, exportTXT, exportPDF } from '@/lib/exportUtils';
import {
  runFullScan, createScanState, ScanState, ModuleStatus,
  generateMarkdownReport, generateBurpXML, generateNucleiTargets,
} from '@/lib/reconEngine';

// ── All tabs from v14.6 ──
const ALL_TABS = [
  { id: 'sub', label: 'Subs', icon: Globe, cat: 'subdomains' },
  { id: 'dns', label: 'DNS', icon: Radar, cat: 'subdomains' },
  { id: 'ports', label: 'Ports', icon: Wifi, cat: 'subdomains' },
  { id: 'ep', label: 'Endpoints', icon: Link, cat: 'endpoints' },
  { id: 'js', label: 'JS', icon: FileCode, cat: 'js' },
  { id: 'params', label: 'Params', icon: Key, cat: 'endpoints' },
  { id: 'hdrs', label: 'Headers', icon: Shield, cat: 'intel' },
  { id: 'whois', label: 'WHOIS', icon: Server, cat: 'intel' },
  { id: 'probe', label: 'Probe', icon: Activity, cat: 'subdomains' },
  { id: 'secrets', label: 'Secrets', icon: Lock, cat: 'js' },
  { id: 'vuln', label: 'Vulns', icon: Bug, cat: 'vulns' },
  { id: 'cors', label: 'CORS', icon: Crosshair, cat: 'vulns' },
  { id: 'nuclei', label: 'Nuclei', icon: Skull, cat: 'vulns' },
  { id: 'content', label: 'Content', icon: Layers, cat: 'vulns' },
  { id: 'domxss', label: 'DOM XSS', icon: Code, cat: 'js' },
  { id: 'cookies', label: 'Cookies', icon: Cookie, cat: 'vulns' },
  { id: 'darkweb', label: 'Dark Web', icon: Eye, cat: 'intel' },
  { id: 'tech', label: 'Tech', icon: Cpu, cat: 'intel' },
  { id: 'history', label: 'History', icon: Database, cat: 'reports' },
] as const;

type TabId = typeof ALL_TABS[number]['id'];

const CATEGORIES = [
  { id: 'all', label: '☣ Full Scan', icon: '☣' },
  { id: 'subdomains', label: '⊕ Subdomains', icon: '⊕' },
  { id: 'endpoints', label: '⟁ Endpoints', icon: '⟁' },
  { id: 'js', label: '⚡ JS & Secrets', icon: '⚡' },
  { id: 'vulns', label: '☠ Vulnerabilities', icon: '☠' },
  { id: 'intel', label: '⊛ Intelligence', icon: '⊛' },
  { id: 'reports', label: '⊞ Reports', icon: '⊞' },
];

const SCAN_PROFILES = [
  { id: 'quick', label: 'Quick (2min)', cls: 'quick' },
  { id: 'deep', label: 'Deep (20min)', cls: 'deep' },
  { id: 'stealth', label: 'Stealth', cls: 'stealth' },
];

const SUB_SOURCES = [
  { id: 'crt', label: 'crt.sh' }, { id: 'ht', label: 'HackerTarget' },
  { id: 'jldc', label: 'AnubisDB' }, { id: 'rapiddns', label: 'RapidDNS' },
  { id: 'certspot', label: 'CertSpotter' }, { id: 'otxsub', label: 'OTX PassiveDNS' },
  { id: 'urlscan', label: 'URLScan.io' }, { id: 'threatminer', label: 'ThreatMiner' },
  { id: 'sonar', label: 'Sonar' }, { id: 'wbsubs', label: 'Wayback Subs' },
  { id: 'virus', label: 'VirusTotal' }, { id: 'brute', label: 'DNS Brute (500)' },
  { id: 'wb', label: 'Wayback CDX' }, { id: 'otxurl', label: 'OTX URLs' },
  { id: 'cc', label: 'CommonCrawl' }, { id: 'uscan', label: 'URLScan URLs' },
  { id: 'jsfind', label: 'JS Secrets' }, { id: 'cors', label: 'CORS Scan' },
  { id: 'content', label: 'Content Discovery' }, { id: 'nuclei', label: 'Nuclei Templates' },
  { id: 'geo', label: 'IP Geo' }, { id: 'sitemap', label: 'Sitemap' },
  { id: 'robotstxt', label: 'robots.txt' },
];

interface ScanHistory { id: string; domain: string; created_at: string; scan_type: string; }

const Index = () => {
  const [target, setTarget] = useState('');
  const [activeTab, setActiveTab] = useState<TabId>('sub');
  const [activeCat, setActiveCat] = useState('all');
  const [profile, setProfile] = useState('deep');
  const [scanState, setScanState] = useState<ScanState>(createScanState());
  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [progressLabel, setProgressLabel] = useState('');
  const [modules, setModules] = useState<Record<string, { status: ModuleStatus; detail?: string }>>({});
  const [sources, setSources] = useState<Record<string, boolean>>(() => {
    const s: Record<string, boolean> = {};
    SUB_SOURCES.forEach(src => s[src.id] = true);
    return s;
  });
  const [history, setHistory] = useState<ScanHistory[]>([]);
  const [showCachedPrompt, setShowCachedPrompt] = useState(false);
  const [cachedScanId, setCachedScanId] = useState<string | null>(null);
  const [filter, setFilter] = useState('');
  const scanRef = useRef(false);

  // Load scan history
  useEffect(() => {
    loadHistory();
  }, []);

  const loadHistory = async () => {
    const { data } = await supabase
      .from('scan_results')
      .select('id, domain, created_at, scan_type')
      .order('created_at', { ascending: false })
      .limit(50);
    if (data) setHistory(data);
  };

  const checkCachedScan = async (domain: string): Promise<boolean> => {
    const { data } = await supabase
      .from('scan_results')
      .select('id, created_at')
      .eq('domain', domain.toLowerCase().trim())
      .order('created_at', { ascending: false })
      .limit(1);
    if (data && data.length > 0) {
      setCachedScanId(data[0].id);
      setShowCachedPrompt(true);
      return true;
    }
    return false;
  };

  const loadCachedScan = async () => {
    if (!cachedScanId) return;
    const { data } = await supabase
      .from('scan_results')
      .select('scan_data')
      .eq('id', cachedScanId)
      .maybeSingle();
    if (data?.scan_data) {
      const restored = { ...createScanState(), ...data.scan_data } as ScanState;
      setScanState(restored);
    }
    setShowCachedPrompt(false);
  };

  const saveScanToDb = async (state: ScanState) => {
    await supabase.from('scan_results').insert({
      domain: state.domain.toLowerCase().trim(),
      scan_data: state as any,
      scan_type: profile,
    });
    loadHistory();
  };

  const startScan = async () => {
    const domain = target.trim().toLowerCase();
    if (!domain || scanning) return;

    const hasCached = await checkCachedScan(domain);
    if (hasCached) return; // prompt will show

    runNewScan(domain);
  };

  const runNewScan = async (domain?: string) => {
    const d = domain || target.trim().toLowerCase();
    if (!d) return;
    setShowCachedPrompt(false);
    setScanning(true);
    setProgress(0);
    setProgressLabel('Initializing…');
    setModules({});
    setScanState(createScanState());
    scanRef.current = true;

    try {
      const result = await runFullScan(
        d,
        sources,
        (name, status, detail) => {
          setModules(prev => ({ ...prev, [name]: { status, detail } }));
        },
        (pct, label) => {
          setProgress(pct);
          setProgressLabel(label);
        },
        (partial) => {
          setScanState(prev => ({ ...prev, ...partial }));
        },
      );
      await saveScanToDb(result);
    } catch (e: any) {
      console.error('Scan failed:', e);
    } finally {
      setScanning(false);
      scanRef.current = false;
    }
  };

  const handleExport = (format: string) => {
    const domain = scanState.domain || target || 'scan';
    if (format === 'json') exportJSON(scanState, `${domain}_report`);
    else if (format === 'csv') {
      const rows = scanState.subs.map(s => ({ subdomain: s.subdomain, ip: s.ip, status: s.status, source: s.source, alive: s.alive, ports: s.ports.join(';'), geo: s.geo }));
      exportCSV(rows.length ? rows : [{ info: 'No data' }], `${domain}_subdomains`);
    } else if (format === 'txt') {
      const md = generateMarkdownReport(scanState);
      exportTXT(md.split('\n'), `${domain}_report`);
    } else if (format === 'pdf') {
      const sections: { heading: string; content: string }[] = [];
      if (scanState.subs.length) sections.push({ heading: `Subdomains (${scanState.subs.length})`, content: scanState.subs.slice(0, 200).map(s => `${s.subdomain}  ${s.ip || '—'}  [${s.source}]`).join('\n') });
      if (Object.keys(scanState.dns).length) sections.push({ heading: 'DNS Records', content: Object.entries(scanState.dns).filter(([, r]) => r.length).map(([t, recs]) => `${t}:\n${recs.map(r => `  ${r.val}`).join('\n')}`).join('\n\n') });
      if (scanState.secrets.length) sections.push({ heading: `Secrets (${scanState.secrets.length})`, content: scanState.secrets.map(s => `[${s.sev}] ${s.type}: ${s.value.slice(0, 80)} — ${s.file}`).join('\n') });
      if (scanState.corsFindings.length) sections.push({ heading: `CORS Issues (${scanState.corsFindings.length})`, content: scanState.corsFindings.map(c => `${c.host}: ${c.type} [${c.sev}]`).join('\n') });
      if (scanState.darkWebFindings.length) sections.push({ heading: `Dark Web (${scanState.darkWebFindings.length})`, content: scanState.darkWebFindings.map(d => `[${d.severity}] ${d.source}: ${d.title}`).join('\n') });
      if (!sections.length) sections.push({ heading: 'No Data', content: 'Run a scan first.' });
      exportPDF(`Recon Report — ${domain}`, sections);
    } else if (format === 'burp') {
      const xml = generateBurpXML(scanState.eps);
      const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([xml], { type: 'text/xml' })); a.download = `${domain}_burp.xml`; a.click();
    } else if (format === 'nuclei') {
      const targets = generateNucleiTargets(scanState.subs);
      const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([targets], { type: 'text/plain' })); a.download = `${domain}_nuclei_targets.txt`; a.click();
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  const filteredTabs = activeCat === 'all' ? ALL_TABS : ALL_TABS.filter(t => t.cat === activeCat);

  const counts: Record<string, number> = {
    sub: scanState.subs.length,
    dns: Object.values(scanState.dns).flat().length,
    ports: Object.values(scanState.ips).reduce((a, v) => a + (v.ports?.length || 0), 0),
    ep: scanState.eps.length,
    js: scanState.js.length,
    params: Object.keys(scanState.params).length,
    probe: scanState.probes.length,
    secrets: scanState.secrets.length,
    vuln: scanState.vulns.length,
    cors: scanState.corsFindings.length,
    nuclei: scanState.nucleiFindings.length,
    content: scanState.contentFindings.length,
    domxss: scanState.domXss.length,
    cookies: scanState.cookieFindings.length,
    darkweb: scanState.darkWebFindings.length,
    tech: scanState.tech.length,
    history: history.length,
  };

  return (
    <div className="min-h-screen bg-background relative z-[2]">
      {/* NAV */}
      <nav className="sticky top-0 z-50 bg-background/92 backdrop-blur-[28px] border-b border-border relative">
        <div className="absolute bottom-0 left-0 right-0 h-px nav-glow-line" />
        <div className="max-w-[1300px] mx-auto px-6 flex items-center gap-3 h-[58px]">
          <a href="/" className="flex items-center gap-2.5 no-underline shrink-0" onClick={e => { e.preventDefault(); setScanState(createScanState()); setTarget(''); }}>
            <img src="https://github.com/mohidqx.png" alt="Logo" className="w-[34px] h-[34px] rounded-full border-2 border-primary/40 drop-shadow-[0_0_10px_hsla(350,85%,48%,0.5)]" />
            <span className="brand-gradient text-[17px] font-extrabold tracking-[0.06em] uppercase">TeamCyberOps</span>
            <span className="font-mono text-[8.5px] font-bold tracking-[0.1em] px-[7px] py-[2px] rounded-full bg-primary/10 border border-primary/25 text-primary uppercase">RECON v14.6</span>
          </a>
          <div className="flex-1" />
          <div className="flex items-center gap-2 shrink-0">
            {[
              { fmt: 'json', icon: FileJson, label: '{}' },
              { fmt: 'csv', icon: Download, label: 'CSV' },
              { fmt: 'txt', icon: FileText, label: 'TXT' },
              { fmt: 'pdf', icon: Printer, label: 'PDF' },
              { fmt: 'burp', icon: Terminal, label: 'Burp' },
              { fmt: 'nuclei', icon: Crosshair, label: 'Nuclei' },
            ].map(({ fmt, label }) => (
              <button key={fmt} onClick={() => handleExport(fmt)}
                className="px-2.5 py-1.5 border border-border rounded-lg text-[10px] font-semibold text-muted-foreground hover:text-foreground hover:border-primary/25 hover:bg-primary/5 transition-all cursor-pointer">
                {label}
              </button>
            ))}
            <a href="/oneliners" className="px-3 py-1.5 border border-purple-400/20 bg-purple-400/5 rounded-lg text-[10.5px] font-semibold text-purple-400 hover:bg-purple-400/10 transition-colors no-underline">
              ⚡ Oneliners
            </a>
          </div>
        </div>
      </nav>

      <div className="max-w-[1300px] mx-auto px-5 pb-20">
        {/* HERO */}
        <div className="text-center py-12 animate-fade-in-up">
          <div className="inline-flex items-center gap-2 bg-primary/7 border border-primary/25 rounded-full px-4 py-1.5 text-[11px] font-bold tracking-[0.12em] text-primary uppercase mb-5">
            <span className="w-1.5 h-1.5 bg-[hsl(var(--green))] rounded-full shadow-[0_0_8px_hsl(var(--green))] animate-pulse" />
            BugHunting OSINT Platform
          </div>
          <h1 className="hero-gradient text-[clamp(2.4rem,6vw,4.5rem)] font-bold leading-[1.05] tracking-[-0.04em] mb-3">
            ☣︎ Recon 🗡<br />Engine v14.6
          </h1>
          <p className="text-muted-foreground max-w-[540px] mx-auto leading-[1.7] mb-5">
            500+ OSINT sources · DNS multi-resolver · Port intel · JS secrets · DOM XSS · CORS · Nuclei · Cookie analysis · Dark Web OSINT
          </p>
        </div>

        {/* SEARCH CARD */}
        <div className="bg-card/50 border border-primary/8 rounded-[18px] p-[22px_26px_18px] backdrop-blur-[20px] mb-5 transition-all focus-within:border-primary/30 focus-within:shadow-[var(--glow)] animate-fade-in-up" style={{ animationDelay: '0.2s' }}>
          <div className="flex gap-2.5 flex-wrap mb-3.5">
            <div className="flex-1 min-w-[200px] relative">
              <Search size={15} className="absolute left-[14px] top-1/2 -translate-y-1/2 text-muted-foreground pointer-events-none" />
              <input
                type="text" value={target} onChange={e => setTarget(e.target.value)}
                placeholder="Enter target domain — e.g. tesla.com"
                onKeyDown={e => e.key === 'Enter' && startScan()}
                className="w-full bg-white/[0.04] border border-primary/10 rounded-[11px] py-[13px] pl-[42px] pr-4 text-foreground font-mono text-[13.5px] outline-none transition-all placeholder:text-muted-foreground focus:border-primary/40 focus:bg-primary/[0.04] focus:shadow-[0_0_0_3px_hsla(350,85%,48%,0.1)]"
              />
            </div>
            <button onClick={startScan} disabled={!target.trim() || scanning}
              className="scan-btn-gradient border-none rounded-[11px] px-6 py-[13px] text-white font-bold text-[13px] tracking-[0.03em] cursor-pointer transition-all flex items-center gap-2 disabled:opacity-45 disabled:cursor-not-allowed disabled:transform-none active:translate-y-0">
              {scanning ? <Loader2 size={14} className="animate-spin" /> : <Search size={14} />}
              {scanning ? 'Scanning…' : 'Full Scan'}
            </button>
          </div>

          {/* Scan Profiles */}
          <div className="flex gap-1.5 flex-wrap mb-3">
            <span className="text-[9px] font-bold tracking-[0.1em] uppercase text-muted-foreground self-center mr-1">Profile:</span>
            {SCAN_PROFILES.map(p => (
              <button key={p.id} onClick={() => setProfile(p.id)}
                className={`px-3.5 py-[5px] rounded-full text-[10.5px] font-bold tracking-[0.06em] border cursor-pointer transition-all
                  ${profile === p.id
                    ? p.cls === 'quick' ? 'bg-[hsl(var(--green))]/10 border-[hsl(var(--green))]/35 text-[hsl(var(--green))]'
                      : p.cls === 'stealth' ? 'bg-[hsl(var(--purple))]/10 border-[hsl(var(--purple))]/35 text-[hsl(var(--purple))]'
                      : 'bg-primary/12 border-primary/35 text-primary'
                    : 'border-border bg-white/[0.03] text-muted-foreground hover:border-primary/25 hover:text-foreground'
                  }`}>
                {p.label}
              </button>
            ))}
          </div>

          {/* Source Toggles */}
          <div className="flex items-center justify-between mb-2">
            <span className="text-[9.5px] font-bold tracking-[0.1em] uppercase text-muted-foreground">⟐ Data Sources — click to toggle</span>
            <div className="flex gap-1.5">
              <button onClick={() => setSources(prev => { const n: Record<string, boolean> = {}; Object.keys(prev).forEach(k => n[k] = true); return n; })} className="text-[9.5px] text-muted-foreground bg-white/[0.03] border border-border rounded-[5px] px-2 py-0.5 cursor-pointer hover:text-primary hover:border-primary/25 transition-all">All</button>
              <button onClick={() => setSources(prev => { const n: Record<string, boolean> = {}; Object.keys(prev).forEach(k => n[k] = false); return n; })} className="text-[9.5px] text-muted-foreground bg-white/[0.03] border border-border rounded-[5px] px-2 py-0.5 cursor-pointer hover:text-primary hover:border-primary/25 transition-all">None</button>
            </div>
          </div>
          <div className="flex gap-1.5 flex-wrap">
            {SUB_SOURCES.map(s => (
              <label key={s.id} onClick={() => setSources(prev => ({ ...prev, [s.id]: !prev[s.id] }))}
                className={`flex items-center gap-[5px] px-2.5 py-1 rounded-full text-[10.5px] font-semibold cursor-pointer transition-all select-none border
                  ${sources[s.id] ? 'bg-primary/8 border-primary/30 text-primary' : 'opacity-[0.38] bg-transparent border-white/[0.04] text-muted-foreground'}`}>
                <span className={`w-[5px] h-[5px] rounded-full transition-all shrink-0 ${sources[s.id] ? 'bg-[hsl(var(--green))] shadow-[0_0_5px_hsl(var(--green))]' : 'bg-destructive'}`} />
                {s.label}
              </label>
            ))}
          </div>
        </div>

        {/* Cached Scan Prompt */}
        {showCachedPrompt && (
          <div className="mb-4 p-4 rounded-xl border border-primary/30 bg-primary/5 flex items-center justify-between animate-fade-in-up">
            <div>
              <span className="text-primary font-semibold text-sm">⚠ Previous scan found for "{target}"</span>
              <p className="text-muted-foreground text-xs mt-1">Load saved results or run a fresh scan?</p>
            </div>
            <div className="flex gap-2">
              <button onClick={loadCachedScan} className="px-4 py-2 rounded-lg bg-primary/10 border border-primary/30 text-primary text-xs font-bold cursor-pointer hover:bg-primary/20 transition-all">Load Saved</button>
              <button onClick={() => { setShowCachedPrompt(false); runNewScan(); }} className="px-4 py-2 rounded-lg bg-white/[0.04] border border-border text-foreground text-xs font-bold cursor-pointer hover:bg-white/[0.08] transition-all">New Scan</button>
            </div>
          </div>
        )}

        {/* Category Selector */}
        <div className="flex flex-wrap justify-center gap-2 mb-5 animate-fade-in-up" style={{ animationDelay: '0.25s' }}>
          {CATEGORIES.map(c => (
            <button key={c.id} onClick={() => { setActiveCat(c.id); if (c.id !== 'all') { const t = ALL_TABS.find(tab => tab.cat === c.id); if (t) setActiveTab(t.id); } }}
              className={`px-3.5 py-2 rounded-[10px] text-[11.5px] font-semibold border cursor-pointer transition-all
                ${activeCat === c.id ? 'pill-active' : 'border-border bg-white/[0.03] text-muted-foreground hover:border-primary/25 hover:bg-primary/5'}`}>
              {c.label}
            </button>
          ))}
        </div>

        {/* Progress Bar */}
        {scanning && (
          <div className="bg-card/60 border border-primary/12 rounded-[13px] p-4 mb-4 animate-fade-in-up">
            <div className="flex justify-between items-center mb-2.5">
              <div className="text-[12.5px] font-semibold text-primary flex items-center gap-2">
                <Loader2 size={14} className="animate-spin" />
                {progressLabel}
              </div>
              <span className="text-[11.5px] text-muted-foreground font-mono">{progress}%</span>
            </div>
            <div className="h-[3px] bg-white/[0.06] rounded-[3px] overflow-hidden">
              <div className="h-full progress-fill rounded-[3px] transition-[width] duration-400" style={{ width: `${progress}%` }} />
            </div>
            {/* Module Status */}
            {Object.keys(modules).length > 0 && (
              <div className="mt-3 flex flex-wrap gap-1.5">
                {Object.entries(modules).map(([name, { status }]) => (
                  <span key={name} className={`text-[9px] font-mono px-2 py-0.5 rounded-full border ${
                    status === 'done' ? 'border-[hsl(var(--green))]/30 text-[hsl(var(--green))] bg-[hsl(var(--green))]/5'
                    : status === 'running' ? 'border-primary/30 text-primary bg-primary/5 animate-pulse'
                    : status === 'error' ? 'border-destructive/30 text-destructive bg-destructive/5'
                    : status === 'skip' ? 'border-border text-muted-foreground'
                    : 'border-border text-muted-foreground'
                  }`}>{name}</span>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Stats Row */}
        <div className="grid grid-cols-[repeat(auto-fit,minmax(120px,1fr))] gap-2.5 mb-5 animate-fade-in-up" style={{ animationDelay: '0.3s' }}>
          {[
            { label: 'Subdomains', val: scanState.subs.length, color: 'hsl(var(--crimson))' },
            { label: 'Live Hosts', val: scanState.subs.filter(s => s.alive).length, color: 'hsl(var(--green))' },
            { label: 'Unique IPs', val: Object.keys(scanState.ips).length, color: 'hsl(210,100%,70%)' },
            { label: 'Open Ports', val: Object.values(scanState.ips).reduce((a, v) => a + (v.ports?.length || 0), 0), color: 'hsl(var(--purple))' },
            { label: 'Endpoints', val: scanState.eps.length, color: 'hsl(var(--teal))' },
            { label: 'JS Files', val: scanState.js.length, color: 'hsl(var(--amber))' },
            { label: 'Params', val: Object.keys(scanState.params).length, color: 'hsl(var(--pink))' },
            { label: 'Secrets', val: scanState.secrets.length, color: 'hsl(0, 72%, 60%)' },
            { label: 'CORS Issues', val: scanState.corsFindings.length, color: 'hsl(0, 72%, 60%)' },
            { label: 'Nuclei Hits', val: scanState.nucleiFindings.length, color: 'hsl(0, 72%, 60%)' },
            { label: 'Dark Web', val: scanState.darkWebFindings.length, color: 'hsl(var(--amber))' },
            { label: 'Vulns', val: scanState.vulns.length, color: 'hsl(0, 72%, 60%)' },
          ].map(s => (
            <div key={s.label} className="bg-white/[0.028] border border-border rounded-[13px] px-4 py-3.5 transition-all hover:border-primary/20 hover:-translate-y-0.5 hover:shadow-[0_6px_20px_rgba(0,0,0,0.4)] relative overflow-hidden stat-glow">
              <div className="text-[9.5px] font-bold tracking-[0.1em] text-muted-foreground uppercase mb-1">{s.label}</div>
              <div className="text-[1.8rem] font-bold font-mono leading-none" style={{ color: s.color }}>{s.val}</div>
            </div>
          ))}
        </div>

        {/* Tab Pills */}
        <div className="flex flex-wrap justify-center gap-2 mb-5">
          {filteredTabs.map(t => {
            const Icon = t.icon;
            const count = counts[t.id] || 0;
            return (
              <button key={t.id} onClick={() => setActiveTab(t.id)}
                className={`flex items-center gap-1.5 px-3 py-2 rounded-lg border text-[11.5px] font-semibold cursor-pointer transition-all whitespace-nowrap
                  ${activeTab === t.id ? 'pill-active' : 'border-border bg-white/[0.03] text-muted-foreground hover:text-foreground hover:border-primary/25'}`}>
                <Icon size={12} />
                {t.label}
                {count > 0 && <span className="bg-primary/15 text-primary rounded-[5px] px-[5px] py-[1px] text-[9px] font-mono ml-0.5">{count}</span>}
              </button>
            );
          })}
        </div>

        {/* CONTENT PANELS */}
        <div className="bg-card/70 border border-primary/8 rounded-[16px] overflow-hidden backdrop-blur-[20px]">
          <div className="px-4 py-2.5 border-b border-border bg-white/[0.02] flex items-center justify-between">
            <span className="font-mono text-[10px] text-muted-foreground tracking-[0.12em] uppercase">{ALL_TABS.find(t => t.id === activeTab)?.label || activeTab}</span>
            <div className="flex items-center gap-2">
              {filter !== undefined && ['sub', 'ep', 'js', 'probe'].includes(activeTab) && (
                <input value={filter} onChange={e => setFilter(e.target.value)} placeholder="Filter…"
                  className="bg-white/[0.04] border border-border rounded-lg px-2.5 py-1 text-foreground font-mono text-[11px] outline-none focus:border-primary/30 w-40" />
              )}
            </div>
          </div>

          <div className="p-4 min-h-[400px] max-h-[70vh] overflow-y-auto scrollbar-thin font-mono text-xs">
            {/* SUBDOMAINS */}
            {activeTab === 'sub' && (
              scanState.subs.length === 0 ? <Empty /> : (
                <div>
                  <table className="w-full text-xs"><thead><tr className="text-muted-foreground text-left border-b border-border">
                    <th className="pb-2 font-bold text-[9.5px] tracking-[0.12em] uppercase">#</th>
                    <th className="pb-2 font-bold text-[9.5px] tracking-[0.12em] uppercase">SUBDOMAIN</th>
                    <th className="pb-2 font-bold text-[9.5px] tracking-[0.12em] uppercase">IP</th>
                    <th className="pb-2 font-bold text-[9.5px] tracking-[0.12em] uppercase">HTTP</th>
                    <th className="pb-2 font-bold text-[9.5px] tracking-[0.12em] uppercase">PORTS</th>
                    <th className="pb-2 font-bold text-[9.5px] tracking-[0.12em] uppercase">GEO</th>
                    <th className="pb-2 font-bold text-[9.5px] tracking-[0.12em] uppercase">SOURCE</th>
                  </tr></thead>
                  <tbody>{scanState.subs.filter(s => !filter || s.subdomain.includes(filter) || s.ip.includes(filter)).slice(0, 500).map((s, i) => (
                    <tr key={i} className="border-t border-white/[0.035] hover:bg-primary/[0.025] transition-colors">
                      <td className="py-2 text-muted-foreground">{i + 1}</td>
                      <td className="py-2"><a href={`https://${s.subdomain}`} target="_blank" rel="noreferrer" className="text-primary no-underline hover:underline">{s.subdomain}</a></td>
                      <td className="py-2">{s.ip ? <span className="bg-white/5 border border-white/10 rounded-md px-2 py-0.5 text-[11px]">{s.ip}</span> : <span className="text-muted-foreground">—</span>}</td>
                      <td className="py-2"><StatusBadge status={s.httpStatus} /></td>
                      <td className="py-2 text-muted-foreground">{s.ports.length ? s.ports.join(', ') : '—'}</td>
                      <td className="py-2 text-muted-foreground text-[10px]">{s.geo || '—'}</td>
                      <td className="py-2 text-muted-foreground">{s.source}</td>
                    </tr>
                  ))}</tbody></table>
                  {scanState.subs.length > 500 && <div className="text-center py-3 text-muted-foreground text-[11px]">Showing 500 of {scanState.subs.length} — Export for full list</div>}
                </div>
              )
            )}

            {/* DNS */}
            {activeTab === 'dns' && (
              Object.values(scanState.dns).flat().length === 0 ? <Empty /> : (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                  {Object.entries(scanState.dns).filter(([, recs]) => recs.length > 0).map(([type, recs]) => (
                    <div key={type} className="bg-white/[0.028] border border-border rounded-[14px] overflow-hidden">
                      <div className="flex items-center justify-between px-3.5 py-2.5 bg-white/[0.02] border-b border-border">
                        <span className="text-[10px] font-bold tracking-[0.12em] text-[hsl(var(--purple))] uppercase">{type}</span>
                        <span className="text-[10px] font-mono text-muted-foreground">{recs.length}</span>
                      </div>
                      {recs.map((r, i) => (
                        <div key={i} className="flex justify-between items-center px-3.5 py-[7px] border-b border-white/[0.03] last:border-none font-mono text-[11px]">
                          <span className="text-secondary-foreground break-all">{r.val}</span>
                          <span className="text-[9.5px] text-muted-foreground shrink-0 ml-2">TTL:{r.ttl}</span>
                        </div>
                      ))}
                    </div>
                  ))}
                </div>
              )
            )}

            {/* PORTS */}
            {activeTab === 'ports' && (
              Object.keys(scanState.ips).length === 0 ? <Empty /> : (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                  {Object.entries(scanState.ips).filter(([, v]) => v.ports?.length > 0).map(([ip, data]) => (
                    <div key={ip} className="bg-white/[0.028] border border-border rounded-[14px] overflow-hidden">
                      <div className="flex items-center justify-between px-3.5 py-2.5 bg-white/[0.02] border-b border-border">
                        <span className="font-mono text-[13px] text-primary font-semibold">{ip}</span>
                      </div>
                      <div className="px-3.5 py-2.5 flex flex-wrap gap-[5px]">
                        {data.ports.map((p: number) => (
                          <span key={p} className="px-2 py-0.5 bg-primary/10 border border-primary/20 rounded text-primary text-[10px] font-mono">{p}</span>
                        ))}
                      </div>
                      {data.cves?.length > 0 && (
                        <div className="px-3.5 py-2 flex flex-wrap gap-1">
                          {data.cves.slice(0, 10).map((c: string) => (
                            <a key={c} href={`https://nvd.nist.gov/vuln/detail/${c}`} target="_blank" rel="noreferrer" className="text-[9px] px-1.5 py-0.5 bg-destructive/10 border border-destructive/20 rounded text-destructive no-underline hover:bg-destructive/20">{c}</a>
                          ))}
                        </div>
                      )}
                      {data.geo && <div className="px-3.5 py-1.5 text-[9.5px] text-muted-foreground font-mono">{data.geo.city}, {data.geo.country_code} · {data.geo.org}</div>}
                    </div>
                  ))}
                </div>
              )
            )}

            {/* ENDPOINTS */}
            {activeTab === 'ep' && (
              scanState.eps.length === 0 ? <Empty /> : (
                <div>
                  {scanState.eps.filter(e => !filter || e.url.includes(filter)).slice(0, 300).map((ep, i) => (
                    <div key={i} className="flex items-center gap-2 py-[7px] border-b border-white/[0.03] hover:bg-primary/[0.02]">
                      <span className="text-muted-foreground w-8 text-right shrink-0">{i + 1}</span>
                      <a href={ep.url} target="_blank" rel="noreferrer" className="text-secondary-foreground no-underline hover:text-primary truncate text-[11px]">{ep.url}</a>
                      <span className="ml-auto text-muted-foreground text-[9px] shrink-0">{ep.source}</span>
                    </div>
                  ))}
                </div>
              )
            )}

            {/* JS Files */}
            {activeTab === 'js' && (
              scanState.js.length === 0 ? <Empty /> : (
                <div>
                  {scanState.js.filter(j => !filter || j.url.includes(filter)).slice(0, 200).map((j, i) => (
                    <div key={i} className="flex items-center gap-2 py-[7px] border-b border-white/[0.03] hover:bg-primary/[0.02]">
                      <span className="text-muted-foreground w-8 text-right shrink-0">{i + 1}</span>
                      <a href={j.url} target="_blank" rel="noreferrer" className="text-[hsl(var(--amber))] no-underline hover:underline truncate text-[11px]">{j.url}</a>
                      <span className="ml-auto text-muted-foreground text-[9px] shrink-0">{j.source}</span>
                    </div>
                  ))}
                </div>
              )
            )}

            {/* PARAMS */}
            {activeTab === 'params' && (
              Object.keys(scanState.params).length === 0 ? <Empty /> : (
                <div className="flex flex-wrap gap-1.5">
                  {Object.entries(scanState.params).sort((a, b) => b[1] - a[1]).map(([param, count]) => {
                    const isHigh = /pass|token|secret|key|auth|session|api/i.test(param);
                    const isMed = /url|redirect|path|file|page|callback|next|return|goto/i.test(param);
                    return (
                      <span key={param} onClick={() => copyToClipboard(param)}
                        className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-lg font-mono text-[11px] cursor-pointer transition-all border
                          ${isHigh ? 'bg-destructive/7 border-destructive/20 text-destructive hover:bg-destructive/15'
                            : isMed ? 'bg-[hsl(var(--amber))]/7 border-[hsl(var(--amber))]/20 text-[hsl(var(--amber))] hover:bg-[hsl(var(--amber))]/15'
                            : 'bg-white/[0.04] border-white/[0.08] text-secondary-foreground hover:bg-primary/8 hover:border-primary/22 hover:text-primary'}`}>
                        {param}
                        <span className="text-[9px] text-muted-foreground ml-0.5">{count}</span>
                      </span>
                    );
                  })}
                </div>
              )
            )}

            {/* HEADERS */}
            {activeTab === 'hdrs' && (
              scanState.hdrs.length === 0 ? <Empty /> : (
                <div>
                  {scanState.waf && scanState.waf !== 'unknown' && (
                    <div className="mb-4 p-3 rounded-lg border border-destructive/30 bg-destructive/5 flex items-center gap-2">
                      <Shield size={14} className="text-destructive" /> <span className="text-destructive font-semibold">WAF Detected: {scanState.waf}</span>
                    </div>
                  )}
                  <div className="bg-white/[0.028] border border-border rounded-[14px] overflow-hidden">
                    {scanState.hdrs.map((h, i) => (
                      <div key={i} className="grid grid-cols-[1fr_2fr] gap-2 px-3.5 py-2 border-b border-white/[0.035] last:border-none">
                        <span className="text-[10.5px] font-mono text-muted-foreground">{h.key}</span>
                        <span className="text-[11px] font-mono text-secondary-foreground break-all">{h.value}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )
            )}

            {/* WHOIS */}
            {activeTab === 'whois' && (
              !scanState.whois || Object.keys(scanState.whois).length === 0 ? <Empty /> : (
                <div className="bg-white/[0.028] border border-border rounded-[14px] overflow-hidden">
                  {Object.entries(scanState.whois).map(([k, v]) => (
                    <div key={k} className="grid grid-cols-[1fr_2fr] gap-2 px-3.5 py-2 border-b border-white/[0.035] last:border-none">
                      <span className="text-[10.5px] font-mono text-muted-foreground capitalize">{k}</span>
                      <span className="text-[11px] font-mono text-secondary-foreground break-all">{typeof v === 'object' ? JSON.stringify(v) : String(v)}</span>
                    </div>
                  ))}
                </div>
              )
            )}

            {/* PROBE */}
            {activeTab === 'probe' && (
              scanState.probes.length === 0 ? <Empty /> : (
                <div>
                  {scanState.probes.filter(p => !filter || p.host.includes(filter) || p.url.includes(filter)).map((p, i) => (
                    <div key={i} className="mb-2.5 p-3 bg-white/[0.02] border border-border rounded-lg">
                      <div className="flex items-center gap-2 mb-1">
                        <StatusBadge status={p.status} />
                        <a href={p.url} target="_blank" rel="noreferrer" className="text-primary no-underline hover:underline text-[11px]">{p.url}</a>
                        {p.alive && <span className="text-[8px] px-1.5 py-0.5 rounded-full bg-[hsl(var(--green))]/10 border border-[hsl(var(--green))]/20 text-[hsl(var(--green))]">LIVE</span>}
                      </div>
                      {p.title && <div className="text-foreground/70 text-[11px] ml-6">Title: {p.title}</div>}
                      {p.tech?.length > 0 && <div className="ml-6 flex gap-1 mt-1 flex-wrap">{p.tech.map((t, j) => <span key={j} className="text-[9px] px-1.5 py-0.5 bg-muted rounded">{t}</span>)}</div>}
                      {p.redirected && <div className="text-muted-foreground ml-6 text-[10px]">→ {p.final_url}</div>}
                      {p.error && <div className="text-destructive ml-6 text-[10px]">{p.error}</div>}
                    </div>
                  ))}
                </div>
              )
            )}

            {/* SECRETS */}
            {activeTab === 'secrets' && (
              scanState.secrets.length === 0 ? <Empty msg="No secrets detected yet." /> : (
                <div>
                  {scanState.secrets.map((s, i) => (
                    <div key={i} className="mb-2 p-3 rounded-lg border bg-white/[0.02] border-destructive/20">
                      <div className="flex items-center gap-2 mb-1">
                        <SevBadge sev={s.sev} />
                        <span className="text-primary font-semibold text-[11px]">{s.type}</span>
                      </div>
                      <div className="text-secondary-foreground text-[10px] font-mono break-all ml-6">{s.value.slice(0, 120)}</div>
                      <div className="text-muted-foreground text-[9px] ml-6 mt-1">File: {s.file} · Line: {s.line}</div>
                    </div>
                  ))}
                </div>
              )
            )}

            {/* VULNS */}
            {activeTab === 'vuln' && (
              scanState.vulns.length === 0 ? <Empty msg="No vulnerabilities detected." /> : (
                <div>{scanState.vulns.map((v, i) => (
                  <div key={i} className="mb-2 p-3 rounded-lg border bg-white/[0.02] border-destructive/20">
                    <div className="flex items-center gap-2 mb-1"><SevBadge sev={v.sev} /><span className="font-semibold text-[11px]">{v.type}</span></div>
                    <div className="text-secondary-foreground text-[10px] font-mono break-all ml-6">{v.url}</div>
                    <div className="text-muted-foreground text-[9px] ml-6">{v.desc}</div>
                  </div>
                ))}</div>
              )
            )}

            {/* CORS */}
            {activeTab === 'cors' && (
              scanState.corsFindings.length === 0 ? <Empty msg="No CORS misconfigs found." /> : (
                <div>{scanState.corsFindings.map((c, i) => (
                  <div key={i} className="mb-2 p-3 rounded-lg border bg-white/[0.02] border-destructive/20">
                    <div className="flex items-center gap-2 mb-1"><SevBadge sev={c.sev} /><span className="font-semibold text-[11px]">{c.host}</span><span className="text-muted-foreground text-[9px]">{c.type}</span></div>
                    <div className="text-[10px] font-mono ml-6">ACAO: {c.acao} | ACAC: {c.acac}</div>
                    <div className="text-muted-foreground text-[9px] ml-6">Origin tested: {c.origin}</div>
                  </div>
                ))}</div>
              )
            )}

            {/* NUCLEI */}
            {activeTab === 'nuclei' && (
              scanState.nucleiFindings.length === 0 ? <Empty msg="No nuclei matches." /> : (
                <div>{scanState.nucleiFindings.map((n, i) => (
                  <div key={i} className="mb-2 p-3 rounded-lg border bg-white/[0.02] border-destructive/20">
                    <div className="flex items-center gap-2 mb-1"><SevBadge sev={n.sev} /><span className="font-semibold text-[11px]">{n.template}</span>{n.cve && <span className="text-destructive text-[9px]">{n.cve}</span>}</div>
                    <a href={n.url} target="_blank" rel="noreferrer" className="text-[10px] font-mono ml-6 text-primary no-underline hover:underline">{n.url}</a>
                  </div>
                ))}</div>
              )
            )}

            {/* CONTENT */}
            {activeTab === 'content' && (
              scanState.contentFindings.length === 0 ? <Empty msg="No content discovered." /> : (
                <div>{scanState.contentFindings.map((c, i) => (
                  <div key={i} className="flex items-center gap-2 py-[7px] border-b border-white/[0.03] hover:bg-primary/[0.02]">
                    <SevBadge sev={c.sev} />
                    <StatusBadge status={c.status} />
                    <a href={c.url} target="_blank" rel="noreferrer" className="text-secondary-foreground no-underline hover:text-primary truncate text-[11px]">{c.path}</a>
                    <span className="ml-auto text-muted-foreground text-[9px]">{c.size}B</span>
                  </div>
                ))}</div>
              )
            )}

            {/* DOM XSS */}
            {activeTab === 'domxss' && (
              scanState.domXss.length === 0 ? <Empty msg="No DOM XSS sinks found." /> : (
                <div>{scanState.domXss.map((d, i) => (
                  <div key={i} className="mb-2 p-3 rounded-lg border bg-destructive/5 border-destructive/20">
                    <div className="flex items-center gap-2 mb-1"><SevBadge sev={d.sev} /><span className="font-mono text-[11px] text-primary">{d.sink}</span><span className="text-[9px] text-muted-foreground">×{d.count}</span></div>
                    <div className="text-muted-foreground text-[9px] ml-6">{d.file}</div>
                  </div>
                ))}</div>
              )
            )}

            {/* COOKIES */}
            {activeTab === 'cookies' && (
              scanState.cookieFindings.length === 0 ? <Empty msg="No cookie issues found." /> : (
                <div>{scanState.cookieFindings.map((c, i) => (
                  <div key={i} className="mb-2 p-3 rounded-lg border bg-white/[0.02] border-border">
                    <div className="flex items-center gap-2 mb-1"><Cookie size={12} className="text-[hsl(var(--amber))]" /><span className="font-semibold text-[11px]">{c.host}</span><span className="font-mono text-primary text-[10px]">{c.name}</span></div>
                    {c.issues.map((iss, j) => (
                      <div key={j} className="flex items-center gap-2 ml-6 text-[10px]"><SevBadge sev={iss.sev} /><span className="text-foreground/80">{iss.issue}</span><span className="text-muted-foreground">— {iss.desc}</span></div>
                    ))}
                  </div>
                ))}</div>
              )
            )}

            {/* DARK WEB */}
            {activeTab === 'darkweb' && (
              scanState.darkWebFindings.length === 0 ? <Empty msg="No dark web intel found." /> : (
                <div>{scanState.darkWebFindings.map((d, i) => (
                  <div key={i} className="mb-2 p-3 rounded-lg border bg-white/[0.02] border-border">
                    <div className="flex items-center gap-2 mb-1"><SevBadge sev={d.severity} /><span className="font-semibold text-[11px]">{d.source}</span></div>
                    <div className="text-foreground/80 text-[11px] ml-6">{d.title}</div>
                    <div className="text-muted-foreground text-[9px] ml-6">{d.detail}</div>
                    {d.url && <a href={d.url} target="_blank" rel="noreferrer" className="text-primary text-[9px] ml-6 no-underline hover:underline">{d.url}</a>}
                  </div>
                ))}</div>
              )
            )}

            {/* TECH */}
            {activeTab === 'tech' && (
              scanState.tech.length === 0 ? <Empty msg="No technologies detected." /> : (
                <div className="flex flex-wrap gap-2">
                  {scanState.tech.map((t, i) => (
                    <span key={i} className="px-3 py-1.5 bg-primary/10 border border-primary/20 rounded-lg text-primary text-sm font-medium">{t}</span>
                  ))}
                </div>
              )
            )}

            {/* HISTORY */}
            {activeTab === 'history' && (
              history.length === 0 ? <Empty msg="No scan history yet." /> : (
                <div>
                  {history.map(h => (
                    <div key={h.id} className="flex items-center gap-3 py-2.5 px-3 border-b border-white/[0.03] hover:bg-primary/[0.02] cursor-pointer transition-colors"
                      onClick={async () => {
                        const { data } = await supabase.from('scan_results').select('scan_data, domain').eq('id', h.id).maybeSingle();
                        if (data?.scan_data) {
                          const restored = { ...createScanState(), ...data.scan_data } as ScanState;
                          setScanState(restored);
                          setTarget(data.domain);
                          setActiveTab('sub');
                        }
                      }}>
                      <Globe size={14} className="text-primary shrink-0" />
                      <span className="text-primary font-semibold text-[12px]">{h.domain}</span>
                      <span className="text-muted-foreground text-[9px] font-mono">{h.scan_type}</span>
                      <span className="ml-auto text-muted-foreground text-[9px] font-mono">{new Date(h.created_at).toLocaleString()}</span>
                    </div>
                  ))}
                </div>
              )
            )}
          </div>
        </div>
      </div>

      {/* FOOTER */}
      <footer className="border-t border-primary/7 py-5">
        <div className="max-w-[1300px] mx-auto px-6 flex items-center justify-between flex-wrap gap-3">
          <div className="flex items-center gap-2.5">
            <img src="https://github.com/mohidqx.png" alt="Logo" className="w-7 h-7 rounded-full opacity-80" />
            <span className="text-[12px] font-semibold text-secondary-foreground">TeamCyberOps</span>
          </div>
          <div className="flex gap-4">
            <a href="https://github.com/mohidqx" target="_blank" rel="noreferrer" className="text-[12px] text-muted-foreground no-underline hover:text-primary transition-colors">GitHub</a>
          </div>
          <span className="text-[10.5px] text-muted-foreground">© 2025 TeamCyberOps — For authorized security testing only</span>
        </div>
      </footer>
    </div>
  );
};

// ── Helper Components ──
const Empty = ({ msg }: { msg?: string }) => (
  <div className="text-center py-16">
    <div className="text-2xl mb-2.5 opacity-50">⊘</div>
    <p className="text-muted-foreground text-[13px] leading-[1.6]">{msg || 'Enter a domain and click Full Scan'}</p>
  </div>
);

const StatusBadge = ({ status }: { status: number }) => {
  if (!status) return <span className="px-1.5 py-0.5 rounded text-[9px] border font-mono bg-muted text-muted-foreground border-border">—</span>;
  const cls = status >= 200 && status < 300 ? 'bg-[hsl(var(--green))]/8 text-[hsl(var(--green))] border-[hsl(var(--green))]/20'
    : status >= 300 && status < 400 ? 'bg-[hsl(var(--amber))]/8 text-[hsl(var(--amber))] border-[hsl(var(--amber))]/20'
    : status >= 400 ? 'bg-destructive/8 text-destructive border-destructive/20'
    : 'bg-muted text-muted-foreground border-border';
  return <span className={`px-1.5 py-0.5 rounded text-[9px] border font-mono ${cls}`}>{status}</span>;
};

const SevBadge = ({ sev }: { sev: string }) => {
  const s = sev?.toUpperCase() || 'INFO';
  const cls = s === 'CRITICAL' || s === 'HIGH' ? 'bg-destructive/8 border-destructive/20 text-destructive'
    : s === 'MEDIUM' ? 'bg-[hsl(var(--amber))]/8 border-[hsl(var(--amber))]/20 text-[hsl(var(--amber))]'
    : s === 'LOW' ? 'bg-[hsl(var(--teal))]/8 border-[hsl(var(--teal))]/20 text-[hsl(var(--teal))]'
    : 'bg-white/[0.04] border-white/[0.08] text-muted-foreground';
  return <span className={`inline-flex items-center rounded-md px-2 py-0.5 text-[9.5px] font-semibold tracking-[0.04em] border ${cls}`}>{s}</span>;
};

export default Index;
