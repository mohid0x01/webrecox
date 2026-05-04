import { useState, useCallback, useRef, useEffect, lazy, Suspense } from 'react';
import { Search, Download, FileJson, FileText, Printer, Loader2, CheckCircle, AlertCircle, Globe, Radar, Activity, Cpu, Shield, Server, Link, Key, Bug, Eye, Terminal, ChevronDown, Copy, ExternalLink, Zap, Lock, Code, Database, Map, FileCode, AlertTriangle, Skull, Cookie, Layers, GitBranch, Crosshair, Wifi, Target, RefreshCw, Gauge, Network, Hammer, Award, Package, Fingerprint, Box, ListChecks, Mail, Cloud, BookOpen, History, Hash, ChevronRight, Volume2, Bell, MapPin, BarChart3, GitCompare, List, Share2, Keyboard, Microscope } from 'lucide-react';
import { supabase } from '@/integrations/supabase/client';
import { exportCSV, exportJSON, exportTXT, exportPDF } from '@/lib/exportUtils';
import { toast } from 'sonner';
import {
  runFullScan, createScanState, ScanState, ModuleStatus,
  generateMarkdownReport, generateBurpXML, generateNucleiTargets,
} from '@/lib/reconEngine';
import { playScanStart, playScanComplete, playModuleDone, playModuleError, playAlert, playFindingCritical } from '@/lib/soundUtils';
import JSAnalyzerModal from '@/components/JSAnalyzerModal';
import ProxySettingsPanel from '@/components/ProxySettingsPanel';
import { applyProfileToSources, type ProfileId } from '@/lib/scanProfiles';
const ThreatMap = lazy(() => import('@/components/ThreatMap'));

const HISTORY_PASSPHRASE = 'WebRecox-TeamCyberOps';
const HISTORY_UNLOCK_KEY = 'webrecox.historyUnlocked.v1';

// ── All tabs ──
const ALL_TABS = [
  { id: 'sub', label: 'Subs', icon: Globe, cat: 'subdomains' },
  { id: 'dns', label: 'DNS', icon: Radar, cat: 'subdomains' },
  { id: 'ports', label: 'Ports', icon: Wifi, cat: 'subdomains' },
  { id: 'probe', label: 'Probe', icon: Activity, cat: 'subdomains' },
  { id: 'ips', label: 'Unique IPs', icon: MapPin, cat: 'subdomains' },
  { id: 'ep', label: 'Endpoints', icon: Link, cat: 'endpoints' },
  { id: 'js', label: 'JS', icon: FileCode, cat: 'js' },
  { id: 'params', label: 'Params', icon: Key, cat: 'endpoints' },
  { id: 'secrets', label: 'Secrets', icon: Lock, cat: 'js' },
  { id: 'jsanalyzer', label: 'JS Analyzer', icon: Microscope, cat: 'js' },
  { id: 'domxss', label: 'DOM XSS', icon: Code, cat: 'js' },
  { id: 'jwt', label: 'JWT', icon: Key, cat: 'js' },
  { id: 'hdrs', label: 'Headers', icon: Shield, cat: 'intel' },
  { id: 'ssl', label: 'SSL', icon: Lock, cat: 'intel' },
  { id: 'whois', label: 'WHOIS', icon: Server, cat: 'intel' },
  { id: 'tech', label: 'Tech', icon: Cpu, cat: 'intel' },
  { id: 'vuln', label: 'Vulns', icon: Bug, cat: 'vulns' },
  { id: 'cors', label: 'CORS', icon: Crosshair, cat: 'vulns' },
  { id: 'nuclei', label: 'Nuclei', icon: Skull, cat: 'vulns' },
  { id: 'content', label: 'Content', icon: Layers, cat: 'vulns' },
  { id: 'takeover', label: 'Takeover', icon: AlertTriangle, cat: 'vulns' },
  { id: 'idor', label: 'IDOR', icon: Fingerprint, cat: 'vulns' },
  { id: 'race', label: 'Race', icon: RefreshCw, cat: 'vulns' },
  { id: 'cache', label: 'Cache Poison', icon: Box, cat: 'vulns' },
  { id: 'crlf', label: 'CRLF', icon: Terminal, cat: 'vulns' },
  { id: 'hostinj', label: 'Host Inj', icon: Network, cat: 'vulns' },
  { id: 'cookies', label: 'Cookies', icon: Cookie, cat: 'vulns' },
  { id: 'graphql', label: 'GraphQL', icon: Database, cat: 'vulns' },
  { id: 'methods', label: 'Methods', icon: ListChecks, cat: 'vulns' },
  { id: 'vhosts', label: 'VHosts', icon: Server, cat: 'vulns' },
  { id: 'ssti', label: 'SSTI/SQLi', icon: Terminal, cat: 'vulns' },
  { id: 'blh', label: 'BLH', icon: GitBranch, cat: 'vulns' },
  { id: 'depconf', label: 'Dep Conf', icon: Package, cat: 'vulns' },
  { id: 'urlscan', label: 'URLScan', icon: Search, cat: 'intel' },
  { id: 'intel', label: 'Intel', icon: Eye, cat: 'intel' },
  { id: 'dorks', label: 'Dorks', icon: BookOpen, cat: 'intel' },
  { id: 'email', label: 'Email', icon: Mail, cat: 'intel' },
  { id: 'cloud', label: 'Cloud', icon: Cloud, cat: 'intel' },
  { id: 'ghleaks', label: 'GH Leaks', icon: Code, cat: 'intel' },
  { id: 'authmap', label: 'AuthMap', icon: Fingerprint, cat: 'intel' },
  { id: 'certmine', label: 'Cert Mine', icon: Lock, cat: 'intel' },
  { id: 'bounty', label: 'Bounty', icon: Award, cat: 'intel' },
  { id: 'darkweb', label: 'Dark Web', icon: Eye, cat: 'intel' },
  { id: 'breaches', label: 'Breaches', icon: AlertTriangle, cat: 'intel' },
  { id: 'pastes', label: 'Pastes', icon: FileText, cat: 'intel' },
  { id: 'exploits', label: 'Exploits', icon: Hammer, cat: 'vulns' },
  { id: 'threatmap', label: 'Map', icon: MapPin, cat: 'reports' },
  { id: 'heatmap', label: 'Heatmap', icon: BarChart3, cat: 'reports' },
  { id: 'risk', label: 'Score', icon: Gauge, cat: 'reports' },
  { id: 'adv', label: 'Adv', icon: Zap, cat: 'reports' },
  { id: 'history', label: 'History', icon: History, cat: 'reports' },
  { id: 'diff', label: 'Diff', icon: GitCompare, cat: 'reports' },
  { id: 'queue', label: 'Queue', icon: List, cat: 'reports' },
] as const;

type TabId = typeof ALL_TABS[number]['id'];

const CATEGORIES = [
  { id: 'all', label: '☣ Full Scan' },
  { id: 'subdomains', label: '⊕ Subdomains' },
  { id: 'endpoints', label: '⟁ Endpoints' },
  { id: 'js', label: '⚡ JS & Secrets' },
  { id: 'vulns', label: '☠ Vulnerabilities' },
  { id: 'intel', label: '⊛ Intelligence' },
  { id: 'reports', label: '⊞ Reports & Tools' },
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
  { id: 'sonar', label: 'Sonar/Crobat' }, { id: 'wbsubs', label: 'Wayback Subs' },
  { id: 'virus', label: 'VirusTotal Subs' }, { id: 'brute', label: 'DNS Brute (500)' },
  { id: 'bufferover', label: 'BufferOver' }, { id: 'threatcrowd', label: 'ThreatCrowd' },
  { id: 'dnsrepo', label: 'DNSRepo' }, { id: 'riddler', label: 'Riddler' },
  { id: 'wbfull', label: 'Wayback Full (1M+)' }, { id: 'dnsx', label: 'DNSx Multi-Query' },
  // Endpoint sources
  { id: 'wb', label: 'Wayback CDX' }, { id: 'otxurl', label: 'OTX URLs' },
  { id: 'cc', label: 'CommonCrawl' }, { id: 'uscan', label: 'URLScan URLs' },
  { id: 'sitemap', label: 'Sitemap Parse' }, { id: 'robotstxt', label: 'robots.txt' },
  // Analysis sources
  { id: 'jsfind', label: 'JS Secret Scan' }, { id: 'cors', label: 'CORS Scan' },
  { id: 'content', label: 'Content Discovery' }, { id: 'nuclei', label: 'Nuclei Templates' },
  { id: 'geo', label: 'IP Geo' }, { id: 'shodan', label: 'Shodan IDB' },
  { id: 'rdap', label: 'RDAP/WHOIS' }, { id: 'httpheaders', label: 'HTTPHeaders' },
  { id: 'otxintel', label: 'OTXIntel' }, { id: 'github', label: 'GitHub' },
  { id: 'clouds3', label: 'Cloud/S3' }, { id: 'gau', label: 'GAU/GetAllUrls' },
  { id: 'ghep', label: 'GitHub Endpoints' }, { id: 'vtfull', label: 'VirusTotal Full' },
  { id: 'certmine', label: 'Cert Mine' }, { id: 'favicon', label: 'Favicon Hash' },
  { id: 'ghleaks', label: 'GitHub Code Leaks' }, { id: 'ssti', label: 'SSTI/SQLi' },
  { id: 'vhosts', label: 'VHost Fuzz' }, { id: 'email', label: 'Email Security' },
  { id: 'pastes', label: 'Paste Search' }, { id: 'dorks', label: 'Dork Generator' },
  // Dark web
  { id: 'hibp', label: 'HIBP' }, { id: 'hudson', label: 'Hudson Rock' },
  { id: 'ransomwatch', label: 'RansomWatch' }, { id: 'leakix', label: 'LeakIX' },
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
  const [expandedModules, setExpandedModules] = useState<Set<string>>(new Set());
  const [soundEnabled, setSoundEnabled] = useState(true);
  const [sources, setSources] = useState<Record<string, boolean>>(() => {
    const s: Record<string, boolean> = {};
    SUB_SOURCES.forEach(src => s[src.id] = true);
    return s;
  });
  const [history, setHistory] = useState<ScanHistory[]>([]);
  const [showCachedPrompt, setShowCachedPrompt] = useState(false);
  const [cachedScanId, setCachedScanId] = useState<string | null>(null);
  const [filter, setFilter] = useState('');
  const [queueDomains, setQueueDomains] = useState('');
  const [queueStatus, setQueueStatus] = useState<{ domain: string; status: string }[]>([]);
  const [shareId, setShareId] = useState<string | null>(null);
  const [showAnalyzer, setShowAnalyzer] = useState(false);
  const [analyzerTarget, setAnalyzerTarget] = useState<string>('');
  const [showProxySettings, setShowProxySettings] = useState(false);
  const [historyUnlocked, setHistoryUnlocked] = useState<boolean>(() => {
    try { return localStorage.getItem(HISTORY_UNLOCK_KEY) === '1'; } catch { return false; }
  });
  const [historyKeyInput, setHistoryKeyInput] = useState('');
  const scanRef = useRef(false);
  const prevModulesRef = useRef<Record<string, { status: ModuleStatus }>>({});

  // Load shared view / target from URL
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const sid = params.get('share');
    const deepTab = params.get('tab');
    const prefill = params.get('target');

    if (deepTab && ALL_TABS.some(t => t.id === deepTab)) {
      setActiveTab(deepTab as TabId);
      const found = ALL_TABS.find(t => t.id === deepTab);
      if (found) setActiveCat(found.cat);
    }
    if (prefill) {
      setTarget(prefill);
      toast.info(`Target prefilled: ${prefill}`, { duration: 2500 });
    }

    if (sid) {
      setShareId(sid);
      (async () => {
        // New shared_views table (short share IDs)
        const { data: sv } = await supabase.from('shared_views').select('payload, target_domain, view_count').eq('share_id', sid).maybeSingle();
        if (sv?.payload) {
          const p = sv.payload as any;
          if (p.scan_data) setScanState({ ...createScanState(), ...p.scan_data } as ScanState);
          if (typeof p.filter === 'string') setFilter(p.filter);
          if (p.activeCat) setActiveCat(p.activeCat);
          if (p.activeTab && ALL_TABS.some(t => t.id === p.activeTab)) setActiveTab(p.activeTab);
          if (sv.target_domain) setTarget(sv.target_domain);
          supabase.from('shared_views').update({ view_count: (sv.view_count || 0) + 1 }).eq('share_id', sid).then(() => {});
          toast.success(`Loaded shared view: ${sv.target_domain || 'session'}`);
          return;
        }
        // Legacy fallback: full scan_results UUID
        const { data } = await supabase.from('scan_results').select('scan_data, domain').eq('id', sid).maybeSingle();
        if (data?.scan_data) {
          setScanState({ ...createScanState(), ...(data.scan_data as Record<string, any>) } as ScanState);
          setTarget(data.domain || '');
          toast.success(`Loaded shared scan for ${data.domain}`);
        } else toast.error('Shared view not found');
      })();
    }
    loadHistory();
  }, []);

  // Keyboard shortcuts
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.ctrlKey && e.key === 'Enter') { e.preventDefault(); startScan(); }
      if (e.ctrlKey && e.key === 'e') { e.preventDefault(); handleExport('json'); }
      if (!e.ctrlKey && !e.altKey && !e.metaKey && e.target === document.body) {
        const num = parseInt(e.key);
        if (num >= 1 && num <= 9) {
          const tabs = activeCat === 'all' ? ALL_TABS : ALL_TABS.filter(t => t.cat === activeCat);
          if (tabs[num - 1]) setActiveTab(tabs[num - 1].id);
        }
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [target, scanning, activeCat]);

  // Sound effects on module status changes
  useEffect(() => {
    if (!soundEnabled) return;
    Object.entries(modules).forEach(([name, { status }]) => {
      const prev = prevModulesRef.current[name]?.status;
      if (prev === status) return;
      if (status === 'done' && prev === 'running') playModuleDone();
      if (status === 'error' && prev === 'running') playModuleError();
    });
    prevModulesRef.current = { ...modules };
  }, [modules, soundEnabled]);

  const loadHistory = async () => {
    const { data } = await supabase.from('scan_results').select('id, domain, created_at, scan_type').order('created_at', { ascending: false }).limit(50);
    if (data) setHistory(data);
  };

  const checkCachedScan = async (domain: string): Promise<boolean> => {
    const { data } = await supabase.from('scan_results').select('id, created_at').eq('domain', domain.toLowerCase().trim()).order('created_at', { ascending: false }).limit(1);
    if (data && data.length > 0) { setCachedScanId(data[0].id); setShowCachedPrompt(true); return true; }
    return false;
  };

  const loadCachedScan = async () => {
    if (!cachedScanId) return;
    const { data } = await supabase.from('scan_results').select('scan_data').eq('id', cachedScanId).maybeSingle();
    if (data?.scan_data) {
      setScanState({ ...createScanState(), ...(data.scan_data as Record<string, any>) } as ScanState);
      toast.success('Loaded cached scan results');
    }
    setShowCachedPrompt(false);
  };

  const saveScanToDb = async (state: ScanState) => {
    await supabase.from('scan_results').insert({ domain: state.domain.toLowerCase().trim(), scan_data: state as any, scan_type: profile });
    loadHistory();
  };

  const startScan = async () => {
    const domain = target.trim().toLowerCase();
    if (!domain || scanning) return;
    const hasCached = await checkCachedScan(domain);
    if (hasCached) return;
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
    setExpandedModules(new Set());
    setScanState(createScanState());
    scanRef.current = true;
    if (soundEnabled) playScanStart();
    toast.info(`🔍 Starting scan for ${d}`, { duration: 3000 });
    try {
      const effectiveSources = applyProfileToSources(profile as ProfileId, sources);
      const result = await runFullScan(d, effectiveSources,
        (name, status, detail) => {
          setModules(prev => ({ ...prev, [name]: { status, detail } }));
          if (status === 'done') toast.success(`✓ ${name} complete`, { duration: 2000 });
          if (status === 'error') { toast.error(`✗ ${name} failed: ${detail || 'unknown'}`, { duration: 4000 }); }
        },
        (pct, label) => { setProgress(pct); setProgressLabel(label); },
        (partial) => { setScanState(prev => ({ ...prev, ...partial })); },
      );
      // Notify critical findings
      if (result.secrets.length > 0) { toast.warning(`⚠ ${result.secrets.length} secrets found!`, { duration: 5000 }); if (soundEnabled) playFindingCritical(); }
      if (result.takeover.length > 0) { toast.warning(`⚠ ${result.takeover.length} takeover candidates!`, { duration: 5000 }); if (soundEnabled) playAlert(); }
      if (result.darkWebFindings.length > 0) { toast.warning(`⚠ ${result.darkWebFindings.length} dark web findings!`, { duration: 5000 }); }
      await saveScanToDb(result);
      if (soundEnabled) playScanComplete();
      toast.success(`✅ Scan complete — ${result.subs.length} subs, ${result.eps.length} endpoints, Risk: ${result.riskGrade}`, { duration: 8000 });
    } catch (e: any) { console.error('Scan failed:', e); toast.error('Scan failed: ' + (e.message || 'Unknown error')); }
    finally { setScanning(false); scanRef.current = false; }
  };

  const runQueueScan = async () => {
    const domains = queueDomains.split('\n').map(d => d.trim().toLowerCase()).filter(Boolean);
    if (!domains.length) return;
    setQueueStatus(domains.map(d => ({ domain: d, status: 'Pending' })));
    for (let i = 0; i < domains.length; i++) {
      setQueueStatus(prev => prev.map((item, idx) => idx === i ? { ...item, status: 'Scanning…' } : item));
      setTarget(domains[i]);
      await runNewScan(domains[i]);
      setQueueStatus(prev => prev.map((item, idx) => idx === i ? { ...item, status: 'Done ✓' } : item));
    }
  };

  const handleExport = (format: string) => {
    const domain = scanState.domain || target || 'scan';
    if (format === 'json') exportJSON(scanState, `${domain}_report`);
    else if (format === 'csv') {
      const rows = scanState.subs.map(s => ({ subdomain: s.subdomain, ip: s.ip, status: s.status, source: s.source, alive: s.alive, ports: s.ports.join(';'), geo: s.geo }));
      exportCSV(rows.length ? rows : [{ info: 'No data' }], `${domain}_subdomains`);
    } else if (format === 'txt') { exportTXT(generateMarkdownReport(scanState).split('\n'), `${domain}_report`); }
    else if (format === 'pdf') {
      const sections: { heading: string; content: string }[] = [];
      if (scanState.subs.length) sections.push({ heading: `Subdomains (${scanState.subs.length})`, content: scanState.subs.slice(0, 1000000).map(s => `${s.subdomain}  ${s.ip || '—'}  [${s.source}]`).join('\n') });
      if (Object.keys(scanState.dns).length) sections.push({ heading: 'DNS Records', content: Object.entries(scanState.dns).filter(([, r]) => r.length).map(([t, recs]) => `${t}:\n${recs.map(r => `  ${r.val}`).join('\n')}`).join('\n\n') });
      if (scanState.secrets.length) sections.push({ heading: `Secrets (${scanState.secrets.length})`, content: scanState.secrets.map(s => `[${s.sev}] ${s.type}: ${s.value.slice(0, 80)} — ${s.file}`).join('\n') });
      if (scanState.riskScore) sections.push({ heading: 'Risk Score', content: `Score: ${scanState.riskScore}/100 — Grade: ${scanState.riskGrade}` });
      if (!sections.length) sections.push({ heading: 'No Data', content: 'Run a scan first.' });
      exportPDF(`Recon Report — ${domain}`, sections);
    } else if (format === 'burp') {
      const xml = generateBurpXML(scanState.eps);
      const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([xml], { type: 'text/xml' })); a.download = `${domain}_burp.xml`; a.click();
    } else if (format === 'nuclei') {
      const targets = generateNucleiTargets(scanState.subs);
      const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([targets], { type: 'text/plain' })); a.download = `${domain}_nuclei_targets.txt`; a.click();
    }
    toast.success(`Exported ${format.toUpperCase()}`);
  };

  const copyToClipboard = (text: string) => { navigator.clipboard.writeText(text); toast.success('Copied!', { duration: 1000 }); };

  const shareScan = async () => {
    if (!scanState.domain && !target) { toast.error('Run or load a scan first'); return; }
    // Generate short share ID (8 chars, base36)
    const shortId = (Math.random().toString(36).slice(2, 6) + Date.now().toString(36).slice(-4)).toLowerCase();
    const payload = {
      scan_data: scanState,
      filter,
      activeCat,
      activeTab,
      sources,
      created_at: new Date().toISOString(),
    };
    const { error } = await supabase.from('shared_views').insert({
      share_id: shortId,
      kind: 'recon',
      target_domain: scanState.domain || target,
      payload: payload as any,
    });
    if (error) { toast.error('Could not create share link: ' + error.message); return; }
    const url = `${window.location.origin}/?share=${shortId}`;
    try { await navigator.clipboard.writeText(url); } catch { /* */ }
    toast.success(`Share link copied: ${url}`, { duration: 6000 });
  };

  const filteredTabs = activeCat === 'all' ? ALL_TABS : ALL_TABS.filter(t => t.cat === activeCat);

  const counts: Record<string, number> = {
    sub: scanState.subs.length,
    dns: Object.values(scanState.dns).flat().length,
    ports: Object.values(scanState.ips).reduce((a: number, v: any) => a + (v.ports?.length || 0), 0),
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
    idor: scanState.idorFindings.length,
    race: scanState.raceFindings.length,
    cache: scanState.cachePoisonFindings.length,
    crlf: scanState.crlfFindings.length,
    hostinj: scanState.hostInjectionFindings.length,
    blh: scanState.blhFindings.length,
    bounty: scanState.bountyFindings.length,
    depconf: scanState.depConfFindings.length,
    jwt: scanState.jwtFindings.length,
    graphql: scanState.graphqlFindings.length,
    methods: scanState.methodsFindings.length,
    exploits: scanState.exploitFindings.length,
    risk: scanState.riskScore > 0 ? 1 : 0,
    ssl: scanState.ssl.length,
    takeover: scanState.takeover.length,
    ips: Object.keys(scanState.ips).length,
    email: scanState.emailFindings.length,
    cloud: scanState.cloud.s3.length,
    dorks: scanState.dorks.length,
    ghleaks: scanState.ghLeaks.length,
    ssti: scanState.sstiFindings?.length || 0,
    vhosts: scanState.vhostFindings?.length || 0,
    breaches: scanState.darkWebFindings.filter(d => d.type === 'breach').length,
    pastes: scanState.pasteFindings?.length || 0,
    urlscan: scanState.uscan.length,
    intel: (scanState.otx.p || 0),
    adv: 0,
    authmap: Object.values(scanState.authSurface).flat().length,
    certmine: scanState.ssl.length,
    heatmap: scanState.subs.length > 0 ? 1 : 0,
    diff: 0,
    queue: queueStatus.length,
    hdrs: scanState.hdrs.length,
    whois: Object.keys(scanState.whois || {}).length > 0 ? 1 : 0,
    jsanalyzer: scanState.jsCodeFindings?.length || 0,
    threatmap: Object.keys(scanState.ips).length,
  };

  const toggleModule = (name: string) => {
    setExpandedModules(prev => {
      const n = new Set(prev);
      if (n.has(name)) n.delete(name); else n.add(name);
      return n;
    });
  };

  return (
    <div className="min-h-screen bg-background relative z-[2]">
      {/* NAV */}
      <nav className="sticky top-0 z-50 bg-background/92 backdrop-blur-[28px] border-b border-border relative">
        <div className="absolute bottom-0 left-0 right-0 h-px nav-glow-line" />
        <div className="max-w-[1300px] mx-auto px-6 flex items-center gap-3 h-[58px]">
          <a href="/" className="flex items-center gap-2.5 no-underline shrink-0" onClick={e => { e.preventDefault(); setScanState(createScanState()); setTarget(''); }}>
            <img src="https://github.com/mohidqx.png" alt="Logo" className="w-[34px] h-[34px] rounded-full border-2 border-primary/40 drop-shadow-[0_0_10px_hsla(38,92%,50%,0.5)]" />
            <span className="brand-gradient text-[17px] font-extrabold tracking-[0.06em] uppercase">WebRecox</span>
            <span className="font-mono text-[8.5px] font-bold tracking-[0.1em] px-[7px] py-[2px] rounded-full bg-primary/10 border border-primary/25 text-primary uppercase">by TeamCyberOps</span>
          </a>
          <div className="flex-1" />
          <button onClick={() => setSoundEnabled(!soundEnabled)} className={`p-1.5 rounded-lg border transition-all ${soundEnabled ? 'border-primary/25 text-primary' : 'border-border text-muted-foreground'}`}>
            <Volume2 size={13} />
          </button>
          <div className="flex items-center gap-2 shrink-0">
            {[
              { fmt: 'json', label: '{}' }, { fmt: 'csv', label: 'CSV' },
              { fmt: 'txt', label: 'TXT' }, { fmt: 'pdf', label: 'PDF' },
              { fmt: 'burp', label: 'Burp' }, { fmt: 'nuclei', label: 'Nuclei' },
            ].map(({ fmt, label }) => (
              <button key={fmt} onClick={() => handleExport(fmt)}
                className="px-2.5 py-1.5 border border-border rounded-lg text-[10px] font-semibold text-muted-foreground hover:text-foreground hover:border-primary/25 hover:bg-primary/5 transition-all cursor-pointer">
                {label}
              </button>
            ))}
            <button onClick={shareScan} className="px-2.5 py-1.5 border border-[hsl(var(--green))]/20 bg-[hsl(var(--green))]/5 rounded-lg text-[10px] font-semibold text-[hsl(var(--green))] hover:bg-[hsl(var(--green))]/10 transition-all cursor-pointer flex items-center gap-1">
              <Share2 size={10} /> Share
            </button>
            <button onClick={() => { setAnalyzerTarget(target.trim() ? (target.trim().startsWith('http') ? target.trim() : 'https://' + target.trim()) : ''); setShowAnalyzer(true); }}
              className="px-2.5 py-1.5 border border-[hsl(var(--teal))]/25 bg-[hsl(var(--teal))]/5 rounded-lg text-[10px] font-semibold text-[hsl(var(--teal))] hover:bg-[hsl(var(--teal))]/10 transition-all cursor-pointer flex items-center gap-1">
              <Microscope size={10} /> JS Analyzer
            </button>
            <button onClick={() => setShowProxySettings(true)}
              className="px-2.5 py-1.5 border border-border bg-white/[0.03] rounded-lg text-[10px] font-semibold text-muted-foreground hover:text-foreground hover:border-primary/25 transition-all cursor-pointer flex items-center gap-1"
              title="Proxy fallback settings">
              ⚙ Proxy
            </button>
            <a href="/oneliners" className="px-3 py-1.5 border border-[hsl(var(--purple))]/20 bg-[hsl(var(--purple))]/5 rounded-lg text-[10.5px] font-semibold text-[hsl(var(--purple))] hover:bg-[hsl(var(--purple))]/10 transition-colors no-underline">
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
            ☣︎ WebRecox 🗡<br />Recon Engine v15
          </h1>
          <div className="flex items-center justify-center gap-2 flex-wrap mb-4">
            <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-primary/10 border border-primary/30 text-primary">by TeamCyberOps</span>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-[hsl(var(--green))]/10 border border-[hsl(var(--green))]/30 text-[hsl(var(--green))]">v15.0 · NO LIMITS</span>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-[hsl(var(--purple))]/10 border border-[hsl(var(--purple))]/30 text-[hsl(var(--purple))]">51 Tabs</span>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-[hsl(var(--teal))]/10 border border-[hsl(var(--teal))]/30 text-[hsl(var(--teal))]">170+ Oneliners</span>
          </div>
          <p className="text-muted-foreground max-w-[640px] mx-auto leading-[1.7] mb-5">
            <span className="text-primary font-semibold">WebRecox</span> — 50+ OSINT sources · 42 scan phases · DNS multi-resolver · Port intel · JS Code Analyzer · DOM XSS · CORS · IDOR · Race · Cache Poison · CRLF · GraphQL · Nuclei · Threat Map · Dark Web · <span className="text-primary">NO LIMITS</span>
          </p>
        </div>

        {/* SEARCH CARD */}
        <div className="bg-card/50 border border-primary/8 rounded-[18px] p-[22px_26px_18px] backdrop-blur-[20px] mb-5 transition-all focus-within:border-primary/30 focus-within:shadow-[var(--glow)] animate-fade-in-up" style={{ animationDelay: '0.2s' }}>
          <div className="flex gap-2.5 flex-wrap mb-3.5">
            <div className="flex-1 min-w-[200px] relative">
              <Search size={15} className="absolute left-[14px] top-1/2 -translate-y-1/2 text-muted-foreground pointer-events-none" />
              <input type="text" value={target} onChange={e => setTarget(e.target.value)}
                placeholder="Enter target domain — e.g. tesla.com"
                onKeyDown={e => e.key === 'Enter' && startScan()}
                className="w-full bg-white/[0.04] border border-primary/10 rounded-[11px] py-[13px] pl-[42px] pr-4 text-foreground font-mono text-[13.5px] outline-none transition-all placeholder:text-muted-foreground focus:border-primary/40 focus:bg-primary/[0.04] focus:shadow-[0_0_0_3px_hsla(38,92%,50%,0.1)]" />
            </div>
            <button onClick={startScan} disabled={!target.trim() || scanning}
              className="scan-btn-gradient border-none rounded-[11px] px-6 py-[13px] text-white font-bold text-[13px] tracking-[0.03em] cursor-pointer transition-all flex items-center gap-2 disabled:opacity-45 disabled:cursor-not-allowed active:translate-y-0">
              {scanning ? <Loader2 size={14} className="animate-spin" /> : <Search size={14} />}
              {scanning ? 'Scanning…' : 'Full Scan'}
            </button>
            <button onClick={() => { setAnalyzerTarget(target.trim() ? (target.trim().startsWith('http') ? target.trim() : 'https://' + target.trim()) : ''); setShowAnalyzer(true); }}
              className="border border-[hsl(var(--teal))]/40 bg-[hsl(var(--teal))]/8 rounded-[11px] px-5 py-[13px] text-[hsl(var(--teal))] font-bold text-[13px] tracking-[0.03em] hover:bg-[hsl(var(--teal))]/15 transition-all flex items-center gap-2"
              title="Open JS Code Analyzer (AST + endpoint crawler)">
              <Microscope size={14} /> JS Analyzer
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
            <span className="text-[9.5px] font-bold tracking-[0.1em] uppercase text-muted-foreground">⟐ Data Sources ({SUB_SOURCES.length}) — click to toggle</span>
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

        {/* ANIMATED PROGRESS DASHBOARD */}
        {scanning && (
          <div className="bg-card/60 border border-primary/12 rounded-[13px] p-4 mb-4 animate-fade-in-up">
            <div className="flex justify-between items-center mb-2.5">
              <div className="text-[12.5px] font-semibold text-primary flex items-center gap-2">
                <Loader2 size={14} className="animate-spin" />
                {progressLabel}
              </div>
              <span className="text-[11.5px] text-muted-foreground font-mono">{progress}%</span>
            </div>
            <div className="h-[3px] bg-white/[0.06] rounded-[3px] overflow-hidden mb-3">
              <div className="h-full progress-fill rounded-[3px] transition-[width] duration-400" style={{ width: `${progress}%` }} />
            </div>
            {/* Module Cards */}
            {Object.keys(modules).length > 0 && (
              <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 gap-2">
                {Object.entries(modules).map(([name, { status, detail }]) => (
                  <div key={name} onClick={() => toggleModule(name)}
                    className={`rounded-lg border p-2 cursor-pointer transition-all ${
                      status === 'done' ? 'border-[hsl(var(--green))]/30 bg-[hsl(var(--green))]/5'
                      : status === 'running' ? 'border-primary/30 bg-primary/5 animate-pulse'
                      : status === 'error' ? 'border-destructive/30 bg-destructive/5'
                      : 'border-border bg-white/[0.02]'
                    }`}>
                    <div className="flex items-center gap-1.5">
                      {status === 'done' ? <CheckCircle size={10} className="text-[hsl(var(--green))] shrink-0" /> :
                       status === 'running' ? <Loader2 size={10} className="text-primary animate-spin shrink-0" /> :
                       status === 'error' ? <AlertCircle size={10} className="text-destructive shrink-0" /> :
                       <div className="w-2.5 h-2.5 rounded-full bg-muted shrink-0" />}
                      <span className="text-[9px] font-mono text-foreground/80 truncate">{name}</span>
                    </div>
                    {expandedModules.has(name) && detail && (
                      <div className="mt-1.5 text-[8px] text-muted-foreground font-mono">{detail}</div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Stats Row */}
        <div className="grid grid-cols-[repeat(auto-fit,minmax(110px,1fr))] gap-2.5 mb-5 animate-fade-in-up" style={{ animationDelay: '0.3s' }}>
          {[
            { label: 'Subdomains', val: scanState.subs.length, color: 'hsl(var(--amber))' },
            { label: 'Live Hosts', val: scanState.subs.filter(s => s.alive).length, color: 'hsl(var(--green))' },
            { label: 'Unique IPs', val: Object.keys(scanState.ips).length, color: 'hsl(210,100%,70%)' },
            { label: 'Open Ports', val: Object.values(scanState.ips).reduce((a: number, v: any) => a + (v.ports?.length || 0), 0), color: 'hsl(var(--purple))' },
            { label: 'Endpoints', val: scanState.eps.length, color: 'hsl(var(--teal))' },
            { label: 'JS Files', val: scanState.js.length, color: 'hsl(var(--amber))' },
            { label: 'Params', val: Object.keys(scanState.params).length, color: 'hsl(var(--pink))' },
            { label: 'Secrets', val: scanState.secrets.length, color: 'hsl(0,72%,60%)' },
            { label: 'CORS', val: scanState.corsFindings.length, color: 'hsl(0,72%,60%)' },
            { label: 'Nuclei', val: scanState.nucleiFindings.length, color: 'hsl(0,72%,60%)' },
            { label: 'Takeover', val: scanState.takeover.length, color: 'hsl(0,72%,60%)' },
            { label: 'Dark Web', val: scanState.darkWebFindings.length, color: 'hsl(var(--amber))' },
            { label: 'Risk', val: scanState.riskScore, color: scanState.riskGrade === 'CRITICAL' ? 'hsl(0,72%,50%)' : scanState.riskGrade === 'HIGH' ? 'hsl(var(--amber))' : 'hsl(var(--green))' },
          ].map(s => (
            <div key={s.label} className="bg-white/[0.028] border border-border rounded-[13px] px-4 py-3.5 transition-all hover:border-primary/20 hover:-translate-y-0.5 hover:shadow-[0_6px_20px_rgba(0,0,0,0.4)] relative overflow-hidden stat-glow">
              <div className="text-[9.5px] font-bold tracking-[0.1em] text-muted-foreground uppercase mb-1">{s.label}</div>
              <div className="text-[1.6rem] font-bold font-mono leading-none" style={{ color: s.color }}>{s.val}</div>
            </div>
          ))}
        </div>

        {/* Tab Pills */}
        <div className="flex flex-wrap justify-center gap-1.5 mb-5">
          {filteredTabs.map(t => {
            const Icon = t.icon;
            const count = counts[t.id] || 0;
            return (
              <button key={t.id} onClick={() => setActiveTab(t.id)}
                className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border text-[10.5px] font-semibold cursor-pointer transition-all whitespace-nowrap
                  ${activeTab === t.id ? 'pill-active' : 'border-border bg-white/[0.03] text-muted-foreground hover:text-foreground hover:border-primary/25'}`}>
                <Icon size={11} />
                {t.label}
                {count > 0 && <span className="bg-primary/15 text-primary rounded-[5px] px-[5px] py-[1px] text-[8px] font-mono ml-0.5">{count}</span>}
              </button>
            );
          })}
        </div>

        {/* CONTENT PANELS */}
        <div className="bg-card/70 border border-primary/8 rounded-[16px] overflow-hidden backdrop-blur-[20px]">
          <div className="px-4 py-2.5 border-b border-border bg-white/[0.02] flex items-center justify-between">
            <span className="font-mono text-[10px] text-muted-foreground tracking-[0.12em] uppercase">{ALL_TABS.find(t => t.id === activeTab)?.label || activeTab}</span>
            {['sub', 'ep', 'js', 'probe'].includes(activeTab) && (
              <input value={filter} onChange={e => setFilter(e.target.value)} placeholder="Filter…"
                className="bg-white/[0.04] border border-border rounded-lg px-2.5 py-1 text-foreground font-mono text-[11px] outline-none focus:border-primary/30 w-40" />
            )}
          </div>

          <div className="p-4 min-h-[400px] max-h-[70vh] overflow-y-auto scrollbar-thin font-mono text-xs">
            {/* SUBDOMAINS */}
            {activeTab === 'sub' && (scanState.subs.length === 0 ? <Empty /> : (
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
                <tbody>{scanState.subs.filter(s => !filter || s.subdomain.includes(filter) || s.ip.includes(filter)).slice(0, 100000000).map((s, i) => (
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
                {scanState.subs.length > 1000 && <div className="text-center py-3 text-muted-foreground text-[11px]">Showing 1000 of {scanState.subs.length} — Export for full list</div>}
              </div>
            ))}

            {/* DNS */}
            {activeTab === 'dns' && (Object.values(scanState.dns).flat().length === 0 ? <Empty /> : (
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
            ))}

            {/* PORTS */}
            {activeTab === 'ports' && (Object.keys(scanState.ips).length === 0 ? <Empty /> : (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                {Object.entries(scanState.ips).filter(([, v]: [string, any]) => v.ports?.length > 0).map(([ip, data]: [string, any]) => (
                  <div key={ip} className="bg-white/[0.028] border border-border rounded-[14px] overflow-hidden">
                    <div className="px-3.5 py-2.5 bg-white/[0.02] border-b border-border">
                      <span className="font-mono text-[13px] text-primary font-semibold">{ip}</span>
                    </div>
                    <div className="px-3.5 py-2.5 flex flex-wrap gap-[5px]">
                      {data.ports.map((p: number) => <span key={p} className={`px-2 py-0.5 border rounded text-[10px] font-mono ${[3306,5432,27017,6379,9200,11211,5900,3389,2375].includes(p) ? 'bg-destructive/10 border-destructive/20 text-destructive' : 'bg-primary/10 border-primary/20 text-primary'}`}>{p}</span>)}
                    </div>
                    {data.cves?.length > 0 && <div className="px-3.5 py-2 flex flex-wrap gap-1">{data.cves.slice(0, 10).map((c: string) => <a key={c} href={`https://nvd.nist.gov/vuln/detail/${c}`} target="_blank" rel="noreferrer" className="text-[9px] px-1.5 py-0.5 bg-destructive/10 border border-destructive/20 rounded text-destructive no-underline hover:bg-destructive/20">{c}</a>)}</div>}
                    {data.geo && <div className="px-3.5 py-1.5 text-[9.5px] text-muted-foreground font-mono">{data.geo.city}, {data.geo.country_code} · {data.geo.org}</div>}
                  </div>
                ))}
              </div>
            ))}

            {/* UNIQUE IPs */}
            {activeTab === 'ips' && (Object.keys(scanState.ips).length === 0 ? <Empty msg="No IPs discovered yet." /> : (
              <div>
                <table className="w-full text-xs"><thead><tr className="text-muted-foreground text-left border-b border-border">
                  <th className="pb-2 font-bold text-[9.5px] tracking-[0.12em] uppercase">IP</th>
                  <th className="pb-2 font-bold text-[9.5px] tracking-[0.12em] uppercase">HOSTS</th>
                  <th className="pb-2 font-bold text-[9.5px] tracking-[0.12em] uppercase">PORTS</th>
                  <th className="pb-2 font-bold text-[9.5px] tracking-[0.12em] uppercase">CVEs</th>
                  <th className="pb-2 font-bold text-[9.5px] tracking-[0.12em] uppercase">GEO</th>
                  <th className="pb-2 font-bold text-[9.5px] tracking-[0.12em] uppercase">CLOUD</th>
                </tr></thead>
                <tbody>{Object.entries(scanState.ips).map(([ip, data]: [string, any], i) => (
                  <tr key={ip} className="border-t border-white/[0.035] hover:bg-primary/[0.025]">
                    <td className="py-2 text-primary font-semibold">{ip}</td>
                    <td className="py-2 text-muted-foreground text-[10px]">{(data.hosts || []).length}</td>
                    <td className="py-2">{(data.ports || []).slice(0, 8).map((p: number) => <span key={p} className="text-[9px] px-1 bg-primary/10 rounded mr-1">{p}</span>)}</td>
                    <td className="py-2 text-destructive">{(data.cves || []).length || '—'}</td>
                    <td className="py-2 text-[10px] text-muted-foreground">{data.geo ? `${data.geo.city || ''}, ${data.geo.country_code || ''}` : '—'}</td>
                    <td className="py-2 text-[10px] text-[hsl(var(--teal))]">{data.cloud || '—'}</td>
                  </tr>
                ))}</tbody></table>
              </div>
            ))}

            {/* ENDPOINTS */}
            {activeTab === 'ep' && (scanState.eps.length === 0 ? <Empty /> : (
              <div>{scanState.eps.filter(e => !filter || e.url.includes(filter)).slice(0, 100000000).map((ep, i) => (
                <div key={i} className="flex items-center gap-2 py-[7px] border-b border-white/[0.03] hover:bg-primary/[0.02]">
                  <span className="text-muted-foreground w-8 text-right shrink-0">{i + 1}</span>
                  <a href={ep.url} target="_blank" rel="noreferrer" className="text-secondary-foreground no-underline hover:text-primary truncate text-[11px]">{ep.url}</a>
                  <span className="ml-auto text-muted-foreground text-[9px] shrink-0">{ep.source}</span>
                </div>
              ))}</div>
            ))}

            {/* JS Files */}
            {activeTab === 'js' && (scanState.js.length === 0 ? <Empty /> : (
              <div>{scanState.js.filter(j => !filter || j.url.includes(filter)).slice(0, 100000000).map((j, i) => (
                <div key={i} className="group flex items-center gap-2 py-[7px] border-b border-white/[0.03] hover:bg-primary/[0.02]">
                  <span className="text-muted-foreground w-8 text-right shrink-0">{i + 1}</span>
                  <a href={j.url} target="_blank" rel="noreferrer" className="text-primary no-underline hover:underline truncate text-[11px] flex-1">{j.url}</a>
                  <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                    <button onClick={() => { setAnalyzerTarget(j.url); setShowAnalyzer(true); }}
                      className="px-2 py-0.5 rounded text-[9.5px] font-bold bg-[hsl(var(--teal))]/12 border border-[hsl(var(--teal))]/30 text-[hsl(var(--teal))] hover:bg-[hsl(var(--teal))]/20 flex items-center gap-1"
                      title="Analyze this JS with AST analyzer">
                      <Microscope size={9} /> Analyze
                    </button>
                    <button onClick={() => copyToClipboard(j.url)}
                      className="px-2 py-0.5 rounded text-[9.5px] font-bold bg-white/[0.04] border border-border text-muted-foreground hover:text-foreground"
                      title="Copy URL">
                      <Copy size={9} />
                    </button>
                  </div>
                  <span className="ml-1 text-muted-foreground text-[9px] shrink-0">{j.source}</span>
                </div>
              ))}</div>
            ))}

            {/* PARAMS */}
            {activeTab === 'params' && (Object.keys(scanState.params).length === 0 ? <Empty /> : (
              <div className="flex flex-wrap gap-1.5">
                {Object.entries(scanState.params).sort((a, b) => b[1] - a[1]).map(([param, count]) => {
                  const isHigh = /pass|token|secret|key|auth|session|api|id|uid|cmd|exec|file|url|redirect/i.test(param);
                  const isMed = /search|q|name|email|page|callback|next|return|goto|path/i.test(param);
                  return (
                    <span key={param} onClick={() => copyToClipboard(param)}
                      className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-lg font-mono text-[11px] cursor-pointer transition-all border
                        ${isHigh ? 'bg-destructive/7 border-destructive/20 text-destructive hover:bg-destructive/15'
                          : isMed ? 'bg-primary/7 border-primary/20 text-primary hover:bg-primary/15'
                          : 'bg-white/[0.04] border-white/[0.08] text-secondary-foreground hover:bg-primary/8'}`}>
                      {param}<span className="text-[9px] text-muted-foreground ml-0.5">{count}</span>
                    </span>
                  );
                })}
              </div>
            ))}

            {/* HEADERS */}
            {activeTab === 'hdrs' && (scanState.hdrs.length === 0 ? <Empty /> : (
              <div>
                {scanState.waf && scanState.waf !== 'unknown' && (
                  <div className="mb-4 p-3 rounded-lg border border-destructive/30 bg-destructive/5 flex items-center gap-2">
                    <Shield size={14} className="text-destructive" /> <span className="text-destructive font-semibold">WAF Detected: {scanState.waf}</span>
                  </div>
                )}
                <div className="bg-white/[0.028] border border-border rounded-[14px] overflow-hidden">
                  {scanState.hdrs.map((h: any, i: number) => (
                    <div key={i} className="grid grid-cols-[1fr_2fr] gap-2 px-3.5 py-2 border-b border-white/[0.035] last:border-none">
                      <span className="text-[10.5px] font-mono text-muted-foreground">{h.key}</span>
                      <span className="text-[11px] font-mono text-secondary-foreground break-all">{h.value}</span>
                    </div>
                  ))}
                </div>
              </div>
            ))}

            {/* SSL */}
            {activeTab === 'ssl' && (scanState.ssl.length === 0 ? <Empty msg="No SSL certificates found." /> : (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {scanState.ssl.map((c, i) => (
                  <div key={i} className="bg-white/[0.028] border border-border rounded-[14px] p-3">
                    <div className="flex items-center gap-2 mb-1">
                      <Lock size={12} className="text-primary" />
                      <span className="font-semibold text-[11px] truncate">{c.cn}</span>
                      {c.wildcard && <span className="text-[8px] px-1.5 py-0.5 bg-primary/10 rounded text-primary">Wildcard</span>}
                    </div>
                    <div className="text-[9px] text-muted-foreground ml-5">Issuer: {c.issuer.slice(0, 60)}</div>
                    <div className="text-[9px] ml-5 flex gap-2">
                      <span className="text-muted-foreground">{c.notBefore} → {c.notAfter}</span>
                      <span className={`font-semibold ${c.daysLeft < 30 ? 'text-destructive' : c.daysLeft < 90 ? 'text-primary' : 'text-[hsl(var(--green))]'}`}>{c.daysLeft}d left</span>
                    </div>
                  </div>
                ))}
              </div>
            ))}

            {/* WHOIS */}
            {activeTab === 'whois' && (!scanState.whois || Object.keys(scanState.whois).length === 0 ? <Empty /> : (
              <div className="bg-white/[0.028] border border-border rounded-[14px] overflow-hidden">
                {Object.entries(scanState.whois).map(([k, v]) => (
                  <div key={k} className="grid grid-cols-[1fr_2fr] gap-2 px-3.5 py-2 border-b border-white/[0.035] last:border-none">
                    <span className="text-[10.5px] font-mono text-muted-foreground capitalize">{k}</span>
                    <span className="text-[11px] font-mono text-secondary-foreground break-all">{typeof v === 'object' ? JSON.stringify(v) : String(v)}</span>
                  </div>
                ))}
              </div>
            ))}

            {/* TAKEOVER */}
            {activeTab === 'takeover' && (scanState.takeover.length === 0 ? <Empty msg="No takeover candidates found." /> : (
              <div>{scanState.takeover.map((t, i) => (
                <div key={i} className="mb-2 p-3 rounded-lg border bg-destructive/5 border-destructive/20">
                  <div className="flex items-center gap-2 mb-1"><SevBadge sev={t.sev} /><span className="font-semibold text-[11px]">{t.subdomain}</span>{t.confirmed && <span className="text-[8px] px-1.5 py-0.5 bg-destructive/10 rounded text-destructive">CONFIRMED</span>}</div>
                  <div className="text-[10px] font-mono ml-6">CNAME: {t.cname} → {t.service}</div>
                </div>
              ))}</div>
            ))}

            {/* EMAIL SECURITY */}
            {activeTab === 'email' && (scanState.emailFindings.length === 0 ? <Empty msg="No email security data." /> : (
              <div>{scanState.emailFindings.map((f, i) => (
                <div key={i} className="mb-2 p-3 rounded-lg border bg-white/[0.02] border-border">
                  <div className="flex items-center gap-2 mb-1"><SevBadge sev={f.sev} /><span className="font-semibold text-[11px]">{f.type}</span><span className="text-[hsl(var(--teal))] text-[9px]">{f.status}</span></div>
                  <div className="text-[10px] font-mono ml-6 text-muted-foreground break-all">{f.record || f.detail}</div>
                </div>
              ))}</div>
            ))}

            {/* CLOUD / S3 */}
            {activeTab === 'cloud' && (scanState.cloud.s3.length === 0 ? <Empty msg="No cloud resources found." /> : (
              <div>{scanState.cloud.s3.map((b, i) => (
                <div key={i} className="mb-2 p-3 rounded-lg border bg-white/[0.02] border-border">
                  <div className="flex items-center gap-2 mb-1"><SevBadge sev={b.sev} /><Cloud size={12} className="text-[hsl(var(--teal))]" /><span className="font-semibold text-[11px]">{b.bucket}</span><span className={`text-[9px] ${b.status === 'PUBLIC' ? 'text-destructive' : 'text-muted-foreground'}`}>{b.status}</span></div>
                  <a href={b.url} target="_blank" rel="noreferrer" className="text-primary text-[10px] ml-6 no-underline hover:underline font-mono">{b.url}</a>
                  {b.files.length > 0 && <div className="ml-6 mt-1 flex flex-wrap gap-1">{b.files.slice(0, 10).map((f, j) => <span key={j} className="text-[9px] px-1.5 py-0.5 bg-destructive/10 rounded text-destructive">{f}</span>)}</div>}
                </div>
              ))}</div>
            ))}

            {/* DORKS */}
            {activeTab === 'dorks' && (scanState.dorks.length === 0 ? <Empty msg="Run a scan to generate dorks." /> : (
              <div>
                {[...new Set(scanState.dorks.map(d => d.category))].map(cat => (
                  <div key={cat} className="mb-4">
                    <h3 className="text-[11px] font-bold text-primary tracking-[0.1em] uppercase mb-2">{cat}</h3>
                    {scanState.dorks.filter(d => d.category === cat).map((d, i) => (
                      <div key={i} className="flex items-center gap-2 py-[5px] border-b border-white/[0.03]">
                        <a href={d.url} target="_blank" rel="noreferrer" className="text-secondary-foreground no-underline hover:text-primary text-[10px] truncate">{d.query}</a>
                        <ExternalLink size={10} className="shrink-0 text-muted-foreground" />
                      </div>
                    ))}
                  </div>
                ))}
              </div>
            ))}

            {/* GH LEAKS */}
            {activeTab === 'ghleaks' && (scanState.ghLeaks.length === 0 ? <Empty msg="No GitHub leaks found." /> : (
              <div>{scanState.ghLeaks.map((l, i) => (
                <div key={i} className="mb-2 p-3 rounded-lg border bg-white/[0.02] border-destructive/20">
                  <div className="flex items-center gap-2 mb-1"><Code size={12} className="text-destructive" /><span className="font-semibold text-[11px]">{l.repo}</span><span className="text-destructive text-[9px]">{l.keyword}</span></div>
                  <div className="text-[10px] font-mono ml-6 text-muted-foreground">{l.file}</div>
                  <a href={l.url} target="_blank" rel="noreferrer" className="text-primary text-[9px] ml-6 no-underline hover:underline">{l.url}</a>
                </div>
              ))}</div>
            ))}

            {/* AUTH MAP */}
            {activeTab === 'authmap' && (Object.values(scanState.authSurface).flat().length === 0 ? <Empty msg="No auth surface mapped." /> : (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {Object.entries(scanState.authSurface).filter(([, urls]) => urls.length > 0).map(([cat, urls]) => (
                  <div key={cat} className="bg-white/[0.028] border border-border rounded-[14px] p-3">
                    <div className="text-[10px] font-bold text-primary tracking-[0.1em] uppercase mb-2">{cat} ({urls.length})</div>
                    {urls.slice(0, 10).map((u, i) => <div key={i} className="text-[10px] text-secondary-foreground truncate py-0.5">{u}</div>)}
                  </div>
                ))}
              </div>
            ))}

            {/* CERT MINE */}
            {activeTab === 'certmine' && (scanState.ssl.length === 0 ? <Empty msg="No certificate data." /> : (
              <div>
                <div className="mb-3 p-3 rounded-lg border border-primary/20 bg-primary/5">
                  <div className="text-[11px] font-semibold text-primary mb-1">Certificate Summary</div>
                  <div className="grid grid-cols-4 gap-2 text-[10px]">
                    <div><span className="text-muted-foreground">Total:</span> {scanState.ssl.length}</div>
                    <div><span className="text-muted-foreground">Wildcard:</span> {scanState.ssl.filter(c => c.wildcard).length}</div>
                    <div><span className="text-muted-foreground">Expiring &lt;30d:</span> <span className="text-destructive">{scanState.ssl.filter(c => c.daysLeft < 30).length}</span></div>
                    <div><span className="text-muted-foreground">Expired:</span> <span className="text-destructive">{scanState.ssl.filter(c => c.daysLeft < 0).length}</span></div>
                  </div>
                </div>
                {scanState.ssl.filter(c => c.wildcard || c.daysLeft < 90 || c.san.length > 3).slice(0, 50).map((c, i) => (
                  <div key={i} className="mb-2 p-3 rounded-lg border bg-white/[0.02] border-border">
                    <div className="font-semibold text-[11px]">{c.cn}</div>
                    <div className="text-[9px] text-muted-foreground">SANs: {c.san.slice(0, 5).join(', ')}{c.san.length > 5 ? ` +${c.san.length - 5} more` : ''}</div>
                  </div>
                ))}
              </div>
            ))}

            {/* PROBE */}
            {activeTab === 'probe' && (scanState.probes.length === 0 ? <Empty /> : (
              <div>{scanState.probes.filter(p => !filter || p.host.includes(filter)).slice(0, 100000000).map((p, i) => (
                <div key={i} className="flex items-center gap-2 py-[7px] border-b border-white/[0.03]">
                  <span className={`w-2 h-2 rounded-full shrink-0 ${p.alive ? 'bg-[hsl(var(--green))]' : 'bg-destructive'}`} />
                  <StatusBadge status={p.status} />
                  <a href={p.url} target="_blank" rel="noreferrer" className="text-primary no-underline hover:underline text-[11px] truncate">{p.host}</a>
                  <span className="text-muted-foreground text-[9px] shrink-0">{p.title?.slice(0, 30) || '—'}</span>
                  <span className="text-muted-foreground text-[9px] shrink-0 ml-auto">{p.server || '—'}</span>
                </div>
              ))}</div>
            ))}

            {/* ADV - External Tools */}
            {activeTab === 'adv' && (
              <div>
                <div className="mb-4 p-3 rounded-lg border border-primary/20 bg-primary/5">
                  <div className="text-[11px] font-semibold text-primary mb-2">Quick Checks</div>
                  <div className="flex flex-wrap gap-1.5">
                    {['/robots.txt', '/.git/config', '/.env', '/api/swagger.json', '/graphql', '/.well-known/security.txt', '/sitemap.xml'].map(path => (
                      <a key={path} href={`https://${scanState.domain || target}${path}`} target="_blank" rel="noreferrer" className="text-[10px] px-2 py-1 bg-white/[0.04] border border-border rounded text-muted-foreground no-underline hover:text-primary hover:border-primary/25">{path}</a>
                    ))}
                  </div>
                </div>
                <div className="text-[11px] font-semibold text-primary mb-2">External Tools</div>
                <div className="flex flex-wrap gap-1.5">
                  {[
                    { label: 'SecurityTrails', url: `https://securitytrails.com/domain/${scanState.domain || target}` },
                    { label: 'Shodan', url: `https://www.shodan.io/search?query=hostname:${scanState.domain || target}` },
                    { label: 'Censys', url: `https://search.censys.io/search?resource=hosts&sort=RELEVANCE&per_page=25&virtual_hosts=EXCLUDE&q=${scanState.domain || target}` },
                    { label: 'BuiltWith', url: `https://builtwith.com/${scanState.domain || target}` },
                    { label: 'VirusTotal', url: `https://www.virustotal.com/gui/domain/${scanState.domain || target}` },
                    { label: 'DNSDumpster', url: `https://dnsdumpster.com/` },
                    { label: 'FOFA', url: `https://en.fofa.info/result?qbase64=${btoa(`domain="${scanState.domain || target}"`)}` },
                    { label: 'Hunter.io', url: `https://hunter.io/domain-search/${scanState.domain || target}` },
                    { label: 'Wayback', url: `https://web.archive.org/web/*/${scanState.domain || target}` },
                    { label: 'OTX', url: `https://otx.alienvault.com/indicator/domain/${scanState.domain || target}` },
                    { label: 'crt.sh', url: `https://crt.sh/?q=%25.${scanState.domain || target}` },
                    { label: 'BGPView', url: `https://bgpview.io/search/${scanState.domain || target}` },
                  ].map(t => (
                    <a key={t.label} href={t.url} target="_blank" rel="noreferrer" className="text-[10px] px-2.5 py-1.5 bg-white/[0.04] border border-border rounded-lg text-muted-foreground no-underline hover:text-primary hover:border-primary/25 flex items-center gap-1">{t.label} <ExternalLink size={9} /></a>
                  ))}
                </div>
              </div>
            )}

            {/* SECRETS */}
            {activeTab === 'secrets' && (scanState.secrets.length === 0 ? <Empty msg="No secrets found." /> : (
              <div>{scanState.secrets.map((s, i) => (
                <div key={i} className="mb-2 p-3 rounded-lg border bg-destructive/5 border-destructive/20">
                  <div className="flex items-center gap-2 mb-1"><SevBadge sev={s.sev} /><span className="font-semibold text-[11px]">{s.type}</span></div>
                  <div className="text-primary text-[10px] font-mono ml-6 break-all">{s.value}</div>
                  <div className="text-muted-foreground text-[9px] ml-6 truncate">File: {s.file} (line {s.line})</div>
                </div>
              ))}</div>
            ))}

            {/* VULNS */}
            {activeTab === 'vuln' && (scanState.vulns.length === 0 ? <Empty msg="No vulnerabilities detected." /> : (
              <div>{scanState.vulns.map((v, i) => (
                <div key={i} className="mb-2 p-3 rounded-lg border bg-white/[0.02] border-destructive/20">
                  <div className="flex items-center gap-2 mb-1"><SevBadge sev={v.sev} /><span className="font-semibold text-[11px]">{v.type}</span></div>
                  <div className="text-[10px] font-mono ml-6 text-secondary-foreground break-all">{v.url}</div>
                  <div className="text-muted-foreground text-[9px] ml-6">{v.desc} — Param: {v.param}</div>
                </div>
              ))}</div>
            ))}

            {/* CORS */}
            {activeTab === 'cors' && (scanState.corsFindings.length === 0 ? <Empty msg="No CORS issues." /> : (
              <div>{scanState.corsFindings.map((c, i) => (
                <div key={i} className="mb-2 p-3 rounded-lg border bg-white/[0.02] border-destructive/20">
                  <div className="flex items-center gap-2 mb-1"><SevBadge sev={c.sev} /><span className="font-semibold text-[11px]">{c.host}</span><span className="text-muted-foreground text-[9px]">{c.type}</span></div>
                  <div className="text-[10px] font-mono ml-6">ACAO: {c.acao} | ACAC: {c.acac}</div>
                </div>
              ))}</div>
            ))}

            {/* NUCLEI */}
            {activeTab === 'nuclei' && (scanState.nucleiFindings.length === 0 ? <Empty msg="No nuclei matches." /> : (
              <div>{scanState.nucleiFindings.map((n, i) => (
                <div key={i} className="mb-2 p-3 rounded-lg border bg-white/[0.02] border-destructive/20">
                  <div className="flex items-center gap-2 mb-1"><SevBadge sev={n.sev} /><span className="font-semibold text-[11px]">{n.template}</span>{n.cve && <span className="text-destructive text-[9px]">{n.cve}</span>}</div>
                  <a href={n.url} target="_blank" rel="noreferrer" className="text-[10px] font-mono ml-6 text-primary no-underline hover:underline">{n.url}</a>
                </div>
              ))}</div>
            ))}

            {/* CONTENT */}
            {activeTab === 'content' && (scanState.contentFindings.length === 0 ? <Empty msg="No content discovered." /> : (
              <div>{scanState.contentFindings.map((c, i) => (
                <div key={i} className="flex items-center gap-2 py-[7px] border-b border-white/[0.03]">
                  <SevBadge sev={c.sev} /><StatusBadge status={c.status} />
                  <a href={c.url} target="_blank" rel="noreferrer" className="text-secondary-foreground no-underline hover:text-primary truncate text-[11px]">{c.path}</a>
                  <span className="ml-auto text-muted-foreground text-[9px]">{c.size}B</span>
                </div>
              ))}</div>
            ))}

            {/* DOM XSS */}
            {activeTab === 'domxss' && (scanState.domXss.length === 0 ? <Empty msg="No DOM XSS sinks found." /> : (
              <div>{scanState.domXss.map((d, i) => (
                <div key={i} className="mb-2 p-3 rounded-lg border bg-destructive/5 border-destructive/20">
                  <div className="flex items-center gap-2 mb-1"><SevBadge sev={d.sev} /><span className="font-mono text-[11px] text-primary">{d.sink}</span><span className="text-[9px] text-muted-foreground">×{d.count}</span></div>
                  <div className="text-muted-foreground text-[9px] ml-6">{d.file}</div>
                </div>
              ))}</div>
            ))}

            {/* COOKIES */}
            {activeTab === 'cookies' && (scanState.cookieFindings.length === 0 ? <Empty msg="No cookie issues found." /> : (
              <div>{scanState.cookieFindings.map((c, i) => (
                <div key={i} className="mb-2 p-3 rounded-lg border bg-white/[0.02] border-border">
                  <div className="flex items-center gap-2 mb-1"><Cookie size={12} className="text-primary" /><span className="font-semibold text-[11px]">{c.host}</span><span className="font-mono text-primary text-[10px]">{c.name}</span></div>
                  {c.issues.map((iss, j) => <div key={j} className="flex items-center gap-2 ml-6 text-[10px]"><SevBadge sev={iss.sev} /><span className="text-foreground/80">{iss.issue}</span></div>)}
                </div>
              ))}</div>
            ))}

            {/* GRAPHQL */}
            {activeTab === 'graphql' && (scanState.graphqlFindings.length === 0 ? <Empty msg="No GraphQL endpoints found." /> : (
              <div>{scanState.graphqlFindings.map((f, i) => (
                <div key={i} className="mb-2 p-3 rounded-lg border bg-white/[0.02] border-primary/20">
                  <div className="flex items-center gap-2 mb-1"><Database size={12} className="text-[hsl(var(--purple))]" /><span className="font-semibold text-[11px]">{f.host}</span><span className="text-[hsl(var(--purple))] text-[9px]">{f.typeCount} types</span></div>
                  <a href={f.url} target="_blank" rel="noreferrer" className="text-primary text-[10px] ml-6 no-underline hover:underline font-mono">{f.url}</a>
                </div>
              ))}</div>
            ))}

            {/* HTTP METHODS */}
            {activeTab === 'methods' && (scanState.methodsFindings.length === 0 ? <Empty msg="No dangerous HTTP methods found." /> : (
              <div>{scanState.methodsFindings.map((f, i) => (
                <div key={i} className="mb-2 p-3 rounded-lg border bg-white/[0.02] border-primary/20">
                  <div className="flex items-center gap-2 mb-1"><SevBadge sev={f.sev} /><span className="font-semibold text-[11px]">{f.host}</span></div>
                  <div className="text-[10px] font-mono ml-6">Allow: {f.allow}</div>
                  <div className="ml-6 flex gap-1 mt-1">{f.dangerous.map((m, j) => <span key={j} className="text-[9px] px-1.5 py-0.5 bg-destructive/10 border border-destructive/20 rounded text-destructive">{m}</span>)}</div>
                </div>
              ))}</div>
            ))}

            {/* VHOSTS */}
            {activeTab === 'vhosts' && ((scanState.vhostFindings || []).length === 0 ? <Empty msg="No virtual hosts found." /> : (
              <div>{(scanState.vhostFindings || []).map((f, i) => (
                <div key={i} className="mb-2 p-3 rounded-lg border bg-white/[0.02] border-primary/20">
                  <div className="flex items-center gap-2 mb-1"><SevBadge sev={f.sev} /><span className="font-semibold text-[11px]">{f.vhost}</span></div>
                  <div className="text-[10px] font-mono ml-6">IP: {f.ip} | Status: {f.status} | Size: {f.size}B</div>
                </div>
              ))}</div>
            ))}

            {/* SSTI/SQLi */}
            {activeTab === 'ssti' && ((scanState.sstiFindings || []).length === 0 ? <Empty msg="No SSTI/SQLi found." /> : (
              <div>{(scanState.sstiFindings || []).map((f, i) => (
                <div key={i} className="mb-2 p-3 rounded-lg border bg-destructive/5 border-destructive/20">
                  <div className="flex items-center gap-2 mb-1"><SevBadge sev={f.sev} /><span className="font-semibold text-[11px]">{f.type}</span></div>
                  <div className="text-[10px] font-mono ml-6 text-secondary-foreground break-all">{f.url}</div>
                  <div className="text-muted-foreground text-[9px] ml-6">Param: {f.param} | Payload: {f.payload}</div>
                </div>
              ))}</div>
            ))}

            {/* JWT */}
            {activeTab === 'jwt' && (scanState.jwtFindings.length === 0 ? <Empty msg="No JWT tokens found." /> : (
              <div>{scanState.jwtFindings.map((f, i) => (
                <div key={i} className="mb-2 p-3 rounded-lg border bg-white/[0.02] border-primary/20">
                  <div className="flex items-center gap-2 mb-1"><Key size={12} className="text-primary" /><span className="font-semibold text-[11px]">JWT Token</span><span className="text-muted-foreground text-[9px]">{f.source}</span></div>
                  <div className="text-[10px] font-mono ml-6 text-muted-foreground">Algorithm: {f.header?.alg || '?'}</div>
                  {f.issues.map((iss, j) => <div key={j} className="flex items-center gap-2 ml-6 text-[10px] mt-0.5"><SevBadge sev={iss.sev} /><span>{iss.issue}</span></div>)}
                </div>
              ))}</div>
            ))}

            {/* BLH */}
            {activeTab === 'blh' && (scanState.blhFindings.length === 0 ? <Empty msg="No broken links found." /> : (
              <div>{scanState.blhFindings.map((f, i) => (
                <div key={i} className="mb-2 p-3 rounded-lg border bg-white/[0.02] border-primary/20">
                  <div className="flex items-center gap-2 mb-1"><SevBadge sev={f.sev} /><span className="font-semibold text-[11px]">{f.domain}</span></div>
                  <div className="text-muted-foreground text-[9px] ml-6">{f.status}</div>
                  <a href={f.registerUrl} target="_blank" rel="noreferrer" className="text-primary text-[9px] ml-6 no-underline hover:underline">Check availability →</a>
                </div>
              ))}</div>
            ))}

            {/* DEP CONFUSION */}
            {activeTab === 'depconf' && (scanState.depConfFindings.length === 0 ? <Empty msg="No dependency confusion found." /> : (
              <div>{scanState.depConfFindings.map((f, i) => (
                <div key={i} className="mb-2 p-3 rounded-lg border bg-white/[0.02] border-destructive/20">
                  <div className="flex items-center gap-2 mb-1"><SevBadge sev={f.sev} /><span className="font-semibold text-[11px]">{f.pkg}</span></div>
                  <div className="text-muted-foreground text-[9px] ml-6">Registry: {f.registry} — {f.status}</div>
                </div>
              ))}</div>
            ))}

            {/* BOUNTY */}
            {activeTab === 'bounty' && (scanState.bountyFindings.length === 0 ? <Empty msg="No bug bounty programs detected." /> : (
              <div>{scanState.bountyFindings.map((f, i) => (
                <div key={i} className="mb-2 p-3 rounded-lg border bg-white/[0.02] border-[hsl(var(--green))]/20">
                  <div className="flex items-center gap-2 mb-1"><Award size={12} className="text-[hsl(var(--green))]" /><span className="font-semibold text-[11px]">{f.platform}</span><span className="text-[hsl(var(--green))] text-[9px]">{f.status}</span></div>
                  <a href={f.url} target="_blank" rel="noreferrer" className="text-primary text-[10px] ml-6 no-underline hover:underline font-mono">{f.url}</a>
                </div>
              ))}</div>
            ))}

            {/* IDOR */}
            {activeTab === 'idor' && (scanState.idorFindings.length === 0 ? <Empty msg="No IDOR vulnerabilities found." /> : (
              <div>{scanState.idorFindings.map((f, i) => (
                <div key={i} className="mb-2 p-3 rounded-lg border bg-white/[0.02] border-destructive/20">
                  <div className="flex items-center gap-2 mb-1"><SevBadge sev={f.sev} /><span className="font-semibold text-[11px]">IDOR — {f.param}</span></div>
                  <div className="text-[10px] font-mono ml-6 text-secondary-foreground break-all">{f.url}</div>
                  <div className="text-muted-foreground text-[9px] ml-6">{f.desc}</div>
                </div>
              ))}</div>
            ))}

            {/* RACE CONDITIONS */}
            {activeTab === 'race' && (scanState.raceFindings.length === 0 ? <Empty msg="No race conditions detected." /> : (
              <div>{scanState.raceFindings.map((f, i) => (
                <div key={i} className="mb-2 p-3 rounded-lg border bg-white/[0.02] border-destructive/20">
                  <div className="flex items-center gap-2 mb-1"><SevBadge sev={f.sev} /><span className="font-semibold text-[11px]">Race Condition</span></div>
                  <div className="text-[10px] font-mono ml-6 break-all">{f.url}</div>
                  <div className="text-muted-foreground text-[9px] ml-6">{f.desc}</div>
                </div>
              ))}</div>
            ))}

            {/* CACHE POISONING */}
            {activeTab === 'cache' && (scanState.cachePoisonFindings.length === 0 ? <Empty msg="No cache poisoning found." /> : (
              <div>{scanState.cachePoisonFindings.map((f, i) => (
                <div key={i} className="mb-2 p-3 rounded-lg border bg-white/[0.02] border-destructive/20">
                  <div className="flex items-center gap-2 mb-1"><SevBadge sev={f.sev} /><span className="font-semibold text-[11px]">{f.host}</span></div>
                  <div className="text-[10px] font-mono ml-6">{f.header}: {f.value}</div>
                  <div className="text-muted-foreground text-[9px] ml-6">{f.desc}</div>
                </div>
              ))}</div>
            ))}

            {/* CRLF */}
            {activeTab === 'crlf' && (scanState.crlfFindings.length === 0 ? <Empty msg="No CRLF injection found." /> : (
              <div>{scanState.crlfFindings.map((f, i) => (
                <div key={i} className="mb-2 p-3 rounded-lg border bg-white/[0.02] border-destructive/20">
                  <div className="flex items-center gap-2 mb-1"><SevBadge sev={f.sev} /><span className="font-semibold text-[11px]">CRLF Injection</span></div>
                  <div className="text-[10px] font-mono ml-6 break-all">{f.url}</div>
                </div>
              ))}</div>
            ))}

            {/* HOST HEADER INJECTION */}
            {activeTab === 'hostinj' && (scanState.hostInjectionFindings.length === 0 ? <Empty msg="No host header injection found." /> : (
              <div>{scanState.hostInjectionFindings.map((f, i) => (
                <div key={i} className="mb-2 p-3 rounded-lg border bg-white/[0.02] border-destructive/20">
                  <div className="flex items-center gap-2 mb-1"><SevBadge sev={f.sev} /><span className="font-semibold text-[11px]">Host Header Injection</span></div>
                  <div className="text-[10px] font-mono ml-6 break-all">{f.url}</div>
                  <div className="text-muted-foreground text-[9px] ml-6">{f.desc}</div>
                </div>
              ))}</div>
            ))}

            {/* EXPLOITS */}
            {activeTab === 'exploits' && (scanState.exploitFindings.length === 0 ? <Empty msg="No exploits found." /> : (
              <div>{scanState.exploitFindings.map((f, i) => (
                <div key={i} className="mb-2 p-3 rounded-lg border bg-white/[0.02] border-destructive/20">
                  <div className="flex items-center gap-2 mb-1"><Hammer size={12} className="text-destructive" /><span className="font-semibold text-[11px]">{f.title}</span><span className="text-destructive text-[9px]">{f.edb_id}</span></div>
                  <a href={f.url} target="_blank" rel="noreferrer" className="text-primary text-[10px] ml-6 no-underline hover:underline font-mono">{f.url}</a>
                </div>
              ))}</div>
            ))}

            {/* HEATMAP — NO LIMIT, ALL COLORS */}
            {activeTab === 'heatmap' && (scanState.subs.length === 0 ? <Empty msg="Run a scan to see heatmap." /> : (
              <div>
                <div className="flex items-center justify-between mb-3">
                  <div className="text-[11px] text-muted-foreground">Risk heatmap of ALL <span className="text-primary font-bold">{scanState.subs.length.toLocaleString()}</span> subdomains (0–100)</div>
                  <div className="flex gap-3 text-[9px] text-muted-foreground">
                    <span className="flex items-center gap-1"><div className="w-3 h-3 rounded-sm" style={{background:'hsl(0,80%,55%)'}} /> ≥70</span>
                    <span className="flex items-center gap-1"><div className="w-3 h-3 rounded-sm" style={{background:'hsl(25,90%,55%)'}} /> ≥50</span>
                    <span className="flex items-center gap-1"><div className="w-3 h-3 rounded-sm" style={{background:'hsl(45,95%,55%)'}} /> ≥30</span>
                    <span className="flex items-center gap-1"><div className="w-3 h-3 rounded-sm" style={{background:'hsl(180,55%,45%)'}} /> ≥15</span>
                    <span className="flex items-center gap-1"><div className="w-3 h-3 rounded-sm" style={{background:'hsl(140,50%,40%)'}} /> &lt;15</span>
                  </div>
                </div>
                <div className="flex flex-wrap gap-[3px]">
                  {scanState.subs.map((s, i) => {
                    let score = 5;
                    if (s.tko) score += 50;
                    if (s.ports.some(p => [3306,5432,27017,6379,9200,3389,21,23,25,11211].includes(p))) score += 35;
                    if (s.ports.length > 0) score += 8;
                    if (/admin|dev|vpn|api|internal|staging|test|beta|jenkins|gitlab|jira|wiki|backup|stage|qa|uat|prod|root|sql|db|console/.test(s.subdomain)) score += 25;
                    if (s.alive) score += 10;
                    if (s.httpStatus >= 500) score += 8;
                    score = Math.min(100, score);
                    const hue = score >= 70 ? 0 : score >= 50 ? 25 : score >= 30 ? 45 : score >= 15 ? 180 : 140;
                    const sat = score >= 70 ? 80 : score >= 30 ? 90 : 50;
                    const light = score >= 70 ? 55 : score >= 30 ? 55 : 42;
                    return <div key={i} className="w-[14px] h-[14px] rounded-sm cursor-pointer transition-transform hover:scale-150 hover:z-10 hover:ring-2 hover:ring-primary/60" style={{background:`hsl(${hue},${sat}%,${light}%)`}} title={`${s.subdomain} — risk ${score}`} />;
                  })}
                </div>
              </div>
            ))}

            {/* THREAT MAP */}
            {activeTab === 'threatmap' && (Object.keys(scanState.ips).length === 0 ? <Empty msg="Run a scan to see threat map." /> : (
              <Suspense fallback={<div className="text-center py-10 text-muted-foreground">Loading map…</div>}>
                <ThreatMap ips={scanState.ips} />
              </Suspense>
            ))}

            {/* JS CODE ANALYZER */}
            {activeTab === 'jsanalyzer' && ((scanState.jsCodeFindings?.length || 0) === 0 ? <Empty msg="No JS code analysis findings." /> : (
              <div>
                {/* Summary */}
                <div className="mb-4 p-3 rounded-lg border border-primary/20 bg-primary/5">
                  <div className="text-[11px] font-semibold text-primary mb-2">JS Code Analysis Summary</div>
                  <div className="grid grid-cols-4 gap-2 text-[10px]">
                    <div><span className="text-muted-foreground">Endpoints:</span> <span className="text-[hsl(var(--teal))]">{scanState.jsCodeFindings.filter(f => f.category === 'endpoint').length}</span></div>
                    <div><span className="text-muted-foreground">Bugs:</span> <span className="text-destructive">{scanState.jsCodeFindings.filter(f => f.category === 'bug').length}</span></div>
                    <div><span className="text-muted-foreground">Secrets:</span> <span className="text-primary">{scanState.jsCodeFindings.filter(f => f.category === 'secret').length}</span></div>
                    <div><span className="text-muted-foreground">Info:</span> <span className="text-muted-foreground">{scanState.jsCodeFindings.filter(f => f.category === 'info').length}</span></div>
                  </div>
                </div>
                {/* Filter by category */}
                {['bug', 'endpoint', 'secret', 'info'].map(cat => {
                  const items = scanState.jsCodeFindings.filter(f => f.category === cat);
                  if (!items.length) return null;
                  return (
                    <div key={cat} className="mb-4">
                      <h3 className="text-[11px] font-bold tracking-[0.1em] uppercase mb-2" style={{ color: cat === 'bug' ? 'hsl(0,72%,60%)' : cat === 'endpoint' ? 'hsl(var(--teal))' : cat === 'secret' ? 'hsl(var(--amber))' : 'hsl(var(--muted-foreground))' }}>
                        {cat === 'bug' ? '🐛 Security Bugs' : cat === 'endpoint' ? '🔗 Extracted Endpoints' : cat === 'secret' ? '🔑 Secrets' : 'ℹ️ Info'} ({items.length})
                      </h3>
                      {items.filter(f => !filter || f.match.toLowerCase().includes(filter.toLowerCase()) || f.file.toLowerCase().includes(filter.toLowerCase())).map((f, i) => (
                        <div key={i} className="mb-1.5 p-2.5 rounded-lg border bg-white/[0.02] border-border hover:border-primary/20 transition-colors">
                          <div className="flex items-center gap-2 mb-0.5">
                            <SevBadge sev={f.sev} />
                            <span className="font-semibold text-[10px]">{f.type}</span>
                          </div>
                          <div className="text-primary text-[10px] font-mono ml-6 break-all">{f.match}</div>
                          <div className="text-muted-foreground text-[8px] ml-6 truncate">File: {f.file}</div>
                        </div>
                      ))}
                    </div>
                  );
                })}
              </div>
            ))}

            {/* RISK SCORE — Animated gauge */}
            {activeTab === 'risk' && (() => {
              const score = scanState.riskScore || 0;
              const grade = scanState.riskGrade || 'N/A';
              const color = grade === 'CRITICAL' ? 'hsl(0,80%,58%)' : grade === 'HIGH' ? 'hsl(25,95%,55%)' : grade === 'MEDIUM' ? 'hsl(45,95%,55%)' : 'hsl(140,55%,50%)';
              const C = 2 * Math.PI * 90; // circumference
              const offset = C - (score / 100) * C * 0.75;
              return (
                <div className="py-6">
                  <div className="flex flex-col items-center">
                    <div className="relative" style={{ width: 260, height: 260 }}>
                      <svg viewBox="0 0 220 220" className="w-full h-full -rotate-[225deg]">
                        <defs>
                          <linearGradient id="riskGrad" x1="0" x2="1">
                            <stop offset="0" stopColor="hsl(140,55%,50%)" />
                            <stop offset="0.5" stopColor="hsl(45,95%,55%)" />
                            <stop offset="1" stopColor="hsl(0,80%,58%)" />
                          </linearGradient>
                        </defs>
                        <circle cx="110" cy="110" r="90" fill="none" stroke="hsl(var(--border))" strokeWidth="14" strokeLinecap="round" strokeDasharray={`${C * 0.75} ${C}`} />
                        <circle cx="110" cy="110" r="90" fill="none" stroke="url(#riskGrad)" strokeWidth="14" strokeLinecap="round"
                          strokeDasharray={`${C * 0.75} ${C}`} strokeDashoffset={offset}
                          style={{ transition: 'stroke-dashoffset 1.6s cubic-bezier(.2,.9,.3,1)', filter: `drop-shadow(0 0 14px ${color})` }} />
                      </svg>
                      <div className="absolute inset-0 flex flex-col items-center justify-center">
                        <div className="text-[12px] font-mono uppercase tracking-[0.3em] text-muted-foreground">Risk</div>
                        <div className="text-[72px] font-bold leading-none font-mono tabular-nums" style={{ color, textShadow: `0 0 24px ${color}66` }}>{score}</div>
                        <div className="text-[11px] font-mono text-muted-foreground">/ 100</div>
                        <div className="mt-2 px-3 py-0.5 rounded-full text-[11px] font-bold tracking-[0.18em] border" style={{ color, borderColor: color, background: `${color}14` }}>{grade}</div>
                      </div>
                    </div>
                    <div className="mt-6 grid grid-cols-2 md:grid-cols-4 gap-2.5 w-full max-w-3xl">
                      {[
                        { label: 'Subdomains', val: scanState.subs.length, color: 'hsl(180,55%,55%)' },
                        { label: 'Live Hosts', val: scanState.subs.filter(s => s.alive).length, color: 'hsl(140,55%,50%)' },
                        { label: 'Unique IPs', val: Object.keys(scanState.ips).length, color: 'hsl(200,75%,55%)' },
                        { label: 'Endpoints', val: scanState.eps.length, color: 'hsl(45,95%,55%)' },
                        { label: 'JS Files', val: scanState.js.length, color: 'hsl(60,80%,55%)' },
                        { label: 'Secrets', val: scanState.secrets.length, color: 'hsl(0,80%,58%)' },
                        { label: 'CORS', val: scanState.corsFindings.length, color: 'hsl(25,95%,55%)' },
                        { label: 'Nuclei', val: scanState.nucleiFindings.length, color: 'hsl(0,80%,58%)' },
                        { label: 'IDOR', val: scanState.idorFindings.length, color: 'hsl(0,80%,58%)' },
                        { label: 'Takeover', val: scanState.takeover.length, color: 'hsl(0,80%,58%)' },
                        { label: 'Exploits', val: scanState.exploitFindings.length, color: 'hsl(0,80%,58%)' },
                        { label: 'Dark Web', val: scanState.darkWebFindings.length, color: 'hsl(280,60%,60%)' },
                      ].map(s => (
                        <div key={s.label} className="p-3 rounded-lg border bg-white/[0.02] border-border hover:border-primary/30 transition-all">
                          <div className="text-[9px] uppercase tracking-[0.16em] text-muted-foreground mb-1">{s.label}</div>
                          <div className="text-[22px] font-bold font-mono tabular-nums" style={{ color: s.color }}>{Number(s.val).toLocaleString()}</div>
                        </div>
                      ))}
                    </div>
                    <div className="mt-5 text-[10.5px] text-muted-foreground font-mono text-center max-w-xl">
                      Composite risk uses subdomain count, exposed dangerous ports, secret/CVE findings, takeover signals, dark-web/breach hits and active vulnerabilities.
                    </div>
                  </div>
                </div>
              );
            })()}

            {/* DIFF */}
            {activeTab === 'diff' && (
              <div className="text-center py-10">
                <div className="text-2xl mb-2.5 opacity-50">⇄</div>
                <p className="text-muted-foreground text-[13px]">Load two scans from History to compare differences</p>
                <p className="text-muted-foreground text-[11px] mt-2">New subdomains (green) and removed subdomains (red) will be shown</p>
              </div>
            )}

            {/* QUEUE */}
            {activeTab === 'queue' && (
              <div>
                <div className="mb-4">
                  <div className="text-[11px] font-semibold text-primary mb-2">Batch Scanner — Enter one domain per line</div>
                  <textarea value={queueDomains} onChange={e => setQueueDomains(e.target.value)} rows={5} placeholder="tesla.com&#10;google.com&#10;github.com"
                    className="w-full bg-white/[0.04] border border-border rounded-lg p-3 text-foreground font-mono text-[12px] outline-none focus:border-primary/30 resize-none" />
                  <button onClick={runQueueScan} disabled={scanning || !queueDomains.trim()}
                    className="mt-2 px-4 py-2 rounded-lg scan-btn-gradient text-white text-xs font-bold disabled:opacity-40">
                    Start Queue Scan
                  </button>
                </div>
                {queueStatus.length > 0 && (
                  <table className="w-full text-xs"><thead><tr className="text-muted-foreground border-b border-border">
                    <th className="pb-2 text-left">Domain</th><th className="pb-2 text-left">Status</th>
                  </tr></thead>
                  <tbody>{queueStatus.map((q, i) => (
                    <tr key={i} className="border-t border-white/[0.035]">
                      <td className="py-2 text-primary">{q.domain}</td>
                      <td className={`py-2 ${q.status.includes('Done') ? 'text-[hsl(var(--green))]' : q.status.includes('Scanning') ? 'text-primary' : 'text-muted-foreground'}`}>{q.status}</td>
                    </tr>
                  ))}</tbody></table>
                )}
              </div>
            )}

            {/* DARK WEB */}
            {activeTab === 'darkweb' && (scanState.darkWebFindings.length === 0 ? <Empty msg="No dark web intel found." /> : (
              <div>{scanState.darkWebFindings.map((d, i) => (
                <div key={i} className="mb-2 p-3 rounded-lg border bg-white/[0.02] border-border">
                  <div className="flex items-center gap-2 mb-1"><SevBadge sev={d.severity} /><span className="font-semibold text-[11px]">{d.source}</span></div>
                  <div className="text-foreground/80 text-[11px] ml-6">{d.title}</div>
                  <div className="text-muted-foreground text-[9px] ml-6">{d.detail}</div>
                  {d.url && <a href={d.url} target="_blank" rel="noreferrer" className="text-primary text-[9px] ml-6 no-underline hover:underline">{d.url}</a>}
                </div>
              ))}</div>
            ))}

            {/* BREACHES */}
            {activeTab === 'breaches' && (scanState.darkWebFindings.filter(d => d.type === 'breach').length === 0 ? <Empty msg="No breaches found." /> : (
              <div>{scanState.darkWebFindings.filter(d => d.type === 'breach').map((d, i) => (
                <div key={i} className="mb-2 p-3 rounded-lg border bg-destructive/5 border-destructive/20">
                  <div className="flex items-center gap-2 mb-1"><SevBadge sev={d.severity} /><span className="font-semibold text-[11px]">{d.title}</span></div>
                  <div className="text-muted-foreground text-[10px] ml-6">{d.detail}</div>
                  {d.date && <div className="text-[9px] text-muted-foreground ml-6">Date: {d.date}</div>}
                </div>
              ))}</div>
            ))}

            {/* PASTES */}
            {activeTab === 'pastes' && ((scanState.pasteFindings || []).length === 0 ? <Empty msg="No paste site mentions found." /> : (
              <div>{(scanState.pasteFindings || []).map((p, i) => (
                <div key={i} className="mb-2 p-3 rounded-lg border bg-white/[0.02] border-border">
                  <div className="flex items-center gap-2 mb-1"><FileText size={12} className="text-primary" /><span className="font-semibold text-[11px]">{p.source}</span></div>
                  <a href={p.url} target="_blank" rel="noreferrer" className="text-primary text-[10px] ml-6 no-underline hover:underline font-mono">{p.url}</a>
                  {p.snippet && <div className="text-muted-foreground text-[9px] ml-6 mt-1">{p.snippet.slice(0, 150)}</div>}
                </div>
              ))}</div>
            ))}

            {/* URLSCAN */}
            {activeTab === 'urlscan' && (scanState.uscan.length === 0 ? <Empty msg="No URLScan data." /> : (
              <div>{scanState.uscan.map((u: any, i: number) => (
                <div key={i} className="flex items-center gap-2 py-[7px] border-b border-white/[0.03]">
                  <span className="text-muted-foreground w-8 text-right shrink-0">{i + 1}</span>
                  <span className="text-secondary-foreground text-[11px] truncate">{u.url || u}</span>
                </div>
              ))}</div>
            ))}

            {/* INTEL */}
            {activeTab === 'intel' && (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div className="bg-white/[0.028] border border-border rounded-[14px] p-3">
                  <div className="text-[10px] font-bold text-primary uppercase mb-2">OTX AlienVault</div>
                  <div className="text-[11px]">Pulses: {scanState.otx.p} | Malware: {scanState.otx.m} | URLs: {scanState.otx.u}</div>
                </div>
                <div className="bg-white/[0.028] border border-border rounded-[14px] p-3">
                  <div className="text-[10px] font-bold text-primary uppercase mb-2">CVE Summary</div>
                  <div className="text-[11px]">{Object.values(scanState.ips).reduce((a: number, v: any) => a + (v.cves?.length || 0), 0)} CVEs across {Object.keys(scanState.ips).length} IPs</div>
                </div>
                <div className="bg-white/[0.028] border border-border rounded-[14px] p-3">
                  <div className="text-[10px] font-bold text-primary uppercase mb-2">WAF</div>
                  <div className="text-[11px]">{scanState.waf !== 'unknown' ? scanState.waf : 'Not detected'}</div>
                </div>
                <div className="bg-white/[0.028] border border-border rounded-[14px] p-3">
                  <div className="text-[10px] font-bold text-primary uppercase mb-2">Technologies</div>
                  <div className="flex flex-wrap gap-1">{scanState.tech.map((t, i) => <span key={i} className="text-[9px] px-1.5 py-0.5 bg-primary/10 rounded text-primary">{t}</span>)}</div>
                </div>
              </div>
            )}

            {/* TECH */}
            {activeTab === 'tech' && (scanState.tech.length === 0 ? <Empty msg="No technologies detected." /> : (
              <div className="flex flex-wrap gap-2">
                {scanState.tech.map((t, i) => <span key={i} className="px-3 py-1.5 bg-primary/10 border border-primary/20 rounded-lg text-primary text-sm font-medium">{t}</span>)}
              </div>
            ))}

            {/* HISTORY */}
            {activeTab === 'history' && (!historyUnlocked ? (
              <div className="flex flex-col items-center justify-center py-20 px-6">
                <Lock size={36} className="text-primary/60 mb-4" />
                <div className="text-sm font-bold text-foreground mb-1">History is locked</div>
                <p className="text-[11.5px] text-muted-foreground mb-5 text-center max-w-sm">
                  Enter the access passphrase to unlock the scan history vault.
                </p>
                <form onSubmit={(e) => {
                  e.preventDefault();
                  if (historyKeyInput === HISTORY_PASSPHRASE) {
                    setHistoryUnlocked(true);
                    try { localStorage.setItem(HISTORY_UNLOCK_KEY, '1'); } catch { /* ignore */ }
                    toast.success('🔓 History unlocked');
                  } else {
                    toast.error('Wrong passphrase');
                    setHistoryKeyInput('');
                  }
                }} className="flex gap-2 w-full max-w-sm">
                  <input type="password" value={historyKeyInput} onChange={e => setHistoryKeyInput(e.target.value)}
                    placeholder="Access passphrase…"
                    className="flex-1 bg-background/60 border border-border rounded-lg px-3 py-2 text-xs text-foreground font-mono outline-none focus:border-primary/40" />
                  <button type="submit" className="px-4 py-2 rounded-lg bg-primary/15 border border-primary/30 text-primary text-xs font-bold hover:bg-primary/25">
                    Unlock
                  </button>
                </form>
              </div>
            ) : (history.length === 0 ? <Empty msg="No scan history yet." /> : (
              <div>
                <div className="flex items-center justify-between mb-2 px-2">
                  <span className="text-[10.5px] text-muted-foreground">{history.length} scan{history.length === 1 ? '' : 's'} stored</span>
                  <button onClick={() => { setHistoryUnlocked(false); try { localStorage.removeItem(HISTORY_UNLOCK_KEY); } catch { /* ignore */ } toast.info('History re-locked'); }}
                    className="text-[10px] text-muted-foreground hover:text-destructive flex items-center gap-1">
                    <Lock size={9} /> Re-lock
                  </button>
                </div>
                {history.map(h => (
                  <div key={h.id} className="flex items-center gap-3 py-2.5 px-3 border-b border-white/[0.03] hover:bg-primary/[0.02] cursor-pointer transition-colors"
                    onClick={async () => {
                      const { data } = await supabase.from('scan_results').select('scan_data, domain').eq('id', h.id).maybeSingle();
                      if (data?.scan_data) { setScanState({ ...createScanState(), ...(data.scan_data as Record<string, any>) } as ScanState); setTarget(data.domain); setActiveTab('sub'); toast.success(`Loaded scan for ${data.domain}`); }
                    }}>
                    <Globe size={14} className="text-primary shrink-0" />
                    <span className="text-primary font-semibold text-[12px]">{h.domain}</span>
                    <span className="text-muted-foreground text-[9px] font-mono">{h.scan_type}</span>
                    <span className="ml-auto text-muted-foreground text-[9px] font-mono">{new Date(h.created_at).toLocaleString()}</span>
                  </div>
                ))}
              </div>
            )))}
          </div>
        </div>
      </div>

      {/* MODALS */}
      <JSAnalyzerModal open={showAnalyzer} onClose={() => setShowAnalyzer(false)} initialTarget={analyzerTarget} />
      <ProxySettingsPanel open={showProxySettings} onClose={() => setShowProxySettings(false)} />

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
          <span className="text-[10.5px] text-muted-foreground">© 2025 TeamCyberOps — For authorized security testing only — NO LIMITS</span>
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
    : status >= 300 && status < 400 ? 'bg-primary/8 text-primary border-primary/20'
    : status >= 400 ? 'bg-destructive/8 text-destructive border-destructive/20'
    : 'bg-muted text-muted-foreground border-border';
  return <span className={`px-1.5 py-0.5 rounded text-[9px] border font-mono ${cls}`}>{status}</span>;
};

const SevBadge = ({ sev }: { sev: string }) => {
  const s = sev?.toUpperCase() || 'INFO';
  const cls = s === 'CRITICAL' || s === 'HIGH' ? 'bg-destructive/8 border-destructive/20 text-destructive'
    : s === 'MEDIUM' ? 'bg-primary/8 border-primary/20 text-primary'
    : s === 'LOW' ? 'bg-[hsl(var(--teal))]/8 border-[hsl(var(--teal))]/20 text-[hsl(var(--teal))]'
    : 'bg-white/[0.04] border-white/[0.08] text-muted-foreground';
  return <span className={`inline-flex items-center rounded-md px-2 py-0.5 text-[9.5px] font-semibold tracking-[0.04em] border ${cls}`}>{s}</span>;
};

export default Index;
