import { useState, useMemo, useEffect } from 'react';
import { Search, Copy, Check, Star, Download, ExternalLink, Microscope, X, Zap, Filter as FilterIcon } from 'lucide-react';
import { ONELINERS_DATA, SECTION_NAMES, CATEGORIES, MODULE_LINKS } from '@/data/onelinersData';

const TAG_COLORS: Record<string, string> = {
  bash: 'bg-[hsl(var(--green))]/10 text-[hsl(var(--green))] border-[hsl(var(--green))]/25',
  py: 'bg-[hsl(var(--info))]/10 text-[hsl(var(--info))] border-[hsl(var(--info))]/25',
  api: 'bg-[hsl(var(--purple))]/10 text-[hsl(var(--purple))] border-[hsl(var(--purple))]/25',
  java: 'bg-[hsl(var(--pink))]/10 text-[hsl(var(--pink))] border-[hsl(var(--pink))]/25',
  ps: 'bg-[hsl(var(--teal))]/10 text-[hsl(var(--teal))] border-[hsl(var(--teal))]/25',
};

// Lightweight JS analyzer — runs in-browser, no upload needed
const JS_PATTERNS: { name: string; sev: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'; re: RegExp; cat: 'bug' | 'endpoint' | 'secret' | 'info' }[] = [
  { name: 'eval() usage', sev: 'CRITICAL', re: /\beval\s*\(/g, cat: 'bug' },
  { name: 'Function() constructor', sev: 'HIGH', re: /\bnew\s+Function\s*\(/g, cat: 'bug' },
  { name: 'innerHTML sink', sev: 'HIGH', re: /\.innerHTML\s*=/g, cat: 'bug' },
  { name: 'document.write', sev: 'HIGH', re: /document\.write\s*\(/g, cat: 'bug' },
  { name: 'dangerouslySetInnerHTML', sev: 'HIGH', re: /dangerouslySetInnerHTML/g, cat: 'bug' },
  { name: 'location assignment', sev: 'MEDIUM', re: /location\s*=\s*[^;]+/g, cat: 'bug' },
  { name: 'postMessage *', sev: 'MEDIUM', re: /postMessage\s*\([^,]+,\s*['"]\*['"]\s*\)/g, cat: 'bug' },
  { name: 'Debug flag enabled', sev: 'LOW', re: /(?:debug|dev_mode)\s*[:=]\s*true/gi, cat: 'bug' },
  { name: 'AWS Access Key', sev: 'CRITICAL', re: /\b(AKIA[0-9A-Z]{16})\b/g, cat: 'secret' },
  { name: 'Generic API Key', sev: 'HIGH', re: /(?:api[_-]?key|apikey|secret|token)\s*[:=]\s*['"]([A-Za-z0-9_\-]{20,})['"]/gi, cat: 'secret' },
  { name: 'Bearer token', sev: 'HIGH', re: /Bearer\s+[A-Za-z0-9\-_=.]{20,}/g, cat: 'secret' },
  { name: 'Google API Key', sev: 'HIGH', re: /\bAIza[0-9A-Za-z\-_]{35}\b/g, cat: 'secret' },
  { name: 'JWT', sev: 'MEDIUM', re: /\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b/g, cat: 'secret' },
  { name: 'Slack token', sev: 'CRITICAL', re: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g, cat: 'secret' },
  { name: 'API endpoint', sev: 'LOW', re: /['"`](\/[a-zA-Z0-9_\-./]{3,}\/(?:api|v1|v2|v3|graphql|rest)[a-zA-Z0-9_\-./?=&]*)['"`]/g, cat: 'endpoint' },
  { name: 'Absolute URL', sev: 'LOW', re: /['"`](https?:\/\/[^'"`\s<>]{8,200})['"`]/g, cat: 'endpoint' },
  { name: 'Source map exposed', sev: 'LOW', re: /sourceMappingURL\s*=/g, cat: 'info' },
];

interface JSFinding { name: string; sev: string; cat: string; match: string; }

const Oneliners = () => {
  const [search, setSearch] = useState('');
  const [category, setCategory] = useState('all');
  const [tagFilter, setTagFilter] = useState('all');
  const [copied, setCopied] = useState<string | null>(null);
  const [favs, setFavs] = useState<Set<string>>(new Set());
  const [showFavs, setShowFavs] = useState(false);
  const [showAnalyzer, setShowAnalyzer] = useState(false);
  const [jsInput, setJsInput] = useState('');
  const [jsResults, setJsResults] = useState<JSFinding[] | null>(null);
  const [analyzing, setAnalyzing] = useState(false);

  // Load favs
  useEffect(() => {
    try {
      const s = localStorage.getItem('webrecox-fav-oneliners');
      if (s) setFavs(new Set(JSON.parse(s)));
    } catch { /* */ }
  }, []);

  const toggleFav = (id: string) => {
    setFavs(prev => {
      const n = new Set(prev);
      n.has(id) ? n.delete(id) : n.add(id);
      try { localStorage.setItem('webrecox-fav-oneliners', JSON.stringify([...n])); } catch { /* */ }
      return n;
    });
  };

  const allTags = useMemo(() => {
    const s = new Set<string>();
    ONELINERS_DATA.forEach(c => c.t.forEach(t => s.add(t)));
    return [...s];
  }, []);

  const filtered = useMemo(() => {
    return ONELINERS_DATA.filter((cmd, i) => {
      const id = `${cmd.c}-${i}`;
      const catMatch = category === 'all' || cmd.c === category;
      const tagMatch = tagFilter === 'all' || cmd.t.includes(tagFilter);
      const favMatch = !showFavs || favs.has(id);
      const q = search.toLowerCase();
      const searchMatch = !q || (cmd.n + ' ' + cmd.d + ' ' + cmd.q + ' ' + cmd.c).toLowerCase().includes(q);
      return catMatch && tagMatch && favMatch && searchMatch;
    }).map((cmd, i) => ({ cmd, id: `${cmd.c}-${ONELINERS_DATA.indexOf(cmd)}` }));
  }, [search, category, tagFilter, showFavs, favs]);

  const grouped = useMemo(() => {
    const g: Record<string, typeof filtered> = {};
    filtered.forEach(item => {
      if (!g[item.cmd.c]) g[item.cmd.c] = [];
      g[item.cmd.c].push(item);
    });
    return g;
  }, [filtered]);

  const handleCopy = (q: string, id: string) => {
    navigator.clipboard.writeText(q);
    setCopied(id);
    setTimeout(() => setCopied(null), 1500);
  };

  const exportCSV = () => {
    const rows = [
      ['Category', 'Name', 'Description', 'Tags', 'Module', 'Command'],
      ...filtered.map(({ cmd }) => [
        cmd.c, cmd.n, cmd.d, cmd.t.join('|'),
        MODULE_LINKS[cmd.c]?.label || '',
        cmd.q,
      ]),
    ];
    const csv = rows.map(r => r.map(c => `"${String(c).replace(/"/g, '""')}"`).join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `webrecox-oneliners-${Date.now()}.csv`;
    a.click(); URL.revokeObjectURL(url);
  };

  const analyzeJS = async (text: string) => {
    setAnalyzing(true);
    setJsResults(null);
    await new Promise(r => setTimeout(r, 50));
    const seen = new Set<string>();
    const out: JSFinding[] = [];
    for (const p of JS_PATTERNS) {
      const re = new RegExp(p.re.source, p.re.flags);
      let m: RegExpExecArray | null;
      while ((m = re.exec(text)) !== null) {
        const match = (m[1] || m[0]).slice(0, 200);
        if (p.cat === 'endpoint') {
          if (/\.(css|png|jpg|jpeg|svg|gif|ico|woff2?|ttf|eot|map)$/i.test(match)) continue;
          if (match.length < 4) continue;
        }
        const k = `${p.name}|${match}`;
        if (seen.has(k)) continue;
        seen.add(k);
        out.push({ name: p.name, sev: p.sev, cat: p.cat, match });
        if (out.length > 5000) break;
      }
      if (out.length > 5000) break;
    }
    setJsResults(out);
    setAnalyzing(false);
  };

  const onFile = (e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0];
    if (!f) return;
    const r = new FileReader();
    r.onload = () => {
      const txt = String(r.result || '');
      setJsInput(txt.slice(0, 5_000_000));
      analyzeJS(txt);
    };
    r.readAsText(f);
  };

  const sevColor = (s: string) =>
    s === 'CRITICAL' ? 'hsl(0,82%,58%)' :
    s === 'HIGH' ? 'hsl(25,95%,55%)' :
    s === 'MEDIUM' ? 'hsl(45,95%,55%)' :
    'hsl(var(--muted-foreground))';

  const catCounts = useMemo(() => {
    const c: Record<string, number> = {};
    ONELINERS_DATA.forEach(o => { c[o.c] = (c[o.c] || 0) + 1; });
    return c;
  }, []);

  return (
    <div className="min-h-screen bg-background">
      {/* Header — matches Index */}
      <nav className="sticky top-0 z-50 bg-background/85 border-b border-primary/10 backdrop-blur-[20px]">
        <div className="max-w-[1400px] mx-auto px-5 h-[60px] flex items-center gap-3">
          <a href="/" className="flex items-center gap-2.5 no-underline">
            <img src="https://github.com/mohidqx.png" alt="TeamCyberOps"
              className="w-9 h-9 rounded-full border-2 border-primary/40 shadow-[0_0_20px_hsla(38,92%,50%,0.25)]" />
            <div className="leading-tight">
              <div className="text-[15px] font-extrabold tracking-[0.04em] uppercase">
                <span className="text-foreground">Web</span><span className="text-primary">Recox</span>
              </div>
              <div className="text-[8.5px] text-muted-foreground font-mono tracking-[0.18em] uppercase">Bug Bounty Oneliners</div>
            </div>
          </a>
          <span className="hidden md:inline-flex font-mono text-[8.5px] px-2 py-0.5 rounded-full bg-primary/10 border border-primary/30 text-primary tracking-[0.18em] uppercase ml-2">
            {ONELINERS_DATA.length}+ Commands
          </span>
          <div className="ml-auto flex items-center gap-2">
            <button onClick={() => setShowAnalyzer(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-[hsl(var(--purple))]/30 bg-[hsl(var(--purple))]/8 text-[hsl(var(--purple))] text-[10.5px] font-semibold hover:bg-[hsl(var(--purple))]/15 transition-colors">
              <Microscope size={11} /> JS Analyzer
            </button>
            <button onClick={exportCSV}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-border bg-white/[0.04] text-foreground text-[10.5px] font-semibold hover:bg-white/[0.07] transition-colors">
              <Download size={11} /> CSV
            </button>
            <a href="/" className="px-3 py-1.5 rounded-lg border border-primary/25 bg-primary/8 text-primary text-[10.5px] font-semibold no-underline hover:bg-primary/15 transition-colors">
              ← Recon
            </a>
          </div>
        </div>
      </nav>

      <div className="max-w-[1400px] mx-auto px-5 py-9">
        {/* Hero */}
        <div className="text-center mb-9 animate-fade-in-up">
          <div className="inline-flex items-center gap-2 bg-primary/8 border border-primary/25 rounded-full px-4 py-1.5 text-[11px] font-bold tracking-[0.12em] text-primary uppercase mb-5">
            <Zap size={11} /> Oneliner Library
          </div>
          <h1 className="hero-gradient text-[clamp(2rem,5vw,3.6rem)] font-bold leading-[1.05] tracking-[-0.04em] mb-3">
            ⚡ {ONELINERS_DATA.length}+ Bug-Bounty <br />Oneliners
          </h1>
          <p className="text-muted-foreground max-w-[640px] mx-auto leading-[1.7] text-[13px]">
            Curated commands across <span className="text-primary font-semibold">{CATEGORIES.length}</span> categories — tagged, searchable, deep-linked into the WebRecox dashboard.
            <br/>Replace <code className="text-primary font-mono">example.com</code> with your authorised target.
          </p>
        </div>

        {/* Filter card */}
        <div className="bg-card/55 border border-primary/10 rounded-[18px] p-[18px_22px] backdrop-blur-[20px] mb-6">
          <div className="flex gap-2.5 mb-3 flex-wrap items-center">
            <div className="flex-1 min-w-[220px] relative">
              <Search size={14} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-muted-foreground" />
              <input
                className="w-full pl-9 pr-3 py-2.5 bg-white/[0.04] border border-primary/10 rounded-[10px] font-mono text-[12px] text-foreground placeholder:text-muted-foreground focus:outline-none focus:border-primary/40 focus:bg-primary/[0.04] focus:shadow-[0_0_0_3px_hsla(38,92%,50%,0.1)] transition-all"
                placeholder="Search commands, tools, descriptions…"
                value={search}
                onChange={e => setSearch(e.target.value)}
              />
            </div>
            <button onClick={() => setShowFavs(s => !s)}
              className={`px-3 py-2 rounded-[10px] text-[10.5px] font-semibold border transition-all flex items-center gap-1.5 ${showFavs ? 'bg-primary/15 border-primary/40 text-primary' : 'bg-white/[0.04] border-border text-muted-foreground hover:text-foreground'}`}>
              <Star size={11} fill={showFavs ? 'currentColor' : 'none'} />
              Favorites {favs.size > 0 && <span className="text-[8.5px] opacity-70">({favs.size})</span>}
            </button>
          </div>

          <div className="flex flex-wrap gap-1.5 mb-2">
            <span className="text-[8.5px] font-bold tracking-[0.14em] uppercase text-muted-foreground self-center mr-1">
              <FilterIcon size={9} className="inline mr-1" />Category:
            </span>
            <button onClick={() => setCategory('all')}
              className={`px-2.5 py-1 rounded text-[10px] border transition-colors ${category === 'all' ? 'border-primary/40 text-primary bg-primary/12' : 'border-border text-muted-foreground bg-transparent hover:text-foreground'}`}>
              All <span className="opacity-60">({ONELINERS_DATA.length})</span>
            </button>
            {CATEGORIES.map(c => (
              <button key={c} onClick={() => setCategory(c)}
                className={`px-2.5 py-1 rounded text-[10px] border transition-colors whitespace-nowrap ${category === c ? 'border-primary/40 text-primary bg-primary/12' : 'border-border text-muted-foreground bg-transparent hover:text-foreground'}`}>
                {c} <span className="opacity-60">({catCounts[c] || 0})</span>
              </button>
            ))}
          </div>

          <div className="flex flex-wrap gap-1.5">
            <span className="text-[8.5px] font-bold tracking-[0.14em] uppercase text-muted-foreground self-center mr-1">Tag:</span>
            <button onClick={() => setTagFilter('all')}
              className={`px-2.5 py-1 rounded text-[10px] border transition-colors ${tagFilter === 'all' ? 'border-primary/40 text-primary bg-primary/12' : 'border-border text-muted-foreground hover:text-foreground'}`}>All</button>
            {allTags.map(t => (
              <button key={t} onClick={() => setTagFilter(t)}
                className={`px-2.5 py-1 rounded text-[10px] border transition-colors font-mono ${tagFilter === t ? 'border-primary/40 text-primary bg-primary/12' : `${TAG_COLORS[t] || TAG_COLORS.bash} opacity-70 hover:opacity-100`}`}>{t}</button>
            ))}
          </div>
        </div>

        {/* Stats bar */}
        <div className="flex flex-wrap items-center gap-3 mb-5 text-[10.5px] text-muted-foreground font-mono">
          <span className="text-primary font-semibold">{filtered.length}</span> matching ·
          <span><span className="text-foreground">{Object.keys(grouped).length}</span> categories</span> ·
          <span><span className="text-foreground">{favs.size}</span> ★ favorites</span>
        </div>

        {/* Commands */}
        {filtered.length === 0 && (
          <div className="text-center py-14 text-muted-foreground font-mono text-sm">🔍 No commands match your filter.</div>
        )}
        {Object.entries(grouped).map(([cat, items]) => {
          const moduleLink = MODULE_LINKS[cat];
          return (
            <div key={cat} className="mb-7">
              <div className="flex items-center gap-2 mb-3 pb-2 border-b border-primary/10">
                <span className="text-[13px] font-bold text-foreground">{SECTION_NAMES[cat] || cat}</span>
                <span className="bg-primary/10 text-primary px-1.5 rounded font-mono text-[9px]">{items.length}</span>
                {moduleLink && (
                  <a href={`/?tab=${moduleLink.tab}`} title="Open the matching scanner module"
                    className="ml-auto flex items-center gap-1.5 px-2.5 py-1 rounded-md border border-[hsl(var(--purple))]/25 bg-[hsl(var(--purple))]/5 text-[hsl(var(--purple))] text-[9.5px] font-semibold no-underline hover:bg-[hsl(var(--purple))]/12 transition-colors">
                    <ExternalLink size={9} /> Run in {moduleLink.label}
                  </a>
                )}
              </div>
              <div className="flex flex-col gap-1.5">
                {items.map(({ cmd, id }) => {
                  const isFav = favs.has(id);
                  return (
                    <div key={id} className="bg-card/60 border border-border rounded-[10px] overflow-hidden hover:border-primary/25 transition-all">
                      <div className="px-3 py-2 flex items-center gap-2 flex-wrap">
                        <button onClick={() => toggleFav(id)}
                          className={`p-1 rounded hover:bg-white/[0.06] transition-colors ${isFav ? 'text-primary' : 'text-muted-foreground'}`}
                          aria-label={isFav ? 'Unfavorite' : 'Favorite'}>
                          <Star size={11} fill={isFav ? 'currentColor' : 'none'} />
                        </button>
                        <span className="text-[12px] font-semibold text-foreground">{cmd.n}</span>
                        <span className="text-[10px] text-muted-foreground font-mono">— {cmd.d}</span>
                        <div className="ml-auto flex gap-1">
                          {cmd.t.map(t => (
                            <span key={t} className={`px-1.5 py-0.5 rounded text-[8px] font-mono border ${TAG_COLORS[t] || TAG_COLORS.bash}`}>{t}</span>
                          ))}
                        </div>
                      </div>
                      <div className="px-3 pb-2.5">
                        <div className="relative bg-black/55 border border-primary/10 rounded-md p-2.5 pr-16">
                          <pre className="font-mono text-[11px] text-foreground/75 whitespace-pre-wrap break-all leading-relaxed">{cmd.q}</pre>
                          <button
                            onClick={() => handleCopy(cmd.q, id)}
                            className="absolute top-1.5 right-1.5 px-2 py-1 bg-primary/12 border border-primary/25 rounded text-[8.5px] font-mono text-primary hover:bg-primary/20 transition-colors flex items-center gap-1 active:scale-95">
                            {copied === id ? <><Check size={9} /> Done</> : <><Copy size={9} /> Copy</>}
                          </button>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          );
        })}
      </div>

      {/* Footer */}
      <footer className="border-t border-primary/10 py-6 text-center font-mono text-[10px] text-muted-foreground mt-8">
        © 2026 <span className="text-primary">WebRecox</span> by <a href="https://teamcyberops.vercel.app" target="_blank" rel="noreferrer" className="text-primary no-underline">TeamCyberOps</a> — for authorised security testing only.
      </footer>

      {/* JS Analyzer Modal */}
      {showAnalyzer && (
        <div className="fixed inset-0 z-[200] bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 animate-fade-in" onClick={() => setShowAnalyzer(false)}>
          <div className="bg-card border border-primary/25 rounded-[16px] w-full max-w-[1100px] max-h-[88vh] overflow-hidden flex flex-col shadow-[0_24px_80px_-12px_hsla(38,92%,50%,0.35)]" onClick={e => e.stopPropagation()}>
            <div className="flex items-center gap-2 px-5 py-3 border-b border-primary/10">
              <Microscope size={15} className="text-[hsl(var(--purple))]" />
              <span className="text-[13px] font-bold">JS Code Analyzer <span className="text-muted-foreground font-normal">— paste or upload JS to extract endpoints + bugs</span></span>
              <div className="ml-auto flex items-center gap-2">
                <label className="px-3 py-1.5 rounded-md border border-border bg-white/[0.04] text-[10px] font-semibold cursor-pointer hover:bg-white/[0.08] transition-colors">
                  📁 Upload .js
                  <input type="file" accept=".js,.mjs,.ts,.jsx,.tsx,text/javascript" className="hidden" onChange={onFile} />
                </label>
                <button onClick={() => analyzeJS(jsInput)} disabled={!jsInput.trim() || analyzing}
                  className="px-3 py-1.5 rounded-md bg-primary/15 border border-primary/30 text-primary text-[10px] font-semibold hover:bg-primary/25 transition-colors disabled:opacity-50">
                  {analyzing ? 'Analyzing…' : 'Analyze'}
                </button>
                <button onClick={() => setShowAnalyzer(false)} className="text-muted-foreground hover:text-foreground p-1">
                  <X size={15} />
                </button>
              </div>
            </div>
            <div className="grid md:grid-cols-2 gap-0 flex-1 min-h-0">
              <div className="border-r border-primary/10 p-4 overflow-auto">
                <div className="text-[9px] uppercase tracking-[0.14em] text-muted-foreground mb-2 font-bold">Source</div>
                <textarea
                  value={jsInput}
                  onChange={e => setJsInput(e.target.value)}
                  placeholder="// Paste JavaScript code here&#10;fetch('/api/v1/users').then(r => r.json())"
                  className="w-full h-[60vh] font-mono text-[11px] bg-black/55 border border-primary/10 rounded-md p-3 text-foreground/85 placeholder:text-muted-foreground focus:outline-none focus:border-primary/40 resize-none"
                />
              </div>
              <div className="p-4 overflow-auto">
                <div className="text-[9px] uppercase tracking-[0.14em] text-muted-foreground mb-2 font-bold">
                  Findings {jsResults && <span className="text-primary">· {jsResults.length}</span>}
                </div>
                {!jsResults && !analyzing && (
                  <div className="text-muted-foreground font-mono text-[11px] py-12 text-center">
                    Paste or upload JS, then click <span className="text-primary">Analyze</span>.
                  </div>
                )}
                {analyzing && <div className="text-muted-foreground font-mono text-[11px] py-12 text-center">⚙ Analysing…</div>}
                {jsResults && jsResults.length === 0 && <div className="text-muted-foreground font-mono text-[11px] py-12 text-center">✅ Clean — no signals found.</div>}
                {jsResults && jsResults.length > 0 && (
                  <>
                    <div className="grid grid-cols-4 gap-2 mb-3">
                      {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map(s => (
                        <div key={s} className="rounded-md border border-border bg-white/[0.03] p-2">
                          <div className="text-[8px] tracking-[0.14em] uppercase font-bold" style={{ color: sevColor(s) }}>{s}</div>
                          <div className="text-[15px] font-bold" style={{ color: sevColor(s) }}>
                            {jsResults.filter(r => r.sev === s).length}
                          </div>
                        </div>
                      ))}
                    </div>
                    {(['bug', 'secret', 'endpoint', 'info'] as const).map(c => {
                      const items = jsResults.filter(r => r.cat === c);
                      if (!items.length) return null;
                      return (
                        <div key={c} className="mb-3">
                          <div className="text-[10px] font-bold mb-1.5 text-foreground/85">
                            {c === 'bug' ? '🐛 Security Bugs' : c === 'secret' ? '🔑 Secrets' : c === 'endpoint' ? '🔗 Endpoints' : 'ℹ Info'} ({items.length})
                          </div>
                          {items.slice(0, 500).map((r, i) => (
                            <div key={i} className="mb-1 p-2 rounded border bg-white/[0.02] border-border hover:border-primary/20 transition-colors">
                              <div className="flex items-center gap-2 mb-0.5">
                                <span className="px-1.5 py-0.5 rounded text-[8px] font-bold font-mono border"
                                  style={{ color: sevColor(r.sev), borderColor: sevColor(r.sev) + '50', background: sevColor(r.sev) + '12' }}>
                                  {r.sev}
                                </span>
                                <span className="text-[10px] font-semibold">{r.name}</span>
                              </div>
                              <code className="text-[10px] text-primary font-mono break-all block ml-1">{r.match}</code>
                            </div>
                          ))}
                        </div>
                      );
                    })}
                  </>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Oneliners;
