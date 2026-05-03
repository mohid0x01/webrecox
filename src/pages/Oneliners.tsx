import { useState, useMemo, useEffect } from 'react';
import { Search, Copy, Check, Star, Download, ExternalLink, Microscope, X, Zap, Filter as FilterIcon, Share2, Upload, FileCode2 } from 'lucide-react';
import { ONELINERS_DATA, SECTION_NAMES, CATEGORIES, MODULE_LINKS } from '@/data/onelinersData';
import { analyzeJS, aggregateAnalyses, JSAnalysisResult, JSAnalysisFinding, Severity, SEV_ORDER } from '@/lib/jsAnalyzer';
import { supabase } from '@/integrations/supabase/client';
import { toast } from 'sonner';

const TAG_COLORS: Record<string, string> = {
  bash: 'bg-[hsl(var(--green))]/10 text-[hsl(var(--green))] border-[hsl(var(--green))]/25',
  py: 'bg-[hsl(var(--info))]/10 text-[hsl(var(--info))] border-[hsl(var(--info))]/25',
  api: 'bg-[hsl(var(--purple))]/10 text-[hsl(var(--purple))] border-[hsl(var(--purple))]/25',
  java: 'bg-[hsl(var(--pink))]/10 text-[hsl(var(--pink))] border-[hsl(var(--pink))]/25',
  ps: 'bg-[hsl(var(--teal))]/10 text-[hsl(var(--teal))] border-[hsl(var(--teal))]/25',
};

const SEV_COLOR: Record<Severity, string> = {
  CRITICAL: 'hsl(0,82%,58%)',
  HIGH: 'hsl(25,95%,55%)',
  MEDIUM: 'hsl(45,95%,55%)',
  LOW: 'hsl(195,75%,55%)',
  INFO: 'hsl(var(--muted-foreground))',
};

const Oneliners = () => {
  const [search, setSearch] = useState('');
  const [category, setCategory] = useState('all');
  const [tagFilter, setTagFilter] = useState('all');
  const [copied, setCopied] = useState<string | null>(null);
  const [favs, setFavs] = useState<Set<string>>(new Set());
  const [showFavs, setShowFavs] = useState(false);
  const [showAnalyzer, setShowAnalyzer] = useState(false);
  const [jsInput, setJsInput] = useState('');
  const [jsResults, setJsResults] = useState<JSAnalysisResult[] | null>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [target, setTarget] = useState('example.com');

  // ── Load favorites + shared view from URL ──
  useEffect(() => {
    try {
      const s = localStorage.getItem('webrecox-fav-oneliners');
      if (s) setFavs(new Set(JSON.parse(s)));
    } catch { /* */ }

    const params = new URLSearchParams(window.location.search);
    const sid = params.get('share');
    const t = params.get('target');
    if (t) setTarget(t);

    if (sid) {
      (async () => {
        const { data } = await supabase
          .from('shared_views')
          .select('payload, kind')
          .eq('share_id', sid)
          .maybeSingle();
        if (data?.payload && (data.kind === 'oneliners' || data.kind === 'js_analysis')) {
          const p = data.payload as any;
          if (typeof p.search === 'string') setSearch(p.search);
          if (typeof p.category === 'string') setCategory(p.category);
          if (typeof p.tagFilter === 'string') setTagFilter(p.tagFilter);
          if (Array.isArray(p.favs)) setFavs(new Set(p.favs));
          if (typeof p.showFavs === 'boolean') setShowFavs(p.showFavs);
          if (Array.isArray(p.jsResults)) setJsResults(p.jsResults);
          if (typeof p.target === 'string') setTarget(p.target);
          toast.success('Loaded shared view');
        }
      })();
    }
  }, []);

  const toggleFav = (id: string) => {
    setFavs(prev => {
      const n = new Set(prev);
      if (n.has(id)) n.delete(id); else n.add(id);
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
    }).map((cmd) => ({ cmd, id: `${cmd.c}-${ONELINERS_DATA.indexOf(cmd)}` }));
  }, [search, category, tagFilter, showFavs, favs]);

  const grouped = useMemo(() => {
    const g: Record<string, typeof filtered> = {};
    filtered.forEach(item => {
      if (!g[item.cmd.c]) g[item.cmd.c] = [];
      g[item.cmd.c].push(item);
    });
    return g;
  }, [filtered]);

  // Replace example.com with target across the displayed command
  const personalize = (q: string) => target && target !== 'example.com' ? q.replaceAll('example.com', target) : q;

  const handleCopy = (q: string, id: string) => {
    navigator.clipboard.writeText(personalize(q));
    setCopied(id);
    setTimeout(() => setCopied(null), 1500);
  };

  const exportCSV = () => {
    const rows = [
      ['Category', 'Name', 'Description', 'Tags', 'Module', 'Command'],
      ...filtered.map(({ cmd }) => [
        cmd.c, cmd.n, cmd.d, cmd.t.join('|'),
        MODULE_LINKS[cmd.c]?.label || '',
        personalize(cmd.q),
      ]),
    ];
    const csv = rows.map(r => r.map(c => `"${String(c).replace(/"/g, '""')}"`).join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `webrecox-oneliners-${Date.now()}.csv`;
    a.click(); URL.revokeObjectURL(url);
  };

  // ── JS analysis (multi-file aware) ──
  const analyzeBatch = async (files: { name: string; text: string }[]) => {
    setAnalyzing(true);
    setJsResults(null);
    await new Promise(r => setTimeout(r, 30));
    const results: JSAnalysisResult[] = [];
    for (const f of files) {
      try {
        results.push(analyzeJS(f.text, f.name));
      } catch (e: any) {
        results.push({ file: f.name, endpoints: [], secrets: [], bugs: [], info: [], parseError: e?.message, totalLOC: 0 });
      }
    }
    setJsResults(results);
    setAnalyzing(false);
    const totals = aggregateAnalyses(results);
    toast.success(`Analyzed ${results.length} file(s) · ${totals.endpoints.length} endpoints · ${totals.secrets.length} secrets · ${totals.bugs.length} bugs`);
  };

  const onAnalyzeText = () => {
    if (!jsInput.trim()) return;
    analyzeBatch([{ name: 'inline.js', text: jsInput }]);
  };

  const onMultiFile = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = Array.from(e.target.files || []);
    if (!files.length) return;
    const loaded: { name: string; text: string }[] = [];
    for (const f of files) {
      try {
        const txt = await f.text();
        loaded.push({ name: f.name, text: txt.slice(0, 5_000_000) });
      } catch { /* */ }
    }
    e.target.value = '';
    if (!loaded.length) { toast.error('Could not read files'); return; }
    if (loaded.length === 1) setJsInput(loaded[0].text);
    analyzeBatch(loaded);
  };

  const aggregated = useMemo(() => jsResults ? aggregateAnalyses(jsResults) : null, [jsResults]);

  // ── Share current view ──
  const shareView = async () => {
    const shortId = (Math.random().toString(36).slice(2, 6) + Date.now().toString(36).slice(-4)).toLowerCase();
    const payload = {
      search, category, tagFilter, favs: [...favs], showFavs, target,
      jsResults: jsResults || undefined,
    };
    const { error } = await supabase.from('shared_views').insert({
      share_id: shortId,
      kind: jsResults?.length ? 'js_analysis' : 'oneliners',
      target_domain: target,
      payload: payload as any,
    });
    if (error) { toast.error('Share failed: ' + error.message); return; }
    const url = `${window.location.origin}/oneliners?share=${shortId}`;
    try { await navigator.clipboard.writeText(url); } catch { /* */ }
    toast.success(`Share link copied: ${url}`, { duration: 6000 });
  };

  const catCounts = useMemo(() => {
    const c: Record<string, number> = {};
    ONELINERS_DATA.forEach(o => { c[o.c] = (c[o.c] || 0) + 1; });
    return c;
  }, []);

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
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
            <input
              value={target}
              onChange={e => setTarget(e.target.value.trim() || 'example.com')}
              placeholder="target domain"
              className="hidden md:block w-[170px] px-2.5 py-1.5 rounded-lg border border-primary/20 bg-white/[0.04] font-mono text-[10.5px] text-foreground placeholder:text-muted-foreground focus:outline-none focus:border-primary/45"
            />
            <button onClick={() => setShowAnalyzer(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-[hsl(var(--purple))]/30 bg-[hsl(var(--purple))]/8 text-[hsl(var(--purple))] text-[10.5px] font-semibold hover:bg-[hsl(var(--purple))]/15 transition-colors">
              <Microscope size={11} /> JS Analyzer
            </button>
            <button onClick={shareView}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-[hsl(var(--green))]/25 bg-[hsl(var(--green))]/8 text-[hsl(var(--green))] text-[10.5px] font-semibold hover:bg-[hsl(var(--green))]/15 transition-colors">
              <Share2 size={11} /> Share
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
            <br />Set a target above and we'll personalise every command — share filters/favorites/findings via short links.
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
          <span><span className="text-foreground">{favs.size}</span> ★ favorites</span> ·
          <span>target: <span className="text-primary">{target}</span></span>
        </div>

        {/* Commands */}
        {filtered.length === 0 && (
          <div className="text-center py-14 text-muted-foreground font-mono text-sm">🔍 No commands match your filter.</div>
        )}
        {Object.entries(grouped).map(([cat, items]) => {
          const moduleLink = MODULE_LINKS[cat];
          const moduleHref = moduleLink ? `/?tab=${moduleLink.tab}&target=${encodeURIComponent(target)}` : null;
          return (
            <div key={cat} className="mb-7">
              <div className="flex items-center gap-2 mb-3 pb-2 border-b border-primary/10">
                <span className="text-[13px] font-bold text-foreground">{SECTION_NAMES[cat] || cat}</span>
                <span className="bg-primary/10 text-primary px-1.5 rounded font-mono text-[9px]">{items.length}</span>
                {moduleHref && (
                  <a href={moduleHref} title={`Open ${moduleLink!.label} pre-filled with ${target}`}
                    className="ml-auto flex items-center gap-1.5 px-2.5 py-1 rounded-md border border-[hsl(var(--purple))]/25 bg-[hsl(var(--purple))]/5 text-[hsl(var(--purple))] text-[9.5px] font-semibold no-underline hover:bg-[hsl(var(--purple))]/12 transition-colors">
                    <ExternalLink size={9} /> Run in {moduleLink!.label}
                  </a>
                )}
              </div>
              <div className="flex flex-col gap-1.5">
                {items.map(({ cmd, id }) => {
                  const isFav = favs.has(id);
                  const displayed = personalize(cmd.q);
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
                          <pre className="font-mono text-[11px] text-foreground/75 whitespace-pre-wrap break-all leading-relaxed">{displayed}</pre>
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

      {/* JS Analyzer Modal — AST-powered */}
      {showAnalyzer && (
        <div className="fixed inset-0 z-[200] bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 animate-fade-in" onClick={() => setShowAnalyzer(false)}>
          <div className="bg-card border border-primary/25 rounded-[16px] w-full max-w-[1200px] max-h-[92vh] overflow-hidden flex flex-col shadow-[0_24px_80px_-12px_hsla(38,92%,50%,0.35)]" onClick={e => e.stopPropagation()}>
            <div className="flex items-center gap-2 px-5 py-3 border-b border-primary/10">
              <Microscope size={15} className="text-[hsl(var(--purple))]" />
              <span className="text-[13px] font-bold">
                JS AST Analyzer
                <span className="text-muted-foreground font-normal"> — acorn-walked endpoints + secrets + bugs (multi-file aware)</span>
              </span>
              <div className="ml-auto flex items-center gap-2">
                <label className="px-3 py-1.5 rounded-md border border-border bg-white/[0.04] text-[10px] font-semibold cursor-pointer hover:bg-white/[0.08] transition-colors flex items-center gap-1.5">
                  <Upload size={10} /> Upload many .js
                  <input type="file" accept=".js,.mjs,.ts,.jsx,.tsx,text/javascript" multiple className="hidden" onChange={onMultiFile} />
                </label>
                <button onClick={onAnalyzeText} disabled={!jsInput.trim() || analyzing}
                  className="px-3 py-1.5 rounded-md bg-primary/15 border border-primary/30 text-primary text-[10px] font-semibold hover:bg-primary/25 transition-colors disabled:opacity-50">
                  {analyzing ? 'Analyzing…' : 'Analyze pasted'}
                </button>
                <button onClick={() => setShowAnalyzer(false)} className="text-muted-foreground hover:text-foreground p-1">
                  <X size={15} />
                </button>
              </div>
            </div>

            <div className="grid md:grid-cols-2 gap-0 flex-1 min-h-0">
              {/* Left: source */}
              <div className="border-r border-primary/10 p-4 overflow-auto">
                <div className="text-[9px] uppercase tracking-[0.14em] text-muted-foreground mb-2 font-bold flex items-center gap-2">
                  <FileCode2 size={10} /> Source
                  {jsResults && jsResults.length > 1 && <span className="text-primary">{jsResults.length} files analyzed</span>}
                </div>
                <textarea
                  value={jsInput}
                  onChange={e => setJsInput(e.target.value)}
                  placeholder="// Paste JavaScript code, or use 'Upload many .js' for multi-file analysis&#10;fetch('/api/v1/users').then(r => r.json())"
                  className="w-full h-[68vh] font-mono text-[11px] bg-black/55 border border-primary/10 rounded-md p-3 text-foreground/85 placeholder:text-muted-foreground focus:outline-none focus:border-primary/40 resize-none"
                />
                {jsResults && jsResults.length > 1 && (
                  <div className="mt-3 space-y-1 text-[10px] font-mono">
                    {jsResults.map((r, i) => (
                      <div key={i} className="flex items-center gap-2 px-2 py-1 rounded bg-white/[0.03] border border-border">
                        <span className="truncate flex-1">{r.file}</span>
                        <span className="text-muted-foreground">{r.totalLOC} loc</span>
                        <span className="text-[hsl(var(--teal))]">{r.endpoints.length} ep</span>
                        <span className="text-primary">{r.secrets.length} sec</span>
                        <span className="text-destructive">{r.bugs.length} bug</span>
                        {r.parseError && <span className="text-[hsl(25,95%,55%)]" title={r.parseError}>!</span>}
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Right: findings grouped by severity */}
              <div className="p-4 overflow-auto">
                <div className="text-[9px] uppercase tracking-[0.14em] text-muted-foreground mb-2 font-bold">
                  Findings {aggregated && <span className="text-primary">· {aggregated.endpoints.length + aggregated.secrets.length + aggregated.bugs.length + aggregated.info.length}</span>}
                </div>
                {!aggregated && !analyzing && (
                  <div className="text-muted-foreground font-mono text-[11px] py-12 text-center">
                    Paste JS, or upload one or many <code className="text-primary">.js</code> files. We'll AST-walk them and group findings by severity.
                  </div>
                )}
                {analyzing && <div className="text-muted-foreground font-mono text-[11px] py-12 text-center">⚙ Walking AST…</div>}
                {aggregated && (
                  <>
                    {/* Severity tiles */}
                    <div className="grid grid-cols-5 gap-1.5 mb-3">
                      {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as Severity[]).map(s => {
                        const n = aggregated.bySeverity[s].length;
                        return (
                          <div key={s} className="rounded-md border bg-white/[0.03] p-2"
                            style={{ borderColor: SEV_COLOR[s] + '40' }}>
                            <div className="text-[8px] tracking-[0.14em] uppercase font-bold" style={{ color: SEV_COLOR[s] }}>{s}</div>
                            <div className="text-[15px] font-bold" style={{ color: SEV_COLOR[s] }}>{n}</div>
                          </div>
                        );
                      })}
                    </div>

                    {/* Per-category sections */}
                    {([
                      { key: 'secrets', label: '🔑 Secrets', items: aggregated.secrets },
                      { key: 'bugs', label: '🐛 Security Bugs', items: aggregated.bugs },
                      { key: 'endpoints', label: '🔗 Real Endpoints (AST)', items: aggregated.endpoints },
                      { key: 'info', label: 'ℹ Info', items: aggregated.info },
                    ] as const).map(section => {
                      if (!section.items.length) return null;
                      const sorted = [...section.items].sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity]);
                      return (
                        <div key={section.key} className="mb-3">
                          <div className="text-[10px] font-bold mb-1.5 text-foreground/85">
                            {section.label} <span className="text-muted-foreground">({section.items.length})</span>
                          </div>
                          {sorted.slice(0, 1500).map((r: JSAnalysisFinding, i: number) => (
                            <div key={i} className="mb-1 p-2 rounded border bg-white/[0.02] border-border hover:border-primary/20 transition-colors">
                              <div className="flex items-center gap-2 mb-0.5 flex-wrap">
                                <span className="px-1.5 py-0.5 rounded text-[8px] font-bold font-mono border"
                                  style={{ color: SEV_COLOR[r.severity], borderColor: SEV_COLOR[r.severity] + '50', background: SEV_COLOR[r.severity] + '12' }}>
                                  {r.severity}
                                </span>
                                <span className="text-[10px] font-semibold">{r.type}</span>
                                {r.confidence !== 'high' && (
                                  <span className="text-[8px] text-muted-foreground font-mono uppercase tracking-wider">{r.confidence} conf</span>
                                )}
                                {r.file && r.file !== 'inline.js' && (
                                  <span className="ml-auto text-[8px] text-muted-foreground font-mono truncate max-w-[180px]">{r.file}{r.line ? `:${r.line}` : ''}</span>
                                )}
                              </div>
                              <code className="text-[10px] text-primary font-mono break-all block ml-1">{r.value}</code>
                              {r.context && <div className="text-[9px] text-muted-foreground mt-0.5 ml-1">{r.context}</div>}
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
