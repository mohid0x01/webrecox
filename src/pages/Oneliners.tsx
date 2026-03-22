import { useState, useMemo } from 'react';
import { Search, Copy, Check } from 'lucide-react';
import { ONELINERS_DATA, SECTION_NAMES, CATEGORIES } from '@/data/onelinersData';

const TAG_COLORS: Record<string, string> = {
  bash: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
  py: 'bg-blue-400/10 text-blue-400 border-blue-400/20',
  api: 'bg-purple-400/10 text-purple-400 border-purple-400/20',
  java: 'bg-pink-400/10 text-pink-400 border-pink-400/20',
  ps: 'bg-teal-400/10 text-teal-400 border-teal-400/20',
};

const Oneliners = () => {
  const [search, setSearch] = useState('');
  const [category, setCategory] = useState('all');
  const [copied, setCopied] = useState<string | null>(null);

  const filtered = useMemo(() => {
    return ONELINERS_DATA.filter(cmd => {
      const catMatch = category === 'all' || cmd.c === category;
      const q = search.toLowerCase();
      const searchMatch = !q || (cmd.n + ' ' + cmd.d + ' ' + cmd.q).toLowerCase().includes(q);
      return catMatch && searchMatch;
    });
  }, [search, category]);

  const grouped = useMemo(() => {
    const g: Record<string, typeof ONELINERS_DATA> = {};
    filtered.forEach(cmd => {
      if (!g[cmd.c]) g[cmd.c] = [];
      g[cmd.c].push(cmd);
    });
    return g;
  }, [filtered]);

  const handleCopy = (q: string, id: string) => {
    navigator.clipboard.writeText(q);
    setCopied(id);
    setTimeout(() => setCopied(null), 1500);
  };

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="sticky top-0 z-50 border-b border-border bg-background/95 backdrop-blur-sm">
        <div className="max-w-[1400px] mx-auto px-5 h-[52px] flex items-center gap-3">
          <a href="/" className="flex items-center gap-2.5 no-underline">
            <img src="https://github.com/mohidqx.png" alt="TeamCyberOps" className="w-[30px] h-[30px] rounded-full border-2 border-[hsl(var(--warning))]/40" />
            <span className="text-sm font-bold text-foreground">Team<span className="text-[hsl(var(--warning))]">CyberOps</span></span>
          </a>
          <span className="font-mono text-[8px] px-1.5 py-0.5 rounded-full bg-[hsl(var(--warning))]/10 border border-border text-[hsl(var(--warning))] tracking-widest">ONELINERS</span>
          <div className="ml-auto flex gap-2">
            <a href="/" className="px-3 py-1.5 rounded-md text-xs border border-border bg-[hsl(var(--warning))]/5 text-muted-foreground hover:text-foreground transition-colors no-underline">← Recon Tool</a>
            <a href="https://github.com/mohidqx" target="_blank" className="px-3 py-1.5 rounded-md text-xs border border-border text-muted-foreground hover:text-foreground transition-colors no-underline">@mohidqx</a>
          </div>
        </div>
      </header>

      <div className="max-w-[1400px] mx-auto px-5 py-7">
        {/* Hero */}
        <div className="text-center mb-8">
          <h1 className="text-3xl font-bold mb-2">⚡ Bug Bounty <span className="text-[hsl(var(--warning))]">Oneliners</span></h1>
          <p className="text-xs text-muted-foreground font-mono leading-relaxed max-w-xl mx-auto">
            {filtered.length}+ advanced commands across {CATEGORIES.length} categories for authorized security testing.
            <br/>Replace <span className="text-[hsl(var(--warning))]">example.com</span> with your authorized target.
          </p>
          <div className="flex items-center justify-center gap-3 mt-4">
            <img src="https://github.com/mohidqx.png" alt="mohidqx" className="w-8 h-8 rounded-full border-2 border-[hsl(var(--warning))]/30" />
            <span className="font-mono text-[10px] text-muted-foreground">
              By <a href="https://github.com/mohidqx" target="_blank" className="text-[hsl(var(--warning))] no-underline">@mohidqx</a>
            </span>
          </div>
        </div>

        {/* Search + Filters */}
        <div className="flex gap-2 mb-5 flex-wrap items-center">
          <div className="flex-1 min-w-[200px] relative">
            <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" />
            <input
              className="w-full pl-9 pr-3 py-2 bg-card border border-border rounded-lg font-mono text-xs text-foreground placeholder:text-muted-foreground focus:outline-none focus:border-[hsl(var(--warning))]/40 transition-colors"
              placeholder="Search commands, tools, descriptions…"
              value={search}
              onChange={e => setSearch(e.target.value)}
            />
          </div>
          <button onClick={() => setCategory('all')} className={`px-2.5 py-1.5 rounded text-[10px] border transition-colors cursor-pointer ${category === 'all' ? 'border-[hsl(var(--warning))]/40 text-[hsl(var(--warning))] bg-[hsl(var(--warning))]/10' : 'border-border text-muted-foreground bg-transparent hover:text-foreground'}`}>All</button>
          {CATEGORIES.map(c => (
            <button key={c} onClick={() => setCategory(c)} className={`px-2.5 py-1.5 rounded text-[10px] border transition-colors cursor-pointer whitespace-nowrap ${category === c ? 'border-[hsl(var(--warning))]/40 text-[hsl(var(--warning))] bg-[hsl(var(--warning))]/10' : 'border-border text-muted-foreground bg-transparent hover:text-foreground'}`}>
              {c.charAt(0).toUpperCase() + c.slice(1)}
            </button>
          ))}
        </div>

        {/* Commands */}
        {filtered.length === 0 && (
          <div className="text-center py-12 text-muted-foreground font-mono text-sm">🔍 No commands match your search.</div>
        )}
        {Object.entries(grouped).map(([cat, items]) => (
          <div key={cat} className="mb-7">
            <div className="flex items-center gap-2 mb-3 pb-2 border-b border-border">
              <span className="text-sm font-bold text-foreground/80">{SECTION_NAMES[cat] || cat}</span>
              <span className="bg-[hsl(var(--warning))]/10 text-[hsl(var(--warning))] px-1.5 rounded font-mono text-[9px]">{items.length}</span>
            </div>
            <div className="flex flex-col gap-1.5">
              {items.map((cmd, i) => {
                const id = `${cat}-${i}`;
                return (
                  <div key={id} className="bg-card border border-border rounded-lg overflow-hidden hover:border-[hsl(var(--warning))]/20 transition-colors">
                    <div className="px-3 py-2 flex items-center gap-2 flex-wrap">
                      <span className="text-xs font-semibold text-foreground">{cmd.n}</span>
                      <span className="text-[10px] text-muted-foreground font-mono">— {cmd.d}</span>
                      <div className="ml-auto flex gap-1">
                        {cmd.t.map(t => (
                          <span key={t} className={`px-1.5 py-0.5 rounded text-[8px] font-mono border ${TAG_COLORS[t] || TAG_COLORS.bash}`}>{t}</span>
                        ))}
                      </div>
                    </div>
                    <div className="px-3 pb-2.5">
                      <div className="relative bg-black/50 border border-[hsl(var(--warning))]/10 rounded-md p-2.5 pr-16">
                        <pre className="font-mono text-[11px] text-foreground/70 whitespace-pre-wrap break-all leading-relaxed">{cmd.q}</pre>
                        <button
                          onClick={() => handleCopy(cmd.q, id)}
                          className="absolute top-1.5 right-1.5 px-2 py-1 bg-[hsl(var(--warning))]/10 border border-border rounded text-[8px] font-mono text-[hsl(var(--warning))] hover:bg-[hsl(var(--warning))]/20 transition-colors cursor-pointer flex items-center gap-1 active:scale-95"
                        >
                          {copied === id ? <><Check size={8} /> Done</> : <><Copy size={8} /> Copy</>}
                        </button>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        ))}
      </div>

      {/* Footer */}
      <footer className="border-t border-border py-5 text-center font-mono text-[10px] text-muted-foreground mt-8">
        © 2025 TeamCyberOps — <a href="https://github.com/mohidqx" className="text-[hsl(var(--warning))] no-underline">github.com/mohidqx</a> — For authorized penetration testing only.
      </footer>
    </div>
  );
};

export default Oneliners;
