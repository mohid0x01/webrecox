import { useState, useEffect } from 'react';
import { ExternalLink, X } from 'lucide-react';

const FloatingPortfolio = () => {
  const [open, setOpen] = useState(false);
  const [show, setShow] = useState(false);

  useEffect(() => {
    const t = setTimeout(() => setShow(true), 1200);
    return () => clearTimeout(t);
  }, []);

  if (!show) return null;

  return (
    <div className="fixed bottom-5 right-5 z-[9999] flex flex-col items-end gap-2 animate-fade-in">
      {open && (
        <div className="bg-card/95 backdrop-blur-xl border border-primary/30 rounded-2xl p-4 shadow-2xl w-72 animate-scale-in"
          style={{ boxShadow: '0 24px 60px -10px hsl(var(--primary) / 0.35), 0 0 0 1px hsl(var(--primary) / 0.18)' }}>
          <div className="flex items-start gap-3 mb-3">
            <img src="https://github.com/mohidqx.png" alt="TeamCyberOps" className="w-12 h-12 rounded-full border-2 border-primary/40" />
            <div className="flex-1 min-w-0">
              <div className="text-[13px] font-bold text-foreground truncate">TeamCyberOps</div>
              <div className="text-[10px] text-muted-foreground truncate">Offensive Security · OSINT · BugBounty</div>
            </div>
            <button onClick={() => setOpen(false)} className="text-muted-foreground hover:text-foreground transition-colors p-1 -mt-1 -mr-1">
              <X size={14} />
            </button>
          </div>
          <p className="text-[10.5px] text-muted-foreground leading-relaxed mb-3">
            Explore tools, write-ups, CTF solves and bug-bounty research from <span className="text-primary font-semibold">@mohidqx</span>.
          </p>
          <div className="flex flex-col gap-1.5">
            <a href="https://teamcyberops.vercel.app" target="_blank" rel="noreferrer"
              className="flex items-center justify-between gap-2 px-3 py-2 rounded-lg bg-primary/12 border border-primary/30 text-primary text-[11px] font-semibold no-underline hover:bg-primary/20 transition-all">
              <span className="flex items-center gap-2">🌐 Visit Portfolio</span>
              <ExternalLink size={11} />
            </a>
            <a href="https://github.com/mohidqx" target="_blank" rel="noreferrer"
              className="flex items-center justify-between gap-2 px-3 py-2 rounded-lg bg-white/[0.04] border border-border text-foreground text-[11px] font-semibold no-underline hover:bg-white/[0.08] transition-all">
              <span className="flex items-center gap-2">⚡ GitHub @mohidqx</span>
              <ExternalLink size={11} />
            </a>
            <a href="/oneliners"
              className="flex items-center justify-between gap-2 px-3 py-2 rounded-lg bg-white/[0.04] border border-border text-foreground text-[11px] font-semibold no-underline hover:bg-white/[0.08] transition-all">
              <span className="flex items-center gap-2">📜 Oneliners Library</span>
              <ExternalLink size={11} />
            </a>
          </div>
        </div>
      )}
      <button
        onClick={() => setOpen(o => !o)}
        aria-label="Open TeamCyberOps portfolio"
        className="group relative w-14 h-14 rounded-full overflow-hidden border-2 border-primary/40 hover:border-primary/80 transition-all hover:scale-110"
        style={{ boxShadow: '0 12px 32px -6px hsl(var(--primary) / 0.45)' }}
      >
        <span className="absolute inset-0 rounded-full animate-ping bg-primary/30" />
        <img src="https://github.com/mohidqx.png" alt="TeamCyberOps" className="relative w-full h-full object-cover" />
      </button>
    </div>
  );
};

export default FloatingPortfolio;
