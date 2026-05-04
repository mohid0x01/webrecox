/* WebRecox — Proxy Settings panel
   Lets the user enable/disable proxy fallback, tune timeout, reorder providers. */

import { useState } from 'react';
import { Settings, X, RotateCcw, Check } from 'lucide-react';
import { toast } from 'sonner';
import {
  DEFAULT_PROVIDERS, getProxyConfig, setProxyConfig, resetProxyConfig,
} from '@/lib/proxyConfig';

interface Props { open: boolean; onClose: () => void; }

export default function ProxySettingsPanel({ open, onClose }: Props) {
  const [, force] = useState(0);
  const cfg = getProxyConfig();
  if (!open) return null;

  const toggleProvider = (id: string) => {
    const list = cfg.enabledProviders.includes(id)
      ? cfg.enabledProviders.filter(x => x !== id)
      : [...cfg.enabledProviders, id];
    setProxyConfig({ enabledProviders: list });
    force(x => x + 1);
  };

  const move = (id: string, dir: -1 | 1) => {
    const list = [...cfg.enabledProviders];
    const i = list.indexOf(id);
    if (i < 0) return;
    const j = i + dir;
    if (j < 0 || j >= list.length) return;
    [list[i], list[j]] = [list[j], list[i]];
    setProxyConfig({ enabledProviders: list });
    force(x => x + 1);
  };

  return (
    <div className="fixed inset-0 z-[110] bg-background/85 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="w-full max-w-xl bg-card border border-primary/20 rounded-2xl shadow-2xl">
        <div className="flex items-center justify-between p-4 border-b border-border">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-primary/15 border border-primary/30 flex items-center justify-center">
              <Settings size={18} className="text-primary" />
            </div>
            <div>
              <div className="text-sm font-bold text-foreground">Proxy Fallback Settings</div>
              <div className="text-[11px] text-muted-foreground">Tune CORS-resilient fetching for this environment</div>
            </div>
          </div>
          <button onClick={onClose} className="p-2 rounded-md hover:bg-white/[0.05] text-muted-foreground"><X size={18} /></button>
        </div>

        <div className="p-4 space-y-4 max-h-[70vh] overflow-y-auto">
          {/* Master toggle */}
          <label className="flex items-center justify-between p-3 rounded-lg border border-border bg-white/[0.02] cursor-pointer">
            <div>
              <div className="text-sm font-semibold text-foreground">Enable proxy fallback</div>
              <div className="text-[11px] text-muted-foreground">When direct fetches fail (CORS), try the providers below in order.</div>
            </div>
            <input type="checkbox" checked={cfg.enabled} onChange={e => { setProxyConfig({ enabled: e.target.checked }); force(x => x + 1); }}
              className="w-4 h-4 accent-primary" />
          </label>

          {/* Timeout slider */}
          <div className="p-3 rounded-lg border border-border bg-white/[0.02]">
            <div className="flex justify-between text-sm font-semibold text-foreground mb-1">
              <span>Per-attempt timeout</span><span className="text-primary">{cfg.timeoutMs} ms</span>
            </div>
            <input type="range" min={3000} max={45000} step={1000} value={cfg.timeoutMs}
              onChange={e => { setProxyConfig({ timeoutMs: parseInt(e.target.value) }); force(x => x + 1); }}
              className="w-full accent-primary" />
            <div className="flex justify-between text-[10px] text-muted-foreground"><span>3s</span><span>45s</span></div>
          </div>

          {/* Provider list */}
          <div>
            <div className="text-[11px] font-bold uppercase text-muted-foreground tracking-wider mb-2">Providers (priority order)</div>
            <div className="space-y-1.5">
              {DEFAULT_PROVIDERS.map(p => {
                const enabled = cfg.enabledProviders.includes(p.id);
                const idx = cfg.enabledProviders.indexOf(p.id);
                return (
                  <div key={p.id} className={`flex items-center gap-2 p-2.5 rounded-lg border ${enabled ? 'border-primary/25 bg-primary/[0.04]' : 'border-border bg-white/[0.02]'}`}>
                    <button onClick={() => toggleProvider(p.id)}
                      className={`w-5 h-5 rounded border flex items-center justify-center ${enabled ? 'bg-primary/20 border-primary/50' : 'border-border'}`}>
                      {enabled && <Check size={12} className="text-primary" />}
                    </button>
                    <div className="flex-1 min-w-0">
                      <div className="text-xs font-semibold text-foreground">{p.label}</div>
                      <div className="text-[10px] text-muted-foreground font-mono truncate">{p.build('https://example.com').replace('https://example.com', '<url>')}</div>
                    </div>
                    {enabled && (
                      <div className="flex items-center gap-1">
                        <span className="text-[10px] text-muted-foreground tabular-nums">#{idx + 1}</span>
                        <button onClick={() => move(p.id, -1)} disabled={idx <= 0} className="px-1.5 py-0.5 text-[10px] rounded border border-border text-muted-foreground hover:text-foreground disabled:opacity-30">↑</button>
                        <button onClick={() => move(p.id, 1)} disabled={idx === cfg.enabledProviders.length - 1} className="px-1.5 py-0.5 text-[10px] rounded border border-border text-muted-foreground hover:text-foreground disabled:opacity-30">↓</button>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        <div className="flex items-center justify-between p-3 border-t border-border bg-card/40">
          <button onClick={() => { resetProxyConfig(); force(x => x + 1); toast.success('Proxy settings reset'); }}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-border text-muted-foreground hover:text-foreground text-xs">
            <RotateCcw size={11} /> Reset defaults
          </button>
          <button onClick={() => { toast.success('Proxy settings saved'); onClose(); }}
            className="px-4 py-1.5 rounded-lg bg-primary/15 border border-primary/30 text-primary text-xs font-bold hover:bg-primary/25">
            Done
          </button>
        </div>
      </div>
    </div>
  );
}
