/* WebRecox — Reusable JS Code Analyzer modal.
   Accepts pasted code, file uploads, OR a target URL to crawl <script src> from.
   Shows endpoints + secrets + bugs grouped by severity. */

import { useState } from 'react';
import { X, Upload, Code, Globe, Loader2, AlertTriangle, Shield, Zap, Info, FileCode, ChevronRight } from 'lucide-react';
import { toast } from 'sonner';
import {
  analyzeJS, aggregateAnalyses, crawlAndAnalyze, type JSAnalysisResult, type Severity,
} from '@/lib/jsAnalyzer';

interface Props {
  open: boolean;
  onClose: () => void;
  /** Optional target URL to pre-fill the crawl tab. */
  initialTarget?: string;
  /** Optional initial pasted code snippet. */
  initialCode?: string;
}

const SEV_STYLE: Record<Severity, string> = {
  CRITICAL: 'bg-destructive/15 text-destructive border-destructive/30',
  HIGH: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
  MEDIUM: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  LOW: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
  INFO: 'bg-muted text-muted-foreground border-border',
};

export default function JSAnalyzerModal({ open, onClose, initialTarget, initialCode }: Props) {
  const [tab, setTab] = useState<'paste' | 'upload' | 'crawl'>(initialTarget ? 'crawl' : 'paste');
  const [code, setCode] = useState(initialCode || '');
  const [target, setTarget] = useState(initialTarget || '');
  const [results, setResults] = useState<JSAnalysisResult[]>([]);
  const [busy, setBusy] = useState(false);
  const [activeSev, setActiveSev] = useState<Severity | 'ALL'>('ALL');

  if (!open) return null;

  const runPaste = () => {
    if (!code.trim()) { toast.error('Paste some JS first'); return; }
    setBusy(true);
    try {
      const r = analyzeJS(code, 'pasted.js');
      setResults([r]);
      toast.success(`Analyzed: ${r.endpoints.length} endpoints, ${r.secrets.length} secrets, ${r.bugs.length} bugs`);
    } finally { setBusy(false); }
  };

  const runUpload = async (files: FileList | null) => {
    if (!files?.length) return;
    setBusy(true);
    try {
      const out: JSAnalysisResult[] = [];
      for (const f of Array.from(files)) {
        const text = await f.text();
        out.push(analyzeJS(text, f.name));
      }
      setResults(out);
      const agg = aggregateAnalyses(out);
      toast.success(`${out.length} files: ${agg.endpoints.length} endpoints, ${agg.secrets.length} secrets, ${agg.bugs.length} bugs`);
    } catch (e: any) {
      toast.error('Failed: ' + (e?.message || 'unknown'));
    } finally { setBusy(false); }
  };

  const runCrawl = async () => {
    let url = target.trim();
    if (!url) { toast.error('Enter a target URL'); return; }
    if (!/^https?:\/\//.test(url)) url = 'https://' + url;
    setBusy(true);
    toast.info(`Crawling ${url} for <script> sources…`);
    try {
      const out = await crawlAndAnalyze(url, { maxFiles: 200 });
      setResults(out);
      const agg = aggregateAnalyses(out);
      toast.success(`${out.length} JS files crawled — ${agg.endpoints.length} endpoints, ${agg.secrets.length} secrets`);
    } catch (e: any) {
      toast.error('Crawl failed: ' + (e?.message || 'unknown'));
    } finally { setBusy(false); }
  };

  const agg = aggregateAnalyses(results);
  const allFindings = [...agg.secrets, ...agg.bugs, ...agg.endpoints, ...agg.info];
  const filtered = activeSev === 'ALL' ? allFindings : allFindings.filter(f => f.severity === activeSev);

  return (
    <div className="fixed inset-0 z-[120] bg-background/85 backdrop-blur-sm flex items-center justify-center p-4 animate-fade-in">
      <div className="w-full max-w-5xl max-h-[90vh] overflow-hidden bg-card border border-primary/20 rounded-2xl shadow-2xl flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-border">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-primary/15 border border-primary/30 flex items-center justify-center">
              <FileCode size={18} className="text-primary" />
            </div>
            <div>
              <div className="text-sm font-bold text-foreground">JS Code Analyzer</div>
              <div className="text-[11px] text-muted-foreground">AST-walk + regex fallback · endpoints · secrets · bugs</div>
            </div>
          </div>
          <button onClick={onClose} className="p-2 rounded-md hover:bg-white/[0.05] text-muted-foreground"><X size={18} /></button>
        </div>

        {/* Tab switcher */}
        <div className="flex border-b border-border bg-card/40">
          {([
            { id: 'paste', label: 'Paste Code', icon: Code },
            { id: 'upload', label: 'Upload Files', icon: Upload },
            { id: 'crawl', label: 'Crawl Target', icon: Globe },
          ] as const).map(t => (
            <button key={t.id} onClick={() => setTab(t.id)}
              className={`flex items-center gap-2 px-4 py-2.5 text-xs font-semibold border-b-2 transition-all ${tab === t.id ? 'border-primary text-primary' : 'border-transparent text-muted-foreground hover:text-foreground'}`}>
              <t.icon size={13} /> {t.label}
            </button>
          ))}
        </div>

        {/* Input area */}
        <div className="p-4 border-b border-border bg-card/20">
          {tab === 'paste' && (
            <div className="space-y-2">
              <textarea value={code} onChange={e => setCode(e.target.value)} placeholder="// Paste minified or readable JavaScript here…"
                className="w-full h-28 bg-background/60 border border-border rounded-lg p-3 font-mono text-[12px] text-foreground outline-none focus:border-primary/40 resize-none" />
              <button onClick={runPaste} disabled={busy} className="px-4 py-2 rounded-lg bg-primary/15 border border-primary/30 text-primary text-xs font-bold hover:bg-primary/25 disabled:opacity-40">
                {busy ? <Loader2 size={13} className="animate-spin inline mr-1" /> : null} Analyze
              </button>
            </div>
          )}
          {tab === 'upload' && (
            <div className="space-y-2">
              <label className="block">
                <input type="file" multiple accept=".js,.mjs,.cjs,.jsx,.ts,.tsx,.txt" onChange={e => runUpload(e.target.files)}
                  className="block w-full text-xs text-muted-foreground file:mr-3 file:px-3 file:py-2 file:rounded-md file:border-0 file:bg-primary/15 file:text-primary file:font-semibold hover:file:bg-primary/25" />
              </label>
              <p className="text-[11px] text-muted-foreground">Upload multiple JS/TS files — all analyzed in one batch.</p>
            </div>
          )}
          {tab === 'crawl' && (
            <div className="space-y-2">
              <div className="flex gap-2">
                <input value={target} onChange={e => setTarget(e.target.value)} placeholder="https://example.com"
                  className="flex-1 bg-background/60 border border-border rounded-lg px-3 py-2 text-xs text-foreground font-mono outline-none focus:border-primary/40" />
                <button onClick={runCrawl} disabled={busy} className="px-4 py-2 rounded-lg bg-primary/15 border border-primary/30 text-primary text-xs font-bold hover:bg-primary/25 disabled:opacity-40 whitespace-nowrap">
                  {busy ? <Loader2 size={13} className="animate-spin inline mr-1" /> : <Globe size={12} className="inline mr-1" />} Crawl & Analyze
                </button>
              </div>
              <p className="text-[11px] text-muted-foreground">Fetches the target page, extracts every &lt;script src&gt; URL, and runs analyzer on each (max 200).</p>
            </div>
          )}
        </div>

        {/* Summary chips */}
        {results.length > 0 && (
          <div className="flex flex-wrap gap-1.5 p-3 border-b border-border bg-card/10">
            {(['ALL','CRITICAL','HIGH','MEDIUM','LOW','INFO'] as const).map(s => {
              const count = s === 'ALL' ? allFindings.length : (agg.bySeverity[s as Severity]?.length || 0);
              return (
                <button key={s} onClick={() => setActiveSev(s)}
                  className={`px-2.5 py-1 rounded-md text-[10.5px] font-bold border transition-all ${activeSev === s ? 'bg-primary/15 border-primary/40 text-primary' : 'bg-white/[0.03] border-border text-muted-foreground hover:text-foreground'}`}>
                  {s} <span className="ml-1 opacity-70">({count})</span>
                </button>
              );
            })}
            <span className="ml-auto text-[10.5px] text-muted-foreground self-center">
              {results.length} file{results.length === 1 ? '' : 's'} · {agg.totalLOC.toLocaleString()} LOC
            </span>
          </div>
        )}

        {/* Findings list */}
        <div className="flex-1 overflow-y-auto p-3 space-y-1">
          {results.length === 0 && (
            <div className="text-center text-muted-foreground text-xs py-12">No analysis yet — paste code, upload files, or crawl a target.</div>
          )}
          {filtered.slice(0, 5000).map((f, i) => (
            <div key={i} className="flex items-start gap-3 p-2.5 rounded-lg border border-border bg-white/[0.02] hover:bg-white/[0.04]">
              <span className={`shrink-0 px-2 py-0.5 rounded text-[9.5px] font-bold border ${SEV_STYLE[f.severity]}`}>{f.severity}</span>
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2 text-[11.5px]">
                  {f.category === 'secret' && <Shield size={11} className="text-destructive" />}
                  {f.category === 'bug' && <AlertTriangle size={11} className="text-orange-400" />}
                  {f.category === 'endpoint' && <Zap size={11} className="text-primary" />}
                  {f.category === 'info' && <Info size={11} className="text-muted-foreground" />}
                  <span className="font-semibold text-foreground">{f.type}</span>
                  {f.confidence && <span className="text-[9.5px] text-muted-foreground">· {f.confidence} conf</span>}
                </div>
                <code className="block text-[11px] text-foreground/90 font-mono mt-0.5 break-all">{f.value}</code>
                {f.context && <p className="text-[10.5px] text-muted-foreground mt-0.5">{f.context}</p>}
                <div className="text-[10px] text-muted-foreground/70 mt-0.5 flex items-center gap-1">
                  <ChevronRight size={9} /> {f.file}{f.line ? `:${f.line}` : ''}
                </div>
              </div>
            </div>
          ))}
          {filtered.length > 5000 && (
            <div className="text-center text-[10px] text-muted-foreground py-2">Showing first 5000 of {filtered.length}</div>
          )}
        </div>
      </div>
    </div>
  );
}
