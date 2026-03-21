import { useState, useCallback, useRef, useEffect } from 'react';
import { X, CheckCircle, AlertCircle, Loader2 } from 'lucide-react';

interface TerminalModalProps {
  isOpen: boolean;
  onClose: () => void;
  toolName: string;
  target: string;
  scanResult: any | null;
  scanError: string | null;
  isScanning: boolean;
  isRealScan: boolean;
}

const TerminalModal = ({ isOpen, onClose, toolName, target, scanResult, scanError, isScanning, isRealScan }: TerminalModalProps) => {
  const [simLines, setSimLines] = useState<string[]>([]);
  const scrollRef = useRef<HTMLDivElement>(null);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // For non-real scans, simulate
  useEffect(() => {
    if (!isOpen || isRealScan) return;
    setSimLines([]);
    const lines = [
      'Initializing audit engine...',
      'Loading compliance rulesets...',
      `Resolving target: ${target}...`,
      'Running analysis...',
      'Processing results...',
      '[!] This module requires server-side tooling not available via public APIs.',
      'Simulation complete — use dedicated tooling for full results.',
    ];
    let i = 0;
    intervalRef.current = setInterval(() => {
      if (i < lines.length) {
        setSimLines(prev => [...prev, `[${new Date().toISOString().slice(11, 19)}] ${lines[i]}`]);
        i++;
      } else {
        if (intervalRef.current) clearInterval(intervalRef.current);
      }
    }, 350);
    return () => { if (intervalRef.current) clearInterval(intervalRef.current); };
  }, [isOpen, isRealScan, target]);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: 'smooth' });
  }, [simLines, scanResult, isScanning]);

  if (!isOpen) return null;

  const renderResults = (data: any) => {
    if (!data) return null;
    const lines: string[] = [];

    if (data.subdomains) {
      lines.push(`[✓] Found ${data.count} unique subdomains (source: ${data.source})`);
      lines.push('');
      data.subdomains.forEach((s: string) => lines.push(`  → ${s}`));
    } else if (data.certificates) {
      lines.push(`[✓] Found ${data.count} certificates (source: ${data.source})`);
      lines.push('');
      data.certificates.forEach((c: any) => {
        lines.push(`  CN: ${c.common_name}`);
        lines.push(`  Issuer: ${c.issuer}`);
        lines.push(`  Valid: ${c.not_before} → ${c.not_after}`);
        lines.push('');
      });
    } else if (data.records) {
      lines.push(`[✓] DNS Records (source: ${data.source})`);
      lines.push('');
      Object.entries(data.records).forEach(([type, recs]) => {
        lines.push(`  ${type} Records:`);
        (recs as any[]).forEach(r => lines.push(`    ${r.data} (TTL: ${r.ttl})`));
        lines.push('');
      });
    } else if (data.probes) {
      lines.push(`[✓] HTTP Probe Results (source: ${data.source})`);
      lines.push('');
      data.probes.forEach((p: any) => {
        if (p.status === 'error') {
          lines.push(`  ✗ ${p.url} — ${p.error}`);
        } else {
          lines.push(`  ✓ ${p.url} — ${p.status} ${p.status_text}`);
          if (p.redirected) lines.push(`    → Redirected to: ${p.final_url}`);
        }
      });
    } else if (data.found !== undefined) {
      lines.push(`[✓] Security Headers (source: ${data.source})`);
      lines.push('');
      lines.push('  Present:');
      Object.entries(data.found).forEach(([h, v]) => lines.push(`    ✓ ${h}: ${v}`));
      if (data.missing?.length) {
        lines.push('');
        lines.push('  Missing (⚠ potential risk):');
        data.missing.forEach((h: string) => lines.push(`    ✗ ${h}`));
      }
    } else if (data.technologies) {
      lines.push(`[✓] Technology Detection (source: ${data.source})`);
      lines.push('');
      data.technologies.forEach((t: string) => lines.push(`  • ${t}`));
      if (data.technologies.length === 0) lines.push('  No technologies detected.');
    } else if (data.name !== undefined && data.nameservers) {
      lines.push(`[✓] WHOIS/RDAP (source: ${data.source})`);
      lines.push(`  Domain: ${data.name}`);
      if (data.status) lines.push(`  Status: ${data.status.join(', ')}`);
      if (data.nameservers) {
        lines.push('  Nameservers:');
        data.nameservers.forEach((ns: string) => lines.push(`    • ${ns}`));
      }
      if (data.events) {
        lines.push('  Events:');
        data.events.forEach((e: any) => lines.push(`    ${e.action}: ${e.date}`));
      }
    } else {
      lines.push(JSON.stringify(data, null, 2));
    }

    return lines;
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-background/80 backdrop-blur-sm" onClick={onClose}>
      <div
        className="w-full max-w-3xl mx-4 rounded-lg border border-border bg-card overflow-hidden animate-fade-in-up"
        onClick={e => e.stopPropagation()}
      >
        <div className="flex items-center justify-between px-4 py-3 border-b border-border">
          <div className="flex items-center gap-2">
            <div className="flex gap-1.5">
              <span className="w-3 h-3 rounded-full bg-destructive/80" />
              <span className="w-3 h-3 rounded-full" style={{ background: 'hsl(38, 92%, 50%)' }} />
              <span className="w-3 h-3 rounded-full bg-primary/80" />
            </div>
            <span className="ml-2 text-xs font-mono text-muted-foreground">
              {toolName} — {target}
              {isRealScan && <span className="ml-2 text-primary">● LIVE</span>}
            </span>
          </div>
          <button onClick={onClose} className="p-1 rounded-md hover:bg-muted transition-colors active:scale-95">
            <X size={14} className="text-muted-foreground" />
          </button>
        </div>

        <div ref={scrollRef} className="p-4 h-96 overflow-y-auto scrollbar-thin font-mono text-xs leading-relaxed">
          {isRealScan ? (
            <>
              <div className="text-muted-foreground">[{new Date().toISOString().slice(11, 19)}] Initiating live scan against {target}...</div>
              {isScanning && (
                <div className="flex items-center gap-2 mt-2 text-primary">
                  <Loader2 size={12} className="animate-spin" />
                  <span>Scanning in progress...</span>
                </div>
              )}
              {scanError && (
                <div className="flex items-center gap-2 mt-2 text-destructive">
                  <AlertCircle size={12} />
                  <span>Error: {scanError}</span>
                </div>
              )}
              {scanResult && (
                <div className="mt-2">
                  <div className="flex items-center gap-2 text-primary mb-2">
                    <CheckCircle size={12} />
                    <span>Scan completed successfully</span>
                  </div>
                  {renderResults(scanResult)?.map((line, i) => (
                    <div key={i} className={line.startsWith('  ✗') ? 'text-destructive' : line.startsWith('  ✓') || line.startsWith('[✓]') ? 'text-primary' : 'text-foreground/80'}>
                      {line || '\u00A0'}
                    </div>
                  ))}
                </div>
              )}
            </>
          ) : (
            simLines.map((line, i) => (
              <div key={i} className="text-terminal opacity-90">{line}</div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};

export default TerminalModal;
