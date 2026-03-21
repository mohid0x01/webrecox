import { useState, useCallback, useRef, useEffect } from 'react';
import { X } from 'lucide-react';

interface TerminalModalProps {
  isOpen: boolean;
  onClose: () => void;
  toolName: string;
  target: string;
}

const SIMULATED_LINES = [
  'Initializing audit engine...',
  'Loading compliance rulesets...',
  'Resolving target infrastructure...',
  'Establishing secure connection...',
  'Enumerating attack surface...',
  'Running signature analysis...',
  'Cross-referencing vulnerability database...',
  'Analyzing response patterns...',
  'Checking TLS certificate chain...',
  'Evaluating security headers...',
  'Scanning for misconfigurations...',
  'Processing results...',
  'Generating compliance report...',
  'Audit complete. No critical findings.',
];

const TerminalModal = ({ isOpen, onClose, toolName, target }: TerminalModalProps) => {
  const [lines, setLines] = useState<string[]>([]);
  const [isRunning, setIsRunning] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const startSimulation = useCallback(() => {
    setLines([]);
    setIsRunning(true);
    let i = 0;

    intervalRef.current = setInterval(() => {
      if (i < SIMULATED_LINES.length) {
        const line = SIMULATED_LINES[i].replace('target', target);
        setLines(prev => [...prev, `[${new Date().toISOString().slice(11, 19)}] ${line}`]);
        i++;
      } else {
        if (intervalRef.current) clearInterval(intervalRef.current);
        setIsRunning(false);
      }
    }, 320 + Math.random() * 280);
  }, [target]);

  useEffect(() => {
    if (isOpen) startSimulation();
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [isOpen, startSimulation]);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: 'smooth' });
  }, [lines]);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-background/80 backdrop-blur-sm" onClick={onClose}>
      <div
        className="w-full max-w-2xl mx-4 rounded-lg border border-border bg-card overflow-hidden animate-fade-in-up"
        onClick={e => e.stopPropagation()}
      >
        <div className="flex items-center justify-between px-4 py-3 border-b border-border">
          <div className="flex items-center gap-2">
            <div className="flex gap-1.5">
              <span className="w-3 h-3 rounded-full bg-destructive/80" />
              <span className="w-3 h-3 rounded-full" style={{ background: 'hsl(38, 92%, 50%)' }} />
              <span className="w-3 h-3 rounded-full bg-primary/80" />
            </div>
            <span className="ml-2 text-xs font-mono text-muted-foreground">{toolName} — {target}</span>
          </div>
          <button onClick={onClose} className="p-1 rounded-md hover:bg-muted transition-colors active:scale-95">
            <X size={14} className="text-muted-foreground" />
          </button>
        </div>

        <div ref={scrollRef} className="p-4 h-80 overflow-y-auto scrollbar-thin font-mono text-xs leading-relaxed">
          {lines.map((line, i) => (
            <div key={i} className="text-terminal opacity-90">{line}</div>
          ))}
          {isRunning && (
            <span className="inline-block w-2 h-4 bg-primary animate-pulse-terminal ml-0.5" />
          )}
        </div>
      </div>
    </div>
  );
};

export default TerminalModal;
