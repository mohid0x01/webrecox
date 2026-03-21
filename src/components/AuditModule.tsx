import { useState } from 'react';
import { icons } from 'lucide-react';
import type { AuditTool } from '@/data/toolkitData';
import TerminalModal from './TerminalModal';
import { supabase } from '@/integrations/supabase/client';

interface AuditModuleProps {
  label: string;
  icon: string;
  tools: AuditTool[];
  target: string;
  index: number;
}

const AuditModule = ({ label, icon, tools, target, index }: AuditModuleProps) => {
  const [activeTool, setActiveTool] = useState<AuditTool | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState<any>(null);
  const [scanError, setScanError] = useState<string | null>(null);
  const IconComponent = icons[icon as keyof typeof icons];

  const handleAudit = async (tool: AuditTool) => {
    setActiveTool(tool);
    setScanResult(null);
    setScanError(null);

    if (tool.scanType) {
      setIsScanning(true);
      try {
        const { data, error } = await supabase.functions.invoke('run-scan', {
          body: { tool: tool.scanType, target },
        });
        if (error) throw error;
        if (data?.error) throw new Error(data.error);
        setScanResult(data.results);
      } catch (e: any) {
        setScanError(e.message || 'Scan failed');
      } finally {
        setIsScanning(false);
      }
    }
  };

  return (
    <>
      <div
        className="rounded-lg border border-border bg-card p-5 opacity-0 animate-fade-in-up hover:border-primary/20 transition-colors"
        style={{ animationDelay: `${index * 60}ms`, animationFillMode: 'forwards' }}
      >
        <div className="flex items-center gap-3 mb-4">
          {IconComponent && <IconComponent size={18} className="text-primary" />}
          <h3 className="text-sm font-semibold text-foreground tracking-tight">{label}</h3>
        </div>

        <div className="space-y-3">
          {tools.map(tool => (
            <div key={tool.name} className="flex items-start justify-between gap-3">
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <p className="text-sm font-medium text-foreground/90">{tool.name}</p>
                  {tool.scanType && (
                    <span className="px-1.5 py-0.5 text-[10px] font-medium rounded bg-primary/10 text-primary uppercase tracking-wider">Live</span>
                  )}
                </div>
                <p className="text-xs text-muted-foreground mt-0.5 leading-relaxed">{tool.description}</p>
              </div>
              <button
                onClick={() => handleAudit(tool)}
                className="shrink-0 px-3 py-1.5 text-xs font-medium rounded-md bg-primary/10 text-primary hover:bg-primary/20 transition-colors active:scale-[0.97]"
              >
                Begin Audit
              </button>
            </div>
          ))}
        </div>
      </div>

      <TerminalModal
        isOpen={activeTool !== null}
        onClose={() => setActiveTool(null)}
        toolName={activeTool?.name ?? ''}
        target={target}
        scanResult={scanResult}
        scanError={scanError}
        isScanning={isScanning}
        isRealScan={!!activeTool?.scanType}
      />
    </>
  );
};

export default AuditModule;
