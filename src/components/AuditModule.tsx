import { useState } from 'react';
import { icons } from 'lucide-react';
import type { AuditTool } from '@/data/toolkitData';
import TerminalModal from './TerminalModal';

interface AuditModuleProps {
  label: string;
  icon: string;
  tools: AuditTool[];
  target: string;
  index: number;
}

const AuditModule = ({ label, icon, tools, target, index }: AuditModuleProps) => {
  const [activeTool, setActiveTool] = useState<string | null>(null);
  const IconComponent = icons[icon as keyof typeof icons];

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
                <p className="text-sm font-medium text-foreground/90">{tool.name}</p>
                <p className="text-xs text-muted-foreground mt-0.5 leading-relaxed">{tool.description}</p>
              </div>
              <button
                onClick={() => setActiveTool(tool.name)}
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
        toolName={activeTool ?? ''}
        target={target}
      />
    </>
  );
};

export default AuditModule;
