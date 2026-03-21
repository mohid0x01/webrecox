import { useState, useMemo } from 'react';
import { Shield, Search, Activity } from 'lucide-react';
import createToolkitData from '@/data/toolkitData';
import AuditModule from '@/components/AuditModule';

const Index = () => {
  const [target, setTarget] = useState('example.com');
  const categories = useMemo(() => createToolkitData(target), [target]);

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="border-b border-border">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Shield size={22} className="text-primary" />
            <div>
              <h1 className="text-base font-semibold tracking-tight text-foreground">CyberOps v4</h1>
              <p className="text-[11px] text-muted-foreground tracking-wide uppercase">Digital Asset Inventory & Security Compliance</p>
            </div>
          </div>
          <div className="flex items-center gap-3 text-xs text-muted-foreground">
            <Activity size={14} className="text-primary animate-pulse-terminal" />
            <span className="font-mono">{categories.reduce((a, c) => a + c.tools.length, 0)} modules loaded</span>
          </div>
        </div>
      </header>

      {/* Search */}
      <div className="max-w-7xl mx-auto px-6 py-8">
        <div className="relative max-w-xl">
          <Search size={16} className="absolute left-4 top-1/2 -translate-y-1/2 text-muted-foreground" />
          <input
            type="text"
            value={target}
            onChange={e => setTarget(e.target.value)}
            placeholder="Target Infrastructure"
            className="w-full pl-11 pr-4 py-3 rounded-lg border border-border bg-card text-sm font-mono text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary/50 transition-shadow"
          />
        </div>
        <p className="mt-2 text-xs text-muted-foreground">
          All audit modules will dynamically target <span className="font-mono text-terminal">{target}</span>
        </p>
      </div>

      {/* Modules Grid */}
      <main className="max-w-7xl mx-auto px-6 pb-16">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {categories.map((cat, i) => (
            <AuditModule
              key={cat.key}
              label={cat.label}
              icon={cat.icon}
              tools={cat.tools}
              target={target}
              index={i}
            />
          ))}
        </div>
      </main>
    </div>
  );
};

export default Index;
