import { useBuilderStore } from '../store/useBuilderStore';
import type { BuilderMode } from '../types';

const MODES: { mode: BuilderMode; label: string; icon: string }[] = [
  { mode: 'build', label: 'Build', icon: '🔧' },
  { mode: 'test', label: 'Test', icon: '▶' },
  { mode: 'demo', label: 'Demo', icon: '📺' },
  { mode: 'publish', label: 'Publish', icon: '🚀' },
];

export function ModeBar() {
  const { mode, setMode, workflow, savedModules } = useBuilderStore();

  return (
    <div className="h-11 flex items-center px-4 gap-3 border-b border-white/[0.06]" style={{ background: 'rgba(13,17,23,0.7)', backdropFilter: 'blur(12px)' }}>
      {/* Mode tabs */}
      <div className="flex gap-0.5 p-0.5 rounded-lg bg-white/[0.03]">
        {MODES.map(m => (
          <button
            key={m.mode}
            onClick={() => setMode(m.mode)}
            className={`flex items-center gap-1.5 px-3 py-1 rounded-md text-[11px] font-medium transition-all ${mode === m.mode ? 'bg-white/[0.08] text-[#e6edf3]' : 'text-[#8b949e] hover:text-[#e6edf3]'}`}
          >
            <span className="text-[10px]">{m.icon}</span>
            {m.label}
          </button>
        ))}
      </div>

      {/* Workflow name */}
      <div className="flex-1 text-center">
        <span className="text-[12px] font-semibold text-[#e6edf3]">{workflow.name}</span>
        <span className="text-[9px] text-[#8b949e] ml-2">v{workflow.version}</span>
      </div>

      {/* Stats */}
      <div className="flex items-center gap-4 text-[9px] text-[#8b949e]">
        <span>{workflow.nodes.length} nodes</span>
        <span>{workflow.edges.length} edges</span>
        <span>{savedModules.length} modules</span>
      </div>
    </div>
  );
}
