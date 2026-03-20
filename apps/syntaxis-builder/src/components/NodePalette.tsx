import { useState } from 'react';
import { SERVICE_NODES, COMBINATOR_NODES, CONTROL_NODES } from '../registry/nodeTypes';
import type { NodeTypeConfig } from '../types';

function PaletteSection({ title, nodes, defaultOpen = true }: { title: string; nodes: NodeTypeConfig[]; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen);

  const onDragStart = (e: React.DragEvent, cfg: NodeTypeConfig) => {
    e.dataTransfer.setData('application/syntaxis-moduleRef', cfg.moduleRef);
    e.dataTransfer.setData('application/syntaxis-type', cfg.category);
    e.dataTransfer.effectAllowed = 'move';
  };

  return (
    <div className="mb-3">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center gap-1.5 text-[10px] uppercase tracking-wider font-semibold text-[#8b949e] mb-1.5 hover:text-[#e6edf3] transition-colors"
      >
        <span className="text-[8px]">{open ? '▼' : '▶'}</span>
        {title}
        <span className="ml-auto text-[8px] font-normal">{nodes.length}</span>
      </button>
      {open && (
        <div className="flex flex-col gap-1">
          {nodes.map(cfg => (
            <div
              key={cfg.moduleRef}
              draggable
              onDragStart={e => onDragStart(e, cfg)}
              className="flex items-center gap-2 px-2.5 py-2 rounded-lg cursor-grab active:cursor-grabbing transition-all hover:bg-white/[0.04] border border-transparent hover:border-white/[0.08]"
              style={{ borderLeftColor: cfg.color, borderLeftWidth: 2 }}
            >
              <span className="text-sm flex-shrink-0">{cfg.icon}</span>
              <div className="min-w-0 flex-1">
                <div className="text-[11px] font-medium truncate">{cfg.name}</div>
                <div className="text-[9px] text-[#8b949e] truncate">{cfg.description}</div>
              </div>
              {cfg.service && (
                <span className="text-[8px] font-mono px-1 py-0.5 rounded flex-shrink-0"
                  style={{ background: `${cfg.color}15`, color: cfg.color }}>
                  :{cfg.service.port}
                </span>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export function NodePalette() {
  return (
    <div className="h-full overflow-y-auto p-3">
      <div className="text-[11px] font-semibold mb-3 flex items-center gap-2">
        <span className="text-sm">🧩</span> Node Palette
      </div>
      <PaletteSection title="ExoChain Services" nodes={SERVICE_NODES} />
      <PaletteSection title="Governance Combinators" nodes={COMBINATOR_NODES} />
      <PaletteSection title="Control Flow" nodes={CONTROL_NODES} defaultOpen={false} />
    </div>
  );
}
