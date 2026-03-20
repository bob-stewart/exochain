import { memo } from 'react';
import { Handle, Position } from '@xyflow/react';
import type { NodeProps } from '@xyflow/react';
import type { NodeTypeConfig, NodeExecState } from '../../types';

interface ServiceNodeData {
  config: NodeTypeConfig;
  execState?: NodeExecState;
  label?: string;
  [key: string]: unknown;
}

const EXEC_STYLES: Record<NodeExecState, { border: string; shadow: string; pulse: string }> = {
  idle: { border: 'rgba(255,255,255,0.06)', shadow: 'none', pulse: 'rgba(255,255,255,0.15)' },
  active: { border: 'var(--node-color)', shadow: '0 0 24px var(--node-glow)', pulse: 'var(--node-color)' },
  done: { border: '#3fb950', shadow: '0 0 16px rgba(63,185,80,.25)', pulse: '#3fb950' },
  error: { border: '#f85149', shadow: '0 0 16px rgba(248,81,73,.25)', pulse: '#f85149' },
};

export const ServiceNode = memo(({ data, selected }: NodeProps) => {
  const d = data as ServiceNodeData;
  const cfg = d.config;
  const exec = d.execState || 'idle';
  const st = EXEC_STYLES[exec];

  return (
    <div
      className="relative rounded-2xl overflow-hidden"
      style={{
        width: 200,
        background: 'rgba(255,255,255,0.03)',
        backdropFilter: 'blur(24px) saturate(1.4)',
        border: `1.5px solid ${selected ? cfg.color : st.border}`,
        boxShadow: selected ? `0 0 20px ${cfg.glow}` : st.shadow,
        ['--node-color' as string]: cfg.color,
        ['--node-glow' as string]: cfg.glow,
        transition: 'all 0.3s cubic-bezier(.4,0,.2,1)',
      }}
    >
      {/* Top shine */}
      <div className="absolute top-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-white/15 to-transparent" />

      {/* Left module color bar */}
      <div className="absolute left-0 top-0 bottom-0 w-[3px] rounded-l-2xl" style={{ background: cfg.color }} />

      <div className="p-3 pl-4">
        {/* Header */}
        <div className="flex items-center gap-2 mb-1">
          <span className="text-lg">{cfg.icon}</span>
          <span className="text-[11px] font-semibold flex-1 truncate">{cfg.name}</span>
          {cfg.service && (
            <span className="text-[8px] font-mono px-1.5 py-0.5 rounded" style={{ background: `${cfg.color}20`, color: cfg.color }}>
              {cfg.service.port}
            </span>
          )}
        </div>

        {/* Description */}
        <div className="text-[9px] text-[#8b949e] mb-2">{cfg.description}</div>

        {/* Combinators */}
        {cfg.combinators && cfg.combinators.length > 0 && (
          <div className="flex flex-wrap gap-1 mb-2">
            {cfg.combinators.slice(0, 3).map((c, i) => (
              <span key={i} className="text-[8px] font-semibold px-1.5 py-0.5 rounded" style={{ background: 'rgba(163,113,247,0.12)', color: '#a371f7' }}>
                {c.type}
              </span>
            ))}
          </div>
        )}

        {/* Status */}
        <div className="flex items-center gap-1.5">
          <span
            className="w-[7px] h-[7px] rounded-full flex-shrink-0"
            style={{
              background: st.pulse,
              animation: exec === 'active' ? 'nodePulse 1.2s ease-in-out infinite' : 'none',
            }}
          />
          <span className="text-[9px] text-[#8b949e] capitalize">{exec}</span>
        </div>
      </div>

      {/* Input handles */}
      {cfg.parameters.map((p, i) => (
        <Handle
          key={`in-${p.key}`}
          type="target"
          position={Position.Left}
          id={p.key}
          style={{
            top: `${30 + i * 18}%`,
            width: 10, height: 10,
            background: '#58a6ff',
            border: '2px solid #0d1117',
          }}
          title={`${p.key} (${p.type})`}
        />
      ))}

      {/* Output handles */}
      {cfg.outputs.map((o, i) => (
        <Handle
          key={`out-${o}`}
          type="source"
          position={Position.Right}
          id={o}
          style={{
            top: `${30 + i * 18}%`,
            width: 10, height: 10,
            background: '#3fb950',
            border: '2px solid #0d1117',
          }}
          title={o}
        />
      ))}
    </div>
  );
});

ServiceNode.displayName = 'ServiceNode';
