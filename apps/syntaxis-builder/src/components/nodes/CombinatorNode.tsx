import { memo } from 'react';
import { Handle, Position } from '@xyflow/react';
import type { NodeProps } from '@xyflow/react';
import type { NodeTypeConfig, NodeExecState } from '../../types';

interface CombNodeData { config: NodeTypeConfig; execState?: NodeExecState; [key: string]: unknown }

export const CombinatorNode = memo(({ data, selected }: NodeProps) => {
  const d = data as CombNodeData;
  const cfg = d.config;
  const exec = d.execState || 'idle';
  const borderColor = exec === 'done' ? '#3fb950' : exec === 'active' ? cfg.color : exec === 'error' ? '#f85149' : selected ? cfg.color : 'rgba(255,255,255,0.08)';

  return (
    <div style={{
      width: 120, padding: '8px 10px',
      background: 'rgba(255,255,255,0.03)',
      backdropFilter: 'blur(20px)',
      border: `1.5px solid ${borderColor}`,
      borderRadius: 12,
      boxShadow: (exec === 'active' || selected) ? `0 0 16px ${cfg.glow}` : 'none',
      transition: 'all 0.3s',
    }}>
      <div className="flex items-center gap-1.5 mb-1">
        <span className="text-sm">{cfg.icon}</span>
        <span className="text-[10px] font-semibold truncate" style={{ color: cfg.color }}>{cfg.name}</span>
      </div>
      <div className="text-[8px] text-[#8b949e]">{cfg.combinators?.[0]?.exochainTerm || cfg.description}</div>

      <Handle type="target" position={Position.Left} id="in" style={{ width: 8, height: 8, background: '#a371f7', border: '2px solid #0d1117' }} />
      <Handle type="source" position={Position.Right} id="out" style={{ width: 8, height: 8, background: '#a371f7', border: '2px solid #0d1117' }} />
    </div>
  );
});

CombinatorNode.displayName = 'CombinatorNode';
