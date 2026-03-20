import { memo } from 'react';
import { Handle, Position } from '@xyflow/react';
import type { NodeProps } from '@xyflow/react';
import type { NodeTypeConfig } from '../../types';

interface ControlNodeData { config: NodeTypeConfig; [key: string]: unknown }

export const ControlNode = memo(({ data, selected }: NodeProps) => {
  const d = data as ControlNodeData;
  const cfg = d.config;
  return (
    <div style={{
      width: 100, padding: '8px 10px', textAlign: 'center',
      background: 'rgba(255,255,255,0.03)',
      backdropFilter: 'blur(20px)',
      border: `1.5px solid ${selected ? cfg.color : 'rgba(255,255,255,0.06)'}`,
      borderRadius: 10,
      boxShadow: selected ? `0 0 12px ${cfg.glow}` : 'none',
      transition: 'all 0.3s',
    }}>
      <div className="text-lg mb-0.5">{cfg.icon}</div>
      <div className="text-[10px] font-semibold" style={{ color: cfg.color }}>{cfg.name}</div>

      {cfg.moduleRef !== 'input' && <Handle type="target" position={Position.Left} id="in" style={{ width: 8, height: 8, background: '#8b949e', border: '2px solid #0d1117' }} />}
      {cfg.moduleRef !== 'output' && cfg.outputs.map((o, i) => (
        <Handle key={o} type="source" position={Position.Right} id={o} style={{ top: `${40 + i * 20}%`, width: 8, height: 8, background: '#8b949e', border: '2px solid #0d1117' }} />
      ))}
    </div>
  );
});

ControlNode.displayName = 'ControlNode';
