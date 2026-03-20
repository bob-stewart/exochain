import { Canvas } from './components/Canvas';
import { NodePalette } from './components/NodePalette';
import { Inspector } from './components/Inspector';
import { ModeBar } from './components/ModeBar';
import { useBuilderStore } from './store/useBuilderStore';
import { useState } from 'react';
import * as yaml from 'js-yaml';

function PublishPanel() {
  const { workflow, updateWorkflowMeta, saveAsModule } = useBuilderStore();
  const [saved, setSaved] = useState(false);

  const exportJSON = () => {
    const blob = new Blob([JSON.stringify(workflow, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = `${workflow.name.replace(/\s+/g, '-').toLowerCase()}.json`; a.click();
    URL.revokeObjectURL(url);
  };

  const exportYAML = () => {
    const blob = new Blob([yaml.dump(workflow)], { type: 'text/yaml' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = `${workflow.name.replace(/\s+/g, '-').toLowerCase()}.yaml`; a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="absolute inset-0 bg-black/40 backdrop-blur-sm flex items-center justify-center z-50">
      <div className="w-[480px] rounded-2xl border border-white/[0.08] p-6" style={{ background: 'rgba(22,27,34,0.95)', backdropFilter: 'blur(24px)' }}>
        <div className="text-[14px] font-semibold mb-4">Publish Workflow as Module</div>

        <div className="mb-3">
          <label className="text-[9px] uppercase tracking-wider text-[#8b949e] font-semibold mb-1 block">Workflow Name</label>
          <input className="w-full text-[12px] bg-white/[0.04] border border-white/[0.08] rounded-lg px-3 py-2 text-[#e6edf3] outline-none focus:border-[#a371f7]"
            value={workflow.name} onChange={e => updateWorkflowMeta({ name: e.target.value })} />
        </div>
        <div className="mb-3">
          <label className="text-[9px] uppercase tracking-wider text-[#8b949e] font-semibold mb-1 block">Version</label>
          <input className="w-full text-[12px] bg-white/[0.04] border border-white/[0.08] rounded-lg px-3 py-2 text-[#e6edf3] outline-none focus:border-[#a371f7]"
            value={workflow.version} onChange={e => updateWorkflowMeta({ version: e.target.value })} />
        </div>
        <div className="mb-4">
          <label className="text-[9px] uppercase tracking-wider text-[#8b949e] font-semibold mb-1 block">Description</label>
          <textarea className="w-full text-[12px] bg-white/[0.04] border border-white/[0.08] rounded-lg px-3 py-2 text-[#e6edf3] outline-none focus:border-[#a371f7] h-20 resize-none"
            value={workflow.description} onChange={e => updateWorkflowMeta({ description: e.target.value })} />
        </div>

        <div className="flex gap-2">
          <button onClick={() => { saveAsModule(); setSaved(true); setTimeout(() => setSaved(false), 2000); }}
            className="flex-1 py-2 rounded-lg text-[11px] font-semibold bg-gradient-to-r from-[#a371f7] to-[#58a6ff] text-white">
            {saved ? '✓ Saved to Library' : 'Save as Module'}
          </button>
          <button onClick={exportJSON} className="px-3 py-2 rounded-lg text-[11px] font-medium bg-white/[0.05] border border-white/[0.08] text-[#8b949e] hover:text-[#e6edf3]">
            JSON
          </button>
          <button onClick={exportYAML} className="px-3 py-2 rounded-lg text-[11px] font-medium bg-white/[0.05] border border-white/[0.08] text-[#8b949e] hover:text-[#e6edf3]">
            YAML
          </button>
        </div>

        <div className="mt-3 text-[9px] text-[#8b949e]">
          {workflow.nodes.length} nodes · {workflow.edges.length} edges · {new Date(workflow.metadata.updatedAt).toLocaleString()}
        </div>
      </div>
    </div>
  );
}

function TestOverlay() {
  const { workflow, setNodeExecState, resetExecution, mode } = useBuilderStore();
  const [running, setRunning] = useState(false);

  const runTest = async () => {
    setRunning(true);
    resetExecution();

    // Topological sort (simple: follow edges)
    const visited = new Set<string>();
    const order: string[] = [];
    const adj = new Map<string, string[]>();
    for (const e of workflow.edges) {
      if (!adj.has(e.source)) adj.set(e.source, []);
      adj.get(e.source)!.push(e.target);
    }
    const sources = workflow.nodes.filter(n => !workflow.edges.some(e => e.target === n.id));
    const queue = sources.map(n => n.id);
    while (queue.length) {
      const id = queue.shift()!;
      if (visited.has(id)) continue;
      visited.add(id);
      order.push(id);
      for (const next of (adj.get(id) || [])) queue.push(next);
    }
    // Add any unvisited
    for (const n of workflow.nodes) if (!visited.has(n.id)) order.push(n.id);

    for (const id of order) {
      setNodeExecState(id, 'active');
      await new Promise(r => setTimeout(r, 600));
      setNodeExecState(id, 'done');
    }
    setRunning(false);
  };

  if (mode !== 'test') return null;

  return (
    <div className="absolute top-3 left-1/2 -translate-x-1/2 z-20">
      <button
        onClick={runTest}
        disabled={running || workflow.nodes.length === 0}
        className="px-5 py-2 rounded-xl text-[11px] font-semibold text-white disabled:opacity-40 transition-all"
        style={{ background: running ? 'rgba(163,113,247,0.3)' : 'linear-gradient(135deg, #a371f7, #58a6ff)', boxShadow: '0 4px 15px rgba(163,113,247,0.25)' }}
      >
        {running ? 'Executing...' : `▶ Run Test (${workflow.nodes.length} nodes)`}
      </button>
    </div>
  );
}

export default function App() {
  const { mode } = useBuilderStore();

  return (
    <div className="h-screen flex flex-col" style={{ background: '#06080f' }}>
      {/* Header */}
      <div className="h-12 flex items-center px-5 gap-3 border-b border-white/[0.06]" style={{ background: 'rgba(13,17,23,0.85)', backdropFilter: 'blur(20px)' }}>
        <span className="text-[16px] font-bold bg-gradient-to-r from-[#a371f7] to-[#39d2c0] bg-clip-text text-transparent">Syntaxis</span>
        <span className="text-[10px] text-[#8b949e] tracking-wider">VISUAL BUILDER</span>
        <div className="flex gap-1.5 ml-auto">
          {['ExoChain', 'CrossChecked', 'LegalDyne', 'Decision Forge', 'LiveSafe', '0dentity', 'CAIP'].map(b => (
            <span key={b} className="text-[8px] font-semibold px-2 py-0.5 rounded-full border border-white/[0.08] text-[#8b949e]">{b}</span>
          ))}
        </div>
      </div>

      {/* Mode bar */}
      <ModeBar />

      {/* Main three-panel layout */}
      <div className="flex-1 flex overflow-hidden">
        {/* Left: Node Palette */}
        <div className="w-[240px] flex-shrink-0 border-r border-white/[0.06]" style={{ background: 'rgba(13,17,23,0.7)', backdropFilter: 'blur(16px)' }}>
          <NodePalette />
        </div>

        {/* Center: Canvas */}
        <div className="flex-1 relative">
          <Canvas />
          <TestOverlay />
        </div>

        {/* Right: Inspector */}
        <div className="w-[300px] flex-shrink-0 border-l border-white/[0.06]" style={{ background: 'rgba(13,17,23,0.7)', backdropFilter: 'blur(16px)' }}>
          <Inspector />
        </div>
      </div>

      {/* Publish overlay */}
      {mode === 'publish' && <PublishPanel />}

      {/* Status bar */}
      <div className="h-6 flex items-center px-4 text-[9px] text-[#8b949e] border-t border-white/[0.06] gap-4" style={{ background: 'rgba(13,17,23,0.6)' }}>
        <span className="flex items-center gap-1"><span className="w-1.5 h-1.5 rounded-full bg-[#3fb950]" /> Connected</span>
        <span>Mode: {mode}</span>
        <span className="ml-auto">Syntaxis Visual Builder v0.1.0</span>
      </div>
    </div>
  );
}
