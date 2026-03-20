import { useBuilderStore } from '../store/useBuilderStore';
import { getNodeType } from '../registry/nodeTypes';

export function Inspector() {
  const { workflow, selectedNodeId, updateNodeConfig, removeNode } = useBuilderStore();
  const node = workflow.nodes.find(n => n.id === selectedNodeId);
  const cfg = node ? getNodeType(node.moduleRef) : null;

  if (!node || !cfg) {
    return (
      <div className="h-full flex items-center justify-center p-4">
        <div className="text-center text-[#8b949e]">
          <div className="text-2xl mb-2 opacity-30">⚙️</div>
          <div className="text-[11px]">Select a node to inspect</div>
          <div className="text-[9px] mt-1">Click a node on the canvas or drag one from the palette</div>
        </div>
      </div>
    );
  }

  const setConfigField = (key: string, value: unknown) => updateNodeConfig(node.id, { [key]: value });

  return (
    <div className="h-full overflow-y-auto p-3">
      {/* Header */}
      <div className="flex items-center gap-2 mb-3 pb-3 border-b border-white/[0.06]">
        <span className="text-xl">{cfg.icon}</span>
        <div className="flex-1 min-w-0">
          <div className="text-[13px] font-semibold truncate">{cfg.name}</div>
          <div className="text-[9px] text-[#8b949e]">{cfg.module || cfg.moduleRef} — v{cfg.version}</div>
        </div>
        <button onClick={() => removeNode(node.id)} className="text-[9px] px-2 py-1 rounded border border-[#f85149]/30 text-[#f85149] hover:bg-[#f85149]/10 transition-colors">
          Delete
        </button>
      </div>

      {/* Service Endpoint */}
      {cfg.service && (
        <Section title="Service Endpoint">
          <Row k="Service" v={cfg.service.name} />
          <Row k="Port" v={String(cfg.service.port)} color={cfg.color} />
          <Row k="Protocol" v={cfg.service.protocol} />
          <Row k="Health" v={cfg.service.healthEndpoint} color="#3fb950" />
        </Section>
      )}

      {/* ExoChain Binding */}
      {cfg.exochainCrates && cfg.exochainCrates.length > 0 && (
        <Section title="ExoChain Binding">
          <Row k="Module" v={cfg.module || cfg.moduleRef} color="#a371f7" />
          {cfg.gatewayPrefix && <Row k="Gateway" v={cfg.gatewayPrefix} color="#39d2c0" />}
          <div className="flex flex-wrap gap-1 mt-1">
            {cfg.exochainCrates.map(c => (
              <span key={c} className="text-[8px] font-semibold px-1.5 py-0.5 rounded" style={{ background: 'rgba(57,210,192,0.1)', color: '#39d2c0' }}>{c}</span>
            ))}
          </div>
        </Section>
      )}

      {/* Parameters — Editable */}
      {cfg.parameters.length > 0 && (
        <Section title="Parameters">
          {cfg.parameters.map(p => (
            <div key={p.key} className="mb-2">
              <div className="flex items-center gap-1 mb-0.5">
                <span className="text-[9px] font-medium text-[#8b949e]">{p.key}</span>
                {p.required && <span className="text-[8px] text-[#f85149]">*</span>}
                <span className="text-[8px] ml-auto" style={{ color: '#f0883e' }}>{p.type}</span>
              </div>
              {p.values ? (
                <select
                  className="w-full text-[10px] bg-white/[0.04] border border-white/[0.08] rounded-md px-2 py-1.5 text-[#e6edf3] outline-none focus:border-[#a371f7]"
                  value={(node.config[p.key] as string) ?? p.default ?? ''}
                  onChange={e => setConfigField(p.key, e.target.value)}
                >
                  {p.values.map(v => <option key={v} value={v}>{v}</option>)}
                </select>
              ) : p.type === 'boolean' ? (
                <button
                  className={`w-9 h-5 rounded-full transition-colors ${(node.config[p.key] ?? p.default) ? 'bg-[#3fb950]' : 'bg-white/10'}`}
                  onClick={() => setConfigField(p.key, !(node.config[p.key] ?? p.default))}
                >
                  <div className={`w-4 h-4 rounded-full bg-white transition-transform ml-0.5 ${(node.config[p.key] ?? p.default) ? 'translate-x-4' : ''}`} />
                </button>
              ) : (
                <input
                  className="w-full text-[10px] bg-white/[0.04] border border-white/[0.08] rounded-md px-2 py-1.5 text-[#e6edf3] outline-none focus:border-[#a371f7] font-mono"
                  value={(node.config[p.key] as string) ?? p.default ?? ''}
                  onChange={e => setConfigField(p.key, p.type === 'number' ? Number(e.target.value) : e.target.value)}
                  placeholder={p.description}
                />
              )}
              <div className="text-[8px] text-[#8b949e] mt-0.5">{p.description}</div>
            </div>
          ))}
        </Section>
      )}

      {/* Outputs */}
      {cfg.outputs.length > 0 && (
        <Section title="Outputs">
          <div className="flex flex-wrap gap-1">
            {cfg.outputs.map(o => (
              <span key={o} className="text-[8px] font-semibold px-1.5 py-0.5 rounded" style={{ background: 'rgba(63,185,80,0.1)', color: '#3fb950' }}>{o}</span>
            ))}
          </div>
        </Section>
      )}

      {/* Combinators */}
      {cfg.combinators && cfg.combinators.length > 0 && (
        <Section title="Governance Combinators">
          {cfg.combinators.map((c, i) => (
            <div key={i} className="mb-2 p-2 rounded-lg bg-white/[0.02] border border-white/[0.04]">
              <div className="flex items-center justify-between mb-0.5">
                <span className="text-[9px] font-semibold" style={{ color: '#a371f7' }}>{c.type}</span>
                <span className="text-[8px] font-mono text-[#39d2c0]">{c.exochainTerm}</span>
              </div>
              <div className="text-[8px] text-[#8b949e]">{c.description}</div>
              {c.args && (
                <div className="mt-1 p-1.5 rounded bg-white/[0.02] text-[8px] font-mono text-[#39d2c0]">
                  {JSON.stringify(c.args)}
                </div>
              )}
            </div>
          ))}
        </Section>
      )}

      {/* Council Roles */}
      {cfg.councilRoles && cfg.councilRoles.length > 0 && (
        <Section title="Council Roles">
          {cfg.councilRoles.map(r => (
            <div key={r.id} className="flex items-center justify-between py-1">
              <span className="text-[10px]">{r.name}</span>
              <span className={`text-[8px] font-semibold px-1.5 py-0.5 rounded ${r.vetoCapable ? 'bg-[#f85149]/10 text-[#f85149]' : 'bg-white/5 text-[#8b949e]'}`}>
                {r.vetoCapable ? 'Veto' : 'No veto'}
              </span>
            </div>
          ))}
        </Section>
      )}

      {/* PACE Config */}
      {cfg.paceConfig && (
        <Section title="PACE Configuration">
          <Row k="Threshold" v={cfg.paceConfig.threshold} color="#3fb950" />
          <Row k="Recovery" v={cfg.paceConfig.recoveryPolicy} />
          <Row k="Shards" v={String(cfg.paceConfig.shards)} />
        </Section>
      )}

      {/* Gates */}
      {cfg.gates && cfg.gates.length > 0 && (
        <Section title="Governance Gates">
          <div className="flex flex-wrap gap-1">
            {cfg.gates.map(g => (
              <span key={g} className="text-[8px] font-semibold px-1.5 py-0.5 rounded" style={{ background: 'rgba(163,113,247,0.1)', color: '#a371f7' }}>{g}</span>
            ))}
          </div>
        </Section>
      )}

      {/* Decision Classes */}
      {cfg.decisionClasses && cfg.decisionClasses.length > 0 && (
        <Section title="Decision Classes">
          <div className="flex flex-wrap gap-1">
            {cfg.decisionClasses.map(d => (
              <span key={d} className="text-[8px] font-semibold px-1.5 py-0.5 rounded" style={{ background: 'rgba(88,166,255,0.1)', color: '#58a6ff' }}>{d}</span>
            ))}
          </div>
        </Section>
      )}

      {/* Signals */}
      {cfg.signals && cfg.signals.length > 0 && (
        <Section title="Consensus Signals">
          {cfg.signals.map(s => (
            <div key={s.source} className="flex items-start gap-2 py-1">
              <span className="text-[9px] font-medium text-[#3fb950] flex-shrink-0">{s.source}</span>
              <span className="text-[8px] text-[#8b949e]">{s.description}</span>
            </div>
          ))}
        </Section>
      )}

      {/* Node ID */}
      <Section title="Node Info">
        <Row k="Node ID" v={node.id} color="#8b949e" />
        <Row k="Type" v={node.type} />
        <Row k="Module Ref" v={node.moduleRef} color="#a371f7" />
      </Section>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="mb-4">
      <div className="flex items-center gap-1.5 mb-2">
        <span className="text-[9px] uppercase tracking-wider font-semibold text-[#8b949e]">{title}</span>
        <div className="flex-1 h-px bg-white/[0.04]" />
      </div>
      {children}
    </div>
  );
}

function Row({ k, v, color }: { k: string; v: string; color?: string }) {
  return (
    <div className="flex items-center justify-between py-0.5 text-[10px]">
      <span className="text-[#8b949e]">{k}</span>
      <span className="font-medium font-mono" style={color ? { color } : undefined}>{v}</span>
    </div>
  );
}
