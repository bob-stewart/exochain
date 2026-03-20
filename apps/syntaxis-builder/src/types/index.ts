export interface PortDef {
  id: string;
  name: string;
  type: string; // e.g. 'address', 'object', 'string', 'boolean'
}

export interface CombinatorDef {
  type: string;
  exochainTerm: string;
  args?: Record<string, unknown>;
  description: string;
}

export interface CouncilRoleDef {
  id: string;
  name: string;
  vetoCapable: boolean;
  decisionClasses?: string[];
}

export interface NodeTypeConfig {
  moduleRef: string;
  category: 'service' | 'combinator' | 'control';
  icon: string;
  name: string;
  description: string;
  color: string;
  glow: string;
  module?: string;
  exochainCrates?: string[];
  gatewayPrefix?: string;
  service?: { name: string; port: number; protocol: string; healthEndpoint: string };
  parameters: { key: string; type: string; required: boolean; description: string; default?: unknown; values?: string[] }[];
  outputs: string[];
  combinators?: CombinatorDef[];
  councilRoles?: CouncilRoleDef[];
  paceConfig?: { threshold: string; recoveryPolicy: string; shards: number };
  gates?: string[];
  decisionClasses?: string[];
  signals?: { source: string; description: string }[];
  version: string;
}

export interface WorkflowNode {
  id: string;
  type: 'service' | 'combinator' | 'control' | 'module';
  moduleRef: string;
  position: { x: number; y: number };
  config: Record<string, unknown>;
}

export interface WorkflowEdge {
  id: string;
  source: string;
  sourceHandle: string | null;
  target: string;
  targetHandle: string | null;
}

export interface WorkflowDefinition {
  id: string;
  name: string;
  version: string;
  description: string;
  nodes: WorkflowNode[];
  edges: WorkflowEdge[];
  metadata: { author: string; createdAt: string; updatedAt: string };
}

export type BuilderMode = 'build' | 'test' | 'demo' | 'publish';
export type NodeExecState = 'idle' | 'active' | 'done' | 'error';
