import { create } from 'zustand';
import type { WorkflowDefinition, WorkflowNode, WorkflowEdge, BuilderMode, NodeExecState } from '../types';

interface BuilderStore {
  workflow: WorkflowDefinition;
  selectedNodeId: string | null;
  mode: BuilderMode;
  executionState: Record<string, NodeExecState>;
  executionResults: Record<string, unknown>;
  savedModules: WorkflowDefinition[];

  addNode: (node: WorkflowNode) => void;
  removeNode: (id: string) => void;
  updateNodePosition: (id: string, position: { x: number; y: number }) => void;
  updateNodeConfig: (id: string, config: Record<string, unknown>) => void;
  addEdge: (edge: WorkflowEdge) => void;
  removeEdge: (id: string) => void;
  selectNode: (id: string | null) => void;
  setMode: (mode: BuilderMode) => void;
  setNodeExecState: (id: string, state: NodeExecState) => void;
  setExecResult: (id: string, result: unknown) => void;
  resetExecution: () => void;
  updateWorkflowMeta: (meta: Partial<Pick<WorkflowDefinition, 'name' | 'description' | 'version'>>) => void;
  saveAsModule: () => void;
  importWorkflow: (wf: WorkflowDefinition) => void;
  clearWorkflow: () => void;
}

const EMPTY_WORKFLOW: WorkflowDefinition = {
  id: crypto.randomUUID(),
  name: 'Untitled Workflow',
  version: '0.1.0',
  description: '',
  nodes: [],
  edges: [],
  metadata: { author: 'syntaxis', createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() },
};

export const useBuilderStore = create<BuilderStore>((set, get) => ({
  workflow: { ...EMPTY_WORKFLOW },
  selectedNodeId: null,
  mode: 'build',
  executionState: {},
  executionResults: {},
  savedModules: [],

  addNode: (node) => set(s => ({
    workflow: { ...s.workflow, nodes: [...s.workflow.nodes, node], metadata: { ...s.workflow.metadata, updatedAt: new Date().toISOString() } },
  })),

  removeNode: (id) => set(s => ({
    workflow: {
      ...s.workflow,
      nodes: s.workflow.nodes.filter(n => n.id !== id),
      edges: s.workflow.edges.filter(e => e.source !== id && e.target !== id),
      metadata: { ...s.workflow.metadata, updatedAt: new Date().toISOString() },
    },
    selectedNodeId: s.selectedNodeId === id ? null : s.selectedNodeId,
  })),

  updateNodePosition: (id, position) => set(s => ({
    workflow: { ...s.workflow, nodes: s.workflow.nodes.map(n => n.id === id ? { ...n, position } : n) },
  })),

  updateNodeConfig: (id, config) => set(s => ({
    workflow: {
      ...s.workflow,
      nodes: s.workflow.nodes.map(n => n.id === id ? { ...n, config: { ...n.config, ...config } } : n),
      metadata: { ...s.workflow.metadata, updatedAt: new Date().toISOString() },
    },
  })),

  addEdge: (edge) => set(s => ({
    workflow: { ...s.workflow, edges: [...s.workflow.edges, edge], metadata: { ...s.workflow.metadata, updatedAt: new Date().toISOString() } },
  })),

  removeEdge: (id) => set(s => ({
    workflow: { ...s.workflow, edges: s.workflow.edges.filter(e => e.id !== id), metadata: { ...s.workflow.metadata, updatedAt: new Date().toISOString() } },
  })),

  selectNode: (id) => set({ selectedNodeId: id }),
  setMode: (mode) => set({ mode }),

  setNodeExecState: (id, state) => set(s => ({ executionState: { ...s.executionState, [id]: state } })),
  setExecResult: (id, result) => set(s => ({ executionResults: { ...s.executionResults, [id]: result } })),
  resetExecution: () => set({ executionState: {}, executionResults: {} }),

  updateWorkflowMeta: (meta) => set(s => ({
    workflow: { ...s.workflow, ...meta, metadata: { ...s.workflow.metadata, updatedAt: new Date().toISOString() } },
  })),

  saveAsModule: () => {
    const wf = get().workflow;
    set(s => ({ savedModules: [...s.savedModules, { ...wf, id: crypto.randomUUID() }] }));
  },

  importWorkflow: (wf) => set({ workflow: wf, selectedNodeId: null }),

  clearWorkflow: () => set({ workflow: { ...EMPTY_WORKFLOW, id: crypto.randomUUID() }, selectedNodeId: null }),
}));
