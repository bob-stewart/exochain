import { useCallback, useMemo, useRef } from 'react';
import { ReactFlow, Background, Controls, MiniMap, BackgroundVariant, useReactFlow, ReactFlowProvider } from '@xyflow/react';
import type { Node, Edge, Connection, OnNodesChange, OnEdgesChange, NodeChange, EdgeChange, XYPosition } from '@xyflow/react';
import { useBuilderStore } from '../store/useBuilderStore';
import { getNodeType } from '../registry/nodeTypes';
import { ServiceNode } from './nodes/ServiceNode';
import { CombinatorNode } from './nodes/CombinatorNode';
import { ControlNode } from './nodes/ControlNode';

const nodeTypes = { service: ServiceNode, combinator: CombinatorNode, control: ControlNode };

function CanvasInner() {
  const { workflow, addNode, addEdge, updateNodePosition, removeNode, removeEdge, selectNode, executionState, mode } = useBuilderStore();
  const reactFlowWrapper = useRef<HTMLDivElement>(null);
  const { screenToFlowPosition } = useReactFlow();

  const rfNodes: Node[] = useMemo(() =>
    workflow.nodes.map(n => {
      const cfg = getNodeType(n.moduleRef);
      return {
        id: n.id,
        type: n.type === 'combinator' ? 'combinator' : n.type === 'control' ? 'control' : 'service',
        position: n.position,
        data: { config: cfg, execState: executionState[n.id] || 'idle', ...n.config },
        selected: false,
      };
    }), [workflow.nodes, executionState]);

  const rfEdges: Edge[] = useMemo(() =>
    workflow.edges.map(e => ({
      id: e.id,
      source: e.source,
      sourceHandle: e.sourceHandle,
      target: e.target,
      targetHandle: e.targetHandle,
      animated: mode === 'test' && executionState[e.source] === 'active',
      style: {
        stroke: executionState[e.source] === 'done' ? '#3fb950' : executionState[e.source] === 'active' ? '#a371f7' : 'rgba(255,255,255,0.12)',
        strokeWidth: 2,
      },
    })), [workflow.edges, executionState, mode]);

  const onNodesChange: OnNodesChange = useCallback((changes: NodeChange[]) => {
    for (const c of changes) {
      if (c.type === 'position' && c.position) updateNodePosition(c.id, c.position);
      if (c.type === 'remove') removeNode(c.id);
    }
  }, [updateNodePosition, removeNode]);

  const onEdgesChange: OnEdgesChange = useCallback((changes: EdgeChange[]) => {
    for (const c of changes) {
      if (c.type === 'remove') removeEdge(c.id);
    }
  }, [removeEdge]);

  const onConnect = useCallback((conn: Connection) => {
    if (!conn.source || !conn.target) return;
    addEdge({ id: `e-${conn.source}-${conn.target}-${Date.now()}`, source: conn.source, sourceHandle: conn.sourceHandle ?? null, target: conn.target, targetHandle: conn.targetHandle ?? null });
  }, [addEdge]);

  const onNodeClick = useCallback((_: unknown, node: Node) => selectNode(node.id), [selectNode]);
  const onPaneClick = useCallback(() => selectNode(null), [selectNode]);

  const onDragOver = useCallback((e: React.DragEvent) => { e.preventDefault(); e.dataTransfer.dropEffect = 'move'; }, []);

  const onDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    const moduleRef = e.dataTransfer.getData('application/syntaxis-moduleRef');
    const nodeType = e.dataTransfer.getData('application/syntaxis-type') as 'service' | 'combinator' | 'control';
    if (!moduleRef) return;

    const position: XYPosition = screenToFlowPosition({ x: e.clientX, y: e.clientY });
    addNode({
      id: `n-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
      type: nodeType,
      moduleRef,
      position,
      config: {},
    });
  }, [screenToFlowPosition, addNode]);

  return (
    <div ref={reactFlowWrapper} className="w-full h-full">
      <ReactFlow
        nodes={rfNodes}
        edges={rfEdges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onConnect={onConnect}
        onNodeClick={onNodeClick}
        onPaneClick={onPaneClick}
        onDragOver={onDragOver}
        onDrop={onDrop}
        nodeTypes={nodeTypes}
        fitView
        deleteKeyCode="Backspace"
        proOptions={{ hideAttribution: true }}
      >
        <Background variant={BackgroundVariant.Dots} gap={24} size={1} color="rgba(255,255,255,0.04)" />
        <Controls position="bottom-left" />
        <MiniMap
          nodeStrokeWidth={3}
          maskColor="rgba(6,8,15,0.8)"
          style={{ background: '#0d1117' }}
        />
      </ReactFlow>
    </div>
  );
}

export function Canvas() {
  return (
    <ReactFlowProvider>
      <CanvasInner />
    </ReactFlowProvider>
  );
}
