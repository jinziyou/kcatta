"use client";

import {
  Background,
  Controls,
  type Edge,
  MiniMap,
  type Node,
  Position,
  ReactFlow,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";

import type { AttackPathStep, Severity } from "@/lib/contracts";

const SEVERITY_COLOR: Record<Severity, string> = {
  critical: "#dc2626",
  high: "#f97316",
  medium: "#f59e0b",
  low: "#94a3b8",
  info: "#cbd5e1",
};

const COLUMN_WIDTH = 300;
const ROW_HEIGHT = 118;

/**
 * Node-link view of a predicted attack path. Each step is a node; hosts become
 * columns so a pivot to another host visibly steps sideways. Edges are labelled
 * with the tactic and coloured by the path's severity.
 */
export function AttackGraph({
  steps,
  severity,
}: {
  steps: AttackPathStep[];
  severity: Severity;
}) {
  const color = SEVERITY_COLOR[severity];

  const hostColumn = new Map<string, number>();
  for (const step of steps) {
    if (!hostColumn.has(step.host_id)) hostColumn.set(step.host_id, hostColumn.size);
  }

  const nodes: Node[] = steps.map((step, i) => ({
    id: String(i),
    position: { x: (hostColumn.get(step.host_id) ?? 0) * COLUMN_WIDTH, y: i * ROW_HEIGHT },
    data: {
      label: `${step.technique_id || "—"}  ·  ${step.tactic}\n${step.module_id}\n@ ${step.host_label || step.host_id}`,
    },
    sourcePosition: Position.Bottom,
    targetPosition: Position.Top,
    className:
      "whitespace-pre-line rounded-md border-2 bg-card p-2 text-[11px] leading-snug text-card-foreground",
    style: { width: 240, borderColor: color },
  }));

  const edges: Edge[] = steps.slice(1).map((step, i) => ({
    id: `e${i}`,
    source: String(i),
    target: String(i + 1),
    animated: true,
    label: step.host_id !== steps[i].host_id ? `pivot · ${step.tactic}` : step.tactic,
    style: { stroke: color },
    labelStyle: { fontSize: 10, fill: "currentColor" },
    labelBgStyle: { fill: "var(--background)" },
  }));

  return (
    <div
      className="rounded-md border"
      style={{ height: Math.max(380, steps.length * ROW_HEIGHT + 80) }}
    >
      <ReactFlow nodes={nodes} edges={edges} fitView minZoom={0.2}>
        <Background />
        <Controls showInteractive={false} />
        <MiniMap pannable zoomable />
      </ReactFlow>
    </div>
  );
}
