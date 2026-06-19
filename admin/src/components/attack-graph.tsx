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

/** Archive-palette severity hues (aligned with `--sev-*`, no neon). */
const SEVERITY_COLOR: Record<Severity, string> = {
  critical: "var(--sev-critical)",
  high: "var(--sev-high)",
  medium: "var(--sev-medium)",
  low: "var(--sev-low)",
  info: "var(--muted-foreground)",
};

const COLUMN_WIDTH = 300;
const ROW_HEIGHT = 118;

/**
 * Node-link view of a predicted attack path. Each step is a small dossier card;
 * hosts become columns so a pivot to another host visibly steps sideways. Edges
 * are labelled with the tactic, drawn in the brand hairline (warm on a pivot)
 * and the leading severity accent borders the entry node.
 */
export function AttackGraph({
  steps,
  severity,
}: {
  steps: AttackPathStep[];
  severity: Severity;
}) {
  const sevColor = SEVERITY_COLOR[severity] ?? "var(--muted-foreground)";

  const hostColumn = new Map<string, number>();
  for (const step of steps) {
    if (!hostColumn.has(step.host_id)) hostColumn.set(step.host_id, hostColumn.size);
  }

  const nodes: Node[] = steps.map((step, i) => ({
    id: String(i),
    position: { x: (hostColumn.get(step.host_id) ?? 0) * COLUMN_WIDTH, y: i * ROW_HEIGHT },
    data: {
      label: `${String(i + 1).padStart(2, "0")} · ${step.technique_id || "—"}  ·  ${step.tactic}\n${step.module_id}\n@ ${step.host_label || step.host_id}`,
    },
    sourcePosition: Position.Bottom,
    targetPosition: Position.Top,
    className:
      "whitespace-pre-line rounded-lg border bg-card p-2.5 font-mono text-[11px] leading-snug text-card-foreground",
    style: {
      width: 240,
      borderColor: "var(--border)",
      borderLeftWidth: 2,
      borderLeftColor: sevColor,
    },
  }));

  const edges: Edge[] = steps.slice(1).map((step, i) => {
    const pivot = step.host_id !== steps[i].host_id;
    return {
      id: `e${i}`,
      source: String(i),
      target: String(i + 1),
      animated: true,
      label: pivot ? `pivot · ${step.tactic}` : step.tactic,
      style: { stroke: pivot ? "var(--muted-foreground)" : "var(--brand)", strokeWidth: 1.4 },
      labelStyle: { fontSize: 10, fill: "var(--muted-foreground)", fontFamily: "var(--font-mono)" },
      labelBgStyle: { fill: "var(--card)" },
    };
  });

  return (
    <div
      className="border-rule overflow-hidden rounded-lg border"
      style={{ height: Math.max(380, steps.length * ROW_HEIGHT + 80) }}
    >
      <ReactFlow nodes={nodes} edges={edges} fitView minZoom={0.2}>
        <Background color="var(--rule-soft)" />
        <Controls showInteractive={false} />
        <MiniMap pannable zoomable maskColor="color-mix(in oklab, var(--background) 70%, transparent)" />
      </ReactFlow>
    </div>
  );
}
