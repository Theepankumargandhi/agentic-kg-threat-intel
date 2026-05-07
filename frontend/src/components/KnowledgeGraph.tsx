import { useRef, useCallback, useMemo } from 'react'
import ForceGraph2D from 'react-force-graph-2d'
import type { PathTrace, GraphData, GraphNode, NodeType } from '../types'

const NODE_COLORS: Record<NodeType, string> = {
  Tactic: '#ef4444',
  Technique: '#3b82f6',
  SubTechnique: '#60a5fa',
  Group: '#f59e0b',
  Software: '#a855f7',
  Mitigation: '#22c55e',
}

const NODE_SIZE: Record<NodeType, number> = {
  Tactic: 8,
  Technique: 6,
  SubTechnique: 4,
  Group: 10,
  Software: 5,
  Mitigation: 5,
}

function buildGraphData(trace: PathTrace): GraphData {
  const nodes: GraphNode[] = trace.nodes.map((n) => ({
    id: n.id,
    name: n.name,
    type: n.type,
    val: NODE_SIZE[n.type] ?? 5,
    color: NODE_COLORS[n.type] ?? '#6b7280',
  }))

  const nodeIds = new Set(nodes.map((n) => n.id))
  const links = trace.edges
    .filter((e) => nodeIds.has(e.source) && nodeIds.has(e.target))
    .map((e) => ({ source: e.source, target: e.target, relation: e.relation }))

  return { nodes, links }
}

interface Props {
  pathTrace: PathTrace | null
  width: number
  height: number
}

export default function KnowledgeGraph({ pathTrace, width, height }: Props) {
  const graphRef = useRef<any>(null)

  const graphData = useMemo(
    () => (pathTrace ? buildGraphData(pathTrace) : { nodes: [], links: [] }),
    [pathTrace],
  )

  const drawNode = useCallback((node: any, ctx: CanvasRenderingContext2D) => {
    const r = node.val ?? 5
    ctx.beginPath()
    ctx.arc(node.x, node.y, r, 0, 2 * Math.PI)
    ctx.fillStyle = node.color
    ctx.fill()

    // Glow
    ctx.shadowColor = node.color
    ctx.shadowBlur = 8
    ctx.fill()
    ctx.shadowBlur = 0

    // Label
    if (r > 4) {
      ctx.font = `${Math.max(3, r * 0.8)}px Inter`
      ctx.fillStyle = '#e6edf3'
      ctx.textAlign = 'center'
      ctx.fillText(
        node.name.length > 18 ? node.name.slice(0, 16) + '…' : node.name,
        node.x,
        node.y + r + 5,
      )
    }
  }, [])

  if (!pathTrace || pathTrace.nodes.length === 0) {
    return (
      <div
        className="flex flex-col items-center justify-center text-gray-600 border border-dashed border-border rounded-lg"
        style={{ width, height }}
      >
        <svg
          className="w-12 h-12 mb-3 opacity-30"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={1}
            d="M9 20l-5.447-2.724A1 1 0 013 16.382V5.618a1 1 0 011.447-.894L9 7m0 13l6-3m-6 3V7m6 10l4.553 2.276A1 1 0 0021 18.382V7.618a1 1 0 00-.553-.894L15 4m0 13V4m0 0L9 7"
          />
        </svg>
        <p className="text-sm">Knowledge graph appears here after a query</p>
      </div>
    )
  }

  return (
    <div className="graph-container rounded-lg overflow-hidden border border-border" style={{ width, height }}>
      <ForceGraph2D
        ref={graphRef}
        graphData={graphData}
        width={width}
        height={height}
        backgroundColor="#0d1117"
        nodeCanvasObject={drawNode}
        nodeCanvasObjectMode={() => 'replace'}
        linkColor={() => '#30363d'}
        linkWidth={1.5}
        linkDirectionalArrowLength={4}
        linkDirectionalArrowRelPos={1}
        linkLabel={(link: any) => link.relation}
        onNodeClick={(node: any) => {
          graphRef.current?.centerAt(node.x, node.y, 500)
          graphRef.current?.zoom(4, 500)
        }}
        cooldownTicks={80}
        d3AlphaDecay={0.02}
        d3VelocityDecay={0.3}
      />
    </div>
  )
}

export { NODE_COLORS }
