export type NodeType =
  | 'Tactic'
  | 'Technique'
  | 'SubTechnique'
  | 'Group'
  | 'Software'
  | 'Mitigation'

export interface PathNode {
  id: string
  type: NodeType
  name: string
  properties: Record<string, unknown>
}

export interface PathEdge {
  source: string
  target: string
  relation: string
}

export interface PathTrace {
  nodes: PathNode[]
  edges: PathEdge[]
}

export interface ReasoningStep {
  step: number
  action: string
  observation: string
  source: string
}

export interface Source {
  name: string
  external_id: string
  type: string
}

export interface QueryResponse {
  query: string
  answer: string
  path_trace: PathTrace
  reasoning_steps: ReasoningStep[]
  sources: Source[]
  confidence: number
  latency_ms: number
}

export interface HealthResponse {
  status: string
  neo4j: boolean
  chromadb: boolean
  llm: boolean
  version: string
}

export interface IngestResponse {
  status: string
  nodes_created: number
  edges_created: number
  embeddings_created: number
  duration_s: number
}

// react-force-graph-2d shapes
export interface GraphNode {
  id: string
  name: string
  type: NodeType
  val: number
  color: string
}

export interface GraphLink {
  source: string
  target: string
  relation: string
}

export interface GraphData {
  nodes: GraphNode[]
  links: GraphLink[]
}
