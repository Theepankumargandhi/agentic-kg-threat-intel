import { NODE_COLORS } from './KnowledgeGraph'
import type { NodeType } from '../types'

const TYPES: NodeType[] = ['Tactic', 'Technique', 'SubTechnique', 'Group', 'Software', 'Mitigation']

export default function Legend() {
  return (
    <div className="flex flex-wrap gap-x-4 gap-y-1 px-4 py-2 border-b border-border text-xs">
      {TYPES.map((t) => (
        <div key={t} className="flex items-center gap-1.5">
          <span
            className="w-2.5 h-2.5 rounded-full"
            style={{ backgroundColor: NODE_COLORS[t], boxShadow: `0 0 4px ${NODE_COLORS[t]}` }}
          />
          <span className="text-gray-400">{t}</span>
        </div>
      ))}
    </div>
  )
}
