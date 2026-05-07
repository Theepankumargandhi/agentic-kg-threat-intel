import type { Source, NodeType } from '../types'

const BADGE_CLASS: Record<string, string> = {
  Tactic: 'badge-tactic',
  Technique: 'badge-technique',
  SubTechnique: 'badge-subtechnique',
  Group: 'badge-group',
  Software: 'badge-software',
  Mitigation: 'badge-mitigation',
}

interface Props {
  sources: Source[]
}

export default function SourcesPanel({ sources }: Props) {
  if (sources.length === 0) return null

  return (
    <div className="p-4 border-t border-border">
      <h2 className="text-xs font-semibold uppercase tracking-widest text-gray-500 mb-3">
        Sources ({sources.length})
      </h2>
      <div className="space-y-1.5 max-h-48 overflow-y-auto">
        {sources.map((src, i) => {
          const badgeClass = BADGE_CLASS[src.type] ?? 'badge-technique'
          return (
            <div
              key={i}
              className="flex items-center justify-between gap-2 text-xs py-1 px-2 rounded
                         bg-bg border border-border hover:border-accent/30 transition-colors"
            >
              <div className="flex items-center gap-2 min-w-0">
                {src.external_id && (
                  <span className="font-mono text-accent shrink-0">{src.external_id}</span>
                )}
                <span className="text-gray-300 truncate">{src.name}</span>
              </div>
              <span className={`text-[10px] px-1.5 py-0.5 rounded font-medium shrink-0 ${badgeClass}`}>
                {src.type}
              </span>
            </div>
          )
        })}
      </div>
    </div>
  )
}
