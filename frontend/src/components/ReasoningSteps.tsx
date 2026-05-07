import { CheckCircle, Brain, Database, GitBranch, Cpu, ShieldAlert } from 'lucide-react'
import type { ReasoningStep } from '../types'

const SOURCE_ICON: Record<string, React.ReactNode> = {
  llm: <Brain className="w-3 h-3" />,
  vector: <Database className="w-3 h-3" />,
  graph: <GitBranch className="w-3 h-3" />,
  'vector+graph': <Cpu className="w-3 h-3" />,
}

const SOURCE_COLOR: Record<string, string> = {
  llm: 'text-purple-400 bg-purple-400/10 border-purple-400/20',
  vector: 'text-blue-400 bg-blue-400/10 border-blue-400/20',
  graph: 'text-amber-400 bg-amber-400/10 border-amber-400/20',
  'vector+graph': 'text-cyan-400 bg-cyan-400/10 border-cyan-400/20',
}

interface Props {
  steps: ReasoningStep[]
  loading: boolean
}

function StepSkeleton() {
  return (
    <div className="space-y-2 animate-pulse">
      {Array.from({ length: 5 }).map((_, i) => (
        <div key={i} className="flex items-center gap-3">
          <div className="w-4 h-4 rounded-full bg-border" />
          <div className="flex-1 h-3 bg-border rounded" />
        </div>
      ))}
    </div>
  )
}

export default function ReasoningSteps({ steps, loading }: Props) {
  return (
    <div className="p-4">
      <h2 className="text-xs font-semibold uppercase tracking-widest text-gray-500 mb-3">
        Reasoning Chain
      </h2>

      {loading ? (
        <StepSkeleton />
      ) : steps.length === 0 ? (
        <p className="text-xs text-gray-600">Reasoning steps appear after a query.</p>
      ) : (
        <div className="space-y-2">
          {steps.map((step) => {
            const src = step.source?.toLowerCase() ?? 'llm'
            const color = SOURCE_COLOR[src] ?? SOURCE_COLOR.llm
            const icon = SOURCE_ICON[src] ?? <Brain className="w-3 h-3" />
            return (
              <div key={step.step} className="flex gap-3 group">
                {/* Step indicator */}
                <div className="flex flex-col items-center">
                  <CheckCircle className="w-4 h-4 text-green-400 shrink-0 mt-0.5" />
                  {step.step < steps.length && (
                    <div className="w-px flex-1 bg-border mt-1" />
                  )}
                </div>

                {/* Content */}
                <div className="pb-3 flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-0.5">
                    <span className="text-xs font-medium text-gray-200">{step.action}</span>
                    <span
                      className={`flex items-center gap-1 text-[10px] px-1.5 py-0.5 rounded border font-mono ${color}`}
                    >
                      {icon}
                      {step.source}
                    </span>
                  </div>
                  <p className="text-xs text-gray-500 leading-relaxed line-clamp-2">
                    {step.observation}
                  </p>
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
