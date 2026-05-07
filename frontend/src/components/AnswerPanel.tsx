import { CheckCircle, Clock, TrendingUp } from 'lucide-react'
import type { QueryResponse } from '../types'

interface Props {
  result: QueryResponse | null
  loading: boolean
}

function ConfidenceBar({ value }: { value: number }) {
  const pct = Math.round(value * 100)
  const color =
    pct >= 80 ? 'bg-green-500' : pct >= 60 ? 'bg-yellow-500' : 'bg-red-500'
  return (
    <div className="flex items-center gap-3">
      <div className="flex-1 h-2 bg-bg rounded-full overflow-hidden">
        <div
          className={`h-full ${color} transition-all duration-700`}
          style={{ width: `${pct}%` }}
        />
      </div>
      <span className="text-xs font-mono text-gray-300 w-8">{pct}%</span>
    </div>
  )
}

function Skeleton() {
  return (
    <div className="space-y-3 animate-pulse">
      <div className="h-3 bg-border rounded w-3/4" />
      <div className="h-3 bg-border rounded w-full" />
      <div className="h-3 bg-border rounded w-5/6" />
      <div className="h-3 bg-border rounded w-2/3" />
    </div>
  )
}

export default function AnswerPanel({ result, loading }: Props) {
  if (loading) {
    return (
      <div className="p-4">
        <h2 className="text-xs font-semibold uppercase tracking-widest text-gray-500 mb-3">
          Answer
        </h2>
        <Skeleton />
      </div>
    )
  }

  if (!result) {
    return (
      <div className="p-4 text-gray-600 text-sm">
        Run a query to see the AI-generated threat intelligence answer here.
      </div>
    )
  }

  // Format answer: bold T1xxx IDs
  const formattedAnswer = result.answer.replace(
    /\b(T\d{4}(?:\.\d{3})?)\b/g,
    '<span class="font-mono text-accent font-semibold">$1</span>',
  )

  return (
    <div className="p-4 space-y-4 fade-in">
      <div className="flex items-center justify-between">
        <h2 className="text-xs font-semibold uppercase tracking-widest text-gray-500">
          Answer
        </h2>
        <div className="flex items-center gap-3 text-xs text-gray-500">
          <span className="flex items-center gap-1">
            <Clock className="w-3 h-3" />
            {result.latency_ms.toFixed(0)}ms
          </span>
        </div>
      </div>

      {/* Answer text */}
      <div
        className="text-sm text-gray-200 leading-relaxed whitespace-pre-wrap"
        dangerouslySetInnerHTML={{ __html: formattedAnswer }}
      />

      {/* Confidence */}
      <div>
        <div className="flex items-center gap-1.5 text-xs text-gray-500 mb-1.5">
          <TrendingUp className="w-3 h-3" />
          Confidence
        </div>
        <ConfidenceBar value={result.confidence} />
      </div>
    </div>
  )
}
