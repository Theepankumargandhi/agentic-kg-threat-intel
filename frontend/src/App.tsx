import { useState, useCallback } from 'react'
import { fetchQuery } from './api/client'
import type { QueryResponse } from './types'
import Header from './components/Header'
import SearchBar from './components/SearchBar'
import KnowledgeGraph from './components/KnowledgeGraph'
import AnswerPanel from './components/AnswerPanel'
import ReasoningSteps from './components/ReasoningSteps'
import SourcesPanel from './components/SourcesPanel'
import Legend from './components/Legend'

export default function App() {
  const [result, setResult] = useState<QueryResponse | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const handleSearch = useCallback(async (query: string) => {
    setLoading(true)
    setError(null)
    try {
      const data = await fetchQuery(query)
      setResult(data)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Unknown error')
    } finally {
      setLoading(false)
    }
  }, [])

  return (
    <div className="h-screen flex flex-col bg-bg text-gray-200 overflow-hidden">
      {/* Top bar */}
      <Header />

      {/* Search */}
      <SearchBar onSearch={handleSearch} loading={loading} />

      {/* Legend */}
      <Legend />

      {/* Error */}
      {error && (
        <div className="mx-4 mt-2 px-4 py-2 bg-red-900/30 border border-red-700 rounded text-sm text-red-400">
          {error}
        </div>
      )}

      {/* Main content */}
      <div className="flex flex-1 overflow-hidden">
        {/* Left: Knowledge Graph */}
        <div className="flex-1 p-4 overflow-hidden">
          <KnowledgeGraph
            pathTrace={result?.path_trace ?? null}
            width={700}
            height={500}
          />
        </div>

        {/* Right: Answer + Reasoning + Sources */}
        <div className="w-[420px] border-l border-border flex flex-col overflow-hidden">
          {/* Answer */}
          <div className="flex-1 overflow-y-auto">
            <AnswerPanel result={result} loading={loading} />
          </div>

          {/* Reasoning Steps */}
          <div className="border-t border-border overflow-y-auto max-h-64">
            <ReasoningSteps
              steps={result?.reasoning_steps ?? []}
              loading={loading}
            />
          </div>

          {/* Sources */}
          {result && <SourcesPanel sources={result.sources} />}
        </div>
      </div>
    </div>
  )
}
