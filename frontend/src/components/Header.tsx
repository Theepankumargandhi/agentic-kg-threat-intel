import { useQuery } from '@tanstack/react-query'
import { Shield, Database, Brain, Cpu, RefreshCw } from 'lucide-react'
import { fetchHealth, fetchIngest } from '../api/client'
import { useState } from 'react'

function StatusDot({ ok, label }: { ok: boolean; label: string }) {
  return (
    <div className="flex items-center gap-1.5 text-xs">
      <span
        className={`w-2 h-2 rounded-full ${ok ? 'bg-green-400 shadow-[0_0_6px_#4ade80]' : 'bg-red-500'}`}
      />
      <span className={ok ? 'text-green-400' : 'text-red-400'}>{label}</span>
    </div>
  )
}

export default function Header() {
  const { data: health } = useQuery({
    queryKey: ['health'],
    queryFn: fetchHealth,
    refetchInterval: 30_000,
  })

  const [ingesting, setIngesting] = useState(false)
  const [ingestMsg, setIngestMsg] = useState('')

  async function handleIngest() {
    setIngesting(true)
    setIngestMsg('Ingesting MITRE ATT&CK data...')
    try {
      const res = await fetchIngest(false)
      setIngestMsg(
        `Done: ${res.nodes_created} nodes, ${res.edges_created} edges, ${res.embeddings_created} embeddings`,
      )
    } catch (e) {
      setIngestMsg('Ingestion failed — check API logs')
    } finally {
      setIngesting(false)
      setTimeout(() => setIngestMsg(''), 5000)
    }
  }

  return (
    <header className="border-b border-border bg-surface px-6 py-3">
      <div className="flex items-center justify-between">
        {/* Logo */}
        <div className="flex items-center gap-3">
          <div className="p-1.5 rounded-lg bg-accent/10 border border-accent/20">
            <Shield className="w-5 h-5 text-accent" />
          </div>
          <div>
            <h1 className="text-sm font-bold text-white tracking-wide">
              Agentic Knowledge Graph
            </h1>
            <p className="text-xs text-gray-500">MITRE ATT&CK Threat Intelligence</p>
          </div>
        </div>

        {/* Status indicators */}
        <div className="flex items-center gap-5">
          <StatusDot ok={health?.neo4j ?? false} label="Neo4j" />
          <StatusDot ok={health?.chromadb ?? false} label="ChromaDB" />
          <StatusDot ok={health?.llm ?? false} label="LLM" />

          <div className="h-4 w-px bg-border" />

          <button
            onClick={handleIngest}
            disabled={ingesting}
            className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-md
                       bg-accent/10 border border-accent/30 text-accent
                       hover:bg-accent/20 transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`w-3 h-3 ${ingesting ? 'animate-spin' : ''}`} />
            {ingesting ? 'Ingesting...' : 'Ingest Data'}
          </button>
        </div>
      </div>

      {ingestMsg && (
        <div className="mt-2 text-xs text-green-400 font-mono">{ingestMsg}</div>
      )}
    </header>
  )
}
