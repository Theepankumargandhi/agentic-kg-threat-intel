import { useState, KeyboardEvent } from 'react'
import { Search, Loader2 } from 'lucide-react'

const EXAMPLES = [
  'What techniques does APT29 use for initial access?',
  'How does Lazarus Group achieve lateral movement?',
  'Which techniques bypass Windows Defender?',
  'What persistence mechanisms does FIN7 use?',
  'How does ransomware achieve impact on victim systems?',
]

interface Props {
  onSearch: (query: string) => void
  loading: boolean
}

export default function SearchBar({ onSearch, loading }: Props) {
  const [query, setQuery] = useState('')

  function handleSubmit() {
    if (query.trim() && !loading) onSearch(query.trim())
  }

  function handleKey(e: KeyboardEvent<HTMLTextAreaElement>) {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      handleSubmit()
    }
  }

  return (
    <div className="p-4 border-b border-border bg-surface">
      <div className="relative">
        <textarea
          rows={2}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={handleKey}
          placeholder="Ask a threat intelligence question... (Enter to search)"
          className="w-full bg-bg border border-border rounded-lg px-4 py-3 pr-14
                     text-sm text-gray-200 placeholder-gray-600
                     focus:outline-none focus:border-accent resize-none
                     font-mono leading-relaxed"
        />
        <button
          onClick={handleSubmit}
          disabled={!query.trim() || loading}
          className="absolute right-3 bottom-3 p-2 rounded-md bg-accent
                     hover:bg-accent/80 disabled:opacity-40 transition-colors"
        >
          {loading ? (
            <Loader2 className="w-4 h-4 text-white animate-spin" />
          ) : (
            <Search className="w-4 h-4 text-white" />
          )}
        </button>
      </div>

      {/* Example queries */}
      <div className="flex flex-wrap gap-2 mt-3">
        {EXAMPLES.map((ex) => (
          <button
            key={ex}
            onClick={() => { setQuery(ex); onSearch(ex) }}
            className="text-xs px-2 py-1 rounded border border-border text-gray-400
                       hover:border-accent/50 hover:text-gray-200 transition-colors truncate
                       max-w-[260px]"
          >
            {ex}
          </button>
        ))}
      </div>
    </div>
  )
}
