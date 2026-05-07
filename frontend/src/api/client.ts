import type { QueryResponse, HealthResponse, IngestResponse } from '../types'

const BASE = import.meta.env.VITE_API_URL ?? 'http://localhost:8000'

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  })
  if (!res.ok) {
    const text = await res.text()
    throw new Error(`${res.status}: ${text}`)
  }
  return res.json() as Promise<T>
}

export function fetchHealth(): Promise<HealthResponse> {
  return request<HealthResponse>('/api/v1/health')
}

export function fetchQuery(
  query: string,
  topK = 10,
  includesMitigations = true,
  maxHops = 3,
): Promise<QueryResponse> {
  return request<QueryResponse>('/api/v1/query', {
    method: 'POST',
    body: JSON.stringify({
      query,
      top_k: topK,
      include_mitigations: includesMitigations,
      max_hops: maxHops,
    }),
  })
}

export function fetchIngest(forceRefresh = false): Promise<IngestResponse> {
  return request<IngestResponse>('/api/v1/ingest', {
    method: 'POST',
    body: JSON.stringify({ source: 'mitre', force_refresh: forceRefresh }),
  })
}
