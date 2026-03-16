import { useState, useEffect, useCallback } from 'react'
import type { Decision } from '../lib/types'
import { api } from '../lib/api'

export function useDecisions() {
  const [decisions, setDecisions] = useState<Decision[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const refresh = useCallback(() => {
    setLoading(true)
    setError(null)
    api.decisions
      .list()
      .then(setDecisions)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => {
    refresh()
  }, [refresh])

  return { decisions, loading, error, refresh }
}

export function useDecision(id: string) {
  const [decision, setDecision] = useState<Decision | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const refresh = useCallback(() => {
    if (!id) return
    setLoading(true)
    setError(null)
    api.decisions
      .get(id)
      .then(setDecision)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false))
  }, [id])

  useEffect(() => {
    refresh()
  }, [refresh])

  return { decision, loading, error, refresh }
}
