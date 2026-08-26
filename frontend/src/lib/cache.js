/**
 * Lightweight in-memory stale-while-revalidate cache for SentinelAI frontend.
 * - Serves cached data immediately on first render
 * - Silently revalidates in the background
 * - Automatically invalidated on mutations
 */

const store = new Map()

/**
 * Store data with a TTL in milliseconds.
 * @param {string} key
 * @param {*} data
 * @param {number} ttl  Time-to-live in ms (default 60s)
 */
export function setCache(key, data, ttl = 60_000) {
  store.set(key, { data, expiresAt: Date.now() + ttl })
}

/**
 * Retrieve cached data. Returns `null` if expired or missing.
 * @param {string} key
 */
export function getCache(key) {
  const entry = store.get(key)
  if (!entry) return null
  if (Date.now() > entry.expiresAt) {
    store.delete(key)
    return null
  }
  return entry.data
}

/**
 * Check if a cache entry exists (even if stale) — used for stale-while-revalidate.
 * @param {string} key
 */
export function hasCache(key) {
  return store.has(key)
}

/**
 * Get stale data even if expired (for stale-while-revalidate rendering).
 * @param {string} key
 */
export function getStale(key) {
  return store.get(key)?.data ?? null
}

/**
 * Remove a cache entry (call after mutations).
 * @param {string} key
 */
export function invalidateCache(...keys) {
  keys.forEach((k) => store.delete(k))
}

/**
 * React hook implementing stale-while-revalidate.
 *
 * @param {string} key        - Cache key
 * @param {() => Promise<*>} fetcher - Async function that loads data
 * @param {any[]} deps        - Extra useEffect deps that should trigger re-fetch
 * @param {number} ttl        - Cache TTL in ms
 * @returns {{ data, loading, error, refresh }}
 */
import { useState, useEffect, useRef, useCallback } from 'react'

export function useQuery(key, fetcher, deps = [], ttl = 60_000) {
  const stale = getStale(key)
  const [data, setData] = useState(stale)
  const [loading, setLoading] = useState(!stale)
  const [error, setError] = useState(null)
  const mountedRef = useRef(true)

  const run = useCallback(async (silent = false) => {
    if (!silent) setLoading(true)
    setError(null)
    try {
      const result = await fetcher()
      if (mountedRef.current) {
        setCache(key, result, ttl)
        setData(result)
      }
    } catch (e) {
      if (mountedRef.current) setError(e)
    } finally {
      if (mountedRef.current) setLoading(false)
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, ttl])

  useEffect(() => {
    mountedRef.current = true
    const cached = getCache(key)
    if (cached) {
      setData(cached)
      setLoading(false)
      // Silently revalidate in background
      run(true)
    } else {
      run(false)
    }
    return () => { mountedRef.current = false }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, ...deps])

  return { data, loading, error, refresh: () => run(false) }
}
