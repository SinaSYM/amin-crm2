import { isIP } from 'node:net'

/**
 * In-memory fixed-window rate limiter. Fine for this single-process
 * deployment (see CLAUDE.md: bun standalone server, no horizontal scaling);
 * would need a shared store (e.g. Redis) if the app is ever run as
 * multiple instances behind a load balancer.
 */

type Entry = { count: number; resetAt: number }

const buckets = new Map<string, Entry>()
const MAX_BUCKETS = 10_000
let operations = 0

function pruneExpired(now: number): void {
  for (const [key, entry] of buckets) {
    if (entry.resetAt <= now) buckets.delete(key)
  }
}

export function checkRateLimit(key: string, maxAttempts: number, windowMs: number): boolean {
  const now = Date.now()
  operations += 1
  if (operations % 128 === 0 || buckets.size >= MAX_BUCKETS) pruneExpired(now)

  const entry = buckets.get(key)
  if (!entry || entry.resetAt <= now) {
    if (buckets.size >= MAX_BUCKETS) {
      const oldestKey = buckets.keys().next().value
      if (oldestKey !== undefined) buckets.delete(oldestKey)
    }
    buckets.set(key, { count: 1, resetAt: now + windowMs })
    return true
  }
  entry.count += 1
  return entry.count <= maxAttempts
}

export function resetRateLimit(key: string): void {
  buckets.delete(key)
}

export function getClientIp(req: Request): string {
  // Caddy overwrites X-Real-IP with the peer address. Do not trust
  // X-Forwarded-For: clients can supply arbitrary values there.
  const realIp = req.headers.get('x-real-ip')?.trim()
  if (realIp && isIP(realIp) !== 0) return realIp
  return 'unknown'
}
