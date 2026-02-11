/**
 * Cache Utility
 *
 * A simple in-memory cache with TTL (time-to-live) support.
 * Useful for caching expensive operations like tool results.
 *
 * Features:
 * - TTL-based expiration
 * - LRU-like cleanup
 * - Input hashing for cache keys
 * - Statistics tracking
 */

import { createHash } from "node:crypto";

// ============================================================================
// Types
// ============================================================================

interface CacheEntry<T> {
  value: T;
  timestamp: number;
  ttl: number;
  hits: number;
}

interface CacheStats {
  size: number;
  hits: number;
  misses: number;
  hitRate: number;
}

// ============================================================================
// Cache Implementation
// ============================================================================

/**
 * In-memory cache with TTL support.
 */
class Cache<T = unknown> {
  private readonly cache = new Map<string, CacheEntry<T>>();
  private readonly maxSize: number;
  private hits = 0;
  private misses = 0;

  constructor(maxSize = 100) {
    this.maxSize = maxSize;
  }

  /**
   * Get a value from the cache.
   *
   * @param key - The cache key
   * @returns The cached value or undefined if not found/expired
   */
  get(key: string): T | undefined {
    const entry = this.cache.get(key);

    if (!entry) {
      this.misses++;
      return undefined;
    }

    // Check if expired
    if (Date.now() - entry.timestamp > entry.ttl) {
      this.cache.delete(key);
      this.misses++;
      return undefined;
    }

    entry.hits++;
    this.hits++;
    return entry.value;
  }

  /**
   * Set a value in the cache.
   *
   * @param key - The cache key
   * @param value - The value to cache
   * @param ttlMs - Time-to-live in milliseconds (default: 60 seconds)
   */
  set(key: string, value: T, ttlMs = 60_000): void {
    // Cleanup if cache is full
    if (this.cache.size >= this.maxSize) {
      this.cleanup();
    }

    this.cache.set(key, {
      value,
      timestamp: Date.now(),
      ttl: ttlMs,
      hits: 0,
    });
  }

  /**
   * Check if a key exists and is not expired.
   *
   * @param key - The cache key
   * @returns True if the key exists and is valid
   */
  has(key: string): boolean {
    const entry = this.cache.get(key);
    if (!entry) return false;

    if (Date.now() - entry.timestamp > entry.ttl) {
      this.cache.delete(key);
      return false;
    }

    return true;
  }

  /**
   * Delete a key from the cache.
   *
   * @param key - The cache key
   * @returns True if the key was deleted
   */
  delete(key: string): boolean {
    return this.cache.delete(key);
  }

  /**
   * Clear all entries from the cache.
   */
  clear(): void {
    this.cache.clear();
    this.hits = 0;
    this.misses = 0;
  }

  /**
   * Get cache statistics.
   */
  getStats(): CacheStats {
    const total = this.hits + this.misses;
    return {
      size: this.cache.size,
      hits: this.hits,
      misses: this.misses,
      hitRate: total > 0 ? this.hits / total : 0,
    };
  }

  /**
   * Remove expired entries and least-used entries if over capacity.
   */
  private cleanup(): void {
    const now = Date.now();
    const entries: Array<[string, CacheEntry<T>]> = [];

    // Remove expired and collect non-expired
    for (const [key, entry] of this.cache) {
      if (now - entry.timestamp > entry.ttl) {
        this.cache.delete(key);
      } else {
        entries.push([key, entry]);
      }
    }

    // If still over capacity, remove least-used
    if (this.cache.size >= this.maxSize) {
      entries.sort((a, b) => a[1].hits - b[1].hits);
      const toRemove = Math.ceil(this.maxSize * 0.2); // Remove 20%

      for (let i = 0; i < toRemove && i < entries.length; i++) {
        const entry = entries[i];
        if (entry) {
          this.cache.delete(entry[0]);
        }
      }
    }
  }

  /**
   * Get or compute a value, caching the result.
   *
   * @param key - The cache key
   * @param compute - Function to compute the value if not cached
   * @param ttlMs - Time-to-live in milliseconds
   * @returns The cached or computed value
   */
  async getOrCompute(key: string, compute: () => Promise<T>, ttlMs = 60_000): Promise<T> {
    const cached = this.get(key);
    if (cached !== undefined) {
      return cached;
    }

    const value = await compute();
    this.set(key, value, ttlMs);
    return value;
  }

  /**
   * Get or compute a value synchronously, caching the result.
   *
   * @param key - The cache key
   * @param compute - Function to compute the value if not cached
   * @param ttlMs - Time-to-live in milliseconds
   * @returns The cached or computed value
   */
  getOrComputeSync(key: string, compute: () => T, ttlMs = 60_000): T {
    const cached = this.get(key);
    if (cached !== undefined) {
      return cached;
    }

    const value = compute();
    this.set(key, value, ttlMs);
    return value;
  }
}

// ============================================================================
// Global Cache Instances
// ============================================================================

/**
 * Cache for tool results (slither, aderyn, etc.)
 * TTL: 5 minutes
 */
export const toolResultsCache = new Cache<unknown>(50);

/**
 * Cache for file content hashes
 * TTL: 1 minute
 */
export const fileHashCache = new Cache<string>(100);

/**
 * Cache for parsed contract info
 * TTL: 2 minutes
 */
export const contractInfoCache = new Cache<unknown>(50);

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Generate a SHA-256 hash of the input.
 *
 * @param input - The input to hash (will be JSON stringified if not a string)
 * @returns The hex-encoded hash
 */
export function hashInput(input: unknown): string {
  const data = typeof input === "string" ? input : JSON.stringify(input);
  return createHash("sha256").update(data).digest("hex");
}

/**
 * Generate a cache key from multiple parts.
 *
 * @param parts - The parts to combine into a key
 * @returns A hash-based cache key
 */
export function makeCacheKey(...parts: unknown[]): string {
  return hashInput(parts);
}

/**
 * Create a memoized version of an async function.
 *
 * @param fn - The function to memoize
 * @param keyFn - Function to generate cache key from arguments
 * @param ttlMs - Time-to-live in milliseconds
 * @returns A memoized version of the function
 *
 * @example
 * ```ts
 * const memoizedAnalyze = memoize(
 *   analyzeContract,
 *   (path) => path,
 *   300_000 // 5 minutes
 * );
 * ```
 */
export function memoize<TArgs extends unknown[], TResult>(
  fn: (...args: TArgs) => Promise<TResult>,
  keyFn: (...args: TArgs) => string,
  ttlMs = 60_000
): (...args: TArgs) => Promise<TResult> {
  const cache = new Cache<TResult>(100);

  return async (...args: TArgs): Promise<TResult> => {
    const key = keyFn(...args);
    return cache.getOrCompute(key, () => fn(...args), ttlMs);
  };
}

/**
 * Create a memoized version of a sync function.
 *
 * @param fn - The function to memoize
 * @param keyFn - Function to generate cache key from arguments
 * @param ttlMs - Time-to-live in milliseconds
 * @returns A memoized version of the function
 */
export function memoizeSync<TArgs extends unknown[], TResult>(
  fn: (...args: TArgs) => TResult,
  keyFn: (...args: TArgs) => string,
  ttlMs = 60_000
): (...args: TArgs) => TResult {
  const cache = new Cache<TResult>(100);

  return (...args: TArgs): TResult => {
    const key = keyFn(...args);
    return cache.getOrComputeSync(key, () => fn(...args), ttlMs);
  };
}

// ============================================================================
// Export Cache Class
// ============================================================================

export { Cache };
