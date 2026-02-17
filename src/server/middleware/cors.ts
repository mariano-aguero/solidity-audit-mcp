/**
 * CORS Middleware
 *
 * Cross-Origin Resource Sharing configuration for HTTP endpoints.
 */

import type { ServerResponse } from "node:http";

// ============================================================================
// CORS Configuration
// ============================================================================

export interface CorsOptions {
  /** Allowed origins (default: "*") */
  origin?: string | string[];
  /** Allowed methods (default: GET, POST, OPTIONS) */
  methods?: string[];
  /** Allowed headers */
  headers?: string[];
  /** Max age for preflight cache (seconds) */
  maxAge?: number;
}

const DEFAULT_CORS: Required<CorsOptions> = {
  origin: "*",
  methods: ["GET", "POST", "OPTIONS"],
  headers: ["Content-Type", "Authorization", "X-API-Key"],
  maxAge: 86400, // 24 hours
};

// ============================================================================
// CORS Functions
// ============================================================================

/**
 * Set CORS headers on a response.
 */
export function setCorsHeaders(res: ServerResponse, options: CorsOptions = {}): void {
  const config = { ...DEFAULT_CORS, ...options };

  const origin = Array.isArray(config.origin) ? config.origin.join(", ") : config.origin;

  res.setHeader("Access-Control-Allow-Origin", origin);
  res.setHeader("Access-Control-Allow-Methods", config.methods.join(", "));
  res.setHeader("Access-Control-Allow-Headers", config.headers.join(", "));
  res.setHeader("Access-Control-Max-Age", String(config.maxAge));
}

/**
 * Handle CORS preflight request.
 *
 * @returns true if this was a preflight request (already handled)
 */
export function handlePreflight(
  method: string,
  res: ServerResponse,
  options: CorsOptions = {}
): boolean {
  if (method === "OPTIONS") {
    setCorsHeaders(res, options);
    res.writeHead(204);
    res.end();
    return true;
  }
  return false;
}
