/**
 * Authentication Middleware
 *
 * API key authentication for HTTP endpoints.
 */

import type { IncomingMessage } from "node:http";

// ============================================================================
// Authentication
// ============================================================================

/**
 * Check if the request is authenticated.
 *
 * Supports two authentication methods:
 * - Bearer token in Authorization header
 * - API key in X-API-Key header
 *
 * @param req - HTTP request
 * @param apiKey - Expected API key (if undefined, auth is disabled)
 * @returns true if authenticated or auth is disabled
 */
export function checkAuth(req: IncomingMessage, apiKey?: string): boolean {
  // If no API key is configured, allow all requests
  if (!apiKey) return true;

  const authHeader = req.headers["authorization"];
  const apiKeyHeader = req.headers["x-api-key"];

  // Check Bearer token
  if (authHeader?.startsWith("Bearer ")) {
    return authHeader.slice(7) === apiKey;
  }

  // Check X-API-Key header
  return apiKeyHeader === apiKey;
}

/**
 * Extract bearer token from Authorization header.
 */
export function extractBearerToken(req: IncomingMessage): string | undefined {
  const authHeader = req.headers["authorization"];
  if (authHeader?.startsWith("Bearer ")) {
    return authHeader.slice(7);
  }
  return undefined;
}

/**
 * Extract API key from headers.
 */
export function extractApiKey(req: IncomingMessage): string | undefined {
  return req.headers["x-api-key"] as string | undefined;
}
