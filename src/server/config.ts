/**
 * Server Configuration
 *
 * Centralized configuration for both stdio and HTTP/SSE servers.
 */

import { parseArgs } from "node:util";

// ============================================================================
// Server Identity
// ============================================================================

export const SERVER_NAME = "solidity-audit-mcp";
export const SERVER_VERSION = "1.0.0";

// ============================================================================
// HTTP Server Configuration
// ============================================================================

export interface HttpServerConfig {
  port: number;
  host: string;
  apiKey?: string;
}

/**
 * Parse command line arguments and environment variables for HTTP server config.
 */
export function getHttpServerConfig(): HttpServerConfig {
  const { values: args } = parseArgs({
    options: {
      port: { type: "string", short: "p", default: process.env["PORT"] || "3000" },
      host: { type: "string", short: "h", default: process.env["HOST"] || "0.0.0.0" },
    },
  });

  return {
    port: parseInt(args.port!, 10),
    host: args.host!,
    apiKey: process.env["MCP_API_KEY"],
  };
}

// ============================================================================
// Health Check Configuration
// ============================================================================

export const HEALTH_CACHE_TTL = 30000; // 30 seconds
