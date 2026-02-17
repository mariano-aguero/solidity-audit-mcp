#!/usr/bin/env node

/**
 * MCP Audit Server - HTTP/SSE Transport
 *
 * Exposes the MCP server over HTTP with SSE transport for remote access.
 * This allows running the audit tools as a SaaS service.
 *
 * Usage:
 *   node dist/server.js [--port 3000] [--host 0.0.0.0]
 *
 * Environment variables:
 *   PORT - Server port (default: 3000)
 *   HOST - Server host (default: 0.0.0.0)
 *   MCP_API_KEY - Optional API key for authentication
 */

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { parse as parseUrl } from "node:url";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";

import { logger } from "./utils/logger.js";
import {
  // Server
  createMcpServer,
  getHttpServerConfig,
  SERVER_NAME,
  SERVER_VERSION,
  // Tools
  TOOLS,
  getToolSummaries,
  // Handlers
  handleApiAnalyze,
  handleApiCheck,
  handleApiCiReview,
  sendJson,
  sendError,
  // Health
  getCachedHealthStatus,
  getQuickHealthStatus,
  formatAnalyzerStatus,
  // Middleware
  checkAuth,
  setCorsHeaders,
  handlePreflight,
} from "./server/index.js";

// ============================================================================
// Configuration
// ============================================================================

const config = getHttpServerConfig();
const { port: PORT, host: HOST, apiKey: API_KEY } = config;

// ============================================================================
// SSE Connection Management
// ============================================================================

const activeTransports = new Map<string, SSEServerTransport>();

// ============================================================================
// Request Router
// ============================================================================

async function handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
  setCorsHeaders(res);

  // Handle CORS preflight
  if (handlePreflight(req.method ?? "", res)) {
    return;
  }

  const url = parseUrl(req.url || "/", true);
  const pathname = url.pathname || "/";
  const method = req.method ?? "GET";

  // Route: Health check (full)
  if (pathname === "/health" && method === "GET") {
    const health = await getCachedHealthStatus();
    const httpStatus = health.status === "unhealthy" ? 503 : 200;
    sendJson(res, httpStatus, health);
    return;
  }

  // Route: Health check (quick)
  if (pathname === "/health/quick" && method === "GET") {
    sendJson(res, 200, getQuickHealthStatus());
    return;
  }

  // Route: Server info
  if (pathname === "/info" && method === "GET") {
    sendJson(res, 200, {
      server: SERVER_NAME,
      version: SERVER_VERSION,
      transport: "sse",
      tools: getToolSummaries(),
    });
    return;
  }

  // Route: REST API - Analyze contract
  if (pathname === "/api/analyze" && method === "POST") {
    if (!checkAuth(req, API_KEY)) {
      sendError(res, 401, "Unauthorized");
      return;
    }

    try {
      const result = await handleApiAnalyze(req);
      sendJson(res, result.statusCode, result.body);
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      logger.error("API analyze error", { error: errorMessage });
      sendError(res, 500, errorMessage);
    }
    return;
  }

  // Route: REST API - Check vulnerabilities
  if (pathname === "/api/check" && method === "POST") {
    if (!checkAuth(req, API_KEY)) {
      sendError(res, 401, "Unauthorized");
      return;
    }

    try {
      const result = await handleApiCheck(req);
      sendJson(res, result.statusCode, result.body);
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      sendError(res, 500, errorMessage);
    }
    return;
  }

  // Route: REST API - CI Review
  if (pathname === "/api/ci/review" && method === "POST") {
    if (!checkAuth(req, API_KEY)) {
      sendError(res, 401, "Unauthorized");
      return;
    }

    try {
      const result = await handleApiCiReview(req);
      sendJson(res, result.statusCode, result.body);
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      logger.error("CI Review error", { error: errorMessage });
      sendError(res, 500, errorMessage);
    }
    return;
  }

  // Route: SSE endpoint
  if (pathname === "/sse" && method === "GET") {
    if (!checkAuth(req, API_KEY)) {
      sendError(res, 401, "Unauthorized");
      return;
    }

    // Create new MCP server and transport for this connection
    const server = createMcpServer();
    const transport = new SSEServerTransport("/message", res);

    const connectionId = Math.random().toString(36).substring(7);
    activeTransports.set(connectionId, transport);

    logger.info(`SSE connection established`, { connectionId });

    // Clean up on close
    res.on("close", () => {
      activeTransports.delete(connectionId);
      logger.info(`SSE connection closed`, { connectionId });
    });

    await server.connect(transport);
    return;
  }

  // Route: Message endpoint for SSE
  if (pathname === "/message" && method === "POST") {
    if (!checkAuth(req, API_KEY)) {
      sendError(res, 401, "Unauthorized");
      return;
    }

    // Collect body
    const chunks: Buffer[] = [];
    for await (const chunk of req) {
      chunks.push(chunk as Buffer);
    }
    const body = Buffer.concat(chunks).toString();

    // Route to the appropriate transport
    for (const transport of activeTransports.values()) {
      try {
        await transport.handlePostMessage(req, res, body);
        return;
      } catch {
        // Try next transport
      }
    }

    sendError(res, 400, "No active SSE connection");
    return;
  }

  // 404 for unknown routes
  sendError(res, 404, "Not found");
}

// ============================================================================
// Server Startup
// ============================================================================

const httpServer = createServer((req, res) => {
  handleRequest(req, res).catch((error) => {
    logger.error("Request handler error", { error: String(error) });
    sendError(res, 500, "Internal server error");
  });
});

httpServer.listen(PORT, HOST, () => {
  logger.info(`MCP Audit Server (SSE) running`, {
    host: HOST,
    port: PORT,
    authEnabled: !!API_KEY,
  });

  console.warn(`
╔════════════════════════════════════════════════════════════════╗
║                    MCP Audit Server (SSE)                      ║
╠════════════════════════════════════════════════════════════════╣
║  Status:    Running                                            ║
║  Host:      ${HOST.padEnd(49)}║
║  Port:      ${String(PORT).padEnd(49)}║
║  Auth:      ${(API_KEY ? "Enabled (API Key)" : "Disabled").padEnd(49)}║
╠════════════════════════════════════════════════════════════════╣
║  MCP Endpoints:                                                ║
║    GET  /sse          - SSE connection (MCP clients)           ║
║    POST /message      - Message handler (MCP)                  ║
╠════════════════════════════════════════════════════════════════╣
║  REST API:                                                     ║
║    POST /api/analyze    - Analyze contract from source         ║
║    POST /api/check      - Quick vulnerability check            ║
║    POST /api/ci/review  - CI: Analyze & post inline comments   ║
╠════════════════════════════════════════════════════════════════╣
║  Health:                                                       ║
║    GET  /health       - Full health + analyzer status          ║
║    GET  /health/quick - Quick health check                     ║
║    GET  /info         - Server information                     ║
╠════════════════════════════════════════════════════════════════╣
║  Tools: ${String(TOOLS.length).padEnd(53)}║
╚════════════════════════════════════════════════════════════════╝
`);

  // Log initial analyzer status
  getCachedHealthStatus().then((health) => {
    logger.info(`Analyzer status: ${formatAnalyzerStatus(health)}`);
  });
});

// ============================================================================
// Graceful Shutdown
// ============================================================================

function shutdown(signal: string): void {
  logger.info(`Received ${signal}, shutting down...`);
  httpServer.close(() => {
    logger.info("Server closed");
    process.exit(0);
  });
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
