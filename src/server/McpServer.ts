/**
 * MCP Server Factory
 *
 * Creates and configures MCP servers for both stdio and SSE transports.
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

import { logger } from "../utils/logger.js";
import { SERVER_NAME, SERVER_VERSION } from "./config.js";
import { TOOLS, getToolNames } from "./tools/toolDefinitions.js";
import { executeTool } from "./handlers/toolHandlers.js";

// ============================================================================
// MCP Server Factory
// ============================================================================

/**
 * Create a new MCP server instance with all tool handlers configured.
 */
export function createMcpServer(): Server {
  const server = new Server(
    {
      name: SERVER_NAME,
      version: SERVER_VERSION,
    },
    {
      capabilities: {
        tools: {},
      },
    }
  );

  // Handler: List available tools
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    logger.info(`ListTools request received - returning ${TOOLS.length} tools`);
    return { tools: TOOLS };
  });

  // Handler: Execute tool
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    return executeTool(name, args);
  });

  return server;
}

/**
 * Get server info for logging.
 */
export function getServerInfo(): { name: string; version: string; tools: string[] } {
  return {
    name: SERVER_NAME,
    version: SERVER_VERSION,
    tools: getToolNames(),
  };
}
