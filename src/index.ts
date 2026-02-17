#!/usr/bin/env node

/**
 * MCP Audit Server - Stdio Transport
 *
 * A Model Context Protocol server for automated security audits
 * of Solidity smart contracts. Integrates with Slither, Aderyn,
 * and Foundry to provide comprehensive vulnerability detection.
 *
 * This entry point uses stdio transport for local use with Claude Desktop.
 */

import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

import { logger } from "./utils/logger.js";
import { createMcpServer, getServerInfo } from "./server/index.js";

// ============================================================================
// Main Entry Point
// ============================================================================

async function main(): Promise<void> {
  const { name, version, tools } = getServerInfo();

  logger.info(`Starting ${name} v${version}`);

  const server = createMcpServer();
  const transport = new StdioServerTransport();

  await server.connect(transport);

  logger.info(`${name} is running on stdio transport`);
  logger.info(`Available tools: ${tools.join(", ")}`);
}

// Run the server
main().catch((error) => {
  logger.error(`Fatal error: ${error instanceof Error ? error.message : String(error)}`);
  process.exit(1);
});
