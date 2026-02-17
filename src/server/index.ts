/**
 * Server Module Exports
 *
 * Public API for the server module.
 */

// Core
export { createMcpServer, getServerInfo } from "./McpServer.js";
export {
  SERVER_NAME,
  SERVER_VERSION,
  getHttpServerConfig,
  type HttpServerConfig,
} from "./config.js";

// Tools
export { TOOLS, getToolNames, getToolSummaries } from "./tools/index.js";

// Handlers
export {
  executeTool,
  isValidToolName,
  type ToolResult,
  type ToolName,
} from "./handlers/toolHandlers.js";
export {
  handleApiAnalyze,
  handleApiCheck,
  handleApiCiReview,
  parseJsonBody,
  sendJson,
  sendError,
  type JsonResponse,
} from "./handlers/httpHandlers.js";

// Health
export {
  getCachedHealthStatus,
  getQuickHealthStatus,
  getUptime,
  formatAnalyzerStatus,
  type HealthStatus,
  type QuickHealthStatus,
  type AnalyzerStatus,
} from "./health/index.js";

// Middleware
export { checkAuth, extractBearerToken, extractApiKey } from "./middleware/auth.js";
export { setCorsHeaders, handlePreflight, type CorsOptions } from "./middleware/cors.js";

// Schemas
export * from "./schemas/index.js";
