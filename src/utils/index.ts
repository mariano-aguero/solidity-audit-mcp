/**
 * Utility Exports
 *
 * Re-exports all utility functions and types for external use.
 */

export { logger, type LogLevel, type LogContext, type LogEntry, formatDuration } from "./logger.js";
export {
  Cache,
  toolResultsCache,
  fileHashCache,
  contractInfoCache,
  hashInput,
  makeCacheKey,
  memoize,
  memoizeSync,
} from "./cache.js";
export {
  validateContractPath,
  validateFileExists,
  validateExtension,
  validateSolidityPath,
  sanitizeFilename,
  isPathSafe,
  type PathValidationError,
  type ValidatedPath,
} from "./pathValidation.js";
export {
  executeCommand,
  executeCommandSafe,
  executeWithAbort,
  checkToolAvailable,
  checkToolsAvailable,
  getProjectRoot,
  detectProjectType,
  parseJsonOutput,
  formatDuration as formatExecutorDuration,
  timeout,
  executeParallel,
  type ExecuteResult,
  type ExecuteOptions,
  type ToolAvailability,
  type ExecuteError,
} from "./executor.js";
