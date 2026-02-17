/**
 * Utility Exports
 *
 * Re-exports all utility functions and types for external use.
 */

export { logger, type LogLevel, type LogContext, type LogEntry, formatDuration } from "./logger.js";
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
export {
  countBySeverity,
  sortBySeverity,
  compareSeverity,
  getSeverityEmoji,
  estimateGasSavings,
  extractGasSavings,
  formatGasSavings,
  calculateTotalGasSavings,
  SEVERITY_ORDER,
  SEVERITY_EMOJI,
  SEVERITY_GAS_ESTIMATES,
  type SeverityCounts,
} from "./severity.js";
