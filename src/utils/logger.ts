/**
 * Structured Logger
 *
 * A lightweight structured logging utility for MCP servers.
 * Outputs JSON to stderr (stdout is reserved for MCP protocol).
 *
 * Features:
 * - Log levels: debug, info, warn, error
 * - Structured context support
 * - Environment-based level filtering
 * - Timestamps in ISO format
 */

// ============================================================================
// Types
// ============================================================================

export type LogLevel = "debug" | "info" | "warn" | "error";

export interface LogContext {
  [key: string]: unknown;
}

export interface LogEntry {
  level: LogLevel;
  message: string;
  timestamp: string;
  context?: LogContext;
}

// ============================================================================
// Constants
// ============================================================================

const LOG_LEVELS: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
};

const LEVEL_PREFIXES: Record<LogLevel, string> = {
  debug: "DEBUG",
  info: "INFO",
  warn: "WARN",
  error: "ERROR",
};

// ============================================================================
// Configuration
// ============================================================================

function getLogLevel(): LogLevel {
  const envLevel = process.env["LOG_LEVEL"]?.toLowerCase();
  if (envLevel && envLevel in LOG_LEVELS) {
    return envLevel as LogLevel;
  }
  return "info";
}

function shouldOutputJson(): boolean {
  return process.env["LOG_FORMAT"] === "json";
}

// ============================================================================
// Core Logger
// ============================================================================

/**
 * Log a message with the specified level and optional context.
 *
 * @param level - The log level
 * @param message - The log message
 * @param context - Optional structured context
 */
export function log(level: LogLevel, message: string, context?: LogContext): void {
  const currentLevel = getLogLevel();

  if (LOG_LEVELS[level] < LOG_LEVELS[currentLevel]) {
    return;
  }

  const timestamp = new Date().toISOString();

  if (shouldOutputJson()) {
    const entry: LogEntry = {
      level,
      message,
      timestamp,
      ...(context && Object.keys(context).length > 0 ? { context } : {}),
    };
    console.error(JSON.stringify(entry));
  } else {
    // Human-readable format for development
    const prefix = `[${timestamp}] [${LEVEL_PREFIXES[level]}]`;
    if (context && Object.keys(context).length > 0) {
      console.error(`${prefix} ${message}`, context);
    } else {
      console.error(`${prefix} ${message}`);
    }
  }
}

// ============================================================================
// Logger Interface
// ============================================================================

/**
 * Structured logger with convenience methods for each log level.
 *
 * @example
 * ```ts
 * import { logger } from "./utils/logger.js";
 *
 * logger.info("Starting analysis", { contractPath: "/path/to/contract.sol" });
 * logger.error("Analysis failed", { error: err.message, duration: 1234 });
 * ```
 */
export const logger = {
  /**
   * Log a debug message.
   * Only shown when LOG_LEVEL=debug.
   */
  debug(message: string, context?: LogContext): void {
    log("debug", message, context);
  },

  /**
   * Log an info message.
   * Shown when LOG_LEVEL is debug or info (default).
   */
  info(message: string, context?: LogContext): void {
    log("info", message, context);
  },

  /**
   * Log a warning message.
   * Shown when LOG_LEVEL is debug, info, or warn.
   */
  warn(message: string, context?: LogContext): void {
    log("warn", message, context);
  },

  /**
   * Log an error message.
   * Always shown unless LOG_LEVEL is set higher than error.
   */
  error(message: string, context?: LogContext): void {
    log("error", message, context);
  },

  /**
   * Create a child logger with preset context.
   *
   * @param baseContext - Context to include in all log messages
   * @returns A new logger with the base context applied
   *
   * @example
   * ```ts
   * const toolLogger = logger.child({ tool: "slither" });
   * toolLogger.info("Running analysis"); // includes { tool: "slither" }
   * ```
   */
  child(baseContext: LogContext) {
    return {
      debug: (message: string, context?: LogContext) =>
        log("debug", message, { ...baseContext, ...context }),
      info: (message: string, context?: LogContext) =>
        log("info", message, { ...baseContext, ...context }),
      warn: (message: string, context?: LogContext) =>
        log("warn", message, { ...baseContext, ...context }),
      error: (message: string, context?: LogContext) =>
        log("error", message, { ...baseContext, ...context }),
    };
  },

  /**
   * Time an async operation and log its duration.
   *
   * @param label - Label for the operation
   * @param fn - Async function to time
   * @returns The result of the function
   *
   * @example
   * ```ts
   * const result = await logger.time("slither-analysis", async () => {
   *   return await runSlither(contractPath);
   * });
   * ```
   */
  async time<T>(label: string, fn: () => Promise<T>): Promise<T> {
    const start = Date.now();
    try {
      const result = await fn();
      const duration = Date.now() - start;
      log("debug", `${label} completed`, { durationMs: duration });
      return result;
    } catch (error) {
      const duration = Date.now() - start;
      log("error", `${label} failed`, {
        durationMs: duration,
        error: error instanceof Error ? error.message : String(error),
      });
      throw error;
    }
  },
};

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Format duration in human-readable form.
 */
export function formatDuration(ms: number): string {
  if (ms < 1000) {
    return `${ms}ms`;
  }
  if (ms < 60_000) {
    return `${(ms / 1000).toFixed(1)}s`;
  }
  const minutes = Math.floor(ms / 60_000);
  const seconds = Math.floor((ms % 60_000) / 1000);
  return `${minutes}m ${seconds}s`;
}
