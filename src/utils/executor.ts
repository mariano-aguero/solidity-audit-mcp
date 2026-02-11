/**
 * Executor Utility
 *
 * Executes external tools (slither, aderyn, forge, solc) as subprocesses.
 * Uses execa for process management with proper timeout and error handling.
 *
 * Features:
 * - AbortController for graceful cancellation
 * - Structured logging
 * - Result type for error handling
 */

import { execa, type Options as ExecaOptions } from "execa";
import { access, stat } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { logger } from "./logger.js";
import { type Result, ok, err } from "../types/result.js";

// ============================================================================
// Types
// ============================================================================

export interface ExecuteResult {
  stdout: string;
  stderr: string;
  exitCode: number;
  signal?: string;
  timedOut?: boolean;
}

export interface ExecuteOptions {
  /** Working directory for the command */
  cwd?: string;
  /** Timeout in milliseconds (default: 120000 = 2 minutes) */
  timeout?: number;
  /** Environment variables to add */
  env?: Record<string, string>;
  /** AbortController for cancellation */
  signal?: AbortSignal;
}

export interface ToolAvailability {
  available: boolean;
  version?: string;
  path?: string;
}

export interface ExecuteError {
  message: string;
  code: "TIMEOUT" | "ABORTED" | "NOT_FOUND" | "PERMISSION_DENIED" | "UNKNOWN";
  stderr?: string;
}

// Default timeout: 120 seconds (slither can be slow on large projects)
const DEFAULT_TIMEOUT = 120_000;

// Project config files to search for
const PROJECT_CONFIG_FILES = [
  "foundry.toml", // Foundry
  "hardhat.config.js", // Hardhat JS
  "hardhat.config.ts", // Hardhat TS
  "hardhat.config.cjs", // Hardhat CommonJS
  "hardhat.config.mjs", // Hardhat ESM
  "truffle-config.js", // Truffle
  "brownie-config.yaml", // Brownie
  "ape-config.yaml", // Ape
];

// ============================================================================
// Execute Command
// ============================================================================

/**
 * Execute a command and capture its output.
 *
 * Does NOT throw on non-zero exit codes — returns the result for the caller
 * to handle. This is important for tools like slither that may return non-zero
 * exit codes for findings (not errors).
 *
 * @param command - The command to execute
 * @param args - Arguments to pass to the command
 * @param options - Execution options (cwd, timeout, env, signal)
 * @returns ExecuteResult with stdout, stderr, and exitCode
 *
 * @example
 * ```ts
 * const result = await executeCommand("slither", [".", "--json", "-"], { cwd: projectRoot });
 * if (result.exitCode !== 0) {
 *   logger.error("Slither failed", { stderr: result.stderr });
 * }
 * const findings = JSON.parse(result.stdout);
 * ```
 */
export async function executeCommand(
  command: string,
  args: string[],
  options: ExecuteOptions = {}
): Promise<ExecuteResult> {
  const timeoutMs = options.timeout ?? DEFAULT_TIMEOUT;

  // Check if already aborted via external signal
  if (options.signal?.aborted) {
    return {
      stdout: "",
      stderr: "Operation was aborted",
      exitCode: 1,
      timedOut: false,
    };
  }

  const execaOptions: ExecaOptions = {
    cwd: options.cwd,
    timeout: timeoutMs,
    reject: false, // Don't throw on non-zero exit codes
    env: {
      ...process.env,
      ...options.env,
    },
    // Ensure we get string output
    encoding: "utf8",
    // Don't kill on SIGTERM, let the process finish or timeout
    forceKillAfterDelay: 5000,
  };

  try {
    logger.debug(`Executing command: ${command} ${args.join(" ")}`, {
      cwd: options.cwd,
      timeout: timeoutMs,
    });

    const result = await execa(command, args, execaOptions);

    const executeResult: ExecuteResult = {
      stdout: String(result.stdout ?? ""),
      stderr: String(result.stderr ?? ""),
      exitCode: result.exitCode ?? (result.failed ? 1 : 0),
      timedOut: result.timedOut,
    };

    if (result.signal) {
      executeResult.signal = result.signal;
    }

    return executeResult;
  } catch (error) {
    // This catches errors like command not found, permission denied, timeout, etc.
    if (error instanceof Error) {
      const isTimeout = error.message.includes("timed out") || error.message.includes("ETIMEDOUT");
      return {
        stdout: "",
        stderr: error.message,
        exitCode: 1,
        timedOut: isTimeout,
      };
    }

    return {
      stdout: "",
      stderr: "Unknown error executing command",
      exitCode: 1,
    };
  }
}

/**
 * Execute a command with Result type for error handling.
 *
 * @param command - The command to execute
 * @param args - Arguments to pass to the command
 * @param options - Execution options
 * @returns Result with ExecuteResult or ExecuteError
 */
export async function executeCommandSafe(
  command: string,
  args: string[],
  options: ExecuteOptions = {}
): Promise<Result<ExecuteResult, ExecuteError>> {
  const result = await executeCommand(command, args, options);

  if (result.timedOut) {
    return err({
      message: "Command timed out",
      code: "TIMEOUT",
      stderr: result.stderr,
    });
  }

  if (result.stderr.includes("command not found") || result.stderr.includes("not recognized")) {
    return err({
      message: `Command not found: ${command}`,
      code: "NOT_FOUND",
      stderr: result.stderr,
    });
  }

  if (result.stderr.includes("permission denied") || result.stderr.includes("Permission denied")) {
    return err({
      message: `Permission denied: ${command}`,
      code: "PERMISSION_DENIED",
      stderr: result.stderr,
    });
  }

  return ok(result);
}

/**
 * Execute a command with automatic abort after timeout using AbortController.
 *
 * @param command - The command to execute
 * @param args - Arguments to pass to the command
 * @param timeoutMs - Timeout in milliseconds
 * @param options - Additional execution options
 * @returns ExecuteResult
 */
export async function executeWithAbort(
  command: string,
  args: string[],
  timeoutMs: number,
  options: Omit<ExecuteOptions, "timeout" | "signal"> = {}
): Promise<ExecuteResult> {
  const controller = new AbortController();

  return executeCommand(command, args, {
    ...options,
    timeout: timeoutMs,
    signal: controller.signal,
  });
}

// ============================================================================
// Check Tool Availability
// ============================================================================

/**
 * Tool-specific version commands
 */
const TOOL_VERSION_COMMANDS: Record<
  string,
  { args: string[]; parseVersion: (output: string) => string | undefined }
> = {
  slither: {
    args: ["--version"],
    parseVersion: (output) => {
      const match = output.match(/(\d+\.\d+\.\d+)/);
      return match?.[1];
    },
  },
  aderyn: {
    args: ["--version"],
    parseVersion: (output) => {
      const match = output.match(/(\d+\.\d+\.\d+)/);
      return match?.[1];
    },
  },
  forge: {
    args: ["--version"],
    parseVersion: (output) => {
      const match = output.match(/forge\s+(\d+\.\d+\.\d+)/i);
      return match?.[1];
    },
  },
  solc: {
    args: ["--version"],
    parseVersion: (output) => {
      const match = output.match(/Version:\s*(\d+\.\d+\.\d+)/);
      return match?.[1];
    },
  },
  "solc-select": {
    args: ["--version"],
    parseVersion: (output) => {
      const match = output.match(/solc-select\s+(\d+\.\d+\.\d+)/);
      return match?.[1];
    },
  },
};

/**
 * Check if a tool is available in the system PATH.
 *
 * @param tool - Name of the tool to check (slither, aderyn, forge, solc)
 * @returns ToolAvailability with available status and version if found
 */
export async function checkToolAvailable(tool: string): Promise<ToolAvailability> {
  // First, try to find the tool path using 'which' (Unix) or 'where' (Windows)
  const whichCommand = process.platform === "win32" ? "where" : "which";
  const whichResult = await executeCommand(whichCommand, [tool], { timeout: 5000 });

  if (whichResult.exitCode !== 0) {
    return { available: false };
  }

  const toolPath = whichResult.stdout.trim().split("\n")[0];

  // Get version info if we know how to parse it
  const versionConfig = TOOL_VERSION_COMMANDS[tool];

  if (!versionConfig) {
    return {
      available: true,
      path: toolPath,
    };
  }

  const versionResult = await executeCommand(tool, versionConfig.args, { timeout: 10000 });
  const versionOutput = versionResult.stdout || versionResult.stderr;
  const version = versionConfig.parseVersion(versionOutput);

  return {
    available: true,
    version,
    path: toolPath,
  };
}

/**
 * Check multiple tools at once.
 *
 * @param tools - Array of tool names to check
 * @returns Record mapping tool names to their availability
 */
export async function checkToolsAvailable(
  tools: string[]
): Promise<Record<string, ToolAvailability>> {
  const results = await Promise.all(
    tools.map(async (tool) => [tool, await checkToolAvailable(tool)] as const)
  );

  return Object.fromEntries(results);
}

// ============================================================================
// Project Root Detection
// ============================================================================

/**
 * Check if a file exists.
 */
async function fileExists(filePath: string): Promise<boolean> {
  try {
    await access(filePath);
    return true;
  } catch {
    return false;
  }
}

/**
 * Check if a path is a directory.
 */
async function isDirectory(path: string): Promise<boolean> {
  try {
    const stats = await stat(path);
    return stats.isDirectory();
  } catch {
    return false;
  }
}

/**
 * Find the project root by searching upward for config files.
 *
 * @param contractPath - Path to the contract file or directory
 * @returns The project root path, or the contract's directory if not found
 */
export async function getProjectRoot(contractPath: string): Promise<string> {
  const absolutePath = resolve(contractPath);

  let currentDir: string;
  if (await isDirectory(absolutePath)) {
    currentDir = absolutePath;
  } else {
    currentDir = dirname(absolutePath);
  }

  const startingDir = currentDir;
  const root = process.platform === "win32" ? currentDir.split(":")[0] + ":\\" : "/";

  while (currentDir !== root) {
    for (const configFile of PROJECT_CONFIG_FILES) {
      const configPath = join(currentDir, configFile);
      if (await fileExists(configPath)) {
        logger.debug("Found project root", { root: currentDir, config: configFile });
        return currentDir;
      }
    }

    const hasContracts = await fileExists(join(currentDir, "contracts"));
    const hasSrc = await fileExists(join(currentDir, "src"));
    const hasLib = await fileExists(join(currentDir, "lib"));
    const hasNodeModules = await fileExists(join(currentDir, "node_modules"));

    if ((hasContracts || hasSrc) && (hasLib || hasNodeModules)) {
      logger.debug("Found project root by structure", { root: currentDir });
      return currentDir;
    }

    const parentDir = dirname(currentDir);
    if (parentDir === currentDir) {
      break;
    }
    currentDir = parentDir;
  }

  logger.debug("Using fallback project root", { root: startingDir });
  return startingDir;
}

/**
 * Detect the project type based on config files.
 *
 * @param projectRoot - The project root directory
 * @returns The detected project type or "unknown"
 */
export async function detectProjectType(
  projectRoot: string
): Promise<"foundry" | "hardhat" | "truffle" | "brownie" | "ape" | "unknown"> {
  const checks: Array<{
    file: string;
    type: "foundry" | "hardhat" | "truffle" | "brownie" | "ape";
  }> = [
    { file: "foundry.toml", type: "foundry" },
    { file: "hardhat.config.js", type: "hardhat" },
    { file: "hardhat.config.ts", type: "hardhat" },
    { file: "hardhat.config.cjs", type: "hardhat" },
    { file: "hardhat.config.mjs", type: "hardhat" },
    { file: "truffle-config.js", type: "truffle" },
    { file: "brownie-config.yaml", type: "brownie" },
    { file: "ape-config.yaml", type: "ape" },
  ];

  for (const { file, type } of checks) {
    if (await fileExists(join(projectRoot, file))) {
      return type;
    }
  }

  return "unknown";
}

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Parse JSON output safely, handling common issues with tool output.
 *
 * @param output - The raw output string
 * @returns Parsed JSON or null if parsing fails
 */
export function parseJsonOutput<T = unknown>(output: string): T | null {
  // First, try direct parsing
  try {
    return JSON.parse(output) as T;
  } catch {
    // Continue to try extracting JSON
  }

  // Try to find JSON object or array in the output
  const jsonMatch = output.match(/(\{[\s\S]*\}|\[[\s\S]*\])/);
  if (jsonMatch) {
    try {
      return JSON.parse(jsonMatch[1]!) as T;
    } catch {
      // Failed to parse extracted JSON
    }
  }

  return null;
}

/**
 * Format a duration in milliseconds to a human-readable string.
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

/**
 * Create a timeout promise that rejects after the specified duration.
 * Uses AbortController for proper cleanup.
 */
export function timeout<T>(promise: Promise<T>, ms: number, message?: string): Promise<T> {
  const controller = new AbortController();

  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      controller.abort();
      reject(new Error(message ?? `Operation timed out after ${formatDuration(ms)}`));
    }, ms);

    promise
      .then((result) => {
        clearTimeout(timer);
        resolve(result);
      })
      .catch((error) => {
        clearTimeout(timer);
        reject(error);
      });
  });
}

/**
 * Run multiple commands in parallel with a concurrency limit.
 *
 * @param commands - Array of command configurations
 * @param concurrency - Maximum number of parallel executions (default: 3)
 * @returns Array of results in the same order as input
 */
export async function executeParallel(
  commands: Array<{ command: string; args: string[]; options?: ExecuteOptions }>,
  concurrency = 3
): Promise<ExecuteResult[]> {
  const results: ExecuteResult[] = [];
  const queue = [...commands];
  let index = 0;

  const workers = Array.from({ length: Math.min(concurrency, commands.length) }, async () => {
    while (index < queue.length) {
      const currentIndex = index++;
      const cmd = queue[currentIndex];
      if (cmd) {
        const result = await executeCommand(cmd.command, cmd.args, cmd.options);
        results[currentIndex] = result;
      }
    }
  });

  await Promise.all(workers);
  return results;
}
