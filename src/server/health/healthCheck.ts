/**
 * Health Check
 *
 * Health check logic for the HTTP/SSE server.
 * Checks availability of external analyzers.
 */

import { execa } from "execa";
import { existsSync } from "node:fs";
import { join } from "node:path";

import { SERVER_NAME, SERVER_VERSION, HEALTH_CACHE_TTL } from "../config.js";
import { TOOLS } from "../tools/toolDefinitions.js";

// ============================================================================
// Types
// ============================================================================

export interface AnalyzerStatus {
  available: boolean;
  version?: string;
  error?: string;
}

export interface HealthStatus {
  status: "healthy" | "degraded" | "unhealthy";
  server: string;
  version: string;
  uptime: number;
  tools: number;
  analyzers: {
    // External binaries
    slither: AnalyzerStatus;
    aderyn: AnalyzerStatus;
    forge: AnalyzerStatus;
    solc: AnalyzerStatus;
    echidna: AnalyzerStatus;
    halmos: AnalyzerStatus;
    // Internal (Node.js package — no binary required)
    slang: AnalyzerStatus;
  };
  timestamp: string;
}

export interface QuickHealthStatus {
  status: "ok";
  server: string;
  version: string;
  uptime: number;
}

// ============================================================================
// State
// ============================================================================

const startTime = Date.now();
let cachedHealth: HealthStatus | null = null;
let cachedHealthTime = 0;

// ============================================================================
// Analyzer Checks
// ============================================================================

/**
 * Check if an analyzer is available and get its version.
 */
async function checkAnalyzer(
  command: string,
  args: string[],
  versionParser?: (output: string) => string
): Promise<AnalyzerStatus> {
  try {
    const result = await execa(command, args, { timeout: 5000 });
    const output = result.stdout || result.stderr;
    const version = versionParser ? versionParser(output) : output.split("\n")[0]?.trim();
    return { available: true, version };
  } catch (error) {
    return {
      available: false,
      error: error instanceof Error ? error.message : "Unknown error",
    };
  }
}

/**
 * Check if the @nomicfoundation/slang npm package is available.
 */
async function checkSlang(): Promise<AnalyzerStatus> {
  try {
    // The package is a Node.js native addon — verify the module directory exists
    const slangDir = join(
      new URL("../../../", import.meta.url).pathname,
      "node_modules/@nomicfoundation/slang"
    );
    if (!existsSync(slangDir)) {
      return { available: false, error: "@nomicfoundation/slang package not found" };
    }
    // Try actually importing to confirm the native binary loads
    const { NonterminalKind } = await import("@nomicfoundation/slang/cst");
    const version = NonterminalKind ? "available" : "unknown";
    return { available: true, version };
  } catch (error) {
    return {
      available: false,
      error: error instanceof Error ? error.message : "Unknown error",
    };
  }
}

/**
 * Get full health status with analyzer availability.
 */
async function getHealthStatus(): Promise<HealthStatus> {
  // Run all checks in parallel
  const [slither, aderyn, forge, solc, echidna, halmos, slang] = await Promise.all([
    checkAnalyzer("slither", ["--version"], (out) => out.trim()),
    checkAnalyzer(
      "aderyn",
      ["--version"],
      (out) => out.match(/aderyn\s+([\d.]+)/i)?.[1] || out.trim()
    ),
    checkAnalyzer(
      "forge",
      ["--version"],
      (out) => out.match(/Version:\s*([\d.]+(?:-\w+)?)/i)?.[1] ?? out.split("\n")[0]?.trim() ?? out.trim()
    ),
    checkAnalyzer(
      "solc",
      ["--version"],
      (out) => out.match(/Version:\s*([\d.]+)/)?.[1] || out.trim()
    ),
    checkAnalyzer(
      "echidna",
      ["--version"],
      (out) => out.match(/Echidna\s+([\d.]+)/i)?.[1] || out.trim()
    ),
    checkAnalyzer(
      "halmos",
      ["--version"],
      (out) => out.match(/halmos\s+([\d.]+)/i)?.[1] || out.trim()
    ),
    checkSlang(),
  ]);

  const analyzers = { slither, aderyn, forge, solc, echidna, halmos, slang };

  // Determine overall status based on core tools (slither + forge = static analysis backbone)
  // Slang is internal so always expected; echidna/halmos are opt-in fuzzers
  const coreAvailable = [slither, forge].filter((a) => a.available).length;
  let status: HealthStatus["status"];

  if (coreAvailable === 2) {
    status = "healthy"; // Both core analyzers available
  } else if (coreAvailable === 1 || slang.available) {
    status = "degraded"; // Can still do pattern/slang analysis
  } else {
    status = "unhealthy";
  }

  return {
    status,
    server: SERVER_NAME,
    version: SERVER_VERSION,
    uptime: getUptime(),
    tools: TOOLS.length,
    analyzers,
    timestamp: new Date().toISOString(),
  };
}

// ============================================================================
// Public API
// ============================================================================

/**
 * Get uptime in seconds.
 */
export function getUptime(): number {
  return Math.floor((Date.now() - startTime) / 1000);
}

/**
 * Get cached health status (avoids too many subprocess calls).
 */
export async function getCachedHealthStatus(): Promise<HealthStatus> {
  const now = Date.now();

  if (cachedHealth && now - cachedHealthTime < HEALTH_CACHE_TTL) {
    // Return cached health with updated uptime
    return { ...cachedHealth, uptime: getUptime() };
  }

  cachedHealth = await getHealthStatus();
  cachedHealthTime = now;
  return cachedHealth;
}

/**
 * Get quick health status (no analyzer verification).
 */
export function getQuickHealthStatus(): QuickHealthStatus {
  return {
    status: "ok",
    server: SERVER_NAME,
    version: SERVER_VERSION,
    uptime: getUptime(),
  };
}

/**
 * Format analyzer status for logging.
 */
export function formatAnalyzerStatus(health: HealthStatus): string {
  return Object.entries(health.analyzers)
    .map(([name, status]) => `${name}: ${status.available ? "✓" : "✗"}`)
    .join(", ");
}
