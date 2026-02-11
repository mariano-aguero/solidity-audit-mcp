/**
 * Get Contract Info Tool
 *
 * Extracts metadata from a Solidity contract without running analysis.
 * Useful for understanding contract structure before deeper analysis.
 */

import { access, readFile } from "fs/promises";
import { z } from "zod";
import {
  parseContractInfo,
  detectPatterns,
  type ParsedContract,
} from "../analyzers/slangAnalyzer.js";
import type { FunctionInfo, Visibility } from "../types/index.js";
import { logger } from "../utils/logger.js";

// ============================================================================
// Types
// ============================================================================

export const GetContractInfoInputSchema = z.object({
  contractPath: z.string().describe("Path to the Solidity contract file"),
});

export type GetContractInfoInput = z.infer<typeof GetContractInfoInputSchema>;

export interface AttackSurface {
  externalFunctions: number;
  publicFunctions: number;
  payableFunctions: number;
  hasReceive: boolean;
  hasFallback: boolean;
  hasConstructor: boolean;
  stateVariableCount: number;
  publicStateVariables: number;
  usesProxy: boolean;
  usesDelegatecall: boolean;
  usesAssembly: boolean;
  usesSelfDestruct: boolean;
}

// ============================================================================
// Main Function
// ============================================================================

/**
 * Get metadata and attack surface information for a Solidity contract.
 *
 * @param input - Input containing contract path
 * @returns Formatted contract information
 */
export async function getContractInfo(input: GetContractInfoInput): Promise<string> {
  logger.info(`[getContractInfo] Analyzing ${input.contractPath}`);

  // Validate file exists
  try {
    await access(input.contractPath);
  } catch {
    return formatError(`Contract file not found: ${input.contractPath}`);
  }

  if (!input.contractPath.endsWith(".sol")) {
    return formatError("Only Solidity (.sol) files are supported");
  }

  // Parse contract
  let contractInfo: ParsedContract;
  try {
    contractInfo = await parseContractInfo(input.contractPath);
  } catch (err) {
    return formatError(
      `Failed to parse contract: ${err instanceof Error ? err.message : String(err)}`
    );
  }

  // Read source for pattern detection
  const source = await readFile(input.contractPath, "utf-8");
  const patterns = detectPatterns(source);

  // Calculate attack surface
  const attackSurface = calculateAttackSurface(contractInfo, patterns);

  // Format output
  return formatOutput(contractInfo, attackSurface, patterns);
}

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Calculate attack surface metrics
 */
function calculateAttackSurface(
  info: ParsedContract,
  patterns: ReturnType<typeof detectPatterns>
): AttackSurface {
  const externalFunctions = info.functions.filter((f) => f.visibility === "external").length;

  const publicFunctions = info.functions.filter((f) => f.visibility === "public").length;

  const payableFunctions = info.functions.filter((f) => f.stateMutability === "payable").length;

  const hasReceive = info.functions.some((f) => f.name === "receive");
  const hasFallback = info.functions.some((f) => f.name === "fallback");

  const publicStateVariables = info.stateVariables.filter((v) => v.visibility === "public").length;

  const usesDelegatecall = patterns.some((p) => p.pattern === "delegatecall");
  const usesAssembly = patterns.some((p) => p.pattern === "inline-assembly");
  const usesSelfDestruct = patterns.some((p) => p.pattern === "selfdestruct");

  return {
    externalFunctions,
    publicFunctions,
    payableFunctions,
    hasReceive,
    hasFallback,
    hasConstructor: info.hasConstructor,
    stateVariableCount: info.stateVariables.length,
    publicStateVariables,
    usesProxy: info.usesProxy,
    usesDelegatecall,
    usesAssembly,
    usesSelfDestruct,
  };
}

/**
 * Format function signature
 */
function formatFunctionSignature(fn: FunctionInfo): string {
  const mutability = fn.stateMutability !== "nonpayable" ? ` ${fn.stateMutability}` : "";
  const modifiers = fn.modifiers.length > 0 ? ` [${fn.modifiers.join(", ")}]` : "";
  return `${fn.name}()${mutability}${modifiers}`;
}

/**
 * Format visibility badge
 */
function formatVisibility(visibility: Visibility): string {
  switch (visibility) {
    case "external":
      return "🌐 external";
    case "public":
      return "📢 public";
    case "internal":
      return "🔒 internal";
    case "private":
      return "🔐 private";
  }
}

/**
 * Format error response
 */
function formatError(message: string): string {
  return JSON.stringify({ success: false, error: message }, null, 2);
}

/**
 * Format the contract info output
 */
function formatOutput(
  info: ParsedContract,
  attackSurface: AttackSurface,
  patterns: ReturnType<typeof detectPatterns>
): string {
  const lines: string[] = [];

  // Header
  lines.push("═══════════════════════════════════════════════════════════════════════════════");
  lines.push(`  CONTRACT INFO: ${info.name}`);
  lines.push("═══════════════════════════════════════════════════════════════════════════════");
  lines.push("");

  // Basic info
  lines.push("┌─────────────────────────────────────────────────────────────────────────────┐");
  lines.push("│  OVERVIEW                                                                   │");
  lines.push("└─────────────────────────────────────────────────────────────────────────────┘");
  lines.push(`  Name: ${info.name}`);
  lines.push(`  Path: ${info.path}`);
  lines.push(`  Compiler: ${info.compiler}`);
  lines.push(`  Type: ${getContractType(info)}`);
  lines.push("");

  // Inheritance
  if (info.inherits.length > 0) {
    lines.push("┌─────────────────────────────────────────────────────────────────────────────┐");
    lines.push("│  INHERITANCE                                                                │");
    lines.push("└─────────────────────────────────────────────────────────────────────────────┘");
    lines.push(`  ${info.name} is ${info.inherits.join(", ")}`);
    lines.push("");
    lines.push("  Inheritance chain:");
    for (const parent of info.inherits) {
      lines.push(`    └─ ${parent}`);
    }
    lines.push("");
  }

  // Interfaces
  if (info.interfaces.length > 0) {
    lines.push(`  Implements interfaces: ${info.interfaces.join(", ")}`);
    lines.push("");
  }

  // Attack Surface Summary
  lines.push("┌─────────────────────────────────────────────────────────────────────────────┐");
  lines.push("│  ATTACK SURFACE                                                             │");
  lines.push("└─────────────────────────────────────────────────────────────────────────────┘");
  lines.push(
    `  Entry points: ${attackSurface.externalFunctions + attackSurface.publicFunctions} functions`
  );
  lines.push(`    • External functions: ${attackSurface.externalFunctions}`);
  lines.push(`    • Public functions: ${attackSurface.publicFunctions}`);
  lines.push(`    • Payable functions: ${attackSurface.payableFunctions}`);
  lines.push("");
  lines.push("  ETH handling:");
  lines.push(`    • Has receive(): ${attackSurface.hasReceive ? "✅ yes" : "❌ no"}`);
  lines.push(`    • Has fallback(): ${attackSurface.hasFallback ? "✅ yes" : "❌ no"}`);
  lines.push(`    • Payable functions: ${attackSurface.payableFunctions}`);
  lines.push("");
  lines.push("  State:");
  lines.push(`    • State variables: ${attackSurface.stateVariableCount}`);
  lines.push(`    • Public state variables: ${attackSurface.publicStateVariables}`);
  lines.push("");
  lines.push("  Special patterns:");
  lines.push(`    • Uses proxy pattern: ${attackSurface.usesProxy ? "⚠️  yes" : "❌ no"}`);
  lines.push(`    • Uses delegatecall: ${attackSurface.usesDelegatecall ? "⚠️  yes" : "❌ no"}`);
  lines.push(`    • Uses assembly: ${attackSurface.usesAssembly ? "⚠️  yes" : "❌ no"}`);
  lines.push(`    • Has selfdestruct: ${attackSurface.usesSelfDestruct ? "🔴 yes" : "❌ no"}`);
  lines.push("");

  // Functions
  lines.push("┌─────────────────────────────────────────────────────────────────────────────┐");
  lines.push("│  FUNCTIONS                                                                  │");
  lines.push("└─────────────────────────────────────────────────────────────────────────────┘");

  // Group by visibility
  const byVisibility: Record<Visibility, FunctionInfo[]> = {
    external: [],
    public: [],
    internal: [],
    private: [],
  };

  for (const fn of info.functions) {
    byVisibility[fn.visibility].push(fn);
  }

  // Show external and public first (attack surface)
  for (const visibility of ["external", "public", "internal", "private"] as const) {
    const functions = byVisibility[visibility];
    if (functions.length === 0) continue;

    lines.push("");
    lines.push(`  ${formatVisibility(visibility)} (${functions.length})`);
    lines.push("  " + "─".repeat(40));

    for (const fn of functions) {
      const sig = formatFunctionSignature(fn);
      const payableTag = fn.stateMutability === "payable" ? " 💰" : "";
      const viewTag = fn.stateMutability === "view" ? " 👁️" : "";
      const pureTag = fn.stateMutability === "pure" ? " 🔢" : "";
      lines.push(`    • ${sig}${payableTag}${viewTag}${pureTag}`);
    }
  }
  lines.push("");

  // State Variables
  if (info.stateVariables.length > 0) {
    lines.push("┌─────────────────────────────────────────────────────────────────────────────┐");
    lines.push("│  STATE VARIABLES                                                            │");
    lines.push("└─────────────────────────────────────────────────────────────────────────────┘");

    for (const variable of info.stateVariables) {
      const vis = variable.visibility === "public" ? "📢" : "🔒";
      lines.push(`  ${vis} ${variable.type} ${variable.name}`);
    }
    lines.push("");
  }

  // Events
  if (info.events.length > 0) {
    lines.push("┌─────────────────────────────────────────────────────────────────────────────┐");
    lines.push("│  EVENTS                                                                     │");
    lines.push("└─────────────────────────────────────────────────────────────────────────────┘");
    for (const event of info.events) {
      lines.push(`  📡 ${event}`);
    }
    lines.push("");
  }

  // Errors
  if (info.errors.length > 0) {
    lines.push("┌─────────────────────────────────────────────────────────────────────────────┐");
    lines.push("│  CUSTOM ERRORS                                                              │");
    lines.push("└─────────────────────────────────────────────────────────────────────────────┘");
    for (const error of info.errors) {
      lines.push(`  ❌ ${error}`);
    }
    lines.push("");
  }

  // Modifiers
  if (info.modifiers.length > 0) {
    lines.push("┌─────────────────────────────────────────────────────────────────────────────┐");
    lines.push("│  MODIFIERS                                                                  │");
    lines.push("└─────────────────────────────────────────────────────────────────────────────┘");
    for (const modifier of info.modifiers) {
      lines.push(`  🛡️  ${modifier}`);
    }
    lines.push("");
  }

  // Imports
  if (info.imports.length > 0) {
    lines.push("┌─────────────────────────────────────────────────────────────────────────────┐");
    lines.push("│  IMPORTS                                                                    │");
    lines.push("└─────────────────────────────────────────────────────────────────────────────┘");
    for (const imp of info.imports) {
      const isOpenZeppelin = imp.includes("@openzeppelin");
      const icon = isOpenZeppelin ? "🔷" : "📦";
      lines.push(`  ${icon} ${imp}`);
    }
    lines.push("");
  }

  // Detected Patterns
  const highRiskPatterns = patterns.filter((p) => p.risk === "high");
  const mediumRiskPatterns = patterns.filter((p) => p.risk === "medium");

  if (highRiskPatterns.length > 0 || mediumRiskPatterns.length > 0) {
    lines.push("┌─────────────────────────────────────────────────────────────────────────────┐");
    lines.push("│  DETECTED PATTERNS                                                          │");
    lines.push("└─────────────────────────────────────────────────────────────────────────────┘");

    if (highRiskPatterns.length > 0) {
      lines.push("");
      lines.push("  🔴 High Risk:");
      for (const p of highRiskPatterns) {
        lines.push(`    • Line ${p.line}: ${p.pattern}`);
        lines.push(`      ${p.description}`);
      }
    }

    if (mediumRiskPatterns.length > 0) {
      lines.push("");
      lines.push("  🟡 Medium Risk:");
      for (const p of mediumRiskPatterns) {
        lines.push(`    • Line ${p.line}: ${p.pattern}`);
        lines.push(`      ${p.description}`);
      }
    }
    lines.push("");
  }

  // Security considerations based on attack surface
  lines.push("┌─────────────────────────────────────────────────────────────────────────────┐");
  lines.push("│  SECURITY CONSIDERATIONS                                                    │");
  lines.push("└─────────────────────────────────────────────────────────────────────────────┘");

  const considerations: string[] = [];

  if (attackSurface.payableFunctions > 0) {
    considerations.push(
      "• Contract handles ETH - check for reentrancy and proper withdrawal patterns"
    );
  }

  if (attackSurface.hasReceive || attackSurface.hasFallback) {
    considerations.push("• Has receive/fallback - verify ETH handling logic");
  }

  if (attackSurface.usesProxy) {
    considerations.push("• Uses proxy pattern - check initialization and upgrade security");
  }

  if (attackSurface.usesDelegatecall) {
    considerations.push("• Uses delegatecall - high risk, verify target contracts");
  }

  if (attackSurface.usesAssembly) {
    considerations.push("• Uses inline assembly - bypasses Solidity safety checks");
  }

  if (attackSurface.usesSelfDestruct) {
    considerations.push("• Has selfdestruct - can permanently destroy contract");
  }

  if (attackSurface.publicStateVariables > 0) {
    considerations.push("• Has public state variables - all data is readable on-chain");
  }

  if (attackSurface.externalFunctions + attackSurface.publicFunctions > 10) {
    considerations.push("• Large attack surface - many entry points to audit");
  }

  if (info.inherits.length > 3) {
    considerations.push("• Complex inheritance - check for function shadowing");
  }

  if (considerations.length === 0) {
    considerations.push("• No obvious high-risk patterns detected");
  }

  for (const c of considerations) {
    lines.push(`  ${c}`);
  }

  lines.push("");
  lines.push("═══════════════════════════════════════════════════════════════════════════════");

  // Add JSON data at the end
  const jsonData = {
    success: true,
    contractInfo: info,
    attackSurface,
    patternsDetected: patterns.length,
    highRiskPatterns: highRiskPatterns.length,
  };

  lines.push("");
  lines.push("JSON DATA:");
  lines.push(JSON.stringify(jsonData, null, 2));

  return lines.join("\n");
}

/**
 * Determine contract type from parsed info
 */
function getContractType(info: ParsedContract): string {
  if (info.usesProxy) {
    if (info.inherits.some((i) => i.includes("UUPS"))) {
      return "UUPS Upgradeable Proxy";
    }
    if (info.inherits.some((i) => i.includes("Transparent"))) {
      return "Transparent Proxy";
    }
    if (info.inherits.some((i) => i.includes("Beacon"))) {
      return "Beacon Proxy";
    }
    return "Upgradeable Contract";
  }

  if (info.inherits.some((i) => i.includes("ERC20"))) {
    return "ERC20 Token";
  }
  if (info.inherits.some((i) => i.includes("ERC721"))) {
    return "ERC721 NFT";
  }
  if (info.inherits.some((i) => i.includes("ERC1155"))) {
    return "ERC1155 Multi-Token";
  }
  if (info.inherits.some((i) => i.includes("Governor"))) {
    return "Governance Contract";
  }
  if (info.inherits.some((i) => i.includes("AccessControl"))) {
    return "Access-Controlled Contract";
  }
  if (info.inherits.some((i) => i.includes("Ownable"))) {
    return "Ownable Contract";
  }

  return "Standard Contract";
}
