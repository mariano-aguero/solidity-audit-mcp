/**
 * Gas Optimization Tool
 *
 * Analyzes smart contracts for inefficient gas usage patterns
 * and provides optimization recommendations with estimated savings.
 */

import { z } from "zod";
import { existsSync } from "fs";
import { resolve } from "path";
import { analyzeGasPatterns } from "../analyzers/adapters/GasAdapter.js";
import { Severity, Finding } from "../types/index.js";

// ============================================================================
// Input Schema
// ============================================================================

export const OptimizeGasInputSchema = z.object({
  contractPath: z.string().describe("Absolute path to the Solidity contract file"),
  includeInformational: z
    .boolean()
    .optional()
    .default(false)
    .describe("Include INFORMATIONAL severity findings (default: false)"),
});

export type OptimizeGasInput = z.infer<typeof OptimizeGasInputSchema>;

// ============================================================================
// Output Types
// ============================================================================

export interface GasOptimizationResult {
  success: boolean;
  gasScore: number;
  findings: Finding[];
  estimatedTotalSavings: string;
  summaryText: string;
  breakdown: {
    high: number;
    medium: number;
    low: number;
    informational: number;
  };
}

// ============================================================================
// Gas Savings Parsing
// ============================================================================

/**
 * Extract numeric gas savings from description string.
 * Handles formats like "~100 gas", "~5000 gas per write", "~300-600 gas"
 */
function extractGasSavings(description: string): number {
  // Look for "Estimated savings: ~X gas" pattern
  const savingsMatch = description.match(/Estimated savings:\s*~?(\d+)(?:-(\d+))?\s*gas/i);
  if (savingsMatch) {
    const low = parseInt(savingsMatch[1]!, 10);
    const high = savingsMatch[2] ? parseInt(savingsMatch[2], 10) : low;
    return Math.floor((low + high) / 2);
  }

  // Fallback: look for any gas number in description
  const gasMatch = description.match(/~?(\d+)(?:-(\d+))?\s*gas/i);
  if (gasMatch) {
    const low = parseInt(gasMatch[1]!, 10);
    const high = gasMatch[2] ? parseInt(gasMatch[2], 10) : low;
    return Math.floor((low + high) / 2);
  }

  return 0;
}

/**
 * Sort findings by estimated gas savings (highest first)
 */
function sortByGasSavings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const savingsA = extractGasSavings(a.description);
    const savingsB = extractGasSavings(b.description);
    return savingsB - savingsA;
  });
}

// ============================================================================
// Gas Score Calculation
// ============================================================================

/**
 * Calculate a gas efficiency score from 0-100.
 * 100 = perfect (no issues found)
 * Lower scores indicate more optimization opportunities.
 */
function calculateGasScore(findings: Finding[]): number {
  let score = 100;

  for (const finding of findings) {
    switch (finding.severity) {
      case Severity.CRITICAL:
        score -= 25;
        break;
      case Severity.HIGH:
        score -= 15;
        break;
      case Severity.MEDIUM:
        score -= 10;
        break;
      case Severity.LOW:
        score -= 5;
        break;
      case Severity.INFORMATIONAL:
        score -= 2;
        break;
    }
  }

  return Math.max(0, score);
}

/**
 * Calculate total estimated gas savings
 */
function calculateTotalSavings(findings: Finding[]): number {
  return findings.reduce((total, finding) => {
    return total + extractGasSavings(finding.description);
  }, 0);
}

/**
 * Format gas savings for display
 */
function formatGasSavings(gas: number): string {
  if (gas >= 1000000) {
    return `${(gas / 1000000).toFixed(1)}M`;
  }
  if (gas >= 1000) {
    return `${(gas / 1000).toFixed(1)}K`;
  }
  return gas.toString();
}

// ============================================================================
// Main Tool Implementation
// ============================================================================

/**
 * Analyze a smart contract for gas optimization opportunities.
 */
export async function optimizeGas(input: OptimizeGasInput): Promise<GasOptimizationResult> {
  // Validate input
  const contractPath = resolve(input.contractPath);

  if (!existsSync(contractPath)) {
    return {
      success: false,
      gasScore: 0,
      findings: [],
      estimatedTotalSavings: "0",
      summaryText: `Error: Contract file not found: ${contractPath}`,
      breakdown: { high: 0, medium: 0, low: 0, informational: 0 },
    };
  }

  if (!contractPath.endsWith(".sol")) {
    return {
      success: false,
      gasScore: 0,
      findings: [],
      estimatedTotalSavings: "0",
      summaryText: "Error: File must be a Solidity contract (.sol)",
      breakdown: { high: 0, medium: 0, low: 0, informational: 0 },
    };
  }

  try {
    // Run gas analysis
    let findings = await analyzeGasPatterns(contractPath);

    // Count by severity before filtering
    const breakdown = {
      high: findings.filter((f) => f.severity === Severity.HIGH).length,
      medium: findings.filter((f) => f.severity === Severity.MEDIUM).length,
      low: findings.filter((f) => f.severity === Severity.LOW).length,
      informational: findings.filter((f) => f.severity === Severity.INFORMATIONAL).length,
    };

    // Filter out informational if not requested
    if (!input.includeInformational) {
      findings = findings.filter((f) => f.severity !== Severity.INFORMATIONAL);
    }

    // Sort by gas savings (highest first)
    findings = sortByGasSavings(findings);

    // Calculate metrics
    const gasScore = calculateGasScore(findings);
    const totalSavings = calculateTotalSavings(findings);
    const formattedSavings = formatGasSavings(totalSavings);

    // Generate summary
    const summaryText =
      findings.length === 0
        ? "No se encontraron optimizaciones de gas significativas."
        : `Se encontraron ${findings.length} optimizaciones que podrían ahorrar ~${formattedSavings} gas.`;

    return {
      success: true,
      gasScore,
      findings,
      estimatedTotalSavings: formattedSavings,
      summaryText,
      breakdown,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      success: false,
      gasScore: 0,
      findings: [],
      estimatedTotalSavings: "0",
      summaryText: `Error analyzing contract: ${message}`,
      breakdown: { high: 0, medium: 0, low: 0, informational: 0 },
    };
  }
}

// ============================================================================
// Response Formatter
// ============================================================================

/**
 * Format the gas optimization result for MCP response.
 */
export function formatGasOptimizationResult(result: GasOptimizationResult): string {
  if (!result.success) {
    return result.summaryText;
  }

  const lines: string[] = [];

  // Header
  lines.push("# Gas Optimization Report");
  lines.push("");

  // Summary
  lines.push("## Summary");
  lines.push("");
  lines.push(`**Gas Score:** ${result.gasScore}/100`);
  lines.push(`**Estimated Total Savings:** ~${result.estimatedTotalSavings} gas`);
  lines.push(`**Findings:** ${result.findings.length}`);
  lines.push("");

  // Breakdown
  lines.push("### Breakdown by Severity");
  lines.push("");
  lines.push(`- High: ${result.breakdown.high}`);
  lines.push(`- Medium: ${result.breakdown.medium}`);
  lines.push(`- Low: ${result.breakdown.low}`);
  lines.push(`- Informational: ${result.breakdown.informational}`);
  lines.push("");

  // Findings
  if (result.findings.length > 0) {
    lines.push("## Findings");
    lines.push("");

    for (const finding of result.findings) {
      lines.push(`### ${finding.id}: ${finding.title}`);
      lines.push("");
      lines.push(`**Severity:** ${finding.severity.toUpperCase()}`);
      lines.push(`**Location:** ${finding.location.file}:${finding.location.lines?.[0] ?? "?"}`);
      if (finding.location.function) {
        lines.push(`**Function:** ${finding.location.function}`);
      }
      lines.push("");
      lines.push(finding.description);
      lines.push("");
      lines.push(`**Recommendation:** ${finding.recommendation}`);
      lines.push("");
      lines.push("---");
      lines.push("");
    }
  }

  // Footer
  lines.push(result.summaryText);

  return lines.join("\n");
}
