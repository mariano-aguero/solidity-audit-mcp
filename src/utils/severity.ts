/**
 * Severity utilities
 *
 * Centralized severity-related functions to avoid duplication
 * across the codebase.
 */

import { Severity, type Finding } from "../types/index.js";

// ============================================================================
// Severity Order (for sorting)
// ============================================================================

/**
 * Numeric ordering for severity levels (lower = more severe)
 */
export const SEVERITY_ORDER: Record<Severity, number> = {
  [Severity.CRITICAL]: 0,
  [Severity.HIGH]: 1,
  [Severity.MEDIUM]: 2,
  [Severity.LOW]: 3,
  [Severity.INFORMATIONAL]: 4,
};

/**
 * Compare two severities for sorting (most severe first)
 */
export function compareSeverity(a: Severity, b: Severity): number {
  return SEVERITY_ORDER[a] - SEVERITY_ORDER[b];
}

/**
 * Sort findings by severity (most severe first)
 */
export function sortBySeverity<T extends { severity: Severity }>(items: T[]): T[] {
  return [...items].sort((a, b) => compareSeverity(a.severity, b.severity));
}

// ============================================================================
// Severity Emojis
// ============================================================================

/**
 * Emoji mapping for severity levels
 */
export const SEVERITY_EMOJI: Record<Severity, string> = {
  [Severity.CRITICAL]: "🔴",
  [Severity.HIGH]: "🟠",
  [Severity.MEDIUM]: "🟡",
  [Severity.LOW]: "🟢",
  [Severity.INFORMATIONAL]: "🔵",
};

/**
 * Get emoji for a severity level
 */
export function getSeverityEmoji(severity: Severity): string {
  // Using Record<Severity, string> ensures all severity levels are covered
  return SEVERITY_EMOJI[severity];
}

// ============================================================================
// Severity Counts
// ============================================================================

/**
 * Base interface for severity counts
 */
export interface SeverityCounts {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  informational: number;
}

/**
 * Count findings by severity level.
 * Generic function that replaces calculateSummary, calculateGasSummary, etc.
 *
 * @param findings - Array of items with a severity property
 * @returns Object with counts per severity level
 */
export function countBySeverity<T extends { severity: Severity }>(items: T[]): SeverityCounts {
  const counts: SeverityCounts = {
    total: items.length,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    informational: 0,
  };

  for (const item of items) {
    switch (item.severity) {
      case Severity.CRITICAL:
        counts.critical++;
        break;
      case Severity.HIGH:
        counts.high++;
        break;
      case Severity.MEDIUM:
        counts.medium++;
        break;
      case Severity.LOW:
        counts.low++;
        break;
      case Severity.INFORMATIONAL:
        counts.informational++;
        break;
    }
  }

  return counts;
}

// ============================================================================
// Gas Savings Estimation
// ============================================================================

/**
 * Estimate gas savings based on severity level
 */
export const SEVERITY_GAS_ESTIMATES: Record<Severity, number> = {
  [Severity.CRITICAL]: 5000,
  [Severity.HIGH]: 2000,
  [Severity.MEDIUM]: 500,
  [Severity.LOW]: 100,
  [Severity.INFORMATIONAL]: 50,
};

/**
 * Get estimated gas savings for a severity level
 */
export function estimateGasSavings(severity: Severity): number {
  // Using Record<Severity, number> ensures all severity levels are covered
  return SEVERITY_GAS_ESTIMATES[severity];
}

/**
 * Extract gas savings from a finding description
 */
export function extractGasSavings(description: string): number {
  const gasMatch = description.match(/~?(\d+)(?:-(\d+))?\s*gas/i);
  if (gasMatch) {
    const low = parseInt(gasMatch[1]!, 10);
    const high = gasMatch[2] ? parseInt(gasMatch[2], 10) : low;
    return Math.floor((low + high) / 2);
  }
  return 0;
}

/**
 * Format gas savings for display
 */
export function formatGasSavings(totalGas: number): string {
  if (totalGas >= 1_000_000) {
    return `${(totalGas / 1_000_000).toFixed(1)}M`;
  }
  if (totalGas >= 1_000) {
    return `${(totalGas / 1_000).toFixed(1)}K`;
  }
  return totalGas.toString();
}

/**
 * Calculate total gas savings from findings
 */
export function calculateTotalGasSavings(findings: Finding[]): number {
  return findings.reduce((sum, finding) => sum + extractGasSavings(finding.description), 0);
}
