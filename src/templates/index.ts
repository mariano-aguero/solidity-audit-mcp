/**
 * Template Exports
 *
 * Export template file paths and utilities for rendering Markdown templates.
 * Supports Handlebars-style syntax for complex templating.
 */

import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { Severity } from "../types/index.js";

// Get the templates directory path
const __dirname = dirname(fileURLToPath(import.meta.url));

// ============================================================================
// Template Paths
// ============================================================================

export const TEMPLATE_PATHS = {
  /** Full audit report template */
  report: join(__dirname, "reportTemplate.md"),
  /** Individual finding template (partial) */
  finding: join(__dirname, "findingTemplate.md"),
  /** PR summary comment template */
  prSummary: join(__dirname, "prSummaryTemplate.md"),
  /** PR line comment template (for inline code comments) */
  prLineComment: join(__dirname, "prLineCommentTemplate.md"),
  /** Diff audit report template */
  diffAudit: join(__dirname, "diffAuditTemplate.md"),
} as const;

export type TemplateName = keyof typeof TEMPLATE_PATHS;

// ============================================================================
// Severity Styling
// ============================================================================

/** Emoji mapping for severities */
export const SEVERITY_EMOJI: Record<Severity, string> = {
  [Severity.CRITICAL]: ":rotating_light:",
  [Severity.HIGH]: ":red_circle:",
  [Severity.MEDIUM]: ":orange_circle:",
  [Severity.LOW]: ":yellow_circle:",
  [Severity.INFORMATIONAL]: ":blue_circle:",
};

/** Badge colors for shields.io */
export const SEVERITY_BADGE_COLOR: Record<Severity, string> = {
  [Severity.CRITICAL]: "critical",
  [Severity.HIGH]: "red",
  [Severity.MEDIUM]: "orange",
  [Severity.LOW]: "yellow",
  [Severity.INFORMATIONAL]: "blue",
};

/** Confidence level emojis */
export const CONFIDENCE_EMOJI: Record<string, string> = {
  high: ":white_check_mark:",
  medium: ":large_blue_circle:",
  low: ":grey_question:",
};

// ============================================================================
// Template Loading
// ============================================================================

/**
 * Load a template by name.
 *
 * @param name - Template name
 * @returns Template content as string
 */
export async function loadTemplate(name: TemplateName): Promise<string> {
  const path = TEMPLATE_PATHS[name];
  return readFile(path, "utf-8");
}

/**
 * Load all templates.
 *
 * @returns Map of template name to content
 */
export async function loadAllTemplates(): Promise<Map<TemplateName, string>> {
  const templates = new Map<TemplateName, string>();

  const entries = Object.entries(TEMPLATE_PATHS) as [TemplateName, string][];

  await Promise.all(
    entries.map(async ([name, path]) => {
      const content = await readFile(path, "utf-8");
      templates.set(name, content);
    })
  );

  return templates;
}

// ============================================================================
// Template Context Helpers
// ============================================================================

/**
 * Create a template context with common computed properties.
 */
export interface TemplateContext {
  /** Severity counts */
  critical: number;
  high: number;
  medium: number;
  low: number;
  informational: number;
  /** Computed properties */
  totalFindings: number;
  hasIssues: boolean;
  hasBlockingIssues: boolean;
  blockingCount: number;
  plural: boolean;
  blockingPlural: boolean;
  /** Styling */
  summaryColor: string;
  summaryEmoji: string;
}

/**
 * Build a template context from severity counts.
 */
export function buildTemplateContext(counts: {
  critical?: number;
  high?: number;
  medium?: number;
  low?: number;
  informational?: number;
}): TemplateContext {
  const critical = counts.critical ?? 0;
  const high = counts.high ?? 0;
  const medium = counts.medium ?? 0;
  const low = counts.low ?? 0;
  const informational = counts.informational ?? 0;

  const totalFindings = critical + high + medium + low + informational;
  const blockingCount = critical + high;

  // Determine summary color based on highest severity
  let summaryColor = "success";
  let summaryEmoji = ":white_check_mark:";

  if (critical > 0) {
    summaryColor = "critical";
    summaryEmoji = ":rotating_light:";
  } else if (high > 0) {
    summaryColor = "red";
    summaryEmoji = ":red_circle:";
  } else if (medium > 0) {
    summaryColor = "orange";
    summaryEmoji = ":orange_circle:";
  } else if (low > 0) {
    summaryColor = "yellow";
    summaryEmoji = ":yellow_circle:";
  } else if (informational > 0) {
    summaryColor = "blue";
    summaryEmoji = ":blue_circle:";
  }

  return {
    critical,
    high,
    medium,
    low,
    informational,
    totalFindings,
    hasIssues: totalFindings > 0,
    hasBlockingIssues: blockingCount > 0,
    blockingCount,
    plural: totalFindings !== 1,
    blockingPlural: blockingCount !== 1,
    summaryColor,
    summaryEmoji,
  };
}

/**
 * Get risk level and color based on findings.
 */
export function getRiskAssessment(counts: {
  critical?: number;
  high?: number;
  medium?: number;
  low?: number;
}): { riskLevel: string; riskColor: string; auditStatus: string; statusColor: string } {
  const critical = counts.critical ?? 0;
  const high = counts.high ?? 0;
  const medium = counts.medium ?? 0;

  if (critical > 0) {
    return {
      riskLevel: "Critical",
      riskColor: "critical",
      auditStatus: "Failed",
      statusColor: "critical",
    };
  }
  if (high > 0) {
    return {
      riskLevel: "High",
      riskColor: "red",
      auditStatus: "Action_Required",
      statusColor: "red",
    };
  }
  if (medium > 0) {
    return {
      riskLevel: "Medium",
      riskColor: "orange",
      auditStatus: "Review_Needed",
      statusColor: "orange",
    };
  }
  return {
    riskLevel: "Low",
    riskColor: "success",
    auditStatus: "Passed",
    statusColor: "success",
  };
}

// ============================================================================
// Simple Template Rendering
// ============================================================================

/**
 * Simple template variable replacement.
 *
 * Replaces {{variable}} patterns with values from the context object.
 * For complex templating (conditionals, loops), use Handlebars or similar.
 *
 * @param template - Template string with {{variable}} placeholders
 * @param context - Object with variable values
 * @returns Rendered string
 *
 * @example
 * ```ts
 * const result = renderSimple("Hello {{name}}!", { name: "World" });
 * // "Hello World!"
 * ```
 */
export function renderSimple(template: string, context: Record<string, unknown>): string {
  return template.replace(/\{\{(\w+(?:\.\w+)*)\}\}/g, (match, path: string) => {
    const value = getNestedValue(context, path);
    return value !== undefined ? String(value) : match;
  });
}

/**
 * Get a nested value from an object using dot notation.
 *
 * @param obj - Source object
 * @param path - Dot-separated path (e.g., "location.file")
 * @returns Value at path or undefined
 */
function getNestedValue(obj: Record<string, unknown>, path: string): unknown {
  const parts = path.split(".");
  let current: unknown = obj;

  for (const part of parts) {
    if (current === null || current === undefined) return undefined;
    if (typeof current !== "object") return undefined;
    current = (current as Record<string, unknown>)[part];
  }

  return current;
}

// ============================================================================
// ASCII Chart Generation
// ============================================================================

/**
 * Generate a simple ASCII bar chart for risk distribution.
 *
 * @example
 * ```
 * Critical  ████████ 2
 * High      ████████████████ 4
 * Medium    ████████████ 3
 * Low       ████ 1
 * Info      ████████ 2
 * ```
 */
export function generateRiskChart(counts: {
  critical?: number;
  high?: number;
  medium?: number;
  low?: number;
  informational?: number;
}): string {
  const critical = counts.critical ?? 0;
  const high = counts.high ?? 0;
  const medium = counts.medium ?? 0;
  const low = counts.low ?? 0;
  const informational = counts.informational ?? 0;

  const max = Math.max(critical, high, medium, low, informational, 1);
  const scale = 20 / max; // Max bar width of 20 characters

  const bar = (count: number): string => "█".repeat(Math.ceil(count * scale));

  const lines: string[] = [];

  if (critical > 0) lines.push(`Critical  ${bar(critical)} ${critical}`);
  if (high > 0) lines.push(`High      ${bar(high)} ${high}`);
  if (medium > 0) lines.push(`Medium    ${bar(medium)} ${medium}`);
  if (low > 0) lines.push(`Low       ${bar(low)} ${low}`);
  if (informational > 0) lines.push(`Info      ${bar(informational)} ${informational}`);

  return lines.length > 0 ? lines.join("\n") : "No findings";
}

/**
 * Format a timestamp in a consistent way.
 */
export function formatTimestamp(date: Date = new Date()): string {
  return date.toISOString().replace("T", " ").slice(0, 19) + " UTC";
}

/**
 * Escape special markdown characters.
 */
export function escapeMarkdown(text: string): string {
  return text.replace(/[\\`*_{}[\]()#+\-.!|]/g, "\\$&");
}

/**
 * Truncate text with ellipsis.
 */
export function truncate(text: string, maxLength: number): string {
  if (text.length <= maxLength) return text;
  return text.slice(0, maxLength - 3) + "...";
}
