/**
 * Generate Report Tool
 *
 * Produces a formatted security audit report from findings and contract metadata.
 * Supports Markdown and JSON output formats.
 */

import { z } from "zod";
import { type Finding, Severity } from "../types/index.js";
import { logger } from "../utils/logger.js";

// ============================================================================
// Types
// ============================================================================

const FindingSchema = z.object({
  id: z.string(),
  title: z.string(),
  description: z.string(),
  severity: z.nativeEnum(Severity),
  location: z.object({
    file: z.string(),
    lines: z.tuple([z.number(), z.number()]).optional(),
    function: z.string().optional(),
  }),
  recommendation: z.string(),
  detector: z.enum(["slither", "aderyn", "manual"]),
  confidence: z.enum(["high", "medium", "low"]),
  references: z.array(z.string()).optional(),
  swcId: z.string().optional(),
});

const ContractInfoSchema = z.object({
  name: z.string(),
  path: z.string(),
  compiler: z.string(),
  functions: z.array(z.any()),
  stateVariables: z.array(z.any()),
  inherits: z.array(z.string()),
  interfaces: z.array(z.string()),
  hasConstructor: z.boolean(),
  usesProxy: z.boolean(),
  license: z.string().optional(),
  isAbstract: z.boolean().optional(),
  isLibrary: z.boolean().optional(),
});

export const GenerateReportInputSchema = z.object({
  findings: z.array(FindingSchema).describe("Array of Finding objects from the analysis"),
  contractInfo: ContractInfoSchema.describe("ContractInfo object with contract metadata"),
  format: z
    .enum(["markdown", "json"])
    .optional()
    .default("markdown")
    .describe("Output format for the report"),
  projectName: z.string().optional().describe("Name of the project being audited"),
  auditorName: z
    .string()
    .optional()
    .default("MCP Audit Server")
    .describe("Name of the auditor or tool"),
});

export type GenerateReportInput = z.input<typeof GenerateReportInputSchema>;

export interface AuditReportOutput {
  metadata: {
    projectName: string;
    contractName: string;
    contractPath: string;
    auditor: string;
    date: string;
    toolsUsed: string[];
  };
  summary: {
    totalFindings: number;
    bySeverity: Record<string, number>;
    byDetector: Record<string, number>;
    riskLevel: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL";
  };
  contractOverview: {
    compiler: string;
    license?: string;
    type: string;
    inheritance: string[];
    publicFunctions: number;
    externalFunctions: number;
    stateVariables: number;
    hasConstructor: boolean;
    usesProxy: boolean;
  };
  findings: Finding[];
  recommendations: string[];
}

// ============================================================================
// Main Function
// ============================================================================

/**
 * Generate a formatted audit report from findings and contract info.
 *
 * @param input - Input containing findings, contract info, and format options
 * @returns Formatted report in the requested format
 */
export async function generateReport(input: GenerateReportInput): Promise<string> {
  const parsed = GenerateReportInputSchema.parse(input);
  const { findings, contractInfo, format, projectName, auditorName } = parsed;

  logger.info(`[generateReport] Generating ${format} report for ${contractInfo.name}`);

  // Calculate summary statistics
  const bySeverity: Record<string, number> = {
    [Severity.CRITICAL]: 0,
    [Severity.HIGH]: 0,
    [Severity.MEDIUM]: 0,
    [Severity.LOW]: 0,
    [Severity.INFORMATIONAL]: 0,
  };

  const byDetector: Record<string, number> = {};
  const toolsUsed = new Set<string>();

  for (const finding of findings) {
    bySeverity[finding.severity] = (bySeverity[finding.severity] || 0) + 1;
    byDetector[finding.detector] = (byDetector[finding.detector] || 0) + 1;
    toolsUsed.add(finding.detector);
  }

  // Determine overall risk level
  let riskLevel: AuditReportOutput["summary"]["riskLevel"] = "INFORMATIONAL";
  if ((bySeverity[Severity.CRITICAL] || 0) > 0) {
    riskLevel = "CRITICAL";
  } else if ((bySeverity[Severity.HIGH] || 0) > 0) {
    riskLevel = "HIGH";
  } else if ((bySeverity[Severity.MEDIUM] || 0) > 0) {
    riskLevel = "MEDIUM";
  } else if ((bySeverity[Severity.LOW] || 0) > 0) {
    riskLevel = "LOW";
  }

  // Count function types
  let publicFunctions = 0;
  let externalFunctions = 0;

  if (contractInfo.functions) {
    for (const fn of contractInfo.functions) {
      if (fn.visibility === "public") publicFunctions++;
      if (fn.visibility === "external") externalFunctions++;
    }
  }

  // Determine contract type
  let contractType = "Contract";
  if (contractInfo.isLibrary) {
    contractType = "Library";
  } else if (contractInfo.isAbstract) {
    contractType = "Abstract Contract";
  }

  // Build report structure
  const report: AuditReportOutput = {
    metadata: {
      projectName: projectName || contractInfo.name,
      contractName: contractInfo.name,
      contractPath: contractInfo.path,
      auditor: auditorName || "MCP Audit Server",
      date: new Date().toISOString().split("T")[0] || new Date().toISOString(),
      toolsUsed: Array.from(toolsUsed),
    },
    summary: {
      totalFindings: findings.length,
      bySeverity,
      byDetector,
      riskLevel,
    },
    contractOverview: {
      compiler: contractInfo.compiler,
      license: contractInfo.license,
      type: contractType,
      inheritance: contractInfo.inherits || [],
      publicFunctions,
      externalFunctions,
      stateVariables: contractInfo.stateVariables?.length || 0,
      hasConstructor: contractInfo.hasConstructor,
      usesProxy: contractInfo.usesProxy,
    },
    findings: findings as Finding[],
    recommendations: generateRecommendations(findings as Finding[], bySeverity, riskLevel),
  };

  // Generate output
  if (format === "json") {
    return JSON.stringify(report, null, 2);
  }

  return generateMarkdownReport(report);
}

// ============================================================================
// Helper Functions
// ============================================================================

function generateRecommendations(
  findings: Finding[],
  bySeverity: Record<string, number>,
  riskLevel: string
): string[] {
  const recommendations: string[] = [];

  // Critical/High severity recommendations
  if ((bySeverity[Severity.CRITICAL] || 0) > 0) {
    recommendations.push(
      "🔴 IMMEDIATE ACTION REQUIRED: Fix all critical issues before deployment. " +
        "These vulnerabilities can lead to total loss of funds or contract takeover."
    );
  }

  if ((bySeverity[Severity.HIGH] || 0) > 0) {
    recommendations.push(
      "🟠 HIGH PRIORITY: Address high-severity issues as soon as possible. " +
        "These can cause significant financial loss or unintended behavior."
    );
  }

  // Detector-specific recommendations
  const detectors = findings.map((f) => f.detector);
  const uniqueDetectors = new Set(detectors);

  if (uniqueDetectors.has("slither")) {
    recommendations.push(
      "Slither detected issues in this contract. Review each finding carefully and " +
        "consider the context to determine if it's a true positive."
    );
  }

  if (uniqueDetectors.has("aderyn")) {
    recommendations.push(
      "Aderyn found potential issues. Cross-reference with Slither findings to " +
        "identify overlapping concerns."
    );
  }

  // General recommendations based on risk level
  if (riskLevel === "CRITICAL" || riskLevel === "HIGH") {
    recommendations.push(
      "Request a formal audit from a professional security firm before mainnet deployment."
    );
    recommendations.push(
      "Consider implementing a bug bounty program to incentivize responsible disclosure."
    );
  }

  if (findings.length > 0) {
    recommendations.push(
      "Add comprehensive test coverage for all identified issues to prevent regressions."
    );
  }

  // Default recommendations
  if (recommendations.length === 0) {
    recommendations.push(
      "✅ No critical or high-severity issues found. Continue with standard security practices."
    );
    recommendations.push("Consider periodic security reviews as the codebase evolves.");
  }

  return recommendations;
}

// ============================================================================
// Markdown Report Generation
// ============================================================================

function generateMarkdownReport(report: AuditReportOutput): string {
  const lines: string[] = [];

  // Title
  lines.push(`# Security Audit Report: ${report.metadata.projectName}`);
  lines.push("");
  lines.push(`**Contract:** ${report.metadata.contractName}`);
  lines.push(`**Auditor:** ${report.metadata.auditor}`);
  lines.push(`**Date:** ${report.metadata.date}`);
  lines.push(`**Tools Used:** ${report.metadata.toolsUsed.join(", ") || "N/A"}`);
  lines.push("");

  // Table of Contents
  lines.push("## Table of Contents");
  lines.push("");
  lines.push("1. [Executive Summary](#executive-summary)");
  lines.push("2. [Contract Overview](#contract-overview)");
  lines.push("3. [Findings](#findings)");
  lines.push("4. [Recommendations](#recommendations)");
  lines.push("");

  // Executive Summary
  lines.push("## Executive Summary");
  lines.push("");

  const riskEmoji: Record<string, string> = {
    CRITICAL: "🔴",
    HIGH: "🟠",
    MEDIUM: "🟡",
    LOW: "🔵",
    INFORMATIONAL: "⚪",
  };

  const severityEmoji: Record<string, string> = {
    [Severity.CRITICAL]: "🔴",
    [Severity.HIGH]: "🟠",
    [Severity.MEDIUM]: "🟡",
    [Severity.LOW]: "🔵",
    [Severity.INFORMATIONAL]: "⚪",
  };

  const riskColor: Record<string, string> = {
    CRITICAL: "CRITICAL - DO NOT DEPLOY",
    HIGH: "HIGH - Major Issues Found",
    MEDIUM: "MEDIUM - Issues Found",
    LOW: "LOW - Minor Issues",
    INFORMATIONAL: "INFORMATIONAL - Clean",
  };

  lines.push(
    `**Overall Risk Level:** ${riskEmoji[report.summary.riskLevel] || ""} ${riskColor[report.summary.riskLevel] || report.summary.riskLevel}`
  );
  lines.push("");
  lines.push(`**Total Findings:** ${report.summary.totalFindings}`);
  lines.push("");

  // Findings breakdown table
  lines.push("| Severity | Count |");
  lines.push("|----------|-------|");
  for (const [severity, count] of Object.entries(report.summary.bySeverity)) {
    if (count > 0) {
      const emoji = severityEmoji[severity] || "";
      lines.push(`| ${emoji} ${severity} | ${count} |`);
    }
  }
  lines.push("");

  // Detector breakdown
  if (Object.keys(report.summary.byDetector).length > 0) {
    lines.push("### Findings by Detector");
    lines.push("");
    lines.push("| Detector | Count |");
    lines.push("|----------|-------|");
    for (const [detector, count] of Object.entries(report.summary.byDetector)) {
      lines.push(`| ${detector} | ${count} |`);
    }
    lines.push("");
  }

  // Contract Overview
  lines.push("## Contract Overview");
  lines.push("");
  lines.push(`- **Type:** ${report.contractOverview.type}`);
  lines.push(`- **Solidity Version:** ${report.contractOverview.compiler}`);
  if (report.contractOverview.license) {
    lines.push(`- **License:** ${report.contractOverview.license}`);
  }
  if (report.contractOverview.inheritance.length > 0) {
    lines.push(`- **Inherits:** ${report.contractOverview.inheritance.join(", ")}`);
  }
  lines.push(`- **Uses Proxy:** ${report.contractOverview.usesProxy ? "Yes" : "No"}`);
  lines.push(`- **Has Constructor:** ${report.contractOverview.hasConstructor ? "Yes" : "No"}`);
  lines.push("");
  lines.push("### Attack Surface");
  lines.push("");
  lines.push(`- Public Functions: ${report.contractOverview.publicFunctions}`);
  lines.push(`- External Functions: ${report.contractOverview.externalFunctions}`);
  lines.push(`- State Variables: ${report.contractOverview.stateVariables}`);
  lines.push("");

  // Findings
  lines.push("## Findings");
  lines.push("");

  if (report.findings.length === 0) {
    lines.push("✅ **No security issues were identified.**");
    lines.push("");
  } else {
    for (const finding of report.findings) {
      const emoji = severityEmoji[finding.severity] || "";

      lines.push(`### ${emoji} [${finding.severity.toUpperCase()}] ${finding.title}`);
      lines.push("");
      lines.push(`**ID:** ${finding.id}`);
      lines.push(`**Detector:** ${finding.detector}`);
      lines.push(`**Confidence:** ${finding.confidence}`);
      if (finding.swcId) {
        lines.push(`**SWC ID:** ${finding.swcId}`);
      }
      lines.push("");

      // Location
      lines.push("**Location:**");
      lines.push(`- File: \`${finding.location.file}\``);
      if (finding.location.lines) {
        lines.push(`- Lines: ${finding.location.lines[0]}-${finding.location.lines[1]}`);
      }
      if (finding.location.function) {
        lines.push(`- Function: ${finding.location.function}`);
      }
      lines.push("");

      // Description
      lines.push("**Description:**");
      lines.push("");
      lines.push(finding.description);
      lines.push("");

      // Recommendation
      if (finding.recommendation) {
        lines.push("**Recommendation:**");
        lines.push("");
        lines.push(finding.recommendation);
        lines.push("");
      }

      // References
      if (finding.references && finding.references.length > 0) {
        lines.push("**References:**");
        for (const ref of finding.references) {
          lines.push(`- ${ref}`);
        }
        lines.push("");
      }

      lines.push("---");
      lines.push("");
    }
  }

  // Recommendations
  lines.push("## Recommendations");
  lines.push("");

  for (const rec of report.recommendations) {
    lines.push(`- ${rec}`);
  }
  lines.push("");

  // Footer
  lines.push("---");
  lines.push("");
  lines.push(
    "*This report was generated by MCP Audit Server. Always verify findings manually " +
      "and consider engaging professional auditors for critical deployments.*"
  );

  return lines.join("\n");
}
