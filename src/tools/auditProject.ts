/**
 * Audit Project Tool
 *
 * Analyzes an entire Solidity project - scans all contracts,
 * prioritizes by risk, and generates a consolidated report.
 */

import { z } from "zod";
import { basename } from "path";
import {
  scanProject,
  prioritizeAudit,
  buildDependencyGraph,
  type ContractFile,
  type ProjectStructure,
  type ProjectSummary,
  type DependencyGraph,
  type AuditPriority,
} from "../analyzers/projectScanner.js";
import { analyzeContract, type AnalysisResult } from "./analyzeContract.js";
import { executeCommand, formatDuration } from "../utils/executor.js";
import { getSeverityEmoji } from "../utils/severity.js";
import { Severity, type Finding } from "../types/index.js";
import { logger } from "../utils/logger.js";

// ============================================================================
// Types
// ============================================================================

export const AuditProjectInputSchema = z.object({
  projectRoot: z.string().describe("Root directory of the Solidity project"),
  maxContracts: z
    .number()
    .optional()
    .describe("Maximum number of contracts to analyze (default: all)"),
  priorityOnly: z
    .boolean()
    .optional()
    .default(false)
    .describe("Only analyze critical and high priority contracts"),
  parallel: z
    .boolean()
    .optional()
    .default(true)
    .describe("Run contract analysis in parallel (with concurrency limit of 3)"),
  skipTests: z.boolean().optional().default(false).describe("Skip running project tests"),
  skipGas: z.boolean().optional().default(false).describe("Skip gas optimization analysis"),
});

export type AuditProjectInput = z.infer<typeof AuditProjectInputSchema>;

export type OverallRisk = "critical" | "high" | "medium" | "low" | "minimal";

export interface ContractReport {
  contract: ContractFile;
  findingsCount: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  findings: Finding[];
  gasOptimizations: Finding[];
  analysisTime: number;
  error?: string;
}

export interface ProjectTestResults {
  passed: number;
  failed: number;
  skipped: number;
  coverage?: number;
  contractCoverage: Map<string, number>;
  duration: number;
}

export interface AuditProjectResult {
  projectSummary: ProjectSummary & {
    projectType: string;
    projectRoot: string;
  };
  contractReports: ContractReport[];
  projectFindings: Finding[];
  overallRisk: OverallRisk;
  auditPriority: Array<{
    contract: string;
    path: string;
    priority: AuditPriority;
    findingsCount: number;
    risk: OverallRisk;
  }>;
  testResults?: ProjectTestResults;
  executionTime: number;
  warnings: string[];
}

// ============================================================================
// Constants
// ============================================================================

/** Maximum concurrent contract analyses */
const MAX_CONCURRENCY = 3;

// ============================================================================
// Main Function
// ============================================================================

/**
 * Audit an entire Solidity project.
 */
export async function auditProject(input: AuditProjectInput): Promise<string> {
  const startTime = Date.now();
  const warnings: string[] = [];

  logger.info(`[audit-project] Starting project audit at ${input.projectRoot}`);

  // -------------------------------------------------------------------------
  // 1. Scan project structure
  // -------------------------------------------------------------------------
  logger.info("[audit-project] Scanning project structure...");
  let projectStructure: ProjectStructure;

  try {
    projectStructure = scanProject(input.projectRoot);
  } catch (error) {
    return formatError(
      "Failed to scan project",
      error instanceof Error ? error.message : String(error)
    );
  }

  if (projectStructure.contracts.length === 0) {
    return formatError(
      "No contracts found",
      `No Solidity contracts were found in ${input.projectRoot}. ` +
        "Ensure the project has a src/ or contracts/ directory."
    );
  }

  logger.info(
    `[audit-project] Found ${projectStructure.contracts.length} contracts, ` +
      `project type: ${projectStructure.projectType}`
  );

  // -------------------------------------------------------------------------
  // 2. Build dependency graph and prioritize
  // -------------------------------------------------------------------------
  const graph = buildDependencyGraph(projectStructure.contracts);
  let contractsToAudit = prioritizeAudit(projectStructure.contracts, graph);

  // Filter by priority if requested
  if (input.priorityOnly) {
    const before = contractsToAudit.length;
    contractsToAudit = contractsToAudit.filter(
      (c) => c.priority === "critical" || c.priority === "high"
    );
    logger.info(
      `[audit-project] Filtered to ${contractsToAudit.length}/${before} priority contracts`
    );
  }

  // Limit number of contracts if requested
  if (input.maxContracts && input.maxContracts < contractsToAudit.length) {
    contractsToAudit = contractsToAudit.slice(0, input.maxContracts);
    logger.info(`[audit-project] Limited to ${input.maxContracts} contracts`);
  }

  // -------------------------------------------------------------------------
  // 3. Analyze each contract
  // -------------------------------------------------------------------------
  logger.info(
    `[audit-project] Analyzing ${contractsToAudit.length} contracts ` +
      `(parallel: ${input.parallel}, concurrency: ${MAX_CONCURRENCY})...`
  );

  const contractReports: ContractReport[] = [];

  if (input.parallel) {
    // Run with concurrency pool
    const results = await runWithConcurrency(
      contractsToAudit,
      async (contract) => analyzeContractSafe(contract, input.projectRoot, input.skipGas),
      MAX_CONCURRENCY
    );
    contractReports.push(...results);
  } else {
    // Run sequentially
    for (const contract of contractsToAudit) {
      const report = await analyzeContractSafe(contract, input.projectRoot, input.skipGas);
      contractReports.push(report);
    }
  }

  // -------------------------------------------------------------------------
  // 4. Run project tests (once for entire project)
  // -------------------------------------------------------------------------
  let testResults: ProjectTestResults | undefined;

  if (!input.skipTests) {
    logger.info("[audit-project] Running project tests...");
    try {
      testResults = await runProjectTests(input.projectRoot);
      logger.info(
        `[audit-project] Tests: ${testResults.passed} passed, ${testResults.failed} failed`
      );
    } catch (error) {
      warnings.push(`Tests failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  // -------------------------------------------------------------------------
  // 5. Generate project-level findings
  // -------------------------------------------------------------------------
  logger.info("[audit-project] Generating project-level findings...");
  const projectFindings = generateProjectFindings(
    projectStructure,
    graph,
    contractReports,
    testResults
  );

  // Add findings from project scanner (circular dependencies, etc.)
  projectFindings.push(...projectStructure.findings);

  // -------------------------------------------------------------------------
  // 6. Calculate overall risk
  // -------------------------------------------------------------------------
  const overallRisk = calculateOverallRisk(contractReports, projectFindings);

  // -------------------------------------------------------------------------
  // 7. Build audit priority list
  // -------------------------------------------------------------------------
  const auditPriority = contractReports.map((report) => ({
    contract: report.contract.name,
    path: report.contract.relativePath,
    priority: report.contract.priority ?? ("medium" as AuditPriority),
    findingsCount: report.findingsCount,
    risk: calculateContractRisk(report),
  }));

  // Sort by risk level
  const riskOrder: Record<OverallRisk, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    minimal: 4,
  };
  auditPriority.sort((a, b) => riskOrder[a.risk] - riskOrder[b.risk]);

  // -------------------------------------------------------------------------
  // 8. Build result
  // -------------------------------------------------------------------------
  const executionTime = Date.now() - startTime;

  const result: AuditProjectResult = {
    projectSummary: {
      ...projectStructure.summary,
      projectType: projectStructure.projectType,
      projectRoot: input.projectRoot,
    },
    contractReports,
    projectFindings,
    overallRisk,
    auditPriority,
    testResults,
    executionTime,
    warnings,
  };

  logger.info(`[audit-project] Audit complete in ${formatDuration(executionTime)}`);

  // -------------------------------------------------------------------------
  // 9. Format output
  // -------------------------------------------------------------------------
  return formatProjectAuditReport(result);
}

// ============================================================================
// Concurrency Pool
// ============================================================================

/**
 * Run async tasks with limited concurrency.
 * Uses Promise.allSettled for safer handling of concurrent operations.
 */
async function runWithConcurrency<T, R>(
  items: T[],
  fn: (item: T) => Promise<R>,
  concurrency: number
): Promise<R[]> {
  const results: R[] = [];
  let currentIndex = 0;

  // Process items in batches
  async function processNext(): Promise<void> {
    while (currentIndex < items.length) {
      const index = currentIndex++;
      const item = items[index]!;
      const result = await fn(item);
      results[index] = result;
    }
  }

  // Start `concurrency` number of workers
  const workers: Promise<void>[] = [];
  for (let i = 0; i < Math.min(concurrency, items.length); i++) {
    workers.push(processNext());
  }

  // Wait for all workers to complete
  await Promise.allSettled(workers);

  // Filter out any undefined results (shouldn't happen but safe)
  return results.filter((r): r is R => r !== undefined);
}

// ============================================================================
// Contract Analysis
// ============================================================================

/**
 * Analyze a single contract safely (catches errors).
 */
async function analyzeContractSafe(
  contract: ContractFile,
  projectRoot: string,
  _skipGas?: boolean
): Promise<ContractReport> {
  const start = Date.now();

  try {
    logger.info(`[audit-project] Analyzing ${contract.name}...`);

    const resultStr = await analyzeContract({
      contractPath: contract.path,
      projectRoot,
      runTests: false, // Tests run once at project level
    });

    // Parse the JSON from the result (it's after the text summary)
    const jsonMatch = resultStr.match(/\{[\s\S]*"success"[\s\S]*\}$/);
    if (!jsonMatch) {
      throw new Error("Failed to parse analysis result");
    }

    const result = JSON.parse(jsonMatch[0]) as { success: boolean } & AnalysisResult;

    if (!result.success) {
      throw new Error("Analysis returned failure");
    }

    return {
      contract,
      findingsCount: result.summary.total,
      criticalCount: result.summary.critical,
      highCount: result.summary.high,
      mediumCount: result.summary.medium,
      lowCount: result.summary.low,
      findings: result.findings,
      gasOptimizations: result.gasOptimizations,
      analysisTime: Date.now() - start,
    };
  } catch (error) {
    logger.error(
      `[audit-project] Failed to analyze ${contract.name}: ${error instanceof Error ? error.message : String(error)}`
    );

    return {
      contract,
      findingsCount: 0,
      criticalCount: 0,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0,
      findings: [],
      gasOptimizations: [],
      analysisTime: Date.now() - start,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

// ============================================================================
// Project Tests
// ============================================================================

/**
 * Run tests for the entire project.
 */
async function runProjectTests(projectRoot: string): Promise<ProjectTestResults> {
  const start = Date.now();

  // Run forge test
  const testResult = await executeCommand("forge", ["test", "-v"], {
    cwd: projectRoot,
    timeout: 180_000,
  });

  // Parse test results
  let passed = 0;
  let failed = 0;
  let skipped = 0;

  const passMatch = testResult.stdout.match(/(\d+)\s+passed/);
  const failMatch = testResult.stdout.match(/(\d+)\s+failed/);
  const skipMatch = testResult.stdout.match(/(\d+)\s+skipped/);

  if (passMatch) passed = parseInt(passMatch[1]!, 10);
  if (failMatch) failed = parseInt(failMatch[1]!, 10);
  if (skipMatch) skipped = parseInt(skipMatch[1]!, 10);

  // Try to get coverage
  let coverage: number | undefined;
  const contractCoverage = new Map<string, number>();

  try {
    const coverageResult = await executeCommand("forge", ["coverage", "--report", "summary"], {
      cwd: projectRoot,
      timeout: 180_000,
    });

    // Parse overall coverage
    const totalMatch = coverageResult.stdout.match(/Total[^|]*\|\s*([\d.]+)%/);
    if (totalMatch) {
      coverage = parseFloat(totalMatch[1]!);
    }

    // Parse per-contract coverage
    const lines = coverageResult.stdout.split("\n");
    for (const line of lines) {
      const contractMatch = line.match(/^\|\s*([^|]+\.sol)\s*\|\s*([\d.]+)%/);
      if (contractMatch) {
        contractCoverage.set(contractMatch[1]!.trim(), parseFloat(contractMatch[2]!));
      }
    }
  } catch {
    // Coverage not available
  }

  return {
    passed,
    failed,
    skipped,
    coverage,
    contractCoverage,
    duration: Date.now() - start,
  };
}

// ============================================================================
// Project-Level Findings
// ============================================================================

/**
 * Generate findings that apply to the project level.
 */
function generateProjectFindings(
  structure: ProjectStructure,
  graph: DependencyGraph,
  reports: ContractReport[],
  testResults?: ProjectTestResults
): Finding[] {
  const findings: Finding[] = [];
  let findingIndex = 0;

  // 1. Contracts without tests (0% coverage)
  if (testResults?.coverage !== undefined) {
    const contractsWithZeroCoverage = structure.contracts.filter((c) => {
      const cov = testResults.contractCoverage.get(basename(c.relativePath));
      return cov === 0 || cov === undefined;
    });

    for (const contract of contractsWithZeroCoverage) {
      // Skip interfaces and libraries
      if (contract.type === "interface" || contract.type === "library") continue;

      findings.push({
        id: `project-no-tests-${findingIndex++}`,
        title: "Contract Has No Test Coverage",
        description: `${contract.name} has 0% test coverage. Untested code is a significant security risk.`,
        severity: contract.hasPayable ? Severity.HIGH : Severity.MEDIUM,
        confidence: "high",
        detector: "custom:project-scanner",
        location: {
          file: contract.relativePath,
        },
        recommendation: `Add comprehensive tests for ${contract.name}, especially for state-changing functions.`,
      });
    }
  }

  // 2. Failed tests indicate potential issues
  if (testResults && testResults.failed > 0) {
    findings.push({
      id: `project-failed-tests-${findingIndex++}`,
      title: "Project Has Failing Tests",
      description: `${testResults.failed} tests are failing. This may indicate bugs or security issues.`,
      severity: Severity.HIGH,
      confidence: "high",
      detector: "custom:project-scanner",
      location: {
        file: structure.projectRoot,
      },
      recommendation: "Fix all failing tests before deployment.",
    });
  }

  // 3. Low overall coverage
  if (testResults?.coverage !== undefined && testResults.coverage < 80) {
    const severity = testResults.coverage < 50 ? Severity.HIGH : Severity.MEDIUM;
    findings.push({
      id: `project-low-coverage-${findingIndex++}`,
      title: "Low Test Coverage",
      description: `Project has only ${testResults.coverage.toFixed(1)}% test coverage. Industry standard is 80%+.`,
      severity,
      confidence: "high",
      detector: "custom:project-scanner",
      location: {
        file: structure.projectRoot,
      },
      recommendation: "Increase test coverage to at least 80%, focusing on critical paths.",
    });
  }

  // 4. Version inconsistencies in imports
  const versionIssues = detectVersionInconsistencies(structure.contracts);
  for (const issue of versionIssues) {
    findings.push({
      id: `project-version-inconsistency-${findingIndex++}`,
      title: "Import Version Inconsistency",
      description: issue.description,
      severity: Severity.LOW,
      confidence: "medium",
      detector: "custom:project-scanner",
      location: {
        file: issue.file,
      },
      recommendation: "Ensure all contracts use consistent dependency versions.",
    });
  }

  // 5. Contracts with many dependents but security issues
  for (const critical of graph.criticalContracts.slice(0, 5)) {
    const report = reports.find((r) => r.contract.relativePath === critical.path);
    if (report && (report.criticalCount > 0 || report.highCount > 0)) {
      findings.push({
        id: `project-critical-dependency-${findingIndex++}`,
        title: "Critical Dependency Has Security Issues",
        description:
          `${basename(critical.path, ".sol")} is imported by ${critical.dependentCount} other contracts ` +
          `but has ${report.criticalCount} critical and ${report.highCount} high severity findings.`,
        severity: Severity.CRITICAL,
        confidence: "high",
        detector: "custom:project-scanner",
        location: {
          file: critical.path,
        },
        recommendation:
          "Prioritize fixing issues in this contract as they affect multiple dependents.",
      });
    }
  }

  // 6. Upgradeable contracts without proper safeguards
  const upgradeableContracts = structure.contracts.filter((c) => c.isUpgradeable);
  for (const contract of upgradeableContracts) {
    const report = reports.find((r) => r.contract.relativePath === contract.relativePath);
    // Check if there's an initializer-related finding
    const hasInitializerIssue = report?.findings.some(
      (f) =>
        f.title.toLowerCase().includes("initializ") ||
        f.description.toLowerCase().includes("initializ")
    );

    if (hasInitializerIssue) {
      findings.push({
        id: `project-upgradeable-issue-${findingIndex++}`,
        title: "Upgradeable Contract Has Initialization Issues",
        description: `${contract.name} is upgradeable but has potential initialization vulnerabilities.`,
        severity: Severity.HIGH,
        confidence: "medium",
        detector: "custom:project-scanner",
        location: {
          file: contract.relativePath,
        },
        recommendation:
          "Review initialization logic. Ensure initializer can only be called once " +
          "and all state is properly initialized.",
      });
    }
  }

  return findings;
}

/**
 * Detect version inconsistencies in imports.
 */
function detectVersionInconsistencies(
  contracts: ContractFile[]
): Array<{ file: string; description: string }> {
  const issues: Array<{ file: string; description: string }> = [];
  const importVersions = new Map<string, Set<string>>();

  // Track which version of each dependency is imported where
  for (const contract of contracts) {
    for (const imp of contract.imports) {
      // Extract package name and version hint
      const match = imp.match(/@([^/]+)\/([^/]+)/);
      if (match) {
        const pkg = `@${match[1]}/${match[2]}`;
        if (!importVersions.has(pkg)) {
          importVersions.set(pkg, new Set());
        }
        importVersions.get(pkg)!.add(imp);
      }
    }
  }

  // Check for inconsistencies
  for (const [pkg, versions] of importVersions) {
    if (versions.size > 1) {
      issues.push({
        file: contracts[0]?.relativePath ?? "unknown",
        description: `Multiple versions of ${pkg} are imported: ${Array.from(versions).join(", ")}`,
      });
    }
  }

  return issues;
}

// ============================================================================
// Risk Calculation
// ============================================================================

/**
 * Calculate overall project risk level.
 */
function calculateOverallRisk(reports: ContractReport[], projectFindings: Finding[]): OverallRisk {
  // Count all findings
  let totalCritical = 0;
  let totalHigh = 0;
  let totalMedium = 0;

  for (const report of reports) {
    totalCritical += report.criticalCount;
    totalHigh += report.highCount;
    totalMedium += report.mediumCount;
  }

  // Add project-level findings
  for (const finding of projectFindings) {
    switch (finding.severity) {
      case Severity.CRITICAL:
        totalCritical++;
        break;
      case Severity.HIGH:
        totalHigh++;
        break;
      case Severity.MEDIUM:
        totalMedium++;
        break;
      case Severity.LOW:
      case Severity.INFORMATIONAL:
        // Not counted for overall risk calculation
        break;
    }
  }

  // Determine risk level
  if (totalCritical > 0) {
    return "critical";
  } else if (totalHigh > 2 || (totalHigh > 0 && totalMedium > 5)) {
    return "high";
  } else if (totalHigh > 0 || totalMedium > 3) {
    return "medium";
  } else if (totalMedium > 0) {
    return "low";
  }

  return "minimal";
}

/**
 * Calculate risk level for a single contract.
 */
function calculateContractRisk(report: ContractReport): OverallRisk {
  if (report.criticalCount > 0) {
    return "critical";
  } else if (report.highCount > 0) {
    return "high";
  } else if (report.mediumCount > 0) {
    return "medium";
  } else if (report.lowCount > 0) {
    return "low";
  }
  return "minimal";
}

// ============================================================================
// Report Formatting
// ============================================================================

/**
 * Format the complete project audit report.
 */
function formatProjectAuditReport(result: AuditProjectResult): string {
  const lines: string[] = [];
  const projectName = basename(result.projectSummary.projectRoot);

  // -------------------------------------------------------------------------
  // Header
  // -------------------------------------------------------------------------
  lines.push(`# Project Audit: ${projectName}`);
  lines.push("");
  lines.push(`*Generated: ${new Date().toISOString()}*`);
  lines.push(`*Analysis time: ${formatDuration(result.executionTime)}*`);
  lines.push("");

  // -------------------------------------------------------------------------
  // Project Overview
  // -------------------------------------------------------------------------
  lines.push("## Project Overview");
  lines.push("");
  lines.push(`- **Type:** ${result.projectSummary.projectType}`);
  lines.push(`- **Root:** ${result.projectSummary.projectRoot}`);
  lines.push(
    `- **Contracts:** ${result.projectSummary.totalContracts} ` +
      `(${getCriticalCount(result)} critical, ${getHighCount(result)} high priority)`
  );
  lines.push(`- **Total SLOC:** ${result.projectSummary.totalSLOC.toLocaleString()}`);
  if (result.testResults?.coverage !== undefined) {
    lines.push(`- **Test Coverage:** ${result.testResults.coverage.toFixed(1)}%`);
  }
  lines.push(`- **Overall Risk:** ${getRiskBadge(result.overallRisk)}`);
  lines.push("");

  // -------------------------------------------------------------------------
  // Risk Matrix
  // -------------------------------------------------------------------------
  lines.push("## Risk Matrix");
  lines.push("");
  lines.push("| Contract | Priority | Critical | High | Medium | Low | Risk |");
  lines.push("|----------|:--------:|:--------:|:----:|:------:|:---:|:----:|");

  for (const entry of result.auditPriority) {
    const report = result.contractReports.find((r) => r.contract.relativePath === entry.path);
    if (!report) continue;

    lines.push(
      `| ${entry.contract} | ${getPriorityBadge(entry.priority)} | ` +
        `${report.criticalCount || "-"} | ${report.highCount || "-"} | ` +
        `${report.mediumCount || "-"} | ${report.lowCount || "-"} | ` +
        `${getRiskBadge(entry.risk)} |`
    );
  }
  lines.push("");

  // -------------------------------------------------------------------------
  // Top Findings
  // -------------------------------------------------------------------------
  const topFindings = collectTopFindings(result);
  if (topFindings.length > 0) {
    lines.push("## Top Findings (Critical + High)");
    lines.push("");

    for (const finding of topFindings.slice(0, 10)) {
      const emoji = getSeverityEmoji(finding.severity);
      lines.push(`### ${emoji} ${finding.title}`);
      lines.push("");
      lines.push(`**Severity:** ${finding.severity.toUpperCase()}`);
      lines.push(`**Location:** \`${finding.location.file}\``);
      lines.push("");
      lines.push(finding.description);
      lines.push("");
      lines.push(`**Recommendation:** ${finding.recommendation}`);
      lines.push("");
    }

    if (topFindings.length > 10) {
      lines.push(`*... and ${topFindings.length - 10} more critical/high findings*`);
      lines.push("");
    }
  }

  // -------------------------------------------------------------------------
  // Per-Contract Reports
  // -------------------------------------------------------------------------
  lines.push("## Per-Contract Reports");
  lines.push("");

  for (const report of result.contractReports) {
    lines.push(`### ${report.contract.name}`);
    lines.push("");
    lines.push(`**Path:** \`${report.contract.relativePath}\``);
    lines.push(`**Type:** ${report.contract.type}`);
    lines.push(`**SLOC:** ${report.contract.sloc}`);
    lines.push(`**Priority:** ${getPriorityBadge(report.contract.priority ?? "medium")}`);
    lines.push("");

    if (report.error) {
      lines.push(`> **Error:** ${report.error}`);
      lines.push("");
      continue;
    }

    // Risk indicators
    const risks: string[] = [];
    if (report.contract.hasPayable) risks.push("payable");
    if (report.contract.hasDelegatecall) risks.push("delegatecall");
    if (report.contract.hasSelfdestruct) risks.push("selfdestruct");
    if (report.contract.isUpgradeable) risks.push("upgradeable");
    if (report.contract.hasExternalCalls) risks.push("external-calls");

    if (risks.length > 0) {
      lines.push(`**Risk Indicators:** ${risks.join(", ")}`);
      lines.push("");
    }

    // Findings summary
    if (report.findingsCount > 0) {
      lines.push(
        `**Findings:** ${report.criticalCount} critical, ${report.highCount} high, ` +
          `${report.mediumCount} medium, ${report.lowCount} low`
      );
      lines.push("");

      // List top findings for this contract
      const contractTopFindings = report.findings
        .filter((f) => f.severity === Severity.CRITICAL || f.severity === Severity.HIGH)
        .slice(0, 3);

      if (contractTopFindings.length > 0) {
        lines.push("<details>");
        lines.push("<summary>View top findings</summary>");
        lines.push("");
        for (const finding of contractTopFindings) {
          lines.push(`- **${finding.title}** (${finding.severity.toUpperCase()})`);
          lines.push(`  ${truncate(finding.description, 150)}`);
        }
        lines.push("</details>");
        lines.push("");
      }
    } else {
      lines.push("**Findings:** No issues detected");
      lines.push("");
    }
  }

  // -------------------------------------------------------------------------
  // Project-Level Findings
  // -------------------------------------------------------------------------
  if (result.projectFindings.length > 0) {
    lines.push("## Project-Level Findings");
    lines.push("");

    for (const finding of result.projectFindings) {
      const emoji = getSeverityEmoji(finding.severity);
      lines.push(`### ${emoji} ${finding.title}`);
      lines.push("");
      lines.push(`**Severity:** ${finding.severity.toUpperCase()}`);
      if (finding.location.file !== result.projectSummary.projectRoot) {
        lines.push(`**Location:** \`${finding.location.file}\``);
      }
      lines.push("");
      lines.push(finding.description);
      lines.push("");
      lines.push(`**Recommendation:** ${finding.recommendation}`);
      lines.push("");
    }
  }

  // -------------------------------------------------------------------------
  // Test Results
  // -------------------------------------------------------------------------
  if (result.testResults) {
    lines.push("## Test Results");
    lines.push("");
    lines.push(`- **Passed:** ${result.testResults.passed}`);
    lines.push(`- **Failed:** ${result.testResults.failed}`);
    lines.push(`- **Skipped:** ${result.testResults.skipped}`);
    if (result.testResults.coverage !== undefined) {
      lines.push(`- **Coverage:** ${result.testResults.coverage.toFixed(1)}%`);
    }
    lines.push(`- **Duration:** ${formatDuration(result.testResults.duration)}`);
    lines.push("");
  }

  // -------------------------------------------------------------------------
  // Warnings
  // -------------------------------------------------------------------------
  if (result.warnings.length > 0) {
    lines.push("## Warnings");
    lines.push("");
    for (const warning of result.warnings) {
      lines.push(`- ${warning}`);
    }
    lines.push("");
  }

  // -------------------------------------------------------------------------
  // JSON Data
  // -------------------------------------------------------------------------
  lines.push("---");
  lines.push("");
  lines.push("<details>");
  lines.push("<summary>Full JSON Data</summary>");
  lines.push("");
  lines.push("```json");

  // Convert Maps to objects for JSON serialization
  const jsonResult = {
    ...result,
    testResults: result.testResults
      ? {
          ...result.testResults,
          contractCoverage: Object.fromEntries(result.testResults.contractCoverage),
        }
      : undefined,
  };

  lines.push(JSON.stringify(jsonResult, null, 2));
  lines.push("```");
  lines.push("");
  lines.push("</details>");

  return lines.join("\n");
}

// ============================================================================
// Formatting Helpers
// ============================================================================

function getCriticalCount(result: AuditProjectResult): number {
  return result.auditPriority.filter((p) => p.priority === "critical").length;
}

function getHighCount(result: AuditProjectResult): number {
  return result.auditPriority.filter((p) => p.priority === "high").length;
}

function getRiskBadge(risk: OverallRisk): string {
  const badges: Record<OverallRisk, string> = {
    critical: "🔴 CRITICAL",
    high: "🟠 HIGH",
    medium: "🟡 MEDIUM",
    low: "🟢 LOW",
    minimal: "✅ MINIMAL",
  };
  return badges[risk];
}

function getPriorityBadge(priority: AuditPriority): string {
  const badges: Record<AuditPriority, string> = {
    critical: "🔴",
    high: "🟠",
    medium: "🟡",
    low: "🟢",
  };
  return badges[priority];
}

// getSeverityEmoji is now imported from ../utils/severity.js

function collectTopFindings(result: AuditProjectResult): Finding[] {
  const allFindings: Finding[] = [];

  // Collect from contract reports
  for (const report of result.contractReports) {
    allFindings.push(...report.findings);
  }

  // Add project-level findings
  allFindings.push(...result.projectFindings);

  // Filter and sort
  return allFindings
    .filter((f) => f.severity === Severity.CRITICAL || f.severity === Severity.HIGH)
    .sort((a, b) => {
      const order = { [Severity.CRITICAL]: 0, [Severity.HIGH]: 1 };
      return (
        (order[a.severity as Severity.CRITICAL | Severity.HIGH] ?? 2) -
        (order[b.severity as Severity.CRITICAL | Severity.HIGH] ?? 2)
      );
    });
}

function truncate(str: string, maxLength: number): string {
  if (str.length <= maxLength) return str;
  return str.slice(0, maxLength - 3) + "...";
}

function formatError(error: string, details: string): string {
  return JSON.stringify(
    {
      success: false,
      error,
      details,
    },
    null,
    2
  );
}
