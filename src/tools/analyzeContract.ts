/**
 * Analyze Contract Tool
 *
 * Main entry point for security analysis of Solidity contracts.
 * Uses the AnalyzerOrchestrator to coordinate multiple analyzers.
 */

import { access, readFile } from "node:fs/promises";
import { z } from "zod";
import { getProjectRoot, executeCommand, formatDuration } from "../utils/executor.js";
import { logger } from "../utils/logger.js";
import {
  countBySeverity,
  getSeverityEmoji,
  calculateTotalGasSavings,
  formatGasSavings,
} from "../utils/severity.js";
import { createOrchestrator } from "../analyzers/AnalyzerOrchestrator.js";
import { getAnalyzerRegistry } from "../analyzers/AnalyzerRegistry.js";
import type { AnalyzerId, AnalyzerResult } from "../analyzers/types.js";
import { parseContractInfo, detectPatterns } from "../analyzers/adapters/SlangAdapter.js";
import {
  loadCustomDetectors,
  runCustomDetectors,
  type CustomDetector,
} from "../detectors/customDetectorEngine.js";
import { type Finding, type ContractInfo } from "../types/index.js";

// ============================================================================
// Types
// ============================================================================

export const AnalyzeContractInputSchema = z.object({
  contractPath: z.string().describe("Path to the Solidity contract file"),
  projectRoot: z
    .string()
    .optional()
    .describe("Root directory of the project (auto-detected if not provided)"),
  runTests: z
    .boolean()
    .optional()
    .default(false)
    .describe("Whether to run forge tests as part of the analysis"),
  analyzers: z
    .array(z.enum(["slither", "aderyn", "slang", "gas", "echidna", "halmos"]))
    .optional()
    .describe("Specific analyzers to run (defaults to all available)"),
});

export type AnalyzeContractInput = z.infer<typeof AnalyzeContractInputSchema>;

export interface TestResults {
  passed: number;
  failed: number;
  skipped: number;
  coverage?: number;
  gasReport?: string;
  duration: number;
}

export interface AnalysisSummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  informational: number;
}

export interface GasOptimizationSummary {
  total: number;
  high: number;
  medium: number;
  low: number;
  informational: number;
  estimatedSavings: string;
}

export interface CustomChecksSummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  informational: number;
  detectorsLoaded: number;
}

export interface AnalysisResult {
  contractInfo: ContractInfo;
  findings: Finding[];
  gasOptimizations: Finding[];
  gasSummary: GasOptimizationSummary;
  customFindings: Finding[];
  customSummary: CustomChecksSummary;
  patterns: Array<{
    pattern: string;
    line: number;
    risk: string;
    description: string;
  }>;
  summary: AnalysisSummary;
  testResults?: TestResults;
  toolsUsed: string[];
  warnings: string[];
  rawOutput: {
    slither?: { findingsCount: number; executionTime: number };
    aderyn?: { findingsCount: number; executionTime: number };
    gas?: { findingsCount: number; executionTime: number };
    slang?: {
      findingsCount: number;
      executionTime: number;
      detectorCount: number;
      parseErrors: number;
    };
    custom?: { findingsCount: number; executionTime: number; detectorsLoaded: number };
    tests?: { output: string };
  };
  executionTime: number;
}

// Pipeline timeout: 3 minutes
const PIPELINE_TIMEOUT = 180_000;

// ============================================================================
// Main Function
// ============================================================================

/**
 * Run a complete security analysis on a Solidity contract.
 *
 * @param input - Analysis parameters
 * @returns Analysis result with findings, metadata, and summary
 */
export async function analyzeContract(input: AnalyzeContractInput): Promise<string> {
  const startTime = Date.now();
  const warnings: string[] = [];
  const toolsUsed: string[] = [];

  logger.info(`[analyze] Starting analysis of ${input.contractPath}`);

  // -------------------------------------------------------------------------
  // 1. Validate contract path
  // -------------------------------------------------------------------------
  try {
    await access(input.contractPath);
  } catch {
    return formatError(
      `Contract file not found: ${input.contractPath}`,
      "Ensure the path is correct and the file exists."
    );
  }

  if (!input.contractPath.endsWith(".sol")) {
    return formatError(
      `Invalid file type: ${input.contractPath}`,
      "Only Solidity (.sol) files are supported."
    );
  }

  // -------------------------------------------------------------------------
  // 2. Detect project root
  // -------------------------------------------------------------------------
  let projectRoot = input.projectRoot;

  if (!projectRoot) {
    logger.info("[analyze] Auto-detecting project root...");
    projectRoot = await getProjectRoot(input.contractPath);
    logger.info(`[analyze] Detected project root: ${projectRoot}`);
  }

  // -------------------------------------------------------------------------
  // 3. Parse contract info (always needed for output)
  // -------------------------------------------------------------------------
  let contractInfo: ContractInfo;
  try {
    contractInfo = await parseContractInfo(input.contractPath);
  } catch (err) {
    return formatError(
      "Failed to parse contract",
      `Could not extract contract metadata: ${err instanceof Error ? err.message : String(err)}`
    );
  }

  // -------------------------------------------------------------------------
  // 4. Load custom detectors (if config exists)
  // -------------------------------------------------------------------------
  let customDetectors: CustomDetector[] = [];
  try {
    customDetectors = await loadCustomDetectors(projectRoot);
  } catch (err) {
    warnings.push(
      `Custom detectors failed to load: ${err instanceof Error ? err.message : String(err)}`
    );
  }

  // -------------------------------------------------------------------------
  // 5. Run analyzers using the orchestrator
  // -------------------------------------------------------------------------
  logger.info("[analyze] Running analysis pipeline...");

  const orchestrator = createOrchestrator({
    maxConcurrency: 3,
    pipelineTimeout: PIPELINE_TIMEOUT,
    continueOnError: true,
  });

  // Track progress for toolsUsed
  orchestrator.onProgress((progress) => {
    if (progress.status === "completed" && progress.result) {
      const count = progress.result.findings.length;
      toolsUsed.push(`${progress.analyzerId} (${count} findings)`);
    } else if (progress.status === "failed") {
      warnings.push(`${progress.analyzerId} failed: ${progress.error}`);
    }
  });

  // Run specified analyzers or all available
  let orchestratorResult;
  if (input.analyzers && input.analyzers.length > 0) {
    orchestratorResult = await orchestrator.analyzeWith(input.analyzers as AnalyzerId[], {
      contractPath: input.contractPath,
      projectRoot,
    });
  } else {
    orchestratorResult = await orchestrator.analyze({
      contractPath: input.contractPath,
      projectRoot,
    });
  }

  // Check if any external analyzers ran
  const registry = getAnalyzerRegistry();
  const externalAnalyzers = registry.getExternal();
  const ranExternal = orchestratorResult.analyzersUsed.some((id) =>
    externalAnalyzers.some((a) => a.id === id)
  );

  if (!ranExternal && orchestratorResult.analyzersUsed.length === 0) {
    return formatError(
      "No security analysis tools are available",
      "Install at least one of the following:\n" +
        "  • Slither: pip install slither-analyzer\n" +
        "  • Aderyn: cargo install aderyn"
    );
  }

  // Collect warnings from orchestrator
  warnings.push(...orchestratorResult.warnings);

  // -------------------------------------------------------------------------
  // 6. Extract findings by category
  // -------------------------------------------------------------------------
  const securityFindings: Finding[] = [];
  const gasOptimizations: Finding[] = [];

  // Separate gas findings from security findings
  for (const finding of orchestratorResult.findings) {
    if (finding.detector === "gas-optimizer" || finding.detector.startsWith("gas")) {
      gasOptimizations.push(finding);
    } else {
      securityFindings.push(finding);
    }
  }

  // -------------------------------------------------------------------------
  // 7. Run custom detectors (separate from orchestrator)
  // -------------------------------------------------------------------------
  let customFindings: Finding[] = [];
  let customExecutionTime = 0;

  if (customDetectors.length > 0) {
    const customStart = Date.now();
    try {
      const source = await readFile(input.contractPath, "utf-8");
      customFindings = runCustomDetectors(source, input.contractPath, customDetectors, projectRoot);
      customExecutionTime = Date.now() - customStart;

      if (customFindings.length > 0) {
        toolsUsed.push(
          `custom-detectors (${customFindings.length} findings from ${customDetectors.length} detectors)`
        );
      } else {
        toolsUsed.push(`custom-detectors (0 findings from ${customDetectors.length} detectors)`);
      }
    } catch (err) {
      warnings.push(`Custom detectors failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  // -------------------------------------------------------------------------
  // 8. Run tests if requested
  // -------------------------------------------------------------------------
  let testResults: TestResults | undefined;

  if (input.runTests) {
    try {
      testResults = await runForgeTests(projectRoot);
      toolsUsed.push("forge");
    } catch (err) {
      warnings.push(`Forge tests failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  // -------------------------------------------------------------------------
  // 9. Detect patterns
  // -------------------------------------------------------------------------
  const source = await readFile(input.contractPath, "utf-8");
  const patterns = detectPatterns(source);

  // -------------------------------------------------------------------------
  // 10. Generate summaries
  // -------------------------------------------------------------------------
  const summary = countBySeverity(securityFindings);
  const gasSummary = calculateGasSummary(gasOptimizations);
  const customSummary = {
    ...countBySeverity(customFindings),
    detectorsLoaded: customDetectors.length,
  };

  // -------------------------------------------------------------------------
  // 11. Build raw output from analyzer results
  // -------------------------------------------------------------------------
  const rawOutput = buildRawOutput(
    orchestratorResult.analyzerResults,
    customFindings,
    customExecutionTime,
    customDetectors.length
  );

  // -------------------------------------------------------------------------
  // 12. Build final result
  // -------------------------------------------------------------------------
  const executionTime = Date.now() - startTime;

  const result: AnalysisResult = {
    contractInfo,
    findings: securityFindings,
    gasOptimizations,
    gasSummary,
    customFindings,
    customSummary,
    patterns: patterns.map((p) => ({
      pattern: p.pattern,
      line: p.line,
      risk: p.risk,
      description: p.description,
    })),
    summary,
    testResults,
    toolsUsed,
    warnings,
    rawOutput,
    executionTime,
  };

  logger.info(`[analyze] Analysis complete in ${formatDuration(executionTime)}`);

  // -------------------------------------------------------------------------
  // 13. Format output
  // -------------------------------------------------------------------------
  return formatOutput(result);
}

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Build raw output structure from analyzer results
 */
function buildRawOutput(
  analyzerResults: Map<AnalyzerId, AnalyzerResult>,
  customFindings: Finding[],
  customExecutionTime: number,
  customDetectorsLoaded: number
): AnalysisResult["rawOutput"] {
  const rawOutput: AnalysisResult["rawOutput"] = {};

  const slitherResult = analyzerResults.get("slither");
  if (slitherResult) {
    rawOutput.slither = {
      findingsCount: slitherResult.findings.length,
      executionTime: slitherResult.executionTime,
    };
  }

  const aderynResult = analyzerResults.get("aderyn");
  if (aderynResult) {
    rawOutput.aderyn = {
      findingsCount: aderynResult.findings.length,
      executionTime: aderynResult.executionTime,
    };
  }

  const gasResult = analyzerResults.get("gas");
  if (gasResult) {
    rawOutput.gas = {
      findingsCount: gasResult.findings.length,
      executionTime: gasResult.executionTime,
    };
  }

  const slangResult = analyzerResults.get("slang");
  if (slangResult) {
    rawOutput.slang = {
      findingsCount: slangResult.findings.length,
      executionTime: slangResult.executionTime,
      detectorCount: slangResult.metadata.detectorCount ?? 0,
      parseErrors: (slangResult.metadata.parseErrors as string[] | undefined)?.length ?? 0,
    };
  }

  if (customDetectorsLoaded > 0) {
    rawOutput.custom = {
      findingsCount: customFindings.length,
      executionTime: customExecutionTime,
      detectorsLoaded: customDetectorsLoaded,
    };
  }

  return rawOutput;
}

/**
 * Run Forge tests and coverage
 */
async function runForgeTests(projectRoot: string): Promise<TestResults> {
  const start = Date.now();

  const testResult = await executeCommand("forge", ["test", "--gas-report", "-v"], {
    cwd: projectRoot,
    timeout: 120_000,
  });

  let passed = 0;
  let failed = 0;
  let skipped = 0;

  const passMatch = testResult.stdout.match(/(\d+)\s+passed/);
  const failMatch = testResult.stdout.match(/(\d+)\s+failed/);
  const skipMatch = testResult.stdout.match(/(\d+)\s+skipped/);

  if (passMatch) passed = parseInt(passMatch[1]!, 10);
  if (failMatch) failed = parseInt(failMatch[1]!, 10);
  if (skipMatch) skipped = parseInt(skipMatch[1]!, 10);

  let coverage: number | undefined;
  try {
    const coverageResult = await executeCommand("forge", ["coverage", "--report", "summary"], {
      cwd: projectRoot,
      timeout: 120_000,
    });

    const coverageMatch = coverageResult.stdout.match(/Total[^|]*\|\s*([\d.]+)%/);
    if (coverageMatch) {
      coverage = parseFloat(coverageMatch[1]!);
    }
  } catch {
    // Coverage not available
  }

  return {
    passed,
    failed,
    skipped,
    coverage,
    gasReport: extractGasReport(testResult.stdout),
    duration: Date.now() - start,
  };
}

/**
 * Extract gas report from forge test output
 */
function extractGasReport(output: string): string | undefined {
  const gasSection = output.match(/╭[─┬]+╮[\s\S]*?Gas Report[\s\S]*?╰[─┴]+╯/);
  return gasSection?.[0];
}

/**
 * Calculate gas optimization summary
 */
function calculateGasSummary(findings: Finding[]): GasOptimizationSummary {
  const counts = countBySeverity(findings);
  const totalGas = calculateTotalGasSavings(findings);

  return {
    total: counts.total,
    high: counts.high,
    medium: counts.medium,
    low: counts.low,
    informational: counts.informational,
    estimatedSavings: formatGasSavings(totalGas),
  };
}

/**
 * Format error response
 */
function formatError(error: string, suggestion: string): string {
  return JSON.stringify(
    {
      success: false,
      error,
      suggestion,
    },
    null,
    2
  );
}

/**
 * Format the analysis output for MCP response
 */
function formatOutput(result: AnalysisResult): string {
  const {
    summary,
    findings,
    gasOptimizations,
    gasSummary,
    customFindings,
    customSummary,
    contractInfo,
    patterns,
    testResults,
    warnings,
    toolsUsed,
    executionTime,
  } = result;

  const lines: string[] = [
    "═══════════════════════════════════════════════════════════════════════════════",
    `  SECURITY ANALYSIS REPORT: ${contractInfo.name}`,
    "═══════════════════════════════════════════════════════════════════════════════",
    "",
    `📄 Contract: ${contractInfo.name}`,
    `📁 Path: ${contractInfo.path}`,
    `🔧 Compiler: ${contractInfo.compiler}`,
    `⏱️  Analysis time: ${formatDuration(executionTime)}`,
    `🔧 Tools: ${toolsUsed.join(", ") || "none"}`,
    "",
    "───────────────────────────────────────────────────────────────────────────────",
    "  SUMMARY",
    "───────────────────────────────────────────────────────────────────────────────",
    "",
    `  Total findings: ${summary.total}`,
    `  🔴 Critical: ${summary.critical}`,
    `  🟠 High: ${summary.high}`,
    `  🟡 Medium: ${summary.medium}`,
    `  🟢 Low: ${summary.low}`,
    `  🔵 Informational: ${summary.informational}`,
    "",
  ];

  // Risk assessment
  if (summary.critical > 0) {
    lines.push("  ⚠️  CRITICAL ISSUES FOUND - DO NOT DEPLOY");
  } else if (summary.high > 0) {
    lines.push("  ⚠️  HIGH SEVERITY ISSUES - Review before deployment");
  } else if (summary.medium > 0) {
    lines.push("  ⚡ MEDIUM SEVERITY ISSUES - Consider addressing");
  } else if (summary.low > 0 || summary.informational > 0) {
    lines.push("  ✅ No critical issues - Minor improvements suggested");
  } else {
    lines.push("  ✅ No issues detected by automated analysis");
  }

  // Warnings
  if (warnings.length > 0) {
    lines.push("");
    lines.push("───────────────────────────────────────────────────────────────────────────────");
    lines.push("  WARNINGS");
    lines.push("───────────────────────────────────────────────────────────────────────────────");
    for (const warning of warnings) {
      lines.push(`  ⚠️  ${warning}`);
    }
  }

  // Contract info summary
  lines.push("");
  lines.push("───────────────────────────────────────────────────────────────────────────────");
  lines.push("  CONTRACT INFO");
  lines.push("───────────────────────────────────────────────────────────────────────────────");
  lines.push(`  Functions: ${contractInfo.functions.length}`);
  lines.push(`  State Variables: ${contractInfo.stateVariables.length}`);
  lines.push(`  Inherits: ${contractInfo.inherits.join(", ") || "none"}`);
  lines.push(`  Interfaces: ${contractInfo.interfaces.join(", ") || "none"}`);
  lines.push(`  Has Constructor: ${contractInfo.hasConstructor ? "yes" : "no"}`);
  lines.push(`  Uses Proxy: ${contractInfo.usesProxy ? "yes" : "no"}`);

  // Risky patterns
  const highRiskPatterns = patterns.filter((p) => p.risk === "high");
  if (highRiskPatterns.length > 0) {
    lines.push("");
    lines.push("───────────────────────────────────────────────────────────────────────────────");
    lines.push("  HIGH-RISK PATTERNS DETECTED");
    lines.push("───────────────────────────────────────────────────────────────────────────────");
    for (const p of highRiskPatterns) {
      lines.push(`  • Line ${p.line}: ${p.pattern} - ${p.description}`);
    }
  }

  // Test results
  if (testResults) {
    lines.push("");
    lines.push("───────────────────────────────────────────────────────────────────────────────");
    lines.push("  TEST RESULTS");
    lines.push("───────────────────────────────────────────────────────────────────────────────");
    lines.push(`  Passed: ${testResults.passed}`);
    lines.push(`  Failed: ${testResults.failed}`);
    lines.push(`  Skipped: ${testResults.skipped}`);
    if (testResults.coverage !== undefined) {
      lines.push(`  Coverage: ${testResults.coverage.toFixed(1)}%`);
    }
  }

  // All findings
  if (findings.length > 0) {
    lines.push("");
    lines.push("───────────────────────────────────────────────────────────────────────────────");
    lines.push("  FINDINGS");
    lines.push("───────────────────────────────────────────────────────────────────────────────");

    for (const finding of findings) {
      const emoji = getSeverityEmoji(finding.severity);
      const location = finding.location.lines
        ? `${finding.location.file}:${finding.location.lines[0]}`
        : finding.location.file;
      lines.push("");
      lines.push(`  ${emoji} [${finding.severity.toUpperCase()}] ${finding.title}`);
      lines.push(`     Location: ${location}`);
      const cleanDesc = finding.description.replace(/\n/g, " ").replace(/\s+/g, " ").trim();
      lines.push(`     ${cleanDesc}`);
      if (
        finding.recommendation &&
        finding.recommendation !== "Review the code and apply appropriate fixes"
      ) {
        lines.push(`     Recommendation: ${finding.recommendation}`);
      }
    }
  }

  // Gas Optimizations
  if (gasOptimizations.length > 0) {
    lines.push("");
    lines.push("───────────────────────────────────────────────────────────────────────────────");
    lines.push("  GAS OPTIMIZATIONS");
    lines.push("───────────────────────────────────────────────────────────────────────────────");
    lines.push("");
    lines.push(
      `  Total: ${gasSummary.total} | High: ${gasSummary.high} | Medium: ${gasSummary.medium} | Low: ${gasSummary.low}`
    );
    lines.push(`  Estimated savings: ~${gasSummary.estimatedSavings} gas`);

    for (const finding of gasOptimizations) {
      const emoji = getSeverityEmoji(finding.severity);
      const location = finding.location.lines
        ? `${finding.location.file}:${finding.location.lines[0]}`
        : finding.location.file;
      lines.push("");
      lines.push(`  ${emoji} [${finding.severity.toUpperCase()}] ${finding.title}`);
      lines.push(`     Location: ${location}`);
      lines.push(`     ${finding.recommendation}`);
    }
  }

  // Custom Checks
  if (customFindings.length > 0) {
    lines.push("");
    lines.push("───────────────────────────────────────────────────────────────────────────────");
    lines.push("  CUSTOM CHECKS");
    lines.push("───────────────────────────────────────────────────────────────────────────────");
    lines.push("");
    lines.push(
      `  Detectors: ${customSummary.detectorsLoaded} | Total: ${customSummary.total} | ` +
        `Critical: ${customSummary.critical} | High: ${customSummary.high} | ` +
        `Medium: ${customSummary.medium} | Low: ${customSummary.low}`
    );

    for (const finding of customFindings) {
      const emoji = getSeverityEmoji(finding.severity);
      const location = finding.location.lines
        ? `${finding.location.file}:${finding.location.lines[0]}`
        : finding.location.file;
      lines.push("");
      lines.push(`  ${emoji} [${finding.severity.toUpperCase()}] ${finding.title}`);
      lines.push(`     Detector: ${finding.detector}`);
      lines.push(`     Location: ${location}`);
      const cleanDesc = finding.description.replace(/\n/g, " ").replace(/\s+/g, " ").trim();
      lines.push(`     ${cleanDesc}`);
    }
  } else if (customSummary.detectorsLoaded > 0) {
    lines.push("");
    lines.push("───────────────────────────────────────────────────────────────────────────────");
    lines.push("  CUSTOM CHECKS");
    lines.push("───────────────────────────────────────────────────────────────────────────────");
    lines.push("");
    lines.push(`  Detectors loaded: ${customSummary.detectorsLoaded}`);
    lines.push("  ✅ No issues found by custom detectors");
  }

  lines.push("");
  lines.push("═══════════════════════════════════════════════════════════════════════════════");

  return lines.join("\n");
}
