/**
 * Analyze Contract Tool
 *
 * Main orchestrator for the security analysis pipeline.
 * Runs Slither, Aderyn, and optionally Forge tests in parallel,
 * then deduplicates and formats the results.
 */

import { access, readFile } from "node:fs/promises";
import { z } from "zod";
import {
  getProjectRoot,
  checkToolsAvailable,
  executeCommand,
  formatDuration,
} from "../utils/executor.js";
import { logger } from "../utils/logger.js";
import { runSlither } from "../analyzers/slither.js";
import { runAderyn, deduplicateFindings } from "../analyzers/aderyn.js";
import { analyzeGasPatterns } from "../analyzers/gasOptimizer.js";
import {
  analyzeWithSlang,
  parseContractInfo,
  detectPatterns,
  type SlangAnalysisResult,
} from "../analyzers/slangAnalyzer.js";
import {
  loadCustomDetectors,
  runCustomDetectors,
  type CustomDetector,
} from "../detectors/customDetectorEngine.js";
import { Severity, type Finding, type ContractInfo } from "../types/index.js";

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
  // 3. Load custom detectors (if config exists)
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
  // 4. Check available tools
  // -------------------------------------------------------------------------
  const toolStatus = await checkToolsAvailable(["slither", "aderyn", "forge"]);

  const hasSlither = toolStatus["slither"]?.available ?? false;
  const hasAderyn = toolStatus["aderyn"]?.available ?? false;
  const hasForge = toolStatus["forge"]?.available ?? false;

  if (!hasSlither && !hasAderyn) {
    return formatError(
      "No security analysis tools are installed",
      "Install at least one of the following:\n" +
        "  • Slither: pip install slither-analyzer\n" +
        "  • Aderyn: cargo install aderyn"
    );
  }

  if (!hasSlither) {
    warnings.push("Slither not installed - skipping Slither analysis");
  }
  if (!hasAderyn) {
    warnings.push("Aderyn not installed - skipping Aderyn analysis");
  }
  if (input.runTests && !hasForge) {
    warnings.push("Forge not installed - skipping tests");
  }

  // -------------------------------------------------------------------------
  // 5. Run analysis in parallel
  // -------------------------------------------------------------------------
  logger.info("[analyze] Running analysis pipeline...");

  const analysisPromises: Promise<unknown>[] = [];
  const promiseLabels: string[] = [];

  // Always parse contract info
  analysisPromises.push(
    parseContractInfo(input.contractPath).catch((err) => {
      warnings.push(`Contract parsing failed: ${err.message}`);
      return null;
    })
  );
  promiseLabels.push("parseContractInfo");

  // Run Slither if available
  if (hasSlither) {
    analysisPromises.push(
      runSlitherWithTiming(input.contractPath, projectRoot).catch((err) => {
        warnings.push(`Slither failed: ${err.message}`);
        return { findings: [], executionTime: 0 };
      })
    );
    promiseLabels.push("slither");
  }

  // Run Aderyn if available
  if (hasAderyn) {
    analysisPromises.push(
      runAderynWithTiming(input.contractPath, projectRoot).catch((err) => {
        warnings.push(`Aderyn failed: ${err.message}`);
        return { findings: [], executionTime: 0 };
      })
    );
    promiseLabels.push("aderyn");
  }

  // Run gas optimization analysis
  analysisPromises.push(
    runGasAnalysisWithTiming(input.contractPath).catch((err) => {
      warnings.push(`Gas analysis failed: ${err.message}`);
      return { findings: [], executionTime: 0 };
    })
  );
  promiseLabels.push("gas");

  // Run Slang AST-based analysis (always available, no external dependency)
  analysisPromises.push(
    runSlangWithTiming(input.contractPath).catch((err) => {
      warnings.push(`Slang analysis failed: ${err.message}`);
      return { findings: [], parseErrors: [], executionTime: 0, detectorCount: 0 };
    })
  );
  promiseLabels.push("slang");

  // Run custom detectors if any are loaded
  if (customDetectors.length > 0) {
    analysisPromises.push(
      runCustomDetectorsWithTiming(input.contractPath, customDetectors, projectRoot).catch(
        (err) => {
          warnings.push(`Custom detectors failed: ${err.message}`);
          return { findings: [], executionTime: 0, detectorsLoaded: customDetectors.length };
        }
      )
    );
    promiseLabels.push("custom");
  }

  // Run tests if requested and forge is available
  if (input.runTests && hasForge) {
    analysisPromises.push(
      runForgeTests(projectRoot).catch((err) => {
        warnings.push(`Forge tests failed: ${err.message}`);
        return null;
      })
    );
    promiseLabels.push("forge");
  }

  // Execute all with timeout using Promise.allSettled for better error handling
  let settledResults: PromiseSettledResult<unknown>[];
  try {
    const allPromises = Promise.allSettled(analysisPromises);
    const timeoutProm = new Promise<PromiseSettledResult<unknown>[]>((_, reject) => {
      setTimeout(() => reject(new Error("Pipeline timeout")), PIPELINE_TIMEOUT);
    });
    settledResults = await Promise.race([allPromises, timeoutProm]);
  } catch (err) {
    if (err instanceof Error && err.message === "Pipeline timeout") {
      return formatError(
        "Analysis pipeline timed out",
        `The analysis took longer than ${formatDuration(PIPELINE_TIMEOUT)}. ` +
          "Try analyzing a smaller scope or increasing the timeout."
      );
    }
    return formatError(
      "Analysis pipeline failed",
      err instanceof Error ? err.message : String(err)
    );
  }

  // Process settled results - extract values and collect errors
  const results: unknown[] = settledResults.map((result, index) => {
    if (result.status === "rejected") {
      const label = promiseLabels[index] ?? `task-${index}`;
      const reason = result.reason instanceof Error ? result.reason.message : String(result.reason);
      warnings.push(`${label} failed: ${reason}`);
      logger.warn(`Analysis task failed`, { task: label, error: reason });
      return null;
    }
    return result.value;
  });

  // -------------------------------------------------------------------------
  // 6. Process results
  // -------------------------------------------------------------------------
  let resultIndex = 0;

  // Contract info
  const contractInfo = results[resultIndex++] as Awaited<
    ReturnType<typeof parseContractInfo>
  > | null;

  if (!contractInfo) {
    return formatError(
      "Failed to parse contract",
      "Could not extract contract metadata. The file may be malformed."
    );
  }

  // Slither results
  type ToolResult = { findings: Finding[]; executionTime: number } | null;
  let slitherResult: ToolResult = null;
  if (hasSlither) {
    slitherResult = results[resultIndex++] as ToolResult;
    if (slitherResult && slitherResult.findings.length > 0) {
      toolsUsed.push(`slither (${slitherResult.findings.length} findings)`);
    } else if (slitherResult) {
      toolsUsed.push("slither (0 findings)");
    }
  }

  // Aderyn results
  let aderynResult: ToolResult = null;
  if (hasAderyn) {
    aderynResult = results[resultIndex++] as ToolResult;
    if (aderynResult && aderynResult.findings.length > 0) {
      toolsUsed.push(`aderyn (${aderynResult.findings.length} findings)`);
    } else if (aderynResult) {
      toolsUsed.push("aderyn (0 findings)");
    }
  }

  // Gas optimization results
  const gasResult = results[resultIndex++] as ToolResult;
  const gasOptimizations = gasResult?.findings ?? [];
  if (gasOptimizations.length > 0) {
    toolsUsed.push(`gas-optimizer (${gasOptimizations.length} findings)`);
  }

  // Slang AST-based analysis results
  const slangResult = results[resultIndex++] as SlangAnalysisResult | null;
  const slangFindings = slangResult?.findings ?? [];
  if (slangResult) {
    if (slangResult.findings.length > 0) {
      toolsUsed.push(
        `slang (${slangResult.findings.length} findings from ${slangResult.detectorCount} detectors)`
      );
    } else {
      toolsUsed.push(`slang (0 findings from ${slangResult.detectorCount} detectors)`);
    }
    // Add parse errors to warnings
    if (slangResult.parseErrors.length > 0) {
      warnings.push(...slangResult.parseErrors.map((e) => `Slang parse: ${e}`));
    }
  }

  // Custom detector results
  type CustomResult = {
    findings: Finding[];
    executionTime: number;
    detectorsLoaded: number;
  } | null;
  let customResult: CustomResult = null;
  if (customDetectors.length > 0) {
    customResult = results[resultIndex++] as CustomResult;
    if (customResult && customResult.findings.length > 0) {
      toolsUsed.push(
        `custom-detectors (${customResult.findings.length} findings from ${customResult.detectorsLoaded} detectors)`
      );
    } else if (customResult) {
      toolsUsed.push(
        `custom-detectors (0 findings from ${customResult.detectorsLoaded} detectors)`
      );
    }
  }
  const customFindings = customResult?.findings ?? [];

  // Test results
  let testResults: TestResults | undefined;
  if (input.runTests && hasForge) {
    testResults = (results[resultIndex++] as TestResults | null) ?? undefined;
    if (testResults) {
      toolsUsed.push("forge");
    }
  }

  // -------------------------------------------------------------------------
  // 7. Deduplicate and sort findings
  // -------------------------------------------------------------------------
  const slitherFindings = slitherResult?.findings ?? [];
  const aderynFindings = aderynResult?.findings ?? [];

  // Combine findings from all sources
  let allFindings: Finding[];
  if (slitherFindings.length > 0 && aderynFindings.length > 0) {
    // Deduplicate Slither and Aderyn findings
    allFindings = deduplicateFindings(slitherFindings, aderynFindings);
  } else {
    allFindings = [...slitherFindings, ...aderynFindings];
  }

  // Add Slang findings (these are unique AST-based detections)
  // Slang findings complement Slither/Aderyn, so we add them directly
  if (slangFindings.length > 0) {
    // Deduplicate Slang findings with existing findings based on line and title similarity
    const existingKeys = new Set(
      allFindings.map((f) => `${f.location.lines?.[0] ?? 0}:${f.title.toLowerCase().slice(0, 20)}`)
    );
    const uniqueSlangFindings = slangFindings.filter((f) => {
      const key = `${f.location.lines?.[0] ?? 0}:${f.title.toLowerCase().slice(0, 20)}`;
      return !existingKeys.has(key);
    });
    allFindings = [...allFindings, ...uniqueSlangFindings];
  }

  // Sort by severity (CRITICAL first, INFORMATIONAL last)
  allFindings.sort((a, b) => {
    const severityOrder: Record<Severity, number> = {
      [Severity.CRITICAL]: 0,
      [Severity.HIGH]: 1,
      [Severity.MEDIUM]: 2,
      [Severity.LOW]: 3,
      [Severity.INFORMATIONAL]: 4,
    };
    return severityOrder[a.severity] - severityOrder[b.severity];
  });

  // -------------------------------------------------------------------------
  // 8. Detect patterns
  // -------------------------------------------------------------------------
  const source = await readFile(input.contractPath, "utf-8");
  const patterns = detectPatterns(source);

  // -------------------------------------------------------------------------
  // 9. Generate summaries
  // -------------------------------------------------------------------------
  const summary = calculateSummary(allFindings);
  const gasSummary = calculateGasSummary(gasOptimizations);
  const customSummary = calculateCustomSummary(customFindings, customDetectors.length);

  // -------------------------------------------------------------------------
  // 10. Build result
  // -------------------------------------------------------------------------
  const executionTime = Date.now() - startTime;

  const result: AnalysisResult = {
    contractInfo: {
      name: contractInfo.name,
      path: contractInfo.path,
      compiler: contractInfo.compiler,
      functions: contractInfo.functions,
      stateVariables: contractInfo.stateVariables,
      inherits: contractInfo.inherits,
      interfaces: contractInfo.interfaces,
      hasConstructor: contractInfo.hasConstructor,
      usesProxy: contractInfo.usesProxy,
    },
    findings: allFindings,
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
    rawOutput: {
      slither: slitherResult
        ? {
            findingsCount: slitherResult.findings.length,
            executionTime: slitherResult.executionTime,
          }
        : undefined,
      aderyn: aderynResult
        ? {
            findingsCount: aderynResult.findings.length,
            executionTime: aderynResult.executionTime,
          }
        : undefined,
      gas: gasResult
        ? {
            findingsCount: gasResult.findings.length,
            executionTime: gasResult.executionTime,
          }
        : undefined,
      slang: slangResult
        ? {
            findingsCount: slangResult.findings.length,
            executionTime: slangResult.executionTime,
            detectorCount: slangResult.detectorCount,
            parseErrors: slangResult.parseErrors.length,
          }
        : undefined,
      custom: customResult
        ? {
            findingsCount: customResult.findings.length,
            executionTime: customResult.executionTime,
            detectorsLoaded: customResult.detectorsLoaded,
          }
        : undefined,
    },
    executionTime,
  };

  logger.info(`[analyze] Analysis complete in ${formatDuration(executionTime)}`);

  // -------------------------------------------------------------------------
  // 11. Format output
  // -------------------------------------------------------------------------
  return formatOutput(result);
}

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Run Slither with timing information
 */
async function runSlitherWithTiming(
  contractPath: string,
  projectRoot: string
): Promise<{ findings: Finding[]; executionTime: number }> {
  const start = Date.now();
  const findings = await runSlither(contractPath, projectRoot);
  return {
    findings,
    executionTime: Date.now() - start,
  };
}

/**
 * Run Aderyn with timing information
 */
async function runAderynWithTiming(
  contractPath: string,
  projectRoot: string
): Promise<{ findings: Finding[]; executionTime: number }> {
  const start = Date.now();
  const findings = await runAderyn(contractPath, projectRoot);
  return {
    findings,
    executionTime: Date.now() - start,
  };
}

/**
 * Run gas optimization analysis with timing information
 */
async function runGasAnalysisWithTiming(
  contractPath: string
): Promise<{ findings: Finding[]; executionTime: number }> {
  const start = Date.now();
  const findings = await analyzeGasPatterns(contractPath);
  return {
    findings,
    executionTime: Date.now() - start,
  };
}

/**
 * Run Slang analysis with timing information
 */
async function runSlangWithTiming(contractPath: string): Promise<SlangAnalysisResult> {
  const source = await readFile(contractPath, "utf-8");
  return analyzeWithSlang(source, contractPath, {
    includeInformational: true,
  });
}

/**
 * Run custom detectors with timing information
 */
async function runCustomDetectorsWithTiming(
  contractPath: string,
  detectors: CustomDetector[],
  projectRoot: string
): Promise<{ findings: Finding[]; executionTime: number; detectorsLoaded: number }> {
  const start = Date.now();
  const source = await readFile(contractPath, "utf-8");
  const findings = runCustomDetectors(source, contractPath, detectors, projectRoot);
  return {
    findings,
    executionTime: Date.now() - start,
    detectorsLoaded: detectors.length,
  };
}

/**
 * Run Forge tests and coverage
 */
async function runForgeTests(projectRoot: string): Promise<TestResults> {
  const start = Date.now();

  // Run forge test
  const testResult = await executeCommand("forge", ["test", "--gas-report", "-v"], {
    cwd: projectRoot,
    timeout: 120_000,
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

  // Try to get coverage (may fail if not configured)
  let coverage: number | undefined;
  try {
    const coverageResult = await executeCommand("forge", ["coverage", "--report", "summary"], {
      cwd: projectRoot,
      timeout: 120_000,
    });

    // Parse coverage percentage
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
 * Calculate summary counts by severity
 */
function calculateSummary(findings: Finding[]): AnalysisSummary {
  const summary: AnalysisSummary = {
    total: findings.length,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    informational: 0,
  };

  for (const finding of findings) {
    switch (finding.severity) {
      case Severity.CRITICAL:
        summary.critical++;
        break;
      case Severity.HIGH:
        summary.high++;
        break;
      case Severity.MEDIUM:
        summary.medium++;
        break;
      case Severity.LOW:
        summary.low++;
        break;
      case Severity.INFORMATIONAL:
        summary.informational++;
        break;
    }
  }

  return summary;
}

/**
 * Calculate gas optimization summary
 */
function calculateGasSummary(findings: Finding[]): GasOptimizationSummary {
  const summary: GasOptimizationSummary = {
    total: findings.length,
    high: 0,
    medium: 0,
    low: 0,
    informational: 0,
    estimatedSavings: "0",
  };

  let totalGas = 0;

  for (const finding of findings) {
    switch (finding.severity) {
      case Severity.HIGH:
        summary.high++;
        break;
      case Severity.MEDIUM:
        summary.medium++;
        break;
      case Severity.LOW:
        summary.low++;
        break;
      case Severity.INFORMATIONAL:
        summary.informational++;
        break;
    }

    // Extract gas savings from description
    const gasMatch = finding.description.match(/~?(\d+)(?:-(\d+))?\s*gas/i);
    if (gasMatch) {
      const low = parseInt(gasMatch[1]!, 10);
      const high = gasMatch[2] ? parseInt(gasMatch[2], 10) : low;
      totalGas += Math.floor((low + high) / 2);
    }
  }

  // Format total savings
  if (totalGas >= 1000000) {
    summary.estimatedSavings = `${(totalGas / 1000000).toFixed(1)}M`;
  } else if (totalGas >= 1000) {
    summary.estimatedSavings = `${(totalGas / 1000).toFixed(1)}K`;
  } else {
    summary.estimatedSavings = totalGas.toString();
  }

  return summary;
}

/**
 * Calculate custom checks summary
 */
function calculateCustomSummary(findings: Finding[], detectorsLoaded: number): CustomChecksSummary {
  const summary: CustomChecksSummary = {
    total: findings.length,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    informational: 0,
    detectorsLoaded,
  };

  for (const finding of findings) {
    switch (finding.severity) {
      case Severity.CRITICAL:
        summary.critical++;
        break;
      case Severity.HIGH:
        summary.high++;
        break;
      case Severity.MEDIUM:
        summary.medium++;
        break;
      case Severity.LOW:
        summary.low++;
        break;
      case Severity.INFORMATIONAL:
        summary.informational++;
        break;
    }
  }

  return summary;
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

  // Build text summary for quick reading
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
      // Show full description, just clean up newlines
      const cleanDesc = finding.description.replace(/\n/g, " ").replace(/\s+/g, " ").trim();
      lines.push(`     ${cleanDesc}`);
      if (finding.recommendation && finding.recommendation !== "Review the code and apply appropriate fixes") {
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

/**
 * Get emoji for severity level
 */
function getSeverityEmoji(severity: Severity): string {
  switch (severity) {
    case Severity.CRITICAL:
      return "🔴";
    case Severity.HIGH:
      return "🟠";
    case Severity.MEDIUM:
      return "🟡";
    case Severity.LOW:
      return "🟢";
    case Severity.INFORMATIONAL:
      return "🔵";
  }
}

