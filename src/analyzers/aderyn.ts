/**
 * Aderyn Analyzer
 *
 * Wrapper for Aderyn, the Solidity static analyzer by Cyfrin.
 * https://github.com/Cyfrin/aderyn
 *
 * Aderyn is a Rust-based analyzer that detects vulnerabilities
 * and code quality issues in Solidity smart contracts.
 */

import { createHash, randomUUID } from "crypto";
import { readFile, unlink, access } from "fs/promises";
import { tmpdir } from "os";
import { join } from "path";
import { executeCommand, checkToolAvailable } from "../utils/executor.js";
import { Severity, type Finding, type Confidence } from "../types/index.js";
import { logger } from "../utils/logger.js";

// ============================================================================
// Types
// ============================================================================

/**
 * Aderyn JSON output structure
 */
interface AderynOutput {
  files_summary: {
    total_source_units: number;
    total_sloc: number;
  };
  files_details: {
    files_source_units: Record<string, number>;
  };
  issue_count: {
    high: number;
    medium: number;
    low: number;
    nc: number;
  };
  high_issues: AderynIssueCategory;
  medium_issues: AderynIssueCategory;
  low_issues: AderynIssueCategory;
  nc_issues: AderynIssueCategory; // NC = Non-Critical (Informational)
}

interface AderynIssueCategory {
  issues: AderynIssue[];
}

interface AderynIssue {
  title: string;
  description: string;
  detector_name: string;
  instances: AderynInstance[];
}

interface AderynInstance {
  contract_path: string;
  line_no: number;
  src?: string;
  src_char?: string;
}

export interface AderynRunOptions {
  /** Specific scope to analyze (e.g., "src/") */
  scope?: string;
  /** Paths to exclude from analysis */
  exclude?: string[];
  /** Timeout in milliseconds (default: 120000) */
  timeout?: number;
}

// ============================================================================
// Main Functions
// ============================================================================

/**
 * Run Aderyn analysis on a Solidity project.
 *
 * @param contractPath - Path to the contract file (for reference)
 * @param projectRoot - Root directory of the project
 * @param options - Additional run options
 * @returns Array of Finding objects
 *
 * @example
 * ```ts
 * const findings = await runAderyn("/path/to/Token.sol", "/path/to/project");
 * console.log(`Found ${findings.length} issues`);
 * ```
 */
export async function runAderyn(
  contractPath: string,
  projectRoot: string,
  options: AderynRunOptions = {}
): Promise<Finding[]> {
  // Check if Aderyn is installed
  const toolInfo = await checkToolAvailable("aderyn");

  if (!toolInfo.available) {
    logger.warn("[aderyn] Aderyn is not installed. Install with: cargo install aderyn");
    return [];
  }

  logger.info(`[aderyn] Using Aderyn ${toolInfo.version ?? "unknown version"}`);
  logger.info(`[aderyn] Analyzing project: ${projectRoot}`);
  logger.info(`[aderyn] Target contract: ${contractPath}`);

  // Create temporary output file
  const tempFile = join(tmpdir(), `aderyn-${randomUUID()}.json`);

  try {
    // Build command arguments
    const args: string[] = [projectRoot, "--output", tempFile];

    // Add scope if provided
    if (options.scope) {
      args.push("--scope", options.scope);
    }

    // Add exclude paths
    if (options.exclude && options.exclude.length > 0) {
      for (const path of options.exclude) {
        args.push("--exclude", path);
      }
    }

    logger.info(`[aderyn] Running: aderyn ${args.join(" ")}`);

    // Execute Aderyn
    const result = await executeCommand("aderyn", args, {
      cwd: projectRoot,
      timeout: options.timeout ?? 120_000,
    });

    // Check if output file exists (Aderyn may crash after generating output)
    let outputExists = false;
    try {
      await access(tempFile);
      outputExists = true;
    } catch {
      // Output file doesn't exist
    }

    // If execution failed AND no output file, return empty
    if (result.exitCode !== 0 && !outputExists) {
      logger.error(`[aderyn] Execution failed with code ${result.exitCode}`);
      logger.error(`[aderyn] stderr: ${result.stderr.slice(0, 500)}`);
      return [];
    }

    // Log warning if exit code was non-zero but we have output
    if (result.exitCode !== 0 && outputExists) {
      logger.warn(`[aderyn] Exit code ${result.exitCode} but output file exists, parsing results`);
      if (result.stderr) {
        logger.debug(`[aderyn] stderr: ${result.stderr.slice(0, 200)}`);
      }
    }

    if (!outputExists) {
      logger.error("[aderyn] Output file not created");
      logger.error(`[aderyn] stdout: ${result.stdout.slice(0, 500)}`);
      return [];
    }

    // Read and parse output file
    const outputContent = await readFile(tempFile, "utf-8");
    const output = JSON.parse(outputContent) as AderynOutput;

    return parseAderynResults(output);
  } catch (error) {
    logger.error(`[aderyn] Error: ${error instanceof Error ? error.message : String(error)}`);
    return [];
  } finally {
    // Clean up temporary file
    try {
      await unlink(tempFile);
    } catch {
      // Ignore cleanup errors
    }
  }
}

/**
 * Parse Aderyn output into Finding array
 */
function parseAderynResults(output: AderynOutput): Finding[] {
  const findings: Finding[] = [];

  // Process each severity category
  const categories: Array<{ issues: AderynIssueCategory; severity: Severity }> = [
    { issues: output.high_issues, severity: Severity.HIGH },
    { issues: output.medium_issues, severity: Severity.MEDIUM },
    { issues: output.low_issues, severity: Severity.LOW },
    { issues: output.nc_issues, severity: Severity.INFORMATIONAL },
  ];

  for (const { issues, severity } of categories) {
    if (!issues?.issues) continue;

    for (const issue of issues.issues) {
      // Create a finding for each instance, or one finding if no instances
      if (issue.instances.length === 0) {
        findings.push(createFinding(issue, severity, null));
      } else {
        // Group instances by file to avoid too many findings
        const instancesByFile = groupInstancesByFile(issue.instances);

        for (const [file, fileInstances] of Object.entries(instancesByFile)) {
          findings.push(createFinding(issue, severity, fileInstances, file));
        }
      }
    }
  }

  const totalIssues =
    output.issue_count.high +
    output.issue_count.medium +
    output.issue_count.low +
    output.issue_count.nc;

  logger.info(`[aderyn] Found ${totalIssues} issues (${findings.length} findings after grouping)`);

  return findings;
}

/**
 * Group instances by file path
 */
function groupInstancesByFile(instances: AderynInstance[]): Record<string, AderynInstance[]> {
  const grouped: Record<string, AderynInstance[]> = {};

  for (const instance of instances) {
    const file = instance.contract_path;
    if (!grouped[file]) {
      grouped[file] = [];
    }
    grouped[file].push(instance);
  }

  return grouped;
}

/**
 * Create a Finding from an Aderyn issue
 */
function createFinding(
  issue: AderynIssue,
  severity: Severity,
  instances: AderynInstance[] | null,
  file?: string
): Finding {
  const firstInstance = instances?.[0];

  // Generate unique ID
  const hashInput = [
    issue.detector_name,
    file ?? firstInstance?.contract_path ?? "",
    firstInstance?.line_no?.toString() ?? "",
  ].join(":");

  const hash = createHash("sha256").update(hashInput).digest("hex").slice(0, 8);
  const id = `AD-${hash}`;

  // Build location
  let location: Finding["location"];
  if (firstInstance) {
    const lines = instances!.map((i) => i.line_no).sort((a, b) => a - b);
    location = {
      file: file ?? firstInstance.contract_path,
      lines: [lines[0]!, lines[lines.length - 1]!],
    };
  } else {
    location = { file: file ?? "unknown" };
  }

  // Build description with instance count
  let description = issue.description;
  if (instances && instances.length > 1) {
    description += `\n\nFound in ${instances.length} locations:`;
    for (const inst of instances.slice(0, 5)) {
      description += `\n- Line ${inst.line_no}`;
    }
    if (instances.length > 5) {
      description += `\n- ... and ${instances.length - 5} more`;
    }
  }

  return {
    id,
    title: issue.title,
    severity,
    description: description.trim(),
    location,
    recommendation: getAderynRecommendation(issue.detector_name, issue.title),
    detector: "aderyn",
    confidence: inferConfidence(severity, instances?.length ?? 0),
  };
}

/**
 * Infer confidence based on severity and instance count
 */
function inferConfidence(severity: Severity, instanceCount: number): Confidence {
  // Multiple instances generally mean higher confidence
  if (instanceCount >= 3) return "high";

  // Higher severity with instances = medium-high confidence
  if (severity === Severity.HIGH || severity === Severity.CRITICAL) {
    return instanceCount >= 1 ? "high" : "medium";
  }

  if (severity === Severity.MEDIUM) {
    return instanceCount >= 1 ? "medium" : "low";
  }

  return "low";
}

/**
 * Get recommendation based on detector name or title
 */
function getAderynRecommendation(detectorName: string, title: string): string {
  const recommendations: Record<string, string> = {
    // Reentrancy
    reentrancy: "Use the checks-effects-interactions pattern or ReentrancyGuard",
    "state-change-after-external-call": "Move state changes before external calls",

    // Access control
    "centralization-risk": "Consider using a multi-sig or timelock for critical functions",
    "unprotected-initializer": "Add access control to initializer functions",
    "missing-access-control": "Implement proper access control modifiers",

    // Input validation
    "zero-address-check": "Add require(address != address(0)) validation",
    "missing-zero-check": "Validate that address parameters are not zero",

    // ERC20
    "unsafe-erc20-operation": "Use SafeERC20 from OpenZeppelin for token operations",
    "unchecked-return": "Check return values of external calls",

    // Gas/Optimization
    "gas-optimization": "Consider the suggested gas optimization",
    "cache-array-length": "Cache array length in a local variable before the loop",
    "use-immutable": "Mark variables that are only set in constructor as immutable",
    "use-constant": "Mark variables that never change as constant",

    // Code quality
    "unused-variable": "Remove unused variables to improve code clarity",
    "dead-code": "Remove unreachable or unused code",
    "floating-pragma": "Lock the Solidity version to a specific release",
    "solidity-version": "Consider updating to a more recent Solidity version",

    // Logic
    "divide-before-multiply": "Perform multiplication before division to avoid precision loss",
    "unsafe-casting": "Use SafeCast library for type conversions",
    "timestamp-dependence": "Avoid relying on block.timestamp for critical logic",
  };

  // Try exact match on detector name
  const lowerDetector = detectorName.toLowerCase();
  for (const [key, rec] of Object.entries(recommendations)) {
    if (lowerDetector.includes(key)) {
      return rec;
    }
  }

  // Try matching on title
  const lowerTitle = title.toLowerCase();
  for (const [key, rec] of Object.entries(recommendations)) {
    if (lowerTitle.includes(key.replace(/-/g, " "))) {
      return rec;
    }
  }

  return "Review the code and apply appropriate fixes";
}

/**
 * Check if Aderyn is available on the system
 */
export async function isAderynAvailable(): Promise<boolean> {
  const info = await checkToolAvailable("aderyn");
  return info.available;
}

// ============================================================================
// Deduplication
// ============================================================================

/**
 * Deduplicate findings from multiple analyzers (Slither + Aderyn).
 *
 * When both tools report the same issue (same file, similar line, similar type),
 * this function merges them, keeping the most detailed description.
 *
 * @param slitherFindings - Findings from Slither
 * @param aderynFindings - Findings from Aderyn
 * @returns Deduplicated array of findings
 *
 * @example
 * ```ts
 * const slitherResults = await runSlither(contract, root);
 * const aderynResults = await runAderyn(contract, root);
 * const allFindings = deduplicateFindings(slitherResults, aderynResults);
 * ```
 */
export function deduplicateFindings(
  slitherFindings: Finding[],
  aderynFindings: Finding[]
): Finding[] {
  const result: Finding[] = [];
  const usedAderynIndices = new Set<number>();

  // For each Slither finding, check if there's a matching Aderyn finding
  for (const slitherFinding of slitherFindings) {
    let merged = false;

    for (let i = 0; i < aderynFindings.length; i++) {
      if (usedAderynIndices.has(i)) continue;

      const aderynFinding = aderynFindings[i]!;

      if (areSimilarFindings(slitherFinding, aderynFinding)) {
        // Merge the findings, preferring the more detailed one
        result.push(mergeFindings(slitherFinding, aderynFinding));
        usedAderynIndices.add(i);
        merged = true;
        break;
      }
    }

    if (!merged) {
      result.push(slitherFinding);
    }
  }

  // Add remaining Aderyn findings that weren't matched
  for (let i = 0; i < aderynFindings.length; i++) {
    if (!usedAderynIndices.has(i)) {
      result.push(aderynFindings[i]!);
    }
  }

  logger.info(
    `[dedup] Merged ${slitherFindings.length} Slither + ${aderynFindings.length} Aderyn → ${result.length} unique findings`
  );

  return result;
}

/**
 * Check if two findings are similar enough to be considered duplicates.
 */
function areSimilarFindings(a: Finding, b: Finding): boolean {
  // Must be in the same file
  if (a.location.file !== b.location.file) {
    return false;
  }

  // Must have similar severity (within one level)
  if (!areSeveritiesSimilar(a.severity, b.severity)) {
    return false;
  }

  // Must have overlapping or nearby lines
  if (!areLinesClose(a.location.lines, b.location.lines)) {
    return false;
  }

  // Check for similar issue types based on keywords
  if (haveSimilarType(a, b)) {
    return true;
  }

  return false;
}

/**
 * Check if two severities are similar (same or adjacent)
 */
function areSeveritiesSimilar(a: Severity, b: Severity): boolean {
  const severityOrder: Record<Severity, number> = {
    [Severity.CRITICAL]: 4,
    [Severity.HIGH]: 3,
    [Severity.MEDIUM]: 2,
    [Severity.LOW]: 1,
    [Severity.INFORMATIONAL]: 0,
  };

  const diff = Math.abs(severityOrder[a] - severityOrder[b]);
  return diff <= 1;
}

/**
 * Check if two line ranges are close to each other
 */
function areLinesClose(a: [number, number] | undefined, b: [number, number] | undefined): boolean {
  // If either has no lines, can't compare
  if (!a || !b) return true; // Be lenient

  const [aStart, aEnd] = a;
  const [bStart, bEnd] = b;

  // Check for overlap
  if (aStart <= bEnd && bStart <= aEnd) {
    return true;
  }

  // Check if within 5 lines of each other
  const distance = Math.min(
    Math.abs(aStart - bEnd),
    Math.abs(bStart - aEnd),
    Math.abs(aStart - bStart),
    Math.abs(aEnd - bEnd)
  );

  return distance <= 5;
}

/**
 * Check if two findings have similar issue types based on keywords
 */
function haveSimilarType(a: Finding, b: Finding): boolean {
  const keywords: string[][] = [
    ["reentrancy", "reentrant", "re-entrancy"],
    ["uninitialized", "uninitialised", "not initialized"],
    ["unchecked", "return value", "ignored return"],
    ["arbitrary", "unprotected", "access control"],
    ["selfdestruct", "suicide", "destroy"],
    ["delegatecall", "delegate call"],
    ["timestamp", "block.timestamp", "time manipulation"],
    ["randomness", "random", "prng", "weak random"],
    ["shadowing", "shadow", "shadows"],
    ["ether", "eth", "locked"],
    ["loop", "dos", "denial of service"],
    ["zero address", "address(0)", "zero-address"],
    ["overflow", "underflow", "arithmetic"],
    ["centralization", "centraliz", "admin", "owner"],
    ["pragma", "solidity version", "compiler"],
  ];

  const aText = `${a.title} ${a.description}`.toLowerCase();
  const bText = `${b.title} ${b.description}`.toLowerCase();

  for (const group of keywords) {
    const aHas = group.some((kw) => aText.includes(kw));
    const bHas = group.some((kw) => bText.includes(kw));

    if (aHas && bHas) {
      return true;
    }
  }

  return false;
}

/**
 * Merge two similar findings, keeping the most detailed information
 */
function mergeFindings(a: Finding, b: Finding): Finding {
  // Prefer higher severity
  const severity = compareSeverity(a.severity, b.severity) >= 0 ? a.severity : b.severity;

  // Prefer higher confidence
  const confidence =
    compareConfidence(a.confidence, b.confidence) >= 0 ? a.confidence : b.confidence;

  // Use the longer description
  const description = a.description.length >= b.description.length ? a.description : b.description;

  // Use the longer recommendation
  const recommendation =
    a.recommendation.length >= b.recommendation.length ? a.recommendation : b.recommendation;

  // Prefer Slither's title (usually more specific)
  const title = a.detector === "slither" ? a.title : b.title;

  // Combine line ranges if both have them
  let lines = a.location.lines;
  if (a.location.lines && b.location.lines) {
    const allLines = [...a.location.lines, ...b.location.lines];
    lines = [Math.min(...allLines), Math.max(...allLines)];
  } else if (b.location.lines) {
    lines = b.location.lines;
  }

  return {
    id: a.id, // Keep first finding's ID
    title,
    severity,
    description: `${description}\n\n[Detected by both Slither and Aderyn]`,
    location: {
      file: a.location.file,
      lines,
      function: a.location.function ?? b.location.function,
    },
    recommendation,
    detector: "slither+aderyn" as Finding["detector"],
    confidence,
  };
}

/**
 * Compare two severities, returns positive if a > b
 */
function compareSeverity(a: Severity, b: Severity): number {
  const order: Record<Severity, number> = {
    [Severity.CRITICAL]: 4,
    [Severity.HIGH]: 3,
    [Severity.MEDIUM]: 2,
    [Severity.LOW]: 1,
    [Severity.INFORMATIONAL]: 0,
  };
  return order[a] - order[b];
}

/**
 * Compare two confidence levels, returns positive if a > b
 */
function compareConfidence(a: Confidence, b: Confidence): number {
  const order: Record<Confidence, number> = {
    high: 2,
    medium: 1,
    low: 0,
  };
  return order[a] - order[b];
}
