/**
 * Aderyn Adapter
 *
 * Self-contained adapter for Aderyn, the Solidity static analyzer by Cyfrin.
 * https://github.com/Cyfrin/aderyn
 *
 * Includes the full Aderyn runner implementation, output parsing, deduplication
 * logic, and the IAnalyzer-compatible adapter class.
 */

import { createHash, randomUUID } from "crypto";
import { readFile, unlink, access } from "fs/promises";
import { tmpdir } from "os";
import { join } from "path";
import { BaseAnalyzer } from "../IAnalyzer.js";
import type {
  AnalyzerInput,
  AnalyzerResult,
  AnalyzerCapabilities,
  AnalyzerAvailability,
  AderynOptions,
} from "../types.js";
import { executeCommand, checkToolAvailable } from "../../utils/executor.js";
import { Severity, type Finding, type Confidence } from "../../types/index.js";
import { logger } from "../../utils/logger.js";

// ============================================================================
// Internal Types (Aderyn output format)
// ============================================================================

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
  nc_issues: AderynIssueCategory;
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
// Internal Helper Functions
// ============================================================================

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

function inferConfidence(severity: Severity, instanceCount: number): Confidence {
  if (instanceCount >= 3) return "high";

  if (severity === Severity.HIGH || severity === Severity.CRITICAL) {
    return instanceCount >= 1 ? "high" : "medium";
  }

  if (severity === Severity.MEDIUM) {
    return instanceCount >= 1 ? "medium" : "low";
  }

  return "low";
}

function getAderynRecommendation(detectorName: string, title: string): string {
  const recommendations: Record<string, string> = {
    reentrancy: "Use the checks-effects-interactions pattern or ReentrancyGuard",
    "state-change-after-external-call": "Move state changes before external calls",
    "centralization-risk": "Consider using a multi-sig or timelock for critical functions",
    "unprotected-initializer": "Add access control to initializer functions",
    "missing-access-control": "Implement proper access control modifiers",
    "zero-address-check": "Add require(address != address(0)) validation",
    "missing-zero-check": "Validate that address parameters are not zero",
    "unsafe-erc20-operation": "Use SafeERC20 from OpenZeppelin for token operations",
    "unchecked-return": "Check return values of external calls",
    "gas-optimization": "Consider the suggested gas optimization",
    "cache-array-length": "Cache array length in a local variable before the loop",
    "use-immutable": "Mark variables that are only set in constructor as immutable",
    "use-constant": "Mark variables that never change as constant",
    "unused-variable": "Remove unused variables to improve code clarity",
    "dead-code": "Remove unreachable or unused code",
    "floating-pragma": "Lock the Solidity version to a specific release",
    "solidity-version": "Consider updating to a more recent Solidity version",
    "divide-before-multiply": "Perform multiplication before division to avoid precision loss",
    "unsafe-casting": "Use SafeCast library for type conversions",
    "timestamp-dependence": "Avoid relying on block.timestamp for critical logic",
  };

  const lowerDetector = detectorName.toLowerCase();
  for (const [key, rec] of Object.entries(recommendations)) {
    if (lowerDetector.includes(key)) {
      return rec;
    }
  }

  const lowerTitle = title.toLowerCase();
  for (const [key, rec] of Object.entries(recommendations)) {
    if (lowerTitle.includes(key.replace(/-/g, " "))) {
      return rec;
    }
  }

  return "Review the code and apply appropriate fixes";
}

function createAderynFinding(
  issue: AderynIssue,
  severity: Severity,
  instances: AderynInstance[] | null,
  file?: string
): Finding {
  const firstInstance = instances?.[0];

  const hashInput = [
    issue.detector_name,
    file ?? firstInstance?.contract_path ?? "",
    firstInstance?.line_no?.toString() ?? "",
  ].join(":");

  const hash = createHash("sha256").update(hashInput).digest("hex").slice(0, 8);
  const id = `AD-${hash}`;

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

function parseAderynResults(output: AderynOutput): Finding[] {
  const findings: Finding[] = [];

  const categories: Array<{ issues: AderynIssueCategory; severity: Severity }> = [
    { issues: output.high_issues, severity: Severity.HIGH },
    { issues: output.medium_issues, severity: Severity.MEDIUM },
    { issues: output.low_issues, severity: Severity.LOW },
    { issues: output.nc_issues, severity: Severity.INFORMATIONAL },
  ];

  for (const { issues, severity } of categories) {
    if (!issues?.issues) continue;

    for (const issue of issues.issues) {
      if (issue.instances.length === 0) {
        findings.push(createAderynFinding(issue, severity, null));
      } else {
        const instancesByFile = groupInstancesByFile(issue.instances);

        for (const [file, fileInstances] of Object.entries(instancesByFile)) {
          findings.push(createAderynFinding(issue, severity, fileInstances, file));
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

// ============================================================================
// Aderyn Runner
// ============================================================================

async function runAderyn(
  contractPath: string,
  projectRoot: string,
  options: AderynRunOptions = {}
): Promise<Finding[]> {
  const toolInfo = await checkToolAvailable("aderyn");

  if (!toolInfo.available) {
    logger.warn("[aderyn] Aderyn is not installed. Install with: cargo install aderyn");
    return [];
  }

  logger.info(`[aderyn] Using Aderyn ${toolInfo.version ?? "unknown version"}`);
  logger.info(`[aderyn] Analyzing project: ${projectRoot}`);
  logger.info(`[aderyn] Target contract: ${contractPath}`);

  const tempFile = join(tmpdir(), `aderyn-${randomUUID()}.json`);

  try {
    const args: string[] = [projectRoot, "--output", tempFile];

    if (options.scope) {
      args.push("--scope", options.scope);
    }

    if (options.exclude && options.exclude.length > 0) {
      args.push("--path-excludes", options.exclude.join(","));
    }

    logger.info(`[aderyn] Running: aderyn ${args.join(" ")}`);

    const result = await executeCommand("aderyn", args, {
      cwd: projectRoot,
      timeout: options.timeout ?? 120_000,
    });

    let outputExists = false;
    try {
      await access(tempFile);
      outputExists = true;
    } catch {
      // Output file doesn't exist
    }

    if (result.exitCode !== 0 && !outputExists) {
      logger.error(`[aderyn] Execution failed with code ${result.exitCode}`);
      logger.error(`[aderyn] stderr: ${result.stderr.slice(0, 500)}`);
      return [];
    }

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

    const outputContent = await readFile(tempFile, "utf-8");
    const output = JSON.parse(outputContent) as AderynOutput;

    return parseAderynResults(output);
  } catch (error) {
    logger.error(`[aderyn] Error: ${error instanceof Error ? error.message : String(error)}`);
    return [];
  } finally {
    try {
      await unlink(tempFile);
    } catch {
      // Ignore cleanup errors
    }
  }
}

// ============================================================================
// Deduplication (public — used by AnalyzerOrchestrator and tests)
// ============================================================================

/**
 * Deduplicate findings from multiple analyzers (Slither + Aderyn).
 *
 * When both tools report the same issue (same file, similar line, similar type),
 * this function merges them, keeping the most detailed description.
 */
export function deduplicateFindings(
  slitherFindings: Finding[],
  aderynFindings: Finding[]
): Finding[] {
  const result: Finding[] = [];
  const usedAderynIndices = new Set<number>();

  for (const slitherFinding of slitherFindings) {
    let merged = false;

    for (let i = 0; i < aderynFindings.length; i++) {
      if (usedAderynIndices.has(i)) continue;

      const aderynFinding = aderynFindings[i]!;

      if (areSimilarFindings(slitherFinding, aderynFinding)) {
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

function areSimilarFindings(a: Finding, b: Finding): boolean {
  if (a.location.file !== b.location.file) {
    return false;
  }

  if (!areSeveritiesSimilar(a.severity, b.severity)) {
    return false;
  }

  if (!areLinesClose(a.location.lines, b.location.lines)) {
    return false;
  }

  if (haveSimilarType(a, b)) {
    return true;
  }

  return false;
}

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

function areLinesClose(a: [number, number] | undefined, b: [number, number] | undefined): boolean {
  if (!a || !b) return true;

  const [aStart, aEnd] = a;
  const [bStart, bEnd] = b;

  if (aStart <= bEnd && bStart <= aEnd) {
    return true;
  }

  const distance = Math.min(
    Math.abs(aStart - bEnd),
    Math.abs(bStart - aEnd),
    Math.abs(aStart - bStart),
    Math.abs(aEnd - bEnd)
  );

  return distance <= 5;
}

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

function mergeFindings(a: Finding, b: Finding): Finding {
  const severity = compareSeverity(a.severity, b.severity) >= 0 ? a.severity : b.severity;

  const confidence =
    compareConfidence(a.confidence, b.confidence) >= 0 ? a.confidence : b.confidence;

  const description = a.description.length >= b.description.length ? a.description : b.description;

  const recommendation =
    a.recommendation.length >= b.recommendation.length ? a.recommendation : b.recommendation;

  const title = a.detector === "slither" ? a.title : b.title;

  let lines = a.location.lines;
  if (a.location.lines && b.location.lines) {
    const allLines = [...a.location.lines, ...b.location.lines];
    lines = [Math.min(...allLines), Math.max(...allLines)];
  } else if (b.location.lines) {
    lines = b.location.lines;
  }

  return {
    id: a.id,
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

function compareConfidence(a: Confidence, b: Confidence): number {
  const order: Record<Confidence, number> = {
    high: 2,
    medium: 1,
    low: 0,
  };
  return order[a] - order[b];
}

// ============================================================================
// Aderyn Adapter
// ============================================================================

export class AderynAdapter extends BaseAnalyzer<AderynOptions> {
  readonly id = "aderyn" as const;
  readonly name = "Aderyn Static Analyzer";
  readonly description =
    "Rust-based static analysis tool optimized for speed, " +
    "with 50+ detectors focusing on common Solidity vulnerabilities.";

  readonly capabilities: AnalyzerCapabilities = {
    requiresExternalTool: true,
    externalToolName: "aderyn",
    supportsSourceInput: false,
    supportsOptions: true,
    supportsParallel: true,
    detectorCount: 50,
  };

  private cachedAvailability: AnalyzerAvailability | null = null;
  private availabilityCacheTime = 0;
  private static readonly CACHE_TTL = 60_000; // 1 minute

  async checkAvailability(): Promise<AnalyzerAvailability> {
    const now = Date.now();
    if (this.cachedAvailability && now - this.availabilityCacheTime < AderynAdapter.CACHE_TTL) {
      return this.cachedAvailability;
    }

    try {
      const result = await checkToolAvailable("aderyn");

      this.cachedAvailability = {
        analyzerId: this.id,
        status: result.available ? "available" : "unavailable",
        message: result.available
          ? "Aderyn is installed and ready"
          : "Aderyn is not installed. Install with: cargo install aderyn",
        version: result.version,
        toolPath: result.path,
      };
    } catch (error) {
      this.cachedAvailability = {
        analyzerId: this.id,
        status: "error",
        message: `Failed to check Aderyn availability: ${error instanceof Error ? error.message : String(error)}`,
      };
    }

    this.availabilityCacheTime = now;
    return this.cachedAvailability;
  }

  getDefaultOptions(): AderynOptions {
    return {
      timeout: 120_000,
      includeInformational: false,
      exclude: ["node_modules", "lib", "test", "tests"],
    };
  }

  protected async doAnalyze(input: AnalyzerInput, options: AderynOptions): Promise<AnalyzerResult> {
    const warnings: string[] = [];

    logger.info(`[AderynAdapter] Analyzing ${input.contractPath}`);

    try {
      const findings = await runAderyn(input.contractPath, input.projectRoot ?? input.contractPath, {
        scope: options.scope,
        exclude: options.exclude,
        timeout: options.timeout,
      });

      const filteredFindings = options.includeInformational
        ? findings
        : findings.filter((f) => f.severity !== "informational");

      logger.info(`[AderynAdapter] Found ${filteredFindings.length} findings`);

      return {
        ...this.createSuccessResult(
          filteredFindings,
          {
            detectorCount: this.capabilities.detectorCount,
            toolVersion: this.cachedAvailability?.version,
          },
          warnings
        ),
        analyzerId: this.id,
        executionTime: 0,
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      logger.error(`[AderynAdapter] Analysis failed: ${errorMessage}`);

      if (errorMessage.includes("timeout")) {
        warnings.push("Analysis timed out. Consider increasing the timeout.");
      }

      throw error;
    }
  }
}

// Export singleton instance
export const aderynAdapter = new AderynAdapter();
