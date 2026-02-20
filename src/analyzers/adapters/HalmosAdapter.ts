/**
 * Halmos Adapter
 *
 * Adapter that wraps the Halmos symbolic execution engine to conform to the
 * unified IAnalyzer interface. Halmos is a Foundry-compatible symbolic EVM
 * from a16z that proves or disproves check_* test functions.
 *
 * Install: https://github.com/a16z/halmos
 *   pip install halmos
 */

import { BaseAnalyzer } from "../IAnalyzer.js";
import type {
  AnalyzerInput,
  AnalyzerResult,
  AnalyzerCapabilities,
  AnalyzerAvailability,
  HalmosOptions,
} from "../types.js";
import { checkToolAvailable, executeCommand } from "../../utils/executor.js";
import { Severity, type Finding } from "../../types/index.js";
import { logger } from "../../utils/logger.js";

// ============================================================================
// Halmos Adapter
// ============================================================================

export class HalmosAdapter extends BaseAnalyzer<HalmosOptions> {
  readonly id = "halmos" as const;
  readonly name = "Halmos Symbolic Execution";
  readonly description =
    "a16z symbolic execution engine for Solidity. Formally verifies check_* " +
    "test functions by exploring all possible execution paths using an SMT solver.";

  readonly capabilities: AnalyzerCapabilities = {
    requiresExternalTool: true,
    externalToolName: "halmos",
    supportsSourceInput: false,
    supportsOptions: true,
    supportsParallel: true,
    detectorCount: 0, // Finding count depends on check_* functions defined
  };

  private cachedAvailability: AnalyzerAvailability | null = null;
  private availabilityCacheTime = 0;
  private static readonly CACHE_TTL = 60_000;

  async checkAvailability(): Promise<AnalyzerAvailability> {
    const now = Date.now();
    if (this.cachedAvailability && now - this.availabilityCacheTime < HalmosAdapter.CACHE_TTL) {
      return this.cachedAvailability;
    }

    try {
      const result = await checkToolAvailable("halmos");

      this.cachedAvailability = {
        analyzerId: this.id,
        status: result.available ? "available" : "unavailable",
        message: result.available
          ? "Halmos is installed and ready"
          : "Halmos is not installed. Install with: pip install halmos " +
            "(requires Foundry project with check_* test functions)",
        version: result.version,
        toolPath: result.path,
      };
    } catch (error) {
      this.cachedAvailability = {
        analyzerId: this.id,
        status: "error",
        message: `Failed to check Halmos: ${error instanceof Error ? error.message : String(error)}`,
      };
    }

    this.availabilityCacheTime = now;
    return this.cachedAvailability;
  }

  getDefaultOptions(): HalmosOptions {
    return {
      timeout: 300_000, // 5 minutes — symbolic execution can be slow
      includeInformational: false,
      loopBound: 3,
      solverTimeout: 60,
    };
  }

  protected async doAnalyze(input: AnalyzerInput, options: HalmosOptions): Promise<AnalyzerResult> {
    logger.info(`[HalmosAdapter] Verifying ${input.contractPath}`);
    const warnings: string[] = [];

    const args = buildHalmosArgs(options);

    const result = await executeCommand("halmos", args, {
      cwd: input.projectRoot,
      timeout: options.timeout,
    });

    // Halmos exits non-zero when counterexamples are found — parse output regardless of exit code
    const output = result.stdout + result.stderr;
    const findings = parseHalmosOutput(output, input.contractPath, warnings);

    if (result.exitCode !== 0 && findings.length === 0) {
      logger.warn(`[HalmosAdapter] Non-zero exit (${result.exitCode}): ${result.stderr}`);
      warnings.push(
        "Halmos run failed. Ensure the project compiles with Foundry and has check_* test functions."
      );
      warnings.push(
        "Tip: Add symbolic tests like: function check_balanceNeverOverflows(uint256 a, uint256 b) public { ... }"
      );
    }

    const passCount = (output.match(/\[PASS\]/g) ?? []).length;
    const failCount = (output.match(/\[FAIL\]/g) ?? []).length;

    return {
      ...this.createSuccessResult(findings, { detectorCount: findings.length }, warnings),
      analyzerId: this.id,
      executionTime: 0,
      metadata: {
        detectorCount: findings.length,
        toolVersion: result.stderr?.match(/halmos\s+([\d.]+)/i)?.[1],
        functionFilter: options.functionFilter,
        loopBound: options.loopBound,
        passCount,
        failCount,
      },
      warnings,
    };
  }
}

// ============================================================================
// Helpers
// ============================================================================

function buildHalmosArgs(options: HalmosOptions): string[] {
  const args: string[] = [];

  if (options.functionFilter) {
    args.push("--function", options.functionFilter);
  }

  if (options.loopBound !== undefined) {
    args.push("--loop", String(options.loopBound));
  }

  if (options.solverTimeout !== undefined) {
    args.push("--solver-timeout", String(options.solverTimeout));
  }

  if (options.contractName) {
    args.push("--contract", options.contractName);
  }

  // Output in JSON-like format for easier parsing
  args.push("--statistics");

  return args;
}

function parseHalmosOutput(output: string, contractPath: string, warnings: string[]): Finding[] {
  const findings: Finding[] = [];

  // Match lines like: [FAIL] check_functionName() (counterexample: ...)
  const failPattern = /\[FAIL\]\s+(check_\w+)\s*\([^)]*\)(?:\s+\(counterexample:([^)]+)\))?/g;
  let match;

  while ((match = failPattern.exec(output)) !== null) {
    const funcName = match[1];
    const counterexample = match[2]?.trim();

    findings.push({
      id: `halmos-${funcName}-violated`,
      title: `Symbolic Property Violated: ${funcName}`,
      severity: Severity.HIGH,
      description:
        `Halmos found a counterexample that violates the symbolic property "${funcName}". ` +
        (counterexample ? `Counterexample: ${counterexample}. ` : "") +
        "This means there exists an input combination that causes the property to fail.",
      location: { file: contractPath, lines: [0, 0] },
      recommendation:
        "Review the failing check_* function and the counterexample inputs provided by Halmos. " +
        "Fix the underlying logic that allows the invariant to be violated, or tighten " +
        "the preconditions using vm.assume() to exclude invalid states.",
      detector: "halmos",
      confidence: "high",
      references: [
        "https://github.com/a16z/halmos",
        "https://a16zcrypto.com/posts/article/symbolic-testing-with-halmos/",
      ],
    });
  }

  // Also match assertion violations: AssertionError or revert in symbolic path
  const assertPattern = /\[FAIL\]\s+(check_\w+).*?AssertionError/g;
  while ((match = assertPattern.exec(output)) !== null) {
    const funcName = match[1];
    // Avoid duplicates
    if (!findings.some((f) => f.id === `halmos-${funcName}-violated`)) {
      findings.push({
        id: `halmos-${funcName}-assertion`,
        title: `Assertion Violation: ${funcName}`,
        severity: Severity.HIGH,
        description:
          `Halmos found an execution path that triggers an assertion failure in "${funcName}". ` +
          "The symbolic executor explored all paths and found inputs that cause assert() to fail.",
        location: { file: contractPath, lines: [0, 0] },
        recommendation:
          "Review the assertion conditions in the function and ensure they hold for all " +
          "valid symbolic inputs. Add vm.assume() to restrict the symbolic input space if needed.",
        detector: "halmos",
        confidence: "high",
        references: ["https://github.com/a16z/halmos"],
      });
    }
  }

  if (findings.length === 0 && output.length > 0 && !output.includes("[PASS]")) {
    warnings.push("Could not parse Halmos output — check raw output for results");
  }

  return findings;
}
