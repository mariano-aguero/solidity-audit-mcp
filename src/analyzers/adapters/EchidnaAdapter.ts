/**
 * Echidna Adapter
 *
 * Adapter that wraps the Echidna fuzzer to conform to the unified IAnalyzer interface.
 * Echidna is a Haskell-based smart contract fuzzer from Trail of Bits.
 *
 * Install: https://github.com/crytic/echidna
 *   pip install echidna  (via crytic-compile)
 *   or use Docker: ghcr.io/crytic/echidna/echidna
 */

import { dirname, basename, join } from "node:path";
import { writeFile, unlink } from "node:fs/promises";
import { BaseAnalyzer } from "../IAnalyzer.js";
import type {
  AnalyzerInput,
  AnalyzerResult,
  AnalyzerCapabilities,
  AnalyzerAvailability,
  EchidnaOptions,
} from "../types.js";
import { checkToolAvailable, executeCommand } from "../../utils/executor.js";
import { Severity, type Finding } from "../../types/index.js";
import { logger } from "../../utils/logger.js";

// ============================================================================
// Echidna Adapter
// ============================================================================

export class EchidnaAdapter extends BaseAnalyzer<EchidnaOptions> {
  readonly id = "echidna" as const;
  readonly name = "Echidna Property Fuzzer";
  readonly description =
    "Trail of Bits fuzzer for Solidity property testing. Finds violations of " +
    "user-defined invariants and assertions through guided fuzzing.";

  readonly capabilities: AnalyzerCapabilities = {
    requiresExternalTool: true,
    externalToolName: "echidna",
    supportsSourceInput: false,
    supportsOptions: true,
    supportsParallel: false, // Echidna uses all available cores internally
    detectorCount: 0, // Finding count depends on properties defined
  };

  private cachedAvailability: AnalyzerAvailability | null = null;
  private availabilityCacheTime = 0;
  private static readonly CACHE_TTL = 60_000;

  async checkAvailability(): Promise<AnalyzerAvailability> {
    const now = Date.now();
    if (this.cachedAvailability && now - this.availabilityCacheTime < EchidnaAdapter.CACHE_TTL) {
      return this.cachedAvailability;
    }

    try {
      const result = await checkToolAvailable("echidna");

      this.cachedAvailability = {
        analyzerId: this.id,
        status: result.available ? "available" : "unavailable",
        message: result.available
          ? "Echidna is installed and ready"
          : "Echidna is not installed. Install from: https://github.com/crytic/echidna/releases " +
            "or via Docker: docker pull ghcr.io/crytic/echidna/echidna",
        version: result.version,
        toolPath: result.path,
      };
    } catch (error) {
      this.cachedAvailability = {
        analyzerId: this.id,
        status: "error",
        message: `Failed to check Echidna: ${error instanceof Error ? error.message : String(error)}`,
      };
    }

    this.availabilityCacheTime = now;
    return this.cachedAvailability;
  }

  getDefaultOptions(): EchidnaOptions {
    return {
      timeout: 300_000, // 5 minutes — fuzzing takes longer
      includeInformational: false,
      testLimit: 50_000,
      testMode: "property",
    };
  }

  protected async doAnalyze(
    input: AnalyzerInput,
    options: EchidnaOptions
  ): Promise<AnalyzerResult> {
    logger.info(`[EchidnaAdapter] Fuzzing ${input.contractPath}`);
    const warnings: string[] = [];
    const configPath = join(dirname(input.contractPath), ".echidna-mcp.yaml");

    // Write temporary Echidna config
    const config = buildEchidnaConfig(options);
    await writeFile(configPath, config, "utf-8");

    try {
      const contractName = options.contractName ?? basename(input.contractPath, ".sol");

      const args = [
        input.contractPath,
        "--contract",
        contractName,
        "--config",
        configPath,
        "--format",
        "json",
      ];

      const result = await executeCommand("echidna", args, {
        cwd: input.projectRoot,
        timeout: options.timeout,
      });

      // Echidna exits non-zero when violations are found — parse output regardless of exit code
      const output = result.stdout || result.stderr;
      const findings = parseEchidnaOutput(output, input.contractPath, warnings);

      if (result.exitCode !== 0 && findings.length === 0) {
        logger.warn(`[EchidnaAdapter] Non-zero exit (${result.exitCode}): ${result.stderr}`);
        warnings.push(
          "Echidna run failed. Ensure the contract compiles and has echidna_ prefixed property functions."
        );
        warnings.push(
          "Tip: Add properties like: function echidna_balanceNeverZero() public view returns (bool) { return totalSupply > 0; }"
        );
      }

      return {
        ...this.createSuccessResult(findings, { detectorCount: findings.length }, warnings),
        analyzerId: this.id,
        executionTime: 0,
        metadata: {
          detectorCount: findings.length,
          toolVersion: result.stderr?.match(/echidna (\d+\.\d+\.\d+)/)?.[1],
          testMode: options.testMode,
          testLimit: options.testLimit,
        },
        warnings,
      };
    } finally {
      await unlink(configPath).catch(() => {});
    }
  }
}

// ============================================================================
// Helpers
// ============================================================================

function buildEchidnaConfig(options: EchidnaOptions): string {
  return [
    `testLimit: ${options.testLimit ?? 50000}`,
    `testMode: "${options.testMode ?? "property"}"`,
    options.corpusDir ? `corpusDir: "${options.corpusDir}"` : "",
    options.solcVersion ? `solcVersion: "${options.solcVersion}"` : "",
    "coverage: true",
    "shrinkLimit: 5000",
  ]
    .filter(Boolean)
    .join("\n");
}

function parseEchidnaOutput(output: string, contractPath: string, warnings: string[]): Finding[] {
  const findings: Finding[] = [];

  try {
    // Try JSON parsing first
    const parsed = JSON.parse(output);
    if (Array.isArray(parsed)) {
      for (const item of parsed) {
        if (item.status === "failed" || item.passed === false) {
          findings.push({
            id: `echidna-${item.name ?? "property"}-violated`,
            title: `Property Violated: ${item.name ?? "unknown"}`,
            severity: Severity.HIGH,
            description:
              `Echidna found a sequence of transactions that violates the property "${item.name}". ` +
              `This indicates a real bug in the contract's invariants.`,
            location: { file: contractPath, lines: [0, 0] },
            recommendation:
              "Review the failing property and the call sequence that triggers it. " +
              "Fix the underlying logic that allows the invariant to be violated.",
            detector: "echidna",
            confidence: "high",
            references: ["https://github.com/crytic/echidna"],
          });
        }
      }
    }
  } catch {
    // Fallback: parse text output for failed properties
    const failedPattern = /FAILED!\s+(\w+)/g;
    let match;
    while ((match = failedPattern.exec(output)) !== null) {
      findings.push({
        id: `echidna-${match[1]}-violated`,
        title: `Property Violated: ${match[1]}`,
        severity: Severity.HIGH,
        description:
          `Echidna found a call sequence that violates property "${match[1]}". ` +
          "Review the shrunk call sequence in the output.",
        location: { file: contractPath, lines: [0, 0] },
        recommendation:
          "Fix the logic that allows this property to be violated. " +
          "Review the minimal reproducing call sequence provided by Echidna.",
        detector: "echidna",
        confidence: "high",
        references: ["https://github.com/crytic/echidna"],
      });
    }

    if (findings.length === 0 && output.length > 0) {
      warnings.push("Could not parse Echidna output — check raw output for results");
    }
  }

  return findings;
}
