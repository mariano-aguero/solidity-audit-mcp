/**
 * Aderyn Adapter
 *
 * Adapter that wraps the Aderyn static analyzer to conform
 * to the unified IAnalyzer interface.
 */

import { BaseAnalyzer } from "../IAnalyzer.js";
import type {
  AnalyzerInput,
  AnalyzerResult,
  AnalyzerCapabilities,
  AnalyzerAvailability,
  AderynOptions,
} from "../types.js";
import { runAderyn } from "../aderyn.js";
import { checkToolAvailable } from "../../utils/executor.js";
import { logger } from "../../utils/logger.js";

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

  /**
   * Check if Aderyn is installed and available.
   */
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

  /**
   * Get default Aderyn options.
   */
  getDefaultOptions(): AderynOptions {
    return {
      timeout: 120_000,
      includeInformational: false,
      exclude: ["node_modules", "lib", "test", "tests"],
    };
  }

  /**
   * Run Aderyn analysis.
   */
  protected async doAnalyze(input: AnalyzerInput, options: AderynOptions): Promise<AnalyzerResult> {
    const warnings: string[] = [];

    logger.info(`[AderynAdapter] Analyzing ${input.contractPath}`);

    try {
      // Run the existing Aderyn implementation
      const findings = await runAderyn(input.contractPath, input.projectRoot, {
        scope: options.scope,
        exclude: options.exclude,
        timeout: options.timeout,
      });

      // Filter out informational if not requested
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
