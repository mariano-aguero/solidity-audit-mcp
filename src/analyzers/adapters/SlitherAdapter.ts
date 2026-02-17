/**
 * Slither Adapter
 *
 * Adapter that wraps the Slither static analyzer to conform
 * to the unified IAnalyzer interface.
 */

import { BaseAnalyzer } from "../IAnalyzer.js";
import type {
  AnalyzerInput,
  AnalyzerResult,
  AnalyzerCapabilities,
  AnalyzerAvailability,
  SlitherOptions,
} from "../types.js";
import { runSlither } from "../slither.js";
import { checkToolAvailable } from "../../utils/executor.js";
import { logger } from "../../utils/logger.js";

// ============================================================================
// Slither Adapter
// ============================================================================

export class SlitherAdapter extends BaseAnalyzer<SlitherOptions> {
  readonly id = "slither" as const;
  readonly name = "Slither Static Analyzer";
  readonly description =
    "Python-based static analysis framework with 90+ vulnerability detectors, " +
    "including reentrancy, access control, and arithmetic issues.";

  readonly capabilities: AnalyzerCapabilities = {
    requiresExternalTool: true,
    externalToolName: "slither",
    supportsSourceInput: false,
    supportsOptions: true,
    supportsParallel: true,
    detectorCount: 90,
  };

  private cachedAvailability: AnalyzerAvailability | null = null;
  private availabilityCacheTime = 0;
  private static readonly CACHE_TTL = 60_000; // 1 minute

  /**
   * Check if Slither is installed and available.
   */
  async checkAvailability(): Promise<AnalyzerAvailability> {
    // Return cached result if still valid
    const now = Date.now();
    if (this.cachedAvailability && now - this.availabilityCacheTime < SlitherAdapter.CACHE_TTL) {
      return this.cachedAvailability;
    }

    try {
      const result = await checkToolAvailable("slither");

      this.cachedAvailability = {
        analyzerId: this.id,
        status: result.available ? "available" : "unavailable",
        message: result.available
          ? "Slither is installed and ready"
          : "Slither is not installed. Install with: pip install slither-analyzer",
        version: result.version,
        toolPath: result.path,
      };
    } catch (error) {
      this.cachedAvailability = {
        analyzerId: this.id,
        status: "error",
        message: `Failed to check Slither availability: ${error instanceof Error ? error.message : String(error)}`,
      };
    }

    this.availabilityCacheTime = now;
    return this.cachedAvailability;
  }

  /**
   * Get default Slither options.
   */
  getDefaultOptions(): SlitherOptions {
    return {
      timeout: 120_000,
      includeInformational: false,
      filterPaths: ["node_modules", "lib", "test", "tests", "mock", "mocks"],
    };
  }

  /**
   * Run Slither analysis.
   */
  protected async doAnalyze(
    input: AnalyzerInput,
    options: SlitherOptions
  ): Promise<AnalyzerResult> {
    const warnings: string[] = [];

    logger.info(`[SlitherAdapter] Analyzing ${input.contractPath}`);

    try {
      // Run the existing Slither implementation
      const findings = await runSlither(input.contractPath, input.projectRoot, {
        filterPaths: options.filterPaths,
        detectors: options.detectors,
        excludeDetectors: options.excludeDetectors,
        timeout: options.timeout,
      });

      // Filter out informational if not requested
      const filteredFindings = options.includeInformational
        ? findings
        : findings.filter((f) => f.severity !== "informational");

      logger.info(`[SlitherAdapter] Found ${filteredFindings.length} findings`);

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
        executionTime: 0, // Will be set by base class
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      logger.error(`[SlitherAdapter] Analysis failed: ${errorMessage}`);

      // Check for common errors and provide helpful messages
      if (errorMessage.includes("compilation")) {
        warnings.push("Contract compilation failed. Ensure solc version is compatible.");
      }
      if (errorMessage.includes("timeout")) {
        warnings.push(
          "Analysis timed out. Consider increasing the timeout or analyzing fewer files."
        );
      }

      throw error;
    }
  }
}

// Export singleton instance
export const slitherAdapter = new SlitherAdapter();
