/**
 * Gas Optimizer Adapter
 *
 * Adapter that wraps the gas optimization analyzer to conform
 * to the unified IAnalyzer interface.
 *
 * This is a pure JavaScript analyzer that uses regex patterns
 * to detect gas inefficiencies.
 */

import { BaseAnalyzer } from "../IAnalyzer.js";
import type { AnalyzerInput, AnalyzerResult, AnalyzerCapabilities, GasOptions } from "../types.js";
import { analyzeGasPatterns } from "../gasOptimizer.js";
import { logger } from "../../utils/logger.js";

// ============================================================================
// Gas Optimizer Adapter
// ============================================================================

export class GasAdapter extends BaseAnalyzer<GasOptions> {
  readonly id = "gas" as const;
  readonly name = "Gas Optimizer";
  readonly description =
    "Pattern-based gas optimization analyzer that detects common inefficiencies " +
    "like storage reads in loops, missing immutable/constant, and suboptimal data types.";

  readonly capabilities: AnalyzerCapabilities = {
    requiresExternalTool: false,
    supportsSourceInput: true,
    supportsOptions: true,
    supportsParallel: true,
    detectorCount: 10,
  };

  // Gas optimizer is always available (pure JavaScript)
  // checkAvailability is inherited from BaseAnalyzer

  /**
   * Get default gas optimizer options.
   */
  getDefaultOptions(): GasOptions {
    return {
      timeout: 30_000, // Gas analysis is fast
      includeInformational: true, // Gas optimizations are generally useful
    };
  }

  /**
   * Run gas optimization analysis.
   */
  protected async doAnalyze(input: AnalyzerInput, options: GasOptions): Promise<AnalyzerResult> {
    const warnings: string[] = [];

    logger.info(`[GasAdapter] Analyzing ${input.contractPath}`);

    try {
      // Run the existing gas optimizer implementation
      const findings = await analyzeGasPatterns(input.contractPath);

      // Filter by patterns if specified
      let filteredFindings = findings;
      if (options.patterns && options.patterns.length > 0) {
        filteredFindings = findings.filter((f) =>
          options.patterns!.some(
            (p) => f.id.includes(p) || f.title.toLowerCase().includes(p.toLowerCase())
          )
        );
      }

      // Filter out informational if not requested
      if (!options.includeInformational) {
        filteredFindings = filteredFindings.filter((f) => f.severity !== "informational");
      }

      logger.info(`[GasAdapter] Found ${filteredFindings.length} gas optimization opportunities`);

      return {
        ...this.createSuccessResult(
          filteredFindings,
          {
            detectorCount: this.capabilities.detectorCount,
          },
          warnings
        ),
        analyzerId: this.id,
        executionTime: 0,
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      logger.error(`[GasAdapter] Analysis failed: ${errorMessage}`);
      throw error;
    }
  }
}

// Export singleton instance
export const gasAdapter = new GasAdapter();
