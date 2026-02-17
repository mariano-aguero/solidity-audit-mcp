/**
 * Slang Adapter
 *
 * Adapter that wraps the Slang AST-based analyzer to conform
 * to the unified IAnalyzer interface.
 *
 * Unlike Slither/Aderyn, Slang is a JavaScript library that
 * works directly on source code without external tools.
 */

import { readFile } from "node:fs/promises";
import { BaseAnalyzer } from "../IAnalyzer.js";
import type {
  AnalyzerInput,
  AnalyzerResult,
  AnalyzerCapabilities,
  SlangOptions,
} from "../types.js";
import { analyzeWithSlang } from "../slangAnalyzer.js";
import { logger } from "../../utils/logger.js";

// ============================================================================
// Slang Adapter
// ============================================================================

export class SlangAdapter extends BaseAnalyzer<SlangOptions> {
  readonly id = "slang" as const;
  readonly name = "Slang AST Analyzer";
  readonly description =
    "AST-based analyzer using @nomicfoundation/slang for deep code analysis, " +
    "detecting patterns that require understanding of code structure.";

  readonly capabilities: AnalyzerCapabilities = {
    requiresExternalTool: false,
    supportsSourceInput: true,
    supportsOptions: true,
    supportsParallel: true,
    detectorCount: 12,
  };

  /**
   * Slang is always available (JavaScript library).
   */
  // checkAvailability is inherited from BaseAnalyzer (always available)

  /**
   * Get default Slang options.
   */
  getDefaultOptions(): SlangOptions {
    return {
      timeout: 60_000, // Slang is faster, 1 minute should be plenty
      includeInformational: true, // Slang findings are generally high-quality
    };
  }

  /**
   * Run Slang analysis.
   */
  protected async doAnalyze(input: AnalyzerInput, options: SlangOptions): Promise<AnalyzerResult> {
    const warnings: string[] = [];

    logger.info(`[SlangAdapter] Analyzing ${input.contractPath}`);

    try {
      // Load source if not provided
      let source = input.source;
      if (!source) {
        source = await readFile(input.contractPath, "utf-8");
      }

      // Run the existing Slang implementation
      const result = await analyzeWithSlang(source, input.contractPath, {
        version: input.solidityVersion,
        detectorIds: options.detectorIds,
        includeInformational: options.includeInformational,
      });

      // Add parse errors as warnings
      if (result.parseErrors.length > 0) {
        warnings.push(...result.parseErrors.map((e) => `Parse warning: ${e}`));
      }

      // Filter out informational if not requested
      const filteredFindings = options.includeInformational
        ? result.findings
        : result.findings.filter((f) => f.severity !== "informational");

      logger.info(
        `[SlangAdapter] Found ${filteredFindings.length} findings ` +
          `from ${result.detectorCount} detectors`
      );

      return {
        ...this.createSuccessResult(
          filteredFindings,
          {
            detectorCount: result.detectorCount,
            parseErrors: result.parseErrors,
          },
          warnings
        ),
        analyzerId: this.id,
        executionTime: result.executionTime,
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      logger.error(`[SlangAdapter] Analysis failed: ${errorMessage}`);
      throw error;
    }
  }
}

// Export singleton instance
export const slangAdapter = new SlangAdapter();
