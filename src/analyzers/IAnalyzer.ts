/**
 * IAnalyzer Interface
 *
 * Defines the contract that all analyzer adapters must implement.
 * This is the core of the Adapter pattern, providing a unified
 * interface for diverse analyzer implementations.
 *
 * Design Patterns Used:
 * - Adapter Pattern: Normalizes different analyzer interfaces
 * - Strategy Pattern: Allows swapping analyzers at runtime
 * - Template Method: Base class provides common behavior
 */

import type {
  AnalyzerId,
  AnalyzerInput,
  AnalyzerResult,
  AnalyzerCapabilities,
  AnalyzerAvailability,
  BaseAnalyzerOptions,
} from "./types.js";

// ============================================================================
// Core Interface
// ============================================================================

/**
 * Interface that all analyzer adapters must implement.
 *
 * @example
 * ```typescript
 * class SlitherAdapter implements IAnalyzer {
 *   readonly id = "slither";
 *   readonly name = "Slither Static Analyzer";
 *
 *   async analyze(input: AnalyzerInput): Promise<AnalyzerResult> {
 *     // Implementation
 *   }
 * }
 * ```
 */
export interface IAnalyzer<TOptions extends BaseAnalyzerOptions = BaseAnalyzerOptions> {
  // -------------------------------------------------------------------------
  // Identity
  // -------------------------------------------------------------------------

  /** Unique identifier for this analyzer */
  readonly id: AnalyzerId;

  /** Human-readable name */
  readonly name: string;

  /** Description of the analyzer's purpose */
  readonly description: string;

  // -------------------------------------------------------------------------
  // Capabilities
  // -------------------------------------------------------------------------

  /** Analyzer capabilities and requirements */
  readonly capabilities: AnalyzerCapabilities;

  // -------------------------------------------------------------------------
  // Lifecycle Methods
  // -------------------------------------------------------------------------

  /**
   * Check if the analyzer is available and ready to use.
   * For external tools, this checks if the tool is installed.
   * For library-based analyzers, this always returns available.
   *
   * @returns Availability status with details
   */
  checkAvailability(): Promise<AnalyzerAvailability>;

  /**
   * Initialize the analyzer (optional setup before analysis).
   * Called once before the first analysis.
   *
   * @throws Error if initialization fails
   */
  initialize?(): Promise<void>;

  /**
   * Clean up resources after analysis is complete.
   * Called after all analyses are done.
   */
  dispose?(): Promise<void>;

  // -------------------------------------------------------------------------
  // Analysis
  // -------------------------------------------------------------------------

  /**
   * Run the security analysis on the given input.
   *
   * @param input - Normalized input containing contract path, source, etc.
   * @param options - Analyzer-specific options
   * @returns Standardized result with findings and metadata
   *
   * @example
   * ```typescript
   * const result = await analyzer.analyze({
   *   contractPath: "/path/to/Contract.sol",
   *   projectRoot: "/path/to/project",
   * });
   *
   * console.log(`Found ${result.findings.length} issues`);
   * ```
   */
  analyze(input: AnalyzerInput, options?: TOptions): Promise<AnalyzerResult>;

  // -------------------------------------------------------------------------
  // Configuration
  // -------------------------------------------------------------------------

  /**
   * Get the default options for this analyzer.
   *
   * @returns Default options merged with any user-provided options
   */
  getDefaultOptions(): TOptions;

  /**
   * Validate options before analysis.
   *
   * @param options - Options to validate
   * @returns Validated options or throws if invalid
   */
  validateOptions?(options: TOptions): TOptions;
}

// ============================================================================
// Abstract Base Class
// ============================================================================

/**
 * Abstract base class that provides common functionality for all analyzers.
 * Implements the Template Method pattern for shared behavior.
 */
export abstract class BaseAnalyzer<
  TOptions extends BaseAnalyzerOptions = BaseAnalyzerOptions,
> implements IAnalyzer<TOptions> {
  abstract readonly id: AnalyzerId;
  abstract readonly name: string;
  abstract readonly description: string;
  abstract readonly capabilities: AnalyzerCapabilities;

  // Default timeout: 2 minutes
  protected static readonly DEFAULT_TIMEOUT = 120_000;

  /**
   * Check analyzer availability. Override for external tools.
   */
  async checkAvailability(): Promise<AnalyzerAvailability> {
    // Library-based analyzers are always available
    return {
      analyzerId: this.id,
      status: "available",
      message: `${this.name} is ready`,
    };
  }

  /**
   * Get default options. Override to customize.
   */
  getDefaultOptions(): TOptions {
    return {
      timeout: BaseAnalyzer.DEFAULT_TIMEOUT,
      includeInformational: false,
    } as TOptions;
  }

  /**
   * Validate options. Override for analyzer-specific validation.
   */
  validateOptions(options: TOptions): TOptions {
    const validated = { ...this.getDefaultOptions(), ...options };

    // Ensure timeout is reasonable
    if (validated.timeout && (validated.timeout < 1000 || validated.timeout > 600_000)) {
      throw new Error("Timeout must be between 1 second and 10 minutes");
    }

    return validated;
  }

  /**
   * Template method for analysis. Handles timing and error wrapping.
   */
  async analyze(input: AnalyzerInput, options?: TOptions): Promise<AnalyzerResult> {
    const startTime = Date.now();
    const mergedOptions = this.validateOptions(options ?? ({} as TOptions));
    const warnings: string[] = [];

    try {
      // Check availability first
      const availability = await this.checkAvailability();
      if (availability.status !== "available") {
        return this.createErrorResult(
          startTime,
          `${this.name} is not available: ${availability.message}`,
          warnings
        );
      }

      // Perform the actual analysis (implemented by subclasses)
      const result = await this.doAnalyze(input, mergedOptions);

      return {
        ...result,
        analyzerId: this.id,
        executionTime: Date.now() - startTime,
        warnings: [...warnings, ...result.warnings],
      };
    } catch (error) {
      return this.createErrorResult(
        startTime,
        error instanceof Error ? error.message : String(error),
        warnings
      );
    }
  }

  /**
   * Abstract method that subclasses must implement.
   * This is where the actual analysis logic goes.
   */
  protected abstract doAnalyze(input: AnalyzerInput, options: TOptions): Promise<AnalyzerResult>;

  /**
   * Helper to create a standardized error result.
   */
  protected createErrorResult(
    startTime: number,
    error: string,
    warnings: string[]
  ): AnalyzerResult {
    return {
      analyzerId: this.id,
      success: false,
      findings: [],
      executionTime: Date.now() - startTime,
      metadata: { detectorCount: 0 },
      error,
      warnings,
    };
  }

  /**
   * Helper to create a standardized success result.
   */
  protected createSuccessResult(
    findings: import("../types/index.js").Finding[],
    metadata: Partial<import("./types.js").AnalyzerMetadata>,
    warnings: string[] = []
  ): Omit<AnalyzerResult, "analyzerId" | "executionTime"> {
    return {
      success: true,
      findings,
      metadata: {
        detectorCount: metadata.detectorCount ?? 0,
        ...metadata,
      },
      warnings,
    };
  }
}
