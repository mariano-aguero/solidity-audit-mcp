/**
 * Analyzer Orchestrator
 *
 * Coordinates parallel execution of multiple analyzers with:
 * - Concurrency control
 * - Timeout management
 * - Result deduplication
 * - Error handling and graceful degradation
 *
 * Design Patterns:
 * - Facade Pattern: Simplifies analyzer coordination
 * - Strategy Pattern: Swappable deduplication strategies
 * - Observer Pattern: Progress callbacks (optional)
 */

import type { Finding } from "../types/index.js";
import type { IAnalyzer } from "./IAnalyzer.js";
import type {
  AnalyzerId,
  AnalyzerInput,
  AnalyzerResult,
  OrchestratorConfig,
  OrchestratorResult,
  BaseAnalyzerOptions,
} from "./types.js";
import { getAnalyzerRegistry } from "./AnalyzerRegistry.js";
import { deduplicateFindings } from "./aderyn.js";
import { sortBySeverity } from "../utils/severity.js";
import { logger } from "../utils/logger.js";

// ============================================================================
// Default Configuration
// ============================================================================

const DEFAULT_CONFIG: OrchestratorConfig = {
  maxConcurrency: 3,
  pipelineTimeout: 180_000, // 3 minutes
  continueOnError: true,
};

// ============================================================================
// Progress Callback Types
// ============================================================================

export type AnalyzerProgress = {
  analyzerId: AnalyzerId;
  status: "started" | "completed" | "failed";
  result?: AnalyzerResult;
  error?: string;
};

export type ProgressCallback = (progress: AnalyzerProgress) => void;

// ============================================================================
// Orchestrator Class
// ============================================================================

/**
 * Orchestrates the execution of multiple analyzers.
 *
 * @example
 * ```typescript
 * const orchestrator = new AnalyzerOrchestrator();
 *
 * const result = await orchestrator.analyze({
 *   contractPath: "/path/to/Contract.sol",
 *   projectRoot: "/path/to/project",
 * });
 *
 * console.log(`Found ${result.findings.length} unique findings`);
 * ```
 */
export class AnalyzerOrchestrator {
  private config: OrchestratorConfig;
  private progressCallback?: ProgressCallback;

  constructor(config: Partial<OrchestratorConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  // -------------------------------------------------------------------------
  // Configuration
  // -------------------------------------------------------------------------

  /**
   * Set the progress callback for status updates.
   */
  onProgress(callback: ProgressCallback): this {
    this.progressCallback = callback;
    return this;
  }

  /**
   * Update configuration.
   */
  configure(config: Partial<OrchestratorConfig>): this {
    this.config = { ...this.config, ...config };
    return this;
  }

  // -------------------------------------------------------------------------
  // Main Analysis
  // -------------------------------------------------------------------------

  /**
   * Run all available analyzers on the input.
   *
   * @param input - Analysis input (contract path, project root, etc.)
   * @param options - Options to pass to all analyzers
   * @returns Combined and deduplicated results
   */
  async analyze(input: AnalyzerInput, options?: BaseAnalyzerOptions): Promise<OrchestratorResult> {
    const startTime = Date.now();
    const warnings: string[] = [];

    logger.info(`[Orchestrator] Starting analysis of ${input.contractPath}`);

    // -----------------------------------------------------------------------
    // 1. Determine which analyzers to run
    // -----------------------------------------------------------------------
    const analyzersToRun = await this.selectAnalyzers();

    if (analyzersToRun.length === 0) {
      warnings.push("No analyzers available");
      return this.createEmptyResult(startTime, warnings);
    }

    logger.info(
      `[Orchestrator] Running ${analyzersToRun.length} analyzers: ` +
        `${analyzersToRun.map((a) => a.id).join(", ")}`
    );

    // -----------------------------------------------------------------------
    // 2. Run analyzers with concurrency control and timeout
    // -----------------------------------------------------------------------
    const analyzerResults = await this.runAnalyzersWithTimeout(
      analyzersToRun,
      input,
      options,
      warnings
    );

    // -----------------------------------------------------------------------
    // 3. Deduplicate findings across analyzers
    // -----------------------------------------------------------------------
    const deduplicatedFindings = this.deduplicateResults(analyzerResults, warnings);

    // -----------------------------------------------------------------------
    // 4. Sort findings by severity
    // -----------------------------------------------------------------------
    const sortedFindings = sortBySeverity(deduplicatedFindings);

    // -----------------------------------------------------------------------
    // 5. Build result
    // -----------------------------------------------------------------------
    const executionTime = Date.now() - startTime;

    logger.info(
      `[Orchestrator] Analysis complete in ${executionTime}ms. ` +
        `Found ${sortedFindings.length} unique findings.`
    );

    return {
      findings: sortedFindings,
      analyzerResults,
      executionTime,
      analyzersUsed: Array.from(analyzerResults.keys()),
      warnings,
    };
  }

  /**
   * Run specific analyzers by ID.
   *
   * @param analyzerIds - IDs of analyzers to run
   * @param input - Analysis input
   * @param options - Options to pass to analyzers
   */
  async analyzeWith(
    analyzerIds: AnalyzerId[],
    input: AnalyzerInput,
    options?: BaseAnalyzerOptions
  ): Promise<OrchestratorResult> {
    const startTime = Date.now();
    const warnings: string[] = [];
    const analyzerRegistry = getAnalyzerRegistry();

    // Get specified analyzers
    const analyzers: IAnalyzer[] = [];
    for (const id of analyzerIds) {
      const analyzer = analyzerRegistry.get(id);
      if (analyzer) {
        analyzers.push(analyzer);
      } else {
        warnings.push(`Analyzer not found: ${id}`);
      }
    }

    if (analyzers.length === 0) {
      return this.createEmptyResult(startTime, warnings);
    }

    // Run analysis
    const analyzerResults = await this.runAnalyzersWithTimeout(analyzers, input, options, warnings);

    const deduplicatedFindings = this.deduplicateResults(analyzerResults, warnings);
    const sortedFindings = sortBySeverity(deduplicatedFindings);

    return {
      findings: sortedFindings,
      analyzerResults,
      executionTime: Date.now() - startTime,
      analyzersUsed: Array.from(analyzerResults.keys()),
      warnings,
    };
  }

  // -------------------------------------------------------------------------
  // Analyzer Selection
  // -------------------------------------------------------------------------

  /**
   * Select which analyzers to run based on configuration and availability.
   */
  private async selectAnalyzers(): Promise<IAnalyzer[]> {
    const registry = getAnalyzerRegistry();
    let analyzers: IAnalyzer[];

    // Start with enabled analyzers or all
    if (this.config.enabledAnalyzers && this.config.enabledAnalyzers.length > 0) {
      analyzers = this.config.enabledAnalyzers
        .map((id) => registry.get(id))
        .filter((a): a is IAnalyzer => a !== undefined);
    } else {
      analyzers = registry.getAll();
    }

    // Remove disabled analyzers
    if (this.config.disabledAnalyzers && this.config.disabledAnalyzers.length > 0) {
      const disabledSet = new Set(this.config.disabledAnalyzers);
      analyzers = analyzers.filter((a) => !disabledSet.has(a.id));
    }

    // Check availability
    const available: IAnalyzer[] = [];
    for (const analyzer of analyzers) {
      const availability = await analyzer.checkAvailability();
      if (availability.status === "available") {
        available.push(analyzer);
      } else {
        logger.info(`[Orchestrator] Skipping ${analyzer.id}: ${availability.message}`);
      }
    }

    return available;
  }

  // -------------------------------------------------------------------------
  // Parallel Execution
  // -------------------------------------------------------------------------

  /**
   * Run analyzers with concurrency control and timeout.
   */
  private async runAnalyzersWithTimeout(
    analyzers: IAnalyzer[],
    input: AnalyzerInput,
    options: BaseAnalyzerOptions | undefined,
    warnings: string[]
  ): Promise<Map<AnalyzerId, AnalyzerResult>> {
    const results = new Map<AnalyzerId, AnalyzerResult>();

    // Create a promise for the timeout
    const timeoutPromise = new Promise<never>((_, reject) => {
      setTimeout(() => reject(new Error("Pipeline timeout")), this.config.pipelineTimeout);
    });

    // Create analysis promises with concurrency control
    const analysisPromise = this.runWithConcurrency(
      analyzers,
      async (analyzer) => {
        this.notifyProgress({ analyzerId: analyzer.id, status: "started" });

        try {
          const result = await analyzer.analyze(input, options);

          this.notifyProgress({
            analyzerId: analyzer.id,
            status: "completed",
            result,
          });

          return { id: analyzer.id, result };
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : String(error);

          this.notifyProgress({
            analyzerId: analyzer.id,
            status: "failed",
            error: errorMessage,
          });

          if (!this.config.continueOnError) {
            throw error;
          }

          warnings.push(`${analyzer.name} failed: ${errorMessage}`);

          return {
            id: analyzer.id,
            result: {
              analyzerId: analyzer.id,
              success: false,
              findings: [],
              executionTime: 0,
              metadata: { detectorCount: 0 },
              error: errorMessage,
              warnings: [],
            } as AnalyzerResult,
          };
        }
      },
      this.config.maxConcurrency
    );

    // Race between analysis and timeout
    try {
      const analyzerOutputs = await Promise.race([analysisPromise, timeoutPromise]);

      for (const output of analyzerOutputs) {
        results.set(output.id, output.result);
      }
    } catch (error) {
      if (error instanceof Error && error.message === "Pipeline timeout") {
        warnings.push("Analysis pipeline timed out before all analyzers completed");
      } else {
        throw error;
      }
    }

    return results;
  }

  /**
   * Run tasks with limited concurrency (worker pool pattern).
   */
  private async runWithConcurrency<T, R>(
    items: T[],
    fn: (item: T) => Promise<R>,
    concurrency: number
  ): Promise<R[]> {
    const results: R[] = [];
    let currentIndex = 0;

    async function processNext(): Promise<void> {
      while (currentIndex < items.length) {
        const index = currentIndex++;
        const item = items[index]!;
        const result = await fn(item);
        results[index] = result;
      }
    }

    const workers: Promise<void>[] = [];
    for (let i = 0; i < Math.min(concurrency, items.length); i++) {
      workers.push(processNext());
    }

    await Promise.allSettled(workers);

    return results.filter((r): r is R => r !== undefined);
  }

  // -------------------------------------------------------------------------
  // Deduplication
  // -------------------------------------------------------------------------

  /**
   * Deduplicate findings across all analyzer results.
   */
  private deduplicateResults(
    results: Map<AnalyzerId, AnalyzerResult>,
    _warnings: string[]
  ): Finding[] {
    // Collect all findings grouped by analyzer type
    const slitherFindings: Finding[] = [];
    const aderynFindings: Finding[] = [];
    const otherFindings: Finding[] = [];

    for (const [id, result] of results) {
      if (!result.success) continue;

      switch (id) {
        case "slither":
          slitherFindings.push(...result.findings);
          break;
        case "aderyn":
          aderynFindings.push(...result.findings);
          break;
        default:
          otherFindings.push(...result.findings);
      }
    }

    // Deduplicate Slither and Aderyn findings (they often find same issues)
    let combinedFindings: Finding[];
    if (slitherFindings.length > 0 && aderynFindings.length > 0) {
      combinedFindings = deduplicateFindings(slitherFindings, aderynFindings);
      const removed = slitherFindings.length + aderynFindings.length - combinedFindings.length;
      if (removed > 0) {
        logger.info(`[Orchestrator] Deduplicated ${removed} findings between Slither and Aderyn`);
      }
    } else {
      combinedFindings = [...slitherFindings, ...aderynFindings];
    }

    // Deduplicate other findings (Slang, Gas, Custom) based on line proximity
    const allFindings = this.deduplicateByLine(combinedFindings, otherFindings);

    return allFindings;
  }

  /**
   * Simple line-based deduplication for non-overlapping analyzers.
   */
  private deduplicateByLine(existing: Finding[], newFindings: Finding[]): Finding[] {
    // Create a set of existing finding signatures
    const existingKeys = new Set(
      existing.map((f) => `${f.location.lines?.[0] ?? 0}:${f.title.toLowerCase().slice(0, 20)}`)
    );

    // Filter new findings that don't duplicate existing ones
    const unique = newFindings.filter((f) => {
      const key = `${f.location.lines?.[0] ?? 0}:${f.title.toLowerCase().slice(0, 20)}`;
      return !existingKeys.has(key);
    });

    return [...existing, ...unique];
  }

  // -------------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------------

  /**
   * Notify progress callback if set.
   */
  private notifyProgress(progress: AnalyzerProgress): void {
    if (this.progressCallback) {
      try {
        this.progressCallback(progress);
      } catch (error) {
        logger.warn(`[Orchestrator] Progress callback error: ${error}`);
      }
    }
  }

  /**
   * Create an empty result when no analyzers are available.
   */
  private createEmptyResult(startTime: number, warnings: string[]): OrchestratorResult {
    return {
      findings: [],
      analyzerResults: new Map(),
      executionTime: Date.now() - startTime,
      analyzersUsed: [],
      warnings,
    };
  }
}

// ============================================================================
// Factory Function
// ============================================================================

/**
 * Create a new orchestrator with optional configuration.
 */
export function createOrchestrator(config?: Partial<OrchestratorConfig>): AnalyzerOrchestrator {
  return new AnalyzerOrchestrator(config);
}
