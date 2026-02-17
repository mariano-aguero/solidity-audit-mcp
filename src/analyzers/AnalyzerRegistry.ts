/**
 * Analyzer Registry
 *
 * Factory and registry for managing analyzer adapters.
 * Implements the Factory and Registry patterns.
 *
 * Design Patterns:
 * - Factory Pattern: Creates analyzer instances
 * - Registry Pattern: Manages analyzer registration and lookup
 * - Singleton Pattern: Single registry instance
 */

import type { IAnalyzer } from "./IAnalyzer.js";
import type {
  AnalyzerId,
  AnalyzerRegistration,
  AnalyzerAvailability,
  BaseAnalyzerOptions,
} from "./types.js";
import { SlitherAdapter } from "./adapters/SlitherAdapter.js";
import { AderynAdapter } from "./adapters/AderynAdapter.js";
import { SlangAdapter } from "./adapters/SlangAdapter.js";
import { GasAdapter } from "./adapters/GasAdapter.js";
import { logger } from "../utils/logger.js";

// ============================================================================
// Registry Class
// ============================================================================

/**
 * Central registry for all analyzer adapters.
 *
 * @example
 * ```typescript
 * const registry = AnalyzerRegistry.getInstance();
 *
 * // Get a specific analyzer
 * const slither = registry.get("slither");
 *
 * // Get all available analyzers
 * const available = await registry.getAvailable();
 *
 * // Run analysis with a specific analyzer
 * const result = await slither.analyze(input);
 * ```
 */
export class AnalyzerRegistry {
  private static instance: AnalyzerRegistry;
  private analyzers: Map<AnalyzerId, IAnalyzer> = new Map();
  private registrations: Map<AnalyzerId, AnalyzerRegistration> = new Map();

  /**
   * Private constructor - use getInstance()
   */
  private constructor() {
    this.registerBuiltInAnalyzers();
  }

  /**
   * Get the singleton registry instance.
   */
  static getInstance(): AnalyzerRegistry {
    if (!AnalyzerRegistry.instance) {
      AnalyzerRegistry.instance = new AnalyzerRegistry();
    }
    return AnalyzerRegistry.instance;
  }

  /**
   * Register all built-in analyzers.
   */
  private registerBuiltInAnalyzers(): void {
    // Slither - Python-based static analyzer
    const slither = new SlitherAdapter();
    this.register(slither, {
      id: slither.id,
      name: slither.name,
      description: slither.description,
      capabilities: slither.capabilities,
      defaultOptions: slither.getDefaultOptions(),
    });

    // Aderyn - Rust-based static analyzer
    const aderyn = new AderynAdapter();
    this.register(aderyn, {
      id: aderyn.id,
      name: aderyn.name,
      description: aderyn.description,
      capabilities: aderyn.capabilities,
      defaultOptions: aderyn.getDefaultOptions(),
    });

    // Slang - AST-based analyzer (JavaScript)
    const slang = new SlangAdapter();
    this.register(slang, {
      id: slang.id,
      name: slang.name,
      description: slang.description,
      capabilities: slang.capabilities,
      defaultOptions: slang.getDefaultOptions(),
    });

    // Gas Optimizer - Pattern-based (JavaScript)
    const gas = new GasAdapter();
    this.register(gas, {
      id: gas.id,
      name: gas.name,
      description: gas.description,
      capabilities: gas.capabilities,
      defaultOptions: gas.getDefaultOptions(),
    });

    logger.info(`[AnalyzerRegistry] Registered ${this.analyzers.size} built-in analyzers`);
  }

  // -------------------------------------------------------------------------
  // Registration
  // -------------------------------------------------------------------------

  /**
   * Register an analyzer adapter.
   *
   * @param analyzer - The analyzer instance
   * @param registration - Registration metadata
   */
  register(analyzer: IAnalyzer, registration: AnalyzerRegistration): void {
    if (this.analyzers.has(registration.id)) {
      logger.warn(`[AnalyzerRegistry] Overwriting existing analyzer: ${registration.id}`);
    }

    this.analyzers.set(registration.id, analyzer);
    this.registrations.set(registration.id, registration);

    logger.debug(`[AnalyzerRegistry] Registered analyzer: ${registration.name}`);
  }

  /**
   * Unregister an analyzer.
   *
   * @param id - Analyzer ID to remove
   * @returns true if analyzer was removed, false if not found
   */
  unregister(id: AnalyzerId): boolean {
    const removed = this.analyzers.delete(id);
    this.registrations.delete(id);

    if (removed) {
      logger.debug(`[AnalyzerRegistry] Unregistered analyzer: ${id}`);
    }

    return removed;
  }

  // -------------------------------------------------------------------------
  // Lookup
  // -------------------------------------------------------------------------

  /**
   * Get an analyzer by ID.
   *
   * @param id - Analyzer ID
   * @returns Analyzer instance or undefined if not found
   */
  get<T extends BaseAnalyzerOptions = BaseAnalyzerOptions>(
    id: AnalyzerId
  ): IAnalyzer<T> | undefined {
    return this.analyzers.get(id) as IAnalyzer<T> | undefined;
  }

  /**
   * Get an analyzer by ID, throwing if not found.
   *
   * @param id - Analyzer ID
   * @returns Analyzer instance
   * @throws Error if analyzer not found
   */
  getOrThrow<T extends BaseAnalyzerOptions = BaseAnalyzerOptions>(id: AnalyzerId): IAnalyzer<T> {
    const analyzer = this.get<T>(id);
    if (!analyzer) {
      throw new Error(`Analyzer not found: ${id}`);
    }
    return analyzer;
  }

  /**
   * Get all registered analyzers.
   */
  getAll(): IAnalyzer[] {
    return Array.from(this.analyzers.values());
  }

  /**
   * Get all analyzer IDs.
   */
  getIds(): AnalyzerId[] {
    return Array.from(this.analyzers.keys());
  }

  /**
   * Get registration info for an analyzer.
   */
  getRegistration(id: AnalyzerId): AnalyzerRegistration | undefined {
    return this.registrations.get(id);
  }

  /**
   * Get all registration info.
   */
  getAllRegistrations(): AnalyzerRegistration[] {
    return Array.from(this.registrations.values());
  }

  // -------------------------------------------------------------------------
  // Availability
  // -------------------------------------------------------------------------

  /**
   * Check availability of a specific analyzer.
   *
   * @param id - Analyzer ID
   * @returns Availability status
   */
  async checkAvailability(id: AnalyzerId): Promise<AnalyzerAvailability> {
    const analyzer = this.get(id);
    if (!analyzer) {
      return {
        analyzerId: id,
        status: "unavailable",
        message: `Analyzer not registered: ${id}`,
      };
    }

    return analyzer.checkAvailability();
  }

  /**
   * Check availability of all registered analyzers.
   *
   * @returns Map of analyzer ID to availability status
   */
  async checkAllAvailability(): Promise<Map<AnalyzerId, AnalyzerAvailability>> {
    const results = new Map<AnalyzerId, AnalyzerAvailability>();

    const checks = await Promise.allSettled(
      this.getAll().map(async (analyzer) => ({
        id: analyzer.id,
        availability: await analyzer.checkAvailability(),
      }))
    );

    for (const result of checks) {
      if (result.status === "fulfilled") {
        results.set(result.value.id, result.value.availability);
      } else {
        // Handle rejected promise (shouldn't happen with proper error handling)
        logger.error(`[AnalyzerRegistry] Failed to check availability: ${result.reason}`);
      }
    }

    return results;
  }

  /**
   * Get all available analyzers.
   *
   * @returns List of analyzers that are ready to use
   */
  async getAvailable(): Promise<IAnalyzer[]> {
    const availabilityMap = await this.checkAllAvailability();
    const available: IAnalyzer[] = [];

    for (const [id, availability] of availabilityMap) {
      if (availability.status === "available") {
        const analyzer = this.get(id);
        if (analyzer) {
          available.push(analyzer);
        }
      }
    }

    return available;
  }

  /**
   * Get available analyzer IDs.
   *
   * @returns List of IDs for analyzers that are ready to use
   */
  async getAvailableIds(): Promise<AnalyzerId[]> {
    const available = await this.getAvailable();
    return available.map((a) => a.id);
  }

  // -------------------------------------------------------------------------
  // Filtering
  // -------------------------------------------------------------------------

  /**
   * Get analyzers that don't require external tools.
   * These are always available (JavaScript-based).
   */
  getBuiltIn(): IAnalyzer[] {
    return this.getAll().filter((a) => !a.capabilities.requiresExternalTool);
  }

  /**
   * Get analyzers that require external tools.
   */
  getExternal(): IAnalyzer[] {
    return this.getAll().filter((a) => a.capabilities.requiresExternalTool);
  }

  /**
   * Get analyzers that support source code input.
   */
  getSourceBased(): IAnalyzer[] {
    return this.getAll().filter((a) => a.capabilities.supportsSourceInput);
  }

  // -------------------------------------------------------------------------
  // Utilities
  // -------------------------------------------------------------------------

  /**
   * Get a summary of all registered analyzers.
   */
  getSummary(): string {
    const lines: string[] = ["Registered Analyzers:", ""];

    for (const reg of this.getAllRegistrations()) {
      const external = reg.capabilities.requiresExternalTool ? " (external)" : " (built-in)";
      lines.push(`  ${reg.id}${external}`);
      lines.push(`    ${reg.description}`);
      lines.push(`    Detectors: ${reg.capabilities.detectorCount}`);
      lines.push("");
    }

    return lines.join("\n");
  }

  /**
   * Reset the registry (mainly for testing).
   */
  reset(): void {
    this.analyzers.clear();
    this.registrations.clear();
    this.registerBuiltInAnalyzers();
  }
}

// Export singleton getter for convenience
export function getAnalyzerRegistry(): AnalyzerRegistry {
  return AnalyzerRegistry.getInstance();
}
