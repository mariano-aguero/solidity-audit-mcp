/**
 * Analyzer Types
 *
 * Core type definitions for the unified analyzer interface.
 * Implements the Adapter pattern to normalize different analyzer implementations.
 */

import type { Finding } from "./index.js";

// ============================================================================
// Analyzer Identification
// ============================================================================

/**
 * Unique identifier for each analyzer type
 */
export type AnalyzerId = "slither" | "aderyn" | "slang" | "gas" | "custom" | "echidna" | "halmos";

/**
 * Analyzer capability flags
 */
export interface AnalyzerCapabilities {
  /** Requires external CLI tool to be installed */
  requiresExternalTool: boolean;
  /** Name of the external tool (for availability checks) */
  externalToolName?: string;
  /** Can analyze source code directly (vs requiring file path) */
  supportsSourceInput: boolean;
  /** Supports custom configuration options */
  supportsOptions: boolean;
  /** Can run in parallel with other analyzers */
  supportsParallel: boolean;
  /** Approximate number of detectors/patterns */
  detectorCount: number;
}

// ============================================================================
// Input Types
// ============================================================================

/**
 * Normalized input for all analyzers
 */
export interface AnalyzerInput {
  /** Absolute path to the contract file */
  contractPath: string;
  /** Project root directory (for multi-file projects) */
  projectRoot: string;
  /** Source code content (optional, loaded from path if not provided) */
  source?: string;
  /** Solidity version (optional, auto-detected if not provided) */
  solidityVersion?: string;
}

/**
 * Base options that all analyzers support
 */
export interface BaseAnalyzerOptions {
  /** Execution timeout in milliseconds */
  timeout?: number;
  /** Include informational-level findings */
  includeInformational?: boolean;
}

/**
 * Slither-specific options
 */
export interface SlitherOptions extends BaseAnalyzerOptions {
  /** Paths to exclude from analysis */
  filterPaths?: string[];
  /** Specific detectors to run */
  detectors?: string[];
  /** Detectors to exclude */
  excludeDetectors?: string[];
}

/**
 * Aderyn-specific options
 */
export interface AderynOptions extends BaseAnalyzerOptions {
  /** Scope to analyze */
  scope?: string;
  /** Paths to exclude */
  exclude?: string[];
}

/**
 * Slang-specific options
 */
export interface SlangOptions extends BaseAnalyzerOptions {
  /** Specific detector IDs to run */
  detectorIds?: string[];
}

/**
 * Gas optimizer options
 */
export interface GasOptions extends BaseAnalyzerOptions {
  /** Specific patterns to check */
  patterns?: string[];
}

/**
 * Custom detector options
 */
export interface CustomDetectorOptions extends BaseAnalyzerOptions {
  /** Path to custom detector config file */
  configPath?: string;
  /** Inline detector definitions */
  detectors?: unknown[];
}

/**
 * Echidna fuzzing options
 */
export interface EchidnaOptions extends BaseAnalyzerOptions {
  /** Number of test sequences to run */
  testLimit?: number;
  /** Corpus directory for seed inputs */
  corpusDir?: string;
  /** Contract name to fuzz (required when multiple contracts in file) */
  contractName?: string;
  /** Test mode: "property" | "assertion" | "optimization" | "exploration" */
  testMode?: "property" | "assertion" | "optimization" | "exploration";
  /** Solidity version override */
  solcVersion?: string;
}

/**
 * Halmos symbolic execution options
 */
export interface HalmosOptions extends BaseAnalyzerOptions {
  /** Specific function to verify (runs all if omitted) */
  functionFilter?: string;
  /** Maximum loop unrolling depth */
  loopBound?: number;
  /** Solver timeout in seconds */
  solverTimeout?: number;
  /** Contract name to verify */
  contractName?: string;
}

/**
 * Union type for all analyzer options
 */
export type AnalyzerOptions =
  | SlitherOptions
  | AderynOptions
  | SlangOptions
  | GasOptions
  | CustomDetectorOptions
  | EchidnaOptions
  | HalmosOptions;

// ============================================================================
// Output Types
// ============================================================================

/**
 * Metadata about the analysis execution
 */
export interface AnalyzerMetadata {
  /** Number of detectors/patterns that were run */
  detectorCount: number;
  /** Parse errors encountered (for AST-based analyzers) */
  parseErrors?: string[];
  /** Tool version (if available) */
  toolVersion?: string;
  /** Raw output from the tool (for debugging) */
  rawOutput?: string;
  /** Additional analyzer-specific metadata */
  [key: string]: unknown;
}

/**
 * Standardized result from all analyzers
 */
export interface AnalyzerResult {
  /** Unique identifier of the analyzer that produced this result */
  analyzerId: AnalyzerId;
  /** Whether the analysis completed successfully */
  success: boolean;
  /** Security findings detected */
  findings: Finding[];
  /** Execution time in milliseconds */
  executionTime: number;
  /** Additional metadata about the analysis */
  metadata: AnalyzerMetadata;
  /** Error message if success is false */
  error?: string;
  /** Warnings that don't prevent analysis but should be noted */
  warnings: string[];
}

// ============================================================================
// Analyzer Status
// ============================================================================

/**
 * Current status of an analyzer
 */
export type AnalyzerStatus = "available" | "unavailable" | "error" | "disabled";

/**
 * Information about analyzer availability
 */
export interface AnalyzerAvailability {
  /** Analyzer identifier */
  analyzerId: AnalyzerId;
  /** Current status */
  status: AnalyzerStatus;
  /** Human-readable status message */
  message: string;
  /** Tool version if available */
  version?: string;
  /** Path to the tool if external */
  toolPath?: string;
}

// ============================================================================
// Orchestration Types
// ============================================================================

/**
 * Configuration for the analyzer orchestrator
 */
export interface OrchestratorConfig {
  /** Maximum concurrent analyzer executions */
  maxConcurrency: number;
  /** Global timeout for the entire analysis pipeline */
  pipelineTimeout: number;
  /** Whether to continue if an analyzer fails */
  continueOnError: boolean;
  /** Analyzers to enable (empty = all available) */
  enabledAnalyzers?: AnalyzerId[];
  /** Analyzers to explicitly disable */
  disabledAnalyzers?: AnalyzerId[];
}

/**
 * Result from the orchestrator combining all analyzer results
 */
export interface OrchestratorResult {
  /** Combined and deduplicated findings from all analyzers */
  findings: Finding[];
  /** Individual results from each analyzer */
  analyzerResults: Map<AnalyzerId, AnalyzerResult>;
  /** Total execution time */
  executionTime: number;
  /** Analyzers that were used */
  analyzersUsed: AnalyzerId[];
  /** Warnings from the orchestration process */
  warnings: string[];
}

// ============================================================================
// Factory Types
// ============================================================================

/**
 * Registration information for an analyzer
 */
export interface AnalyzerRegistration {
  /** Unique identifier */
  id: AnalyzerId;
  /** Human-readable name */
  name: string;
  /** Description of what the analyzer does */
  description: string;
  /** Analyzer capabilities */
  capabilities: AnalyzerCapabilities;
  /** Default options */
  defaultOptions: BaseAnalyzerOptions;
}
