/**
 * Core types for the MCP Audit Server
 */

export enum Severity {
  CRITICAL = "critical",
  HIGH = "high",
  MEDIUM = "medium",
  LOW = "low",
  INFORMATIONAL = "informational",
}

export type Confidence = "high" | "medium" | "low";

export type DetectorSource =
  | "slither"
  | "aderyn"
  | "manual"
  | "gas-optimizer"
  | `custom:${string}`
  | `slang:${string}`;

export type Visibility = "public" | "private" | "internal" | "external";

export type StateMutability = "pure" | "view" | "payable" | "nonpayable";

export interface SourceLocation {
  file: string;
  lines?: [number, number];
  function?: string;
}

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  description: string;
  location: SourceLocation;
  recommendation: string;
  detector: DetectorSource;
  confidence: Confidence;
  references?: string[];
  swcId?: string;
}

export interface FunctionInfo {
  name: string;
  visibility: Visibility;
  modifiers: string[];
  stateMutability: StateMutability;
  parameters?: ParameterInfo[];
  returnTypes?: string[];
}

export interface ParameterInfo {
  name: string;
  type: string;
}

export interface VariableInfo {
  name: string;
  type: string;
  visibility: Visibility;
  constant?: boolean;
  immutable?: boolean;
}

export interface ContractInfo {
  name: string;
  path: string;
  compiler: string;
  functions: FunctionInfo[];
  stateVariables: VariableInfo[];
  inherits: string[];
  interfaces: string[];
  hasConstructor: boolean;
  usesProxy: boolean;
  license?: string;
  isAbstract?: boolean;
  isLibrary?: boolean;
}

export interface AuditSummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  informational: number;
}

export interface AuditReport {
  contractName: string;
  contractPath: string;
  timestamp: string;
  summary: AuditSummary;
  findings: Finding[];
  testCoverage?: number;
  toolsUsed: string[];
  contractInfo?: ContractInfo;
  gasOptimizations?: GasOptimization[];
}

export interface GasOptimization {
  title: string;
  description: string;
  location: SourceLocation;
  estimatedSavings?: string;
}

export interface ToolResult<T = unknown> {
  success: boolean;
  data?: T;
  error?: string;
  executionTime?: number;
}

export interface SlitherOutput {
  success: boolean;
  error?: string;
  results?: {
    detectors: SlitherDetector[];
  };
}

export interface SlitherDetector {
  check: string;
  impact: string;
  confidence: string;
  description: string;
  elements: SlitherElement[];
  first_markdown_element?: string;
  markdown?: string;
}

export interface SlitherElement {
  type: string;
  name: string;
  source_mapping: {
    filename_relative: string;
    lines: number[];
    starting_column: number;
    ending_column: number;
  };
}

export interface AderynOutput {
  issues: AderynIssue[];
}

export interface AderynIssue {
  title: string;
  severity: string;
  description: string;
  instances: AderynInstance[];
}

export interface AderynInstance {
  contract: string;
  file: string;
  line: number;
  source: string;
}

export interface ForgeTestResult {
  success: boolean;
  testsPassed: number;
  testsFailed: number;
  testsSkipped: number;
  coverage?: number;
  duration: number;
  details: ForgeTestDetail[];
}

export interface ForgeTestDetail {
  name: string;
  status: "passed" | "failed" | "skipped";
  gasUsed?: number;
  duration?: number;
  reason?: string;
}

export interface SWCEntry {
  id: string;
  title: string;
  description: string;
  remediation: string;
}

// ============================================================================
// Diff Analyzer Types
// ============================================================================

export interface DiffLine {
  lineNumber: number;
  content: string;
}

export interface DiffHunk {
  oldStart: number;
  oldCount: number;
  newStart: number;
  newCount: number;
  lines: string[];
}

export interface DiffSummary {
  linesAdded: number;
  linesRemoved: number;
  functionsChanged: number;
}

export interface DiffResult {
  oldFile: string;
  newFile: string;
  addedLines: DiffLine[];
  removedLines: DiffLine[];
  modifiedFunctions: string[];
  modifiedStateVars: string[];
  newFunctions: string[];
  removedFunctions: string[];
  hunks: DiffHunk[];
  summary: DiffSummary;
}

export type ContextType = "function" | "stateVariable" | "modifier" | "event" | "general";

export interface ChangedContext {
  type: ContextType;
  name: string;
  startLine: number;
  endLine: number;
  content: string;
  changeType: "added" | "removed" | "modified";
  surroundingContext: {
    before: string[];
    after: string[];
  };
}

export type ChangeRiskLevel = "critical" | "high" | "medium" | "low";

export interface ChangeFlag {
  flag: string;
  description: string;
  severity: ChangeRiskLevel;
  location?: {
    function?: string;
    line?: number;
  };
}

export interface ChangeRiskAssessment {
  riskLevel: ChangeRiskLevel;
  changeFlags: ChangeFlag[];
  summary: string;
  recommendations: string[];
}
