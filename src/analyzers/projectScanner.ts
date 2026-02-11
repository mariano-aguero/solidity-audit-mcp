/**
 * Project Scanner
 *
 * Analyzes an entire Solidity project to understand its structure,
 * dependencies between contracts, and prioritize audit efforts.
 */

import { existsSync, readdirSync, readFileSync, statSync } from "fs";
import { join, relative, dirname, basename } from "path";
import { Finding, Severity } from "../types/index.js";
import { logger } from "../utils/logger.js";

// ============================================================================
// Types
// ============================================================================

export type ContractType = "contract" | "interface" | "library" | "abstract";
export type ProjectType = "foundry" | "hardhat" | "mixed" | "unknown";
export type AuditPriority = "critical" | "high" | "medium" | "low";

export interface ContractFile {
  path: string;
  relativePath: string;
  name: string;
  type: ContractType;
  loc: number;
  sloc: number; // Source lines of code (excluding comments/blanks)
  isUpgradeable: boolean;
  hasPayable: boolean;
  hasExternalCalls: boolean;
  hasDelegatecall: boolean;
  hasSelfdestruct: boolean;
  imports: string[];
  inherits: string[];
  priority?: AuditPriority;
}

export interface DependencyGraph {
  /** Map of contract path to list of imported contract paths */
  edges: Map<string, string[]>;
  /** Map of contract path to list of contracts that import it */
  reverseEdges: Map<string, string[]>;
  /** Contracts with circular dependencies */
  circularDependencies: string[][];
  /** Contracts ordered by number of dependents (most imported first) */
  criticalContracts: Array<{ path: string; dependentCount: number }>;
}

export interface ProjectSummary {
  totalContracts: number;
  totalInterfaces: number;
  totalLibraries: number;
  totalAbstract: number;
  totalLOC: number;
  totalSLOC: number;
  contractsWithPayable: number;
  contractsWithExternalCalls: number;
  upgradeableContracts: number;
}

export interface ProjectStructure {
  projectRoot: string;
  projectType: ProjectType;
  contracts: ContractFile[];
  dependencies: DependencyGraph;
  summary: ProjectSummary;
  findings: Finding[];
}

// ============================================================================
// Constants
// ============================================================================

/** Directories to exclude from scanning */
const EXCLUDED_DIRS = new Set([
  "node_modules",
  "lib",
  "test",
  "tests",
  "script",
  "scripts",
  "mock",
  "mocks",
  "forge-std",
  "openzeppelin-contracts",
  ".git",
  "out",
  "artifacts",
  "cache",
  "coverage",
]);

/** Patterns indicating a contract handles funds */
const FUND_HANDLING_PATTERNS = [
  /\bpayable\b/,
  /\.transfer\s*\(/,
  /\.send\s*\(/,
  /\.call\s*\{.*value/,
  /msg\.value/,
  /address\s*\(\s*this\s*\)\s*\.balance/,
];

/** Patterns indicating external calls */
const EXTERNAL_CALL_PATTERNS = [
  /\.call\s*\(/,
  /\.staticcall\s*\(/,
  /\.delegatecall\s*\(/,
  /IERC20\s*\([^)]+\)\s*\./,
  /\.safeTransfer/,
  /\.safeTransferFrom/,
];

/** Patterns indicating upgradeable contracts */
const UPGRADEABLE_PATTERNS = [
  /Upgradeable/i,
  /Initializable/,
  /UUPSUpgradeable/,
  /TransparentUpgradeableProxy/,
  /__gap/,
  /function\s+initialize\s*\(/,
];

// ============================================================================
// Project Detection
// ============================================================================

/**
 * Detect the type of Solidity project.
 */
export function detectProjectType(projectRoot: string): ProjectType {
  const hasFoundry =
    existsSync(join(projectRoot, "foundry.toml")) || existsSync(join(projectRoot, "forge.toml"));

  const hasHardhat =
    existsSync(join(projectRoot, "hardhat.config.js")) ||
    existsSync(join(projectRoot, "hardhat.config.ts"));

  if (hasFoundry && hasHardhat) {
    return "mixed";
  } else if (hasFoundry) {
    return "foundry";
  } else if (hasHardhat) {
    return "hardhat";
  }

  return "unknown";
}

/**
 * Get the source directories for a project.
 */
function getSourceDirs(projectRoot: string, _projectType: ProjectType): string[] {
  const dirs: string[] = [];

  // Common source directories
  const potentialDirs = ["src", "contracts", "sources"];

  for (const dir of potentialDirs) {
    const fullPath = join(projectRoot, dir);
    if (existsSync(fullPath) && statSync(fullPath).isDirectory()) {
      dirs.push(fullPath);
    }
  }

  // If no standard directories found, use project root
  if (dirs.length === 0) {
    dirs.push(projectRoot);
  }

  return dirs;
}

// ============================================================================
// File Discovery
// ============================================================================

/**
 * Find all Solidity files in a directory recursively.
 */
function findSolidityFiles(dir: string, projectRoot: string, files: string[] = []): string[] {
  if (!existsSync(dir)) {
    return files;
  }

  const entries = readdirSync(dir, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = join(dir, entry.name);

    if (entry.isDirectory()) {
      // Skip excluded directories
      if (EXCLUDED_DIRS.has(entry.name.toLowerCase())) {
        continue;
      }
      findSolidityFiles(fullPath, projectRoot, files);
    } else if (entry.isFile() && entry.name.endsWith(".sol")) {
      files.push(fullPath);
    }
  }

  return files;
}

// ============================================================================
// Contract Analysis
// ============================================================================

/**
 * Extract contract metadata from a Solidity file.
 */
function analyzeContractFile(filePath: string, projectRoot: string): ContractFile | null {
  try {
    const content = readFileSync(filePath, "utf-8");
    const lines = content.split("\n");

    // Count lines of code
    const loc = lines.length;
    const sloc = lines.filter((line) => {
      const trimmed = line.trim();
      return trimmed.length > 0 && !trimmed.startsWith("//") && !trimmed.startsWith("/*");
    }).length;

    // Detect contract type and name
    const { name, type } = detectContractType(content, filePath);

    // Extract imports
    const imports = extractImports(content, filePath, projectRoot);

    // Extract inheritance
    const inherits = extractInheritance(content);

    // Detect risk indicators
    const hasPayable = FUND_HANDLING_PATTERNS.some((p) => p.test(content));
    const hasExternalCalls = EXTERNAL_CALL_PATTERNS.some((p) => p.test(content));
    const hasDelegatecall = /\.delegatecall\s*\(/.test(content);
    const hasSelfdestruct = /\bselfdestruct\s*\(/.test(content);
    const isUpgradeable = UPGRADEABLE_PATTERNS.some((p) => p.test(content));

    return {
      path: filePath,
      relativePath: relative(projectRoot, filePath),
      name,
      type,
      loc,
      sloc,
      isUpgradeable,
      hasPayable,
      hasExternalCalls,
      hasDelegatecall,
      hasSelfdestruct,
      imports,
      inherits,
    };
  } catch (error) {
    logger.error(`[project-scanner] Failed to analyze ${filePath}: ${error}`);
    return null;
  }
}

/**
 * Detect the type and name of a contract.
 */
function detectContractType(
  content: string,
  filePath: string
): { name: string; type: ContractType } {
  // Try to match interface first
  const interfaceMatch = content.match(/\binterface\s+(\w+)/);
  if (interfaceMatch) {
    return { name: interfaceMatch[1]!, type: "interface" };
  }

  // Try to match library
  const libraryMatch = content.match(/\blibrary\s+(\w+)/);
  if (libraryMatch) {
    return { name: libraryMatch[1]!, type: "library" };
  }

  // Try to match abstract contract
  const abstractMatch = content.match(/\babstract\s+contract\s+(\w+)/);
  if (abstractMatch) {
    return { name: abstractMatch[1]!, type: "abstract" };
  }

  // Try to match regular contract
  const contractMatch = content.match(/\bcontract\s+(\w+)/);
  if (contractMatch) {
    return { name: contractMatch[1]!, type: "contract" };
  }

  // Fallback to filename
  return {
    name: basename(filePath, ".sol"),
    type: "contract",
  };
}

/**
 * Extract import statements from a contract.
 */
function extractImports(content: string, filePath: string, projectRoot: string): string[] {
  const imports: string[] = [];
  const importRegex = /import\s+(?:{[^}]+}\s+from\s+)?["']([^"']+)["']/g;

  let match;
  while ((match = importRegex.exec(content)) !== null) {
    const importPath = match[1]!;

    // Resolve relative imports
    if (importPath.startsWith("./") || importPath.startsWith("../")) {
      const resolvedPath = join(dirname(filePath), importPath);
      const relativePath = relative(projectRoot, resolvedPath);
      imports.push(relativePath);
    } else {
      // External or absolute import
      imports.push(importPath);
    }
  }

  return imports;
}

/**
 * Extract inheritance list from a contract.
 */
function extractInheritance(content: string): string[] {
  const inherits: string[] = [];

  // Match: contract Name is Parent1, Parent2, ...
  const inheritanceMatch = content.match(
    /\b(?:contract|interface|abstract\s+contract)\s+\w+\s+is\s+([^{]+)/
  );

  if (inheritanceMatch) {
    const parentList = inheritanceMatch[1]!;
    // Split by comma and clean up
    const parents = parentList.split(",").map((p) =>
      p
        .trim()
        .replace(/\([^)]*\)/g, "") // Remove constructor args
        .trim()
    );
    inherits.push(...parents.filter((p) => p.length > 0));
  }

  return inherits;
}

// ============================================================================
// Dependency Graph
// ============================================================================

/**
 * Build a dependency graph from contracts.
 */
export function buildDependencyGraph(contracts: ContractFile[]): DependencyGraph {
  const edges = new Map<string, string[]>();
  const reverseEdges = new Map<string, string[]>();
  const pathToContract = new Map<string, ContractFile>();

  // Index contracts by path
  for (const contract of contracts) {
    pathToContract.set(contract.relativePath, contract);
    edges.set(contract.relativePath, []);
    reverseEdges.set(contract.relativePath, []);
  }

  // Build edges from imports
  for (const contract of contracts) {
    const deps: string[] = [];

    for (const importPath of contract.imports) {
      // Try to find the imported contract
      const normalizedImport = normalizeImportPath(importPath);

      // Check if this import matches any known contract
      for (const [path] of pathToContract) {
        if (
          path === normalizedImport ||
          path.endsWith(normalizedImport) ||
          normalizedImport.endsWith(path)
        ) {
          deps.push(path);

          // Add reverse edge
          const reverseDeps = reverseEdges.get(path) ?? [];
          reverseDeps.push(contract.relativePath);
          reverseEdges.set(path, reverseDeps);
          break;
        }
      }
    }

    edges.set(contract.relativePath, deps);
  }

  // Detect circular dependencies
  const circularDependencies = detectCircularDependencies(edges);

  // Find critical contracts (most imported)
  const criticalContracts = Array.from(reverseEdges.entries())
    .map(([path, dependents]) => ({
      path,
      dependentCount: dependents.length,
    }))
    .filter((c) => c.dependentCount > 0)
    .sort((a, b) => b.dependentCount - a.dependentCount);

  return {
    edges,
    reverseEdges,
    circularDependencies,
    criticalContracts,
  };
}

/**
 * Normalize an import path for comparison.
 */
function normalizeImportPath(importPath: string): string {
  return (
    importPath
      .replace(/^\.\//, "")
      .replace(/^\.\.\//, "")
      .replace(/\.sol$/, "") + ".sol"
  );
}

/**
 * Detect circular dependencies using DFS.
 */
function detectCircularDependencies(edges: Map<string, string[]>): string[][] {
  const cycles: string[][] = [];
  const visited = new Set<string>();
  const recursionStack = new Set<string>();
  const path: string[] = [];

  function dfs(node: string): void {
    visited.add(node);
    recursionStack.add(node);
    path.push(node);

    const neighbors = edges.get(node) ?? [];
    for (const neighbor of neighbors) {
      if (!visited.has(neighbor)) {
        dfs(neighbor);
      } else if (recursionStack.has(neighbor)) {
        // Found a cycle
        const cycleStart = path.indexOf(neighbor);
        if (cycleStart !== -1) {
          const cycle = path.slice(cycleStart);
          cycle.push(neighbor); // Complete the cycle
          cycles.push(cycle);
        }
      }
    }

    path.pop();
    recursionStack.delete(node);
  }

  for (const [node] of edges) {
    if (!visited.has(node)) {
      dfs(node);
    }
  }

  return cycles;
}

// ============================================================================
// Audit Prioritization
// ============================================================================

/**
 * Calculate audit priority for a contract.
 */
function calculatePriority(
  contract: ContractFile,
  graph: DependencyGraph
): { priority: AuditPriority; score: number } {
  let score = 0;

  // Fund handling is highest priority
  if (contract.hasPayable) {
    score += 100;
  }

  // Delegatecall and selfdestruct are critical
  if (contract.hasDelegatecall) {
    score += 80;
  }
  if (contract.hasSelfdestruct) {
    score += 80;
  }

  // External calls increase risk
  if (contract.hasExternalCalls) {
    score += 40;
  }

  // Upgradeable contracts need careful review
  if (contract.isUpgradeable) {
    score += 60;
  }

  // Contracts with many dependents are critical
  const dependentCount = graph.reverseEdges.get(contract.relativePath)?.length ?? 0;
  score += dependentCount * 20;

  // More code = more surface area
  score += Math.min(contract.sloc / 10, 50); // Cap at 50 points

  // Reduce priority for interfaces and libraries
  if (contract.type === "interface") {
    score = Math.floor(score * 0.2);
  } else if (contract.type === "library") {
    score = Math.floor(score * 0.5);
  } else if (contract.type === "abstract") {
    score = Math.floor(score * 0.7);
  }

  // Determine priority level
  let priority: AuditPriority;
  if (score >= 150) {
    priority = "critical";
  } else if (score >= 80) {
    priority = "high";
  } else if (score >= 30) {
    priority = "medium";
  } else {
    priority = "low";
  }

  return { priority, score };
}

/**
 * Prioritize contracts for audit.
 */
export function prioritizeAudit(contracts: ContractFile[], graph: DependencyGraph): ContractFile[] {
  // Calculate priorities
  const prioritized = contracts.map((contract) => {
    const { priority, score } = calculatePriority(contract, graph);
    return {
      ...contract,
      priority,
      _score: score,
    };
  });

  // Sort by score (descending)
  prioritized.sort((a, b) => b._score - a._score);

  // Remove internal score field
  return prioritized.map(({ _score, ...contract }) => contract);
}

// ============================================================================
// Main Scanner Function
// ============================================================================

/**
 * Scan an entire Solidity project.
 */
export function scanProject(projectRoot: string): ProjectStructure {
  logger.info(`[project-scanner] Scanning project at ${projectRoot}`);

  const findings: Finding[] = [];

  // Detect project type
  const projectType = detectProjectType(projectRoot);
  logger.info(`[project-scanner] Detected project type: ${projectType}`);

  // Find source directories
  const sourceDirs = getSourceDirs(projectRoot, projectType);
  logger.info(`[project-scanner] Source directories: ${sourceDirs.join(", ")}`);

  // Find all Solidity files
  const solFiles: string[] = [];
  for (const dir of sourceDirs) {
    findSolidityFiles(dir, projectRoot, solFiles);
  }
  logger.info(`[project-scanner] Found ${solFiles.length} Solidity files`);

  // Analyze each contract
  const contracts: ContractFile[] = [];
  for (const filePath of solFiles) {
    const contract = analyzeContractFile(filePath, projectRoot);
    if (contract) {
      contracts.push(contract);
    }
  }

  // Build dependency graph
  const dependencies = buildDependencyGraph(contracts);

  // Generate findings for circular dependencies
  for (const cycle of dependencies.circularDependencies) {
    findings.push({
      id: `circular-dep-${cycle.join("-").substring(0, 16)}`,
      title: "Circular Dependency Detected",
      description: `Circular dependency detected: ${cycle.join(" → ")}. This can lead to initialization issues and makes the codebase harder to understand and maintain.`,
      severity: Severity.LOW,
      confidence: "high",
      detector: "custom:project-scanner",
      location: {
        file: cycle[0] ?? "unknown",
      },
      recommendation:
        "Refactor the contracts to remove circular dependencies. Consider extracting shared code into a separate base contract or library.",
    });
  }

  // Prioritize contracts
  const prioritizedContracts = prioritizeAudit(contracts, dependencies);

  // Calculate summary
  const summary: ProjectSummary = {
    totalContracts: contracts.filter((c) => c.type === "contract").length,
    totalInterfaces: contracts.filter((c) => c.type === "interface").length,
    totalLibraries: contracts.filter((c) => c.type === "library").length,
    totalAbstract: contracts.filter((c) => c.type === "abstract").length,
    totalLOC: contracts.reduce((sum, c) => sum + c.loc, 0),
    totalSLOC: contracts.reduce((sum, c) => sum + c.sloc, 0),
    contractsWithPayable: contracts.filter((c) => c.hasPayable).length,
    contractsWithExternalCalls: contracts.filter((c) => c.hasExternalCalls).length,
    upgradeableContracts: contracts.filter((c) => c.isUpgradeable).length,
  };

  logger.info(
    `[project-scanner] Summary: ${summary.totalContracts} contracts, ${summary.totalInterfaces} interfaces, ${summary.totalLibraries} libraries, ${summary.totalSLOC} SLOC`
  );

  return {
    projectRoot,
    projectType,
    contracts: prioritizedContracts,
    dependencies,
    summary,
    findings,
  };
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Get contracts that should be audited first.
 */
export function getCriticalContracts(structure: ProjectStructure): ContractFile[] {
  return structure.contracts.filter((c) => c.priority === "critical" || c.priority === "high");
}

/**
 * Get contracts that handle funds.
 */
export function getFundHandlingContracts(structure: ProjectStructure): ContractFile[] {
  return structure.contracts.filter((c) => c.hasPayable);
}

/**
 * Get contracts with external interactions.
 */
export function getExternallyInteractingContracts(structure: ProjectStructure): ContractFile[] {
  return structure.contracts.filter((c) => c.hasExternalCalls || c.hasDelegatecall);
}

/**
 * Format project structure as a report.
 */
export function formatProjectReport(structure: ProjectStructure): string {
  const lines: string[] = [];

  lines.push("# Project Analysis Report");
  lines.push("");
  lines.push(`**Project Type:** ${structure.projectType}`);
  lines.push(`**Root:** ${structure.projectRoot}`);
  lines.push("");

  // Summary
  lines.push("## Summary");
  lines.push("");
  lines.push("| Metric | Count |");
  lines.push("|--------|------:|");
  lines.push(`| Contracts | ${structure.summary.totalContracts} |`);
  lines.push(`| Interfaces | ${structure.summary.totalInterfaces} |`);
  lines.push(`| Libraries | ${structure.summary.totalLibraries} |`);
  lines.push(`| Abstract | ${structure.summary.totalAbstract} |`);
  lines.push(`| Total SLOC | ${structure.summary.totalSLOC} |`);
  lines.push(`| Fund Handling | ${structure.summary.contractsWithPayable} |`);
  lines.push(`| External Calls | ${structure.summary.contractsWithExternalCalls} |`);
  lines.push(`| Upgradeable | ${structure.summary.upgradeableContracts} |`);
  lines.push("");

  // Critical contracts
  const critical = getCriticalContracts(structure);
  if (critical.length > 0) {
    lines.push("## Priority Contracts");
    lines.push("");
    lines.push("| Priority | Contract | Type | SLOC | Risks |");
    lines.push("|:--------:|----------|------|-----:|-------|");

    for (const contract of critical) {
      const risks: string[] = [];
      if (contract.hasPayable) risks.push("payable");
      if (contract.hasDelegatecall) risks.push("delegatecall");
      if (contract.hasSelfdestruct) risks.push("selfdestruct");
      if (contract.isUpgradeable) risks.push("upgradeable");
      if (contract.hasExternalCalls) risks.push("external-calls");

      const priorityEmoji = contract.priority === "critical" ? "🔴" : "🟠";

      lines.push(
        `| ${priorityEmoji} ${contract.priority?.toUpperCase()} | ${contract.name} | ${contract.type} | ${contract.sloc} | ${risks.join(", ") || "-"} |`
      );
    }
    lines.push("");
  }

  // Dependency analysis
  if (structure.dependencies.criticalContracts.length > 0) {
    lines.push("## Most Imported Contracts");
    lines.push("");
    lines.push("| Contract | Dependents |");
    lines.push("|----------|----------:|");

    for (const dep of structure.dependencies.criticalContracts.slice(0, 10)) {
      lines.push(`| ${basename(dep.path, ".sol")} | ${dep.dependentCount} |`);
    }
    lines.push("");
  }

  // Circular dependencies
  if (structure.dependencies.circularDependencies.length > 0) {
    lines.push("## Circular Dependencies");
    lines.push("");
    lines.push("The following circular dependencies were detected:");
    lines.push("");
    for (const cycle of structure.dependencies.circularDependencies) {
      lines.push(`- ${cycle.join(" → ")}`);
    }
    lines.push("");
  }

  // All contracts by priority
  lines.push("## All Contracts");
  lines.push("");
  lines.push("| Priority | Contract | Path | SLOC |");
  lines.push("|:--------:|----------|------|-----:|");

  for (const contract of structure.contracts) {
    const priorityEmoji = {
      critical: "🔴",
      high: "🟠",
      medium: "🟡",
      low: "🟢",
    }[contract.priority ?? "low"];

    lines.push(
      `| ${priorityEmoji} | ${contract.name} | ${contract.relativePath} | ${contract.sloc} |`
    );
  }

  return lines.join("\n");
}
