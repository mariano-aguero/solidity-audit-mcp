/**
 * Slither Analyzer
 *
 * Wrapper for Slither, the Solidity static analyzer by Trail of Bits.
 * https://github.com/crytic/slither
 *
 * Slither detects vulnerabilities, code quality issues, and optimization
 * opportunities in Solidity smart contracts.
 */

import { createHash } from "crypto";
import { executeCommand, checkToolAvailable, parseJsonOutput } from "../utils/executor.js";
import { Severity, type Finding, type Confidence } from "../types/index.js";
import { logger } from "../utils/logger.js";

// ============================================================================
// Types
// ============================================================================

/**
 * Slither JSON output structure
 */
interface SlitherOutput {
  success: boolean;
  error?: string;
  results?: {
    detectors: SlitherDetector[];
    printers?: unknown[];
  };
}

interface SlitherDetector {
  check: string;
  impact: "High" | "Medium" | "Low" | "Informational" | "Optimization";
  confidence: "High" | "Medium" | "Low";
  description: string;
  markdown?: string;
  first_markdown_element?: string;
  elements: SlitherElement[];
}

interface SlitherElement {
  type: string;
  name: string;
  source_mapping: {
    start: number;
    length: number;
    filename_relative: string;
    filename_absolute: string;
    filename_short: string;
    lines: number[];
    starting_column: number;
    ending_column: number;
  };
  type_specific_fields?: {
    parent?: {
      type: string;
      name: string;
    };
    signature?: string;
  };
}

export interface SlitherRunOptions {
  /** Additional paths to filter out (added to default node_modules|lib) */
  filterPaths?: string[];
  /** Specific detectors to run (if empty, runs all) */
  detectors?: string[];
  /** Exclude specific detectors */
  excludeDetectors?: string[];
  /** Timeout in milliseconds (default: 120000) */
  timeout?: number;
}

// ============================================================================
// Detector Mapping
// ============================================================================

/**
 * Maps Slither detector names to human-readable titles.
 * Organized by category for better maintainability.
 */
export const SLITHER_DETECTOR_MAP: Record<string, { title: string; description: string }> = {
  // === Reentrancy ===
  "reentrancy-eth": {
    title: "Reentrancy Vulnerability (ETH)",
    description: "Functions that send ETH before updating state, allowing reentrancy attacks",
  },
  "reentrancy-no-eth": {
    title: "Reentrancy Vulnerability (No ETH)",
    description: "Functions vulnerable to reentrancy without ETH transfer",
  },
  "reentrancy-benign": {
    title: "Reentrancy (Benign)",
    description: "Reentrancy that doesn't lead to direct fund loss but may cause issues",
  },
  "reentrancy-events": {
    title: "Reentrancy (Event Ordering)",
    description: "Events may be emitted in unexpected order due to reentrancy",
  },
  "reentrancy-unlimited-gas": {
    title: "Reentrancy with Unlimited Gas",
    description: "Low-level calls with unlimited gas that may enable reentrancy",
  },

  // === Uninitialized Variables ===
  "uninitialized-state": {
    title: "Uninitialized State Variable",
    description: "State variable is never initialized and used before assignment",
  },
  "uninitialized-local": {
    title: "Uninitialized Local Variable",
    description: "Local variable is used before being initialized",
  },
  "uninitialized-storage": {
    title: "Uninitialized Storage Pointer",
    description: "Uninitialized storage pointer that could corrupt storage",
  },

  // === Arbitrary Send ===
  "arbitrary-send-eth": {
    title: "Arbitrary ETH Transfer",
    description: "Contract allows sending ETH to arbitrary addresses",
  },
  "arbitrary-send-erc20": {
    title: "Arbitrary ERC20 Transfer",
    description: "Contract allows transferring ERC20 tokens to arbitrary addresses",
  },
  "arbitrary-send-erc20-permit": {
    title: "Arbitrary ERC20 Transfer via Permit",
    description: "ERC20 permit can be used to transfer tokens to arbitrary addresses",
  },

  // === Critical ===
  suicidal: {
    title: "Unprotected Selfdestruct",
    description: "Contract can be destroyed by anyone, leading to loss of funds",
  },
  "controlled-delegatecall": {
    title: "Controlled Delegatecall",
    description: "Delegatecall target can be controlled by user input",
  },
  "delegatecall-loop": {
    title: "Delegatecall in Loop",
    description: "Delegatecall inside a loop may be vulnerable to attacks",
  },
  "msg-value-loop": {
    title: "msg.value in Loop",
    description: "msg.value used inside a loop can lead to unexpected behavior",
  },
  "protected-vars": {
    title: "Protected Variable Access",
    description: "Protected variable can be modified through unprotected function",
  },

  // === Access Control ===
  "tx-origin": {
    title: "Dangerous tx.origin Usage",
    description: "tx.origin used for authorization, vulnerable to phishing attacks",
  },
  "unprotected-upgrade": {
    title: "Unprotected Upgrade Function",
    description: "Upgrade function lacks access control, anyone can upgrade",
  },
  "missing-zero-check": {
    title: "Missing Zero Address Check",
    description: "Address parameter not checked for zero address",
  },

  // === Unchecked Operations ===
  "unchecked-transfer": {
    title: "Unchecked ERC20 Transfer",
    description: "Return value of ERC20 transfer not checked",
  },
  "unchecked-lowlevel": {
    title: "Unchecked Low-Level Call",
    description: "Return value of low-level call not checked",
  },
  "unchecked-send": {
    title: "Unchecked Send",
    description: "Return value of send() not checked",
  },
  "unused-return": {
    title: "Unused Return Value",
    description: "Return value of external call is not used",
  },

  // === Shadowing ===
  "shadowing-state": {
    title: "State Variable Shadowing",
    description: "State variable shadows another state variable from parent contract",
  },
  "shadowing-local": {
    title: "Local Variable Shadowing",
    description: "Local variable shadows a state variable",
  },
  "shadowing-builtin": {
    title: "Built-in Symbol Shadowing",
    description: "Variable shadows a built-in symbol (msg, block, etc.)",
  },
  "shadowing-abstract": {
    title: "Abstract Function Shadowing",
    description: "State variable shadows an abstract function",
  },

  // === Logic Issues ===
  "locked-ether": {
    title: "Locked Ether",
    description: "Contract can receive ETH but has no way to withdraw it",
  },
  timestamp: {
    title: "Block Timestamp Manipulation",
    description: "Dangerous use of block.timestamp for critical logic",
  },
  "weak-prng": {
    title: "Weak Randomness",
    description: "Predictable source of randomness (block.timestamp, blockhash)",
  },
  "divide-before-multiply": {
    title: "Precision Loss",
    description: "Division before multiplication can cause precision loss",
  },
  "incorrect-equality": {
    title: "Dangerous Strict Equality",
    description: "Strict equality check on balance/value that can be manipulated",
  },
  tautology: {
    title: "Tautological Comparison",
    description: "Comparison that is always true or always false",
  },
  "boolean-cst": {
    title: "Boolean Constant Misuse",
    description: "Unnecessary comparison to boolean constant",
  },
  "boolean-equal": {
    title: "Boolean Equality",
    description: "Comparison of boolean to true/false constant",
  },

  // === Code Quality ===
  "calls-loop": {
    title: "Calls Inside Loop",
    description: "External calls inside a loop can lead to DoS",
  },
  "costly-loop": {
    title: "Costly Loop Operations",
    description: "Loop contains operations that can exceed block gas limit",
  },
  "dead-code": {
    title: "Dead Code",
    description: "Functions that are never called",
  },
  "unused-state": {
    title: "Unused State Variable",
    description: "State variable is declared but never used",
  },
  "redundant-statements": {
    title: "Redundant Statements",
    description: "Statements that have no effect",
  },

  // === Solidity Issues ===
  "solc-version": {
    title: "Outdated Solidity Version",
    description: "Using an outdated or vulnerable Solidity version",
  },
  pragma: {
    title: "Floating Pragma",
    description: "Pragma version not locked, may compile with unintended version",
  },
  assembly: {
    title: "Inline Assembly Usage",
    description: "Contract uses inline assembly which bypasses safety checks",
  },
  "low-level-calls": {
    title: "Low-Level Call Usage",
    description: "Use of low-level calls (call, delegatecall, staticcall)",
  },
  "encode-packed-collision": {
    title: "ABI Encode Packed Collision",
    description: "abi.encodePacked with multiple dynamic types can cause collisions",
  },

  // === Naming & Style ===
  "naming-convention": {
    title: "Naming Convention Violation",
    description: "Variable/function naming doesn't follow Solidity conventions",
  },
  "similar-names": {
    title: "Similar Variable Names",
    description: "Variables with very similar names that may cause confusion",
  },
  "too-many-digits": {
    title: "Too Many Digits",
    description: "Number literal with many digits that should use scientific notation",
  },
  "constable-states": {
    title: "State Variable Could Be Constant",
    description: "State variable that never changes could be marked constant",
  },
  "immutable-states": {
    title: "State Variable Could Be Immutable",
    description: "State variable only set in constructor could be immutable",
  },
  "external-function": {
    title: "Public Function Could Be External",
    description: "Public function never called internally should be external",
  },

  // === Optimization ===
  "cache-array-length": {
    title: "Cache Array Length",
    description: "Array length should be cached in loop for gas optimization",
  },
  "variable-scope": {
    title: "Variable Scope Optimization",
    description: "Variable can be declared in a more limited scope",
  },
};

/**
 * Maps Slither impact levels to our Severity enum
 */
function mapImpactToSeverity(impact: string): Severity {
  switch (impact) {
    case "High":
      return Severity.HIGH;
    case "Medium":
      return Severity.MEDIUM;
    case "Low":
      return Severity.LOW;
    case "Informational":
    case "Optimization":
      return Severity.INFORMATIONAL;
    default:
      return Severity.INFORMATIONAL;
  }
}

/**
 * Maps Slither confidence to our Confidence type
 */
function mapConfidence(confidence: string): Confidence {
  switch (confidence) {
    case "High":
      return "high";
    case "Medium":
      return "medium";
    case "Low":
      return "low";
    default:
      return "medium";
  }
}

/**
 * Generate a short unique ID for a finding based on its content
 */
function generateFindingId(detector: SlitherDetector): string {
  const element = detector.elements[0];
  const location = element?.source_mapping;

  const hashInput = [
    detector.check,
    location?.filename_relative ?? "",
    location?.lines?.[0]?.toString() ?? "",
    element?.name ?? "",
  ].join(":");

  const hash = createHash("sha256").update(hashInput).digest("hex").slice(0, 8);
  return `SL-${hash}`;
}

/**
 * Get a human-readable title for a detector
 */
function getDetectorTitle(check: string): string {
  const mapped = SLITHER_DETECTOR_MAP[check];
  if (mapped) {
    return mapped.title;
  }

  // Convert kebab-case to Title Case as fallback
  return check
    .split("-")
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(" ");
}

/**
 * Extract location info from Slither elements
 */
function extractLocation(elements: SlitherElement[]): Finding["location"] {
  const element = elements[0];

  if (!element) {
    return { file: "unknown" };
  }

  const mapping = element.source_mapping;
  const lines = mapping.lines;

  return {
    file: mapping.filename_relative || mapping.filename_short || "unknown",
    lines: lines.length >= 1 ? [lines[0]!, lines[lines.length - 1]!] : undefined,
    function:
      element.type === "function" ? element.name : element.type_specific_fields?.parent?.name,
  };
}

// ============================================================================
// Main Function
// ============================================================================

/**
 * Run Slither analysis on a Solidity project.
 *
 * @param contractPath - Path to the contract file (used for reference, Slither runs on project)
 * @param projectRoot - Root directory of the project
 * @param options - Additional run options
 * @returns Array of Finding objects
 *
 * @example
 * ```ts
 * const findings = await runSlither("/path/to/Token.sol", "/path/to/project");
 * console.log(`Found ${findings.length} issues`);
 * ```
 */
export async function runSlither(
  contractPath: string,
  projectRoot: string,
  options: SlitherRunOptions = {}
): Promise<Finding[]> {
  // Check if Slither is installed
  const toolInfo = await checkToolAvailable("slither");

  if (!toolInfo.available) {
    logger.warn("[slither] Slither is not installed. Install with: pip install slither-analyzer");
    return [];
  }

  logger.info(`[slither] Using Slither ${toolInfo.version ?? "unknown version"}`);
  logger.info(`[slither] Analyzing project: ${projectRoot}`);
  logger.info(`[slither] Target contract: ${contractPath}`);

  // Build command arguments
  const args: string[] = [
    projectRoot,
    "--json",
    "-", // Output JSON to stdout
  ];

  // Add filter paths
  const filterPaths = ["node_modules", "lib", "test", "tests", "mocks", "mock"];
  if (options.filterPaths) {
    filterPaths.push(...options.filterPaths);
  }
  args.push("--filter-paths", filterPaths.join("|"));

  // Add specific detectors if provided
  if (options.detectors && options.detectors.length > 0) {
    args.push("--detect", options.detectors.join(","));
  }

  // Exclude specific detectors
  if (options.excludeDetectors && options.excludeDetectors.length > 0) {
    args.push("--exclude", options.excludeDetectors.join(","));
  }

  // Skip compilation if project is already compiled
  args.push("--skip-assembly");

  logger.info(`[slither] Running: slither ${args.join(" ")}`);

  // Execute Slither
  const result = await executeCommand("slither", args, {
    cwd: projectRoot,
    timeout: options.timeout ?? 120_000,
  });

  // Slither may return non-zero exit code even on success (when findings exist)
  // We need to check the JSON output to determine actual success

  // Parse JSON output
  const output = parseJsonOutput<SlitherOutput>(result.stdout);

  if (!output) {
    // Try parsing stderr (some versions output there)
    const stderrOutput = parseJsonOutput<SlitherOutput>(result.stderr);

    if (!stderrOutput) {
      logger.error("[slither] Failed to parse Slither output");
      logger.error("[slither] stdout:", { output: result.stdout.slice(0, 500) });
      logger.error("[slither] stderr:", { output: result.stderr.slice(0, 500) });
      return [];
    }

    return parseSlitherResults(stderrOutput);
  }

  return parseSlitherResults(output);
}

/**
 * Parse Slither output into Finding array
 */
function parseSlitherResults(output: SlitherOutput): Finding[] {
  if (!output.success && output.error) {
    logger.error(`[slither] Analysis failed: ${output.error}`);
    return [];
  }

  const detectors = output.results?.detectors ?? [];
  logger.info(`[slither] Found ${detectors.length} detector results`);

  const findings: Finding[] = [];

  for (const detector of detectors) {
    const finding: Finding = {
      id: generateFindingId(detector),
      title: getDetectorTitle(detector.check),
      severity: mapImpactToSeverity(detector.impact),
      description: cleanDescription(detector.description),
      location: extractLocation(detector.elements),
      recommendation: getRecommendation(detector.check),
      detector: "slither",
      confidence: mapConfidence(detector.confidence),
    };

    findings.push(finding);
  }

  return findings;
}

/**
 * Clean up Slither's description text
 */
function cleanDescription(description: string): string {
  return description.replace(/\t/g, " ").replace(/\n+/g, " ").replace(/\s+/g, " ").trim();
}

/**
 * Get recommendation based on detector type
 */
function getRecommendation(check: string): string {
  const recommendations: Record<string, string> = {
    "reentrancy-eth":
      "Use the checks-effects-interactions pattern or OpenZeppelin's ReentrancyGuard",
    "reentrancy-no-eth": "Apply the checks-effects-interactions pattern to prevent reentrancy",
    "uninitialized-state": "Initialize all state variables in the constructor or at declaration",
    "uninitialized-local": "Always initialize local variables before use",
    "arbitrary-send-eth": "Implement proper access controls and validate recipient addresses",
    "arbitrary-send-erc20": "Add access controls and validate token transfer recipients",
    suicidal: "Add access control to selfdestruct or remove it entirely",
    "controlled-delegatecall": "Never use user input to control delegatecall target",
    "tx-origin": "Use msg.sender instead of tx.origin for authentication",
    "unchecked-transfer": "Check the return value or use SafeERC20 from OpenZeppelin",
    "unchecked-lowlevel": "Always check the return value of low-level calls",
    "shadowing-state": "Rename the variable to avoid shadowing",
    "shadowing-local": "Use a different name for the local variable",
    "locked-ether": "Add a withdraw function or remove the payable modifier",
    timestamp: "Avoid using block.timestamp for critical logic or use a time buffer",
    "weak-prng": "Use Chainlink VRF or commit-reveal scheme for randomness",
    "calls-loop": "Consider pull-over-push pattern or limit loop iterations",
    "unused-state": "Remove unused state variables to save gas",
    "unused-return": "Check and handle the return value of external calls",
    pragma: "Lock the pragma version to a specific compiler version",
    "solc-version": "Update to a recent stable Solidity version",
    "missing-zero-check": "Add require(address != address(0)) to validate addresses",
  };

  return recommendations[check] ?? "Review the code and apply appropriate fixes";
}

/**
 * Get list of all supported Slither detectors
 */
export function getSlitherDetectors(): string[] {
  return Object.keys(SLITHER_DETECTOR_MAP);
}

/**
 * Check if Slither is available on the system
 */
export async function isSlitherAvailable(): Promise<boolean> {
  const info = await checkToolAvailable("slither");
  return info.available;
}
