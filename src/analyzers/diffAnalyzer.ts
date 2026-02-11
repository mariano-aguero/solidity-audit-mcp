/**
 * Diff Analyzer
 *
 * Compares two versions of a Solidity contract to identify changes,
 * extract context, and assess the risk level of modifications.
 */

import { readFile } from "fs/promises";
import {
  DiffResult,
  DiffLine,
  DiffHunk,
  DiffSummary,
  ChangedContext,
  ContextType,
  ChangeRiskAssessment,
  ChangeRiskLevel,
  ChangeFlag,
} from "../types/index.js";

// ============================================================================
// Constants
// ============================================================================

const CONTEXT_LINES = 5;

// Patterns for identifying high-risk code
const FUND_HANDLING_PATTERNS = [
  /\.transfer\s*\(/,
  /\.send\s*\(/,
  /\.call\{value/,
  /payable\s*\(/,
  /withdraw/i,
  /deposit/i,
  /\bbalance\b/,
  /\bmint\b/i,
  /\bburn\b/i,
];

const ACCESS_CONTROL_PATTERNS = [
  /onlyOwner/,
  /onlyAdmin/,
  /onlyRole/,
  /require\s*\(\s*msg\.sender/,
  /require\s*\(\s*_msgSender/,
  /hasRole\s*\(/,
  /\bowner\b/,
  /\badmin\b/i,
  /AccessControl/,
  /Ownable/,
];

const CRITICAL_FUNCTIONS = [
  "transfer",
  "transferFrom",
  "approve",
  "withdraw",
  "deposit",
  "mint",
  "burn",
  "setOwner",
  "renounceOwnership",
  "transferOwnership",
  "grantRole",
  "revokeRole",
  "pause",
  "unpause",
  "upgrade",
  "initialize",
  "selfdestruct",
  "delegatecall",
];

// ============================================================================
// Main Functions
// ============================================================================

/**
 * Generate a diff between two contract files.
 *
 * @param oldPath - Path to the old version of the contract
 * @param newPath - Path to the new version of the contract
 * @returns Structured diff result with changes categorized
 */
export async function generateDiff(oldPath: string, newPath: string): Promise<DiffResult> {
  const [oldSource, newSource] = await Promise.all([
    readFile(oldPath, "utf-8"),
    readFile(newPath, "utf-8"),
  ]);

  const oldLines = oldSource.split("\n");
  const newLines = newSource.split("\n");

  // Generate unified diff
  const hunks = generateUnifiedDiff(oldLines, newLines);

  // Extract added and removed lines
  const { addedLines, removedLines } = extractChangedLines(hunks, oldLines, newLines);

  // Extract function information from both versions
  const oldFunctions = extractFunctionNames(oldSource);
  const newFunctions = extractFunctionNames(newSource);

  // Determine function changes
  const newFuncs = newFunctions.filter((f) => !oldFunctions.includes(f));
  const removedFuncs = oldFunctions.filter((f) => !newFunctions.includes(f));
  const modifiedFunctions = findModifiedFunctions(hunks, oldSource, newSource);

  // Extract state variable information
  const oldStateVars = extractStateVariableNames(oldSource);
  const newStateVars = extractStateVariableNames(newSource);
  const modifiedStateVars = findModifiedStateVars(
    hunks,
    oldSource,
    newSource,
    oldStateVars,
    newStateVars
  );

  // Generate summary
  const summary: DiffSummary = {
    linesAdded: addedLines.length,
    linesRemoved: removedLines.length,
    functionsChanged: modifiedFunctions.length + newFuncs.length + removedFuncs.length,
  };

  return {
    oldFile: oldPath,
    newFile: newPath,
    addedLines,
    removedLines,
    modifiedFunctions,
    modifiedStateVars,
    newFunctions: newFuncs,
    removedFunctions: removedFuncs,
    hunks,
    summary,
  };
}

/**
 * Extract the full context around each change.
 *
 * @param diffResult - The diff result from generateDiff
 * @param newSource - The new source code
 * @returns Array of changed contexts with surrounding code
 */
export function extractChangedContext(diffResult: DiffResult, newSource: string): ChangedContext[] {
  const contexts: ChangedContext[] = [];
  const lines = newSource.split("\n");

  // Process new functions
  for (const funcName of diffResult.newFunctions) {
    const funcContext = extractFunctionContext(newSource, funcName);
    if (funcContext) {
      contexts.push({
        type: "function",
        name: funcName,
        startLine: funcContext.startLine,
        endLine: funcContext.endLine,
        content: funcContext.content,
        changeType: "added",
        surroundingContext: {
          before: getSurroundingLines(lines, funcContext.startLine - 1, -CONTEXT_LINES),
          after: getSurroundingLines(lines, funcContext.endLine + 1, CONTEXT_LINES),
        },
      });
    }
  }

  // Process modified functions
  for (const funcName of diffResult.modifiedFunctions) {
    const funcContext = extractFunctionContext(newSource, funcName);
    if (funcContext) {
      contexts.push({
        type: "function",
        name: funcName,
        startLine: funcContext.startLine,
        endLine: funcContext.endLine,
        content: funcContext.content,
        changeType: "modified",
        surroundingContext: {
          before: getSurroundingLines(lines, funcContext.startLine - 1, -CONTEXT_LINES),
          after: getSurroundingLines(lines, funcContext.endLine + 1, CONTEXT_LINES),
        },
      });
    }
  }

  // Process modified state variables
  for (const varName of diffResult.modifiedStateVars) {
    const stateVarsSection = extractStateVariablesSection(newSource);
    if (stateVarsSection) {
      contexts.push({
        type: "stateVariable",
        name: varName,
        startLine: stateVarsSection.startLine,
        endLine: stateVarsSection.endLine,
        content: stateVarsSection.content,
        changeType: "modified",
        surroundingContext: {
          before: getSurroundingLines(lines, stateVarsSection.startLine - 1, -CONTEXT_LINES),
          after: getSurroundingLines(lines, stateVarsSection.endLine + 1, CONTEXT_LINES),
        },
      });
    }
  }

  // Process general changes that aren't in functions
  for (const hunk of diffResult.hunks) {
    const hunkContext = determineHunkContext(hunk, newSource);
    if (hunkContext && !contexts.some((c) => c.name === hunkContext.name)) {
      contexts.push({
        type: hunkContext.type,
        name: hunkContext.name,
        startLine: hunk.newStart,
        endLine: hunk.newStart + hunk.newCount - 1,
        content: hunk.lines.join("\n"),
        changeType: "modified",
        surroundingContext: {
          before: getSurroundingLines(lines, hunk.newStart - 1, -CONTEXT_LINES),
          after: getSurroundingLines(lines, hunk.newStart + hunk.newCount, CONTEXT_LINES),
        },
      });
    }
  }

  return contexts;
}

/**
 * Assess the risk level of the changes.
 *
 * @param diffResult - The diff result from generateDiff
 * @returns Risk assessment with flags and recommendations
 */
export function assessChangeRisk(diffResult: DiffResult): ChangeRiskAssessment {
  const changeFlags: ChangeFlag[] = [];
  let highestRisk: ChangeRiskLevel = "low";

  // Check for critical function modifications
  for (const funcName of [...diffResult.modifiedFunctions, ...diffResult.newFunctions]) {
    const lowerName = funcName.toLowerCase();

    // Check if it's a critical function
    if (CRITICAL_FUNCTIONS.some((cf) => lowerName.includes(cf.toLowerCase()))) {
      changeFlags.push({
        flag: "CRITICAL_FUNCTION_MODIFIED",
        description: `Critical function '${funcName}' was modified or added`,
        severity: "critical",
        location: { function: funcName },
      });
      highestRisk = "critical";
    }
  }

  // Check added lines for fund handling patterns
  for (const line of diffResult.addedLines) {
    for (const pattern of FUND_HANDLING_PATTERNS) {
      if (pattern.test(line.content)) {
        changeFlags.push({
          flag: "FUND_HANDLING_ADDED",
          description: `New code handles funds: ${line.content.trim().slice(0, 60)}...`,
          severity: "critical",
          location: { line: line.lineNumber },
        });
        highestRisk = "critical";
        break;
      }
    }
  }

  // Check for access control changes
  for (const line of diffResult.addedLines) {
    for (const pattern of ACCESS_CONTROL_PATTERNS) {
      if (pattern.test(line.content)) {
        changeFlags.push({
          flag: "ACCESS_CONTROL_MODIFIED",
          description: `Access control logic modified: ${line.content.trim().slice(0, 60)}...`,
          severity: "high",
          location: { line: line.lineNumber },
        });
        if (highestRisk !== "critical") highestRisk = "high";
        break;
      }
    }
  }

  // Check for removed access control (more dangerous)
  for (const line of diffResult.removedLines) {
    for (const pattern of ACCESS_CONTROL_PATTERNS) {
      if (pattern.test(line.content)) {
        changeFlags.push({
          flag: "ACCESS_CONTROL_REMOVED",
          description: `Access control may have been removed: ${line.content.trim().slice(0, 60)}...`,
          severity: "critical",
          location: { line: line.lineNumber },
        });
        highestRisk = "critical";
        break;
      }
    }
  }

  // Check for new payable functions
  for (const line of diffResult.addedLines) {
    if (/function\s+\w+[^{]*payable/.test(line.content)) {
      changeFlags.push({
        flag: "NEW_PAYABLE_FUNCTION",
        description: `New payable function added`,
        severity: "high",
        location: { line: line.lineNumber },
      });
      if (highestRisk !== "critical") highestRisk = "high";
    }
  }

  // Check for state variable changes
  if (diffResult.modifiedStateVars.length > 0) {
    changeFlags.push({
      flag: "STATE_VARS_MODIFIED",
      description: `State variables modified: ${diffResult.modifiedStateVars.join(", ")}`,
      severity: "medium",
    });
    if (highestRisk === "low") highestRisk = "medium";
  }

  // Check for removed functions
  if (diffResult.removedFunctions.length > 0) {
    const hasCriticalRemoval = diffResult.removedFunctions.some((f) =>
      CRITICAL_FUNCTIONS.some((cf) => f.toLowerCase().includes(cf.toLowerCase()))
    );

    changeFlags.push({
      flag: "FUNCTIONS_REMOVED",
      description: `Functions removed: ${diffResult.removedFunctions.join(", ")}`,
      severity: hasCriticalRemoval ? "high" : "medium",
    });
    if (hasCriticalRemoval && highestRisk !== "critical") highestRisk = "high";
    else if (highestRisk === "low") highestRisk = "medium";
  }

  // If no significant changes, mark as low risk
  if (changeFlags.length === 0) {
    if (diffResult.summary.linesAdded > 0 || diffResult.summary.linesRemoved > 0) {
      changeFlags.push({
        flag: "COSMETIC_CHANGES",
        description: "Changes appear to be cosmetic (formatting, comments, etc.)",
        severity: "low",
      });
    }
  }

  // Generate recommendations
  const recommendations = generateRecommendations(changeFlags, highestRisk);

  // Generate summary
  const summary = generateRiskSummary(diffResult, highestRisk, changeFlags);

  return {
    riskLevel: highestRisk,
    changeFlags,
    summary,
    recommendations,
  };
}

// ============================================================================
// Helper Functions - Diff Generation
// ============================================================================

/**
 * Generate unified diff hunks using Myers diff algorithm (simplified)
 */
function generateUnifiedDiff(oldLines: string[], newLines: string[]): DiffHunk[] {
  const hunks: DiffHunk[] = [];

  // Use LCS-based diff
  const lcs = longestCommonSubsequence(oldLines, newLines);
  const diffOps = generateDiffOperations(oldLines, newLines, lcs);

  // Group operations into hunks
  let currentHunk: DiffHunk | null = null;
  let oldIdx = 0;
  let newIdx = 0;

  for (const op of diffOps) {
    if (op.type === "equal") {
      if (currentHunk && currentHunk.lines.length > 0) {
        // Add context lines
        currentHunk.lines.push(` ${oldLines[oldIdx]}`);
        if (currentHunk.lines.filter((l) => !l.startsWith(" ")).length > 0) {
          hunks.push(currentHunk);
        }
        currentHunk = null;
      }
      oldIdx++;
      newIdx++;
    } else if (op.type === "delete") {
      if (!currentHunk) {
        currentHunk = {
          oldStart: oldIdx + 1,
          oldCount: 0,
          newStart: newIdx + 1,
          newCount: 0,
          lines: [],
        };
      }
      currentHunk.lines.push(`-${oldLines[oldIdx]}`);
      currentHunk.oldCount++;
      oldIdx++;
    } else if (op.type === "insert") {
      if (!currentHunk) {
        currentHunk = {
          oldStart: oldIdx + 1,
          oldCount: 0,
          newStart: newIdx + 1,
          newCount: 0,
          lines: [],
        };
      }
      currentHunk.lines.push(`+${newLines[newIdx]}`);
      currentHunk.newCount++;
      newIdx++;
    }
  }

  if (currentHunk && currentHunk.lines.filter((l) => !l.startsWith(" ")).length > 0) {
    hunks.push(currentHunk);
  }

  return hunks;
}

interface DiffOp {
  type: "equal" | "delete" | "insert";
}

function longestCommonSubsequence(a: string[], b: string[]): number[][] {
  const m = a.length;
  const n = b.length;
  const dp: number[][] = Array(m + 1)
    .fill(null)
    .map(() => Array(n + 1).fill(0));

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (a[i - 1] === b[j - 1]) {
        dp[i]![j] = dp[i - 1]![j - 1]! + 1;
      } else {
        dp[i]![j] = Math.max(dp[i - 1]![j]!, dp[i]![j - 1]!);
      }
    }
  }

  return dp;
}

function generateDiffOperations(a: string[], b: string[], dp: number[][]): DiffOp[] {
  const ops: DiffOp[] = [];
  let i = a.length;
  let j = b.length;

  while (i > 0 || j > 0) {
    if (i > 0 && j > 0 && a[i - 1] === b[j - 1]) {
      ops.unshift({ type: "equal" });
      i--;
      j--;
    } else if (j > 0 && (i === 0 || dp[i]![j - 1]! >= dp[i - 1]![j]!)) {
      ops.unshift({ type: "insert" });
      j--;
    } else {
      ops.unshift({ type: "delete" });
      i--;
    }
  }

  return ops;
}

function extractChangedLines(
  hunks: DiffHunk[],
  _oldLines: string[],
  _newLines: string[]
): { addedLines: DiffLine[]; removedLines: DiffLine[] } {
  const addedLines: DiffLine[] = [];
  const removedLines: DiffLine[] = [];

  for (const hunk of hunks) {
    let oldLineNum = hunk.oldStart;
    let newLineNum = hunk.newStart;

    for (const line of hunk.lines) {
      if (line.startsWith("+")) {
        addedLines.push({
          lineNumber: newLineNum,
          content: line.slice(1),
        });
        newLineNum++;
      } else if (line.startsWith("-")) {
        removedLines.push({
          lineNumber: oldLineNum,
          content: line.slice(1),
        });
        oldLineNum++;
      } else {
        oldLineNum++;
        newLineNum++;
      }
    }
  }

  return { addedLines, removedLines };
}

// ============================================================================
// Helper Functions - Code Extraction
// ============================================================================

function extractFunctionNames(source: string): string[] {
  const functions: string[] = [];
  const funcRegex = /\bfunction\s+(\w+)\s*\(/g;

  let match;
  while ((match = funcRegex.exec(source)) !== null) {
    functions.push(match[1]!);
  }

  // Also check for constructor
  if (/\bconstructor\s*\(/.test(source)) {
    functions.push("constructor");
  }

  return functions;
}

function extractStateVariableNames(source: string): string[] {
  const variables: string[] = [];
  const lines = source.split("\n");

  // Track brace depth to identify contract-level declarations
  let braceDepth = 0;
  let inContract = false;
  let inFunction = false;

  for (const line of lines) {
    // Check for contract start
    if (/\b(?:contract|library|interface)\s+\w+/.test(line)) {
      inContract = true;
    }

    // Count braces
    for (const char of line) {
      if (char === "{") braceDepth++;
      else if (char === "}") braceDepth--;
    }

    // Check for function start
    if (/\bfunction\s+\w+/.test(line) || /\bconstructor\s*\(/.test(line)) {
      inFunction = true;
    }

    // State variables are at contract level (braceDepth === 1)
    if (inContract && braceDepth === 1 && !inFunction) {
      const varMatch = line.match(
        /^\s*(?:mapping\s*\([^)]+\)|[\w[\]]+)\s+(?:public|private|internal|external)?\s*(?:constant|immutable)?\s*(\w+)\s*(?:=|;)/
      );
      if (varMatch) {
        variables.push(varMatch[1]!);
      }
    }

    // Reset function flag at function end
    if (inFunction && braceDepth <= 1) {
      inFunction = false;
    }
  }

  return variables;
}

function findModifiedFunctions(hunks: DiffHunk[], oldSource: string, newSource: string): string[] {
  const modified: Set<string> = new Set();
  const oldFunctions = extractFunctionNames(oldSource);
  const newFunctions = extractFunctionNames(newSource);

  // Functions that exist in both versions
  const commonFunctions = oldFunctions.filter((f) => newFunctions.includes(f));

  // For each hunk, determine which function it's in
  for (const hunk of hunks) {
    const funcName = findContainingFunction(newSource, hunk.newStart);
    if (funcName && commonFunctions.includes(funcName)) {
      modified.add(funcName);
    }
  }

  return Array.from(modified);
}

function findModifiedStateVars(
  hunks: DiffHunk[],
  _oldSource: string,
  _newSource: string,
  oldVars: string[],
  newVars: string[]
): string[] {
  const modified: Set<string> = new Set();

  // Check for new or removed vars
  const addedVars = newVars.filter((v) => !oldVars.includes(v));
  const removedVars = oldVars.filter((v) => !newVars.includes(v));

  addedVars.forEach((v) => modified.add(v));
  removedVars.forEach((v) => modified.add(v));

  // Check hunks for modifications to existing vars
  for (const hunk of hunks) {
    for (const line of hunk.lines) {
      if (line.startsWith("+") || line.startsWith("-")) {
        for (const varName of oldVars) {
          if (line.includes(varName)) {
            modified.add(varName);
          }
        }
      }
    }
  }

  return Array.from(modified);
}

function findContainingFunction(source: string, lineNumber: number): string | null {
  const lines = source.split("\n");
  let currentFunction: string | null = null;
  let braceDepth = 0;
  let functionBraceDepth = 0;

  for (let i = 0; i < Math.min(lineNumber, lines.length); i++) {
    const line = lines[i]!;

    // Check for function declaration
    const funcMatch = line.match(/\bfunction\s+(\w+)\s*\(/);
    if (funcMatch) {
      currentFunction = funcMatch[1]!;
      functionBraceDepth = braceDepth;
    }

    // Check for constructor
    if (/\bconstructor\s*\(/.test(line)) {
      currentFunction = "constructor";
      functionBraceDepth = braceDepth;
    }

    // Track braces
    for (const char of line) {
      if (char === "{") braceDepth++;
      else if (char === "}") {
        braceDepth--;
        if (braceDepth <= functionBraceDepth && currentFunction) {
          if (i < lineNumber - 1) {
            currentFunction = null;
          }
        }
      }
    }
  }

  return currentFunction;
}

interface FunctionContext {
  startLine: number;
  endLine: number;
  content: string;
}

function extractFunctionContext(source: string, funcName: string): FunctionContext | null {
  const lines = source.split("\n");

  // Find function start
  const funcPattern =
    funcName === "constructor"
      ? /\bconstructor\s*\(/
      : new RegExp(`\\bfunction\\s+${funcName}\\s*\\(`);

  let startLine = -1;
  for (let i = 0; i < lines.length; i++) {
    if (funcPattern.test(lines[i]!)) {
      startLine = i;
      break;
    }
  }

  if (startLine === -1) return null;

  // Find function end
  let braceDepth = 0;
  let foundFirstBrace = false;
  let endLine = startLine;

  for (let i = startLine; i < lines.length; i++) {
    for (const char of lines[i]!) {
      if (char === "{") {
        braceDepth++;
        foundFirstBrace = true;
      } else if (char === "}") {
        braceDepth--;
      }
    }

    if (foundFirstBrace && braceDepth === 0) {
      endLine = i;
      break;
    }
  }

  const content = lines.slice(startLine, endLine + 1).join("\n");

  return {
    startLine: startLine + 1,
    endLine: endLine + 1,
    content,
  };
}

interface StateVarsSection {
  startLine: number;
  endLine: number;
  content: string;
}

function extractStateVariablesSection(source: string): StateVarsSection | null {
  const lines = source.split("\n");
  let inContract = false;
  let braceDepth = 0;
  let startLine = -1;
  let endLine = -1;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;

    if (/\b(?:contract|library)\s+\w+/.test(line)) {
      inContract = true;
    }

    for (const char of line) {
      if (char === "{") braceDepth++;
      else if (char === "}") braceDepth--;
    }

    // State variables section starts after contract opening brace
    if (inContract && braceDepth === 1) {
      // Check if this is a state variable declaration
      if (
        /^\s*(?:mapping|[\w[\]]+)\s+(?:public|private|internal|external)?/.test(line) &&
        !line.includes("function")
      ) {
        if (startLine === -1) startLine = i;
        endLine = i;
      }
    }

    // Stop when we hit a function or constructor
    if (startLine !== -1 && (/\bfunction\s+/.test(line) || /\bconstructor\s*\(/.test(line))) {
      break;
    }
  }

  if (startLine === -1) return null;

  return {
    startLine: startLine + 1,
    endLine: endLine + 1,
    content: lines.slice(startLine, endLine + 1).join("\n"),
  };
}

function getSurroundingLines(lines: string[], startIdx: number, count: number): string[] {
  const result: string[] = [];

  if (count > 0) {
    // Get lines after
    for (let i = 0; i < count && startIdx + i < lines.length; i++) {
      result.push(lines[startIdx + i]!);
    }
  } else {
    // Get lines before (count is negative)
    const absCount = Math.abs(count);
    const actualStart = Math.max(0, startIdx - absCount + 1);
    for (let i = actualStart; i <= startIdx && i < lines.length; i++) {
      result.push(lines[i]!);
    }
  }

  return result;
}

function determineHunkContext(
  hunk: DiffHunk,
  source: string
): { type: ContextType; name: string } | null {
  const funcName = findContainingFunction(source, hunk.newStart);
  if (funcName) {
    return { type: "function", name: funcName };
  }

  // Check if it's in the state variables section
  const stateVarsSection = extractStateVariablesSection(source);
  if (
    stateVarsSection &&
    hunk.newStart >= stateVarsSection.startLine &&
    hunk.newStart <= stateVarsSection.endLine
  ) {
    return { type: "stateVariable", name: "state_variables" };
  }

  return { type: "general", name: "contract_level" };
}

// ============================================================================
// Helper Functions - Risk Assessment
// ============================================================================

function generateRecommendations(flags: ChangeFlag[], riskLevel: ChangeRiskLevel): string[] {
  const recommendations: string[] = [];

  if (riskLevel === "critical") {
    recommendations.push("MANDATORY: Full security audit required before deployment");
    recommendations.push("Test all modified fund handling logic extensively");
    recommendations.push("Verify access control hasn't been weakened");
  }

  if (riskLevel === "high") {
    recommendations.push("Security review strongly recommended");
    recommendations.push("Add comprehensive tests for modified functions");
  }

  if (flags.some((f) => f.flag === "ACCESS_CONTROL_REMOVED")) {
    recommendations.push("Verify that removed access control was intentional and safe");
  }

  if (flags.some((f) => f.flag === "NEW_PAYABLE_FUNCTION")) {
    recommendations.push("Review new payable function for reentrancy and fund handling issues");
  }

  if (flags.some((f) => f.flag === "STATE_VARS_MODIFIED")) {
    recommendations.push("Check that state variable changes don't break existing storage layout");
  }

  if (flags.some((f) => f.flag === "FUNCTIONS_REMOVED")) {
    recommendations.push("Verify removed functions are not called by external contracts");
  }

  if (recommendations.length === 0) {
    recommendations.push("Standard code review recommended");
    recommendations.push("Ensure tests pass for modified code");
  }

  return recommendations;
}

function generateRiskSummary(
  diffResult: DiffResult,
  riskLevel: ChangeRiskLevel,
  flags: ChangeFlag[]
): string {
  const parts: string[] = [];

  parts.push(`Risk Level: ${riskLevel.toUpperCase()}`);
  parts.push(`Lines added: ${diffResult.summary.linesAdded}`);
  parts.push(`Lines removed: ${diffResult.summary.linesRemoved}`);
  parts.push(`Functions changed: ${diffResult.summary.functionsChanged}`);

  if (flags.length > 0) {
    const criticalCount = flags.filter((f) => f.severity === "critical").length;
    const highCount = flags.filter((f) => f.severity === "high").length;
    if (criticalCount > 0) {
      parts.push(`Critical flags: ${criticalCount}`);
    }
    if (highCount > 0) {
      parts.push(`High risk flags: ${highCount}`);
    }
  }

  return parts.join(" | ");
}

// ============================================================================
// Exports
// ============================================================================

export { CRITICAL_FUNCTIONS, FUND_HANDLING_PATTERNS, ACCESS_CONTROL_PATTERNS };
