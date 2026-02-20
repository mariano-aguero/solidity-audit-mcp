/**
 * Diff Audit Tool
 *
 * Compares two versions of a contract and audits only the changed parts.
 * Ideal for PR reviews and contract upgrades.
 */

import { z } from "zod";
import { existsSync } from "fs";
import { readFile } from "fs/promises";
import { resolve, basename, dirname } from "path";
import {
  generateDiff,
  extractChangedContext,
  assessChangeRisk,
} from "../analyzers/diffAnalyzer.js";
import { AnalyzerOrchestrator } from "../analyzers/AnalyzerOrchestrator.js";
import {
  Finding,
  Severity,
  DiffResult,
  ChangeRiskAssessment,
  ChangedContext,
} from "../types/index.js";
import { logger } from "../utils/logger.js";

// ============================================================================
// Input Schema
// ============================================================================

export const DiffAuditInputSchema = z.object({
  oldContractPath: z.string().describe("Path to the old version of the contract"),
  newContractPath: z.string().describe("Path to the new version of the contract"),
  focusOnly: z
    .boolean()
    .optional()
    .default(true)
    .describe("If true, only analyze changed parts (default: true)"),
});

export type DiffAuditInput = z.infer<typeof DiffAuditInputSchema>;

// ============================================================================
// Output Types
// ============================================================================

export interface DiffAuditResult {
  success: boolean;
  diff: DiffSummaryOutput;
  changeRisk: ChangeRiskAssessment;
  findings: Finding[];
  newFindings: Finding[];
  resolvedFindings: Finding[];
  diffSpecificFindings: Finding[];
  changedContexts: ChangedContext[];
  report: string;
  error?: string;
}

interface DiffSummaryOutput {
  linesAdded: number;
  linesRemoved: number;
  functionsChanged: number;
  newFunctions: string[];
  removedFunctions: string[];
  modifiedFunctions: string[];
  modifiedStateVars: string[];
}

// ============================================================================
// Main Function
// ============================================================================

/**
 * Run a diff-focused audit between two contract versions.
 */
export async function diffAudit(input: DiffAuditInput): Promise<DiffAuditResult> {
  const oldPath = resolve(input.oldContractPath);
  const newPath = resolve(input.newContractPath);

  // Validate inputs
  if (!existsSync(oldPath)) {
    return createErrorResult(`Old contract file not found: ${oldPath}`);
  }
  if (!existsSync(newPath)) {
    return createErrorResult(`New contract file not found: ${newPath}`);
  }
  if (!oldPath.endsWith(".sol") || !newPath.endsWith(".sol")) {
    return createErrorResult("Both files must be Solidity contracts (.sol)");
  }

  try {
    // -------------------------------------------------------------------------
    // 1. Generate diff between versions
    // -------------------------------------------------------------------------
    logger.info("[diff-audit] Generating diff...");
    const diffResult = await generateDiff(oldPath, newPath);

    // -------------------------------------------------------------------------
    // 2. Assess change risk
    // -------------------------------------------------------------------------
    logger.info("[diff-audit] Assessing change risk...");
    const changeRisk = assessChangeRisk(diffResult);

    // -------------------------------------------------------------------------
    // 3. Extract changed contexts
    // -------------------------------------------------------------------------
    logger.info("[diff-audit] Extracting changed contexts...");
    const newSource = await readFile(newPath, "utf-8");
    const changedContexts = extractChangedContext(diffResult, newSource);

    // -------------------------------------------------------------------------
    // 4. Run analyzers on both versions
    // -------------------------------------------------------------------------
    logger.info("[diff-audit] Running security analyzers...");
    const projectRoot = dirname(newPath);

    const orchestrator = new AnalyzerOrchestrator();
    const [oldResult, newResult] = await Promise.all([
      orchestrator.analyzeWith(["slither", "aderyn"], { contractPath: oldPath, projectRoot }),
      orchestrator.analyzeWith(["slither", "aderyn"], { contractPath: newPath, projectRoot }),
    ]);
    const [oldFindings, newFindings] = [oldResult.findings, newResult.findings];

    // -------------------------------------------------------------------------
    // 5. Compare findings between versions
    // -------------------------------------------------------------------------
    logger.info("[diff-audit] Comparing findings...");
    const { added, resolved } = compareFindings(oldFindings, newFindings);

    // -------------------------------------------------------------------------
    // 6. Filter findings to changed areas (if focusOnly)
    // -------------------------------------------------------------------------
    let relevantFindings = newFindings;
    if (input.focusOnly) {
      relevantFindings = filterFindingsToChanges(newFindings, diffResult);
    }

    // -------------------------------------------------------------------------
    // 7. Generate diff-specific findings
    // -------------------------------------------------------------------------
    logger.info("[diff-audit] Generating diff-specific findings...");
    const oldSource = await readFile(oldPath, "utf-8");
    const diffSpecificFindings = await generateDiffSpecificFindings(
      diffResult,
      oldSource,
      newSource,
      newPath
    );

    // Combine all relevant findings
    const allFindings = [...relevantFindings, ...diffSpecificFindings];

    // Sort by severity
    allFindings.sort((a, b) => {
      const order: Record<Severity, number> = {
        [Severity.CRITICAL]: 0,
        [Severity.HIGH]: 1,
        [Severity.MEDIUM]: 2,
        [Severity.LOW]: 3,
        [Severity.INFORMATIONAL]: 4,
      };
      return order[a.severity] - order[b.severity];
    });

    // -------------------------------------------------------------------------
    // 8. Generate report
    // -------------------------------------------------------------------------
    logger.info("[diff-audit] Generating report...");
    const report = generateReport({
      diffResult,
      changeRisk,
      findings: allFindings,
      newFindings: added,
      resolvedFindings: resolved,
      diffSpecificFindings,
      changedContexts,
      oldPath,
      newPath,
    });

    return {
      success: true,
      diff: {
        linesAdded: diffResult.summary.linesAdded,
        linesRemoved: diffResult.summary.linesRemoved,
        functionsChanged: diffResult.summary.functionsChanged,
        newFunctions: diffResult.newFunctions,
        removedFunctions: diffResult.removedFunctions,
        modifiedFunctions: diffResult.modifiedFunctions,
        modifiedStateVars: diffResult.modifiedStateVars,
      },
      changeRisk,
      findings: allFindings,
      newFindings: added,
      resolvedFindings: resolved,
      diffSpecificFindings,
      changedContexts,
      report,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return createErrorResult(`Diff audit failed: ${message}`);
  }
}

// ============================================================================
// Helper Functions
// ============================================================================

function createErrorResult(error: string): DiffAuditResult {
  return {
    success: false,
    diff: {
      linesAdded: 0,
      linesRemoved: 0,
      functionsChanged: 0,
      newFunctions: [],
      removedFunctions: [],
      modifiedFunctions: [],
      modifiedStateVars: [],
    },
    changeRisk: {
      riskLevel: "low",
      changeFlags: [],
      summary: "",
      recommendations: [],
    },
    findings: [],
    newFindings: [],
    resolvedFindings: [],
    diffSpecificFindings: [],
    changedContexts: [],
    report: `# Diff Audit Error\n\n${error}`,
    error,
  };
}

interface CompareResult {
  added: Finding[];
  resolved: Finding[];
  common: Finding[];
}

function compareFindings(oldFindings: Finding[], newFindings: Finding[]): CompareResult {
  const added: Finding[] = [];
  const resolved: Finding[] = [];
  const common: Finding[] = [];

  // Create fingerprints for comparison
  const oldFingerprints = new Set(oldFindings.map(fingerprintFinding));
  const newFingerprints = new Set(newFindings.map(fingerprintFinding));

  // Find new findings (in new but not in old)
  for (const finding of newFindings) {
    const fp = fingerprintFinding(finding);
    if (!oldFingerprints.has(fp)) {
      added.push(finding);
    } else {
      common.push(finding);
    }
  }

  // Find resolved findings (in old but not in new)
  for (const finding of oldFindings) {
    const fp = fingerprintFinding(finding);
    if (!newFingerprints.has(fp)) {
      resolved.push(finding);
    }
  }

  return { added, resolved, common };
}

function fingerprintFinding(finding: Finding): string {
  // Create a fingerprint that ignores line numbers (since they may shift)
  // but considers the type of issue and the general location
  return `${finding.detector}:${finding.title}:${finding.location.function ?? "global"}`;
}

function filterFindingsToChanges(findings: Finding[], diffResult: DiffResult): Finding[] {
  const changedFunctions = new Set([...diffResult.modifiedFunctions, ...diffResult.newFunctions]);

  const changedLines = new Set([...diffResult.addedLines.map((l) => l.lineNumber)]);

  return findings.filter((finding) => {
    // Check if finding is in a changed function
    if (finding.location.function && changedFunctions.has(finding.location.function)) {
      return true;
    }

    // Check if finding is on a changed line
    if (finding.location.lines) {
      const [start, end] = finding.location.lines;
      for (let line = start; line <= end; line++) {
        if (changedLines.has(line)) {
          return true;
        }
      }
    }

    // Check if finding mentions any changed state variable
    for (const varName of diffResult.modifiedStateVars) {
      if (finding.description.includes(varName) || finding.title.includes(varName)) {
        return true;
      }
    }

    return false;
  });
}

async function generateDiffSpecificFindings(
  diffResult: DiffResult,
  oldSource: string,
  newSource: string,
  newPath: string
): Promise<Finding[]> {
  const findings: Finding[] = [];
  const fileName = basename(newPath);

  // 1. New functions without apparent tests
  for (const funcName of diffResult.newFunctions) {
    findings.push({
      id: `DIFF-001-${funcName}`,
      title: "New function may lack tests",
      severity: Severity.LOW,
      description: `New function '${funcName}' was added. Ensure it has adequate test coverage.`,
      location: {
        file: fileName,
        function: funcName,
      },
      recommendation: `Add comprehensive tests for the new function '${funcName}' before deployment.`,
      detector: "manual",
      confidence: "medium",
    });
  }

  // 2. Check for removed modifiers
  const removedModifiers = detectRemovedModifiers(oldSource, newSource, diffResult);
  for (const { funcName, modifierName } of removedModifiers) {
    findings.push({
      id: `DIFF-002-${funcName}-${modifierName}`,
      title: "Modifier removed from function",
      severity: Severity.HIGH,
      description: `Modifier '${modifierName}' was removed from function '${funcName}'. This may weaken security controls.`,
      location: {
        file: fileName,
        function: funcName,
      },
      recommendation: `Verify that removing '${modifierName}' from '${funcName}' is intentional and doesn't introduce security risks.`,
      detector: "manual",
      confidence: "high",
    });
  }

  // 3. Check for visibility changes
  const visibilityChanges = detectVisibilityChanges(oldSource, newSource, diffResult);
  for (const { funcName, oldVisibility, newVisibility } of visibilityChanges) {
    const isMorePermissive = isVisibilityMorePermissive(oldVisibility, newVisibility);
    findings.push({
      id: `DIFF-003-${funcName}`,
      title: "Function visibility changed",
      severity: isMorePermissive ? Severity.MEDIUM : Severity.LOW,
      description: `Function '${funcName}' visibility changed from '${oldVisibility}' to '${newVisibility}'.${isMorePermissive ? " This makes the function more accessible." : ""}`,
      location: {
        file: fileName,
        function: funcName,
      },
      recommendation: isMorePermissive
        ? `Review if '${funcName}' should be exposed with '${newVisibility}' visibility.`
        : `Visibility change noted. Ensure callers are updated if needed.`,
      detector: "manual",
      confidence: "high",
    });
  }

  // 4. Check for new payable functions
  const newPayableFunctions = detectNewPayableFunctions(oldSource, newSource, diffResult);
  for (const funcName of newPayableFunctions) {
    findings.push({
      id: `DIFF-004-${funcName}`,
      title: "New payable function added",
      severity: Severity.HIGH,
      description: `A new payable function '${funcName}' was added. Payable functions can receive ETH and require careful security review.`,
      location: {
        file: fileName,
        function: funcName,
      },
      recommendation: `Thoroughly review '${funcName}' for reentrancy, fund handling, and access control issues.`,
      detector: "manual",
      confidence: "high",
    });
  }

  // 5. Check for removed functions that might break interfaces
  for (const funcName of diffResult.removedFunctions) {
    findings.push({
      id: `DIFF-005-${funcName}`,
      title: "Function removed",
      severity: Severity.MEDIUM,
      description: `Function '${funcName}' was removed. This may break existing integrations or interfaces.`,
      location: {
        file: fileName,
      },
      recommendation: `Verify that no external contracts or interfaces depend on '${funcName}'.`,
      detector: "manual",
      confidence: "medium",
    });
  }

  // 6. Check for state variable type changes
  const stateVarChanges = detectStateVariableChanges(oldSource, newSource, diffResult);
  for (const { varName, change } of stateVarChanges) {
    findings.push({
      id: `DIFF-006-${varName}`,
      title: "State variable modified",
      severity: change === "type_changed" ? Severity.HIGH : Severity.MEDIUM,
      description: `State variable '${varName}' was ${change === "type_changed" ? "type changed" : change === "added" ? "added" : "removed"}. This may affect storage layout in upgradeable contracts.`,
      location: {
        file: fileName,
      },
      recommendation:
        change === "type_changed"
          ? `WARNING: Changing state variable types can corrupt storage in upgradeable contracts. Verify storage layout compatibility.`
          : `Review the impact of ${change} state variable on existing data and integrations.`,
      detector: "manual",
      confidence: "high",
    });
  }

  return findings;
}

interface RemovedModifier {
  funcName: string;
  modifierName: string;
}

function detectRemovedModifiers(
  oldSource: string,
  newSource: string,
  diffResult: DiffResult
): RemovedModifier[] {
  const removed: RemovedModifier[] = [];

  for (const funcName of diffResult.modifiedFunctions) {
    const oldModifiers = extractFunctionModifiers(oldSource, funcName);
    const newModifiers = extractFunctionModifiers(newSource, funcName);

    for (const mod of oldModifiers) {
      if (!newModifiers.includes(mod)) {
        removed.push({ funcName, modifierName: mod });
      }
    }
  }

  return removed;
}

function extractFunctionModifiers(source: string, funcName: string): string[] {
  const modifiers: string[] = [];

  // Match function declaration with modifiers
  const funcPattern =
    funcName === "constructor"
      ? /\bconstructor\s*\([^)]*\)\s*([^{]*)\{/
      : new RegExp(`\\bfunction\\s+${funcName}\\s*\\([^)]*\\)\\s*([^{]*)\\{`);

  const match = source.match(funcPattern);
  if (!match) return modifiers;

  const modifiersStr = match[1] ?? "";

  // Extract custom modifiers (not visibility/mutability keywords)
  const keywords = [
    "public",
    "private",
    "internal",
    "external",
    "pure",
    "view",
    "payable",
    "virtual",
    "override",
    "returns",
  ];

  const tokens = modifiersStr.split(/\s+/).filter((t) => t.length > 0);
  for (const token of tokens) {
    const cleanToken = token.replace(/\([^)]*\)/, ""); // Remove parameters
    if (!keywords.includes(cleanToken.toLowerCase()) && /^[a-zA-Z_]\w*$/.test(cleanToken)) {
      modifiers.push(cleanToken);
    }
  }

  return modifiers;
}

interface VisibilityChange {
  funcName: string;
  oldVisibility: string;
  newVisibility: string;
}

function detectVisibilityChanges(
  oldSource: string,
  newSource: string,
  diffResult: DiffResult
): VisibilityChange[] {
  const changes: VisibilityChange[] = [];

  for (const funcName of diffResult.modifiedFunctions) {
    const oldVis = extractFunctionVisibility(oldSource, funcName);
    const newVis = extractFunctionVisibility(newSource, funcName);

    if (oldVis && newVis && oldVis !== newVis) {
      changes.push({
        funcName,
        oldVisibility: oldVis,
        newVisibility: newVis,
      });
    }
  }

  return changes;
}

function extractFunctionVisibility(source: string, funcName: string): string | null {
  const funcPattern =
    funcName === "constructor"
      ? /\bconstructor\s*\([^)]*\)\s*([^{]*)\{/
      : new RegExp(`\\bfunction\\s+${funcName}\\s*\\([^)]*\\)\\s*([^{]*)\\{`);

  const match = source.match(funcPattern);
  if (!match) return null;

  const modifiersStr = match[1] ?? "";

  if (/\bexternal\b/.test(modifiersStr)) return "external";
  if (/\bpublic\b/.test(modifiersStr)) return "public";
  if (/\binternal\b/.test(modifiersStr)) return "internal";
  if (/\bprivate\b/.test(modifiersStr)) return "private";

  return "internal"; // Default
}

function isVisibilityMorePermissive(oldVis: string, newVis: string): boolean {
  const order: Record<string, number> = {
    private: 0,
    internal: 1,
    external: 2,
    public: 3,
  };
  return (order[newVis] ?? 0) > (order[oldVis] ?? 0);
}

function detectNewPayableFunctions(
  oldSource: string,
  newSource: string,
  diffResult: DiffResult
): string[] {
  const newPayable: string[] = [];

  // Check new functions
  for (const funcName of diffResult.newFunctions) {
    if (isFunctionPayable(newSource, funcName)) {
      newPayable.push(funcName);
    }
  }

  // Check modified functions that became payable
  for (const funcName of diffResult.modifiedFunctions) {
    const wasPayable = isFunctionPayable(oldSource, funcName);
    const isPayable = isFunctionPayable(newSource, funcName);

    if (!wasPayable && isPayable) {
      newPayable.push(funcName);
    }
  }

  return newPayable;
}

function isFunctionPayable(source: string, funcName: string): boolean {
  const funcPattern =
    funcName === "constructor"
      ? /\bconstructor\s*\([^)]*\)\s*([^{]*)\{/
      : new RegExp(`\\bfunction\\s+${funcName}\\s*\\([^)]*\\)\\s*([^{]*)\\{`);

  const match = source.match(funcPattern);
  if (!match) return false;

  return /\bpayable\b/.test(match[1] ?? "");
}

interface StateVarChange {
  varName: string;
  change: "added" | "removed" | "type_changed";
}

function detectStateVariableChanges(
  oldSource: string,
  newSource: string,
  diffResult: DiffResult
): StateVarChange[] {
  const changes: StateVarChange[] = [];

  // Extract state variables with types
  const oldVars = extractStateVariablesWithTypes(oldSource);
  const newVars = extractStateVariablesWithTypes(newSource);

  // Check for type changes in modified vars
  for (const varName of diffResult.modifiedStateVars) {
    const oldType = oldVars.get(varName);
    const newType = newVars.get(varName);

    if (oldType && newType && oldType !== newType) {
      changes.push({ varName, change: "type_changed" });
    } else if (!oldType && newType) {
      changes.push({ varName, change: "added" });
    } else if (oldType && !newType) {
      changes.push({ varName, change: "removed" });
    }
  }

  return changes;
}

function extractStateVariablesWithTypes(source: string): Map<string, string> {
  const variables = new Map<string, string>();
  const lines = source.split("\n");

  let braceDepth = 0;
  let inContract = false;

  for (const line of lines) {
    if (/\b(?:contract|library)\s+\w+/.test(line)) {
      inContract = true;
    }

    for (const char of line) {
      if (char === "{") braceDepth++;
      else if (char === "}") braceDepth--;
    }

    if (inContract && braceDepth === 1) {
      const varMatch = line.match(
        /^\s*((?:mapping\s*\([^)]+\)|[\w[\]]+))\s+(?:public|private|internal|external)?\s*(?:constant|immutable)?\s*(\w+)\s*(?:=|;)/
      );
      if (varMatch) {
        variables.set(varMatch[2]!, varMatch[1]!.trim());
      }
    }
  }

  return variables;
}

// ============================================================================
// Report Generation
// ============================================================================

interface ReportData {
  diffResult: DiffResult;
  changeRisk: ChangeRiskAssessment;
  findings: Finding[];
  newFindings: Finding[];
  resolvedFindings: Finding[];
  diffSpecificFindings: Finding[];
  changedContexts: ChangedContext[];
  oldPath: string;
  newPath: string;
}

function generateReport(data: ReportData): string {
  const lines: string[] = [];
  const oldName = basename(data.oldPath);
  const newName = basename(data.newPath);

  // Header
  lines.push("# Diff Audit Report");
  lines.push("");
  lines.push(`**Old Version:** ${oldName}`);
  lines.push(`**New Version:** ${newName}`);
  lines.push(`**Risk Level:** ${data.changeRisk.riskLevel.toUpperCase()}`);
  lines.push("");

  // Changes Summary
  lines.push("## Changes Summary");
  lines.push("");
  lines.push(`- Lines Added: ${data.diffResult.summary.linesAdded}`);
  lines.push(`- Lines Removed: ${data.diffResult.summary.linesRemoved}`);
  lines.push(`- Functions Changed: ${data.diffResult.summary.functionsChanged}`);
  lines.push("");

  if (data.diffResult.newFunctions.length > 0) {
    lines.push(`**New Functions:** ${data.diffResult.newFunctions.join(", ")}`);
  }
  if (data.diffResult.removedFunctions.length > 0) {
    lines.push(`**Removed Functions:** ${data.diffResult.removedFunctions.join(", ")}`);
  }
  if (data.diffResult.modifiedFunctions.length > 0) {
    lines.push(`**Modified Functions:** ${data.diffResult.modifiedFunctions.join(", ")}`);
  }
  if (data.diffResult.modifiedStateVars.length > 0) {
    lines.push(`**Modified State Variables:** ${data.diffResult.modifiedStateVars.join(", ")}`);
  }
  lines.push("");

  // Risk Assessment
  lines.push("## Risk Assessment");
  lines.push("");
  lines.push(`**Overall Risk:** ${data.changeRisk.riskLevel.toUpperCase()}`);
  lines.push("");

  if (data.changeRisk.changeFlags.length > 0) {
    lines.push("### Risk Flags");
    lines.push("");
    for (const flag of data.changeRisk.changeFlags) {
      const emoji =
        flag.severity === "critical"
          ? "🔴"
          : flag.severity === "high"
            ? "🟠"
            : flag.severity === "medium"
              ? "🟡"
              : "🟢";
      lines.push(`- ${emoji} **${flag.flag}**: ${flag.description}`);
    }
    lines.push("");
  }

  if (data.changeRisk.recommendations.length > 0) {
    lines.push("### Recommendations");
    lines.push("");
    for (const rec of data.changeRisk.recommendations) {
      lines.push(`- ${rec}`);
    }
    lines.push("");
  }

  // Findings Summary
  lines.push("## Findings Summary");
  lines.push("");

  const findingsBySeverity = {
    critical: data.findings.filter((f) => f.severity === Severity.CRITICAL).length,
    high: data.findings.filter((f) => f.severity === Severity.HIGH).length,
    medium: data.findings.filter((f) => f.severity === Severity.MEDIUM).length,
    low: data.findings.filter((f) => f.severity === Severity.LOW).length,
    informational: data.findings.filter((f) => f.severity === Severity.INFORMATIONAL).length,
  };

  lines.push(`| Severity | Count |`);
  lines.push(`|----------|-------|`);
  lines.push(`| 🔴 Critical | ${findingsBySeverity.critical} |`);
  lines.push(`| 🟠 High | ${findingsBySeverity.high} |`);
  lines.push(`| 🟡 Medium | ${findingsBySeverity.medium} |`);
  lines.push(`| 🟢 Low | ${findingsBySeverity.low} |`);
  lines.push(`| 🔵 Info | ${findingsBySeverity.informational} |`);
  lines.push("");

  lines.push(`- **New Findings:** ${data.newFindings.length}`);
  lines.push(`- **Resolved Findings:** ${data.resolvedFindings.length}`);
  lines.push("");

  // Diff-Specific Findings
  if (data.diffSpecificFindings.length > 0) {
    lines.push("## Change-Specific Findings");
    lines.push("");
    lines.push("These findings are directly related to the changes made:");
    lines.push("");

    for (const finding of data.diffSpecificFindings) {
      const emoji = getSeverityEmoji(finding.severity);
      lines.push(`### ${emoji} ${finding.title}`);
      lines.push("");
      lines.push(`**Severity:** ${finding.severity.toUpperCase()}`);
      if (finding.location.function) {
        lines.push(`**Function:** ${finding.location.function}`);
      }
      lines.push("");
      lines.push(finding.description);
      lines.push("");
      lines.push(`**Recommendation:** ${finding.recommendation}`);
      lines.push("");
    }
  }

  // New Findings
  if (data.newFindings.length > 0) {
    lines.push("## New Findings");
    lines.push("");
    lines.push("These findings were not present in the old version:");
    lines.push("");

    for (const finding of data.newFindings.slice(0, 10)) {
      const emoji = getSeverityEmoji(finding.severity);
      lines.push(`- ${emoji} **${finding.title}** (${finding.severity})`);
      if (finding.location.function) {
        lines.push(`  - Function: ${finding.location.function}`);
      }
    }
    if (data.newFindings.length > 10) {
      lines.push(`- ... and ${data.newFindings.length - 10} more`);
    }
    lines.push("");
  }

  // Resolved Findings
  if (data.resolvedFindings.length > 0) {
    lines.push("## Resolved Findings");
    lines.push("");
    lines.push("These findings from the old version are no longer present:");
    lines.push("");

    for (const finding of data.resolvedFindings.slice(0, 10)) {
      lines.push(`- ✅ **${finding.title}** (was ${finding.severity})`);
    }
    if (data.resolvedFindings.length > 10) {
      lines.push(`- ... and ${data.resolvedFindings.length - 10} more`);
    }
    lines.push("");
  }

  // All Findings (detailed)
  if (data.findings.length > 0) {
    lines.push("## All Relevant Findings");
    lines.push("");

    for (const finding of data.findings) {
      const emoji = getSeverityEmoji(finding.severity);
      lines.push(`### ${emoji} ${finding.title}`);
      lines.push("");
      lines.push(`**ID:** ${finding.id}`);
      lines.push(`**Severity:** ${finding.severity.toUpperCase()}`);
      lines.push(`**Detector:** ${finding.detector}`);
      if (finding.location.function) {
        lines.push(`**Function:** ${finding.location.function}`);
      }
      if (finding.location.lines) {
        lines.push(`**Lines:** ${finding.location.lines[0]}-${finding.location.lines[1]}`);
      }
      lines.push("");
      lines.push(finding.description);
      lines.push("");
      lines.push(`**Recommendation:** ${finding.recommendation}`);
      lines.push("");
      lines.push("---");
      lines.push("");
    }
  }

  // Footer
  lines.push("---");
  lines.push("");
  lines.push("*Generated by MCP Audit Server - Diff Audit Tool*");

  return lines.join("\n");
}

function getSeverityEmoji(severity: Severity): string {
  switch (severity) {
    case Severity.CRITICAL:
      return "🔴";
    case Severity.HIGH:
      return "🟠";
    case Severity.MEDIUM:
      return "🟡";
    case Severity.LOW:
      return "🟢";
    case Severity.INFORMATIONAL:
      return "🔵";
  }
}
