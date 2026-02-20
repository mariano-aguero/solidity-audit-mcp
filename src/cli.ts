#!/usr/bin/env node

/**
 * MCP Audit Server CLI
 *
 * Command-line interface for running security audits outside of Claude Code.
 * Useful for CI/CD pipelines and local development.
 *
 * Usage:
 *   solidity-audit-cli audit <path> [options]    Run security analysis
 *   solidity-audit-cli diff <old> <new> [options] Compare contract versions
 *   solidity-audit-cli gas <path> [options]      Analyze gas optimizations
 *
 * Exit Codes:
 *   0 - No findings above threshold
 *   1 - Findings above threshold detected
 *   2 - Execution error
 */

import { parseArgs } from "node:util";
import { resolve, basename, dirname } from "node:path";
import { existsSync, writeFileSync } from "node:fs";
import { analyzeContract } from "./tools/analyzeContract.js";
import { diffAudit } from "./tools/diffAudit.js";
import { optimizeGas, formatGasOptimizationResult } from "./tools/optimizeGas.js";
import { generateInvariants } from "./tools/generateInvariants.js";
import { explainFinding } from "./tools/explainFinding.js";
import { Severity, type Finding } from "./types/index.js";
import { generateSarifReport } from "./utils/sarif.js";
import { logger } from "./utils/logger.js";

// ============================================================================
// Types
// ============================================================================

type OutputFormat = "markdown" | "json" | "sarif";
type SeverityThreshold = "critical" | "high" | "medium" | "low" | "informational";

interface CliOptions {
  format: OutputFormat;
  severityThreshold: SeverityThreshold;
  focusOnly: boolean;
  quiet: boolean;
  noColor: boolean;
  output: string | null;
  protocol: string;
  context: string | null;
}

// ============================================================================
// Constants
// ============================================================================

const VERSION = "1.0.0";
const PROGRAM_NAME = "solidity-audit-cli";

const HELP_TEXT = `
${PROGRAM_NAME} v${VERSION} - Smart Contract Security Auditor

Usage:
  ${PROGRAM_NAME} <command> [options]

Commands:
  audit <path>              Run security analysis on a Solidity contract
  diff <old-path> <new-path> Compare two versions of a contract
  gas <path>                Analyze gas optimizations
  invariants <path>         Generate Foundry invariant test templates
  explain <finding-id>      Explain a finding (SWC-107, CUSTOM-032, 'reentrancy', etc.)
  help                      Show this help message
  version                   Show version

Options:
  --format, -f <type>       Output format: markdown, json, sarif (default: markdown)
  --output, -o <file>       Write output to file instead of stdout
  --severity, -s <level>    Minimum severity: critical, high, medium, low, informational (default: low)
  --focus-only              For diff: only analyze changed parts (default: true)
  --protocol, -p <type>     For invariants: erc20, vault, lending, amm, governance, staking, auto (default: auto)
  --context, -c <text>      For explain: brief contract description for tailored output
  --quiet, -q               Suppress progress messages
  --no-color                Disable colored output

Examples:
  ${PROGRAM_NAME} audit ./contracts/Token.sol
  ${PROGRAM_NAME} audit ./contracts/Token.sol --format sarif -o results.sarif
  ${PROGRAM_NAME} diff ./old/Token.sol ./new/Token.sol
  ${PROGRAM_NAME} gas ./contracts/Token.sol --format json
  ${PROGRAM_NAME} invariants ./contracts/Vault.sol --protocol vault
  ${PROGRAM_NAME} explain SWC-107
  ${PROGRAM_NAME} explain reentrancy --context "ERC-4626 vault"

CI/CD Integration (GitHub Code Scanning):
  ${PROGRAM_NAME} audit src/ --format sarif --output audit-results.sarif
  # Then use github/codeql-action/upload-sarif@v3 to upload

Exit Codes:
  0 - No findings above threshold
  1 - Findings above threshold detected
  2 - Execution error
`;

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  informational: 4,
};

// ============================================================================
// Argument Parser using node:util parseArgs
// ============================================================================

function parseCliArgs(): { command: string; args: string[]; options: CliOptions } {
  try {
    const { values, positionals } = parseArgs({
      args: process.argv.slice(2),
      options: {
        format: {
          type: "string",
          short: "f",
          default: "markdown",
        },
        output: {
          type: "string",
          short: "o",
        },
        severity: {
          type: "string",
          short: "s",
          default: "low",
        },
        "focus-only": {
          type: "boolean",
          default: true,
        },
        quiet: {
          type: "boolean",
          short: "q",
          default: false,
        },
        "no-color": {
          type: "boolean",
          default: false,
        },
        protocol: {
          type: "string",
          short: "p",
          default: "auto",
        },
        context: {
          type: "string",
          short: "c",
        },
        help: {
          type: "boolean",
          short: "h",
          default: false,
        },
        version: {
          type: "boolean",
          short: "v",
          default: false,
        },
      },
      allowPositionals: true,
      strict: false,
    });

    // Handle help and version flags
    if (values["help"]) {
      return { command: "help", args: [], options: getDefaultOptions() };
    }
    if (values["version"]) {
      return { command: "version", args: [], options: getDefaultOptions() };
    }

    // Validate format
    const format = values["format"] as string;
    if (!["markdown", "json", "sarif"].includes(format)) {
      throw new Error(`Invalid format: ${format}. Use markdown, json, or sarif.`);
    }

    // Validate severity
    const severity = (values["severity"] as string).toLowerCase();
    if (!["critical", "high", "medium", "low", "informational"].includes(severity)) {
      throw new Error(
        `Invalid severity: ${severity}. Use critical, high, medium, low, or informational.`
      );
    }

    const options: CliOptions = {
      format: format as OutputFormat,
      severityThreshold: severity as SeverityThreshold,
      focusOnly: values["focus-only"] as boolean,
      quiet: values["quiet"] as boolean,
      noColor: values["no-color"] as boolean,
      output: values["output"] ? resolve(values["output"] as string) : null,
      protocol: (values["protocol"] as string) || "auto",
      context: (values["context"] as string) || null,
    };

    const command = positionals[0] ?? "help";
    const args = positionals.slice(1);

    return { command, args, options };
  } catch (error) {
    if (error instanceof Error) {
      logError(error.message);
    }
    process.exit(2);
  }
}

function getDefaultOptions(): CliOptions {
  return {
    format: "markdown",
    severityThreshold: "low",
    focusOnly: true,
    quiet: false,
    noColor: false,
    output: null,
    protocol: "auto",
    context: null,
  };
}

// ============================================================================
// Commands
// ============================================================================

async function runAudit(contractPath: string, options: CliOptions): Promise<number> {
  const absolutePath = resolve(contractPath);

  if (!existsSync(absolutePath)) {
    logError(`File not found: ${absolutePath}`);
    return 2;
  }

  if (!absolutePath.endsWith(".sol")) {
    logError("Only Solidity (.sol) files are supported");
    return 2;
  }

  if (!options.quiet) {
    logInfo(`Analyzing ${basename(absolutePath)}...`);
  }

  try {
    const result = await analyzeContract({
      contractPath: absolutePath,
      projectRoot: dirname(absolutePath),
      runTests: false,
    });

    // Parse the result to extract findings
    const jsonMatch = result.match(/\n\{[\s\S]*\}$/);
    if (!jsonMatch) {
      writeOutput(result, options);
      return 0;
    }

    const data = JSON.parse(jsonMatch[0]) as Record<string, unknown>;
    const findings = (data["findings"] as Finding[] | undefined) ?? [];
    const gasOptimizations = (data["gasOptimizations"] as Finding[] | undefined) ?? [];
    const customFindings = (data["customFindings"] as Finding[] | undefined) ?? [];

    const allFindings = [...findings, ...gasOptimizations, ...customFindings];
    const filteredFindings = filterBySeverity(allFindings, options.severityThreshold);

    await outputResults(filteredFindings, absolutePath, options, data);

    return filteredFindings.length > 0 ? 1 : 0;
  } catch (error) {
    logError(`Analysis failed: ${error instanceof Error ? error.message : String(error)}`);
    return 2;
  }
}

async function runDiff(oldPath: string, newPath: string, options: CliOptions): Promise<number> {
  const absoluteOldPath = resolve(oldPath);
  const absoluteNewPath = resolve(newPath);

  if (!existsSync(absoluteOldPath)) {
    logError(`Old file not found: ${absoluteOldPath}`);
    return 2;
  }

  if (!existsSync(absoluteNewPath)) {
    logError(`New file not found: ${absoluteNewPath}`);
    return 2;
  }

  if (!absoluteOldPath.endsWith(".sol") || !absoluteNewPath.endsWith(".sol")) {
    logError("Only Solidity (.sol) files are supported");
    return 2;
  }

  if (!options.quiet) {
    logInfo(`Comparing ${basename(absoluteOldPath)} -> ${basename(absoluteNewPath)}...`);
  }

  try {
    const result = await diffAudit({
      oldContractPath: absoluteOldPath,
      newContractPath: absoluteNewPath,
      focusOnly: options.focusOnly,
    });

    if (!result.success) {
      logError(`Diff audit failed: ${result.error}`);
      return 2;
    }

    const filteredFindings = filterBySeverity(result.findings, options.severityThreshold);

    let output: string;
    if (options.format === "json") {
      output = JSON.stringify({ ...result, findings: filteredFindings }, null, 2);
    } else if (options.format === "sarif") {
      const sarif = generateSarifReport(filteredFindings, absoluteNewPath);
      output = JSON.stringify(sarif, null, 2);
    } else {
      output = result.report;
    }
    writeOutput(output, options);

    return filteredFindings.length > 0 ? 1 : 0;
  } catch (error) {
    logError(`Diff audit failed: ${error instanceof Error ? error.message : String(error)}`);
    return 2;
  }
}

async function runGas(contractPath: string, options: CliOptions): Promise<number> {
  const absolutePath = resolve(contractPath);

  if (!existsSync(absolutePath)) {
    logError(`File not found: ${absolutePath}`);
    return 2;
  }

  if (!absolutePath.endsWith(".sol")) {
    logError("Only Solidity (.sol) files are supported");
    return 2;
  }

  if (!options.quiet) {
    logInfo(`Analyzing gas usage in ${basename(absolutePath)}...`);
  }

  try {
    const result = await optimizeGas({
      contractPath: absolutePath,
      includeInformational: true,
    });

    const filteredFindings = filterBySeverity(result.findings, options.severityThreshold);

    let output: string;
    if (options.format === "json") {
      output = JSON.stringify({ ...result, findings: filteredFindings }, null, 2);
    } else if (options.format === "sarif") {
      const sarif = generateSarifReport(filteredFindings, absolutePath);
      output = JSON.stringify(sarif, null, 2);
    } else {
      output = formatGasOptimizationResult({
        ...result,
        findings: filteredFindings,
      });
    }
    writeOutput(output, options);

    const hasHighSeverity = filteredFindings.some(
      (f) => f.severity === Severity.HIGH || f.severity === Severity.CRITICAL
    );
    return hasHighSeverity ? 1 : 0;
  } catch (error) {
    logError(`Gas analysis failed: ${error instanceof Error ? error.message : String(error)}`);
    return 2;
  }
}

async function runInvariants(contractPath: string, options: CliOptions): Promise<number> {
  const absolutePath = resolve(contractPath);

  if (!existsSync(absolutePath)) {
    logError(`File not found: ${absolutePath}`);
    return 2;
  }

  if (!absolutePath.endsWith(".sol")) {
    logError("Only Solidity (.sol) files are supported");
    return 2;
  }

  const validProtocols = [
    "auto",
    "erc20",
    "erc721",
    "vault",
    "lending",
    "amm",
    "governance",
    "staking",
  ];
  if (!validProtocols.includes(options.protocol)) {
    logError(`Invalid protocol type: ${options.protocol}. Use: ${validProtocols.join(", ")}`);
    return 2;
  }

  if (!options.quiet) {
    logInfo(`Generating invariants for ${basename(absolutePath)}...`);
  }

  try {
    const result = await generateInvariants({
      contractPath: absolutePath,
      protocolType: options.protocol as
        | "auto"
        | "erc20"
        | "erc721"
        | "vault"
        | "lending"
        | "amm"
        | "governance"
        | "staking",
      includeStateful: true,
    });

    writeOutput(result, options);
    return 0;
  } catch (error) {
    logError(
      `Invariant generation failed: ${error instanceof Error ? error.message : String(error)}`
    );
    return 2;
  }
}

async function runExplain(findingId: string, options: CliOptions): Promise<number> {
  if (!findingId) {
    logError("Missing finding ID. Usage: solidity-audit-cli explain <finding-id>");
    return 2;
  }

  try {
    const result = await explainFinding({
      findingId,
      contractContext: options.context ?? undefined,
    });

    writeOutput(result, options);
    return 0;
  } catch (error) {
    logError(`Explain failed: ${error instanceof Error ? error.message : String(error)}`);
    return 2;
  }
}

// ============================================================================
// Helper Functions
// ============================================================================

function filterBySeverity(findings: Finding[], threshold: SeverityThreshold): Finding[] {
  const thresholdLevel = SEVERITY_ORDER[threshold] ?? 3;

  return findings.filter((f) => {
    const findingLevel = SEVERITY_ORDER[f.severity] ?? 4;
    return findingLevel <= thresholdLevel;
  });
}

async function outputResults(
  findings: Finding[],
  contractPath: string,
  options: CliOptions,
  rawData: Record<string, unknown>
): Promise<void> {
  let output: string;

  if (options.format === "json") {
    output = JSON.stringify({ ...rawData, findings }, null, 2);
  } else if (options.format === "sarif") {
    const sarif = generateSarifReport(findings, contractPath);
    output = JSON.stringify(sarif, null, 2);
  } else {
    const contractName = basename(contractPath, ".sol");
    output = formatMarkdownReport(findings, contractName, contractPath, rawData);
  }

  writeOutput(output, options);
}

function formatMarkdownReport(
  findings: Finding[],
  contractName: string,
  contractPath: string,
  rawData: Record<string, unknown>
): string {
  const lines: string[] = [];

  lines.push(`# Security Audit Report: ${contractName}`);
  lines.push("");
  lines.push(`**Path:** ${contractPath}`);
  lines.push(`**Date:** ${new Date().toISOString()}`);
  lines.push("");

  // Summary
  const summary = {
    critical: findings.filter((f) => f.severity === Severity.CRITICAL).length,
    high: findings.filter((f) => f.severity === Severity.HIGH).length,
    medium: findings.filter((f) => f.severity === Severity.MEDIUM).length,
    low: findings.filter((f) => f.severity === Severity.LOW).length,
    informational: findings.filter((f) => f.severity === Severity.INFORMATIONAL).length,
  };

  lines.push("## Summary");
  lines.push("");
  lines.push("| Severity | Count |");
  lines.push("|----------|-------|");
  lines.push(`| Critical | ${summary.critical} |`);
  lines.push(`| High | ${summary.high} |`);
  lines.push(`| Medium | ${summary.medium} |`);
  lines.push(`| Low | ${summary.low} |`);
  lines.push(`| Informational | ${summary.informational} |`);
  lines.push(`| **Total** | **${findings.length}** |`);
  lines.push("");

  // Findings
  if (findings.length > 0) {
    lines.push("## Findings");
    lines.push("");

    for (const finding of findings) {
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
  } else {
    lines.push("## Findings");
    lines.push("");
    lines.push("No findings detected above the specified severity threshold.");
    lines.push("");
  }

  // Tools used
  const toolsUsed = rawData["toolsUsed"];
  if (toolsUsed && Array.isArray(toolsUsed)) {
    lines.push("## Tools Used");
    lines.push("");
    for (const tool of toolsUsed) {
      lines.push(`- ${tool}`);
    }
    lines.push("");
  }

  lines.push("---");
  lines.push("*Generated by MCP Audit Server CLI*");

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

function logInfo(message: string): void {
  logger.info(message);
}

function logError(message: string): void {
  logger.error(message);
}

function writeOutput(content: string, options: CliOptions): void {
  if (options.output) {
    writeFileSync(options.output, content, "utf-8");
    if (!options.quiet) {
      logInfo(`Output written to ${options.output}`);
    }
  } else {
    process.stdout.write(content + "\n");
  }
}

// ============================================================================
// Main Entry Point
// ============================================================================

async function main(): Promise<void> {
  let exitCode = 0;

  try {
    const { command, args, options } = parseCliArgs();

    // Suppress logs if quiet mode or structured output
    if (options.quiet || options.format === "sarif" || options.format === "json") {
      // Set environment variable to suppress internal logs
      process.env["LOG_LEVEL"] = "error";
    }

    switch (command) {
      case "audit": {
        const path = args[0];
        if (!path) {
          logError("Missing contract path. Usage: solidity-audit-cli audit <path>");
          exitCode = 2;
        } else {
          exitCode = await runAudit(path, options);
        }
        break;
      }

      case "diff": {
        const oldPath = args[0];
        const newPath = args[1];
        if (!oldPath || !newPath) {
          logError("Missing paths. Usage: solidity-audit-cli diff <old-path> <new-path>");
          exitCode = 2;
        } else {
          exitCode = await runDiff(oldPath, newPath, options);
        }
        break;
      }

      case "gas": {
        const path = args[0];
        if (!path) {
          logError("Missing contract path. Usage: solidity-audit-cli gas <path>");
          exitCode = 2;
        } else {
          exitCode = await runGas(path, options);
        }
        break;
      }

      case "invariants": {
        const path = args[0];
        if (!path) {
          logError("Missing contract path. Usage: solidity-audit-cli invariants <path>");
          exitCode = 2;
        } else {
          exitCode = await runInvariants(path, options);
        }
        break;
      }

      case "explain": {
        const findingId = args[0];
        if (!findingId) {
          logError("Missing finding ID. Usage: solidity-audit-cli explain <finding-id>");
          exitCode = 2;
        } else {
          exitCode = await runExplain(findingId, options);
        }
        break;
      }

      case "help":
        process.stdout.write(HELP_TEXT + "\n");
        exitCode = 0;
        break;

      case "version":
        process.stdout.write(`${PROGRAM_NAME} v${VERSION}\n`);
        exitCode = 0;
        break;

      default:
        logError(`Unknown command: ${command}`);
        process.stderr.write(HELP_TEXT + "\n");
        exitCode = 2;
    }
  } catch (error) {
    logError(error instanceof Error ? error.message : String(error));
    exitCode = 2;
  }

  process.exit(exitCode);
}

// Run CLI
main();
