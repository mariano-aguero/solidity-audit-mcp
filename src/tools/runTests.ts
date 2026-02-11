/**
 * Run Tests Tool
 *
 * Executes project tests and coverage analysis.
 * Supports both Foundry and Hardhat projects.
 */

import { access } from "fs/promises";
import { z } from "zod";
import {
  executeCommand,
  detectProjectType,
  formatDuration,
  checkToolAvailable,
} from "../utils/executor.js";
import { logger } from "../utils/logger.js";

// ============================================================================
// Types
// ============================================================================

export const RunTestsInputSchema = z.object({
  projectRoot: z.string().describe("Root directory of the project"),
  contractName: z.string().optional().describe("Specific contract to test (runs all if omitted)"),
});

export type RunTestsInput = z.infer<typeof RunTestsInputSchema>;

export interface TestSummary {
  total: number;
  passed: number;
  failed: number;
  skipped: number;
  duration: number;
}

export interface CoverageReport {
  lines: number;
  branches: number;
  functions: number;
  statements: number;
  byContract?: Record<
    string,
    {
      lines: number;
      branches: number;
      functions: number;
      statements: number;
    }
  >;
}

export interface FailedTest {
  name: string;
  contract: string;
  error: string;
  gasUsed?: number;
}

export interface GasReport {
  contracts: Array<{
    name: string;
    deploymentCost: number;
    functions: Array<{
      name: string;
      minGas: number;
      avgGas: number;
      maxGas: number;
      calls: number;
    }>;
  }>;
}

export interface TestResults {
  projectType: "foundry" | "hardhat" | "unknown";
  testSummary: TestSummary;
  coverage?: CoverageReport;
  failedTests: FailedTest[];
  gasReport?: GasReport;
  warnings: string[];
  rawOutput: {
    testOutput: string;
    coverageOutput?: string;
  };
}

// ============================================================================
// Main Function
// ============================================================================

/**
 * Run tests and coverage for a Solidity project.
 *
 * @param input - Input containing project root and optional contract filter
 * @returns Test results with coverage and gas report
 */
export async function runTests(input: RunTestsInput): Promise<string> {
  const startTime = Date.now();
  const warnings: string[] = [];

  logger.info(`[runTests] Running tests in ${input.projectRoot}`);

  // Validate project root exists
  try {
    await access(input.projectRoot);
  } catch {
    return formatError(`Project directory not found: ${input.projectRoot}`);
  }

  // Detect project type
  const projectType = await detectProjectType(input.projectRoot);
  logger.info(`[runTests] Detected project type: ${projectType}`);

  if (projectType === "unknown") {
    return formatError(
      "Could not detect project type. Ensure foundry.toml or hardhat.config.* exists."
    );
  }

  // Run tests based on project type
  let results: TestResults;

  if (projectType === "foundry") {
    results = await runFoundryTests(input.projectRoot, input.contractName);
  } else if (projectType === "hardhat") {
    results = await runHardhatTests(input.projectRoot, input.contractName);
  } else {
    return formatError(`Unsupported project type: ${projectType}`);
  }

  // Add coverage warnings
  if (results.coverage) {
    const avgCoverage =
      (results.coverage.lines +
        results.coverage.branches +
        results.coverage.functions +
        results.coverage.statements) /
      4;

    if (avgCoverage < 50) {
      warnings.push(
        `⚠️  CRITICAL: Test coverage is very low (${avgCoverage.toFixed(1)}%). ` +
          "This is a significant security risk."
      );
    } else if (avgCoverage < 80) {
      warnings.push(
        `⚠️  WARNING: Test coverage is below 80% (${avgCoverage.toFixed(1)}%). ` +
          "Consider adding more tests."
      );
    }
  } else {
    warnings.push("⚠️  Coverage data not available");
  }

  // Add test failure warning
  if (results.testSummary.failed > 0) {
    warnings.push(`🔴 ${results.testSummary.failed} test(s) failed. Fix these before deployment.`);
  }

  // Add no tests warning
  if (results.testSummary.total === 0) {
    warnings.push("⚠️  CRITICAL: No tests found. Untested contracts are a major security risk.");
  }

  results.warnings = [...results.warnings, ...warnings];

  const totalTime = Date.now() - startTime;
  logger.info(`[runTests] Completed in ${formatDuration(totalTime)}`);

  return formatOutput(results, totalTime);
}

// ============================================================================
// Foundry Tests
// ============================================================================

async function runFoundryTests(projectRoot: string, contractName?: string): Promise<TestResults> {
  const warnings: string[] = [];

  // Check if forge is available
  const forgeAvailable = await checkToolAvailable("forge");
  if (!forgeAvailable.available) {
    return {
      projectType: "foundry",
      testSummary: { total: 0, passed: 0, failed: 0, skipped: 0, duration: 0 },
      failedTests: [],
      warnings: ["Forge not installed. Install with: curl -L https://foundry.paradigm.xyz | bash"],
      rawOutput: { testOutput: "" },
    };
  }

  // Build test command
  const testArgs = ["test", "--json", "-v"];

  if (contractName) {
    testArgs.push("--match-contract", contractName);
  }

  // Run tests
  logger.info(`[runTests] Running: forge ${testArgs.join(" ")}`);
  const testResult = await executeCommand("forge", testArgs, {
    cwd: projectRoot,
    timeout: 300_000, // 5 minutes
  });

  // Parse test results
  const { summary, failedTests } = parseForgeTestOutput(testResult.stdout);

  // Run gas report
  const gasArgs = ["test", "--gas-report"];
  if (contractName) {
    gasArgs.push("--match-contract", contractName);
  }

  logger.info(`[runTests] Running: forge ${gasArgs.join(" ")}`);
  const gasResult = await executeCommand("forge", gasArgs, {
    cwd: projectRoot,
    timeout: 300_000,
  });

  const gasReport = parseForgeGasReport(gasResult.stdout);

  // Run coverage
  let coverage: CoverageReport | undefined;
  let coverageOutput: string | undefined;

  try {
    logger.info("[runTests] Running: forge coverage --report summary");
    const coverageResult = await executeCommand("forge", ["coverage", "--report", "summary"], {
      cwd: projectRoot,
      timeout: 300_000,
    });

    if (coverageResult.exitCode === 0) {
      coverage = parseForgeCoverage(coverageResult.stdout);
      coverageOutput = coverageResult.stdout;
    } else {
      warnings.push("Coverage analysis failed: " + coverageResult.stderr.slice(0, 200));
    }
  } catch (err) {
    warnings.push(`Coverage failed: ${err instanceof Error ? err.message : String(err)}`);
  }

  return {
    projectType: "foundry",
    testSummary: summary,
    coverage,
    failedTests,
    gasReport,
    warnings,
    rawOutput: {
      testOutput: testResult.stdout,
      coverageOutput,
    },
  };
}

/**
 * Parse forge test JSON output
 */
function parseForgeTestOutput(output: string): {
  summary: TestSummary;
  failedTests: FailedTest[];
} {
  const summary: TestSummary = {
    total: 0,
    passed: 0,
    failed: 0,
    skipped: 0,
    duration: 0,
  };
  const failedTests: FailedTest[] = [];

  // Try to parse each line as JSON (forge outputs one JSON per test file)
  const lines = output.split("\n");

  for (const line of lines) {
    if (!line.trim().startsWith("{")) continue;

    try {
      const data = JSON.parse(line) as Record<
        string,
        Record<
          string,
          {
            status: string;
            reason?: string;
            decoded_logs?: string[];
            gas?: number;
            duration?: { secs: number; nanos: number };
          }
        >
      >;

      // Each key is a contract name, each value contains test results
      for (const [contractName, tests] of Object.entries(data)) {
        for (const [testName, result] of Object.entries(tests)) {
          summary.total++;

          if (result.status === "Success") {
            summary.passed++;
          } else if (result.status === "Skipped") {
            summary.skipped++;
          } else {
            summary.failed++;
            failedTests.push({
              name: testName,
              contract: contractName,
              error: result.reason ?? "Unknown error",
              gasUsed: result.gas,
            });
          }

          if (result.duration) {
            summary.duration += result.duration.secs * 1000 + result.duration.nanos / 1_000_000;
          }
        }
      }
    } catch {
      // Not valid JSON, skip
    }
  }

  // Fallback: parse summary from stdout
  if (summary.total === 0) {
    const passMatch = output.match(/(\d+)\s+passed/);
    const failMatch = output.match(/(\d+)\s+failed/);
    const skipMatch = output.match(/(\d+)\s+skipped/);

    if (passMatch) summary.passed = parseInt(passMatch[1]!, 10);
    if (failMatch) summary.failed = parseInt(failMatch[1]!, 10);
    if (skipMatch) summary.skipped = parseInt(skipMatch[1]!, 10);
    summary.total = summary.passed + summary.failed + summary.skipped;
  }

  return { summary, failedTests };
}

/**
 * Parse forge gas report
 */
function parseForgeGasReport(output: string): GasReport | undefined {
  const contracts: GasReport["contracts"] = [];

  let currentContract: (typeof contracts)[0] | null = null;
  const lines = output.split("\n");

  for (const line of lines) {
    // Check for contract header
    const contractMatch = line.match(/\|\s*(\w+)\s+contract\s*\|/i);
    if (contractMatch) {
      if (currentContract) {
        contracts.push(currentContract);
      }
      currentContract = {
        name: contractMatch[1]!,
        deploymentCost: 0,
        functions: [],
      };
      continue;
    }

    // Check for deployment cost
    const deployMatch = line.match(/Deployment Cost:\s*(\d+)/);
    if (deployMatch && currentContract) {
      currentContract.deploymentCost = parseInt(deployMatch[1]!, 10);
      continue;
    }

    // Check for function gas
    if (currentContract) {
      const funcMatch = line.match(
        /\|\s*(\w+)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|/
      );
      if (funcMatch) {
        currentContract.functions.push({
          name: funcMatch[1]!,
          minGas: parseInt(funcMatch[2]!, 10),
          avgGas: parseInt(funcMatch[3]!, 10),
          maxGas: parseInt(funcMatch[4]!, 10),
          calls: parseInt(funcMatch[5]!, 10),
        });
      }
    }
  }

  if (currentContract) {
    contracts.push(currentContract);
  }

  return contracts.length > 0 ? { contracts } : undefined;
}

/**
 * Parse forge coverage summary
 */
function parseForgeCoverage(output: string): CoverageReport {
  const report: CoverageReport = {
    lines: 0,
    branches: 0,
    functions: 0,
    statements: 0,
    byContract: {},
  };

  // Parse total line: | Total | xx.xx% | xx.xx% | xx.xx% | xx.xx% |
  const totalMatch = output.match(
    /\|\s*Total\s*\|\s*([\d.]+)%\s*\|\s*([\d.]+)%\s*\|\s*([\d.]+)%\s*\|\s*([\d.]+)%\s*\|/
  );

  if (totalMatch) {
    report.lines = parseFloat(totalMatch[1]!);
    report.statements = parseFloat(totalMatch[2]!);
    report.branches = parseFloat(totalMatch[3]!);
    report.functions = parseFloat(totalMatch[4]!);
  }

  // Parse per-contract coverage
  const contractRegex =
    /\|\s*([^|]+\.sol)\s*\|\s*([\d.]+)%\s*\|\s*([\d.]+)%\s*\|\s*([\d.]+)%\s*\|\s*([\d.]+)%\s*\|/g;

  let match;
  while ((match = contractRegex.exec(output)) !== null) {
    const contractName = match[1]!.trim();
    report.byContract![contractName] = {
      lines: parseFloat(match[2]!),
      statements: parseFloat(match[3]!),
      branches: parseFloat(match[4]!),
      functions: parseFloat(match[5]!),
    };
  }

  return report;
}

// ============================================================================
// Hardhat Tests
// ============================================================================

async function runHardhatTests(projectRoot: string, contractName?: string): Promise<TestResults> {
  const warnings: string[] = [];

  // Check if npx is available
  const npxAvailable = await checkToolAvailable("npx");
  if (!npxAvailable.available) {
    return {
      projectType: "hardhat",
      testSummary: { total: 0, passed: 0, failed: 0, skipped: 0, duration: 0 },
      failedTests: [],
      warnings: ["npx not available. Ensure Node.js is installed."],
      rawOutput: { testOutput: "" },
    };
  }

  // Build test command
  const testArgs = ["hardhat", "test"];

  if (contractName) {
    testArgs.push("--grep", contractName);
  }

  // Run tests
  logger.info(`[runTests] Running: npx ${testArgs.join(" ")}`);
  const testResult = await executeCommand("npx", testArgs, {
    cwd: projectRoot,
    timeout: 300_000,
  });

  // Parse test results
  const { summary, failedTests } = parseHardhatTestOutput(testResult.stdout + testResult.stderr);

  // Run coverage
  let coverage: CoverageReport | undefined;
  let coverageOutput: string | undefined;

  try {
    // Check if solidity-coverage is installed
    const coverageCheck = await executeCommand("npx", ["hardhat", "coverage", "--help"], {
      cwd: projectRoot,
      timeout: 30_000,
    });

    if (coverageCheck.exitCode === 0) {
      logger.info("[runTests] Running: npx hardhat coverage");
      const coverageResult = await executeCommand(
        "npx",
        ["hardhat", "coverage"],
        { cwd: projectRoot, timeout: 600_000 } // Coverage can take a while
      );

      if (coverageResult.exitCode === 0) {
        coverage = parseHardhatCoverage(coverageResult.stdout);
        coverageOutput = coverageResult.stdout;
      } else {
        warnings.push("Coverage failed: " + coverageResult.stderr.slice(0, 200));
      }
    } else {
      warnings.push(
        "solidity-coverage not installed. Run: npm install --save-dev solidity-coverage"
      );
    }
  } catch (err) {
    warnings.push(`Coverage failed: ${err instanceof Error ? err.message : String(err)}`);
  }

  return {
    projectType: "hardhat",
    testSummary: summary,
    coverage,
    failedTests,
    warnings,
    rawOutput: {
      testOutput: testResult.stdout,
      coverageOutput,
    },
  };
}

/**
 * Parse Hardhat/Mocha test output
 */
function parseHardhatTestOutput(output: string): {
  summary: TestSummary;
  failedTests: FailedTest[];
} {
  const summary: TestSummary = {
    total: 0,
    passed: 0,
    failed: 0,
    skipped: 0,
    duration: 0,
  };
  const failedTests: FailedTest[] = [];

  // Parse summary line: "X passing (Xs)"
  const passMatch = output.match(/(\d+)\s+passing/);
  const failMatch = output.match(/(\d+)\s+failing/);
  const pendMatch = output.match(/(\d+)\s+pending/);
  const durationMatch = output.match(/\((\d+(?:\.\d+)?)(m?s)\)/);

  if (passMatch) summary.passed = parseInt(passMatch[1]!, 10);
  if (failMatch) summary.failed = parseInt(failMatch[1]!, 10);
  if (pendMatch) summary.skipped = parseInt(pendMatch[1]!, 10);
  summary.total = summary.passed + summary.failed + summary.skipped;

  if (durationMatch) {
    const value = parseFloat(durationMatch[1]!);
    const unit = durationMatch[2];
    summary.duration = unit === "ms" ? value : value * 1000;
  }

  // Parse failed tests
  const failedTestRegex = /\d+\)\s+([^\n]+)\n\s+([^\n]+)/g;
  let match;
  while ((match = failedTestRegex.exec(output)) !== null) {
    failedTests.push({
      name: match[1]!.trim(),
      contract: "Unknown",
      error: match[2]!.trim(),
    });
  }

  return { summary, failedTests };
}

/**
 * Parse Hardhat coverage output (Istanbul format)
 */
function parseHardhatCoverage(output: string): CoverageReport {
  const report: CoverageReport = {
    lines: 0,
    branches: 0,
    functions: 0,
    statements: 0,
    byContract: {},
  };

  // Parse All files summary
  // Format: All files | 85.71 | 75 | 90 | 85.71 |
  const totalMatch = output.match(
    /All files\s*\|\s*([\d.]+)\s*\|\s*([\d.]+)\s*\|\s*([\d.]+)\s*\|\s*([\d.]+)/
  );

  if (totalMatch) {
    report.statements = parseFloat(totalMatch[1]!);
    report.branches = parseFloat(totalMatch[2]!);
    report.functions = parseFloat(totalMatch[3]!);
    report.lines = parseFloat(totalMatch[4]!);
  }

  // Parse per-file coverage
  const fileRegex =
    /([^\s|]+\.sol)\s*\|\s*([\d.]+)\s*\|\s*([\d.]+)\s*\|\s*([\d.]+)\s*\|\s*([\d.]+)/g;

  let match;
  while ((match = fileRegex.exec(output)) !== null) {
    const fileName = match[1]!;
    report.byContract![fileName] = {
      statements: parseFloat(match[2]!),
      branches: parseFloat(match[3]!),
      functions: parseFloat(match[4]!),
      lines: parseFloat(match[5]!),
    };
  }

  return report;
}

// ============================================================================
// Output Formatting
// ============================================================================

function formatError(message: string): string {
  return JSON.stringify({ success: false, error: message }, null, 2);
}

function formatOutput(results: TestResults, totalTime: number): string {
  const lines: string[] = [];

  // Header
  lines.push("═══════════════════════════════════════════════════════════════════════════════");
  lines.push(`  TEST RESULTS (${results.projectType.toUpperCase()})`);
  lines.push("═══════════════════════════════════════════════════════════════════════════════");
  lines.push("");

  // Test Summary
  lines.push("┌─────────────────────────────────────────────────────────────────────────────┐");
  lines.push("│  TEST SUMMARY                                                               │");
  lines.push("└─────────────────────────────────────────────────────────────────────────────┘");

  const { testSummary } = results;
  const passRate =
    testSummary.total > 0 ? ((testSummary.passed / testSummary.total) * 100).toFixed(1) : "0";

  const statusEmoji = testSummary.failed > 0 ? "🔴" : testSummary.total === 0 ? "⚠️" : "✅";

  lines.push(
    `  ${statusEmoji} Status: ${testSummary.failed > 0 ? "FAILING" : testSummary.total === 0 ? "NO TESTS" : "PASSING"}`
  );
  lines.push(`  Total tests: ${testSummary.total}`);
  lines.push(`    ✅ Passed: ${testSummary.passed}`);
  lines.push(`    ❌ Failed: ${testSummary.failed}`);
  lines.push(`    ⏭️  Skipped: ${testSummary.skipped}`);
  lines.push(`  Pass rate: ${passRate}%`);
  lines.push(`  Duration: ${formatDuration(testSummary.duration)}`);
  lines.push("");

  // Failed Tests
  if (results.failedTests.length > 0) {
    lines.push("┌─────────────────────────────────────────────────────────────────────────────┐");
    lines.push("│  FAILED TESTS                                                               │");
    lines.push("└─────────────────────────────────────────────────────────────────────────────┘");

    for (const test of results.failedTests) {
      lines.push(`  ❌ ${test.contract}::${test.name}`);
      lines.push(`     Error: ${test.error.slice(0, 100)}`);
      if (test.gasUsed) {
        lines.push(`     Gas: ${test.gasUsed.toLocaleString()}`);
      }
    }
    lines.push("");
  }

  // Coverage
  if (results.coverage) {
    lines.push("┌─────────────────────────────────────────────────────────────────────────────┐");
    lines.push("│  CODE COVERAGE                                                              │");
    lines.push("└─────────────────────────────────────────────────────────────────────────────┘");

    const { coverage } = results;
    const avgCoverage =
      (coverage.lines + coverage.branches + coverage.functions + coverage.statements) / 4;

    const coverageEmoji = avgCoverage >= 80 ? "✅" : avgCoverage >= 50 ? "🟡" : "🔴";

    lines.push(`  ${coverageEmoji} Average coverage: ${avgCoverage.toFixed(1)}%`);
    lines.push("");
    lines.push(`  Lines:      ${formatCoverageBar(coverage.lines)} ${coverage.lines.toFixed(1)}%`);
    lines.push(
      `  Branches:   ${formatCoverageBar(coverage.branches)} ${coverage.branches.toFixed(1)}%`
    );
    lines.push(
      `  Functions:  ${formatCoverageBar(coverage.functions)} ${coverage.functions.toFixed(1)}%`
    );
    lines.push(
      `  Statements: ${formatCoverageBar(coverage.statements)} ${coverage.statements.toFixed(1)}%`
    );

    // Per-contract coverage
    if (coverage.byContract && Object.keys(coverage.byContract).length > 0) {
      lines.push("");
      lines.push("  By Contract:");
      for (const [contract, cov] of Object.entries(coverage.byContract)) {
        const contractAvg = (cov.lines + cov.branches + cov.functions + cov.statements) / 4;
        const emoji = contractAvg >= 80 ? "✅" : contractAvg >= 50 ? "🟡" : "🔴";
        lines.push(`    ${emoji} ${contract}: ${contractAvg.toFixed(1)}%`);
      }
    }
    lines.push("");
  }

  // Gas Report
  if (results.gasReport && results.gasReport.contracts.length > 0) {
    lines.push("┌─────────────────────────────────────────────────────────────────────────────┐");
    lines.push("│  GAS REPORT                                                                 │");
    lines.push("└─────────────────────────────────────────────────────────────────────────────┘");

    for (const contract of results.gasReport.contracts) {
      lines.push(`  📄 ${contract.name}`);
      if (contract.deploymentCost > 0) {
        lines.push(`     Deployment: ${contract.deploymentCost.toLocaleString()} gas`);
      }

      if (contract.functions.length > 0) {
        lines.push("     Functions:");
        // Show top 5 by avg gas
        const topFunctions = [...contract.functions]
          .sort((a, b) => b.avgGas - a.avgGas)
          .slice(0, 5);

        for (const fn of topFunctions) {
          lines.push(
            `       • ${fn.name}: avg ${fn.avgGas.toLocaleString()} gas (${fn.calls} calls)`
          );
        }
      }
      lines.push("");
    }
  }

  // Warnings
  if (results.warnings.length > 0) {
    lines.push("┌─────────────────────────────────────────────────────────────────────────────┐");
    lines.push("│  WARNINGS                                                                   │");
    lines.push("└─────────────────────────────────────────────────────────────────────────────┘");

    for (const warning of results.warnings) {
      lines.push(`  ${warning}`);
    }
    lines.push("");
  }

  // Security implications
  lines.push("┌─────────────────────────────────────────────────────────────────────────────┐");
  lines.push("│  SECURITY IMPLICATIONS                                                       │");
  lines.push("└─────────────────────────────────────────────────────────────────────────────┘");

  if (testSummary.total === 0) {
    lines.push("  🔴 CRITICAL: No tests found");
    lines.push("     Untested code is a major security risk. Add comprehensive tests");
    lines.push("     covering all public functions and edge cases.");
  } else if (testSummary.failed > 0) {
    lines.push("  🔴 CRITICAL: Tests are failing");
    lines.push("     Failing tests indicate bugs that could be security vulnerabilities.");
    lines.push("     Fix all failing tests before deployment.");
  } else if (results.coverage && results.coverage.lines < 50) {
    lines.push("  🟠 WARNING: Very low test coverage");
    lines.push("     Less than 50% line coverage means most code is untested.");
    lines.push("     Aim for at least 80% coverage for security-critical contracts.");
  } else if (results.coverage && results.coverage.branches < 70) {
    lines.push("  🟡 NOTE: Branch coverage could be improved");
    lines.push("     Low branch coverage means edge cases may not be tested.");
  } else {
    lines.push("  ✅ Test suite looks healthy");
  }

  lines.push("");
  lines.push("═══════════════════════════════════════════════════════════════════════════════");
  lines.push(`  Total execution time: ${formatDuration(totalTime)}`);
  lines.push("═══════════════════════════════════════════════════════════════════════════════");

  // Add JSON data
  lines.push("");
  lines.push("JSON DATA:");
  lines.push(
    JSON.stringify(
      {
        success: true,
        projectType: results.projectType,
        testSummary: results.testSummary,
        coverage: results.coverage,
        failedTestsCount: results.failedTests.length,
        failedTests: results.failedTests,
        warningsCount: results.warnings.length,
        warnings: results.warnings,
        hasGasReport: !!results.gasReport,
      },
      null,
      2
    )
  );

  return lines.join("\n");
}

/**
 * Format a coverage percentage as a progress bar
 */
function formatCoverageBar(percentage: number): string {
  const filled = Math.round(percentage / 10);
  const empty = 10 - filled;
  const bar = "█".repeat(filled) + "░".repeat(empty);

  if (percentage >= 80) return `[${bar}]`;
  if (percentage >= 50) return `[${bar}]`;
  return `[${bar}]`;
}
