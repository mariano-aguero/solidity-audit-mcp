/**
 * Tool Handlers
 *
 * Functions that execute MCP tools. Used by both stdio and HTTP/SSE servers.
 */

import { z } from "zod";

import { logger } from "../../utils/logger.js";

// Tool imports
import { analyzeContract } from "../../tools/analyzeContract.js";
import { getContractInfo } from "../../tools/getContractInfo.js";
import { checkVulnerabilities } from "../../tools/checkVulnerabilities.js";
import { runTests } from "../../tools/runTests.js";
import { generateReport } from "../../tools/generateReport.js";
import { optimizeGas, formatGasOptimizationResult } from "../../tools/optimizeGas.js";
import { diffAudit } from "../../tools/diffAudit.js";
import { auditProject } from "../../tools/auditProject.js";

// Schema imports
import {
  AnalyzeContractInputSchema,
  GetContractInfoInputSchema,
  CheckVulnerabilitiesInputSchema,
  RunTestsInputSchema,
  GenerateReportInputSchema,
  OptimizeGasInputSchema,
  DiffAuditInputSchema,
  AuditProjectInputSchema,
} from "../schemas/index.js";

// Tool definitions
import { TOOLS } from "../tools/toolDefinitions.js";

// ============================================================================
// Types
// ============================================================================

export interface ToolResult {
  content: Array<{ type: "text"; text: string }>;
  isError?: boolean;
  [key: string]: unknown;
}

export type ToolName =
  | "analyze_contract"
  | "get_contract_info"
  | "check_vulnerabilities"
  | "run_tests"
  | "generate_report"
  | "optimize_gas"
  | "diff_audit"
  | "audit_project";

// ============================================================================
// Individual Tool Handlers
// ============================================================================

async function handleAnalyzeContract(args: unknown): Promise<string> {
  const input = AnalyzeContractInputSchema.parse(args);
  logger.info(`analyze_contract called`, { contractPath: input.contractPath });
  return await analyzeContract(input);
}

async function handleGetContractInfo(args: unknown): Promise<string> {
  const input = GetContractInfoInputSchema.parse(args);
  logger.info(`get_contract_info called`, { contractPath: input.contractPath });
  return await getContractInfo(input);
}

async function handleCheckVulnerabilities(args: unknown): Promise<string> {
  const input = CheckVulnerabilitiesInputSchema.parse(args);
  logger.info(`check_vulnerabilities called`, { contractPath: input.contractPath });
  return await checkVulnerabilities(input);
}

async function handleRunTests(args: unknown): Promise<string> {
  const input = RunTestsInputSchema.parse(args);
  logger.info(`run_tests called`, { projectRoot: input.projectRoot });
  return await runTests(input);
}

async function handleGenerateReport(args: unknown): Promise<string> {
  const input = GenerateReportInputSchema.parse(args);
  logger.info(`generate_report called`, { format: input.format });
  return await generateReport(input);
}

async function handleOptimizeGas(args: unknown): Promise<string> {
  const input = OptimizeGasInputSchema.parse(args);
  logger.info(`optimize_gas called`, { contractPath: input.contractPath });
  const result = await optimizeGas(input);
  return formatGasOptimizationResult(result);
}

async function handleDiffAudit(args: unknown): Promise<string> {
  const input = DiffAuditInputSchema.parse(args);
  logger.info(`diff_audit called`, {
    oldContractPath: input.oldContractPath,
    newContractPath: input.newContractPath,
  });
  const result = await diffAudit(input);
  return result.report;
}

async function handleAuditProject(args: unknown): Promise<string> {
  const input = AuditProjectInputSchema.parse(args);
  logger.info(`audit_project called`, { projectRoot: input.projectRoot });
  return await auditProject(input);
}

// ============================================================================
// Tool Handler Registry
// ============================================================================

const TOOL_HANDLERS: Record<ToolName, (args: unknown) => Promise<string>> = {
  analyze_contract: handleAnalyzeContract,
  get_contract_info: handleGetContractInfo,
  check_vulnerabilities: handleCheckVulnerabilities,
  run_tests: handleRunTests,
  generate_report: handleGenerateReport,
  optimize_gas: handleOptimizeGas,
  diff_audit: handleDiffAudit,
  audit_project: handleAuditProject,
};

// ============================================================================
// Main Tool Executor
// ============================================================================

/**
 * Execute a tool by name with the given arguments.
 *
 * @param name - Tool name
 * @param args - Tool arguments (will be validated)
 * @returns Tool result in MCP format
 */
export async function executeTool(name: string, args: unknown): Promise<ToolResult> {
  logger.info(`CallTool request: ${name}`);

  try {
    const handler = TOOL_HANDLERS[name as ToolName];

    if (!handler) {
      logger.error(`Unknown tool requested: ${name}`);
      return {
        content: [
          {
            type: "text",
            text: `Error: Unknown tool "${name}". Available tools: ${TOOLS.map((t) => t.name).join(", ")}`,
          },
        ],
        isError: true,
      };
    }

    const result = await handler(args);

    return {
      content: [{ type: "text", text: result }],
    };
  } catch (error) {
    return handleToolError(name, error);
  }
}

/**
 * Handle tool execution errors.
 */
function handleToolError(toolName: string, error: unknown): ToolResult {
  const errorMessage = error instanceof Error ? error.message : String(error);
  logger.error(`Error executing tool ${toolName}: ${errorMessage}`);

  // Handle Zod validation errors specially
  if (error instanceof z.ZodError) {
    const issues = error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ");
    return {
      content: [{ type: "text", text: `Validation error: ${issues}` }],
      isError: true,
    };
  }

  return {
    content: [{ type: "text", text: `Error: ${errorMessage}` }],
    isError: true,
  };
}

/**
 * Check if a tool name is valid.
 */
export function isValidToolName(name: string): name is ToolName {
  return name in TOOL_HANDLERS;
}
