#!/usr/bin/env node

/**
 * MCP Audit Server
 *
 * A Model Context Protocol server for automated security audits
 * of Solidity smart contracts. Integrates with Slither, Aderyn,
 * and Foundry to provide comprehensive vulnerability detection.
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";

// Utils
import { logger } from "./utils/logger.js";

// Tool imports
import { analyzeContract } from "./tools/analyzeContract.js";
import { getContractInfo } from "./tools/getContractInfo.js";
import { checkVulnerabilities } from "./tools/checkVulnerabilities.js";
import { runTests } from "./tools/runTests.js";
import { generateReport } from "./tools/generateReport.js";
import {
  optimizeGas,
  formatGasOptimizationResult,
  OptimizeGasInputSchema,
} from "./tools/optimizeGas.js";
import { diffAudit, DiffAuditInputSchema } from "./tools/diffAudit.js";
import { auditProject, AuditProjectInputSchema } from "./tools/auditProject.js";

// ============================================================================
// Server Configuration
// ============================================================================

const SERVER_NAME = "solidity-audit-mcp";
const SERVER_VERSION = "1.0.0";

// ============================================================================
// Input Schemas (Zod validation)
// ============================================================================

const AnalyzeContractInputSchema = z.object({
  contractPath: z.string().describe("Path to the Solidity contract file"),
  projectRoot: z
    .string()
    .optional()
    .describe("Root directory of the project (defaults to contract directory)"),
  runTests: z
    .boolean()
    .optional()
    .default(false)
    .describe("Whether to run forge tests as part of the analysis"),
});

const GetContractInfoInputSchema = z.object({
  contractPath: z.string().describe("Path to the Solidity contract file"),
});

const CheckVulnerabilitiesInputSchema = z.object({
  contractPath: z.string().describe("Path to the Solidity contract file"),
  detectors: z
    .array(z.string())
    .optional()
    .describe("Specific SWC detectors to check (e.g., ['SWC-107', 'SWC-115'])"),
});

const RunTestsInputSchema = z.object({
  projectRoot: z.string().describe("Root directory of the Foundry project"),
  contractName: z.string().optional().describe("Specific contract to test (runs all if omitted)"),
});

// Use the actual schema from the tool module
import { GenerateReportInputSchema } from "./tools/generateReport.js";

// ============================================================================
// Tool Definitions
// ============================================================================

const TOOLS: Tool[] = [
  {
    name: "analyze_contract",
    description:
      "Runs a complete security analysis pipeline on a Solidity contract. " +
      "Executes Slither and Aderyn, classifies findings by severity, and returns a structured report.",
    inputSchema: {
      type: "object",
      properties: {
        contractPath: {
          type: "string",
          description: "Path to the Solidity contract file",
        },
        projectRoot: {
          type: "string",
          description: "Root directory of the project (defaults to contract directory)",
        },
        runTests: {
          type: "boolean",
          description: "Whether to run forge tests as part of the analysis",
          default: false,
        },
      },
      required: ["contractPath"],
    },
  },
  {
    name: "get_contract_info",
    description:
      "Extracts metadata from a smart contract: public functions, state variables, " +
      "inheritance, interfaces, modifiers. Useful for understanding the attack surface.",
    inputSchema: {
      type: "object",
      properties: {
        contractPath: {
          type: "string",
          description: "Path to the Solidity contract file",
        },
      },
      required: ["contractPath"],
    },
  },
  {
    name: "check_vulnerabilities",
    description:
      "Compares the contract against known vulnerability patterns from the SWC Registry.",
    inputSchema: {
      type: "object",
      properties: {
        contractPath: {
          type: "string",
          description: "Path to the Solidity contract file",
        },
        detectors: {
          type: "array",
          items: { type: "string" },
          description: "Specific SWC detectors to check (e.g., ['SWC-107', 'SWC-115'])",
        },
      },
      required: ["contractPath"],
    },
  },
  {
    name: "run_tests",
    description: "Runs forge test and returns project results and coverage.",
    inputSchema: {
      type: "object",
      properties: {
        projectRoot: {
          type: "string",
          description: "Root directory of the Foundry project",
        },
        contractName: {
          type: "string",
          description: "Specific contract to test (runs all if omitted)",
        },
      },
      required: ["projectRoot"],
    },
  },
  {
    name: "generate_report",
    description: "Generates a formatted audit report from findings and contract metadata.",
    inputSchema: {
      type: "object",
      properties: {
        findings: {
          type: "array",
          description: "Array of Finding objects from the analysis",
        },
        contractInfo: {
          type: "object",
          description: "ContractInfo object with contract metadata",
        },
        format: {
          type: "string",
          enum: ["markdown", "json"],
          description: "Output format for the report",
          default: "markdown",
        },
      },
      required: ["findings", "contractInfo"],
    },
  },
  {
    name: "optimize_gas",
    description:
      "Analyzes a smart contract to detect patterns of inefficient gas usage " +
      "and suggests optimizations with estimated gas savings. Returns findings " +
      "sorted by potential savings, a gas score (0-100), and total estimated savings.",
    inputSchema: {
      type: "object",
      properties: {
        contractPath: {
          type: "string",
          description: "Absolute path to the Solidity contract file",
        },
        includeInformational: {
          type: "boolean",
          description: "Include INFORMATIONAL severity findings (default: false)",
          default: false,
        },
      },
      required: ["contractPath"],
    },
  },
  {
    name: "diff_audit",
    description:
      "Compares two versions of a contract and audits only the parts that changed. " +
      "Ideal for PR reviews and contract upgrades. Returns diff summary, risk assessment, " +
      "new/resolved findings, and change-specific security issues.",
    inputSchema: {
      type: "object",
      properties: {
        oldContractPath: {
          type: "string",
          description: "Path to the old version of the contract",
        },
        newContractPath: {
          type: "string",
          description: "Path to the new version of the contract",
        },
        focusOnly: {
          type: "boolean",
          description: "If true, only analyze changed parts (default: true)",
          default: true,
        },
      },
      required: ["oldContractPath", "newContractPath"],
    },
  },
  {
    name: "audit_project",
    description:
      "Analyzes an entire Solidity project. Scans all contracts, prioritizes by risk " +
      "(payable, delegatecall, external calls, LOC), and generates a consolidated report. " +
      "Runs Slither and Aderyn on each contract with limited concurrency (3 parallel). " +
      "Includes project-level findings like circular dependencies, missing tests, and " +
      "version inconsistencies.",
    inputSchema: {
      type: "object",
      properties: {
        projectRoot: {
          type: "string",
          description: "Root directory of the Solidity project",
        },
        maxContracts: {
          type: "number",
          description: "Maximum number of contracts to analyze (default: all)",
        },
        priorityOnly: {
          type: "boolean",
          description: "Only analyze critical and high priority contracts",
          default: false,
        },
        parallel: {
          type: "boolean",
          description: "Run contract analysis in parallel (default: true)",
          default: true,
        },
        skipTests: {
          type: "boolean",
          description: "Skip running project tests",
          default: false,
        },
        skipGas: {
          type: "boolean",
          description: "Skip gas optimization analysis",
          default: false,
        },
      },
      required: ["projectRoot"],
    },
  },
];

// ============================================================================
// Tool Handlers (Stubs)
// ============================================================================

async function handleAnalyzeContract(args: unknown): Promise<string> {
  const input = AnalyzeContractInputSchema.parse(args);
  logger.info(`analyze_contract called with: ${JSON.stringify(input)}`);

  return await analyzeContract(input);
}

async function handleGetContractInfo(args: unknown): Promise<string> {
  const input = GetContractInfoInputSchema.parse(args);
  logger.info(`get_contract_info called with: ${JSON.stringify(input)}`);

  return await getContractInfo(input);
}

async function handleCheckVulnerabilities(args: unknown): Promise<string> {
  const input = CheckVulnerabilitiesInputSchema.parse(args);
  logger.info(`check_vulnerabilities called with: ${JSON.stringify(input)}`);

  return await checkVulnerabilities(input);
}

async function handleRunTests(args: unknown): Promise<string> {
  const input = RunTestsInputSchema.parse(args);
  logger.info(`run_tests called with: ${JSON.stringify(input)}`);

  return await runTests(input);
}

async function handleGenerateReport(args: unknown): Promise<string> {
  const input = GenerateReportInputSchema.parse(args);
  logger.info(`generate_report called with format: ${input.format}`);

  return await generateReport(input);
}

async function handleOptimizeGas(args: unknown): Promise<string> {
  const input = OptimizeGasInputSchema.parse(args);
  logger.info(`optimize_gas called with: ${JSON.stringify(input)}`);

  const result = await optimizeGas(input);
  return formatGasOptimizationResult(result);
}

async function handleDiffAudit(args: unknown): Promise<string> {
  const input = DiffAuditInputSchema.parse(args);
  logger.info(`diff_audit called with: ${JSON.stringify(input)}`);

  const result = await diffAudit(input);
  return result.report;
}

async function handleAuditProject(args: unknown): Promise<string> {
  const input = AuditProjectInputSchema.parse(args);
  logger.info(`audit_project called with: ${JSON.stringify(input)}`);

  return await auditProject(input);
}

// ============================================================================
// Server Setup
// ============================================================================

const server = new Server(
  {
    name: SERVER_NAME,
    version: SERVER_VERSION,
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// Handler: List available tools
server.setRequestHandler(ListToolsRequestSchema, async () => {
  logger.info(`ListTools request received - returning ${TOOLS.length} tools`);
  return { tools: TOOLS };
});

// Handler: Execute tool
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  logger.info(`CallTool request: ${name}`);

  try {
    let result: string;

    switch (name) {
      case "analyze_contract":
        result = await handleAnalyzeContract(args);
        break;

      case "get_contract_info":
        result = await handleGetContractInfo(args);
        break;

      case "check_vulnerabilities":
        result = await handleCheckVulnerabilities(args);
        break;

      case "run_tests":
        result = await handleRunTests(args);
        break;

      case "generate_report":
        result = await handleGenerateReport(args);
        break;

      case "optimize_gas":
        result = await handleOptimizeGas(args);
        break;

      case "diff_audit":
        result = await handleDiffAudit(args);
        break;

      case "audit_project":
        result = await handleAuditProject(args);
        break;

      default:
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

    return {
      content: [
        {
          type: "text",
          text: result,
        },
      ],
    };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    logger.error(`Error executing tool ${name}: ${errorMessage}`);

    // Handle Zod validation errors specially
    if (error instanceof z.ZodError) {
      const issues = error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ");
      return {
        content: [
          {
            type: "text",
            text: `Validation error: ${issues}`,
          },
        ],
        isError: true,
      };
    }

    return {
      content: [
        {
          type: "text",
          text: `Error: ${errorMessage}`,
        },
      ],
      isError: true,
    };
  }
});

// ============================================================================
// Main Entry Point
// ============================================================================

async function main(): Promise<void> {
  logger.info(`Starting ${SERVER_NAME} v${SERVER_VERSION}`);

  const transport = new StdioServerTransport();

  await server.connect(transport);

  logger.info(`${SERVER_NAME} is running on stdio transport`);
  logger.info(`Available tools: ${TOOLS.map((t) => t.name).join(", ")}`);
}

// Run the server
main().catch((error) => {
  logger.error(`Fatal error: ${error instanceof Error ? error.message : String(error)}`);
  process.exit(1);
});
