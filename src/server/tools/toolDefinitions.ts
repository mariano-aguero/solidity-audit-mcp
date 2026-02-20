/**
 * Tool Definitions
 *
 * MCP tool definitions shared between stdio and HTTP/SSE servers.
 * These define the tool metadata exposed to MCP clients.
 */

import type { Tool } from "@modelcontextprotocol/sdk/types.js";

// ============================================================================
// Tool Definitions
// ============================================================================

export const TOOLS: Tool[] = [
  {
    name: "analyze_contract",
    description:
      "Runs a complete security analysis pipeline on a Solidity contract. " +
      "Executes Slither, Aderyn, and Slang AST analysis, classifies findings by severity, " +
      "and returns a structured report. Supports selective analyzer execution.",
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
        analyzers: {
          type: "array",
          items: {
            type: "string",
            enum: ["slither", "aderyn", "slang", "gas", "echidna", "halmos"],
          },
          description: "Specific analyzers to run (runs all if omitted)",
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
        projectName: {
          type: "string",
          description: "Name of the project being audited",
        },
        auditorName: {
          type: "string",
          description: "Name of the auditor or team",
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
  {
    name: "generate_invariants",
    description:
      "Analyzes a Solidity contract and generates Foundry invariant test suggestions " +
      "based on detected protocol type (ERC-20, ERC-4626 vault, lending, AMM, governance, staking). " +
      "Returns ready-to-use invariant_*() function templates with severity classification.",
    inputSchema: {
      type: "object",
      properties: {
        contractPath: {
          type: "string",
          description: "Path to the Solidity contract file",
        },
        protocolType: {
          type: "string",
          enum: ["auto", "erc20", "erc721", "vault", "lending", "amm", "governance", "staking"],
          description: "Protocol type for targeted invariants (auto-detected if omitted)",
          default: "auto",
        },
        includeStateful: {
          type: "boolean",
          description: "Include stateful invariant suggestions with Foundry run commands",
          default: true,
        },
      },
      required: ["contractPath"],
    },
  },
  {
    name: "explain_finding",
    description:
      "Returns a detailed explanation of a security finding: root cause, impact, step-by-step " +
      "exploit scenario, vulnerable vs. secure code, Foundry PoC template, and remediation steps. " +
      "Accepts SWC IDs (e.g. 'SWC-107'), custom detector IDs (e.g. 'CUSTOM-018'), " +
      "or free-text keywords (e.g. 'reentrancy', 'flash loan', 'paymaster').",
    inputSchema: {
      type: "object",
      properties: {
        findingId: {
          type: "string",
          description:
            "Finding ID or keyword: SWC-107, CUSTOM-018, 'reentrancy', 'flash loan', 'paymaster', etc.",
        },
        severity: {
          type: "string",
          enum: ["critical", "high", "medium", "low", "informational"],
          description: "Severity level for additional context (optional)",
        },
        contractContext: {
          type: "string",
          description: "Brief description of the contract to tailor the explanation",
        },
      },
      required: ["findingId"],
    },
  },
];

/**
 * Get tool names for display purposes.
 */
export function getToolNames(): string[] {
  return TOOLS.map((t) => t.name);
}

/**
 * Get tool summaries for info endpoints.
 */
export function getToolSummaries(): Array<{ name: string; description: string }> {
  return TOOLS.map((t) => ({
    name: t.name,
    description: t.description ?? "",
  }));
}
