/**
 * Input Schemas
 *
 * Zod validation schemas for all MCP tool inputs.
 * Shared between stdio and HTTP/SSE servers.
 */

import { z } from "zod";

// ============================================================================
// Tool Input Schemas
// ============================================================================

export const AnalyzeContractInputSchema = z.object({
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
  analyzers: z
    .array(z.enum(["slither", "aderyn", "slang", "gas", "echidna", "halmos"]))
    .optional()
    .describe("Specific analyzers to run (runs all if omitted)"),
});

export const GetContractInfoInputSchema = z.object({
  contractPath: z.string().describe("Path to the Solidity contract file"),
});

export const CheckVulnerabilitiesInputSchema = z.object({
  contractPath: z.string().describe("Path to the Solidity contract file"),
  detectors: z
    .array(z.string())
    .optional()
    .describe("Specific SWC detectors to check (e.g., ['SWC-107', 'SWC-115'])"),
});

export const RunTestsInputSchema = z.object({
  projectRoot: z.string().describe("Root directory of the Foundry project"),
  contractName: z.string().optional().describe("Specific contract to test (runs all if omitted)"),
});

// Re-export from tool modules for consistency
export { GenerateReportInputSchema } from "../../tools/generateReport.js";
export { OptimizeGasInputSchema } from "../../tools/optimizeGas.js";
export { DiffAuditInputSchema } from "../../tools/diffAudit.js";
export { AuditProjectInputSchema } from "../../tools/auditProject.js";

// ============================================================================
// API Input Schemas (for REST endpoints)
// ============================================================================

export const ApiAnalyzeInputSchema = z.object({
  source: z.string().describe("Solidity source code"),
  filename: z.string().optional().default("Contract.sol"),
});

export const ApiCheckInputSchema = z.object({
  source: z.string().describe("Solidity source code"),
  filename: z.string().optional().default("Contract.sol"),
  detectors: z.array(z.string()).optional(),
});

export const ApiCiReviewInputSchema = z.object({
  files: z
    .array(
      z.object({
        filename: z.string(),
        source: z.string(),
      })
    )
    .min(1),
  github: z.object({
    owner: z.string(),
    repo: z.string(),
    prNumber: z.number(),
    token: z.string(),
    commitSha: z.string(),
  }),
});

// ============================================================================
// Type Exports
// ============================================================================

export type AnalyzeContractInput = z.infer<typeof AnalyzeContractInputSchema>;
export type GetContractInfoInput = z.infer<typeof GetContractInfoInputSchema>;
export type CheckVulnerabilitiesInput = z.infer<typeof CheckVulnerabilitiesInputSchema>;
export type RunTestsInput = z.infer<typeof RunTestsInputSchema>;
export type ApiAnalyzeInput = z.infer<typeof ApiAnalyzeInputSchema>;
export type ApiCheckInput = z.infer<typeof ApiCheckInputSchema>;
export type ApiCiReviewInput = z.infer<typeof ApiCiReviewInputSchema>;
