#!/usr/bin/env node

/**
 * MCP Audit Server - HTTP/SSE Transport
 *
 * Exposes the MCP server over HTTP with SSE transport for remote access.
 * This allows running the audit tools as a SaaS service.
 *
 * Usage:
 *   node dist/server.js [--port 3000] [--host 0.0.0.0]
 *
 * Environment variables:
 *   PORT - Server port (default: 3000)
 *   HOST - Server host (default: 0.0.0.0)
 *   MCP_API_KEY - Optional API key for authentication
 */

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { parse as parseUrl } from "node:url";
import { parseArgs } from "node:util";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { execa } from "execa";

import { logger } from "./utils/logger.js";

// CI integration imports
import {
  postReviewComments,
  postPRComment,
  createAuditResults,
  type ReviewOptions,
  type CommentOptions,
} from "./ci/index.js";
import { Severity, type Finding } from "./types/index.js";

// Tool imports
import { analyzeContract } from "./tools/analyzeContract.js";
import { getContractInfo } from "./tools/getContractInfo.js";
import { checkVulnerabilities } from "./tools/checkVulnerabilities.js";
import { runTests } from "./tools/runTests.js";
import { generateReport, GenerateReportInputSchema } from "./tools/generateReport.js";
import {
  optimizeGas,
  formatGasOptimizationResult,
  OptimizeGasInputSchema,
} from "./tools/optimizeGas.js";
import { diffAudit, DiffAuditInputSchema } from "./tools/diffAudit.js";
import { auditProject, AuditProjectInputSchema } from "./tools/auditProject.js";

// ============================================================================
// Configuration
// ============================================================================

const SERVER_NAME = "solidity-audit-mcp";
const SERVER_VERSION = "1.0.0";

const { values: args } = parseArgs({
  options: {
    port: { type: "string", short: "p", default: process.env["PORT"] || "3000" },
    host: { type: "string", short: "h", default: process.env["HOST"] || "0.0.0.0" },
  },
});

const PORT = parseInt(args.port!, 10);
const HOST = args.host!;
const API_KEY = process.env["MCP_API_KEY"];

// ============================================================================
// Input Schemas
// ============================================================================

const AnalyzeContractInputSchema = z.object({
  contractPath: z.string().describe("Path to the Solidity contract file"),
  projectRoot: z.string().optional().describe("Root directory of the project"),
  runTests: z.boolean().optional().default(false).describe("Whether to run forge tests"),
});

const GetContractInfoInputSchema = z.object({
  contractPath: z.string().describe("Path to the Solidity contract file"),
});

const CheckVulnerabilitiesInputSchema = z.object({
  contractPath: z.string().describe("Path to the Solidity contract file"),
  detectors: z.array(z.string()).optional().describe("Specific SWC detectors to check"),
});

const RunTestsInputSchema = z.object({
  projectRoot: z.string().describe("Root directory of the Foundry project"),
  contractName: z.string().optional().describe("Specific contract to test"),
});

// ============================================================================
// Tool Definitions
// ============================================================================

const TOOLS: Tool[] = [
  {
    name: "analyze_contract",
    description:
      "Runs a complete security analysis pipeline on a Solidity contract using Slither, Aderyn, and Slang.",
    inputSchema: {
      type: "object",
      properties: {
        contractPath: { type: "string", description: "Path to the Solidity contract file" },
        projectRoot: { type: "string", description: "Root directory of the project" },
        runTests: { type: "boolean", description: "Whether to run forge tests", default: false },
      },
      required: ["contractPath"],
    },
  },
  {
    name: "get_contract_info",
    description: "Extracts metadata and attack surface information from a Solidity contract.",
    inputSchema: {
      type: "object",
      properties: {
        contractPath: { type: "string", description: "Path to the Solidity contract file" },
      },
      required: ["contractPath"],
    },
  },
  {
    name: "check_vulnerabilities",
    description: "Scans a contract against SWC Registry patterns.",
    inputSchema: {
      type: "object",
      properties: {
        contractPath: { type: "string", description: "Path to the Solidity contract file" },
        detectors: {
          type: "array",
          items: { type: "string" },
          description: "Specific SWC IDs to check",
        },
      },
      required: ["contractPath"],
    },
  },
  {
    name: "run_tests",
    description: "Executes forge tests and returns results.",
    inputSchema: {
      type: "object",
      properties: {
        projectRoot: { type: "string", description: "Root directory of the Foundry project" },
        contractName: { type: "string", description: "Specific contract to test" },
      },
      required: ["projectRoot"],
    },
  },
  {
    name: "generate_report",
    description: "Generates a formatted audit report from findings.",
    inputSchema: {
      type: "object",
      properties: {
        findings: { type: "array", description: "Array of Finding objects" },
        contractInfo: { type: "object", description: "ContractInfo object" },
        format: { type: "string", enum: ["markdown", "json"], default: "markdown" },
        projectName: { type: "string" },
        auditorName: { type: "string" },
      },
      required: ["findings", "contractInfo"],
    },
  },
  {
    name: "optimize_gas",
    description: "Analyzes a contract for gas optimization opportunities.",
    inputSchema: {
      type: "object",
      properties: {
        contractPath: { type: "string", description: "Path to the Solidity contract file" },
        includeInformational: { type: "boolean", default: false },
      },
      required: ["contractPath"],
    },
  },
  {
    name: "diff_audit",
    description: "Compares two versions of a contract and audits the changes.",
    inputSchema: {
      type: "object",
      properties: {
        oldContractPath: { type: "string", description: "Path to the old version" },
        newContractPath: { type: "string", description: "Path to the new version" },
        focusOnly: { type: "boolean", default: true },
      },
      required: ["oldContractPath", "newContractPath"],
    },
  },
  {
    name: "audit_project",
    description: "Scans an entire project directory for Solidity contracts.",
    inputSchema: {
      type: "object",
      properties: {
        projectRoot: { type: "string", description: "Root directory of the project" },
        pattern: { type: "string", default: "**/*.sol" },
        exclude: { type: "array", items: { type: "string" } },
      },
      required: ["projectRoot"],
    },
  },
];

// ============================================================================
// MCP Server Setup
// ============================================================================

function createMcpServer(): Server {
  const server = new Server(
    { name: SERVER_NAME, version: SERVER_VERSION },
    { capabilities: { tools: {} } }
  );

  // List tools handler
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: TOOLS,
  }));

  // Call tool handler
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    try {
      let result: string;

      switch (name) {
        case "analyze_contract": {
          const input = AnalyzeContractInputSchema.parse(args);
          result = await analyzeContract(input);
          break;
        }
        case "get_contract_info": {
          const input = GetContractInfoInputSchema.parse(args);
          result = await getContractInfo(input);
          break;
        }
        case "check_vulnerabilities": {
          const input = CheckVulnerabilitiesInputSchema.parse(args);
          result = await checkVulnerabilities(input);
          break;
        }
        case "run_tests": {
          const input = RunTestsInputSchema.parse(args);
          result = await runTests(input);
          break;
        }
        case "generate_report": {
          const input = GenerateReportInputSchema.parse(args);
          result = await generateReport(input);
          break;
        }
        case "optimize_gas": {
          const input = OptimizeGasInputSchema.parse(args);
          const gasResult = await optimizeGas(input);
          result = formatGasOptimizationResult(gasResult);
          break;
        }
        case "diff_audit": {
          const input = DiffAuditInputSchema.parse(args);
          const diffResult = await diffAudit(input);
          result = diffResult.report;
          break;
        }
        case "audit_project": {
          const input = AuditProjectInputSchema.parse(args);
          result = await auditProject(input);
          break;
        }
        default:
          throw new Error(`Unknown tool: ${name}`);
      }

      return {
        content: [{ type: "text", text: result }],
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      logger.error(`Tool ${name} failed`, { error: errorMessage });

      return {
        content: [{ type: "text", text: `Error: ${errorMessage}` }],
        isError: true,
      };
    }
  });

  return server;
}

// ============================================================================
// Analyzer Health Checks
// ============================================================================

interface AnalyzerStatus {
  available: boolean;
  version?: string;
  error?: string;
}

interface HealthStatus {
  status: "healthy" | "degraded" | "unhealthy";
  server: string;
  version: string;
  uptime: number;
  tools: number;
  analyzers: {
    slither: AnalyzerStatus;
    aderyn: AnalyzerStatus;
    forge: AnalyzerStatus;
    solc: AnalyzerStatus;
  };
  timestamp: string;
}

const startTime = Date.now();

async function checkAnalyzer(
  command: string,
  args: string[],
  versionParser?: (output: string) => string
): Promise<AnalyzerStatus> {
  try {
    const result = await execa(command, args, { timeout: 5000 });
    const output = result.stdout || result.stderr;
    const version = versionParser ? versionParser(output) : output.split("\n")[0]?.trim();
    return { available: true, version };
  } catch (error) {
    return {
      available: false,
      error: error instanceof Error ? error.message : "Unknown error",
    };
  }
}

async function getHealthStatus(): Promise<HealthStatus> {
  // Run all checks in parallel
  const [slither, aderyn, forge, solc] = await Promise.all([
    checkAnalyzer("slither", ["--version"], (out) => out.trim()),
    checkAnalyzer(
      "aderyn",
      ["--version"],
      (out) => out.match(/aderyn\s+([\d.]+)/i)?.[1] || out.trim()
    ),
    checkAnalyzer(
      "forge",
      ["--version"],
      (out) => out.match(/forge\s+([\d.]+)/i)?.[1] || out.trim()
    ),
    checkAnalyzer(
      "solc",
      ["--version"],
      (out) => out.match(/Version:\s*([\d.]+)/)?.[1] || out.trim()
    ),
  ]);

  const analyzers = { slither, aderyn, forge, solc };

  // Determine overall status
  const availableCount = Object.values(analyzers).filter((a) => a.available).length;
  let status: HealthStatus["status"];

  if (availableCount === 4) {
    status = "healthy";
  } else if (availableCount >= 2) {
    status = "degraded"; // Can still do some analysis
  } else {
    status = "unhealthy";
  }

  return {
    status,
    server: SERVER_NAME,
    version: SERVER_VERSION,
    uptime: Math.floor((Date.now() - startTime) / 1000),
    tools: TOOLS.length,
    analyzers,
    timestamp: new Date().toISOString(),
  };
}

// Cache health status for 30 seconds to avoid too many subprocess calls
let cachedHealth: HealthStatus | null = null;
let cachedHealthTime = 0;
const HEALTH_CACHE_TTL = 30000;

async function getCachedHealthStatus(): Promise<HealthStatus> {
  const now = Date.now();
  if (cachedHealth && now - cachedHealthTime < HEALTH_CACHE_TTL) {
    return { ...cachedHealth, uptime: Math.floor((now - startTime) / 1000) };
  }
  cachedHealth = await getHealthStatus();
  cachedHealthTime = now;
  return cachedHealth;
}

// ============================================================================
// HTTP Server
// ============================================================================

// Store active transports for cleanup
const activeTransports = new Map<string, SSEServerTransport>();

function handleCors(res: ServerResponse): void {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key");
}

function checkAuth(req: IncomingMessage): boolean {
  if (!API_KEY) return true;

  const authHeader = req.headers["authorization"];
  const apiKeyHeader = req.headers["x-api-key"];

  if (authHeader?.startsWith("Bearer ")) {
    return authHeader.slice(7) === API_KEY;
  }

  return apiKeyHeader === API_KEY;
}

async function handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
  handleCors(res);

  // Handle CORS preflight
  if (req.method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }

  const url = parseUrl(req.url || "/", true);
  const pathname = url.pathname || "/";

  // Health check endpoint
  if (pathname === "/health" && req.method === "GET") {
    const health = await getCachedHealthStatus();
    const httpStatus = health.status === "unhealthy" ? 503 : 200;
    res.writeHead(httpStatus, { "Content-Type": "application/json" });
    res.end(JSON.stringify(health, null, 2));
    return;
  }

  // Quick health check (no analyzer verification)
  if (pathname === "/health/quick" && req.method === "GET") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(
      JSON.stringify({
        status: "ok",
        server: SERVER_NAME,
        version: SERVER_VERSION,
        uptime: Math.floor((Date.now() - startTime) / 1000),
      })
    );
    return;
  }

  // Info endpoint
  if (pathname === "/info" && req.method === "GET") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(
      JSON.stringify({
        server: SERVER_NAME,
        version: SERVER_VERSION,
        transport: "sse",
        tools: TOOLS.map((t) => ({ name: t.name, description: t.description })),
      })
    );
    return;
  }

  // REST API: Analyze contract from source code
  if (pathname === "/api/analyze" && req.method === "POST") {
    if (!checkAuth(req)) {
      res.writeHead(401, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Unauthorized" }));
      return;
    }

    try {
      // Collect body
      const chunks: Buffer[] = [];
      for await (const chunk of req) {
        chunks.push(chunk as Buffer);
      }
      const body = JSON.parse(Buffer.concat(chunks).toString());

      const { source, filename = "Contract.sol" } = body;

      if (!source) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Missing 'source' field with contract code" }));
        return;
      }

      // Create temporary file for analysis
      const fs = await import("node:fs/promises");
      const path = await import("node:path");
      const os = await import("node:os");

      const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "mcp-audit-"));
      const contractPath = path.join(tmpDir, filename);
      await fs.writeFile(contractPath, source);

      logger.info(`API analyze request`, { filename, tmpDir });

      // Run analysis
      const result = await analyzeContract({ contractPath, projectRoot: tmpDir, runTests: false });

      // Cleanup
      await fs.rm(tmpDir, { recursive: true, force: true });

      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ result }));
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      logger.error("API analyze error", { error: errorMessage });
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: errorMessage }));
    }
    return;
  }

  // REST API: Check vulnerabilities from source code
  if (pathname === "/api/check" && req.method === "POST") {
    if (!checkAuth(req)) {
      res.writeHead(401, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Unauthorized" }));
      return;
    }

    try {
      const chunks: Buffer[] = [];
      for await (const chunk of req) {
        chunks.push(chunk as Buffer);
      }
      const body = JSON.parse(Buffer.concat(chunks).toString());

      const { source, filename = "Contract.sol", detectors } = body;

      if (!source) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Missing 'source' field with contract code" }));
        return;
      }

      const fs = await import("node:fs/promises");
      const path = await import("node:path");
      const os = await import("node:os");

      const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "mcp-audit-"));
      const contractPath = path.join(tmpDir, filename);
      await fs.writeFile(contractPath, source);

      const result = await checkVulnerabilities({ contractPath, detectors });

      await fs.rm(tmpDir, { recursive: true, force: true });

      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ result }));
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: errorMessage }));
    }
    return;
  }

  // REST API: CI Review - Analyze and post inline review comments
  if (pathname === "/api/ci/review" && req.method === "POST") {
    if (!checkAuth(req)) {
      res.writeHead(401, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Unauthorized" }));
      return;
    }

    try {
      const chunks: Buffer[] = [];
      for await (const chunk of req) {
        chunks.push(chunk as Buffer);
      }
      const body = JSON.parse(Buffer.concat(chunks).toString());

      const { files, github } = body;

      // Validate required fields
      if (!files || !Array.isArray(files) || files.length === 0) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Missing 'files' array with contract files" }));
        return;
      }

      if (!github || !github.owner || !github.repo || !github.prNumber || !github.token || !github.commitSha) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({
          error: "Missing 'github' object with owner, repo, prNumber, commitSha, and token"
        }));
        return;
      }

      const fs = await import("node:fs/promises");
      const path = await import("node:path");
      const os = await import("node:os");

      logger.info(`CI Review request`, {
        filesCount: files.length,
        owner: github.owner,
        repo: github.repo,
        prNumber: github.prNumber,
      });

      // Create temporary directory for all files
      const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "mcp-ci-review-"));
      const allFindings: Finding[] = [];
      const allGasOptimizations: Finding[] = [];
      const analysisResults: Array<{ filename: string; findingsCount: number; error?: string }> = [];

      // Analyze each file
      for (const file of files) {
        const { filename, source } = file;

        if (!filename || !source) {
          analysisResults.push({ filename: filename || "unknown", findingsCount: 0, error: "Missing filename or source" });
          continue;
        }

        try {
          // Create file in temp directory preserving path structure
          const contractPath = path.join(tmpDir, filename);
          await fs.mkdir(path.dirname(contractPath), { recursive: true });
          await fs.writeFile(contractPath, source);

          // Run analyzers directly to get structured findings
          const { runSlither } = await import("./analyzers/slither.js");
          const { runAderyn } = await import("./analyzers/aderyn.js");

          const [slitherFindings, aderynFindings] = await Promise.allSettled([
            runSlither(contractPath, tmpDir).catch(() => []),
            runAderyn(contractPath, tmpDir).catch(() => []),
          ]);

          const findings: Finding[] = [];

          if (slitherFindings.status === "fulfilled") {
            // Adjust paths to be relative to repo root
            for (const f of slitherFindings.value) {
              f.location.file = filename;
              findings.push(f);
            }
          }

          if (aderynFindings.status === "fulfilled") {
            for (const f of aderynFindings.value) {
              f.location.file = filename;
              findings.push(f);
            }
          }

          // Run Slang analysis
          try {
            const { analyzeWithSlang } = await import("./analyzers/slangAnalyzer.js");
            const slangResult = await analyzeWithSlang(source, contractPath, { includeInformational: false });
            for (const f of slangResult.findings) {
              f.location.file = filename;
              findings.push(f);
            }
          } catch {
            // Slang analysis failed, continue
          }

          allFindings.push(...findings);
          analysisResults.push({ filename, findingsCount: findings.length });

        } catch (err) {
          const errorMsg = err instanceof Error ? err.message : String(err);
          analysisResults.push({ filename, findingsCount: 0, error: errorMsg });
          logger.error(`Analysis failed for ${filename}`, { error: errorMsg });
        }
      }

      // Cleanup temp directory
      await fs.rm(tmpDir, { recursive: true, force: true });

      // Deduplicate findings based on file, line, and title
      const uniqueFindings = deduplicateFindingsByLocation(allFindings);

      // Sort by severity
      uniqueFindings.sort((a, b) => {
        const severityOrder: Record<Severity, number> = {
          [Severity.CRITICAL]: 0,
          [Severity.HIGH]: 1,
          [Severity.MEDIUM]: 2,
          [Severity.LOW]: 3,
          [Severity.INFORMATIONAL]: 4,
        };
        return severityOrder[a.severity] - severityOrder[b.severity];
      });

      // Post inline review comments
      const reviewOptions: ReviewOptions = {
        owner: github.owner,
        repo: github.repo,
        prNumber: github.prNumber,
        token: github.token,
        commitSha: github.commitSha,
        event: uniqueFindings.some(f => f.severity === Severity.CRITICAL || f.severity === Severity.HIGH)
          ? "REQUEST_CHANGES"
          : "COMMENT",
      };

      let reviewResult = { reviewId: 0, commentsPosted: 0 };

      try {
        reviewResult = await postReviewComments(uniqueFindings, reviewOptions);
        logger.info(`Review posted`, {
          reviewId: reviewResult.reviewId,
          commentsPosted: reviewResult.commentsPosted,
        });
      } catch (reviewErr) {
        const errorMsg = reviewErr instanceof Error ? reviewErr.message : String(reviewErr);
        logger.error(`Failed to post review comments`, { error: errorMsg });
      }

      // Also post a summary comment
      const auditResults = createAuditResults(uniqueFindings, allGasOptimizations);
      const commentOptions: CommentOptions = {
        owner: github.owner,
        repo: github.repo,
        prNumber: github.prNumber,
        token: github.token,
        prUrl: `https://github.com/${github.owner}/${github.repo}/pull/${github.prNumber}`,
      };

      let summaryResult = { commentId: 0, updated: false };

      try {
        summaryResult = await postPRComment(auditResults, commentOptions);
        logger.info(`Summary comment posted`, {
          commentId: summaryResult.commentId,
          updated: summaryResult.updated,
        });
      } catch (commentErr) {
        const errorMsg = commentErr instanceof Error ? commentErr.message : String(commentErr);
        logger.error(`Failed to post summary comment`, { error: errorMsg });
      }

      // Return results
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({
        success: true,
        summary: {
          filesAnalyzed: files.length,
          totalFindings: uniqueFindings.length,
          critical: uniqueFindings.filter(f => f.severity === Severity.CRITICAL).length,
          high: uniqueFindings.filter(f => f.severity === Severity.HIGH).length,
          medium: uniqueFindings.filter(f => f.severity === Severity.MEDIUM).length,
          low: uniqueFindings.filter(f => f.severity === Severity.LOW).length,
          informational: uniqueFindings.filter(f => f.severity === Severity.INFORMATIONAL).length,
        },
        review: {
          reviewId: reviewResult.reviewId,
          inlineCommentsPosted: reviewResult.commentsPosted,
        },
        summaryComment: {
          commentId: summaryResult.commentId,
          updated: summaryResult.updated,
        },
        files: analysisResults,
      }));

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      logger.error("CI Review error", { error: errorMessage });
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: errorMessage }));
    }
    return;
  }

  // SSE endpoint - check auth
  if (pathname === "/sse" && req.method === "GET") {
    if (!checkAuth(req)) {
      res.writeHead(401, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Unauthorized" }));
      return;
    }

    // Create new MCP server and transport for this connection
    const server = createMcpServer();
    const transport = new SSEServerTransport("/message", res);

    const connectionId = Math.random().toString(36).substring(7);
    activeTransports.set(connectionId, transport);

    logger.info(`SSE connection established`, { connectionId });

    // Clean up on close
    res.on("close", () => {
      activeTransports.delete(connectionId);
      logger.info(`SSE connection closed`, { connectionId });
    });

    await server.connect(transport);
    return;
  }

  // Message endpoint for SSE
  if (pathname === "/message" && req.method === "POST") {
    if (!checkAuth(req)) {
      res.writeHead(401, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Unauthorized" }));
      return;
    }

    // Collect body
    const chunks: Buffer[] = [];
    for await (const chunk of req) {
      chunks.push(chunk as Buffer);
    }
    const body = Buffer.concat(chunks).toString();

    // Find the transport to handle this message
    // In SSE, we need to route to the correct transport
    // For simplicity, we'll broadcast to all (usually there's only one)
    for (const transport of activeTransports.values()) {
      try {
        await transport.handlePostMessage(req, res, body);
        return;
      } catch {
        // Try next transport
      }
    }

    res.writeHead(400, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "No active SSE connection" }));
    return;
  }

  // 404 for unknown routes
  res.writeHead(404, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ error: "Not found" }));
}

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Deduplicate findings based on file, line, and title similarity
 */
function deduplicateFindingsByLocation(findings: Finding[]): Finding[] {
  const seen = new Map<string, Finding>();

  for (const finding of findings) {
    const line = finding.location.lines?.[0] ?? 0;
    const key = `${finding.location.file}:${line}:${finding.title.toLowerCase().slice(0, 30)}`;

    const existing = seen.get(key);
    if (!existing) {
      seen.set(key, finding);
    } else {
      // Keep the one with higher severity
      const severityOrder: Record<Severity, number> = {
        [Severity.CRITICAL]: 0,
        [Severity.HIGH]: 1,
        [Severity.MEDIUM]: 2,
        [Severity.LOW]: 3,
        [Severity.INFORMATIONAL]: 4,
      };
      if (severityOrder[finding.severity] < severityOrder[existing.severity]) {
        seen.set(key, finding);
      }
    }
  }

  return Array.from(seen.values());
}

// ============================================================================
// Main
// ============================================================================

const httpServer = createServer((req, res) => {
  handleRequest(req, res).catch((error) => {
    logger.error("Request handler error", { error: String(error) });
    res.writeHead(500, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Internal server error" }));
  });
});

httpServer.listen(PORT, HOST, () => {
  logger.info(`MCP Audit Server (SSE) running`, {
    host: HOST,
    port: PORT,
    authEnabled: !!API_KEY,
  });
  console.warn(`
╔════════════════════════════════════════════════════════════════╗
║                    MCP Audit Server (SSE)                      ║
╠════════════════════════════════════════════════════════════════╣
║  Status:    Running                                            ║
║  Host:      ${HOST.padEnd(49)}║
║  Port:      ${String(PORT).padEnd(49)}║
║  Auth:      ${(API_KEY ? "Enabled (API Key)" : "Disabled").padEnd(49)}║
╠════════════════════════════════════════════════════════════════╣
║  MCP Endpoints:                                                ║
║    GET  /sse          - SSE connection (MCP clients)           ║
║    POST /message      - Message handler (MCP)                  ║
╠════════════════════════════════════════════════════════════════╣
║  REST API:                                                     ║
║    POST /api/analyze    - Analyze contract from source         ║
║    POST /api/check      - Quick vulnerability check            ║
║    POST /api/ci/review  - CI: Analyze & post inline comments   ║
╠════════════════════════════════════════════════════════════════╣
║  Health:                                                       ║
║    GET  /health       - Full health + analyzer status          ║
║    GET  /health/quick - Quick health check                     ║
║    GET  /info         - Server information                     ║
╠════════════════════════════════════════════════════════════════╣
║  Tools: ${String(TOOLS.length).padEnd(53)}║
╚════════════════════════════════════════════════════════════════╝
`);

  // Log initial analyzer status
  getHealthStatus().then((health) => {
    const analyzerList = Object.entries(health.analyzers)
      .map(([name, status]) => `${name}: ${status.available ? "✓" : "✗"}`)
      .join(", ");
    logger.info(`Analyzer status: ${analyzerList}`);
  });
});

// Graceful shutdown
process.on("SIGTERM", () => {
  logger.info("Received SIGTERM, shutting down...");
  httpServer.close(() => {
    logger.info("Server closed");
    process.exit(0);
  });
});

process.on("SIGINT", () => {
  logger.info("Received SIGINT, shutting down...");
  httpServer.close(() => {
    logger.info("Server closed");
    process.exit(0);
  });
});
