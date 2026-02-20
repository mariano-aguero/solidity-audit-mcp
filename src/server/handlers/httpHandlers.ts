/**
 * HTTP Handlers
 *
 * Request handlers for REST API endpoints.
 * These are separate from MCP tool handlers.
 */

import type { IncomingMessage, ServerResponse } from "node:http";
import { mkdir, writeFile, rm, mkdtemp } from "node:fs/promises";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";

import { logger } from "../../utils/logger.js";
import { Severity, type Finding } from "../../types/index.js";
import { analyzeContract } from "../../tools/analyzeContract.js";
import { checkVulnerabilities } from "../../tools/checkVulnerabilities.js";
import {
  postReviewComments,
  postPRComment,
  createAuditResults,
  type ReviewOptions,
  type CommentOptions,
} from "../../ci/index.js";

// ============================================================================
// Types
// ============================================================================

export interface JsonResponse {
  statusCode: number;
  body: unknown;
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Parse JSON body from request.
 */
export async function parseJsonBody(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(chunk as Buffer);
  }
  return JSON.parse(Buffer.concat(chunks).toString());
}

/**
 * Send JSON response.
 */
export function sendJson(res: ServerResponse, statusCode: number, body: unknown): void {
  res.writeHead(statusCode, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body, null, 2));
}

/**
 * Send error response.
 */
export function sendError(res: ServerResponse, statusCode: number, message: string): void {
  sendJson(res, statusCode, { error: message });
}

/**
 * Create a temporary directory with contract files.
 */
async function createTempContract(
  source: string,
  filename: string
): Promise<{ tmpDir: string; contractPath: string }> {
  const tmpDir = await mkdtemp(join(tmpdir(), "mcp-audit-"));
  const contractPath = join(tmpDir, filename);
  await mkdir(dirname(contractPath), { recursive: true });
  await writeFile(contractPath, source);
  return { tmpDir, contractPath };
}

/**
 * Clean up temporary directory.
 */
async function cleanupTempDir(tmpDir: string): Promise<void> {
  await rm(tmpDir, { recursive: true, force: true });
}

// ============================================================================
// API Handlers
// ============================================================================

/**
 * Handle POST /api/analyze - Analyze contract from source code.
 */
export async function handleApiAnalyze(req: IncomingMessage): Promise<JsonResponse> {
  const body = (await parseJsonBody(req)) as { source?: string; filename?: string };

  const { source, filename = "Contract.sol" } = body;

  if (!source) {
    return { statusCode: 400, body: { error: "Missing 'source' field with contract code" } };
  }

  const { tmpDir, contractPath } = await createTempContract(source, filename);

  try {
    logger.info(`API analyze request`, { filename, tmpDir });

    const result = await analyzeContract({
      contractPath,
      projectRoot: tmpDir,
      runTests: false,
    });

    return { statusCode: 200, body: { result } };
  } finally {
    await cleanupTempDir(tmpDir);
  }
}

/**
 * Handle POST /api/check - Quick vulnerability check from source code.
 */
export async function handleApiCheck(req: IncomingMessage): Promise<JsonResponse> {
  const body = (await parseJsonBody(req)) as {
    source?: string;
    filename?: string;
    detectors?: string[];
  };

  const { source, filename = "Contract.sol", detectors } = body;

  if (!source) {
    return { statusCode: 400, body: { error: "Missing 'source' field with contract code" } };
  }

  const { tmpDir, contractPath } = await createTempContract(source, filename);

  try {
    const result = await checkVulnerabilities({ contractPath, detectors });
    return { statusCode: 200, body: { result } };
  } finally {
    await cleanupTempDir(tmpDir);
  }
}

/**
 * Handle POST /api/ci/review - Analyze and post inline review comments.
 */
export async function handleApiCiReview(req: IncomingMessage): Promise<JsonResponse> {
  const body = (await parseJsonBody(req)) as {
    files?: Array<{ filename: string; source: string }>;
    github?: {
      owner: string;
      repo: string;
      prNumber: number;
      token: string;
      commitSha: string;
    };
  };

  const { files, github } = body;

  // Validate required fields
  if (!files || !Array.isArray(files) || files.length === 0) {
    return { statusCode: 400, body: { error: "Missing 'files' array with contract files" } };
  }

  if (
    !github ||
    !github.owner ||
    !github.repo ||
    !github.prNumber ||
    !github.token ||
    !github.commitSha
  ) {
    return {
      statusCode: 400,
      body: { error: "Missing 'github' object with owner, repo, prNumber, commitSha, and token" },
    };
  }

  logger.info(`CI Review request`, {
    filesCount: files.length,
    owner: github.owner,
    repo: github.repo,
    prNumber: github.prNumber,
  });

  // Create temporary directory for all files
  const tmpDir = await mkdtemp(join(tmpdir(), "mcp-ci-review-"));
  const allFindings: Finding[] = [];
  const allGasOptimizations: Finding[] = [];
  const analysisResults: Array<{ filename: string; findingsCount: number; error?: string }> = [];

  try {
    // Analyze each file
    for (const file of files) {
      const { filename, source } = file;

      if (!filename || !source) {
        analysisResults.push({
          filename: filename || "unknown",
          findingsCount: 0,
          error: "Missing filename or source",
        });
        continue;
      }

      try {
        // Create file in temp directory preserving path structure
        const contractPath = join(tmpDir, filename);
        await mkdir(dirname(contractPath), { recursive: true });
        await writeFile(contractPath, source);

        // Run analyzers via orchestrator
        const { AnalyzerOrchestrator } = await import("../../analyzers/AnalyzerOrchestrator.js");
        const orchestrator = new AnalyzerOrchestrator();
        const orchResult = await orchestrator
          .analyzeWith(["slither", "aderyn"], { contractPath, projectRoot: tmpDir })
          .catch(() => ({ findings: [] as Finding[] }));

        const findings: Finding[] = [];

        for (const f of orchResult.findings) {
          f.location.file = filename;
          findings.push(f);
        }

        // Run Slang analysis
        try {
          const { analyzeWithSlang } = await import("../../analyzers/adapters/SlangAdapter.js");
          const slangResult = await analyzeWithSlang(source, contractPath, {
            includeInformational: false,
          });
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

    // Deduplicate findings
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
      event: uniqueFindings.some(
        (f) => f.severity === Severity.CRITICAL || f.severity === Severity.HIGH
      )
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

    // Post summary comment
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
    return {
      statusCode: 200,
      body: {
        success: true,
        summary: {
          filesAnalyzed: files.length,
          totalFindings: uniqueFindings.length,
          critical: uniqueFindings.filter((f) => f.severity === Severity.CRITICAL).length,
          high: uniqueFindings.filter((f) => f.severity === Severity.HIGH).length,
          medium: uniqueFindings.filter((f) => f.severity === Severity.MEDIUM).length,
          low: uniqueFindings.filter((f) => f.severity === Severity.LOW).length,
          informational: uniqueFindings.filter((f) => f.severity === Severity.INFORMATIONAL).length,
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
      },
    };
  } finally {
    await cleanupTempDir(tmpDir);
  }
}

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Deduplicate findings based on file, line, and title similarity.
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
