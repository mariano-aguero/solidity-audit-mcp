/**
 * GitHub PR Comment Generator
 *
 * Generates formatted markdown comments for GitHub Pull Requests
 * with audit results, and posts/updates comments via GitHub API.
 */

import { Finding, Severity } from "../types/index.js";
import {
  getSeverityEmoji as getSeverityEmojiUtil,
  estimateGasSavings as estimateGasSavingsUtil,
} from "../utils/severity.js";

// ============================================================================
// Types
// ============================================================================

export interface AuditSummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  informational: number;
  gasOptimizations: number;
  estimatedGasSavings: number;
}

export interface AuditResults {
  summary: AuditSummary;
  findings: Finding[];
  gasOptimizations: Finding[];
  diffResults?: DiffResults;
}

export interface DiffResults {
  addedFindings: Finding[];
  resolvedFindings: Finding[];
  unchangedFindings: Finding[];
}

export type RiskLevel = "critical" | "high" | "medium" | "low" | "clean";

export interface CommentOptions {
  owner: string;
  repo: string;
  prNumber: number;
  token: string;
  prUrl?: string;
}

export interface ReviewComment {
  path: string;
  line: number;
  side?: "LEFT" | "RIGHT";
  body: string;
}

export interface ReviewOptions extends CommentOptions {
  commitSha: string;
  event?: "APPROVE" | "REQUEST_CHANGES" | "COMMENT";
}

// ============================================================================
// Risk Level Detection
// ============================================================================

/**
 * Determine the overall risk level based on findings.
 */
export function determineRiskLevel(summary: AuditSummary): RiskLevel {
  if (summary.critical > 0) return "critical";
  if (summary.high > 0) return "high";
  if (summary.medium > 0) return "medium";
  if (summary.low > 0) return "low";
  return "clean";
}

/**
 * Get the badge URL for a risk level.
 */
export function getRiskBadge(riskLevel: RiskLevel): string {
  const badges: Record<RiskLevel, string> = {
    critical: "![Critical](https://img.shields.io/badge/Risk-CRITICAL-red)",
    high: "![High](https://img.shields.io/badge/Risk-HIGH-orange)",
    medium: "![Medium](https://img.shields.io/badge/Risk-MEDIUM-yellow)",
    low: "![Low](https://img.shields.io/badge/Risk-LOW-green)",
    clean: "![Clean](https://img.shields.io/badge/Risk-CLEAN-brightgreen)",
  };
  return badges[riskLevel];
}

/**
 * Get the emoji and label for a risk level.
 */
export function getRiskEmoji(riskLevel: RiskLevel): string {
  const emojis: Record<RiskLevel, string> = {
    critical: "🔴 CRITICAL",
    high: "🟠 HIGH",
    medium: "🟡 MEDIUM",
    low: "🟢 LOW",
    clean: "✅ CLEAN",
  };
  return emojis[riskLevel];
}

/**
 * Get the emoji for a severity level.
 * Re-exported from utils/severity for backwards compatibility.
 */
export function getSeverityEmoji(severity: Severity): string {
  return getSeverityEmojiUtil(severity);
}

// ============================================================================
// Markdown Generation
// ============================================================================

/**
 * Generate a markdown table for security findings, grouped by severity.
 */
export function generateFindingsTable(findings: Finding[], maxItems = 50): string {
  if (findings.length === 0) {
    return "_No security findings detected_";
  }

  // Sort by severity (CRITICAL first, then HIGH, MEDIUM, LOW, INFORMATIONAL)
  const severityOrder: Record<Severity, number> = {
    [Severity.CRITICAL]: 0,
    [Severity.HIGH]: 1,
    [Severity.MEDIUM]: 2,
    [Severity.LOW]: 3,
    [Severity.INFORMATIONAL]: 4,
  };

  const sortedFindings = [...findings].sort(
    (a, b) => severityOrder[a.severity] - severityOrder[b.severity]
  );

  const lines: string[] = [
    "| Severity | Title | Location | Detector |",
    "|:--------:|-------|----------|----------|",
  ];

  const displayFindings = sortedFindings.slice(0, maxItems);
  for (const finding of displayFindings) {
    const emoji = getSeverityEmoji(finding.severity);
    const severity = `${emoji} ${finding.severity.toUpperCase()}`;
    const title = escapeMarkdown(finding.title);
    const location = finding.location.file
      ? `\`${finding.location.file}:${finding.location.lines?.[0] ?? "?"}\``
      : "_Unknown_";
    const detector = `\`${finding.detector}\``;
    lines.push(`| ${severity} | ${title} | ${location} | ${detector} |`);
  }

  if (findings.length > maxItems) {
    lines.push("");
    lines.push(`<details><summary>📋 Show ${findings.length - maxItems} more findings</summary>\n`);
    lines.push("| Severity | Title | Location | Detector |");
    lines.push("|:--------:|-------|----------|----------|");

    for (const finding of sortedFindings.slice(maxItems)) {
      const emoji = getSeverityEmoji(finding.severity);
      const severity = `${emoji} ${finding.severity.toUpperCase()}`;
      const title = escapeMarkdown(finding.title);
      const location = finding.location.file
        ? `\`${finding.location.file}:${finding.location.lines?.[0] ?? "?"}\``
        : "_Unknown_";
      const detector = `\`${finding.detector}\``;
      lines.push(`| ${severity} | ${title} | ${location} | ${detector} |`);
    }
    lines.push("\n</details>");
  }

  return lines.join("\n");
}

/**
 * Generate a markdown table for gas optimizations.
 */
export function generateGasTable(optimizations: Finding[], maxItems = 10): string {
  if (optimizations.length === 0) {
    return "_No gas optimizations found_";
  }

  const lines: string[] = [
    "| Impact | Optimization | Location | Est. Savings |",
    "|:------:|--------------|----------|-------------:|",
  ];

  const displayOptimizations = optimizations.slice(0, maxItems);
  for (const opt of displayOptimizations) {
    const emoji = getSeverityEmoji(opt.severity);
    const impact = `${emoji} ${opt.severity.toUpperCase()}`;
    const title = escapeMarkdown(opt.title);
    const location = opt.location.file
      ? `\`${opt.location.file}:${opt.location.lines?.[0] ?? "?"}\``
      : "_Unknown_";
    // Estimate savings based on severity
    const savings = estimateGasSavings(opt.severity);
    lines.push(`| ${impact} | ${title} | ${location} | ~${savings} gas |`);
  }

  if (optimizations.length > maxItems) {
    lines.push("");
    lines.push(`_...and ${optimizations.length - maxItems} more optimizations_`);
  }

  return lines.join("\n");
}

/**
 * Generate a markdown section for diff analysis results.
 */
export function generateDiffSection(diffResults: DiffResults): string {
  const lines: string[] = [];

  // Added findings (new issues in this PR)
  if (diffResults.addedFindings.length > 0) {
    lines.push("### ⚠️ New Issues Introduced");
    lines.push("");
    lines.push(generateFindingsTable(diffResults.addedFindings, 10));
    lines.push("");
  }

  // Resolved findings (issues fixed in this PR)
  if (diffResults.resolvedFindings.length > 0) {
    lines.push("### ✅ Issues Resolved");
    lines.push("");
    lines.push(
      `This PR resolves **${diffResults.resolvedFindings.length}** existing issue${diffResults.resolvedFindings.length === 1 ? "" : "s"}:`
    );
    lines.push("");
    for (const finding of diffResults.resolvedFindings.slice(0, 5)) {
      lines.push(`- ~~${finding.title}~~ (${finding.severity})`);
    }
    if (diffResults.resolvedFindings.length > 5) {
      lines.push(`- _...and ${diffResults.resolvedFindings.length - 5} more_`);
    }
    lines.push("");
  }

  // Summary
  if (diffResults.addedFindings.length === 0 && diffResults.resolvedFindings.length === 0) {
    lines.push("_No changes in security findings compared to base branch_");
  }

  return lines.join("\n");
}

/**
 * Generate the full PR comment markdown.
 */
export function generatePRComment(
  results: AuditResults,
  prUrl?: string,
  inlineCommentsPosted?: number
): string {
  const riskLevel = determineRiskLevel(results.summary);
  const badge = getRiskBadge(riskLevel);
  const riskEmoji = getRiskEmoji(riskLevel);

  const totalFindings =
    results.summary.critical +
    results.summary.high +
    results.summary.medium +
    results.summary.low +
    results.summary.informational;

  const lines: string[] = [];

  // Header
  lines.push("## 🔍 Smart Contract Audit Report");
  lines.push("");
  lines.push(badge);
  lines.push("");

  // Summary metrics
  lines.push(`**Risk Level:** ${riskEmoji}`);
  lines.push(
    `**Findings:** ${results.summary.critical} critical, ${results.summary.high} high, ${results.summary.medium} medium, ${results.summary.low} low`
  );

  // Show gas optimizations with meaningful display
  if (results.gasOptimizations.length > 0) {
    lines.push(
      `**Gas Optimizations:** ${results.gasOptimizations.length} suggestions (~${results.summary.estimatedGasSavings.toLocaleString()} gas savings)`
    );
  }
  lines.push("");

  // Inline comments note (only if applicable)
  if (inlineCommentsPosted !== undefined && inlineCommentsPosted < totalFindings) {
    lines.push(
      `> 📝 **Note:** ${inlineCommentsPosted} inline comments posted on changed lines. ` +
        `${totalFindings - inlineCommentsPosted} additional findings are in unchanged code (see details below).`
    );
    lines.push("");
  }

  lines.push("---");
  lines.push("");

  // Diff results (if available)
  if (results.diffResults) {
    lines.push("<details>");
    lines.push("<summary><strong>📊 Changes in This PR</strong></summary>");
    lines.push("");
    lines.push(generateDiffSection(results.diffResults));
    lines.push("");
    lines.push("</details>");
    lines.push("");
  }

  // Security findings
  lines.push("<details>");
  lines.push(`<summary><strong>🛡️ Security Findings (${totalFindings})</strong></summary>`);
  lines.push("");
  lines.push(generateFindingsTable(results.findings));
  lines.push("");
  lines.push("</details>");
  lines.push("");

  // Gas optimizations
  lines.push("<details>");
  lines.push(
    `<summary><strong>⛽ Gas Optimizations (${results.gasOptimizations.length})</strong></summary>`
  );
  lines.push("");
  lines.push(generateGasTable(results.gasOptimizations));
  lines.push("");
  lines.push("</details>");
  lines.push("");

  // Breakdown by severity
  lines.push("<details>");
  lines.push("<summary><strong>📈 Severity Breakdown</strong></summary>");
  lines.push("");
  lines.push("| Severity | Count |");
  lines.push("|:---------|------:|");
  lines.push(`| 🔴 Critical | ${results.summary.critical} |`);
  lines.push(`| 🟠 High | ${results.summary.high} |`);
  lines.push(`| 🟡 Medium | ${results.summary.medium} |`);
  lines.push(`| 🟢 Low | ${results.summary.low} |`);
  lines.push(`| 🔵 Informational | ${results.summary.informational} |`);
  lines.push(`| **Total** | **${totalFindings}** |`);
  lines.push("");
  lines.push("</details>");
  lines.push("");

  // Footer
  lines.push("---");
  lines.push("");
  const checksUrl = prUrl ? `${prUrl}/checks` : "#";
  lines.push(
    `<sub>🤖 Generated by [MCP Audit Server](https://github.com/anthropics/solidity-audit-mcp) | [View full report](${checksUrl})</sub>`
  );

  return lines.join("\n");
}

// ============================================================================
// GitHub API Integration
// ============================================================================

const COMMENT_SIGNATURE = "🔍 Smart Contract Audit Report";

// ============================================================================
// Line-by-Line Review Comments
// ============================================================================

/**
 * Convert a Finding to a review comment format for inline PR comments.
 */
export function findingToReviewComment(finding: Finding): ReviewComment | null {
  if (!finding.location.file || !finding.location.lines?.[0]) {
    return null;
  }

  const emoji = getSeverityEmoji(finding.severity);
  const body = [
    `${emoji} **${finding.severity.toUpperCase()}**: ${finding.title}`,
    "",
    finding.description,
    "",
    `**Recommendation:** ${finding.recommendation}`,
    "",
    `_Detector: \`${finding.detector}\`${finding.swcId ? ` | SWC: ${finding.swcId}` : ""}_`,
  ].join("\n");

  return {
    path: finding.location.file,
    line: finding.location.lines[0],
    side: "RIGHT",
    body,
  };
}

/**
 * Convert all findings to review comments, filtering out those without valid locations.
 */
export function findingsToReviewComments(findings: Finding[]): ReviewComment[] {
  return findings
    .map(findingToReviewComment)
    .filter((comment): comment is ReviewComment => comment !== null);
}

/**
 * Post inline review comments on specific lines of the PR diff.
 * This creates a PR review with line-by-line annotations.
 */
export async function postReviewComments(
  findings: Finding[],
  options: ReviewOptions
): Promise<{ reviewId: number; commentsPosted: number }> {
  const { owner, repo, prNumber, token, commitSha, event = "COMMENT" } = options;

  const comments = findingsToReviewComments(findings);

  if (comments.length === 0) {
    // Create a review without inline comments if no valid locations
    const reviewId = await createReview(owner, repo, prNumber, commitSha, [], event, token);
    return { reviewId, commentsPosted: 0 };
  }

  // Get the diff to validate which lines can be commented on
  const diffFiles = await getPRDiffFiles(owner, repo, prNumber, token);
  const validComments = filterValidComments(comments, diffFiles);

  const reviewId = await createReview(
    owner,
    repo,
    prNumber,
    commitSha,
    validComments,
    event,
    token
  );

  return { reviewId, commentsPosted: validComments.length };
}

/**
 * Get the list of files changed in the PR with their diff positions.
 */
async function getPRDiffFiles(
  owner: string,
  repo: string,
  prNumber: number,
  token: string
): Promise<Map<string, Set<number>>> {
  const url = `https://api.github.com/repos/${owner}/${repo}/pulls/${prNumber}/files`;

  const response = await fetch(url, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/vnd.github.v3+json",
      "User-Agent": "solidity-audit-mcp",
    },
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch PR files: ${response.status} ${response.statusText}`);
  }

  const files = (await response.json()) as Array<{
    filename: string;
    patch?: string;
  }>;

  // Build a map of filename -> set of valid line numbers from the diff
  const fileLines = new Map<string, Set<number>>();

  for (const file of files) {
    if (!file.patch) continue;

    const lines = new Set<number>();
    let currentLine = 0;

    // Parse the patch to extract valid line numbers
    // Format: @@ -old_start,old_count +new_start,new_count @@
    const hunkRegex = /@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/g;
    const patchLines = file.patch.split("\n");

    for (const patchLine of patchLines) {
      const hunkMatch = hunkRegex.exec(patchLine);
      if (hunkMatch?.[1]) {
        currentLine = parseInt(hunkMatch[1], 10);
        hunkRegex.lastIndex = 0;
        continue;
      }

      if (patchLine.startsWith("+") && !patchLine.startsWith("+++")) {
        lines.add(currentLine);
        currentLine++;
      } else if (patchLine.startsWith("-") && !patchLine.startsWith("---")) {
        // Deleted lines don't increment currentLine
      } else if (!patchLine.startsWith("\\")) {
        // Context line
        currentLine++;
      }
    }

    fileLines.set(file.filename, lines);
  }

  return fileLines;
}

/**
 * Filter comments to only include those on valid diff lines.
 */
function filterValidComments(
  comments: ReviewComment[],
  diffFiles: Map<string, Set<number>>
): ReviewComment[] {
  return comments.filter((comment) => {
    const fileLines = diffFiles.get(comment.path);
    if (!fileLines) {
      // Try with different path formats
      for (const [diffPath, lines] of diffFiles) {
        if (diffPath.endsWith(comment.path) || comment.path.endsWith(diffPath)) {
          return lines.has(comment.line);
        }
      }
      return false;
    }
    return fileLines.has(comment.line);
  });
}

/**
 * Create a PR review with inline comments.
 */
async function createReview(
  owner: string,
  repo: string,
  prNumber: number,
  commitSha: string,
  comments: ReviewComment[],
  event: "APPROVE" | "REQUEST_CHANGES" | "COMMENT",
  token: string
): Promise<number> {
  const url = `https://api.github.com/repos/${owner}/${repo}/pulls/${prNumber}/reviews`;

  const body =
    comments.length > 0
      ? `🔍 **Solidity Audit**: Found ${comments.length} issue(s) in the changed code.`
      : "🔍 **Solidity Audit**: No issues found in the changed lines.";

  const response = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/vnd.github.v3+json",
      "User-Agent": "solidity-audit-mcp",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      commit_id: commitSha,
      body,
      event,
      comments: comments.map((c) => ({
        path: c.path,
        line: c.line,
        side: c.side ?? "RIGHT",
        body: c.body,
      })),
    }),
  });

  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(
      `Failed to create review: ${response.status} ${response.statusText} - ${errorBody}`
    );
  }

  const data = (await response.json()) as { id: number };
  return data.id;
}

/**
 * Post or update a PR comment with audit results.
 */
export async function postPRComment(
  results: AuditResults,
  options: CommentOptions,
  inlineCommentsPosted?: number
): Promise<{ commentId: number; updated: boolean }> {
  const { owner, repo, prNumber, token, prUrl } = options;

  const commentBody = generatePRComment(results, prUrl, inlineCommentsPosted);

  // Find existing comment
  const existingComment = await findExistingComment(owner, repo, prNumber, token);

  if (existingComment) {
    // Update existing comment
    await updateComment(owner, repo, existingComment.id, commentBody, token);
    return { commentId: existingComment.id, updated: true };
  } else {
    // Create new comment
    const newComment = await createComment(owner, repo, prNumber, commentBody, token);
    return { commentId: newComment.id, updated: false };
  }
}

/**
 * Find an existing audit comment on the PR.
 */
async function findExistingComment(
  owner: string,
  repo: string,
  prNumber: number,
  token: string
): Promise<{ id: number } | null> {
  const url = `https://api.github.com/repos/${owner}/${repo}/issues/${prNumber}/comments`;

  const response = await fetch(url, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/vnd.github.v3+json",
      "User-Agent": "solidity-audit-mcp",
    },
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch comments: ${response.status} ${response.statusText}`);
  }

  const comments = (await response.json()) as Array<{
    id: number;
    body: string;
    user: { type: string };
  }>;

  // Find our comment by signature
  const ourComment = comments.find(
    (c) => c.user.type === "Bot" && c.body.includes(COMMENT_SIGNATURE)
  );

  return ourComment ? { id: ourComment.id } : null;
}

/**
 * Create a new comment on the PR.
 */
async function createComment(
  owner: string,
  repo: string,
  prNumber: number,
  body: string,
  token: string
): Promise<{ id: number }> {
  const url = `https://api.github.com/repos/${owner}/${repo}/issues/${prNumber}/comments`;

  const response = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/vnd.github.v3+json",
      "User-Agent": "solidity-audit-mcp",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ body }),
  });

  if (!response.ok) {
    throw new Error(`Failed to create comment: ${response.status} ${response.statusText}`);
  }

  const data = (await response.json()) as { id: number };
  return { id: data.id };
}

/**
 * Update an existing comment.
 */
async function updateComment(
  owner: string,
  repo: string,
  commentId: number,
  body: string,
  token: string
): Promise<void> {
  const url = `https://api.github.com/repos/${owner}/${repo}/issues/comments/${commentId}`;

  const response = await fetch(url, {
    method: "PATCH",
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/vnd.github.v3+json",
      "User-Agent": "solidity-audit-mcp",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ body }),
  });

  if (!response.ok) {
    throw new Error(`Failed to update comment: ${response.status} ${response.statusText}`);
  }
}

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Escape markdown special characters.
 */
function escapeMarkdown(text: string): string {
  return text.replace(/[|`*_{}[\]()#+\-.!]/g, "\\$&");
}

/**
 * Estimate gas savings based on severity.
 * Delegates to utils/severity for the actual estimation.
 */
function estimateGasSavings(severity: Severity): number {
  return estimateGasSavingsUtil(severity);
}

/**
 * Create an AuditResults object from raw findings.
 */
export function createAuditResults(
  findings: Finding[],
  gasOptimizations: Finding[],
  diffResults?: DiffResults
): AuditResults {
  const summary: AuditSummary = {
    critical: findings.filter((f) => f.severity === Severity.CRITICAL).length,
    high: findings.filter((f) => f.severity === Severity.HIGH).length,
    medium: findings.filter((f) => f.severity === Severity.MEDIUM).length,
    low: findings.filter((f) => f.severity === Severity.LOW).length,
    informational: findings.filter((f) => f.severity === Severity.INFORMATIONAL).length,
    gasOptimizations: gasOptimizations.length,
    estimatedGasSavings: gasOptimizations.reduce(
      (sum, opt) => sum + estimateGasSavings(opt.severity),
      0
    ),
  };

  return {
    summary,
    findings,
    gasOptimizations,
    diffResults,
  };
}

/**
 * Post a complete audit review: inline comments + summary comment.
 * This is the recommended way to post audit results to a PR.
 */
export async function postFullAuditReview(
  results: AuditResults,
  options: ReviewOptions
): Promise<{
  reviewId: number;
  commentId: number;
  inlineCommentsPosted: number;
  updated: boolean;
}> {
  // First, post inline review comments on changed lines
  const { reviewId, commentsPosted } = await postReviewComments(results.findings, options);

  // Then, post the summary comment with inline comment count
  const { commentId, updated } = await postPRComment(results, options, commentsPosted);

  return {
    reviewId,
    commentId,
    inlineCommentsPosted: commentsPosted,
    updated,
  };
}

// ============================================================================
// Exports
// ============================================================================

export { generatePRComment as generateComment, postPRComment as postComment };
