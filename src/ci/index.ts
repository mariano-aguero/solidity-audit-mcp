/**
 * CI/CD Integration Module
 *
 * Provides utilities for integrating the audit server with CI/CD pipelines,
 * including GitHub Actions support and PR comment generation.
 */

export {
  // Types
  type AuditSummary,
  type AuditResults,
  type DiffResults,
  type RiskLevel,
  type CommentOptions,
  type ReviewComment,
  type ReviewOptions,
  // Functions
  determineRiskLevel,
  getRiskBadge,
  getRiskEmoji,
  getSeverityEmoji,
  generateFindingsTable,
  generateGasTable,
  generateDiffSection,
  generatePRComment,
  postPRComment,
  createAuditResults,
  // Line-by-line review comments
  findingToReviewComment,
  findingsToReviewComments,
  postReviewComments,
  // Aliases
  generateComment,
  postComment,
} from "./githubComment.js";
