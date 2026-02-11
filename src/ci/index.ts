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
  // Aliases
  generateComment,
  postComment,
} from "./githubComment.js";
