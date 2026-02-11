/**
 * Storage Module
 *
 * Provides persistent storage for audit findings using SQLite.
 */

export {
  // Types
  type FindingStatus,
  type StoredFinding,
  type AuditRun,
  type AuditRunSummary,
  type TrendData,
  // Functions
  initDb,
  recordAuditRun,
  updateFindingStatus,
  getHistory,
  getOpenFindings,
  getFinding,
  getFindings,
  getFindingTrend,
  getStats,
  cleanupOldRuns,
  closeDb,
  exportFindings,
  generateFindingId,
} from "./findingsDb.js";
