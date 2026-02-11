/**
 * Findings Database
 *
 * SQLite-based tracking system for audit findings.
 * Stores findings history, tracks status changes, and provides trend analysis.
 *
 * Database file: .audit-history/findings.db (in project root)
 */

import Database from "better-sqlite3";
import { createHash, randomUUID } from "crypto";
import { existsSync, mkdirSync } from "fs";
import { execSync } from "child_process";
import { join, basename } from "path";
import { Finding, Severity } from "../types/index.js";
import { logger } from "../utils/logger.js";

// ============================================================================
// Types
// ============================================================================

export type FindingStatus = "open" | "acknowledged" | "fixed" | "false_positive" | "wont_fix";

export interface StoredFinding {
  id: string;
  contractName: string;
  contractPath: string;
  title: string;
  description: string;
  severity: Severity;
  detector: string;
  location: string;
  firstSeen: string;
  lastSeen: string;
  status: FindingStatus;
  resolvedAt: string | null;
  resolvedBy: string | null;
  notes: string | null;
  occurrences: number;
}

export interface AuditRun {
  id: string;
  timestamp: string;
  contractPath: string;
  totalFindings: number;
  newFindings: number;
  resolvedFindings: number;
  toolsUsed: string[];
  commitHash: string | null;
}

export interface AuditRunSummary {
  runId: string;
  timestamp: string;
  newFindings: number;
  resolvedFindings: number;
  persistentFindings: number;
  totalOpen: number;
  findings: {
    new: StoredFinding[];
    resolved: StoredFinding[];
    persistent: StoredFinding[];
  };
}

export interface TrendData {
  dates: string[];
  openCounts: number[];
  newCounts: number[];
  resolvedCounts: number[];
}

// ============================================================================
// Database Singleton
// ============================================================================

let db: Database.Database | null = null;
let currentProjectRoot: string | null = null;

/**
 * Get the database instance, initializing if needed.
 */
function getDb(projectRoot: string): Database.Database {
  if (db && currentProjectRoot === projectRoot) {
    return db;
  }

  // Close existing connection if switching projects
  if (db) {
    db.close();
  }

  const dbDir = join(projectRoot, ".audit-history");
  const dbPath = join(dbDir, "findings.db");

  // Create directory if it doesn't exist
  if (!existsSync(dbDir)) {
    mkdirSync(dbDir, { recursive: true });
  }

  db = new Database(dbPath);
  currentProjectRoot = projectRoot;

  // Enable WAL mode for better performance
  db.pragma("journal_mode = WAL");

  // Create tables
  createTables(db);

  return db;
}

/**
 * Create database tables if they don't exist.
 */
function createTables(database: Database.Database): void {
  database.exec(`
    CREATE TABLE IF NOT EXISTS findings (
      id TEXT PRIMARY KEY,
      contract_name TEXT NOT NULL,
      contract_path TEXT NOT NULL,
      title TEXT NOT NULL,
      description TEXT,
      severity TEXT NOT NULL,
      detector TEXT NOT NULL,
      location TEXT,
      first_seen TEXT NOT NULL,
      last_seen TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'open',
      resolved_at TEXT,
      resolved_by TEXT,
      notes TEXT,
      occurrences INTEGER NOT NULL DEFAULT 1
    );

    CREATE TABLE IF NOT EXISTS audit_runs (
      id TEXT PRIMARY KEY,
      timestamp TEXT NOT NULL,
      contract_path TEXT NOT NULL,
      total_findings INTEGER NOT NULL,
      new_findings INTEGER NOT NULL,
      resolved_findings INTEGER NOT NULL,
      tools_used TEXT NOT NULL,
      commit_hash TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
    CREATE INDEX IF NOT EXISTS idx_findings_contract ON findings(contract_path);
    CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
    CREATE INDEX IF NOT EXISTS idx_audit_runs_timestamp ON audit_runs(timestamp);
    CREATE INDEX IF NOT EXISTS idx_audit_runs_contract ON audit_runs(contract_path);
  `);
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Generate a unique ID for a finding based on its key attributes.
 */
export function generateFindingId(finding: Finding): string {
  const key = [
    finding.location.file,
    finding.location.lines?.join("-") ?? "",
    finding.detector,
    finding.title,
  ].join("|");

  return createHash("sha256").update(key).digest("hex").substring(0, 16);
}

/**
 * Get the current git commit hash if in a git repository.
 */
function getGitCommitHash(projectRoot: string): string | null {
  try {
    const hash = execSync("git rev-parse HEAD", {
      cwd: projectRoot,
      encoding: "utf-8",
      stdio: ["pipe", "pipe", "pipe"],
    }).trim();
    return hash;
  } catch {
    return null;
  }
}

/**
 * Convert a Finding to a StoredFinding.
 */
function findingToStored(
  finding: Finding,
  id: string,
  now: string
): Omit<StoredFinding, "status" | "resolvedAt" | "resolvedBy" | "notes" | "occurrences"> {
  return {
    id,
    contractName: basename(finding.location.file, ".sol"),
    contractPath: finding.location.file,
    title: finding.title,
    description: finding.description,
    severity: finding.severity,
    detector: finding.detector,
    location: JSON.stringify(finding.location),
    firstSeen: now,
    lastSeen: now,
  };
}

/**
 * Convert a database row to a StoredFinding.
 */
function rowToStoredFinding(row: Record<string, unknown>): StoredFinding {
  return {
    id: row.id as string,
    contractName: row.contract_name as string,
    contractPath: row.contract_path as string,
    title: row.title as string,
    description: row.description as string,
    severity: row.severity as Severity,
    detector: row.detector as string,
    location: row.location as string,
    firstSeen: row.first_seen as string,
    lastSeen: row.last_seen as string,
    status: row.status as FindingStatus,
    resolvedAt: row.resolved_at as string | null,
    resolvedBy: row.resolved_by as string | null,
    notes: row.notes as string | null,
    occurrences: row.occurrences as number,
  };
}

/**
 * Convert a database row to an AuditRun.
 */
function rowToAuditRun(row: Record<string, unknown>): AuditRun {
  return {
    id: row.id as string,
    timestamp: row.timestamp as string,
    contractPath: row.contract_path as string,
    totalFindings: row.total_findings as number,
    newFindings: row.new_findings as number,
    resolvedFindings: row.resolved_findings as number,
    toolsUsed: JSON.parse(row.tools_used as string) as string[],
    commitHash: row.commit_hash as string | null,
  };
}

// ============================================================================
// Public API
// ============================================================================

/**
 * Initialize the database for a project.
 * Creates the .audit-history/ directory and tables if they don't exist.
 */
export function initDb(projectRoot: string): void {
  getDb(projectRoot);
  logger.info(
    `[findings-db] Initialized database at ${join(projectRoot, ".audit-history/findings.db")}`
  );
}

/**
 * Record an audit run and update findings status.
 *
 * - New findings are inserted with status "open"
 * - Existing findings get last_seen and occurrences updated
 * - Previously open findings not in this run are marked as "fixed"
 *
 * @returns Summary of the audit run
 */
export function recordAuditRun(
  projectRoot: string,
  findings: Finding[],
  contractPath: string,
  toolsUsed: string[] = []
): AuditRunSummary {
  const database = getDb(projectRoot);
  const now = new Date().toISOString();
  const runId = randomUUID();
  const commitHash = getGitCommitHash(projectRoot);

  // Prepare statements
  const insertFinding = database.prepare(`
    INSERT INTO findings (id, contract_name, contract_path, title, description, severity, detector, location, first_seen, last_seen, status, occurrences)
    VALUES (@id, @contractName, @contractPath, @title, @description, @severity, @detector, @location, @firstSeen, @lastSeen, 'open', 1)
  `);

  const updateFinding = database.prepare(`
    UPDATE findings
    SET last_seen = @lastSeen, occurrences = occurrences + 1
    WHERE id = @id
  `);

  const getFinding = database.prepare(`
    SELECT * FROM findings WHERE id = @id
  `);

  const getOpenFindings = database.prepare(`
    SELECT * FROM findings WHERE contract_path = @contractPath AND status = 'open'
  `);

  const markAsFixed = database.prepare(`
    UPDATE findings
    SET status = 'fixed', resolved_at = @resolvedAt
    WHERE id = @id AND status = 'open'
  `);

  const insertRun = database.prepare(`
    INSERT INTO audit_runs (id, timestamp, contract_path, total_findings, new_findings, resolved_findings, tools_used, commit_hash)
    VALUES (@id, @timestamp, @contractPath, @totalFindings, @newFindings, @resolvedFindings, @toolsUsed, @commitHash)
  `);

  // Track findings
  const newFindings: StoredFinding[] = [];
  const persistentFindings: StoredFinding[] = [];
  const currentFindingIds = new Set<string>();

  // Process each finding
  const processFinding = database.transaction((finding: Finding) => {
    const id = generateFindingId(finding);
    currentFindingIds.add(id);

    const existing = getFinding.get({ id }) as Record<string, unknown> | undefined;

    if (existing) {
      // Update existing finding
      updateFinding.run({ id, lastSeen: now });
      const updated = getFinding.get({ id }) as Record<string, unknown>;
      persistentFindings.push(rowToStoredFinding(updated));
    } else {
      // Insert new finding
      const stored = findingToStored(finding, id, now);
      insertFinding.run({
        id: stored.id,
        contractName: stored.contractName,
        contractPath: stored.contractPath,
        title: stored.title,
        description: stored.description,
        severity: stored.severity,
        detector: stored.detector,
        location: stored.location,
        firstSeen: stored.firstSeen,
        lastSeen: stored.lastSeen,
      });
      const inserted = getFinding.get({ id }) as Record<string, unknown>;
      newFindings.push(rowToStoredFinding(inserted));
    }
  });

  // Process all findings in a transaction
  for (const finding of findings) {
    processFinding(finding);
  }

  // Find and mark resolved findings (were open, not in current run)
  const resolvedFindings: StoredFinding[] = [];
  const previouslyOpen = getOpenFindings.all({ contractPath }) as Record<string, unknown>[];

  for (const row of previouslyOpen) {
    const storedFinding = rowToStoredFinding(row);
    if (!currentFindingIds.has(storedFinding.id)) {
      markAsFixed.run({ id: storedFinding.id, resolvedAt: now });
      storedFinding.status = "fixed";
      storedFinding.resolvedAt = now;
      resolvedFindings.push(storedFinding);
    }
  }

  // Count total open findings for this contract
  const totalOpenResult = database
    .prepare(
      "SELECT COUNT(*) as count FROM findings WHERE contract_path = @contractPath AND status = 'open'"
    )
    .get({ contractPath }) as { count: number };
  const totalOpen = totalOpenResult.count;

  // Record the audit run
  insertRun.run({
    id: runId,
    timestamp: now,
    contractPath,
    totalFindings: findings.length,
    newFindings: newFindings.length,
    resolvedFindings: resolvedFindings.length,
    toolsUsed: JSON.stringify(toolsUsed),
    commitHash,
  });

  const summary: AuditRunSummary = {
    runId,
    timestamp: now,
    newFindings: newFindings.length,
    resolvedFindings: resolvedFindings.length,
    persistentFindings: persistentFindings.length,
    totalOpen,
    findings: {
      new: newFindings,
      resolved: resolvedFindings,
      persistent: persistentFindings,
    },
  };

  logger.info(
    `[findings-db] Recorded audit run: ${newFindings.length} new, ${resolvedFindings.length} resolved, ${persistentFindings.length} persistent, ${totalOpen} total open`
  );

  return summary;
}

/**
 * Update the status of a finding.
 *
 * Use this to mark findings as:
 * - "acknowledged" - Known issue, will fix later
 * - "false_positive" - Not a real issue
 * - "wont_fix" - Won't be fixed (accepted risk)
 *
 * @param projectRoot - Project root directory
 * @param findingId - The finding ID to update
 * @param status - New status
 * @param notes - Optional notes explaining the status change
 * @param resolvedBy - Optional name/email of who made the change
 */
export function updateFindingStatus(
  projectRoot: string,
  findingId: string,
  status: FindingStatus,
  notes?: string,
  resolvedBy?: string
): boolean {
  const database = getDb(projectRoot);
  const now = new Date().toISOString();

  const isResolved = status === "fixed" || status === "false_positive" || status === "wont_fix";

  const result = database
    .prepare(
      `
      UPDATE findings
      SET status = @status,
          notes = COALESCE(@notes, notes),
          resolved_at = CASE WHEN @isResolved THEN @now ELSE resolved_at END,
          resolved_by = CASE WHEN @isResolved THEN COALESCE(@resolvedBy, resolved_by) ELSE resolved_by END
      WHERE id = @id
    `
    )
    .run({
      id: findingId,
      status,
      notes: notes ?? null,
      isResolved: isResolved ? 1 : 0,
      now,
      resolvedBy: resolvedBy ?? null,
    });

  if (result.changes > 0) {
    logger.info(`[findings-db] Updated finding ${findingId} to status: ${status}`);
    return true;
  }

  logger.warn(`[findings-db] Finding ${findingId} not found`);
  return false;
}

/**
 * Get audit run history.
 *
 * @param projectRoot - Project root directory
 * @param contractPath - Optional filter by contract path
 * @param limit - Maximum number of runs to return (default: 50)
 */
export function getHistory(
  projectRoot: string,
  contractPath?: string,
  limit: number = 50
): AuditRun[] {
  const database = getDb(projectRoot);

  let query = "SELECT * FROM audit_runs";
  const params: Record<string, unknown> = { limit };

  if (contractPath) {
    query += " WHERE contract_path = @contractPath";
    params.contractPath = contractPath;
  }

  query += " ORDER BY timestamp DESC LIMIT @limit";

  const rows = database.prepare(query).all(params) as Record<string, unknown>[];
  return rows.map(rowToAuditRun);
}

/**
 * Get all open findings.
 *
 * @param projectRoot - Project root directory
 * @param contractPath - Optional filter by contract path
 */
export function getOpenFindings(projectRoot: string, contractPath?: string): StoredFinding[] {
  const database = getDb(projectRoot);

  let query = "SELECT * FROM findings WHERE status = 'open'";
  const params: Record<string, unknown> = {};

  if (contractPath) {
    query += " AND contract_path = @contractPath";
    params.contractPath = contractPath;
  }

  query += " ORDER BY severity, first_seen DESC";

  const rows = database.prepare(query).all(params) as Record<string, unknown>[];
  return rows.map(rowToStoredFinding);
}

/**
 * Get a specific finding by ID.
 *
 * @param projectRoot - Project root directory
 * @param findingId - The finding ID
 */
export function getFinding(projectRoot: string, findingId: string): StoredFinding | null {
  const database = getDb(projectRoot);

  const row = database.prepare("SELECT * FROM findings WHERE id = @id").get({ id: findingId }) as
    | Record<string, unknown>
    | undefined;

  return row ? rowToStoredFinding(row) : null;
}

/**
 * Get all findings matching certain criteria.
 *
 * @param projectRoot - Project root directory
 * @param options - Filter options
 */
export function getFindings(
  projectRoot: string,
  options: {
    contractPath?: string;
    status?: FindingStatus | FindingStatus[];
    severity?: Severity | Severity[];
    detector?: string;
    limit?: number;
  } = {}
): StoredFinding[] {
  const database = getDb(projectRoot);

  const conditions: string[] = [];
  const params: Record<string, unknown> = {};

  if (options.contractPath) {
    conditions.push("contract_path = @contractPath");
    params.contractPath = options.contractPath;
  }

  if (options.status) {
    const statuses = Array.isArray(options.status) ? options.status : [options.status];
    conditions.push(`status IN (${statuses.map((_, i) => `@status${i}`).join(", ")})`);
    statuses.forEach((s, i) => {
      params[`status${i}`] = s;
    });
  }

  if (options.severity) {
    const severities = Array.isArray(options.severity) ? options.severity : [options.severity];
    conditions.push(`severity IN (${severities.map((_, i) => `@severity${i}`).join(", ")})`);
    severities.forEach((s, i) => {
      params[`severity${i}`] = s;
    });
  }

  if (options.detector) {
    conditions.push("detector = @detector");
    params.detector = options.detector;
  }

  let query = "SELECT * FROM findings";
  if (conditions.length > 0) {
    query += " WHERE " + conditions.join(" AND ");
  }
  query += " ORDER BY severity, first_seen DESC";

  if (options.limit) {
    query += " LIMIT @limit";
    params.limit = options.limit;
  }

  const rows = database.prepare(query).all(params) as Record<string, unknown>[];
  return rows.map(rowToStoredFinding);
}

/**
 * Get finding trends over the last N days.
 *
 * @param projectRoot - Project root directory
 * @param days - Number of days to look back (default: 30)
 * @param contractPath - Optional filter by contract path
 */
export function getFindingTrend(
  projectRoot: string,
  days: number = 30,
  contractPath?: string
): TrendData {
  const database = getDb(projectRoot);

  const dates: string[] = [];
  const openCounts: number[] = [];
  const newCounts: number[] = [];
  const resolvedCounts: number[] = [];

  // Generate date range
  const startDate = new Date();
  startDate.setDate(startDate.getDate() - days);

  // Build params
  const params: Record<string, unknown> = {};
  if (contractPath) {
    params.contractPath = contractPath;
  }

  // For each day, calculate counts
  for (let i = 0; i <= days; i++) {
    const date = new Date(startDate);
    date.setDate(startDate.getDate() + i);
    const dateStr = date.toISOString().split("T")[0]!;
    dates.push(dateStr);

    const dayStart = `${dateStr}T00:00:00.000Z`;
    const dayEnd = `${dateStr}T23:59:59.999Z`;

    // Count open findings as of this date
    // A finding is open if: first_seen <= date AND (status = 'open' OR resolved_at > date)
    let openQuery = `
      SELECT COUNT(*) as count FROM findings
      WHERE first_seen <= @dayEnd
        AND (status = 'open' OR resolved_at > @dayEnd OR resolved_at IS NULL)
    `;
    if (contractPath) {
      openQuery += " AND contract_path = @contractPath";
    }
    const openResult = database.prepare(openQuery).get({ ...params, dayEnd }) as { count: number };
    openCounts.push(openResult.count);

    // Count new findings on this date
    let newQuery = `
      SELECT COUNT(*) as count FROM findings
      WHERE first_seen >= @dayStart AND first_seen <= @dayEnd
    `;
    if (contractPath) {
      newQuery += " AND contract_path = @contractPath";
    }
    const newResult = database.prepare(newQuery).get({ ...params, dayStart, dayEnd }) as {
      count: number;
    };
    newCounts.push(newResult.count);

    // Count resolved findings on this date
    let resolvedQuery = `
      SELECT COUNT(*) as count FROM findings
      WHERE resolved_at >= @dayStart AND resolved_at <= @dayEnd
    `;
    if (contractPath) {
      resolvedQuery += " AND contract_path = @contractPath";
    }
    const resolvedResult = database.prepare(resolvedQuery).get({ ...params, dayStart, dayEnd }) as {
      count: number;
    };
    resolvedCounts.push(resolvedResult.count);
  }

  return {
    dates,
    openCounts,
    newCounts,
    resolvedCounts,
  };
}

/**
 * Get statistics for the project or a specific contract.
 *
 * @param projectRoot - Project root directory
 * @param contractPath - Optional filter by contract path
 */
export function getStats(
  projectRoot: string,
  contractPath?: string
): {
  totalFindings: number;
  openFindings: number;
  fixedFindings: number;
  acknowledgedFindings: number;
  falsePositives: number;
  wontFix: number;
  bySeverity: Record<Severity, number>;
  byDetector: Record<string, number>;
  averageTimeToFix: number | null;
} {
  const database = getDb(projectRoot);

  const params: Record<string, unknown> = {};
  let whereClause = "";
  if (contractPath) {
    whereClause = " WHERE contract_path = @contractPath";
    params.contractPath = contractPath;
  }

  // Count by status
  const statusCounts = database
    .prepare(
      `
      SELECT status, COUNT(*) as count
      FROM findings
      ${whereClause}
      GROUP BY status
    `
    )
    .all(params) as Array<{ status: string; count: number }>;

  const statusMap: Record<string, number> = {};
  for (const row of statusCounts) {
    statusMap[row.status] = row.count;
  }

  // Count by severity
  const severityCounts = database
    .prepare(
      `
      SELECT severity, COUNT(*) as count
      FROM findings
      ${whereClause}
      GROUP BY severity
    `
    )
    .all(params) as Array<{ severity: string; count: number }>;

  const bySeverity: Record<Severity, number> = {
    [Severity.CRITICAL]: 0,
    [Severity.HIGH]: 0,
    [Severity.MEDIUM]: 0,
    [Severity.LOW]: 0,
    [Severity.INFORMATIONAL]: 0,
  };
  for (const row of severityCounts) {
    bySeverity[row.severity as Severity] = row.count;
  }

  // Count by detector
  const detectorCounts = database
    .prepare(
      `
      SELECT detector, COUNT(*) as count
      FROM findings
      ${whereClause}
      GROUP BY detector
      ORDER BY count DESC
    `
    )
    .all(params) as Array<{ detector: string; count: number }>;

  const byDetector: Record<string, number> = {};
  for (const row of detectorCounts) {
    byDetector[row.detector] = row.count;
  }

  // Calculate average time to fix
  let avgTimeQuery = `
    SELECT AVG(
      (julianday(resolved_at) - julianday(first_seen)) * 24 * 60 * 60 * 1000
    ) as avg_ms
    FROM findings
    WHERE status = 'fixed' AND resolved_at IS NOT NULL
  `;
  if (contractPath) {
    avgTimeQuery += " AND contract_path = @contractPath";
  }
  const avgResult = database.prepare(avgTimeQuery).get(params) as { avg_ms: number | null };
  const averageTimeToFix = avgResult.avg_ms
    ? Math.round(avgResult.avg_ms / (1000 * 60 * 60 * 24))
    : null; // Convert to days

  const total = Object.values(statusMap).reduce((a, b) => a + b, 0);

  return {
    totalFindings: total,
    openFindings: statusMap["open"] ?? 0,
    fixedFindings: statusMap["fixed"] ?? 0,
    acknowledgedFindings: statusMap["acknowledged"] ?? 0,
    falsePositives: statusMap["false_positive"] ?? 0,
    wontFix: statusMap["wont_fix"] ?? 0,
    bySeverity,
    byDetector,
    averageTimeToFix,
  };
}

/**
 * Delete old audit runs to keep the database size manageable.
 *
 * @param projectRoot - Project root directory
 * @param keepDays - Number of days to keep (default: 90)
 */
export function cleanupOldRuns(projectRoot: string, keepDays: number = 90): number {
  const database = getDb(projectRoot);

  const cutoffDate = new Date();
  cutoffDate.setDate(cutoffDate.getDate() - keepDays);
  const cutoffStr = cutoffDate.toISOString();

  const result = database
    .prepare("DELETE FROM audit_runs WHERE timestamp < @cutoff")
    .run({ cutoff: cutoffStr });

  logger.info(`[findings-db] Cleaned up ${result.changes} old audit runs`);
  return result.changes;
}

/**
 * Close the database connection.
 * Call this when done with the database.
 */
export function closeDb(): void {
  if (db) {
    db.close();
    db = null;
    currentProjectRoot = null;
  }
}

/**
 * Export all findings to JSON.
 *
 * @param projectRoot - Project root directory
 * @param contractPath - Optional filter by contract path
 */
export function exportFindings(projectRoot: string, contractPath?: string): string {
  const findings = getFindings(projectRoot, { contractPath });
  const history = getHistory(projectRoot, contractPath);
  const stats = getStats(projectRoot, contractPath);

  return JSON.stringify(
    {
      exportedAt: new Date().toISOString(),
      stats,
      findings,
      auditRuns: history,
    },
    null,
    2
  );
}
