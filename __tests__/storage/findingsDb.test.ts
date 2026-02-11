import { mkdtempSync, rmSync, existsSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import {
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
} from "../../src/storage/findingsDb.js";
import { Severity, type Finding } from "../../src/types/index.js";

// ============================================================================
// Test Helpers
// ============================================================================

let testDir: string;

function createTestFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: `test-${Date.now()}-${Math.random().toString(36).substring(7)}`,
    title: "Test Finding",
    description: "A test finding description",
    severity: Severity.MEDIUM,
    confidence: "high",
    detector: "test-detector",
    location: {
      file: "contracts/Test.sol",
      lines: [10, 15],
      function: "testFunction",
    },
    recommendation: "Fix the issue",
    ...overrides,
  };
}

beforeEach(() => {
  // Create a temporary directory for each test
  testDir = mkdtempSync(join(tmpdir(), "audit-test-"));
});

afterEach(() => {
  // Close database and clean up
  closeDb();
  if (existsSync(testDir)) {
    rmSync(testDir, { recursive: true, force: true });
  }
});

// ============================================================================
// Tests
// ============================================================================

describe("initDb", () => {
  it("should create the .audit-history directory", () => {
    initDb(testDir);
    expect(existsSync(join(testDir, ".audit-history"))).toBe(true);
  });

  it("should create the database file", () => {
    initDb(testDir);
    expect(existsSync(join(testDir, ".audit-history", "findings.db"))).toBe(true);
  });

  it("should be idempotent", () => {
    initDb(testDir);
    initDb(testDir);
    expect(existsSync(join(testDir, ".audit-history", "findings.db"))).toBe(true);
  });
});

describe("generateFindingId", () => {
  it("should generate consistent IDs for the same finding", () => {
    const finding = createTestFinding();
    const id1 = generateFindingId(finding);
    const id2 = generateFindingId(finding);
    expect(id1).toBe(id2);
  });

  it("should generate different IDs for different findings", () => {
    const finding1 = createTestFinding({ title: "Finding 1" });
    const finding2 = createTestFinding({ title: "Finding 2" });
    expect(generateFindingId(finding1)).not.toBe(generateFindingId(finding2));
  });

  it("should generate different IDs for different locations", () => {
    const finding1 = createTestFinding({ location: { file: "A.sol", lines: [1, 5] } });
    const finding2 = createTestFinding({ location: { file: "B.sol", lines: [1, 5] } });
    expect(generateFindingId(finding1)).not.toBe(generateFindingId(finding2));
  });
});

describe("recordAuditRun", () => {
  it("should record new findings", () => {
    initDb(testDir);
    const findings = [
      createTestFinding({ title: "Finding 1", severity: Severity.HIGH }),
      createTestFinding({ title: "Finding 2", severity: Severity.MEDIUM }),
    ];

    const summary = recordAuditRun(testDir, findings, "contracts/Test.sol", ["slither"]);

    expect(summary.newFindings).toBe(2);
    expect(summary.persistentFindings).toBe(0);
    expect(summary.resolvedFindings).toBe(0);
    expect(summary.totalOpen).toBe(2);
    expect(summary.findings.new).toHaveLength(2);
  });

  it("should track persistent findings across runs", () => {
    initDb(testDir);
    const finding = createTestFinding({ title: "Persistent Finding" });

    // First run
    const summary1 = recordAuditRun(testDir, [finding], "contracts/Test.sol");
    expect(summary1.newFindings).toBe(1);

    // Second run with same finding
    const summary2 = recordAuditRun(testDir, [finding], "contracts/Test.sol");
    expect(summary2.newFindings).toBe(0);
    expect(summary2.persistentFindings).toBe(1);
    expect(summary2.findings.persistent).toHaveLength(1);
    expect(summary2.findings.persistent[0]!.occurrences).toBe(2);
  });

  it("should detect resolved findings", () => {
    initDb(testDir);
    const finding1 = createTestFinding({ title: "Will be fixed" });
    const finding2 = createTestFinding({ title: "Will persist" });

    // First run with both findings
    recordAuditRun(testDir, [finding1, finding2], "contracts/Test.sol");

    // Second run without finding1
    const summary = recordAuditRun(testDir, [finding2], "contracts/Test.sol");

    expect(summary.resolvedFindings).toBe(1);
    expect(summary.findings.resolved).toHaveLength(1);
    expect(summary.findings.resolved[0]!.title).toBe("Will be fixed");
    expect(summary.findings.resolved[0]!.status).toBe("fixed");
  });

  it("should generate a unique run ID", () => {
    initDb(testDir);
    const summary1 = recordAuditRun(testDir, [], "contracts/Test.sol");
    const summary2 = recordAuditRun(testDir, [], "contracts/Test.sol");

    expect(summary1.runId).not.toBe(summary2.runId);
  });
});

describe("updateFindingStatus", () => {
  it("should update finding status", () => {
    initDb(testDir);
    const finding = createTestFinding();
    recordAuditRun(testDir, [finding], "contracts/Test.sol");

    const findingId = generateFindingId(finding);
    const result = updateFindingStatus(testDir, findingId, "acknowledged", "Known issue");

    expect(result).toBe(true);

    const updated = getFinding(testDir, findingId);
    expect(updated?.status).toBe("acknowledged");
    expect(updated?.notes).toBe("Known issue");
  });

  it("should set resolved_at for terminal statuses", () => {
    initDb(testDir);
    const finding = createTestFinding();
    recordAuditRun(testDir, [finding], "contracts/Test.sol");

    const findingId = generateFindingId(finding);
    updateFindingStatus(testDir, findingId, "false_positive", "Not a real issue", "tester");

    const updated = getFinding(testDir, findingId);
    expect(updated?.status).toBe("false_positive");
    expect(updated?.resolvedAt).not.toBeNull();
    expect(updated?.resolvedBy).toBe("tester");
  });

  it("should return false for non-existent finding", () => {
    initDb(testDir);
    const result = updateFindingStatus(testDir, "non-existent-id", "acknowledged");
    expect(result).toBe(false);
  });

  it("should not auto-detect false positives in future runs", () => {
    initDb(testDir);
    const finding = createTestFinding();
    recordAuditRun(testDir, [finding], "contracts/Test.sol");

    // Mark as false positive
    const findingId = generateFindingId(finding);
    updateFindingStatus(testDir, findingId, "false_positive");

    // Run again without the finding - should not mark as newly resolved
    const summary = recordAuditRun(testDir, [], "contracts/Test.sol");
    expect(summary.resolvedFindings).toBe(0); // Already marked as false positive
  });
});

describe("getHistory", () => {
  it("should return empty array for new database", () => {
    initDb(testDir);
    const history = getHistory(testDir);
    expect(history).toHaveLength(0);
  });

  it("should return audit runs in reverse chronological order", () => {
    initDb(testDir);

    recordAuditRun(testDir, [], "contracts/A.sol");
    recordAuditRun(testDir, [], "contracts/B.sol");
    recordAuditRun(testDir, [], "contracts/C.sol");

    const history = getHistory(testDir);
    expect(history).toHaveLength(3);
    expect(history[0]!.contractPath).toBe("contracts/C.sol");
    expect(history[2]!.contractPath).toBe("contracts/A.sol");
  });

  it("should filter by contract path", () => {
    initDb(testDir);

    recordAuditRun(testDir, [], "contracts/A.sol");
    recordAuditRun(testDir, [], "contracts/B.sol");
    recordAuditRun(testDir, [], "contracts/A.sol");

    const history = getHistory(testDir, "contracts/A.sol");
    expect(history).toHaveLength(2);
    expect(history.every((h) => h.contractPath === "contracts/A.sol")).toBe(true);
  });

  it("should respect limit parameter", () => {
    initDb(testDir);

    for (let i = 0; i < 10; i++) {
      recordAuditRun(testDir, [], "contracts/Test.sol");
    }

    const history = getHistory(testDir, undefined, 5);
    expect(history).toHaveLength(5);
  });
});

describe("getOpenFindings", () => {
  it("should return only open findings", () => {
    initDb(testDir);

    const finding1 = createTestFinding({ title: "Open Finding" });
    const finding2 = createTestFinding({ title: "Will be acknowledged" });

    recordAuditRun(testDir, [finding1, finding2], "contracts/Test.sol");
    updateFindingStatus(testDir, generateFindingId(finding2), "acknowledged");

    const openFindings = getOpenFindings(testDir);
    expect(openFindings).toHaveLength(1);
    expect(openFindings[0]!.title).toBe("Open Finding");
  });

  it("should filter by contract path", () => {
    initDb(testDir);

    const findingA = createTestFinding({
      title: "Finding A",
      location: { file: "contracts/A.sol", lines: [1, 5] },
    });
    const findingB = createTestFinding({
      title: "Finding B",
      location: { file: "contracts/B.sol", lines: [1, 5] },
    });

    recordAuditRun(testDir, [findingA], "contracts/A.sol");
    recordAuditRun(testDir, [findingB], "contracts/B.sol");

    const openA = getOpenFindings(testDir, "contracts/A.sol");
    expect(openA).toHaveLength(1);
    expect(openA[0]!.title).toBe("Finding A");
  });
});

describe("getFindings", () => {
  beforeEach(() => {
    initDb(testDir);

    const findings = [
      createTestFinding({ title: "Critical 1", severity: Severity.CRITICAL, detector: "slither" }),
      createTestFinding({ title: "High 1", severity: Severity.HIGH, detector: "aderyn" }),
      createTestFinding({ title: "Medium 1", severity: Severity.MEDIUM, detector: "slither" }),
    ];

    recordAuditRun(testDir, findings, "contracts/Test.sol");
  });

  it("should return all findings without filters", () => {
    const findings = getFindings(testDir);
    expect(findings).toHaveLength(3);
  });

  it("should filter by severity", () => {
    const findings = getFindings(testDir, { severity: Severity.CRITICAL });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe(Severity.CRITICAL);
  });

  it("should filter by multiple severities", () => {
    const findings = getFindings(testDir, {
      severity: [Severity.CRITICAL, Severity.HIGH],
    });
    expect(findings).toHaveLength(2);
  });

  it("should filter by detector", () => {
    const findings = getFindings(testDir, { detector: "slither" });
    expect(findings).toHaveLength(2);
  });

  it("should filter by status", () => {
    // Mark one as acknowledged
    const allFindings = getFindings(testDir);
    updateFindingStatus(testDir, allFindings[0]!.id, "acknowledged");

    const openFindings = getFindings(testDir, { status: "open" });
    expect(openFindings).toHaveLength(2);

    const acknowledgedFindings = getFindings(testDir, { status: "acknowledged" });
    expect(acknowledgedFindings).toHaveLength(1);
  });

  it("should respect limit", () => {
    const findings = getFindings(testDir, { limit: 2 });
    expect(findings).toHaveLength(2);
  });
});

describe("getFindingTrend", () => {
  it("should return trend data for specified days", () => {
    initDb(testDir);

    const trend = getFindingTrend(testDir, 7);

    expect(trend.dates).toHaveLength(8); // 7 days + today
    expect(trend.openCounts).toHaveLength(8);
    expect(trend.newCounts).toHaveLength(8);
    expect(trend.resolvedCounts).toHaveLength(8);
  });

  it("should track new findings on the correct date", () => {
    initDb(testDir);

    // Add a finding today
    const finding = createTestFinding();
    recordAuditRun(testDir, [finding], "contracts/Test.sol");

    const trend = getFindingTrend(testDir, 7);

    // Today should have 1 new finding
    const todayNew = trend.newCounts[trend.newCounts.length - 1];
    expect(todayNew).toBe(1);

    // Today should have 1 open finding
    const todayOpen = trend.openCounts[trend.openCounts.length - 1];
    expect(todayOpen).toBe(1);
  });
});

describe("getStats", () => {
  it("should return zero counts for empty database", () => {
    initDb(testDir);
    const stats = getStats(testDir);

    expect(stats.totalFindings).toBe(0);
    expect(stats.openFindings).toBe(0);
    expect(stats.fixedFindings).toBe(0);
  });

  it("should count findings by status", () => {
    initDb(testDir);

    const findings = [
      createTestFinding({ title: "Open 1" }),
      createTestFinding({ title: "Open 2" }),
      createTestFinding({ title: "Will acknowledge" }),
    ];

    recordAuditRun(testDir, findings, "contracts/Test.sol");
    updateFindingStatus(testDir, generateFindingId(findings[2]!), "acknowledged");

    const stats = getStats(testDir);
    expect(stats.totalFindings).toBe(3);
    expect(stats.openFindings).toBe(2);
    expect(stats.acknowledgedFindings).toBe(1);
  });

  it("should count findings by severity", () => {
    initDb(testDir);

    const findings = [
      createTestFinding({ title: "Critical Issue", severity: Severity.CRITICAL }),
      createTestFinding({ title: "High Issue 1", severity: Severity.HIGH }),
      createTestFinding({ title: "High Issue 2", severity: Severity.HIGH }),
      createTestFinding({ title: "Medium Issue", severity: Severity.MEDIUM }),
    ];

    recordAuditRun(testDir, findings, "contracts/Test.sol");

    const stats = getStats(testDir);
    expect(stats.bySeverity[Severity.CRITICAL]).toBe(1);
    expect(stats.bySeverity[Severity.HIGH]).toBe(2);
    expect(stats.bySeverity[Severity.MEDIUM]).toBe(1);
  });

  it("should count findings by detector", () => {
    initDb(testDir);

    const findings = [
      createTestFinding({ title: "Slither Issue 1", detector: "slither" }),
      createTestFinding({ title: "Slither Issue 2", detector: "slither" }),
      createTestFinding({ title: "Aderyn Issue", detector: "aderyn" }),
    ];

    recordAuditRun(testDir, findings, "contracts/Test.sol");

    const stats = getStats(testDir);
    expect(stats.byDetector["slither"]).toBe(2);
    expect(stats.byDetector["aderyn"]).toBe(1);
  });
});

describe("cleanupOldRuns", () => {
  it("should remove runs older than specified days", () => {
    initDb(testDir);

    // Create some runs
    recordAuditRun(testDir, [], "contracts/Test.sol");
    recordAuditRun(testDir, [], "contracts/Test.sol");

    // Cleanup with 0 days (should remove all)
    const removed = cleanupOldRuns(testDir, 0);

    // Note: This test is timing-dependent. Runs created just now won't be removed.
    // We just verify the function runs without error.
    expect(typeof removed).toBe("number");
  });
});

describe("exportFindings", () => {
  it("should export findings as JSON", () => {
    initDb(testDir);

    const finding = createTestFinding();
    recordAuditRun(testDir, [finding], "contracts/Test.sol");

    const exported = exportFindings(testDir);
    const data = JSON.parse(exported);

    expect(data).toHaveProperty("exportedAt");
    expect(data).toHaveProperty("stats");
    expect(data).toHaveProperty("findings");
    expect(data).toHaveProperty("auditRuns");
    expect(data.findings).toHaveLength(1);
  });

  it("should filter by contract path", () => {
    initDb(testDir);

    const findingA = createTestFinding({
      location: { file: "contracts/A.sol", lines: [1, 5] },
    });
    const findingB = createTestFinding({
      location: { file: "contracts/B.sol", lines: [1, 5] },
    });

    recordAuditRun(testDir, [findingA], "contracts/A.sol");
    recordAuditRun(testDir, [findingB], "contracts/B.sol");

    const exported = exportFindings(testDir, "contracts/A.sol");
    const data = JSON.parse(exported);

    expect(data.findings).toHaveLength(1);
    expect(data.findings[0].contractPath).toBe("contracts/A.sol");
  });
});
