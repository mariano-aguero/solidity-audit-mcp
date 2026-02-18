import {
  determineRiskLevel,
  getRiskBadge,
  getRiskEmoji,
  getSeverityEmoji,
  generateFindingsTable,
  generateGasTable,
  generateDiffSection,
  generatePRComment,
  createAuditResults,
  type AuditSummary,
  type AuditResults,
  type DiffResults,
} from "../../src/ci/githubComment.js";
import { Severity, type Finding } from "../../src/types/index.js";

// ============================================================================
// Test Data
// ============================================================================

function createTestFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "test-001",
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

function createTestSummary(overrides: Partial<AuditSummary> = {}): AuditSummary {
  return {
    critical: 0,
    high: 0,
    medium: 1,
    low: 0,
    informational: 0,
    gasOptimizations: 0,
    estimatedGasSavings: 0,
    ...overrides,
  };
}

// ============================================================================
// Risk Level Tests
// ============================================================================

describe("determineRiskLevel", () => {
  it("should return critical when critical findings exist", () => {
    const summary = createTestSummary({ critical: 1 });
    expect(determineRiskLevel(summary)).toBe("critical");
  });

  it("should return high when high findings exist", () => {
    const summary = createTestSummary({ high: 1 });
    expect(determineRiskLevel(summary)).toBe("high");
  });

  it("should return medium when medium findings exist", () => {
    const summary = createTestSummary({ medium: 1 });
    expect(determineRiskLevel(summary)).toBe("medium");
  });

  it("should return low when low findings exist", () => {
    const summary = createTestSummary({ medium: 0, low: 1 });
    expect(determineRiskLevel(summary)).toBe("low");
  });

  it("should return clean when no findings exist", () => {
    const summary = createTestSummary({
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      informational: 0,
    });
    expect(determineRiskLevel(summary)).toBe("clean");
  });

  it("should prioritize critical over high", () => {
    const summary = createTestSummary({ critical: 1, high: 5 });
    expect(determineRiskLevel(summary)).toBe("critical");
  });
});

// ============================================================================
// Badge and Emoji Tests
// ============================================================================

describe("getRiskBadge", () => {
  it("should return correct badges", () => {
    expect(getRiskBadge("critical")).toContain("CRITICAL");
    expect(getRiskBadge("critical")).toContain("red");
    expect(getRiskBadge("high")).toContain("HIGH");
    expect(getRiskBadge("high")).toContain("orange");
    expect(getRiskBadge("medium")).toContain("MEDIUM");
    expect(getRiskBadge("low")).toContain("LOW");
    expect(getRiskBadge("clean")).toContain("CLEAN");
  });
});

describe("getRiskEmoji", () => {
  it("should return correct emojis", () => {
    expect(getRiskEmoji("critical")).toBe("🔴 CRITICAL");
    expect(getRiskEmoji("high")).toBe("🟠 HIGH");
    expect(getRiskEmoji("medium")).toBe("🟡 MEDIUM");
    expect(getRiskEmoji("low")).toBe("🟢 LOW");
    expect(getRiskEmoji("clean")).toBe("✅ CLEAN");
  });
});

describe("getSeverityEmoji", () => {
  it("should return correct severity emojis", () => {
    expect(getSeverityEmoji(Severity.CRITICAL)).toBe("🔴");
    expect(getSeverityEmoji(Severity.HIGH)).toBe("🟠");
    expect(getSeverityEmoji(Severity.MEDIUM)).toBe("🟡");
    expect(getSeverityEmoji(Severity.LOW)).toBe("🟢");
    expect(getSeverityEmoji(Severity.INFORMATIONAL)).toBe("🔵");
  });
});

// ============================================================================
// Table Generation Tests
// ============================================================================

describe("generateFindingsTable", () => {
  it("should return empty message for no findings", () => {
    const result = generateFindingsTable([]);
    expect(result).toBe("_No security findings detected_");
  });

  it("should generate markdown table for findings", () => {
    const findings = [
      createTestFinding({ severity: Severity.HIGH, title: "High Issue" }),
      createTestFinding({ severity: Severity.MEDIUM, title: "Medium Issue" }),
    ];

    const result = generateFindingsTable(findings);

    expect(result).toContain("| Severity | Title | Location | Detector |");
    expect(result).toContain("HIGH");
    expect(result).toContain("High Issue");
    expect(result).toContain("contracts/Test.sol");
  });

  it("should show remaining findings in collapsible section", () => {
    const findings = Array(25)
      .fill(null)
      .map((_, i) => createTestFinding({ id: `finding-${i}`, title: `Finding ${i}` }));

    const result = generateFindingsTable(findings, 20);

    // Should use collapsible details section
    expect(result).toContain("<details>");
    expect(result).toContain("Show 5 more findings");
    expect(result).toContain("</details>");
  });

  it("should sort findings by severity (critical first)", () => {
    const findings = [
      createTestFinding({ severity: Severity.LOW, title: "Low Issue" }),
      createTestFinding({ severity: Severity.CRITICAL, title: "Critical Issue" }),
      createTestFinding({ severity: Severity.MEDIUM, title: "Medium Issue" }),
      createTestFinding({ severity: Severity.HIGH, title: "High Issue" }),
    ];

    const result = generateFindingsTable(findings);

    // Critical should appear before High, which appears before Medium, etc.
    const criticalIndex = result.indexOf("Critical Issue");
    const highIndex = result.indexOf("High Issue");
    const mediumIndex = result.indexOf("Medium Issue");
    const lowIndex = result.indexOf("Low Issue");

    expect(criticalIndex).toBeLessThan(highIndex);
    expect(highIndex).toBeLessThan(mediumIndex);
    expect(mediumIndex).toBeLessThan(lowIndex);
  });

  it("should escape markdown characters", () => {
    const findings = [createTestFinding({ title: "Issue | with | pipes" })];

    const result = generateFindingsTable(findings);

    // Pipes should be escaped
    expect(result).toContain("\\|");
  });
});

describe("generateGasTable", () => {
  it("should return empty message for no optimizations", () => {
    const result = generateGasTable([]);
    expect(result).toBe("_No gas optimizations found_");
  });

  it("should generate markdown table for gas optimizations", () => {
    const optimizations = [
      createTestFinding({
        severity: Severity.HIGH,
        title: "Expensive Storage",
        detector: "gas-optimizer",
      }),
    ];

    const result = generateGasTable(optimizations);

    expect(result).toContain("| Impact | Optimization | Location |");
    expect(result).toContain("Expensive Storage");
    expect(result).toContain("gas");
  });

  it("should truncate at maxItems", () => {
    const optimizations = Array(15)
      .fill(null)
      .map((_, i) => createTestFinding({ id: `gas-${i}`, title: `Gas ${i}` }));

    const result = generateGasTable(optimizations, 10);

    expect(result).toContain("...and 5 more optimizations");
  });
});

// ============================================================================
// Diff Section Tests
// ============================================================================

describe("generateDiffSection", () => {
  it("should show new issues introduced", () => {
    const diffResults: DiffResults = {
      addedFindings: [createTestFinding({ title: "New Issue" })],
      resolvedFindings: [],
      unchangedFindings: [],
    };

    const result = generateDiffSection(diffResults);

    expect(result).toContain("New Issues Introduced");
    expect(result).toContain("New Issue");
  });

  it("should show resolved issues", () => {
    const diffResults: DiffResults = {
      addedFindings: [],
      resolvedFindings: [
        createTestFinding({ title: "Fixed Issue", severity: Severity.HIGH }),
        createTestFinding({ title: "Another Fix", severity: Severity.MEDIUM }),
      ],
      unchangedFindings: [],
    };

    const result = generateDiffSection(diffResults);

    expect(result).toContain("Issues Resolved");
    expect(result).toContain("~~Fixed Issue~~");
    expect(result).toContain("resolves **2** existing issues");
  });

  it("should show no changes message when nothing changed", () => {
    const diffResults: DiffResults = {
      addedFindings: [],
      resolvedFindings: [],
      unchangedFindings: [createTestFinding()],
    };

    const result = generateDiffSection(diffResults);

    expect(result).toContain("No changes in security findings");
  });
});

// ============================================================================
// Full Comment Generation Tests
// ============================================================================

describe("generatePRComment", () => {
  it("should generate complete PR comment", () => {
    const results: AuditResults = {
      summary: createTestSummary({
        high: 1,
        medium: 2,
        gasOptimizations: 3,
        estimatedGasSavings: 500,
      }),
      findings: [
        createTestFinding({ severity: Severity.HIGH, title: "Critical Reentrancy" }),
        createTestFinding({ severity: Severity.MEDIUM, title: "Unchecked Return" }),
      ],
      gasOptimizations: [createTestFinding({ severity: Severity.LOW, title: "Use calldata" })],
    };

    const result = generatePRComment(results, "https://github.com/test/repo/pull/1");

    // Check header
    expect(result).toContain("## 🔍 Smart Contract Audit Report");

    // Check badge
    expect(result).toContain("![High]");

    // Check summary
    expect(result).toContain("**Risk Level:** 🟠 HIGH");
    expect(result).toContain("0 critical, 1 high, 2 medium, 0 low");

    // Check sections
    expect(result).toContain("Security Findings (3)");
    expect(result).toContain("Gas Optimizations (1)");
    expect(result).toContain("Severity Breakdown");

    // Check footer
    expect(result).toContain("MCP Audit Server");
  });

  it("should include diff results when provided", () => {
    const results: AuditResults = {
      summary: createTestSummary(),
      findings: [],
      gasOptimizations: [],
      diffResults: {
        addedFindings: [createTestFinding({ title: "New Bug" })],
        resolvedFindings: [],
        unchangedFindings: [],
      },
    };

    const result = generatePRComment(results);

    expect(result).toContain("Changes in This PR");
    expect(result).toContain("New Bug");
  });

  it("should show clean status when no findings", () => {
    const results: AuditResults = {
      summary: createTestSummary({
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        informational: 0,
      }),
      findings: [],
      gasOptimizations: [],
    };

    const result = generatePRComment(results);

    expect(result).toContain("CLEAN");
    expect(result).toContain("✅");
  });

  it("should include inline comments note when provided", () => {
    const results: AuditResults = {
      summary: createTestSummary({
        high: 5,
        medium: 10,
        low: 20,
      }),
      findings: Array(35)
        .fill(null)
        .map((_, i) => createTestFinding({ id: `finding-${i}` })),
      gasOptimizations: [],
    };

    // 35 total findings, only 10 posted as inline comments
    const result = generatePRComment(results, undefined, 10);

    expect(result).toContain("10 inline comments posted on changed lines");
    expect(result).toContain("25 additional findings are in unchanged code");
  });

  it("should not show inline comments note when all comments posted", () => {
    const results: AuditResults = {
      summary: createTestSummary({
        critical: 0,
        high: 2,
        medium: 0,
        low: 0,
        informational: 0,
      }),
      findings: [
        createTestFinding({ id: "1", severity: Severity.HIGH }),
        createTestFinding({ id: "2", severity: Severity.HIGH }),
      ],
      gasOptimizations: [],
    };

    // All findings posted as inline comments (2 of 2)
    const result = generatePRComment(results, undefined, 2);

    expect(result).not.toContain("inline comments posted");
  });
});

// ============================================================================
// createAuditResults Tests
// ============================================================================

describe("createAuditResults", () => {
  it("should compute summary from findings", () => {
    const findings = [
      createTestFinding({ severity: Severity.CRITICAL }),
      createTestFinding({ severity: Severity.HIGH }),
      createTestFinding({ severity: Severity.HIGH }),
      createTestFinding({ severity: Severity.MEDIUM }),
      createTestFinding({ severity: Severity.LOW }),
      createTestFinding({ severity: Severity.INFORMATIONAL }),
    ];

    const gasOptimizations = [
      createTestFinding({ severity: Severity.LOW }),
      createTestFinding({ severity: Severity.INFORMATIONAL }),
    ];

    const result = createAuditResults(findings, gasOptimizations);

    expect(result.summary.critical).toBe(1);
    expect(result.summary.high).toBe(2);
    expect(result.summary.medium).toBe(1);
    expect(result.summary.low).toBe(1);
    expect(result.summary.informational).toBe(1);
    expect(result.summary.gasOptimizations).toBe(2);
    expect(result.summary.estimatedGasSavings).toBeGreaterThan(0);
  });

  it("should include diff results when provided", () => {
    const diffResults: DiffResults = {
      addedFindings: [],
      resolvedFindings: [],
      unchangedFindings: [],
    };

    const result = createAuditResults([], [], diffResults);

    expect(result.diffResults).toBe(diffResults);
  });

  it("should handle empty arrays", () => {
    const result = createAuditResults([], []);

    expect(result.summary.critical).toBe(0);
    expect(result.summary.high).toBe(0);
    expect(result.summary.medium).toBe(0);
    expect(result.summary.low).toBe(0);
    expect(result.summary.informational).toBe(0);
    expect(result.summary.gasOptimizations).toBe(0);
    expect(result.summary.estimatedGasSavings).toBe(0);
    expect(result.findings).toHaveLength(0);
    expect(result.gasOptimizations).toHaveLength(0);
  });
});
