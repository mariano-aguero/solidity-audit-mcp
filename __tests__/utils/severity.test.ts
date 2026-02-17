/**
 * Severity Utilities Tests
 *
 * Tests for the centralized severity utilities using Given-When-Then pattern.
 */

import { describe, it, expect } from "vitest";
import { Severity, type Finding } from "../../src/types/index.js";
import {
  SEVERITY_ORDER,
  SEVERITY_EMOJI,
  compareSeverity,
  sortBySeverity,
  getSeverityEmoji,
  countBySeverity,
  estimateGasSavings,
  extractGasSavings,
  formatGasSavings,
  calculateTotalGasSavings,
} from "../../src/utils/severity.js";

// ============================================================================
// Test Fixtures
// ============================================================================

function createFinding(severity: Severity, description = "Test finding"): Finding {
  return {
    id: `test-${Math.random().toString(36).slice(2, 8)}`,
    title: "Test Finding",
    severity,
    description,
    location: { file: "Test.sol" },
    recommendation: "Fix it",
    detector: "test",
    confidence: "high",
  };
}

// ============================================================================
// SEVERITY_ORDER Tests
// ============================================================================

describe("SEVERITY_ORDER", () => {
  it("should have correct ordering for all severity levels", () => {
    // Given: The severity order constants
    // When: We check the ordering values
    // Then: CRITICAL should be lowest (most severe) and INFORMATIONAL highest
    expect(SEVERITY_ORDER[Severity.CRITICAL]).toBe(0);
    expect(SEVERITY_ORDER[Severity.HIGH]).toBe(1);
    expect(SEVERITY_ORDER[Severity.MEDIUM]).toBe(2);
    expect(SEVERITY_ORDER[Severity.LOW]).toBe(3);
    expect(SEVERITY_ORDER[Severity.INFORMATIONAL]).toBe(4);
  });

  it("should have entries for all Severity enum values", () => {
    // Given: All severity enum values
    const allSeverities = Object.values(Severity);

    // When: We check if each has an order
    // Then: All should have defined order values
    for (const severity of allSeverities) {
      expect(SEVERITY_ORDER[severity]).toBeDefined();
      expect(typeof SEVERITY_ORDER[severity]).toBe("number");
    }
  });
});

// ============================================================================
// SEVERITY_EMOJI Tests
// ============================================================================

describe("SEVERITY_EMOJI", () => {
  it("should have emojis for all severity levels", () => {
    // Given: All severity enum values
    const allSeverities = Object.values(Severity);

    // When: We check if each has an emoji
    // Then: All should have defined emoji strings
    for (const severity of allSeverities) {
      expect(SEVERITY_EMOJI[severity]).toBeDefined();
      expect(typeof SEVERITY_EMOJI[severity]).toBe("string");
      expect(SEVERITY_EMOJI[severity].length).toBeGreaterThan(0);
    }
  });

  it("should have distinct emojis for each severity", () => {
    // Given: The emoji mappings
    // When: We collect all emojis
    const emojis = Object.values(SEVERITY_EMOJI);

    // Then: All should be unique
    const uniqueEmojis = new Set(emojis);
    expect(uniqueEmojis.size).toBe(emojis.length);
  });
});

// ============================================================================
// compareSeverity Tests
// ============================================================================

describe("compareSeverity", () => {
  it("should return negative when first severity is more severe", () => {
    // Given: CRITICAL and HIGH severities
    // When: Comparing CRITICAL to HIGH
    const result = compareSeverity(Severity.CRITICAL, Severity.HIGH);

    // Then: Result should be negative (CRITICAL comes first)
    expect(result).toBeLessThan(0);
  });

  it("should return positive when first severity is less severe", () => {
    // Given: LOW and HIGH severities
    // When: Comparing LOW to HIGH
    const result = compareSeverity(Severity.LOW, Severity.HIGH);

    // Then: Result should be positive (LOW comes after)
    expect(result).toBeGreaterThan(0);
  });

  it("should return zero for equal severities", () => {
    // Given: Two MEDIUM severities
    // When: Comparing them
    const result = compareSeverity(Severity.MEDIUM, Severity.MEDIUM);

    // Then: Result should be zero
    expect(result).toBe(0);
  });
});

// ============================================================================
// sortBySeverity Tests
// ============================================================================

describe("sortBySeverity", () => {
  it("should sort findings from most to least severe", () => {
    // Given: Findings in random order
    const findings = [
      createFinding(Severity.LOW),
      createFinding(Severity.CRITICAL),
      createFinding(Severity.MEDIUM),
      createFinding(Severity.HIGH),
      createFinding(Severity.INFORMATIONAL),
    ];

    // When: Sorting by severity
    const sorted = sortBySeverity(findings);

    // Then: Order should be CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
    expect(sorted[0]!.severity).toBe(Severity.CRITICAL);
    expect(sorted[1]!.severity).toBe(Severity.HIGH);
    expect(sorted[2]!.severity).toBe(Severity.MEDIUM);
    expect(sorted[3]!.severity).toBe(Severity.LOW);
    expect(sorted[4]!.severity).toBe(Severity.INFORMATIONAL);
  });

  it("should not mutate the original array", () => {
    // Given: Original findings array
    const original = [createFinding(Severity.LOW), createFinding(Severity.CRITICAL)];
    const originalFirst = original[0];

    // When: Sorting
    const sorted = sortBySeverity(original);

    // Then: Original should be unchanged
    expect(original[0]).toBe(originalFirst);
    expect(sorted).not.toBe(original);
  });

  it("should handle empty array", () => {
    // Given: Empty array
    // When: Sorting
    const sorted = sortBySeverity([]);

    // Then: Should return empty array
    expect(sorted).toEqual([]);
  });

  it("should handle single item", () => {
    // Given: Single finding
    const findings = [createFinding(Severity.HIGH)];

    // When: Sorting
    const sorted = sortBySeverity(findings);

    // Then: Should return array with single item
    expect(sorted.length).toBe(1);
    expect(sorted[0]!.severity).toBe(Severity.HIGH);
  });
});

// ============================================================================
// getSeverityEmoji Tests
// ============================================================================

describe("getSeverityEmoji", () => {
  it("should return red circle for CRITICAL", () => {
    // Given: CRITICAL severity
    // When: Getting emoji
    const emoji = getSeverityEmoji(Severity.CRITICAL);

    // Then: Should be red circle
    expect(emoji).toBe("🔴");
  });

  it("should return orange circle for HIGH", () => {
    // Given: HIGH severity
    // When: Getting emoji
    const emoji = getSeverityEmoji(Severity.HIGH);

    // Then: Should be orange circle
    expect(emoji).toBe("🟠");
  });

  it("should return yellow circle for MEDIUM", () => {
    // Given: MEDIUM severity
    // When: Getting emoji
    const emoji = getSeverityEmoji(Severity.MEDIUM);

    // Then: Should be yellow circle
    expect(emoji).toBe("🟡");
  });

  it("should return green circle for LOW", () => {
    // Given: LOW severity
    // When: Getting emoji
    const emoji = getSeverityEmoji(Severity.LOW);

    // Then: Should be green circle
    expect(emoji).toBe("🟢");
  });

  it("should return blue circle for INFORMATIONAL", () => {
    // Given: INFORMATIONAL severity
    // When: Getting emoji
    const emoji = getSeverityEmoji(Severity.INFORMATIONAL);

    // Then: Should be blue circle
    expect(emoji).toBe("🔵");
  });
});

// ============================================================================
// countBySeverity Tests
// ============================================================================

describe("countBySeverity", () => {
  it("should count findings by severity level", () => {
    // Given: Mixed severity findings
    const findings = [
      createFinding(Severity.CRITICAL),
      createFinding(Severity.CRITICAL),
      createFinding(Severity.HIGH),
      createFinding(Severity.MEDIUM),
      createFinding(Severity.MEDIUM),
      createFinding(Severity.MEDIUM),
      createFinding(Severity.LOW),
      createFinding(Severity.INFORMATIONAL),
    ];

    // When: Counting by severity
    const counts = countBySeverity(findings);

    // Then: Counts should be correct
    expect(counts.total).toBe(8);
    expect(counts.critical).toBe(2);
    expect(counts.high).toBe(1);
    expect(counts.medium).toBe(3);
    expect(counts.low).toBe(1);
    expect(counts.informational).toBe(1);
  });

  it("should return zeros for empty array", () => {
    // Given: Empty array
    // When: Counting
    const counts = countBySeverity([]);

    // Then: All counts should be zero
    expect(counts.total).toBe(0);
    expect(counts.critical).toBe(0);
    expect(counts.high).toBe(0);
    expect(counts.medium).toBe(0);
    expect(counts.low).toBe(0);
    expect(counts.informational).toBe(0);
  });

  it("should handle single severity type", () => {
    // Given: Only HIGH findings
    const findings = [
      createFinding(Severity.HIGH),
      createFinding(Severity.HIGH),
      createFinding(Severity.HIGH),
    ];

    // When: Counting
    const counts = countBySeverity(findings);

    // Then: Only HIGH should have count
    expect(counts.total).toBe(3);
    expect(counts.high).toBe(3);
    expect(counts.critical).toBe(0);
    expect(counts.medium).toBe(0);
  });
});

// ============================================================================
// estimateGasSavings Tests
// ============================================================================

describe("estimateGasSavings", () => {
  it("should return highest estimate for CRITICAL", () => {
    // Given: CRITICAL severity
    // When: Estimating gas savings
    const estimate = estimateGasSavings(Severity.CRITICAL);

    // Then: Should return 5000
    expect(estimate).toBe(5000);
  });

  it("should return estimates in descending order by severity", () => {
    // Given: All severities
    // When: Getting estimates
    const critical = estimateGasSavings(Severity.CRITICAL);
    const high = estimateGasSavings(Severity.HIGH);
    const medium = estimateGasSavings(Severity.MEDIUM);
    const low = estimateGasSavings(Severity.LOW);
    const info = estimateGasSavings(Severity.INFORMATIONAL);

    // Then: Should be in descending order
    expect(critical).toBeGreaterThan(high);
    expect(high).toBeGreaterThan(medium);
    expect(medium).toBeGreaterThan(low);
    expect(low).toBeGreaterThan(info);
  });
});

// ============================================================================
// extractGasSavings Tests
// ============================================================================

describe("extractGasSavings", () => {
  it("should extract single gas value from description", () => {
    // Given: Description with gas savings
    const description = "Use calldata instead of memory. Saves ~200 gas per call.";

    // When: Extracting
    const savings = extractGasSavings(description);

    // Then: Should extract 200
    expect(savings).toBe(200);
  });

  it("should extract range and return average", () => {
    // Given: Description with gas range
    const description = "Optimization can save 100-300 gas.";

    // When: Extracting
    const savings = extractGasSavings(description);

    // Then: Should return average (200)
    expect(savings).toBe(200);
  });

  it("should return 0 when no gas mentioned", () => {
    // Given: Description without gas
    const description = "This is a security issue.";

    // When: Extracting
    const savings = extractGasSavings(description);

    // Then: Should return 0
    expect(savings).toBe(0);
  });

  it("should handle case insensitive gas keyword", () => {
    // Given: Description with uppercase GAS
    const description = "Saves approximately 500 GAS";

    // When: Extracting
    const savings = extractGasSavings(description);

    // Then: Should extract 500
    expect(savings).toBe(500);
  });
});

// ============================================================================
// formatGasSavings Tests
// ============================================================================

describe("formatGasSavings", () => {
  it("should format millions with M suffix", () => {
    // Given: 1.5 million gas
    // When: Formatting
    const formatted = formatGasSavings(1_500_000);

    // Then: Should be "1.5M"
    expect(formatted).toBe("1.5M");
  });

  it("should format thousands with K suffix", () => {
    // Given: 25 thousand gas
    // When: Formatting
    const formatted = formatGasSavings(25_000);

    // Then: Should be "25.0K"
    expect(formatted).toBe("25.0K");
  });

  it("should format small numbers without suffix", () => {
    // Given: 500 gas
    // When: Formatting
    const formatted = formatGasSavings(500);

    // Then: Should be "500"
    expect(formatted).toBe("500");
  });

  it("should handle zero", () => {
    // Given: 0 gas
    // When: Formatting
    const formatted = formatGasSavings(0);

    // Then: Should be "0"
    expect(formatted).toBe("0");
  });
});

// ============================================================================
// calculateTotalGasSavings Tests
// ============================================================================

describe("calculateTotalGasSavings", () => {
  it("should sum gas savings from all findings", () => {
    // Given: Findings with gas in descriptions
    const findings = [
      createFinding(Severity.MEDIUM, "Saves ~200 gas"),
      createFinding(Severity.LOW, "Saves ~100 gas"),
      createFinding(Severity.INFORMATIONAL, "Saves ~50 gas"),
    ];

    // When: Calculating total
    const total = calculateTotalGasSavings(findings);

    // Then: Should be sum of all (350)
    expect(total).toBe(350);
  });

  it("should return 0 for findings without gas mentions", () => {
    // Given: Findings without gas info
    const findings = [
      createFinding(Severity.HIGH, "Security issue"),
      createFinding(Severity.MEDIUM, "Another issue"),
    ];

    // When: Calculating total
    const total = calculateTotalGasSavings(findings);

    // Then: Should be 0
    expect(total).toBe(0);
  });

  it("should handle empty array", () => {
    // Given: Empty array
    // When: Calculating total
    const total = calculateTotalGasSavings([]);

    // Then: Should be 0
    expect(total).toBe(0);
  });
});
