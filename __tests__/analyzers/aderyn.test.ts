/**
 * Aderyn Analyzer Tests
 *
 * Tests for the Aderyn analyzer, focusing on the pure functions.
 * Integration tests with actual aderyn would require the tool to be installed.
 */

import { describe, it, expect } from "vitest";
import { Severity, type Finding } from "../../src/types/index.js";
import { deduplicateFindings } from "../../src/analyzers/adapters/AderynAdapter.js";

describe("Aderyn Analyzer", () => {
  describe("deduplicateFindings", () => {
    it("should merge duplicate findings from slither and aderyn", () => {
      const slitherFindings: Finding[] = [
        {
          id: "SL-123",
          title: "Reentrancy Vulnerability (ETH)",
          severity: Severity.HIGH,
          description: "Reentrancy in withdraw function",
          location: { file: "Contract.sol", lines: [50, 55] },
          recommendation: "Use CEI pattern",
          detector: "slither",
          confidence: "high",
        },
      ];

      const aderynFindings: Finding[] = [
        {
          id: "AD-456",
          title: "Reentrancy Found",
          severity: Severity.HIGH,
          description: "State change after external call",
          location: { file: "Contract.sol", lines: [50, 52] },
          recommendation: "Fix reentrancy",
          detector: "aderyn",
          confidence: "high",
        },
      ];

      const result = deduplicateFindings(slitherFindings, aderynFindings);

      // Should have only 1 finding (merged)
      expect(result).toHaveLength(1);
      expect(result[0]?.description).toContain("Detected by both");
    });

    it("should keep unique findings from both sources", () => {
      const slitherFindings: Finding[] = [
        {
          id: "SL-1",
          title: "Issue A",
          severity: Severity.HIGH,
          description: "Slither only issue",
          location: { file: "A.sol", lines: [10, 10] },
          recommendation: "Fix A",
          detector: "slither",
          confidence: "high",
        },
      ];

      const aderynFindings: Finding[] = [
        {
          id: "AD-1",
          title: "Issue B",
          severity: Severity.MEDIUM,
          description: "Aderyn only issue",
          location: { file: "B.sol", lines: [20, 20] },
          recommendation: "Fix B",
          detector: "aderyn",
          confidence: "medium",
        },
      ];

      const result = deduplicateFindings(slitherFindings, aderynFindings);

      expect(result).toHaveLength(2);
    });

    it("should prefer higher severity when merging", () => {
      const slitherFindings: Finding[] = [
        {
          id: "SL-1",
          title: "Reentrancy Issue",
          severity: Severity.MEDIUM,
          description: "Reentrancy vulnerability detected",
          location: { file: "C.sol", lines: [30, 30] },
          recommendation: "Use CEI pattern",
          detector: "slither",
          confidence: "high",
        },
      ];

      const aderynFindings: Finding[] = [
        {
          id: "AD-1",
          title: "Reentrancy Found",
          severity: Severity.HIGH,
          description: "Reentrancy in function",
          location: { file: "C.sol", lines: [30, 32] },
          recommendation: "Apply checks-effects-interactions",
          detector: "aderyn",
          confidence: "high",
        },
      ];

      const result = deduplicateFindings(slitherFindings, aderynFindings);

      expect(result).toHaveLength(1);
      expect(result[0]?.severity).toBe(Severity.HIGH);
    });

    it("should handle empty arrays", () => {
      expect(deduplicateFindings([], [])).toEqual([]);

      const singleSlither: Finding[] = [
        {
          id: "SL-1",
          title: "Test",
          severity: Severity.LOW,
          description: "Test issue",
          location: { file: "T.sol" },
          recommendation: "Fix",
          detector: "slither",
          confidence: "low",
        },
      ];

      expect(deduplicateFindings(singleSlither, [])).toHaveLength(1);
      expect(
        deduplicateFindings(
          [],
          singleSlither.map((f) => ({ ...f, detector: "aderyn" as const }))
        )
      ).toHaveLength(1);
    });

    it("should not merge findings in different files", () => {
      const slitherFindings: Finding[] = [
        {
          id: "SL-1",
          title: "Reentrancy",
          severity: Severity.HIGH,
          description: "Reentrancy issue",
          location: { file: "ContractA.sol", lines: [50, 55] },
          recommendation: "Fix",
          detector: "slither",
          confidence: "high",
        },
      ];

      const aderynFindings: Finding[] = [
        {
          id: "AD-1",
          title: "Reentrancy",
          severity: Severity.HIGH,
          description: "Reentrancy issue",
          location: { file: "ContractB.sol", lines: [50, 55] },
          recommendation: "Fix",
          detector: "aderyn",
          confidence: "high",
        },
      ];

      const result = deduplicateFindings(slitherFindings, aderynFindings);

      // Different files, should not merge
      expect(result).toHaveLength(2);
    });

    it("should not merge findings with vastly different line numbers", () => {
      const slitherFindings: Finding[] = [
        {
          id: "SL-1",
          title: "Issue",
          severity: Severity.HIGH,
          description: "Some issue",
          location: { file: "C.sol", lines: [10, 15] },
          recommendation: "Fix",
          detector: "slither",
          confidence: "high",
        },
      ];

      const aderynFindings: Finding[] = [
        {
          id: "AD-1",
          title: "Issue",
          severity: Severity.HIGH,
          description: "Different issue at different location",
          location: { file: "C.sol", lines: [100, 105] },
          recommendation: "Fix",
          detector: "aderyn",
          confidence: "high",
        },
      ];

      const result = deduplicateFindings(slitherFindings, aderynFindings);

      // Lines too far apart, should not merge
      expect(result).toHaveLength(2);
    });

    it("should merge findings on adjacent lines", () => {
      const slitherFindings: Finding[] = [
        {
          id: "SL-1",
          title: "Timestamp Issue",
          severity: Severity.MEDIUM,
          description: "block.timestamp usage",
          location: { file: "C.sol", lines: [50, 52] },
          recommendation: "Use buffer",
          detector: "slither",
          confidence: "high",
        },
      ];

      const aderynFindings: Finding[] = [
        {
          id: "AD-1",
          title: "Time Manipulation",
          severity: Severity.MEDIUM,
          description: "Dangerous timestamp dependence",
          location: { file: "C.sol", lines: [53, 55] },
          recommendation: "Avoid timestamp",
          detector: "aderyn",
          confidence: "medium",
        },
      ];

      const result = deduplicateFindings(slitherFindings, aderynFindings);

      // Adjacent lines should merge
      expect(result).toHaveLength(1);
      expect(result[0]?.description).toContain("Detected by both");
    });

    it("should prefer higher confidence when merging", () => {
      const slitherFindings: Finding[] = [
        {
          id: "SL-1",
          title: "Timestamp Dependence",
          severity: Severity.MEDIUM,
          description: "Timestamp manipulation risk",
          location: { file: "C.sol", lines: [30, 30] },
          recommendation: "Use buffer",
          detector: "slither",
          confidence: "low",
        },
      ];

      const aderynFindings: Finding[] = [
        {
          id: "AD-1",
          title: "Timestamp Issue",
          severity: Severity.MEDIUM,
          description: "Timestamp used for comparison",
          location: { file: "C.sol", lines: [30, 32] },
          recommendation: "Avoid timestamp dependence",
          detector: "aderyn",
          confidence: "high",
        },
      ];

      const result = deduplicateFindings(slitherFindings, aderynFindings);

      expect(result).toHaveLength(1);
      expect(result[0]?.confidence).toBe("high");
    });

    it("should use longer recommendation when merging", () => {
      const slitherFindings: Finding[] = [
        {
          id: "SL-1",
          title: "Issue",
          severity: Severity.HIGH,
          description: "Reentrancy",
          location: { file: "C.sol", lines: [30, 30] },
          recommendation: "Fix",
          detector: "slither",
          confidence: "high",
        },
      ];

      const aderynFindings: Finding[] = [
        {
          id: "AD-1",
          title: "Same Issue",
          severity: Severity.HIGH,
          description: "Reentrancy detected",
          location: { file: "C.sol", lines: [30, 32] },
          recommendation:
            "Use the checks-effects-interactions pattern and consider ReentrancyGuard",
          detector: "aderyn",
          confidence: "high",
        },
      ];

      const result = deduplicateFindings(slitherFindings, aderynFindings);

      expect(result).toHaveLength(1);
      expect(result[0]?.recommendation.length).toBeGreaterThan(10);
    });

    it("should combine line ranges when merging", () => {
      const slitherFindings: Finding[] = [
        {
          id: "SL-1",
          title: "Issue",
          severity: Severity.HIGH,
          description: "Reentrancy",
          location: { file: "C.sol", lines: [50, 55] },
          recommendation: "Fix",
          detector: "slither",
          confidence: "high",
        },
      ];

      const aderynFindings: Finding[] = [
        {
          id: "AD-1",
          title: "Same Issue",
          severity: Severity.HIGH,
          description: "Reentrancy detected",
          location: { file: "C.sol", lines: [53, 60] },
          recommendation: "Fix it",
          detector: "aderyn",
          confidence: "high",
        },
      ];

      const result = deduplicateFindings(slitherFindings, aderynFindings);

      expect(result).toHaveLength(1);
      // Should combine ranges: min(50,53) to max(55,60)
      expect(result[0]?.location.lines).toEqual([50, 60]);
    });

    it("should handle findings without line numbers", () => {
      const slitherFindings: Finding[] = [
        {
          id: "SL-1",
          title: "Pragma Issue",
          severity: Severity.LOW,
          description: "Floating pragma",
          location: { file: "C.sol" },
          recommendation: "Lock pragma",
          detector: "slither",
          confidence: "high",
        },
      ];

      const aderynFindings: Finding[] = [
        {
          id: "AD-1",
          title: "Pragma Warning",
          severity: Severity.LOW,
          description: "Pragma not locked",
          location: { file: "C.sol" },
          recommendation: "Lock the pragma version",
          detector: "aderyn",
          confidence: "high",
        },
      ];

      const result = deduplicateFindings(slitherFindings, aderynFindings);

      // Same file, similar issue type (pragma), should merge
      expect(result).toHaveLength(1);
    });

    it("should handle multiple findings of different types", () => {
      const slitherFindings: Finding[] = [
        {
          id: "SL-1",
          title: "Reentrancy",
          severity: Severity.HIGH,
          description: "Reentrancy in withdraw",
          location: { file: "C.sol", lines: [50, 55] },
          recommendation: "CEI pattern",
          detector: "slither",
          confidence: "high",
        },
        {
          id: "SL-2",
          title: "tx.origin",
          severity: Severity.MEDIUM,
          description: "tx.origin used",
          location: { file: "C.sol", lines: [70, 70] },
          recommendation: "Use msg.sender",
          detector: "slither",
          confidence: "high",
        },
      ];

      const aderynFindings: Finding[] = [
        {
          id: "AD-1",
          title: "Reentrancy Detected",
          severity: Severity.HIGH,
          description: "State change after call",
          location: { file: "C.sol", lines: [52, 54] },
          recommendation: "Fix reentrancy",
          detector: "aderyn",
          confidence: "high",
        },
        {
          id: "AD-2",
          title: "Centralization Risk",
          severity: Severity.MEDIUM,
          description: "Single owner can drain",
          location: { file: "C.sol", lines: [100, 105] },
          recommendation: "Use multisig",
          detector: "aderyn",
          confidence: "medium",
        },
      ];

      const result = deduplicateFindings(slitherFindings, aderynFindings);

      // Reentrancy should merge, others should remain separate
      expect(result).toHaveLength(3);

      // Check that reentrancy was merged
      const reentrancyFindings = result.filter(
        (f) =>
          f.title.toLowerCase().includes("reentrancy") ||
          f.description.toLowerCase().includes("reentrancy")
      );
      expect(reentrancyFindings.length).toBe(1);
      expect(reentrancyFindings[0]?.description).toContain("Detected by both");
    });
  });
});
