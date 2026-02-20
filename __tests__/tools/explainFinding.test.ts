/**
 * Explain Finding Tool Tests
 */

import { describe, it, expect } from "vitest";
import { explainFinding } from "../../src/tools/explainFinding.js";

describe("Explain Finding Tool", () => {
  describe("Known finding IDs", () => {
    it("should return detailed explanation for SWC-107", async () => {
      const result = await explainFinding({ findingId: "SWC-107" });

      expect(typeof result).toBe("string");
      expect(result.length).toBeGreaterThan(0);
      expect(result).toContain("SWC-107");
    });

    it("should return detailed explanation for SWC-115", async () => {
      const result = await explainFinding({ findingId: "SWC-115" });

      expect(typeof result).toBe("string");
      expect(result.length).toBeGreaterThan(0);
      expect(result).toContain("SWC-115");
    });

    it("should return detailed explanation for CUSTOM-032", async () => {
      const result = await explainFinding({ findingId: "CUSTOM-032" });

      expect(typeof result).toBe("string");
      expect(result.length).toBeGreaterThan(0);
      expect(result).toContain("CUSTOM-032");
    });

    it("should return detailed explanation for CUSTOM-018", async () => {
      const result = await explainFinding({ findingId: "CUSTOM-018" });

      expect(typeof result).toBe("string");
      expect(result.length).toBeGreaterThan(0);
      expect(result).toContain("CUSTOM-018");
    });

    it("should return detailed explanation for CUSTOM-004", async () => {
      const result = await explainFinding({ findingId: "CUSTOM-004" });

      expect(typeof result).toBe("string");
      expect(result.length).toBeGreaterThan(0);
      expect(result).toContain("CUSTOM-004");
    });
  });

  describe("Output sections for known IDs", () => {
    it("should include Root Cause section", async () => {
      const result = await explainFinding({ findingId: "SWC-107" });

      expect(result).toMatch(/root cause/i);
    });

    it("should include Impact section", async () => {
      const result = await explainFinding({ findingId: "SWC-107" });

      expect(result).toMatch(/impact/i);
    });

    it("should include Exploit Scenario section", async () => {
      const result = await explainFinding({ findingId: "SWC-107" });

      expect(result).toMatch(/exploit scenario/i);
    });

    it("should include Vulnerable Code section", async () => {
      const result = await explainFinding({ findingId: "SWC-107" });

      expect(result).toMatch(/vulnerable code/i);
    });

    it("should include Secure Code section", async () => {
      const result = await explainFinding({ findingId: "SWC-107" });

      expect(result).toMatch(/secure code/i);
    });

    it("should include PoC Template section", async () => {
      const result = await explainFinding({ findingId: "SWC-107" });

      expect(result).toMatch(/proof of concept|poc template/i);
    });

    it("should include Remediation section", async () => {
      const result = await explainFinding({ findingId: "SWC-107" });

      expect(result).toMatch(/remediation/i);
    });

    it("should include References section", async () => {
      const result = await explainFinding({ findingId: "SWC-107" });

      expect(result).toMatch(/references/i);
    });
  });

  describe("Keyword matching", () => {
    it("should return SWC-107 content for 'reentrancy' keyword", async () => {
      const result = await explainFinding({ findingId: "reentrancy" });

      expect(typeof result).toBe("string");
      expect(result.length).toBeGreaterThan(0);
      expect(result).toContain("SWC-107");
    });

    it("should return CUSTOM-004 content for 'flash loan' keyword", async () => {
      const result = await explainFinding({ findingId: "flash loan" });

      expect(typeof result).toBe("string");
      expect(result.length).toBeGreaterThan(0);
      expect(result).toContain("CUSTOM-004");
    });

    it("should return CUSTOM-032 content for 'paymaster' keyword", async () => {
      const result = await explainFinding({ findingId: "paymaster" });

      expect(typeof result).toBe("string");
      expect(result.length).toBeGreaterThan(0);
      expect(result).toContain("CUSTOM-032");
    });

    it("should return SWC-115 content for 'tx.origin' keyword", async () => {
      const result = await explainFinding({ findingId: "tx.origin" });

      expect(typeof result).toBe("string");
      expect(result.length).toBeGreaterThan(0);
      expect(result).toContain("SWC-115");
    });

    it("should return CUSTOM-004 content for 'oracle' keyword", async () => {
      const result = await explainFinding({ findingId: "oracle" });

      expect(typeof result).toBe("string");
      expect(result.length).toBeGreaterThan(0);
      expect(result).toContain("CUSTOM-004");
    });

    it("should return CUSTOM-004 content for 'price manipulation' keyword", async () => {
      const result = await explainFinding({ findingId: "price manipulation" });

      expect(typeof result).toBe("string");
      expect(result.length).toBeGreaterThan(0);
      expect(result).toContain("CUSTOM-004");
    });
  });

  describe("Unknown finding ID", () => {
    it("should return a not-found message for unknown ID", async () => {
      const result = await explainFinding({ findingId: "SWC-999" });

      expect(typeof result).toBe("string");
      expect(result.length).toBeGreaterThan(0);
      expect(result).toMatch(/not found/i);
    });

    it("should include suggestions in not-found message", async () => {
      const result = await explainFinding({ findingId: "UNKNOWN-XYZ" });

      expect(result).toMatch(/swc-107|swc-115|custom-018|custom-004|custom-032/i);
    });

    it("should include keyword search hints in not-found message", async () => {
      const result = await explainFinding({ findingId: "completely-unknown" });

      expect(result).toMatch(/reentrancy|flash loan|oracle|paymaster/i);
    });
  });

  describe("With severity option", () => {
    it("should work with severity 'critical'", async () => {
      const result = await explainFinding({
        findingId: "SWC-107",
        severity: "critical",
      });

      expect(typeof result).toBe("string");
      expect(result.length).toBeGreaterThan(0);
      expect(result).toContain("SWC-107");
    });

    it("should work with severity 'high'", async () => {
      const result = await explainFinding({
        findingId: "SWC-115",
        severity: "high",
      });

      expect(typeof result).toBe("string");
      expect(result.length).toBeGreaterThan(0);
      expect(result).toContain("SWC-115");
    });

    it("should work with severity 'medium'", async () => {
      const result = await explainFinding({
        findingId: "CUSTOM-004",
        severity: "medium",
      });

      expect(typeof result).toBe("string");
      expect(result.length).toBeGreaterThan(0);
    });
  });

  describe("With contractContext option", () => {
    it("should work without errors when contractContext is provided", async () => {
      const result = await explainFinding({
        findingId: "SWC-107",
        contractContext:
          "A lending protocol that allows users to borrow ETH against ERC20 collateral",
      });

      expect(typeof result).toBe("string");
      expect(result.length).toBeGreaterThan(0);
      expect(result).toContain("SWC-107");
    });

    it("should include context in the output when provided", async () => {
      const context = "A staking contract for governance tokens";
      const result = await explainFinding({
        findingId: "SWC-107",
        contractContext: context,
      });

      expect(result).toContain(context);
    });

    it("should work for unknown IDs with contractContext provided", async () => {
      const result = await explainFinding({
        findingId: "SWC-999",
        contractContext: "Some DeFi protocol",
      });

      expect(typeof result).toBe("string");
      expect(result.length).toBeGreaterThan(0);
    });
  });

  describe("Content validation", () => {
    it("output for SWC-107 should mention 'reentrancy' (case-insensitive)", async () => {
      const result = await explainFinding({ findingId: "SWC-107" });

      expect(result.toLowerCase()).toContain("reentrancy");
    });

    it("output for SWC-115 should mention 'tx.origin' (case-insensitive)", async () => {
      const result = await explainFinding({ findingId: "SWC-115" });

      expect(result.toLowerCase()).toContain("tx.origin");
    });

    it("output for CUSTOM-032 should mention 'paymaster' (case-insensitive)", async () => {
      const result = await explainFinding({ findingId: "CUSTOM-032" });

      expect(result.toLowerCase()).toContain("paymaster");
    });

    it("output for CUSTOM-004 should mention 'oracle' or 'flash loan' (case-insensitive)", async () => {
      const result = await explainFinding({ findingId: "CUSTOM-004" });

      expect(result.toLowerCase()).toMatch(/oracle|flash loan/);
    });

    it("output for CUSTOM-018 should mention 'erc-7702' or 'initialize' (case-insensitive)", async () => {
      const result = await explainFinding({ findingId: "CUSTOM-018" });

      expect(result.toLowerCase()).toMatch(/erc-7702|initialize/);
    });

    it("all known finding IDs should return non-empty strings", async () => {
      const ids = ["SWC-107", "SWC-115", "CUSTOM-018", "CUSTOM-004", "CUSTOM-032"];

      for (const id of ids) {
        const result = await explainFinding({ findingId: id });
        expect(typeof result).toBe("string");
        expect(result.length).toBeGreaterThan(0);
      }
    });
  });
});
