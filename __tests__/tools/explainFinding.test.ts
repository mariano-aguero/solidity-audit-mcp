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
      const ids = [
        "SWC-107",
        "SWC-115",
        "SWC-101",
        "SWC-103",
        "SWC-104",
        "SWC-116",
        "SWC-112",
        "CUSTOM-018",
        "CUSTOM-004",
        "CUSTOM-032",
        "CUSTOM-001",
        "CUSTOM-005",
        "CUSTOM-006",
        "CUSTOM-011",
        "CUSTOM-013",
        "CUSTOM-015",
        "CUSTOM-016",
        "CUSTOM-017",
        "CUSTOM-029",
      ];

      for (const id of ids) {
        const result = await explainFinding({ findingId: id });
        expect(typeof result).toBe("string");
        expect(result.length).toBeGreaterThan(0);
      }
    });
  });

  describe("New SWC entries", () => {
    it("should return detailed explanation for SWC-101", async () => {
      const result = await explainFinding({ findingId: "SWC-101" });

      expect(result).toContain("SWC-101");
      expect(result.toLowerCase()).toMatch(/overflow|underflow/);
    });

    it("should return detailed explanation for SWC-103", async () => {
      const result = await explainFinding({ findingId: "SWC-103" });

      expect(result).toContain("SWC-103");
      expect(result.toLowerCase()).toContain("pragma");
    });

    it("should return detailed explanation for SWC-104", async () => {
      const result = await explainFinding({ findingId: "SWC-104" });

      expect(result).toContain("SWC-104");
      expect(result.toLowerCase()).toMatch(/return value|transfer/);
    });

    it("should return detailed explanation for SWC-116", async () => {
      const result = await explainFinding({ findingId: "SWC-116" });

      expect(result).toContain("SWC-116");
      expect(result.toLowerCase()).toContain("timestamp");
    });

    it("should return detailed explanation for SWC-112", async () => {
      const result = await explainFinding({ findingId: "SWC-112" });

      expect(result).toContain("SWC-112");
      expect(result.toLowerCase()).toContain("delegatecall");
    });
  });

  describe("New CUSTOM entries", () => {
    it("should return detailed explanation for CUSTOM-001", async () => {
      const result = await explainFinding({ findingId: "CUSTOM-001" });

      expect(result).toContain("CUSTOM-001");
      expect(result.toLowerCase()).toMatch(/array|length/);
    });

    it("should return detailed explanation for CUSTOM-005", async () => {
      const result = await explainFinding({ findingId: "CUSTOM-005" });

      expect(result).toContain("CUSTOM-005");
      expect(result.toLowerCase()).toMatch(/zero address|address\(0\)/);
    });

    it("should return detailed explanation for CUSTOM-006", async () => {
      const result = await explainFinding({ findingId: "CUSTOM-006" });

      expect(result).toContain("CUSTOM-006");
      expect(result.toLowerCase()).toContain("event");
    });

    it("should return detailed explanation for CUSTOM-011", async () => {
      const result = await explainFinding({ findingId: "CUSTOM-011" });

      expect(result).toContain("CUSTOM-011");
      expect(result.toLowerCase()).toMatch(/replay|nonce|signature/);
    });

    it("should return detailed explanation for CUSTOM-013", async () => {
      const result = await explainFinding({ findingId: "CUSTOM-013" });

      expect(result).toContain("CUSTOM-013");
      expect(result.toLowerCase()).toMatch(/encodepacked|hash collision/);
    });

    it("should return detailed explanation for CUSTOM-015", async () => {
      const result = await explainFinding({ findingId: "CUSTOM-015" });

      expect(result).toContain("CUSTOM-015");
      expect(result.toLowerCase()).toMatch(/division|precision/);
    });

    it("should return detailed explanation for CUSTOM-016", async () => {
      const result = await explainFinding({ findingId: "CUSTOM-016" });

      expect(result).toContain("CUSTOM-016");
      expect(result.toLowerCase()).toMatch(/permit|deadline/);
    });

    it("should return detailed explanation for CUSTOM-017", async () => {
      const result = await explainFinding({ findingId: "CUSTOM-017" });

      expect(result).toContain("CUSTOM-017");
      expect(result.toLowerCase()).toMatch(/access control/);
    });

    it("should return detailed explanation for CUSTOM-029", async () => {
      const result = await explainFinding({ findingId: "CUSTOM-029" });

      expect(result).toContain("CUSTOM-029");
      expect(result.toLowerCase()).toMatch(/merkle|airdrop/);
    });
  });

  describe("New keyword matches", () => {
    it("should match 'overflow' to SWC-101", async () => {
      const result = await explainFinding({ findingId: "overflow" });

      expect(result).toContain("SWC-101");
    });

    it("should match 'timestamp' to SWC-116", async () => {
      const result = await explainFinding({ findingId: "timestamp" });

      expect(result).toContain("SWC-116");
    });

    it("should match 'delegatecall' to SWC-112", async () => {
      const result = await explainFinding({ findingId: "delegatecall" });

      expect(result).toContain("SWC-112");
    });

    it("should match 'array length' to CUSTOM-001", async () => {
      const result = await explainFinding({ findingId: "array length" });

      expect(result).toContain("CUSTOM-001");
    });

    it("should match 'zero address' to CUSTOM-005", async () => {
      const result = await explainFinding({ findingId: "zero address" });

      expect(result).toContain("CUSTOM-005");
    });

    it("should match 'replay' to CUSTOM-011", async () => {
      const result = await explainFinding({ findingId: "replay" });

      expect(result).toContain("CUSTOM-011");
    });

    it("should match 'merkle' to CUSTOM-029", async () => {
      const result = await explainFinding({ findingId: "merkle" });

      expect(result).toContain("CUSTOM-029");
    });

    it("should match 'access control' to CUSTOM-017", async () => {
      const result = await explainFinding({ findingId: "access control" });

      expect(result).toContain("CUSTOM-017");
    });

    it("should match 'permit' to CUSTOM-016", async () => {
      const result = await explainFinding({ findingId: "permit" });

      expect(result).toContain("CUSTOM-016");
    });

    it("should match 'precision loss' to CUSTOM-015", async () => {
      const result = await explainFinding({ findingId: "precision loss" });

      expect(result).toContain("CUSTOM-015");
    });

    it("should match 'hash collision' to CUSTOM-013", async () => {
      const result = await explainFinding({ findingId: "hash collision" });

      expect(result).toContain("CUSTOM-013");
    });

    it("should match 'airdrop' to CUSTOM-029", async () => {
      const result = await explainFinding({ findingId: "airdrop" });

      expect(result).toContain("CUSTOM-029");
    });
  });
});
