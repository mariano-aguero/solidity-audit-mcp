/**
 * Analyze Contract Tool Tests
 *
 * Tests for the analyze contract tool.
 * These focus on testing pure functions and basic behavior.
 * Full integration tests would require Slither/Aderyn to be installed.
 */

import { describe, it, expect } from "vitest";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";
import { readFile } from "fs/promises";
import { Severity, type Finding } from "../../src/types/index.js";
import { parseContractInfo, detectPatterns } from "../../src/analyzers/adapters/SlangAdapter.js";
import { deduplicateFindings } from "../../src/analyzers/adapters/AderynAdapter.js";

// ESM equivalent of __dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Path to fixtures
const FIXTURES_DIR = resolve(__dirname, "../fixtures");
const VULNERABLE_CONTRACT = resolve(FIXTURES_DIR, "VulnerableContract.sol");
const SAFE_CONTRACT = resolve(FIXTURES_DIR, "SafeContract.sol");
const PROXY_CONTRACT = resolve(FIXTURES_DIR, "ProxyContract.sol");

describe("Analyze Contract Tool", () => {
  describe("Contract Parsing", () => {
    it("should parse VulnerableContract successfully", async () => {
      const info = await parseContractInfo(VULNERABLE_CONTRACT);

      expect(info.name).toBe("VulnerableContract");
      expect(info.compiler).toContain("0.8.20");
      expect(info.functions.length).toBeGreaterThan(0);
      expect(info.stateVariables.length).toBeGreaterThan(0);
    });

    it("should parse SafeContract successfully", async () => {
      const info = await parseContractInfo(SAFE_CONTRACT);

      expect(info.name).toBe("SafeContract");
      expect(info.inherits).toContain("ReentrancyGuard");
      expect(info.inherits).toContain("Ownable");
    });

    it("should detect proxy pattern in ProxyContract", async () => {
      const info = await parseContractInfo(PROXY_CONTRACT);

      expect(info.usesProxy).toBe(true);
    });
  });

  describe("Pattern Detection", () => {
    it("should detect more high-risk patterns in VulnerableContract", async () => {
      const vulnerableSource = await readFile(VULNERABLE_CONTRACT, "utf-8");
      const safeSource = await readFile(SAFE_CONTRACT, "utf-8");

      const vulnerablePatterns = detectPatterns(vulnerableSource);
      const safePatterns = detectPatterns(safeSource);

      const vulnerableHighRisk = vulnerablePatterns.filter((p) => p.risk === "high");
      const safeHighRisk = safePatterns.filter((p) => p.risk === "high");

      expect(vulnerableHighRisk.length).toBeGreaterThan(safeHighRisk.length);
    });

    it("should detect tx.origin in VulnerableContract", async () => {
      const source = await readFile(VULNERABLE_CONTRACT, "utf-8");
      const patterns = detectPatterns(source);

      const txOriginPatterns = patterns.filter((p) => p.pattern === "tx.origin");
      expect(txOriginPatterns.length).toBeGreaterThan(0);
    });

    it("should detect selfdestruct in VulnerableContract", async () => {
      const source = await readFile(VULNERABLE_CONTRACT, "utf-8");
      const patterns = detectPatterns(source);

      const selfdestructPatterns = patterns.filter((p) => p.pattern === "selfdestruct");
      expect(selfdestructPatterns.length).toBeGreaterThan(0);
    });

    it("should detect delegatecall in VulnerableContract", async () => {
      const source = await readFile(VULNERABLE_CONTRACT, "utf-8");
      const patterns = detectPatterns(source);

      const delegatecallPatterns = patterns.filter((p) => p.pattern === "delegatecall");
      expect(delegatecallPatterns.length).toBeGreaterThan(0);
    });

    it("should not detect tx.origin in SafeContract", async () => {
      const source = await readFile(SAFE_CONTRACT, "utf-8");
      const patterns = detectPatterns(source);

      const txOriginPatterns = patterns.filter((p) => p.pattern === "tx.origin");
      expect(txOriginPatterns.length).toBe(0);
    });
  });

  describe("Finding Deduplication", () => {
    it("should deduplicate findings from slither and aderyn", () => {
      const slitherFindings: Finding[] = [
        {
          id: "SL-1",
          title: "Reentrancy Vulnerability",
          severity: Severity.HIGH,
          description: "Reentrancy in withdraw",
          location: { file: "Contract.sol", lines: [50, 55] },
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
          description: "State change after call",
          location: { file: "Contract.sol", lines: [50, 52] },
          recommendation: "Fix reentrancy",
          detector: "aderyn",
          confidence: "high",
        },
      ];

      const result = deduplicateFindings(slitherFindings, aderynFindings);

      expect(result).toHaveLength(1);
      expect(result[0]?.description).toContain("Detected by both");
    });

    it("should keep unique findings from both sources", () => {
      const slitherFindings: Finding[] = [
        {
          id: "SL-1",
          title: "Issue A",
          severity: Severity.HIGH,
          description: "Slither issue",
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
          description: "Aderyn issue",
          location: { file: "B.sol", lines: [20, 20] },
          recommendation: "Fix B",
          detector: "aderyn",
          confidence: "medium",
        },
      ];

      const result = deduplicateFindings(slitherFindings, aderynFindings);

      expect(result).toHaveLength(2);
    });
  });

  describe("Severity Ordering", () => {
    it("should sort findings correctly by severity", () => {
      const findings: Finding[] = [
        {
          id: "1",
          title: "Low Issue",
          severity: Severity.LOW,
          description: "Low",
          location: { file: "C.sol" },
          recommendation: "Fix",
          detector: "slither",
          confidence: "high",
        },
        {
          id: "2",
          title: "Critical Issue",
          severity: Severity.CRITICAL,
          description: "Critical",
          location: { file: "C.sol" },
          recommendation: "Fix now",
          detector: "slither",
          confidence: "high",
        },
        {
          id: "3",
          title: "Medium Issue",
          severity: Severity.MEDIUM,
          description: "Medium",
          location: { file: "C.sol" },
          recommendation: "Fix",
          detector: "aderyn",
          confidence: "medium",
        },
        {
          id: "4",
          title: "High Issue",
          severity: Severity.HIGH,
          description: "High",
          location: { file: "C.sol" },
          recommendation: "Fix soon",
          detector: "slither",
          confidence: "high",
        },
        {
          id: "5",
          title: "Info Issue",
          severity: Severity.INFORMATIONAL,
          description: "Info",
          location: { file: "C.sol" },
          recommendation: "Consider",
          detector: "aderyn",
          confidence: "low",
        },
      ];

      // Sort like analyzeContract does
      const severityOrder: Record<Severity, number> = {
        [Severity.CRITICAL]: 0,
        [Severity.HIGH]: 1,
        [Severity.MEDIUM]: 2,
        [Severity.LOW]: 3,
        [Severity.INFORMATIONAL]: 4,
      };

      const sorted = [...findings].sort(
        (a, b) => severityOrder[a.severity] - severityOrder[b.severity]
      );

      expect(sorted[0]?.severity).toBe(Severity.CRITICAL);
      expect(sorted[1]?.severity).toBe(Severity.HIGH);
      expect(sorted[2]?.severity).toBe(Severity.MEDIUM);
      expect(sorted[3]?.severity).toBe(Severity.LOW);
      expect(sorted[4]?.severity).toBe(Severity.INFORMATIONAL);
    });
  });

  describe("Summary Calculation", () => {
    it("should calculate summary counts correctly", () => {
      const findings: Finding[] = [
        {
          id: "1",
          title: "Critical 1",
          severity: Severity.CRITICAL,
          description: "C1",
          location: { file: "C.sol" },
          recommendation: "Fix",
          detector: "slither",
          confidence: "high",
        },
        {
          id: "2",
          title: "Critical 2",
          severity: Severity.CRITICAL,
          description: "C2",
          location: { file: "C.sol" },
          recommendation: "Fix",
          detector: "slither",
          confidence: "high",
        },
        {
          id: "3",
          title: "High 1",
          severity: Severity.HIGH,
          description: "H1",
          location: { file: "C.sol" },
          recommendation: "Fix",
          detector: "aderyn",
          confidence: "high",
        },
        {
          id: "4",
          title: "Medium 1",
          severity: Severity.MEDIUM,
          description: "M1",
          location: { file: "C.sol" },
          recommendation: "Fix",
          detector: "slither",
          confidence: "medium",
        },
        {
          id: "5",
          title: "Low 1",
          severity: Severity.LOW,
          description: "L1",
          location: { file: "C.sol" },
          recommendation: "Fix",
          detector: "aderyn",
          confidence: "low",
        },
        {
          id: "6",
          title: "Low 2",
          severity: Severity.LOW,
          description: "L2",
          location: { file: "C.sol" },
          recommendation: "Fix",
          detector: "slither",
          confidence: "low",
        },
        {
          id: "7",
          title: "Info 1",
          severity: Severity.INFORMATIONAL,
          description: "I1",
          location: { file: "C.sol" },
          recommendation: "Consider",
          detector: "aderyn",
          confidence: "low",
        },
      ];

      // Calculate summary like analyzeContract does
      const summary = {
        total: findings.length,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        informational: 0,
      };

      for (const finding of findings) {
        switch (finding.severity) {
          case Severity.CRITICAL:
            summary.critical++;
            break;
          case Severity.HIGH:
            summary.high++;
            break;
          case Severity.MEDIUM:
            summary.medium++;
            break;
          case Severity.LOW:
            summary.low++;
            break;
          case Severity.INFORMATIONAL:
            summary.informational++;
            break;
        }
      }

      expect(summary.total).toBe(7);
      expect(summary.critical).toBe(2);
      expect(summary.high).toBe(1);
      expect(summary.medium).toBe(1);
      expect(summary.low).toBe(2);
      expect(summary.informational).toBe(1);
    });
  });

  describe("Contract Info Extraction", () => {
    it("should extract function visibility correctly", async () => {
      const info = await parseContractInfo(VULNERABLE_CONTRACT);

      const publicFns = info.functions.filter((f) => f.visibility === "public");
      const externalFns = info.functions.filter((f) => f.visibility === "external");

      expect(publicFns.length).toBeGreaterThan(0);
      expect(externalFns.length).toBeGreaterThan(0);
    });

    it("should detect constructor", async () => {
      const vulnInfo = await parseContractInfo(VULNERABLE_CONTRACT);
      const safeInfo = await parseContractInfo(SAFE_CONTRACT);

      expect(vulnInfo.hasConstructor).toBe(true);
      expect(safeInfo.hasConstructor).toBe(true);
    });

    it("should extract events", async () => {
      const info = await parseContractInfo(VULNERABLE_CONTRACT);

      expect(info.events).toContain("Deposit");
      expect(info.events).toContain("Withdrawal");
    });

    it("should extract modifiers", async () => {
      const info = await parseContractInfo(VULNERABLE_CONTRACT);

      expect(info.modifiers).toContain("onlyOwner");
    });

    it("should extract imports", async () => {
      const info = await parseContractInfo(SAFE_CONTRACT);

      expect(info.imports.length).toBeGreaterThan(0);
      expect(info.imports.some((i) => i.includes("ReentrancyGuard"))).toBe(true);
    });

    it("should extract inheritance", async () => {
      const info = await parseContractInfo(SAFE_CONTRACT);

      expect(info.inherits).toContain("ReentrancyGuard");
      expect(info.inherits).toContain("Ownable");
      expect(info.inherits).toContain("Pausable");
    });
  });

  describe("Proxy Detection", () => {
    it("should detect proxy pattern in ProxyContract", async () => {
      const info = await parseContractInfo(PROXY_CONTRACT);

      expect(info.usesProxy).toBe(true);
    });

    it("should detect proxy pattern in VulnerableContract due to delegatecall", async () => {
      const info = await parseContractInfo(VULNERABLE_CONTRACT);

      // VulnerableContract uses delegatecall, so proxy detection triggers
      expect(info.usesProxy).toBe(true);
    });

    it("should not detect proxy in SafeContract", async () => {
      const info = await parseContractInfo(SAFE_CONTRACT);

      expect(info.usesProxy).toBe(false);
    });

    it("should parse first contract in ProxyContract file", async () => {
      const info = await parseContractInfo(PROXY_CONTRACT);

      // Note: Parser returns the FIRST contract declaration in the file
      // For ProxyContract.sol, that's the abstract Initializable contract
      expect(info.name).toBe("Initializable");

      // But proxy detection still works because it scans the whole source
      expect(info.usesProxy).toBe(true);
    });
  });
});
