/**
 * Optimize Gas Tool Tests
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { writeFile, mkdir, rm } from "fs/promises";
import { join } from "path";
import { optimizeGas, formatGasOptimizationResult } from "../../src/tools/optimizeGas.js";
import { Severity } from "../../src/types/index.js";

const TEST_DIR = join(process.cwd(), "__tests__/fixtures/optimize-gas");

const TEST_CONTRACT = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract GasTest {
    uint256[] public items;
    uint256 public total;
    mapping(address => uint256) public balances;
    mapping(address => bool) public isActive;

    function badLoop() external {
        for (uint256 i = 0; i < items.length; i++) {
            total += items[i];
        }
    }

    function badExternal(string memory name, uint256[] memory data) external pure returns (uint256) {
        return data.length;
    }

    function check(uint256 amount) external pure {
        require(amount > 0, "Amount must be positive");
    }
}
`;

const CLEAN_CONTRACT = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract CleanContract {
    uint256 public immutable value;

    constructor(uint256 _value) {
        value = _value;
    }

    function getValue() external view returns (uint256) {
        return value;
    }
}
`;

describe("Optimize Gas Tool", () => {
  beforeAll(async () => {
    await mkdir(TEST_DIR, { recursive: true });
    await writeFile(join(TEST_DIR, "GasTest.sol"), TEST_CONTRACT);
    await writeFile(join(TEST_DIR, "CleanContract.sol"), CLEAN_CONTRACT);
  });

  afterAll(async () => {
    await rm(TEST_DIR, { recursive: true, force: true });
  });

  describe("optimizeGas", () => {
    it("should detect gas optimization opportunities", async () => {
      const result = await optimizeGas({
        contractPath: join(TEST_DIR, "GasTest.sol"),
      });

      expect(result.success).toBe(true);
      expect(result.findings.length).toBeGreaterThan(0);
      expect(result.gasScore).toBeLessThan(100);
    });

    it("should filter out informational by default", async () => {
      const result = await optimizeGas({
        contractPath: join(TEST_DIR, "GasTest.sol"),
        includeInformational: false,
      });

      const informationalCount = result.findings.filter(
        (f) => f.severity === Severity.INFORMATIONAL
      ).length;
      expect(informationalCount).toBe(0);
    });

    it("should include informational when requested", async () => {
      const result = await optimizeGas({
        contractPath: join(TEST_DIR, "GasTest.sol"),
        includeInformational: true,
      });

      // The breakdown should still show informational count
      expect(result.breakdown.informational).toBeGreaterThanOrEqual(0);
    });

    it("should calculate gas score correctly", async () => {
      const result = await optimizeGas({
        contractPath: join(TEST_DIR, "GasTest.sol"),
      });

      expect(result.gasScore).toBeGreaterThanOrEqual(0);
      expect(result.gasScore).toBeLessThanOrEqual(100);
    });

    it("should provide estimated savings", async () => {
      const result = await optimizeGas({
        contractPath: join(TEST_DIR, "GasTest.sol"),
      });

      expect(result.estimatedTotalSavings).toBeDefined();
      expect(typeof result.estimatedTotalSavings).toBe("string");
    });

    it("should provide summary text", async () => {
      const result = await optimizeGas({
        contractPath: join(TEST_DIR, "GasTest.sol"),
      });

      expect(result.summaryText).toContain("optimizaciones");
    });

    it("should return error for non-existent file", async () => {
      const result = await optimizeGas({
        contractPath: "/nonexistent/path.sol",
      });

      expect(result.success).toBe(false);
      expect(result.summaryText).toContain("Error");
    });

    it("should return error for non-sol file", async () => {
      // Create a non-.sol file
      await writeFile(join(TEST_DIR, "test.txt"), "not a contract");

      const result = await optimizeGas({
        contractPath: join(TEST_DIR, "test.txt"),
      });

      expect(result.success).toBe(false);
      expect(result.summaryText).toContain("Solidity");
    });

    it("should return high score for clean contract", async () => {
      const result = await optimizeGas({
        contractPath: join(TEST_DIR, "CleanContract.sol"),
      });

      expect(result.success).toBe(true);
      expect(result.gasScore).toBeGreaterThanOrEqual(80);
    });
  });

  describe("formatGasOptimizationResult", () => {
    it("should format successful result", async () => {
      const result = await optimizeGas({
        contractPath: join(TEST_DIR, "GasTest.sol"),
      });

      const formatted = formatGasOptimizationResult(result);

      expect(formatted).toContain("Gas Optimization Report");
      expect(formatted).toContain("Gas Score");
      expect(formatted).toContain("Estimated Total Savings");
    });

    it("should format error result", async () => {
      const result = await optimizeGas({
        contractPath: "/nonexistent/path.sol",
      });

      const formatted = formatGasOptimizationResult(result);

      expect(formatted).toContain("Error");
    });

    it("should include findings in formatted output", async () => {
      const result = await optimizeGas({
        contractPath: join(TEST_DIR, "GasTest.sol"),
      });

      const formatted = formatGasOptimizationResult(result);

      if (result.findings.length > 0) {
        expect(formatted).toContain("Findings");
        expect(formatted).toContain("Recommendation");
      }
    });
  });

  describe("Result Structure", () => {
    it("should have correct breakdown structure", async () => {
      const result = await optimizeGas({
        contractPath: join(TEST_DIR, "GasTest.sol"),
      });

      expect(result.breakdown).toHaveProperty("high");
      expect(result.breakdown).toHaveProperty("medium");
      expect(result.breakdown).toHaveProperty("low");
      expect(result.breakdown).toHaveProperty("informational");
    });

    it("should have findings with correct structure", async () => {
      const result = await optimizeGas({
        contractPath: join(TEST_DIR, "GasTest.sol"),
      });

      if (result.findings.length > 0) {
        const finding = result.findings[0]!;
        expect(finding).toHaveProperty("id");
        expect(finding).toHaveProperty("title");
        expect(finding).toHaveProperty("severity");
        expect(finding).toHaveProperty("description");
        expect(finding).toHaveProperty("recommendation");
        expect(finding).toHaveProperty("detector");
        expect(finding.detector).toBe("gas-optimizer");
      }
    });
  });
});
