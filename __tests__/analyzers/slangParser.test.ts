/**
 * Solidity Parser Tests
 *
 * Tests the regex-based Solidity parser using the fixture contracts.
 */

import { describe, it, expect } from "vitest";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";
import {
  parseContractInfo,
  detectPatterns,
  summarizePatterns,
} from "../../src/analyzers/adapters/SlangAdapter.js";

// ESM equivalent of __dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Path to fixture contracts
const FIXTURES_DIR = resolve(__dirname, "../fixtures");
const VULNERABLE_CONTRACT = resolve(FIXTURES_DIR, "VulnerableContract.sol");
const SAFE_CONTRACT = resolve(FIXTURES_DIR, "SafeContract.sol");
const PROXY_CONTRACT = resolve(FIXTURES_DIR, "ProxyContract.sol");

describe("Solidity Parser", () => {
  describe("parseContractInfo", () => {
    describe("with VulnerableContract", () => {
      it("should extract contract name", async () => {
        const info = await parseContractInfo(VULNERABLE_CONTRACT);

        expect(info.name).toBe("VulnerableContract");
      });

      it("should extract pragma version", async () => {
        const info = await parseContractInfo(VULNERABLE_CONTRACT);

        expect(info.compiler).toMatch(/\^?0\.8\.20/);
      });

      it("should detect public functions", async () => {
        const info = await parseContractInfo(VULNERABLE_CONTRACT);

        const publicFns = info.functions.filter((f) => f.visibility === "public");
        expect(publicFns.length).toBeGreaterThan(0);

        // Should detect the deposit function
        const deposit = info.functions.find((f) => f.name === "deposit");
        expect(deposit).toBeDefined();
      });

      it("should detect external functions", async () => {
        const info = await parseContractInfo(VULNERABLE_CONTRACT);

        const externalFns = info.functions.filter((f) => f.visibility === "external");
        expect(externalFns.length).toBeGreaterThan(0);
      });

      it("should detect state variables", async () => {
        const info = await parseContractInfo(VULNERABLE_CONTRACT);

        expect(info.stateVariables.length).toBeGreaterThan(0);

        // Should detect the owner variable
        const hasOwner = info.stateVariables.some(
          (v) => v.name === "owner" || v.type === "address"
        );
        expect(hasOwner).toBe(true);
      });

      it("should detect events", async () => {
        const info = await parseContractInfo(VULNERABLE_CONTRACT);

        expect(info.events.length).toBeGreaterThan(0);
        expect(info.events).toContain("Deposit");
        expect(info.events).toContain("Withdrawal");
      });

      it("should detect modifiers", async () => {
        const info = await parseContractInfo(VULNERABLE_CONTRACT);

        expect(info.modifiers.length).toBeGreaterThan(0);
        expect(info.modifiers).toContain("onlyOwner");
      });

      it("should detect constructor", async () => {
        const info = await parseContractInfo(VULNERABLE_CONTRACT);

        expect(info.hasConstructor).toBe(true);
      });

      it("should detect proxy pattern due to delegatecall usage", async () => {
        const info = await parseContractInfo(VULNERABLE_CONTRACT);

        // VulnerableContract uses delegatecall, so usesProxy is true
        expect(info.usesProxy).toBe(true);
      });
    });

    describe("with SafeContract", () => {
      it("should extract contract name", async () => {
        const info = await parseContractInfo(SAFE_CONTRACT);

        expect(info.name).toBe("SafeContract");
      });

      it("should extract inheritance", async () => {
        const info = await parseContractInfo(SAFE_CONTRACT);

        expect(info.inherits.length).toBeGreaterThan(0);
        expect(info.inherits).toContain("ReentrancyGuard");
        expect(info.inherits).toContain("Ownable");
        expect(info.inherits).toContain("Pausable");
      });

      it("should extract imports", async () => {
        const info = await parseContractInfo(SAFE_CONTRACT);

        expect(info.imports.length).toBeGreaterThan(0);
        expect(info.imports.some((i) => i.includes("ReentrancyGuard"))).toBe(true);
        expect(info.imports.some((i) => i.includes("Ownable"))).toBe(true);
      });

      it("should detect custom errors", async () => {
        const info = await parseContractInfo(SAFE_CONTRACT);

        expect(info.errors.length).toBeGreaterThan(0);
        expect(info.errors).toContain("ZeroAddress");
        expect(info.errors).toContain("InsufficientBalance");
      });

      it("should detect external visibility correctly", async () => {
        const info = await parseContractInfo(SAFE_CONTRACT);

        const externalFns = info.functions.filter((f) => f.visibility === "external");
        expect(externalFns.length).toBeGreaterThan(0);

        // pause should be external
        const pause = info.functions.find((f) => f.name === "pause");
        expect(pause?.visibility).toBe("external");
      });
    });

    describe("with ProxyContract", () => {
      it("should detect proxy pattern from inheritance", async () => {
        const info = await parseContractInfo(PROXY_CONTRACT);

        // The contract inherits from Initializable
        expect(info.usesProxy).toBe(true);
      });

      it("should detect delegatecall usage", async () => {
        const info = await parseContractInfo(PROXY_CONTRACT);

        // ProxyContract uses delegatecall
        expect(info.usesProxy).toBe(true);
      });

      it("should parse the first contract in file (Initializable)", async () => {
        const info = await parseContractInfo(PROXY_CONTRACT);

        // Note: Parser returns the FIRST contract declaration in the file
        // For ProxyContract.sol, that's the abstract Initializable contract
        expect(info.name).toBe("Initializable");

        // Should detect internal functions from Initializable
        const getInitialized = info.functions.find((f) => f.name === "_getInitialized");
        expect(getInitialized).toBeDefined();
        expect(getInitialized?.visibility).toBe("internal");
      });

      it("should detect storage slot constants", async () => {
        const info = await parseContractInfo(PROXY_CONTRACT);

        // Should have state variables for slots
        expect(info.stateVariables.length).toBeGreaterThan(0);
      });
    });
  });

  describe("detectPatterns", () => {
    it("should detect tx.origin usage in VulnerableContract", async () => {
      const { readFile } = await import("fs/promises");
      const source = await readFile(VULNERABLE_CONTRACT, "utf-8");
      const patterns = detectPatterns(source);

      const txOriginPatterns = patterns.filter((p) => p.pattern === "tx.origin");
      expect(txOriginPatterns.length).toBeGreaterThan(0);
      expect(txOriginPatterns[0]?.risk).toBe("high");
    });

    it("should detect selfdestruct in VulnerableContract", async () => {
      const { readFile } = await import("fs/promises");
      const source = await readFile(VULNERABLE_CONTRACT, "utf-8");
      const patterns = detectPatterns(source);

      const selfdestructPatterns = patterns.filter((p) => p.pattern === "selfdestruct");
      expect(selfdestructPatterns.length).toBeGreaterThan(0);
      expect(selfdestructPatterns[0]?.risk).toBe("high");
    });

    it("should detect delegatecall in VulnerableContract", async () => {
      const { readFile } = await import("fs/promises");
      const source = await readFile(VULNERABLE_CONTRACT, "utf-8");
      const patterns = detectPatterns(source);

      const delegatecallPatterns = patterns.filter((p) => p.pattern === "delegatecall");
      expect(delegatecallPatterns.length).toBeGreaterThan(0);
      expect(delegatecallPatterns[0]?.risk).toBe("high");
    });

    it("should detect block.timestamp usage", async () => {
      const { readFile } = await import("fs/promises");
      const source = await readFile(VULNERABLE_CONTRACT, "utf-8");
      const patterns = detectPatterns(source);

      const timestampPatterns = patterns.filter((p) => p.pattern === "block.timestamp");
      expect(timestampPatterns.length).toBeGreaterThan(0);
      expect(timestampPatterns[0]?.risk).toBe("medium");
    });

    it("should detect unchecked blocks", async () => {
      const { readFile } = await import("fs/promises");
      // SafeContract uses unchecked in the loop
      const source = await readFile(SAFE_CONTRACT, "utf-8");
      const patterns = detectPatterns(source);

      const uncheckedPatterns = patterns.filter((p) => p.pattern === "unchecked");
      expect(uncheckedPatterns.length).toBeGreaterThan(0);
    });

    it("should detect low-level calls", async () => {
      const { readFile } = await import("fs/promises");
      const source = await readFile(VULNERABLE_CONTRACT, "utf-8");
      const patterns = detectPatterns(source);

      const callPatterns = patterns.filter(
        (p) => p.pattern === "low-level-call" || p.pattern === "arbitrary-call"
      );
      expect(callPatterns.length).toBeGreaterThan(0);
    });

    it("should include line number for each pattern", async () => {
      const { readFile } = await import("fs/promises");
      const source = await readFile(VULNERABLE_CONTRACT, "utf-8");
      const patterns = detectPatterns(source);

      for (const pattern of patterns) {
        expect(pattern.line).toBeGreaterThan(0);
        expect(typeof pattern.line).toBe("number");
      }
    });

    it("should include code snippet for each pattern", async () => {
      const { readFile } = await import("fs/promises");
      const source = await readFile(VULNERABLE_CONTRACT, "utf-8");
      const patterns = detectPatterns(source);

      for (const pattern of patterns) {
        expect(pattern.code.length).toBeGreaterThan(0);
      }
    });

    it("should detect fewer high-risk patterns in SafeContract", async () => {
      const { readFile } = await import("fs/promises");
      const vulnerableSource = await readFile(VULNERABLE_CONTRACT, "utf-8");
      const safeSource = await readFile(SAFE_CONTRACT, "utf-8");

      const vulnerablePatterns = detectPatterns(vulnerableSource);
      const safePatterns = detectPatterns(safeSource);

      const vulnerableHighRisk = vulnerablePatterns.filter((p) => p.risk === "high");
      const safeHighRisk = safePatterns.filter((p) => p.risk === "high");

      expect(safeHighRisk.length).toBeLessThan(vulnerableHighRisk.length);
    });
  });

  describe("summarizePatterns", () => {
    it("should count patterns by risk level", async () => {
      const { readFile } = await import("fs/promises");
      const source = await readFile(VULNERABLE_CONTRACT, "utf-8");
      const patterns = detectPatterns(source);
      const summary = summarizePatterns(patterns);

      expect(summary).toHaveProperty("high");
      expect(summary).toHaveProperty("medium");
      expect(summary).toHaveProperty("low");
      expect(summary).toHaveProperty("info");

      const totalFromSummary = summary.high + summary.medium + summary.low + summary.info;
      expect(totalFromSummary).toBe(patterns.length);
    });

    it("should return zeros for empty pattern array", () => {
      const summary = summarizePatterns([]);

      expect(summary.high).toBe(0);
      expect(summary.medium).toBe(0);
      expect(summary.low).toBe(0);
      expect(summary.info).toBe(0);
    });
  });

  describe("edge cases", () => {
    it("should handle contract with no functions", async () => {
      const source = `
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.20;

        contract EmptyContract {
            uint256 public value;
        }
      `;

      // Write temp file
      const { writeFile, unlink } = await import("fs/promises");
      const tempPath = resolve(FIXTURES_DIR, "TempEmpty.sol");
      await writeFile(tempPath, source);

      try {
        const info = await parseContractInfo(tempPath);
        expect(info.name).toBe("EmptyContract");
        // May have state variable getter generated
      } finally {
        await unlink(tempPath);
      }
    });

    it("should handle interface declarations", async () => {
      const source = `
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.20;

        interface IMyInterface {
            function doSomething() external returns (bool);
            event SomethingDone();
        }
      `;

      const { writeFile, unlink } = await import("fs/promises");
      const tempPath = resolve(FIXTURES_DIR, "TempInterface.sol");
      await writeFile(tempPath, source);

      try {
        const info = await parseContractInfo(tempPath);
        expect(info.name).toBe("IMyInterface");
        expect(info.functions.length).toBeGreaterThan(0);
        expect(info.events).toContain("SomethingDone");
      } finally {
        await unlink(tempPath);
      }
    });

    it("should handle library declarations", async () => {
      const source = `
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.20;

        library MyLibrary {
            function add(uint256 a, uint256 b) internal pure returns (uint256) {
                return a + b;
            }
        }
      `;

      const { writeFile, unlink } = await import("fs/promises");
      const tempPath = resolve(FIXTURES_DIR, "TempLibrary.sol");
      await writeFile(tempPath, source);

      try {
        const info = await parseContractInfo(tempPath);
        expect(info.name).toBe("MyLibrary");
        const addFn = info.functions.find((f) => f.name === "add");
        expect(addFn).toBeDefined();
        expect(addFn?.visibility).toBe("internal");
        expect(addFn?.stateMutability).toBe("pure");
      } finally {
        await unlink(tempPath);
      }
    });

    it("should handle multiple contracts in one file", async () => {
      const source = `
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.20;

        contract First {
            function one() public pure returns (uint) { return 1; }
        }

        contract Second {
            function two() public pure returns (uint) { return 2; }
        }
      `;

      const { writeFile, unlink } = await import("fs/promises");
      const tempPath = resolve(FIXTURES_DIR, "TempMultiple.sol");
      await writeFile(tempPath, source);

      try {
        const info = await parseContractInfo(tempPath);
        // Should get first contract (or we can check the name)
        expect(["First", "Second"]).toContain(info.name);
      } finally {
        await unlink(tempPath);
      }
    });
  });
});
