/**
 * Gas Optimizer Analyzer Tests
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { writeFile, mkdir, rm } from "fs/promises";
import { join } from "path";
import { analyzeGasPatterns, GAS_PATTERNS } from "../../src/analyzers/gasOptimizer.js";
import { Severity } from "../../src/types/index.js";

const TEST_DIR = join(process.cwd(), "__tests__/fixtures/gas-optimizer");

// Test contracts
const STORAGE_LOOP_CONTRACT = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract StorageLoop {
    uint256[] public items;
    uint256 public total;

    function badLoop() external {
        for (uint256 i = 0; i < items.length; i++) {
            total += items[i];
        }
    }
}
`;

const MEMORY_VS_CALLDATA_CONTRACT = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract MemoryVsCalldata {
    function badFunction(string memory name, uint256[] memory data) external pure returns (uint256) {
        return data.length;
    }

    function goodFunction(string calldata name, uint256[] calldata data) external pure returns (uint256) {
        return data.length;
    }
}
`;

const IMMUTABLE_CONTRACT = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract MissingImmutable {
    address public owner;
    uint256 public maxSupply;

    constructor(address _owner, uint256 _maxSupply) {
        owner = _owner;
        maxSupply = _maxSupply;
    }

    function getOwner() external view returns (address) {
        return owner;
    }
}
`;

const GT_ZERO_CONTRACT = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract GtZero {
    function check(uint256 amount) external pure returns (bool) {
        require(amount > 0, "Amount must be positive");
        if (amount > 0) {
            return true;
        }
        return false;
    }
}
`;

const STRING_BYTES32_CONTRACT = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract StringBytes32 {
    string public constant NAME = "MyToken";
    string public constant SYMBOL = "MTK";
}
`;

const POST_INCREMENT_CONTRACT = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

contract PostIncrement {
    function loop(uint256 n) external pure returns (uint256) {
        uint256 sum = 0;
        for (uint256 i = 0; i < n; i++) {
            sum += i;
        }
        return sum;
    }
}
`;

const STRUCT_PACKING_CONTRACT = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract StructPacking {
    struct BadPacking {
        uint8 a;
        uint256 b;
        uint8 c;
    }

    struct GoodPacking {
        uint256 b;
        uint8 a;
        uint8 c;
    }

    BadPacking public bad;
    GoodPacking public good;
}
`;

const UNCHECKED_INCREMENT_CONTRACT = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract UncheckedIncrement {
    function loop(uint256[] calldata arr) external pure returns (uint256) {
        uint256 sum = 0;
        for (uint256 i = 0; i < arr.length; i++) {
            sum += arr[i];
        }
        return sum;
    }
}
`;

const MULTIPLE_MAPPINGS_CONTRACT = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract MultipleMappings {
    mapping(address => uint256) public balances;
    mapping(address => bool) public isWhitelisted;
    mapping(address => uint256) public lastAction;
}
`;

describe("Gas Optimizer Analyzer", () => {
  beforeAll(async () => {
    await mkdir(TEST_DIR, { recursive: true });

    // Write test contracts
    await Promise.all([
      writeFile(join(TEST_DIR, "StorageLoop.sol"), STORAGE_LOOP_CONTRACT),
      writeFile(join(TEST_DIR, "MemoryVsCalldata.sol"), MEMORY_VS_CALLDATA_CONTRACT),
      writeFile(join(TEST_DIR, "MissingImmutable.sol"), IMMUTABLE_CONTRACT),
      writeFile(join(TEST_DIR, "GtZero.sol"), GT_ZERO_CONTRACT),
      writeFile(join(TEST_DIR, "StringBytes32.sol"), STRING_BYTES32_CONTRACT),
      writeFile(join(TEST_DIR, "PostIncrement.sol"), POST_INCREMENT_CONTRACT),
      writeFile(join(TEST_DIR, "StructPacking.sol"), STRUCT_PACKING_CONTRACT),
      writeFile(join(TEST_DIR, "UncheckedIncrement.sol"), UNCHECKED_INCREMENT_CONTRACT),
      writeFile(join(TEST_DIR, "MultipleMappings.sol"), MULTIPLE_MAPPINGS_CONTRACT),
    ]);
  });

  afterAll(async () => {
    await rm(TEST_DIR, { recursive: true, force: true });
  });

  describe("GAS_PATTERNS", () => {
    it("should have all 10 patterns defined", () => {
      expect(Object.keys(GAS_PATTERNS)).toHaveLength(10);
    });

    it("should have correct severity levels", () => {
      expect(GAS_PATTERNS.STORAGE_WRITE_IN_LOOP?.severity).toBe(Severity.HIGH);
      expect(GAS_PATTERNS.STORAGE_READ_IN_LOOP?.severity).toBe(Severity.MEDIUM);
      expect(GAS_PATTERNS.STRUCT_PACKING?.severity).toBe(Severity.MEDIUM);
      expect(GAS_PATTERNS.MEMORY_VS_CALLDATA?.severity).toBe(Severity.LOW);
      expect(GAS_PATTERNS.GT_ZERO_VS_NE_ZERO?.severity).toBe(Severity.INFORMATIONAL);
    });
  });

  describe("Storage Reads in Loops", () => {
    it("should detect storage variable length in loop condition", async () => {
      const findings = await analyzeGasPatterns(join(TEST_DIR, "StorageLoop.sol"));
      const storageReadFindings = findings.filter((f) => f.id === "GAS-001");

      expect(storageReadFindings.length).toBeGreaterThan(0);
      expect(storageReadFindings[0]?.description).toContain("items");
      expect(storageReadFindings[0]?.detector).toBe("gas-optimizer");
    });
  });

  describe("Storage Writes in Loops", () => {
    it("should detect storage writes inside loops", async () => {
      const findings = await analyzeGasPatterns(join(TEST_DIR, "StorageLoop.sol"));
      const storageWriteFindings = findings.filter((f) => f.id === "GAS-002");

      expect(storageWriteFindings.length).toBeGreaterThan(0);
      expect(storageWriteFindings[0]?.description).toContain("total");
      expect(storageWriteFindings[0]?.severity).toBe(Severity.HIGH);
    });
  });

  describe("Memory vs Calldata", () => {
    it("should detect memory parameters in external functions", async () => {
      const findings = await analyzeGasPatterns(join(TEST_DIR, "MemoryVsCalldata.sol"));
      const calldataFindings = findings.filter((f) => f.id === "GAS-003");

      expect(calldataFindings.length).toBeGreaterThan(0);
      expect(calldataFindings.some((f) => f.description.includes("string"))).toBe(true);
    });
  });

  describe("Missing Immutable", () => {
    it("should detect variables that could be immutable", async () => {
      const findings = await analyzeGasPatterns(join(TEST_DIR, "MissingImmutable.sol"));
      const immutableFindings = findings.filter((f) => f.id === "GAS-004");

      expect(immutableFindings.length).toBeGreaterThan(0);
      expect(
        immutableFindings.some(
          (f) => f.description.includes("owner") || f.description.includes("maxSupply")
        )
      ).toBe(true);
    });
  });

  describe("> 0 vs != 0", () => {
    it("should detect > 0 comparisons", async () => {
      const findings = await analyzeGasPatterns(join(TEST_DIR, "GtZero.sol"));
      const gtZeroFindings = findings.filter((f) => f.id === "GAS-005");

      expect(gtZeroFindings.length).toBeGreaterThan(0);
      expect(gtZeroFindings[0]?.description).toContain("> 0");
      expect(gtZeroFindings[0]?.description).toContain("!= 0");
    });
  });

  describe("String vs bytes32", () => {
    it("should detect short constant strings", async () => {
      const findings = await analyzeGasPatterns(join(TEST_DIR, "StringBytes32.sol"));
      const stringFindings = findings.filter((f) => f.id === "GAS-006");

      expect(stringFindings.length).toBeGreaterThan(0);
      expect(
        stringFindings.some(
          (f) => f.description.includes("NAME") || f.description.includes("SYMBOL")
        )
      ).toBe(true);
    });
  });

  describe("Post Increment", () => {
    it("should detect i++ in loops for Solidity < 0.8.12", async () => {
      const findings = await analyzeGasPatterns(join(TEST_DIR, "PostIncrement.sol"));
      const postIncFindings = findings.filter((f) => f.id === "GAS-007");

      expect(postIncFindings.length).toBeGreaterThan(0);
      expect(postIncFindings[0]?.description).toContain("++");
    });
  });

  describe("Struct Packing", () => {
    it("should detect inefficient struct packing", async () => {
      const findings = await analyzeGasPatterns(join(TEST_DIR, "StructPacking.sol"));
      const packingFindings = findings.filter((f) => f.id === "GAS-008");

      expect(packingFindings.length).toBeGreaterThan(0);
      expect(packingFindings[0]?.description).toContain("BadPacking");
      expect(packingFindings[0]?.description).toContain("slots");
    });
  });

  describe("Unchecked Loop Increment", () => {
    it("should suggest unchecked for bounded loops", async () => {
      const findings = await analyzeGasPatterns(join(TEST_DIR, "UncheckedIncrement.sol"));
      const uncheckedFindings = findings.filter((f) => f.id === "GAS-009");

      expect(uncheckedFindings.length).toBeGreaterThan(0);
      expect(uncheckedFindings[0]?.description).toContain("unchecked");
    });
  });

  describe("Multiple Address Mappings", () => {
    it("should detect multiple mappings with same key type", async () => {
      const findings = await analyzeGasPatterns(join(TEST_DIR, "MultipleMappings.sol"));
      const mappingFindings = findings.filter((f) => f.id === "GAS-010");

      expect(mappingFindings.length).toBeGreaterThan(0);
      expect(mappingFindings[0]?.description).toContain("address");
      expect(mappingFindings[0]?.description).toContain("balances");
    });
  });

  describe("Finding Structure", () => {
    it("should return properly structured findings", async () => {
      const findings = await analyzeGasPatterns(join(TEST_DIR, "StorageLoop.sol"));

      expect(findings.length).toBeGreaterThan(0);

      const finding = findings[0]!;
      expect(finding).toHaveProperty("id");
      expect(finding).toHaveProperty("title");
      expect(finding).toHaveProperty("severity");
      expect(finding).toHaveProperty("description");
      expect(finding).toHaveProperty("location");
      expect(finding).toHaveProperty("recommendation");
      expect(finding).toHaveProperty("detector");
      expect(finding).toHaveProperty("confidence");

      expect(finding.detector).toBe("gas-optimizer");
      expect(finding.location).toHaveProperty("file");
      expect(finding.location).toHaveProperty("lines");
    });
  });
});
