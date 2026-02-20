/**
 * Generate Invariants Tool Tests
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { writeFile, mkdir, rm } from "fs/promises";
import { join } from "path";
import { generateInvariants } from "../../src/tools/generateInvariants.js";

const TEST_DIR = join(process.cwd(), "__tests__/fixtures/generate-invariants");

const ERC20_CONTRACT = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
contract MyToken is ERC20 {
    constructor() ERC20("Token", "TKN") {
        _mint(msg.sender, 1000000e18);
    }
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}
`;

const LENDING_CONTRACT = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract LendingPool {
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public borrowed;
    function deposit(uint256 amount) external {}
    function borrow(uint256 amount) external {
        require(collateral[msg.sender] >= amount * 150 / 100, "undercollateralized");
        borrowed[msg.sender] += amount;
    }
    function liquidate(address user) external {}
}
`;

const SIMPLE_CONTRACT = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract SimpleCounter {
    uint256 public count;
    function increment() external { count++; }
    function decrement() external { require(count > 0); count--; }
}
`;

describe("Generate Invariants Tool", () => {
  beforeAll(async () => {
    await mkdir(TEST_DIR, { recursive: true });
    await writeFile(join(TEST_DIR, "ERC20Token.sol"), ERC20_CONTRACT);
    await writeFile(join(TEST_DIR, "LendingPool.sol"), LENDING_CONTRACT);
    await writeFile(join(TEST_DIR, "SimpleContract.sol"), SIMPLE_CONTRACT);
  });

  afterAll(async () => {
    await rm(TEST_DIR, { recursive: true, force: true });
  });

  describe("Auto-detection", () => {
    it("should auto-detect ERC20 contract and mention ERC-20 concepts", async () => {
      const result = await generateInvariants({
        contractPath: join(TEST_DIR, "ERC20Token.sol"),
        protocolType: "auto",
      });

      expect(typeof result).toBe("string");
      expect(result.length).toBeGreaterThan(0);
      expect(result.toLowerCase()).toMatch(/erc-20|totalsupply|erc20/);
    });

    it("should auto-detect lending contract and mention lending concepts", async () => {
      const result = await generateInvariants({
        contractPath: join(TEST_DIR, "LendingPool.sol"),
        protocolType: "auto",
      });

      expect(typeof result).toBe("string");
      expect(result.length).toBeGreaterThan(0);
      expect(result.toLowerCase()).toMatch(/lending|solvency|collateral/);
    });

    it("should return generic invariants for a simple contract", async () => {
      const result = await generateInvariants({
        contractPath: join(TEST_DIR, "SimpleContract.sol"),
        protocolType: "auto",
      });

      expect(typeof result).toBe("string");
      expect(result.length).toBeGreaterThan(0);
    });
  });

  describe("Explicit protocolType", () => {
    it("should generate erc20 invariants when protocolType is 'erc20'", async () => {
      const result = await generateInvariants({
        contractPath: join(TEST_DIR, "ERC20Token.sol"),
        protocolType: "erc20",
      });

      expect(typeof result).toBe("string");
      expect(result.length).toBeGreaterThan(0);
      expect(result.toLowerCase()).toMatch(/erc-20|totalsupply|erc20/);
    });

    it("should generate lending invariants when protocolType is 'lending'", async () => {
      const result = await generateInvariants({
        contractPath: join(TEST_DIR, "LendingPool.sol"),
        protocolType: "lending",
      });

      expect(typeof result).toBe("string");
      expect(result.length).toBeGreaterThan(0);
      expect(result.toLowerCase()).toMatch(/lending|solvency|collateral/);
    });

    it("should generate amm invariants when protocolType is 'amm'", async () => {
      const result = await generateInvariants({
        contractPath: join(TEST_DIR, "SimpleContract.sol"),
        protocolType: "amm",
      });

      expect(typeof result).toBe("string");
      expect(result.length).toBeGreaterThan(0);
      expect(result.toLowerCase()).toMatch(/amm|swap|reserve|constant.product/);
    });

    it("should generate vault invariants when protocolType is 'vault'", async () => {
      const result = await generateInvariants({
        contractPath: join(TEST_DIR, "SimpleContract.sol"),
        protocolType: "vault",
      });

      expect(typeof result).toBe("string");
      expect(result.length).toBeGreaterThan(0);
      expect(result.toLowerCase()).toMatch(/vault|totalassets|shares/);
    });

    it("should generate governance invariants when protocolType is 'governance'", async () => {
      const result = await generateInvariants({
        contractPath: join(TEST_DIR, "SimpleContract.sol"),
        protocolType: "governance",
      });

      expect(typeof result).toBe("string");
      expect(result.length).toBeGreaterThan(0);
      expect(result.toLowerCase()).toMatch(/governance|quorum|proposal|timelock/);
    });

    it("should generate staking invariants when protocolType is 'staking'", async () => {
      const result = await generateInvariants({
        contractPath: join(TEST_DIR, "SimpleContract.sol"),
        protocolType: "staking",
      });

      expect(typeof result).toBe("string");
      expect(result.length).toBeGreaterThan(0);
      expect(result.toLowerCase()).toMatch(/stak|reward/);
    });
  });

  describe("includeStateful option", () => {
    it("should still return output when includeStateful is false", async () => {
      const result = await generateInvariants({
        contractPath: join(TEST_DIR, "ERC20Token.sol"),
        includeStateful: false,
      });

      expect(typeof result).toBe("string");
      expect(result.length).toBeGreaterThan(0);
    });

    it("should mention forge commands when includeStateful is true", async () => {
      const result = await generateInvariants({
        contractPath: join(TEST_DIR, "ERC20Token.sol"),
        includeStateful: true,
      });

      expect(typeof result).toBe("string");
      expect(result.length).toBeGreaterThan(0);
      expect(result.toLowerCase()).toContain("forge");
    });

    it("should not include forge run instructions when includeStateful is false", async () => {
      const result = await generateInvariants({
        contractPath: join(TEST_DIR, "ERC20Token.sol"),
        includeStateful: false,
      });

      // The HOW TO RUN section is only added when includeStateful is true
      expect(result).not.toMatch(/how to run/i);
    });
  });

  describe("Output structure", () => {
    it("all outputs are non-empty strings for ERC20 contract", async () => {
      const result = await generateInvariants({
        contractPath: join(TEST_DIR, "ERC20Token.sol"),
      });

      expect(typeof result).toBe("string");
      expect(result.length).toBeGreaterThan(0);
    });

    it("all outputs are non-empty strings for lending contract", async () => {
      const result = await generateInvariants({
        contractPath: join(TEST_DIR, "LendingPool.sol"),
      });

      expect(typeof result).toBe("string");
      expect(result.length).toBeGreaterThan(0);
    });

    it("all outputs are non-empty strings for generic contract", async () => {
      const result = await generateInvariants({
        contractPath: join(TEST_DIR, "SimpleContract.sol"),
      });

      expect(typeof result).toBe("string");
      expect(result.length).toBeGreaterThan(0);
    });

    it("output should contain invariant suggestions header", async () => {
      const result = await generateInvariants({
        contractPath: join(TEST_DIR, "ERC20Token.sol"),
      });

      expect(result).toMatch(/invariant test suggestions/i);
    });

    it("output should contain protocol type information", async () => {
      const result = await generateInvariants({
        contractPath: join(TEST_DIR, "ERC20Token.sol"),
        protocolType: "erc20",
      });

      expect(result).toMatch(/protocol type/i);
      expect(result.toLowerCase()).toContain("erc20");
    });

    it("output should include a Foundry setup template", async () => {
      const result = await generateInvariants({
        contractPath: join(TEST_DIR, "ERC20Token.sol"),
      });

      expect(result).toMatch(/foundry setup template/i);
    });
  });

  describe("Error handling", () => {
    it("should handle non-existent file gracefully", async () => {
      let result: string | undefined;
      let threw = false;

      try {
        result = await generateInvariants({
          contractPath: "/nonexistent/path/Contract.sol",
        });
      } catch {
        threw = true;
      }

      // Either it throws or returns an error message — both are acceptable
      if (!threw) {
        expect(typeof result).toBe("string");
        expect(result!.length).toBeGreaterThan(0);
        expect(result!.toLowerCase()).toMatch(/not found|error|file/);
      } else {
        expect(threw).toBe(true);
      }
    });
  });
});
