/**
 * Diff Analyzer Tests
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { writeFile, mkdir, rm } from "fs/promises";
import { join } from "path";
import {
  generateDiff,
  extractChangedContext,
  assessChangeRisk,
  CRITICAL_FUNCTIONS,
} from "../../src/analyzers/diffAnalyzer.js";

const TEST_DIR = join(process.cwd(), "__tests__/fixtures/diff-analyzer");

// Test contracts
const OLD_CONTRACT = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Token {
    mapping(address => uint256) public balances;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function transfer(address to, uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient");
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }

    function mint(address to, uint256 amount) external {
        require(msg.sender == owner, "Only owner");
        balances[to] += amount;
    }
}
`;

const NEW_CONTRACT_MINOR = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Token {
    mapping(address => uint256) public balances;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // Updated transfer function
    function transfer(address to, uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }

    function mint(address to, uint256 amount) external {
        require(msg.sender == owner, "Only owner");
        balances[to] += amount;
    }
}
`;

const NEW_CONTRACT_CRITICAL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Token {
    mapping(address => uint256) public balances;
    mapping(address => bool) public isAdmin;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function transfer(address to, uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient");
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }

    function mint(address to, uint256 amount) external {
        require(msg.sender == owner || isAdmin[msg.sender], "Not authorized");
        balances[to] += amount;
    }

    function withdraw(uint256 amount) external payable {
        require(balances[msg.sender] >= amount, "Insufficient");
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }

    function setAdmin(address admin, bool status) external {
        require(msg.sender == owner, "Only owner");
        isAdmin[admin] = status;
    }
}
`;

const NEW_CONTRACT_REMOVED_ACCESS = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Token {
    mapping(address => uint256) public balances;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function transfer(address to, uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient");
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }

    // Access control removed - anyone can mint!
    function mint(address to, uint256 amount) external {
        balances[to] += amount;
    }
}
`;

describe("Diff Analyzer", () => {
  beforeAll(async () => {
    await mkdir(TEST_DIR, { recursive: true });
    await Promise.all([
      writeFile(join(TEST_DIR, "OldContract.sol"), OLD_CONTRACT),
      writeFile(join(TEST_DIR, "NewContractMinor.sol"), NEW_CONTRACT_MINOR),
      writeFile(join(TEST_DIR, "NewContractCritical.sol"), NEW_CONTRACT_CRITICAL),
      writeFile(join(TEST_DIR, "NewContractRemovedAccess.sol"), NEW_CONTRACT_REMOVED_ACCESS),
    ]);
  });

  afterAll(async () => {
    await rm(TEST_DIR, { recursive: true, force: true });
  });

  describe("generateDiff", () => {
    it("should detect added and removed lines", async () => {
      const result = await generateDiff(
        join(TEST_DIR, "OldContract.sol"),
        join(TEST_DIR, "NewContractMinor.sol")
      );

      expect(result.addedLines.length).toBeGreaterThan(0);
      expect(result.removedLines.length).toBeGreaterThan(0);
    });

    it("should detect modified functions", async () => {
      const result = await generateDiff(
        join(TEST_DIR, "OldContract.sol"),
        join(TEST_DIR, "NewContractMinor.sol")
      );

      expect(result.modifiedFunctions).toContain("transfer");
    });

    it("should detect new functions", async () => {
      const result = await generateDiff(
        join(TEST_DIR, "OldContract.sol"),
        join(TEST_DIR, "NewContractCritical.sol")
      );

      expect(result.newFunctions).toContain("withdraw");
      expect(result.newFunctions).toContain("setAdmin");
    });

    it("should detect modified state variables", async () => {
      const result = await generateDiff(
        join(TEST_DIR, "OldContract.sol"),
        join(TEST_DIR, "NewContractCritical.sol")
      );

      expect(result.modifiedStateVars.length).toBeGreaterThan(0);
    });

    it("should generate correct summary", async () => {
      const result = await generateDiff(
        join(TEST_DIR, "OldContract.sol"),
        join(TEST_DIR, "NewContractCritical.sol")
      );

      expect(result.summary.linesAdded).toBeGreaterThan(0);
      expect(result.summary.functionsChanged).toBeGreaterThan(0);
    });

    it("should include hunks", async () => {
      const result = await generateDiff(
        join(TEST_DIR, "OldContract.sol"),
        join(TEST_DIR, "NewContractMinor.sol")
      );

      expect(result.hunks.length).toBeGreaterThan(0);
    });
  });

  describe("extractChangedContext", () => {
    it("should extract context for new functions", async () => {
      const diffResult = await generateDiff(
        join(TEST_DIR, "OldContract.sol"),
        join(TEST_DIR, "NewContractCritical.sol")
      );

      const contexts = extractChangedContext(diffResult, NEW_CONTRACT_CRITICAL);

      const withdrawContext = contexts.find((c) => c.name === "withdraw");
      expect(withdrawContext).toBeDefined();
      expect(withdrawContext?.changeType).toBe("added");
      expect(withdrawContext?.type).toBe("function");
    });

    it("should extract context for modified functions", async () => {
      const diffResult = await generateDiff(
        join(TEST_DIR, "OldContract.sol"),
        join(TEST_DIR, "NewContractCritical.sol")
      );

      const contexts = extractChangedContext(diffResult, NEW_CONTRACT_CRITICAL);

      const mintContext = contexts.find((c) => c.name === "mint");
      expect(mintContext).toBeDefined();
      expect(mintContext?.changeType).toBe("modified");
    });

    it("should include surrounding context", async () => {
      const diffResult = await generateDiff(
        join(TEST_DIR, "OldContract.sol"),
        join(TEST_DIR, "NewContractCritical.sol")
      );

      const contexts = extractChangedContext(diffResult, NEW_CONTRACT_CRITICAL);

      const context = contexts[0];
      expect(context?.surroundingContext).toBeDefined();
      expect(context?.surroundingContext.before).toBeDefined();
      expect(context?.surroundingContext.after).toBeDefined();
    });

    it("should include function content", async () => {
      const diffResult = await generateDiff(
        join(TEST_DIR, "OldContract.sol"),
        join(TEST_DIR, "NewContractCritical.sol")
      );

      const contexts = extractChangedContext(diffResult, NEW_CONTRACT_CRITICAL);

      const withdrawContext = contexts.find((c) => c.name === "withdraw");
      expect(withdrawContext?.content).toContain("function withdraw");
      expect(withdrawContext?.content).toContain("payable");
    });
  });

  describe("assessChangeRisk", () => {
    it("should detect changes to critical functions", async () => {
      const diffResult = await generateDiff(
        join(TEST_DIR, "OldContract.sol"),
        join(TEST_DIR, "NewContractMinor.sol")
      );

      const assessment = assessChangeRisk(diffResult);

      // Even minor changes to transfer (a critical function) are flagged
      // The assessment should detect modified critical function
      expect(assessment.changeFlags.length).toBeGreaterThan(0);
    });

    it("should rate new withdraw function as critical", async () => {
      const diffResult = await generateDiff(
        join(TEST_DIR, "OldContract.sol"),
        join(TEST_DIR, "NewContractCritical.sol")
      );

      const assessment = assessChangeRisk(diffResult);

      expect(assessment.riskLevel).toBe("critical");
      expect(assessment.changeFlags.some((f) => f.flag === "CRITICAL_FUNCTION_MODIFIED")).toBe(
        true
      );
    });

    it("should detect new payable function", async () => {
      const diffResult = await generateDiff(
        join(TEST_DIR, "OldContract.sol"),
        join(TEST_DIR, "NewContractCritical.sol")
      );

      const assessment = assessChangeRisk(diffResult);

      expect(assessment.changeFlags.some((f) => f.flag === "NEW_PAYABLE_FUNCTION")).toBe(true);
    });

    it("should detect removed access control as critical", async () => {
      const diffResult = await generateDiff(
        join(TEST_DIR, "OldContract.sol"),
        join(TEST_DIR, "NewContractRemovedAccess.sol")
      );

      const assessment = assessChangeRisk(diffResult);

      expect(assessment.riskLevel).toBe("critical");
      expect(assessment.changeFlags.some((f) => f.flag === "ACCESS_CONTROL_REMOVED")).toBe(true);
    });

    it("should provide recommendations", async () => {
      const diffResult = await generateDiff(
        join(TEST_DIR, "OldContract.sol"),
        join(TEST_DIR, "NewContractCritical.sol")
      );

      const assessment = assessChangeRisk(diffResult);

      expect(assessment.recommendations.length).toBeGreaterThan(0);
      expect(assessment.recommendations.some((r) => r.includes("audit"))).toBe(true);
    });

    it("should provide summary", async () => {
      const diffResult = await generateDiff(
        join(TEST_DIR, "OldContract.sol"),
        join(TEST_DIR, "NewContractCritical.sol")
      );

      const assessment = assessChangeRisk(diffResult);

      expect(assessment.summary).toBeDefined();
      expect(assessment.summary.length).toBeGreaterThan(0);
    });
  });

  describe("CRITICAL_FUNCTIONS constant", () => {
    it("should include common critical functions", () => {
      expect(CRITICAL_FUNCTIONS).toContain("transfer");
      expect(CRITICAL_FUNCTIONS).toContain("withdraw");
      expect(CRITICAL_FUNCTIONS).toContain("mint");
      expect(CRITICAL_FUNCTIONS).toContain("approve");
    });
  });

  describe("DiffResult structure", () => {
    it("should have correct structure", async () => {
      const result = await generateDiff(
        join(TEST_DIR, "OldContract.sol"),
        join(TEST_DIR, "NewContractMinor.sol")
      );

      expect(result).toHaveProperty("oldFile");
      expect(result).toHaveProperty("newFile");
      expect(result).toHaveProperty("addedLines");
      expect(result).toHaveProperty("removedLines");
      expect(result).toHaveProperty("modifiedFunctions");
      expect(result).toHaveProperty("modifiedStateVars");
      expect(result).toHaveProperty("newFunctions");
      expect(result).toHaveProperty("removedFunctions");
      expect(result).toHaveProperty("hunks");
      expect(result).toHaveProperty("summary");
    });

    it("should have correct line structure", async () => {
      const result = await generateDiff(
        join(TEST_DIR, "OldContract.sol"),
        join(TEST_DIR, "NewContractMinor.sol")
      );

      if (result.addedLines.length > 0) {
        const line = result.addedLines[0]!;
        expect(line).toHaveProperty("lineNumber");
        expect(line).toHaveProperty("content");
        expect(typeof line.lineNumber).toBe("number");
        expect(typeof line.content).toBe("string");
      }
    });
  });

  describe("ChangeRiskAssessment structure", () => {
    it("should have correct structure", async () => {
      const diffResult = await generateDiff(
        join(TEST_DIR, "OldContract.sol"),
        join(TEST_DIR, "NewContractCritical.sol")
      );

      const assessment = assessChangeRisk(diffResult);

      expect(assessment).toHaveProperty("riskLevel");
      expect(assessment).toHaveProperty("changeFlags");
      expect(assessment).toHaveProperty("summary");
      expect(assessment).toHaveProperty("recommendations");

      expect(["critical", "high", "medium", "low"]).toContain(assessment.riskLevel);
      expect(Array.isArray(assessment.changeFlags)).toBe(true);
      expect(Array.isArray(assessment.recommendations)).toBe(true);
    });

    it("should have correct flag structure", async () => {
      const diffResult = await generateDiff(
        join(TEST_DIR, "OldContract.sol"),
        join(TEST_DIR, "NewContractCritical.sol")
      );

      const assessment = assessChangeRisk(diffResult);

      if (assessment.changeFlags.length > 0) {
        const flag = assessment.changeFlags[0]!;
        expect(flag).toHaveProperty("flag");
        expect(flag).toHaveProperty("description");
        expect(flag).toHaveProperty("severity");
      }
    });
  });
});
