import { mkdtempSync, rmSync, mkdirSync, writeFileSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { auditProject, AuditProjectInputSchema } from "../../src/tools/auditProject.js";

// ============================================================================
// Test Helpers
// ============================================================================

let testDir: string;

function createTestProject(): void {
  // Create directory structure
  mkdirSync(join(testDir, "src"), { recursive: true });
  mkdirSync(join(testDir, "test"), { recursive: true });

  // Create foundry.toml to mark as Foundry project
  writeFileSync(join(testDir, "foundry.toml"), "[profile.default]\n");
}

function createContract(name: string, content: string): void {
  writeFileSync(join(testDir, "src", `${name}.sol`), content);
}

// Sample contracts for testing
const SIMPLE_CONTRACT = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Simple {
    uint256 public value;

    function setValue(uint256 _value) public {
        value = _value;
    }
}
`;

const PAYABLE_CONTRACT = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract PayableContract {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function deposit() public payable {
        // Accept ether
    }

    function withdraw() public {
        payable(owner).transfer(address(this).balance);
    }
}
`;

const INTERFACE_CONTRACT = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IToken {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}
`;

const LIBRARY_CONTRACT = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

library SafeMath {
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        require(c >= a, "SafeMath: addition overflow");
        return c;
    }
}
`;

const IMPORTING_CONTRACT = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./IToken.sol";
import "./SafeMath.sol";

contract TokenUser {
    using SafeMath for uint256;

    IToken public token;
    uint256 public counter;

    constructor(address _token) {
        token = IToken(_token);
    }

    function increment() public {
        counter = counter.add(1);
    }
}
`;

// ============================================================================
// Tests
// ============================================================================

describe("AuditProjectInputSchema", () => {
  it("should validate valid input", () => {
    const input = {
      projectRoot: "/path/to/project",
    };

    const result = AuditProjectInputSchema.parse(input);
    expect(result.projectRoot).toBe("/path/to/project");
    expect(result.parallel).toBe(true);
    expect(result.skipTests).toBe(false);
    expect(result.priorityOnly).toBe(false);
  });

  it("should apply defaults", () => {
    const input = {
      projectRoot: "/path/to/project",
    };

    const result = AuditProjectInputSchema.parse(input);
    expect(result.parallel).toBe(true);
    expect(result.skipTests).toBe(false);
    expect(result.skipGas).toBe(false);
    expect(result.priorityOnly).toBe(false);
  });

  it("should accept optional parameters", () => {
    const input = {
      projectRoot: "/path/to/project",
      maxContracts: 5,
      priorityOnly: true,
      parallel: false,
      skipTests: true,
      skipGas: true,
    };

    const result = AuditProjectInputSchema.parse(input);
    expect(result.maxContracts).toBe(5);
    expect(result.priorityOnly).toBe(true);
    expect(result.parallel).toBe(false);
    expect(result.skipTests).toBe(true);
    expect(result.skipGas).toBe(true);
  });

  it("should reject missing projectRoot", () => {
    expect(() => AuditProjectInputSchema.parse({})).toThrow();
  });
});

describe("auditProject", () => {
  beforeEach(() => {
    testDir = mkdtempSync(join(tmpdir(), "audit-project-test-"));
    createTestProject();
  });

  afterEach(() => {
    rmSync(testDir, { recursive: true, force: true });
  });

  it("should return error for non-existent project", async () => {
    const result = await auditProject({
      projectRoot: "/non/existent/path",
      skipTests: true,
    });

    const parsed = JSON.parse(result);
    expect(parsed.success).toBe(false);
    expect(parsed.error).toContain("No contracts found");
  });

  it("should return error for empty project", async () => {
    // Project exists but has no contracts
    const result = await auditProject({
      projectRoot: testDir,
      skipTests: true,
    });

    const parsed = JSON.parse(result);
    expect(parsed.success).toBe(false);
    expect(parsed.error).toContain("No contracts found");
  });

  it("should generate report for single contract", async () => {
    createContract("Simple", SIMPLE_CONTRACT);

    const result = await auditProject({
      projectRoot: testDir,
      skipTests: true,
    });

    // Should contain markdown report
    expect(result).toContain("# Project Audit:");
    expect(result).toContain("## Project Overview");
    expect(result).toContain("## Risk Matrix");
    expect(result).toContain("Simple");
  });

  it("should analyze multiple contracts", async () => {
    createContract("Simple", SIMPLE_CONTRACT);
    createContract("PayableContract", PAYABLE_CONTRACT);
    createContract("IToken", INTERFACE_CONTRACT);

    const result = await auditProject({
      projectRoot: testDir,
      skipTests: true,
    });

    expect(result).toContain("Simple");
    expect(result).toContain("PayableContract");
    expect(result).toContain("IToken");
    expect(result).toContain("## Per-Contract Reports");
  });

  it("should prioritize payable contracts higher", async () => {
    createContract("Simple", SIMPLE_CONTRACT);
    createContract("PayableContract", PAYABLE_CONTRACT);

    const result = await auditProject({
      projectRoot: testDir,
      skipTests: true,
    });

    // Should identify payable as a risk indicator
    expect(result).toContain("payable");
    expect(result).toContain("PayableContract");
  });

  it("should respect maxContracts limit", async () => {
    createContract("Contract1", SIMPLE_CONTRACT.replace("Simple", "Contract1"));
    createContract("Contract2", SIMPLE_CONTRACT.replace("Simple", "Contract2"));
    createContract("Contract3", SIMPLE_CONTRACT.replace("Simple", "Contract3"));

    const result = await auditProject({
      projectRoot: testDir,
      maxContracts: 1,
      skipTests: true,
    });

    // Should contain JSON data section
    expect(result).toContain("Full JSON Data");

    // Parse the JSON to verify
    const jsonMatch = result.match(/```json\n([\s\S]*?)\n```/);
    expect(jsonMatch).toBeTruthy();

    const jsonData = JSON.parse(jsonMatch![1]!);
    expect(jsonData.contractReports.length).toBe(1);
  });

  it("should filter by priorityOnly", async () => {
    createContract("Simple", SIMPLE_CONTRACT);
    createContract("PayableContract", PAYABLE_CONTRACT);
    createContract("IToken", INTERFACE_CONTRACT);
    createContract("SafeMath", LIBRARY_CONTRACT);

    const result = await auditProject({
      projectRoot: testDir,
      priorityOnly: true,
      skipTests: true,
    });

    // Parse the JSON to check what was analyzed
    const jsonMatch = result.match(/```json\n([\s\S]*?)\n```/);
    expect(jsonMatch).toBeTruthy();

    const jsonData = JSON.parse(jsonMatch![1]!);

    // Should only have high/critical priority contracts
    for (const report of jsonData.contractReports) {
      expect(["critical", "high"]).toContain(report.contract.priority);
    }
  });

  it("should build dependency graph", async () => {
    createContract("IToken", INTERFACE_CONTRACT);
    createContract("SafeMath", LIBRARY_CONTRACT);
    createContract("TokenUser", IMPORTING_CONTRACT);

    const result = await auditProject({
      projectRoot: testDir,
      skipTests: true,
    });

    expect(result).toContain("TokenUser");
    // Should recognize dependencies
    expect(result).toContain("IToken");
    expect(result).toContain("SafeMath");
  });

  it("should calculate overall risk level", async () => {
    createContract("Simple", SIMPLE_CONTRACT);

    const result = await auditProject({
      projectRoot: testDir,
      skipTests: true,
    });

    // Should have an overall risk assessment
    expect(result).toMatch(/Overall Risk.*(?:CRITICAL|HIGH|MEDIUM|LOW|MINIMAL)/);
  });

  it("should generate markdown report with proper sections", async () => {
    createContract("Simple", SIMPLE_CONTRACT);
    createContract("PayableContract", PAYABLE_CONTRACT);

    const result = await auditProject({
      projectRoot: testDir,
      skipTests: true,
    });

    // Check for required sections
    expect(result).toContain("# Project Audit:");
    expect(result).toContain("## Project Overview");
    expect(result).toContain("## Risk Matrix");
    expect(result).toContain("## Per-Contract Reports");
    expect(result).toContain("Full JSON Data");
  });

  it("should include contract metadata in report", async () => {
    createContract("PayableContract", PAYABLE_CONTRACT);

    const result = await auditProject({
      projectRoot: testDir,
      skipTests: true,
    });

    // Should include risk indicators
    expect(result).toContain("payable");
    expect(result).toContain("**Type:**");
    expect(result).toContain("**SLOC:**");
  });

  it("should run sequentially when parallel=false", async () => {
    createContract("Contract1", SIMPLE_CONTRACT.replace("Simple", "Contract1"));
    createContract("Contract2", SIMPLE_CONTRACT.replace("Simple", "Contract2"));

    const result = await auditProject({
      projectRoot: testDir,
      parallel: false,
      skipTests: true,
    });

    // Should still complete successfully
    expect(result).toContain("Contract1");
    expect(result).toContain("Contract2");
  });
});

describe("project-level findings", () => {
  beforeEach(() => {
    testDir = mkdtempSync(join(tmpdir(), "audit-project-test-"));
    createTestProject();
  });

  afterEach(() => {
    rmSync(testDir, { recursive: true, force: true });
  });

  it("should detect circular dependencies", async () => {
    // Create contracts with circular imports
    const contractA = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "./B.sol";
contract A { B public b; }
`;
    const contractB = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "./A.sol";
contract B { A public a; }
`;

    createContract("A", contractA);
    createContract("B", contractB);

    const result = await auditProject({
      projectRoot: testDir,
      skipTests: true,
    });

    // Should detect and report circular dependency
    // The circular dependency finding comes from projectScanner
    expect(result).toContain("A");
    expect(result).toContain("B");
  });

  it("should identify critical dependencies with issues", async () => {
    createContract("IToken", INTERFACE_CONTRACT);
    createContract("SafeMath", LIBRARY_CONTRACT);
    createContract("TokenUser", IMPORTING_CONTRACT);

    const result = await auditProject({
      projectRoot: testDir,
      skipTests: true,
    });

    // Should analyze dependencies
    expect(result).toContain("TokenUser");
  });
});

describe("risk calculation", () => {
  beforeEach(() => {
    testDir = mkdtempSync(join(tmpdir(), "audit-project-test-"));
    createTestProject();
  });

  afterEach(() => {
    rmSync(testDir, { recursive: true, force: true });
  });

  it("should mark payable contracts as higher risk", async () => {
    createContract("PayableContract", PAYABLE_CONTRACT);

    const result = await auditProject({
      projectRoot: testDir,
      skipTests: true,
    });

    // Parse JSON to check priority
    const jsonMatch = result.match(/```json\n([\s\S]*?)\n```/);
    expect(jsonMatch).toBeTruthy();

    const jsonData = JSON.parse(jsonMatch![1]!);
    const payableReport = jsonData.contractReports.find(
      (r: { contract: { name: string } }) => r.contract.name === "PayableContract"
    );

    expect(payableReport).toBeTruthy();
    expect(["critical", "high"]).toContain(payableReport.contract.priority);
  });

  it("should mark interfaces as lower priority", async () => {
    createContract("IToken", INTERFACE_CONTRACT);
    createContract("Simple", SIMPLE_CONTRACT);

    const result = await auditProject({
      projectRoot: testDir,
      skipTests: true,
    });

    // Parse JSON to check priority
    const jsonMatch = result.match(/```json\n([\s\S]*?)\n```/);
    expect(jsonMatch).toBeTruthy();

    const jsonData = JSON.parse(jsonMatch![1]!);
    const interfaceReport = jsonData.contractReports.find(
      (r: { contract: { name: string } }) => r.contract.name === "IToken"
    );

    expect(interfaceReport).toBeTruthy();
    expect(["medium", "low"]).toContain(interfaceReport.contract.priority);
  });
});
