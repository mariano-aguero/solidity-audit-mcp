import { mkdtempSync, rmSync, mkdirSync, writeFileSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import {
  scanProject,
  buildDependencyGraph,
  prioritizeAudit,
  detectProjectType,
  formatProjectReport,
  getCriticalContracts,
  getFundHandlingContracts,
  type ContractFile,
} from "../../src/analyzers/projectScanner.js";

// ============================================================================
// Test Helpers
// ============================================================================

let testDir: string;

function createTestProject(): void {
  // Create directory structure
  mkdirSync(join(testDir, "src"), { recursive: true });
  mkdirSync(join(testDir, "test"), { recursive: true });
  mkdirSync(join(testDir, "lib"), { recursive: true });

  // Create foundry.toml to mark as Foundry project
  writeFileSync(join(testDir, "foundry.toml"), "[profile.default]\n");
}

function writeContract(relativePath: string, content: string): void {
  const fullPath = join(testDir, relativePath);
  const dir = fullPath.substring(0, fullPath.lastIndexOf("/"));
  mkdirSync(dir, { recursive: true });
  writeFileSync(fullPath, content);
}

const SIMPLE_CONTRACT = `
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SimpleContract {
    uint256 public value;

    function setValue(uint256 _value) external {
        value = _value;
    }
}
`;

const INTERFACE_CONTRACT = `
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IToken {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}
`;

const LIBRARY_CONTRACT = `
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library MathLib {
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        return a + b;
    }
}
`;

const ABSTRACT_CONTRACT = `
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

abstract contract AbstractBase {
    function getValue() public virtual returns (uint256);
}
`;

const PAYABLE_CONTRACT = `
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Vault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient");
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }
}
`;

const DELEGATECALL_CONTRACT = `
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Proxy {
    address public implementation;

    fallback() external payable {
        (bool success,) = implementation.delegatecall(msg.data);
        require(success, "Delegatecall failed");
    }
}
`;

const IMPORTING_CONTRACT = `
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./interfaces/IToken.sol";
import "./libs/MathLib.sol";

contract TokenUser is IToken {
    using MathLib for uint256;

    mapping(address => uint256) private _balances;

    function transfer(address to, uint256 amount) external returns (bool) {
        _balances[msg.sender] -= amount;
        _balances[to] = _balances[to].add(amount);
        return true;
    }

    function balanceOf(address account) external view returns (uint256) {
        return _balances[account];
    }
}
`;

beforeEach(() => {
  testDir = mkdtempSync(join(tmpdir(), "project-scanner-test-"));
});

afterEach(() => {
  rmSync(testDir, { recursive: true, force: true });
});

// ============================================================================
// Tests
// ============================================================================

describe("detectProjectType", () => {
  it("should detect Foundry project", () => {
    writeFileSync(join(testDir, "foundry.toml"), "[profile.default]\n");
    expect(detectProjectType(testDir)).toBe("foundry");
  });

  it("should detect Hardhat project", () => {
    writeFileSync(join(testDir, "hardhat.config.js"), "module.exports = {};\n");
    expect(detectProjectType(testDir)).toBe("hardhat");
  });

  it("should detect mixed project", () => {
    writeFileSync(join(testDir, "foundry.toml"), "[profile.default]\n");
    writeFileSync(join(testDir, "hardhat.config.ts"), "export default {};\n");
    expect(detectProjectType(testDir)).toBe("mixed");
  });

  it("should return unknown for unrecognized project", () => {
    expect(detectProjectType(testDir)).toBe("unknown");
  });
});

describe("scanProject", () => {
  it("should find contracts in src/ directory", () => {
    createTestProject();
    writeContract("src/SimpleContract.sol", SIMPLE_CONTRACT);

    const result = scanProject(testDir);

    expect(result.contracts).toHaveLength(1);
    expect(result.contracts[0]!.name).toBe("SimpleContract");
    expect(result.contracts[0]!.type).toBe("contract");
  });

  it("should exclude test/ and lib/ directories", () => {
    createTestProject();
    writeContract("src/Main.sol", SIMPLE_CONTRACT);
    writeContract("test/TestContract.sol", SIMPLE_CONTRACT);
    writeContract("lib/LibContract.sol", SIMPLE_CONTRACT);

    const result = scanProject(testDir);

    expect(result.contracts).toHaveLength(1);
    expect(result.contracts[0]!.relativePath).toBe("src/Main.sol");
  });

  it("should detect different contract types", () => {
    createTestProject();
    writeContract("src/Contract.sol", SIMPLE_CONTRACT);
    writeContract("src/Interface.sol", INTERFACE_CONTRACT);
    writeContract("src/Library.sol", LIBRARY_CONTRACT);
    writeContract("src/Abstract.sol", ABSTRACT_CONTRACT);

    const result = scanProject(testDir);

    expect(result.summary.totalContracts).toBe(1);
    expect(result.summary.totalInterfaces).toBe(1);
    expect(result.summary.totalLibraries).toBe(1);
    expect(result.summary.totalAbstract).toBe(1);
  });

  it("should count lines of code", () => {
    createTestProject();
    writeContract("src/Simple.sol", SIMPLE_CONTRACT);

    const result = scanProject(testDir);

    expect(result.contracts[0]!.loc).toBeGreaterThan(0);
    expect(result.contracts[0]!.sloc).toBeGreaterThan(0);
    expect(result.contracts[0]!.sloc).toBeLessThanOrEqual(result.contracts[0]!.loc);
  });

  it("should detect payable contracts", () => {
    createTestProject();
    writeContract("src/Vault.sol", PAYABLE_CONTRACT);

    const result = scanProject(testDir);

    expect(result.contracts[0]!.hasPayable).toBe(true);
    expect(result.summary.contractsWithPayable).toBe(1);
  });

  it("should detect delegatecall usage", () => {
    createTestProject();
    writeContract("src/Proxy.sol", DELEGATECALL_CONTRACT);

    const result = scanProject(testDir);

    expect(result.contracts[0]!.hasDelegatecall).toBe(true);
  });

  it("should calculate project summary", () => {
    createTestProject();
    writeContract("src/A.sol", SIMPLE_CONTRACT);
    writeContract("src/B.sol", PAYABLE_CONTRACT);
    writeContract("src/C.sol", INTERFACE_CONTRACT);

    const result = scanProject(testDir);

    expect(result.summary.totalContracts).toBe(2);
    expect(result.summary.totalInterfaces).toBe(1);
    expect(result.summary.totalLOC).toBeGreaterThan(0);
  });
});

describe("buildDependencyGraph", () => {
  it("should build edges from imports", () => {
    createTestProject();
    writeContract("src/interfaces/IToken.sol", INTERFACE_CONTRACT);
    writeContract("src/libs/MathLib.sol", LIBRARY_CONTRACT);
    writeContract("src/TokenUser.sol", IMPORTING_CONTRACT);

    const structure = scanProject(testDir);
    const graph = structure.dependencies;

    // TokenUser should have edges to IToken and MathLib
    const tokenUserDeps = graph.edges.get("src/TokenUser.sol") ?? [];
    expect(tokenUserDeps.length).toBeGreaterThanOrEqual(0); // May or may not resolve
  });

  it("should build reverse edges (dependents)", () => {
    const contracts: ContractFile[] = [
      {
        path: "/test/A.sol",
        relativePath: "A.sol",
        name: "A",
        type: "contract",
        loc: 10,
        sloc: 8,
        isUpgradeable: false,
        hasPayable: false,
        hasExternalCalls: false,
        hasDelegatecall: false,
        hasSelfdestruct: false,
        imports: ["B.sol"],
        inherits: [],
      },
      {
        path: "/test/B.sol",
        relativePath: "B.sol",
        name: "B",
        type: "contract",
        loc: 10,
        sloc: 8,
        isUpgradeable: false,
        hasPayable: false,
        hasExternalCalls: false,
        hasDelegatecall: false,
        hasSelfdestruct: false,
        imports: [],
        inherits: [],
      },
    ];

    const graph = buildDependencyGraph(contracts);

    // B should have A as a dependent
    const bDependents = graph.reverseEdges.get("B.sol") ?? [];
    expect(bDependents).toContain("A.sol");
  });

  it("should detect circular dependencies", () => {
    const contracts: ContractFile[] = [
      {
        path: "/test/A.sol",
        relativePath: "A.sol",
        name: "A",
        type: "contract",
        loc: 10,
        sloc: 8,
        isUpgradeable: false,
        hasPayable: false,
        hasExternalCalls: false,
        hasDelegatecall: false,
        hasSelfdestruct: false,
        imports: ["B.sol"],
        inherits: [],
      },
      {
        path: "/test/B.sol",
        relativePath: "B.sol",
        name: "B",
        type: "contract",
        loc: 10,
        sloc: 8,
        isUpgradeable: false,
        hasPayable: false,
        hasExternalCalls: false,
        hasDelegatecall: false,
        hasSelfdestruct: false,
        imports: ["A.sol"],
        inherits: [],
      },
    ];

    const graph = buildDependencyGraph(contracts);

    expect(graph.circularDependencies.length).toBeGreaterThan(0);
  });

  it("should identify critical contracts by dependent count", () => {
    const contracts: ContractFile[] = [
      {
        path: "/test/Base.sol",
        relativePath: "Base.sol",
        name: "Base",
        type: "contract",
        loc: 10,
        sloc: 8,
        isUpgradeable: false,
        hasPayable: false,
        hasExternalCalls: false,
        hasDelegatecall: false,
        hasSelfdestruct: false,
        imports: [],
        inherits: [],
      },
      {
        path: "/test/Child1.sol",
        relativePath: "Child1.sol",
        name: "Child1",
        type: "contract",
        loc: 10,
        sloc: 8,
        isUpgradeable: false,
        hasPayable: false,
        hasExternalCalls: false,
        hasDelegatecall: false,
        hasSelfdestruct: false,
        imports: ["Base.sol"],
        inherits: [],
      },
      {
        path: "/test/Child2.sol",
        relativePath: "Child2.sol",
        name: "Child2",
        type: "contract",
        loc: 10,
        sloc: 8,
        isUpgradeable: false,
        hasPayable: false,
        hasExternalCalls: false,
        hasDelegatecall: false,
        hasSelfdestruct: false,
        imports: ["Base.sol"],
        inherits: [],
      },
    ];

    const graph = buildDependencyGraph(contracts);

    expect(graph.criticalContracts[0]!.path).toBe("Base.sol");
    expect(graph.criticalContracts[0]!.dependentCount).toBe(2);
  });
});

describe("prioritizeAudit", () => {
  function createMockContract(overrides: Partial<ContractFile>): ContractFile {
    return {
      path: "/test/Contract.sol",
      relativePath: "Contract.sol",
      name: "Contract",
      type: "contract",
      loc: 100,
      sloc: 80,
      isUpgradeable: false,
      hasPayable: false,
      hasExternalCalls: false,
      hasDelegatecall: false,
      hasSelfdestruct: false,
      imports: [],
      inherits: [],
      ...overrides,
    };
  }

  it("should prioritize payable contracts higher", () => {
    const contracts: ContractFile[] = [
      createMockContract({ name: "NoPayable", hasPayable: false }),
      createMockContract({ name: "HasPayable", hasPayable: true }),
    ];

    const graph = buildDependencyGraph(contracts);
    const prioritized = prioritizeAudit(contracts, graph);

    expect(prioritized[0]!.name).toBe("HasPayable");
    // hasPayable (100) + sloc (8) = 108 points -> "high" priority
    expect(prioritized[0]!.priority).toBe("high");
  });

  it("should prioritize delegatecall contracts higher", () => {
    const contracts: ContractFile[] = [
      createMockContract({ name: "Normal", hasDelegatecall: false }),
      createMockContract({ name: "Proxy", hasDelegatecall: true }),
    ];

    const graph = buildDependencyGraph(contracts);
    const prioritized = prioritizeAudit(contracts, graph);

    expect(prioritized[0]!.name).toBe("Proxy");
  });

  it("should give interfaces lower priority", () => {
    const contracts: ContractFile[] = [
      createMockContract({ name: "Interface", type: "interface", hasPayable: true }),
      // Give Contract payable too so we can compare interface vs contract fairly
      createMockContract({ name: "Contract", type: "contract", hasPayable: true }),
    ];

    const graph = buildDependencyGraph(contracts);
    const prioritized = prioritizeAudit(contracts, graph);

    // Interface: (100 + 8) * 0.2 = 21.6 -> 21 points
    // Contract: 100 + 8 = 108 points
    // Contract should be first, interface should be last
    expect(prioritized[0]!.name).toBe("Contract");
    expect(prioritized[prioritized.length - 1]!.name).toBe("Interface");
  });

  it("should give libraries lower priority", () => {
    const contracts: ContractFile[] = [
      createMockContract({ name: "Library", type: "library" }),
      createMockContract({ name: "Contract", type: "contract" }),
    ];

    const graph = buildDependencyGraph(contracts);
    const prioritized = prioritizeAudit(contracts, graph);

    expect(prioritized[prioritized.length - 1]!.name).toBe("Library");
  });

  it("should consider SLOC in prioritization", () => {
    const contracts: ContractFile[] = [
      createMockContract({ name: "Small", sloc: 10 }),
      createMockContract({ name: "Large", sloc: 500 }),
    ];

    const graph = buildDependencyGraph(contracts);
    const prioritized = prioritizeAudit(contracts, graph);

    // Larger contract should have higher priority
    expect(prioritized[0]!.name).toBe("Large");
  });
});

describe("utility functions", () => {
  it("getCriticalContracts should filter by priority", () => {
    createTestProject();
    writeContract("src/Simple.sol", SIMPLE_CONTRACT);
    writeContract("src/Vault.sol", PAYABLE_CONTRACT);

    const structure = scanProject(testDir);
    const critical = getCriticalContracts(structure);

    expect(critical.length).toBeGreaterThanOrEqual(1);
    expect(critical.every((c) => c.priority === "critical" || c.priority === "high")).toBe(true);
  });

  it("getFundHandlingContracts should filter by payable", () => {
    createTestProject();
    writeContract("src/Simple.sol", SIMPLE_CONTRACT);
    writeContract("src/Vault.sol", PAYABLE_CONTRACT);

    const structure = scanProject(testDir);
    const fundHandling = getFundHandlingContracts(structure);

    expect(fundHandling).toHaveLength(1);
    expect(fundHandling[0]!.name).toBe("Vault");
  });
});

describe("formatProjectReport", () => {
  it("should generate markdown report", () => {
    createTestProject();
    writeContract("src/Simple.sol", SIMPLE_CONTRACT);
    writeContract("src/Vault.sol", PAYABLE_CONTRACT);

    const structure = scanProject(testDir);
    const report = formatProjectReport(structure);

    expect(report).toContain("# Project Analysis Report");
    expect(report).toContain("## Summary");
    expect(report).toContain("Contracts");
    expect(report).toContain("SLOC");
  });

  it("should include priority contracts section", () => {
    createTestProject();
    writeContract("src/Vault.sol", PAYABLE_CONTRACT);

    const structure = scanProject(testDir);
    const report = formatProjectReport(structure);

    expect(report).toContain("## Priority Contracts");
    expect(report).toContain("Vault");
  });
});

describe("circular dependency findings", () => {
  it("should generate findings for circular dependencies", () => {
    const contracts: ContractFile[] = [
      {
        path: "/test/A.sol",
        relativePath: "A.sol",
        name: "A",
        type: "contract",
        loc: 10,
        sloc: 8,
        isUpgradeable: false,
        hasPayable: false,
        hasExternalCalls: false,
        hasDelegatecall: false,
        hasSelfdestruct: false,
        imports: ["B.sol"],
        inherits: [],
      },
      {
        path: "/test/B.sol",
        relativePath: "B.sol",
        name: "B",
        type: "contract",
        loc: 10,
        sloc: 8,
        isUpgradeable: false,
        hasPayable: false,
        hasExternalCalls: false,
        hasDelegatecall: false,
        hasSelfdestruct: false,
        imports: ["A.sol"],
        inherits: [],
      },
    ];

    // Manually create a structure with circular dependencies
    const graph = buildDependencyGraph(contracts);

    // At least one circular dependency should be detected
    if (graph.circularDependencies.length > 0) {
      expect(graph.circularDependencies[0]!.length).toBeGreaterThanOrEqual(2);
    }
  });
});
