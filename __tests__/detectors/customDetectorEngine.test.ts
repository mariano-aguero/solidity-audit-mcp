/**
 * Custom Detector Engine Tests
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { writeFile, mkdir, rm } from "fs/promises";
import { join } from "path";
import {
  loadCustomDetectors,
  runCustomDetectors,
  getAvailablePresets,
  type CustomDetector,
} from "../../src/detectors/customDetectorEngine.js";
import { Severity } from "../../src/types/index.js";

const TEST_DIR = join(process.cwd(), "__tests__/fixtures/custom-detectors");

// Test contracts
const TEST_CONTRACT = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "hardhat/console.sol";

contract TestContract {
    address public constant ADMIN = 0x1234567890123456789012345678901234567890;
    uint256 public value;
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function _internalHelper() internal pure returns (uint256) {
        return 42;
    }

    function publicHelper() public pure returns (uint256) {
        return 42;
    }

    function setValue(uint256 _value) external onlyOwner {
        value = _value;
        console.log("Value set to", _value);
    }

    function complexFunction(
        uint256 a,
        uint256 b,
        uint256 c,
        address d,
        bool e,
        bytes memory f
    ) external {
        if (a > 0) {
            if (b > 0) {
                if (c > 0) {
                    if (e) {
                        value = a + b + c;
                    }
                }
            }
        }
    }

    function withdraw() external payable onlyOwner {
        payable(msg.sender).transfer(address(this).balance);
    }
}
`;

// Valid JSON config
const VALID_JSON_CONFIG = {
  detectors: [
    {
      id: "no-hardcoded-addresses",
      title: "Hardcoded Address Detected",
      description: "Contract contains hardcoded Ethereum addresses",
      severity: "LOW",
      pattern: "0x[a-fA-F0-9]{40}",
      type: "regex",
      exclude: ["test/", "script/"],
      recommendation: "Use constructor parameters for addresses",
    },
    {
      id: "no-console-log",
      title: "Console.log Left in Code",
      description: "Hardhat console.log import found",
      severity: "INFORMATIONAL",
      pattern: "import.*console",
      type: "regex",
      recommendation: "Remove console.log imports before deployment",
    },
    {
      id: "requires-timelock",
      title: "Admin Function Without Timelock",
      description: "Functions with onlyOwner that change state should use a timelock",
      severity: "MEDIUM",
      type: "ast-pattern",
      match: {
        hasModifier: "onlyOwner",
        modifiesState: true,
        notHasModifier: "timelocked",
      },
      recommendation: "Add a timelock mechanism for admin functions",
    },
    {
      id: "max-function-complexity",
      title: "Function Too Complex",
      description: "Function has too many lines or nested conditions",
      severity: "LOW",
      type: "complexity",
      threshold: { maxLines: 10, maxDepth: 3 },
      recommendation: "Break down complex functions into smaller units",
    },
    {
      id: "internal-underscore-prefix",
      title: "Internal Function Missing Underscore Prefix",
      description: "Internal functions should start with underscore",
      severity: "INFORMATIONAL",
      type: "naming",
      rules: [
        {
          target: "function",
          pattern: "^_",
          shouldMatch: true,
          scope: "internal",
        },
      ],
      recommendation: "Prefix internal functions with underscore",
    },
  ],
};

// Valid YAML config
const VALID_YAML_CONFIG = `
detectors:
  - id: no-hardcoded-addresses
    title: Hardcoded Address Detected
    description: Contract contains hardcoded Ethereum addresses
    severity: LOW
    pattern: "0x[a-fA-F0-9]{40}"
    type: regex
    recommendation: Use constructor parameters for addresses
`;

// Invalid config (wrong severity)
const INVALID_CONFIG = {
  detectors: [
    {
      id: "test",
      title: "Test",
      description: "Test detector",
      severity: "INVALID_SEVERITY",
      pattern: "test",
      type: "regex",
      recommendation: "Fix it",
    },
  ],
};

describe("Custom Detector Engine", () => {
  beforeAll(async () => {
    await mkdir(TEST_DIR, { recursive: true });
  });

  afterAll(async () => {
    await rm(TEST_DIR, { recursive: true, force: true });
  });

  describe("loadCustomDetectors", () => {
    it("should load detectors from JSON config", async () => {
      await writeFile(
        join(TEST_DIR, ".audit-detectors.json"),
        JSON.stringify(VALID_JSON_CONFIG, null, 2)
      );

      const detectors = await loadCustomDetectors(TEST_DIR);

      expect(detectors).toHaveLength(5);
      expect(detectors[0]!.id).toBe("no-hardcoded-addresses");
      expect(detectors[0]!.type).toBe("regex");
    });

    it("should load detectors from YAML config", async () => {
      // Remove JSON first
      await rm(join(TEST_DIR, ".audit-detectors.json"), { force: true });
      await writeFile(join(TEST_DIR, ".audit-detectors.yml"), VALID_YAML_CONFIG);

      const detectors = await loadCustomDetectors(TEST_DIR);

      expect(detectors).toHaveLength(1);
      expect(detectors[0]!.id).toBe("no-hardcoded-addresses");
    });

    it("should return empty array when no config exists", async () => {
      await rm(join(TEST_DIR, ".audit-detectors.yml"), { force: true });

      const detectors = await loadCustomDetectors(TEST_DIR);

      expect(detectors).toHaveLength(0);
    });

    it("should return empty array for invalid config", async () => {
      await writeFile(
        join(TEST_DIR, ".audit-detectors.json"),
        JSON.stringify(INVALID_CONFIG, null, 2)
      );

      const detectors = await loadCustomDetectors(TEST_DIR);

      expect(detectors).toHaveLength(0);
    });

    it("should prefer JSON over YAML when both exist", async () => {
      await writeFile(
        join(TEST_DIR, ".audit-detectors.json"),
        JSON.stringify(VALID_JSON_CONFIG, null, 2)
      );
      await writeFile(join(TEST_DIR, ".audit-detectors.yml"), VALID_YAML_CONFIG);

      const detectors = await loadCustomDetectors(TEST_DIR);

      expect(detectors).toHaveLength(5); // JSON has 5, YAML has 1
    });

    it("should load detectors from presets via extends", async () => {
      const configWithExtends = {
        extends: ["web3"],
        detectors: [],
      };

      await writeFile(
        join(TEST_DIR, ".audit-detectors.json"),
        JSON.stringify(configWithExtends, null, 2)
      );

      const detectors = await loadCustomDetectors(TEST_DIR);

      // web3 preset has 10 detectors
      expect(detectors.length).toBeGreaterThanOrEqual(10);
      expect(detectors.some((d) => d.id === "no-hardcoded-addresses")).toBe(true);
      expect(detectors.some((d) => d.id === "no-console-log")).toBe(true);
    });

    it("should merge preset and custom detectors", async () => {
      const configWithExtends = {
        extends: ["web3"],
        detectors: [
          {
            id: "custom-rule",
            title: "Custom Rule",
            description: "A custom rule",
            severity: "LOW",
            type: "regex",
            pattern: "customPattern",
            recommendation: "Fix it",
          },
        ],
      };

      await writeFile(
        join(TEST_DIR, ".audit-detectors.json"),
        JSON.stringify(configWithExtends, null, 2)
      );

      const detectors = await loadCustomDetectors(TEST_DIR);

      // Should have web3 presets + 1 custom
      expect(detectors.length).toBeGreaterThanOrEqual(11);
      expect(detectors.some((d) => d.id === "custom-rule")).toBe(true);
      expect(detectors.some((d) => d.id === "no-hardcoded-addresses")).toBe(true);
    });

    it("should allow custom detectors to override preset detectors", async () => {
      const configWithOverride = {
        extends: ["web3"],
        detectors: [
          {
            id: "no-hardcoded-addresses", // Same ID as preset
            title: "Custom Hardcoded Address Rule",
            description: "Overridden rule",
            severity: "HIGH", // Changed severity
            type: "regex",
            pattern: "0x[a-fA-F0-9]{40}",
            recommendation: "Custom recommendation",
          },
        ],
      };

      await writeFile(
        join(TEST_DIR, ".audit-detectors.json"),
        JSON.stringify(configWithOverride, null, 2)
      );

      const detectors = await loadCustomDetectors(TEST_DIR);

      // Find the detector with this ID
      const addressDetector = detectors.find((d) => d.id === "no-hardcoded-addresses");
      expect(addressDetector).toBeDefined();
      expect(addressDetector!.title).toBe("Custom Hardcoded Address Rule");
      expect(addressDetector!.severity).toBe("HIGH");
    });

    it("should handle multiple presets", async () => {
      const configWithMultiplePresets = {
        extends: ["web3", "defi"],
        detectors: [],
      };

      await writeFile(
        join(TEST_DIR, ".audit-detectors.json"),
        JSON.stringify(configWithMultiplePresets, null, 2)
      );

      const detectors = await loadCustomDetectors(TEST_DIR);

      // Should have detectors from both presets
      expect(detectors.some((d) => d.id === "no-console-log")).toBe(true); // from web3
      expect(detectors.some((d) => d.id === "oracle-manipulation")).toBe(true); // from defi
    });

    it("should handle non-existent preset gracefully", async () => {
      const configWithBadPreset = {
        extends: ["non-existent-preset"],
        detectors: [
          {
            id: "custom-rule",
            title: "Custom Rule",
            description: "A custom rule",
            severity: "LOW",
            type: "regex",
            pattern: "test",
            recommendation: "Fix it",
          },
        ],
      };

      await writeFile(
        join(TEST_DIR, ".audit-detectors.json"),
        JSON.stringify(configWithBadPreset, null, 2)
      );

      const detectors = await loadCustomDetectors(TEST_DIR);

      // Should still load custom detectors even if preset fails
      expect(detectors).toHaveLength(1);
      expect(detectors[0]!.id).toBe("custom-rule");
    });
  });

  describe("getAvailablePresets", () => {
    it("should return list of available presets", async () => {
      const presets = await getAvailablePresets();

      expect(presets).toContain("web3");
      expect(presets).toContain("defi");
    });
  });

  describe("runCustomDetectors - regex type", () => {
    const regexDetector: CustomDetector = {
      id: "no-hardcoded-addresses",
      title: "Hardcoded Address Detected",
      description: "Contract contains hardcoded Ethereum addresses",
      severity: "LOW",
      pattern: "0x[a-fA-F0-9]{40}",
      type: "regex",
      recommendation: "Use constructor parameters for addresses",
    };

    it("should detect hardcoded addresses", () => {
      const findings = runCustomDetectors(TEST_CONTRACT, "test.sol", [regexDetector]);

      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0]!.title).toBe("Hardcoded Address Detected");
      expect(findings[0]!.severity).toBe(Severity.LOW);
      expect(findings[0]!.detector).toBe("custom:no-hardcoded-addresses");
    });

    it("should respect exclude patterns", () => {
      const detectorWithExclude: CustomDetector = {
        ...regexDetector,
        exclude: ["test/"],
      };

      // File path relative to projectRoot should match the exclude pattern
      const findings = runCustomDetectors(
        TEST_CONTRACT,
        "/project/test/Contract.sol",
        [detectorWithExclude],
        "/project"
      );

      expect(findings).toHaveLength(0);
    });

    it("should detect console.log imports", () => {
      const consoleDetector: CustomDetector = {
        id: "no-console-log",
        title: "Console.log Left in Code",
        description: "Hardhat console.log import found",
        severity: "INFORMATIONAL",
        pattern: "import.*console",
        type: "regex",
        recommendation: "Remove console.log imports",
      };

      const findings = runCustomDetectors(TEST_CONTRACT, "test.sol", [consoleDetector]);

      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0]!.title).toBe("Console.log Left in Code");
    });
  });

  describe("runCustomDetectors - ast-pattern type", () => {
    const astDetector: CustomDetector = {
      id: "requires-timelock",
      title: "Admin Function Without Timelock",
      description: "Functions with onlyOwner that change state should use a timelock",
      severity: "MEDIUM",
      type: "ast-pattern",
      match: {
        hasModifier: "onlyOwner",
        modifiesState: true,
        notHasModifier: "timelocked",
      },
      recommendation: "Add a timelock mechanism",
    };

    it("should detect functions with onlyOwner that modify state", () => {
      const findings = runCustomDetectors(TEST_CONTRACT, "test.sol", [astDetector]);

      expect(findings.length).toBeGreaterThan(0);
      // setValue and withdraw both have onlyOwner and modify state
      const functionNames = findings.map((f) => f.location.function);
      expect(functionNames).toContain("setValue");
      expect(functionNames).toContain("withdraw");
    });

    it("should detect payable functions", () => {
      const payableDetector: CustomDetector = {
        id: "payable-function",
        title: "Payable Function",
        description: "Function is payable",
        severity: "INFORMATIONAL",
        type: "ast-pattern",
        match: {
          isPayable: true,
        },
        recommendation: "Review payable functions",
      };

      const findings = runCustomDetectors(TEST_CONTRACT, "test.sol", [payableDetector]);

      expect(findings.length).toBeGreaterThan(0);
      expect(findings.some((f) => f.location.function === "withdraw")).toBe(true);
    });

    it("should filter by visibility", () => {
      const externalDetector: CustomDetector = {
        id: "external-function",
        title: "External Function",
        description: "Function is external",
        severity: "INFORMATIONAL",
        type: "ast-pattern",
        match: {
          hasVisibility: "external",
        },
        recommendation: "Review external functions",
      };

      const findings = runCustomDetectors(TEST_CONTRACT, "test.sol", [externalDetector]);

      expect(findings.length).toBeGreaterThan(0);
      // Should find setValue, complexFunction, withdraw
      const functionNames = findings.map((f) => f.location.function);
      expect(functionNames).toContain("setValue");
      expect(functionNames).toContain("complexFunction");
    });
  });

  describe("runCustomDetectors - complexity type", () => {
    const complexityDetector: CustomDetector = {
      id: "max-function-complexity",
      title: "Function Too Complex",
      description: "Function has too many lines or nested conditions",
      severity: "LOW",
      type: "complexity",
      threshold: { maxLines: 10, maxDepth: 3 },
      recommendation: "Break down complex functions",
    };

    it("should detect complex functions", () => {
      const findings = runCustomDetectors(TEST_CONTRACT, "test.sol", [complexityDetector]);

      expect(findings.length).toBeGreaterThan(0);
      expect(findings.some((f) => f.location.function === "complexFunction")).toBe(true);
    });

    it("should include violation details in description", () => {
      const findings = runCustomDetectors(TEST_CONTRACT, "test.sol", [complexityDetector]);

      const complexFinding = findings.find((f) => f.location.function === "complexFunction");
      expect(complexFinding).toBeDefined();
      expect(complexFinding!.description).toContain("Violations:");
    });

    it("should detect functions with many parameters", () => {
      const paramDetector: CustomDetector = {
        id: "max-parameters",
        title: "Too Many Parameters",
        description: "Function has too many parameters",
        severity: "INFORMATIONAL",
        type: "complexity",
        threshold: { maxParameters: 3 },
        recommendation: "Use a struct for multiple parameters",
      };

      const findings = runCustomDetectors(TEST_CONTRACT, "test.sol", [paramDetector]);

      expect(findings.length).toBeGreaterThan(0);
      expect(findings.some((f) => f.location.function === "complexFunction")).toBe(true);
    });
  });

  describe("runCustomDetectors - naming type", () => {
    it("should detect internal functions without underscore prefix", () => {
      const contractWithBadNaming = `
        pragma solidity ^0.8.0;
        contract Test {
            function badInternal() internal {}
            function _goodInternal() internal {}
        }
      `;

      const namingDetector: CustomDetector = {
        id: "internal-underscore",
        title: "Missing Underscore Prefix",
        description: "Internal functions should start with underscore",
        severity: "INFORMATIONAL",
        type: "naming",
        rules: [
          {
            target: "function",
            pattern: "^_",
            shouldMatch: true,
            scope: "internal",
          },
        ],
        recommendation: "Add underscore prefix",
      };

      const findings = runCustomDetectors(contractWithBadNaming, "test.sol", [namingDetector]);

      expect(findings.length).toBe(1);
      expect(findings[0]!.description).toContain("badInternal");
    });

    it("should enforce constant naming conventions", () => {
      const contractWithConstants = `
        pragma solidity ^0.8.0;
        contract Test {
            uint256 public constant maxValue = 100;
            uint256 public constant MAX_SIZE = 200;
        }
      `;

      const constantNamingDetector: CustomDetector = {
        id: "constant-naming",
        title: "Constant Should Be UPPER_CASE",
        description: "Constants should use UPPER_CASE naming",
        severity: "INFORMATIONAL",
        type: "naming",
        rules: [
          {
            target: "constant",
            pattern: "^[A-Z][A-Z0-9_]*$",
            shouldMatch: true,
          },
        ],
        recommendation: "Use UPPER_CASE for constants",
      };

      const findings = runCustomDetectors(contractWithConstants, "test.sol", [
        constantNamingDetector,
      ]);

      expect(findings.length).toBe(1);
      expect(findings[0]!.description).toContain("maxValue");
    });
  });

  describe("runCustomDetectors - multiple detectors", () => {
    it("should run multiple detectors and combine findings", () => {
      const detectors: CustomDetector[] = [
        {
          id: "addresses",
          title: "Hardcoded Address",
          description: "Found hardcoded address",
          severity: "LOW",
          pattern: "0x[a-fA-F0-9]{40}",
          type: "regex",
          recommendation: "Remove",
        },
        {
          id: "console",
          title: "Console Log",
          description: "Found console import",
          severity: "INFORMATIONAL",
          pattern: "import.*console",
          type: "regex",
          recommendation: "Remove",
        },
      ];

      const findings = runCustomDetectors(TEST_CONTRACT, "test.sol", detectors);

      expect(findings.length).toBeGreaterThan(1);
      expect(findings.some((f) => f.detector === "custom:addresses")).toBe(true);
      expect(findings.some((f) => f.detector === "custom:console")).toBe(true);
    });
  });

  describe("edge cases", () => {
    it("should handle empty source", () => {
      const detector: CustomDetector = {
        id: "test",
        title: "Test",
        description: "Test detector",
        severity: "LOW",
        pattern: "anything",
        type: "regex",
        recommendation: "Fix it",
      };

      const findings = runCustomDetectors("", "test.sol", [detector]);

      expect(findings).toHaveLength(0);
    });

    it("should handle empty detectors array", () => {
      const findings = runCustomDetectors(TEST_CONTRACT, "test.sol", []);

      expect(findings).toHaveLength(0);
    });

    it("should handle invalid regex gracefully", () => {
      const detector: CustomDetector = {
        id: "invalid-regex",
        title: "Invalid Regex",
        description: "This has an invalid regex",
        severity: "LOW",
        pattern: "[invalid(regex",
        type: "regex",
        recommendation: "Fix it",
      };

      expect(() => runCustomDetectors(TEST_CONTRACT, "test.sol", [detector])).toThrow();
    });
  });

  describe("finding structure", () => {
    it("should have correct finding structure", () => {
      const detector: CustomDetector = {
        id: "test-detector",
        title: "Test Detector",
        description: "Test description",
        severity: "HIGH",
        pattern: "pragma",
        type: "regex",
        recommendation: "Test recommendation",
      };

      const findings = runCustomDetectors(TEST_CONTRACT, "test.sol", [detector]);

      expect(findings.length).toBeGreaterThan(0);
      const finding = findings[0]!;

      expect(finding.id).toMatch(/^CUSTOM-test-detector-\d+$/);
      expect(finding.title).toBe("Test Detector");
      expect(finding.severity).toBe(Severity.HIGH);
      expect(finding.description).toContain("Test description");
      expect(finding.location.file).toBe("test.sol");
      expect(finding.location.lines).toBeDefined();
      expect(finding.recommendation).toBe("Test recommendation");
      expect(finding.detector).toBe("custom:test-detector");
      expect(finding.confidence).toBe("high");
    });
  });
});
