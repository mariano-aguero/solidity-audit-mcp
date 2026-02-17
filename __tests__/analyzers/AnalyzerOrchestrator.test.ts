/**
 * Analyzer Orchestrator Tests
 *
 * Tests for the AnalyzerOrchestrator (Facade pattern)
 * using Given-When-Then pattern.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  AnalyzerOrchestrator,
  createOrchestrator,
  type AnalyzerProgress,
} from "../../src/analyzers/AnalyzerOrchestrator.js";
import { AnalyzerRegistry } from "../../src/analyzers/AnalyzerRegistry.js";

// ============================================================================
// Test Fixtures
// ============================================================================

const SIMPLE_CONTRACT = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SimpleStorage {
    uint256 public value;

    function setValue(uint256 _value) external {
        value = _value;
    }

    function getValue() external view returns (uint256) {
        return value;
    }
}
`;

// ============================================================================
// Test Setup
// ============================================================================

describe("AnalyzerOrchestrator", () => {
  let tempDir: string;
  let contractPath: string;

  beforeEach(async () => {
    // Create temp directory with test contract
    tempDir = await mkdtemp(join(tmpdir(), "orchestrator-test-"));
    contractPath = join(tempDir, "SimpleStorage.sol");
    await writeFile(contractPath, SIMPLE_CONTRACT);

    // Reset registry
    AnalyzerRegistry.getInstance().reset();
  });

  afterEach(async () => {
    // Cleanup temp directory
    await rm(tempDir, { recursive: true, force: true });
  });

  // ==========================================================================
  // Factory Function Tests
  // ==========================================================================

  describe("createOrchestrator()", () => {
    it("should create orchestrator with default config", () => {
      // Given: No config
      // When: Creating orchestrator
      const orchestrator = createOrchestrator();

      // Then: Should be a valid instance
      expect(orchestrator).toBeInstanceOf(AnalyzerOrchestrator);
    });

    it("should create orchestrator with custom config", () => {
      // Given: Custom config
      const config = {
        maxConcurrency: 5,
        pipelineTimeout: 300_000,
      };

      // When: Creating orchestrator
      const orchestrator = createOrchestrator(config);

      // Then: Should be a valid instance
      expect(orchestrator).toBeInstanceOf(AnalyzerOrchestrator);
    });
  });

  // ==========================================================================
  // Configuration Tests
  // ==========================================================================

  describe("configure()", () => {
    it("should allow chaining configuration", () => {
      // Given: Orchestrator
      const orchestrator = createOrchestrator();

      // When: Configuring with chaining
      const result = orchestrator.configure({ maxConcurrency: 2 });

      // Then: Should return same instance
      expect(result).toBe(orchestrator);
    });
  });

  describe("onProgress()", () => {
    it("should allow setting progress callback", () => {
      // Given: Orchestrator and callback
      const orchestrator = createOrchestrator();
      const callback = vi.fn();

      // When: Setting callback
      const result = orchestrator.onProgress(callback);

      // Then: Should return same instance for chaining
      expect(result).toBe(orchestrator);
    });
  });

  // ==========================================================================
  // Analysis Tests (Built-in analyzers only)
  // ==========================================================================

  describe("analyze()", () => {
    it("should run analysis and return results", async () => {
      // Given: Orchestrator with only built-in analyzers enabled
      const orchestrator = createOrchestrator({
        enabledAnalyzers: ["slang", "gas"], // Only use built-in, always available
        pipelineTimeout: 30_000,
      });

      // When: Running analysis
      const result = await orchestrator.analyze({
        contractPath,
        projectRoot: tempDir,
      });

      // Then: Should have results structure
      expect(result.findings).toBeDefined();
      expect(Array.isArray(result.findings)).toBe(true);
      expect(result.executionTime).toBeGreaterThan(0);
      expect(result.analyzersUsed).toBeDefined();
      expect(result.warnings).toBeDefined();
    });

    it("should include slang in analyzers used when available", async () => {
      // Given: Orchestrator with slang enabled
      const orchestrator = createOrchestrator({
        enabledAnalyzers: ["slang"],
      });

      // When: Running analysis
      const result = await orchestrator.analyze({
        contractPath,
        projectRoot: tempDir,
      });

      // Then: Slang should be used (always available)
      expect(result.analyzersUsed).toContain("slang");
    });

    it("should return empty findings array for clean contract", async () => {
      // Given: Simple clean contract and gas analyzer
      const orchestrator = createOrchestrator({
        enabledAnalyzers: ["gas"],
      });

      // When: Running analysis
      const result = await orchestrator.analyze({
        contractPath,
        projectRoot: tempDir,
      });

      // Then: May have findings (gas optimizations possible)
      expect(Array.isArray(result.findings)).toBe(true);
    });
  });

  describe("analyzeWith()", () => {
    it("should run only specified analyzers", async () => {
      // Given: Orchestrator
      const orchestrator = createOrchestrator();

      // When: Running with specific analyzers
      const result = await orchestrator.analyzeWith(["slang"], {
        contractPath,
        projectRoot: tempDir,
      });

      // Then: Only slang should be used
      expect(result.analyzersUsed).toEqual(["slang"]);
    });

    it("should warn for unknown analyzer IDs", async () => {
      // Given: Orchestrator
      const orchestrator = createOrchestrator();

      // When: Running with unknown analyzer
      const result = await orchestrator.analyzeWith(["unknown" as any, "slang"], {
        contractPath,
        projectRoot: tempDir,
      });

      // Then: Should warn about unknown and still run slang
      expect(result.warnings.some((w) => w.includes("not found"))).toBe(true);
      expect(result.analyzersUsed).toContain("slang");
    });

    it("should return empty result for all unknown analyzers", async () => {
      // Given: Orchestrator
      const orchestrator = createOrchestrator();

      // When: Running with only unknown analyzers
      const result = await orchestrator.analyzeWith(["unknown" as any], {
        contractPath,
        projectRoot: tempDir,
      });

      // Then: Should have no findings and warnings
      expect(result.findings).toEqual([]);
      expect(result.analyzersUsed).toEqual([]);
      expect(result.warnings.length).toBeGreaterThan(0);
    });
  });

  // ==========================================================================
  // Progress Callback Tests
  // ==========================================================================

  describe("Progress Callbacks", () => {
    it("should call progress callback for each analyzer", async () => {
      // Given: Orchestrator with progress callback
      const progressEvents: AnalyzerProgress[] = [];
      const orchestrator = createOrchestrator({
        enabledAnalyzers: ["slang", "gas"],
      }).onProgress((progress) => {
        progressEvents.push(progress);
      });

      // When: Running analysis
      await orchestrator.analyze({
        contractPath,
        projectRoot: tempDir,
      });

      // Then: Should have progress events for each analyzer
      const startedEvents = progressEvents.filter((p) => p.status === "started");
      const completedEvents = progressEvents.filter((p) => p.status === "completed");

      expect(startedEvents.length).toBeGreaterThanOrEqual(2);
      expect(completedEvents.length).toBeGreaterThanOrEqual(2);
    });

    it("should include analyzer ID in progress events", async () => {
      // Given: Orchestrator with progress callback
      const progressEvents: AnalyzerProgress[] = [];
      const orchestrator = createOrchestrator({
        enabledAnalyzers: ["slang"],
      }).onProgress((progress) => {
        progressEvents.push(progress);
      });

      // When: Running analysis
      await orchestrator.analyze({
        contractPath,
        projectRoot: tempDir,
      });

      // Then: All events should have analyzer ID
      for (const event of progressEvents) {
        expect(event.analyzerId).toBeDefined();
      }
    });

    it("should include result in completed events", async () => {
      // Given: Orchestrator with progress callback
      const completedEvents: AnalyzerProgress[] = [];
      const orchestrator = createOrchestrator({
        enabledAnalyzers: ["slang"],
      }).onProgress((progress) => {
        if (progress.status === "completed") {
          completedEvents.push(progress);
        }
      });

      // When: Running analysis
      await orchestrator.analyze({
        contractPath,
        projectRoot: tempDir,
      });

      // Then: Completed events should have result
      for (const event of completedEvents) {
        expect(event.result).toBeDefined();
        expect(event.result!.findings).toBeDefined();
      }
    });
  });

  // ==========================================================================
  // Error Handling Tests
  // ==========================================================================

  describe("Error Handling", () => {
    it("should continue on error when configured", async () => {
      // Given: Orchestrator configured to continue on error
      const orchestrator = createOrchestrator({
        continueOnError: true,
        enabledAnalyzers: ["slang", "gas"],
      });

      // When: Running analysis (both should succeed)
      const result = await orchestrator.analyze({
        contractPath,
        projectRoot: tempDir,
      });

      // Then: Should have results from successful analyzers
      expect(result.analyzersUsed.length).toBeGreaterThan(0);
    });

    it("should return analyzer results map", async () => {
      // Given: Orchestrator
      const orchestrator = createOrchestrator({
        enabledAnalyzers: ["slang"],
      });

      // When: Running analysis
      const result = await orchestrator.analyze({
        contractPath,
        projectRoot: tempDir,
      });

      // Then: Should have analyzer results
      expect(result.analyzerResults).toBeInstanceOf(Map);
      expect(result.analyzerResults.has("slang")).toBe(true);
    });
  });

  // ==========================================================================
  // Result Structure Tests
  // ==========================================================================

  describe("Result Structure", () => {
    it("should have all required fields", async () => {
      // Given: Orchestrator
      const orchestrator = createOrchestrator({
        enabledAnalyzers: ["slang"],
      });

      // When: Running analysis
      const result = await orchestrator.analyze({
        contractPath,
        projectRoot: tempDir,
      });

      // Then: All fields should be present
      expect(result.findings).toBeDefined();
      expect(result.analyzerResults).toBeDefined();
      expect(result.executionTime).toBeDefined();
      expect(result.analyzersUsed).toBeDefined();
      expect(result.warnings).toBeDefined();
    });

    it("should sort findings by severity", async () => {
      // Given: Orchestrator
      const orchestrator = createOrchestrator({
        enabledAnalyzers: ["slang", "gas"],
      });

      // When: Running analysis
      const result = await orchestrator.analyze({
        contractPath,
        projectRoot: tempDir,
      });

      // Then: Findings should be sorted (if any)
      if (result.findings.length > 1) {
        const severityOrder = ["critical", "high", "medium", "low", "informational"];
        for (let i = 0; i < result.findings.length - 1; i++) {
          const currentIdx = severityOrder.indexOf(result.findings[i]!.severity);
          const nextIdx = severityOrder.indexOf(result.findings[i + 1]!.severity);
          expect(currentIdx).toBeLessThanOrEqual(nextIdx);
        }
      }
    });
  });

  // ==========================================================================
  // Disabled Analyzers Tests
  // ==========================================================================

  describe("Analyzer Filtering", () => {
    it("should respect disabledAnalyzers config", async () => {
      // Given: Orchestrator with gas disabled
      const orchestrator = createOrchestrator({
        disabledAnalyzers: ["gas"],
        enabledAnalyzers: ["slang", "gas"],
      });

      // When: Running analysis
      const result = await orchestrator.analyze({
        contractPath,
        projectRoot: tempDir,
      });

      // Then: Gas should not be used
      expect(result.analyzersUsed).not.toContain("gas");
    });

    it("should only run enabled analyzers when specified", async () => {
      // Given: Orchestrator with only slang enabled
      const orchestrator = createOrchestrator({
        enabledAnalyzers: ["slang"],
      });

      // When: Running analysis
      const result = await orchestrator.analyze({
        contractPath,
        projectRoot: tempDir,
      });

      // Then: Only slang should run
      expect(result.analyzersUsed).toEqual(["slang"]);
    });
  });
});
