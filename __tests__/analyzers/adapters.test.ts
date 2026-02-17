/**
 * Analyzer Adapters Tests
 *
 * Tests for individual analyzer adapters using Given-When-Then pattern.
 * Tests focus on interface compliance and capability declarations.
 */

import { describe, it, expect, beforeEach } from "vitest";
import { SlitherAdapter } from "../../src/analyzers/adapters/SlitherAdapter.js";
import { AderynAdapter } from "../../src/analyzers/adapters/AderynAdapter.js";
import { SlangAdapter } from "../../src/analyzers/adapters/SlangAdapter.js";
import { GasAdapter } from "../../src/analyzers/adapters/GasAdapter.js";
import type { IAnalyzer } from "../../src/analyzers/IAnalyzer.js";
import type { AnalyzerCapabilities } from "../../src/analyzers/types.js";

// ============================================================================
// Shared Adapter Tests
// ============================================================================

function testAdapterInterface(
  name: string,
  createAdapter: () => IAnalyzer,
  expectedCapabilities: Partial<AnalyzerCapabilities>
) {
  describe(`${name} Adapter Interface`, () => {
    let adapter: IAnalyzer;

    beforeEach(() => {
      adapter = createAdapter();
    });

    // ========================================================================
    // Identity Tests
    // ========================================================================

    describe("Identity", () => {
      it("should have a valid ID", () => {
        // Given: Adapter instance
        // When: Checking ID
        // Then: Should be a non-empty string
        expect(typeof adapter.id).toBe("string");
        expect(adapter.id.length).toBeGreaterThan(0);
      });

      it("should have a descriptive name", () => {
        // Given: Adapter instance
        // When: Checking name
        // Then: Should be a non-empty string
        expect(typeof adapter.name).toBe("string");
        expect(adapter.name.length).toBeGreaterThan(0);
      });

      it("should have a description", () => {
        // Given: Adapter instance
        // When: Checking description
        // Then: Should explain what the analyzer does
        expect(typeof adapter.description).toBe("string");
        expect(adapter.description.length).toBeGreaterThan(20);
      });
    });

    // ========================================================================
    // Capabilities Tests
    // ========================================================================

    describe("Capabilities", () => {
      it("should declare requiresExternalTool correctly", () => {
        // Given: Adapter instance
        // When: Checking capability
        // Then: Should match expected value
        if (expectedCapabilities.requiresExternalTool !== undefined) {
          expect(adapter.capabilities.requiresExternalTool).toBe(
            expectedCapabilities.requiresExternalTool
          );
        }
      });

      it("should have detectorCount greater than 0", () => {
        // Given: Adapter instance
        // When: Checking detector count
        // Then: Should have at least 1 detector
        expect(adapter.capabilities.detectorCount).toBeGreaterThan(0);
      });

      it("should support parallel execution", () => {
        // Given: Adapter instance
        // When: Checking parallel support
        // Then: Should support it
        expect(adapter.capabilities.supportsParallel).toBe(true);
      });
    });

    // ========================================================================
    // Default Options Tests
    // ========================================================================

    describe("Default Options", () => {
      it("should return default options", () => {
        // Given: Adapter instance
        // When: Getting default options
        const options = adapter.getDefaultOptions();

        // Then: Should have timeout
        expect(options.timeout).toBeDefined();
        expect(typeof options.timeout).toBe("number");
        expect(options.timeout).toBeGreaterThan(0);
      });

      it("should have reasonable timeout", () => {
        // Given: Adapter instance
        // When: Getting default options
        const options = adapter.getDefaultOptions();

        // Then: Timeout should be between 30s and 5min
        expect(options.timeout).toBeGreaterThanOrEqual(30_000);
        expect(options.timeout).toBeLessThanOrEqual(300_000);
      });
    });

    // ========================================================================
    // Availability Tests
    // ========================================================================

    describe("Availability", () => {
      it("should return availability status", async () => {
        // Given: Adapter instance
        // When: Checking availability
        const availability = await adapter.checkAvailability();

        // Then: Should have required fields
        expect(availability.analyzerId).toBe(adapter.id);
        expect(availability.status).toBeDefined();
        expect(availability.message).toBeDefined();
      });

      it("should return valid status value", async () => {
        // Given: Adapter instance
        // When: Checking availability
        const availability = await adapter.checkAvailability();

        // Then: Status should be one of valid values
        expect(["available", "unavailable", "error", "disabled"]).toContain(availability.status);
      });
    });
  });
}

// ============================================================================
// Slither Adapter Tests
// ============================================================================

testAdapterInterface("Slither", () => new SlitherAdapter(), {
  requiresExternalTool: true,
});

describe("SlitherAdapter Specific", () => {
  let adapter: SlitherAdapter;

  beforeEach(() => {
    adapter = new SlitherAdapter();
  });

  it("should have slither as external tool name", () => {
    // Given: Slither adapter
    // When: Checking external tool name
    // Then: Should be "slither"
    expect(adapter.capabilities.externalToolName).toBe("slither");
  });

  it("should have approximately 90 detectors", () => {
    // Given: Slither adapter
    // When: Checking detector count
    // Then: Should be around 90
    expect(adapter.capabilities.detectorCount).toBeGreaterThanOrEqual(80);
    expect(adapter.capabilities.detectorCount).toBeLessThanOrEqual(150);
  });

  it("should not support source input (requires file)", () => {
    // Given: Slither adapter
    // When: Checking source support
    // Then: Should be false
    expect(adapter.capabilities.supportsSourceInput).toBe(false);
  });

  it("should have filter paths in default options", () => {
    // Given: Slither adapter
    // When: Getting default options
    const options = adapter.getDefaultOptions();

    // Then: Should have filter paths
    expect(options.filterPaths).toBeDefined();
    expect(Array.isArray(options.filterPaths)).toBe(true);
    expect(options.filterPaths!.length).toBeGreaterThan(0);
  });
});

// ============================================================================
// Aderyn Adapter Tests
// ============================================================================

testAdapterInterface("Aderyn", () => new AderynAdapter(), {
  requiresExternalTool: true,
});

describe("AderynAdapter Specific", () => {
  let adapter: AderynAdapter;

  beforeEach(() => {
    adapter = new AderynAdapter();
  });

  it("should have aderyn as external tool name", () => {
    // Given: Aderyn adapter
    // When: Checking external tool name
    // Then: Should be "aderyn"
    expect(adapter.capabilities.externalToolName).toBe("aderyn");
  });

  it("should have approximately 50 detectors", () => {
    // Given: Aderyn adapter
    // When: Checking detector count
    // Then: Should be around 50
    expect(adapter.capabilities.detectorCount).toBeGreaterThanOrEqual(40);
    expect(adapter.capabilities.detectorCount).toBeLessThanOrEqual(100);
  });

  it("should have exclude paths in default options", () => {
    // Given: Aderyn adapter
    // When: Getting default options
    const options = adapter.getDefaultOptions();

    // Then: Should have exclude paths
    expect(options.exclude).toBeDefined();
    expect(Array.isArray(options.exclude)).toBe(true);
  });
});

// ============================================================================
// Slang Adapter Tests
// ============================================================================

testAdapterInterface("Slang", () => new SlangAdapter(), {
  requiresExternalTool: false,
});

describe("SlangAdapter Specific", () => {
  let adapter: SlangAdapter;

  beforeEach(() => {
    adapter = new SlangAdapter();
  });

  it("should not require external tool", () => {
    // Given: Slang adapter (JavaScript library)
    // When: Checking requirement
    // Then: Should not require external tool
    expect(adapter.capabilities.requiresExternalTool).toBe(false);
  });

  it("should support source input", () => {
    // Given: Slang adapter
    // When: Checking source support
    // Then: Should support it
    expect(adapter.capabilities.supportsSourceInput).toBe(true);
  });

  it("should always be available", async () => {
    // Given: Slang adapter (no external dependency)
    // When: Checking availability
    const availability = await adapter.checkAvailability();

    // Then: Should always be available
    expect(availability.status).toBe("available");
  });

  it("should include informational by default", () => {
    // Given: Slang adapter
    // When: Getting default options
    const options = adapter.getDefaultOptions();

    // Then: Should include informational
    expect(options.includeInformational).toBe(true);
  });
});

// ============================================================================
// Gas Adapter Tests
// ============================================================================

testAdapterInterface("Gas", () => new GasAdapter(), {
  requiresExternalTool: false,
});

describe("GasAdapter Specific", () => {
  let adapter: GasAdapter;

  beforeEach(() => {
    adapter = new GasAdapter();
  });

  it("should not require external tool", () => {
    // Given: Gas adapter (JavaScript)
    // When: Checking requirement
    // Then: Should not require external tool
    expect(adapter.capabilities.requiresExternalTool).toBe(false);
  });

  it("should support source input", () => {
    // Given: Gas adapter
    // When: Checking source support
    // Then: Should support it
    expect(adapter.capabilities.supportsSourceInput).toBe(true);
  });

  it("should always be available", async () => {
    // Given: Gas adapter (no external dependency)
    // When: Checking availability
    const availability = await adapter.checkAvailability();

    // Then: Should always be available
    expect(availability.status).toBe("available");
  });

  it("should have 10 pattern detectors", () => {
    // Given: Gas adapter
    // When: Checking detector count
    // Then: Should have 10 patterns
    expect(adapter.capabilities.detectorCount).toBe(10);
  });

  it("should have shorter timeout than security analyzers", () => {
    // Given: Gas adapter
    // When: Getting default options
    const options = adapter.getDefaultOptions();

    // Then: Should be 30 seconds (faster analysis)
    expect(options.timeout).toBeLessThanOrEqual(60_000);
  });
});

// ============================================================================
// Singleton Instances Tests
// ============================================================================

describe("Singleton Adapter Instances", () => {
  it("should export slitherAdapter singleton", async () => {
    const { slitherAdapter } = await import("../../src/analyzers/adapters/SlitherAdapter.js");
    expect(slitherAdapter).toBeDefined();
    expect(slitherAdapter.id).toBe("slither");
  });

  it("should export aderynAdapter singleton", async () => {
    const { aderynAdapter } = await import("../../src/analyzers/adapters/AderynAdapter.js");
    expect(aderynAdapter).toBeDefined();
    expect(aderynAdapter.id).toBe("aderyn");
  });

  it("should export slangAdapter singleton", async () => {
    const { slangAdapter } = await import("../../src/analyzers/adapters/SlangAdapter.js");
    expect(slangAdapter).toBeDefined();
    expect(slangAdapter.id).toBe("slang");
  });

  it("should export gasAdapter singleton", async () => {
    const { gasAdapter } = await import("../../src/analyzers/adapters/GasAdapter.js");
    expect(gasAdapter).toBeDefined();
    expect(gasAdapter.id).toBe("gas");
  });
});
