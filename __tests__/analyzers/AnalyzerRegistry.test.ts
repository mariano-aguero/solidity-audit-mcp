/**
 * Analyzer Registry Tests
 *
 * Tests for the AnalyzerRegistry (Factory + Registry pattern)
 * using Given-When-Then pattern.
 */

import { describe, it, expect, beforeEach } from "vitest";
import { AnalyzerRegistry, getAnalyzerRegistry } from "../../src/analyzers/AnalyzerRegistry.js";
import type { AnalyzerId } from "../../src/analyzers/types.js";

// ============================================================================
// Test Setup
// ============================================================================

describe("AnalyzerRegistry", () => {
  let registry: AnalyzerRegistry;

  beforeEach(() => {
    registry = AnalyzerRegistry.getInstance();
    registry.reset(); // Reset to clean state
  });

  // ==========================================================================
  // Singleton Pattern Tests
  // ==========================================================================

  describe("Singleton Pattern", () => {
    it("should return the same instance on multiple calls", () => {
      // Given: Multiple calls to getInstance
      // When: Getting instances
      const instance1 = AnalyzerRegistry.getInstance();
      const instance2 = AnalyzerRegistry.getInstance();

      // Then: Should be the same instance
      expect(instance1).toBe(instance2);
    });

    it("should return same instance via helper function", () => {
      // Given: Direct and helper access
      // When: Getting instances
      const direct = AnalyzerRegistry.getInstance();
      const helper = getAnalyzerRegistry();

      // Then: Should be the same instance
      expect(direct).toBe(helper);
    });
  });

  // ==========================================================================
  // Built-in Analyzer Registration
  // ==========================================================================

  describe("Built-in Analyzers", () => {
    it("should register all built-in analyzers on initialization", () => {
      // Given: Fresh registry
      // When: Getting all analyzer IDs
      const ids = registry.getIds();

      // Then: Should have all built-in analyzers
      expect(ids).toContain("slither");
      expect(ids).toContain("aderyn");
      expect(ids).toContain("slang");
      expect(ids).toContain("gas");
    });

    it("should have correct count of built-in analyzers", () => {
      // Given: Fresh registry
      // When: Getting all analyzers
      const analyzers = registry.getAll();

      // Then: Should have 4 built-in analyzers
      expect(analyzers.length).toBe(4);
    });

    it("should have registration info for all built-in analyzers", () => {
      // Given: Fresh registry
      // When: Getting registrations
      const registrations = registry.getAllRegistrations();

      // Then: Each should have required fields
      for (const reg of registrations) {
        expect(reg.id).toBeDefined();
        expect(reg.name).toBeDefined();
        expect(reg.description).toBeDefined();
        expect(reg.capabilities).toBeDefined();
        expect(reg.defaultOptions).toBeDefined();
      }
    });
  });

  // ==========================================================================
  // Analyzer Lookup
  // ==========================================================================

  describe("get()", () => {
    it("should return analyzer by valid ID", () => {
      // Given: Registry with slither analyzer
      // When: Getting slither
      const analyzer = registry.get("slither");

      // Then: Should return the analyzer
      expect(analyzer).toBeDefined();
      expect(analyzer!.id).toBe("slither");
    });

    it("should return undefined for unknown ID", () => {
      // Given: Registry without "unknown" analyzer
      // When: Getting unknown analyzer
      const analyzer = registry.get("unknown" as AnalyzerId);

      // Then: Should return undefined
      expect(analyzer).toBeUndefined();
    });
  });

  describe("getOrThrow()", () => {
    it("should return analyzer for valid ID", () => {
      // Given: Registry with aderyn analyzer
      // When: Getting aderyn
      const analyzer = registry.getOrThrow("aderyn");

      // Then: Should return the analyzer
      expect(analyzer.id).toBe("aderyn");
    });

    it("should throw for unknown ID", () => {
      // Given: Registry without "unknown" analyzer
      // When/Then: Should throw
      expect(() => registry.getOrThrow("unknown" as AnalyzerId)).toThrow(
        "Analyzer not found: unknown"
      );
    });
  });

  describe("getRegistration()", () => {
    it("should return registration info for valid ID", () => {
      // Given: Registry with slang analyzer
      // When: Getting registration
      const reg = registry.getRegistration("slang");

      // Then: Should have correct info
      expect(reg).toBeDefined();
      expect(reg!.id).toBe("slang");
      expect(reg!.name).toBe("Slang AST Analyzer");
    });

    it("should return undefined for unknown ID", () => {
      // Given: Registry without "unknown"
      // When: Getting registration
      const reg = registry.getRegistration("unknown" as AnalyzerId);

      // Then: Should be undefined
      expect(reg).toBeUndefined();
    });
  });

  // ==========================================================================
  // Filtering Methods
  // ==========================================================================

  describe("getBuiltIn()", () => {
    it("should return only analyzers without external tool dependency", () => {
      // Given: Registry with mixed analyzers
      // When: Getting built-in analyzers
      const builtIn = registry.getBuiltIn();

      // Then: All should not require external tools
      for (const analyzer of builtIn) {
        expect(analyzer.capabilities.requiresExternalTool).toBe(false);
      }
    });

    it("should include slang and gas analyzers", () => {
      // Given: Registry
      // When: Getting built-in analyzers
      const builtIn = registry.getBuiltIn();
      const ids = builtIn.map((a) => a.id);

      // Then: Should include slang and gas
      expect(ids).toContain("slang");
      expect(ids).toContain("gas");
    });
  });

  describe("getExternal()", () => {
    it("should return only analyzers requiring external tools", () => {
      // Given: Registry with mixed analyzers
      // When: Getting external analyzers
      const external = registry.getExternal();

      // Then: All should require external tools
      for (const analyzer of external) {
        expect(analyzer.capabilities.requiresExternalTool).toBe(true);
      }
    });

    it("should include slither and aderyn analyzers", () => {
      // Given: Registry
      // When: Getting external analyzers
      const external = registry.getExternal();
      const ids = external.map((a) => a.id);

      // Then: Should include slither and aderyn
      expect(ids).toContain("slither");
      expect(ids).toContain("aderyn");
    });
  });

  describe("getSourceBased()", () => {
    it("should return analyzers that support source input", () => {
      // Given: Registry
      // When: Getting source-based analyzers
      const sourceBased = registry.getSourceBased();

      // Then: All should support source input
      for (const analyzer of sourceBased) {
        expect(analyzer.capabilities.supportsSourceInput).toBe(true);
      }
    });
  });

  // ==========================================================================
  // Availability Checking
  // ==========================================================================

  describe("checkAvailability()", () => {
    it("should return availability for known analyzer", async () => {
      // Given: Registry with slang analyzer (always available)
      // When: Checking availability
      const availability = await registry.checkAvailability("slang");

      // Then: Should be available (no external dependency)
      expect(availability.analyzerId).toBe("slang");
      expect(availability.status).toBe("available");
    });

    it("should return unavailable for unknown analyzer", async () => {
      // Given: Unknown analyzer ID
      // When: Checking availability
      const availability = await registry.checkAvailability("unknown" as AnalyzerId);

      // Then: Should be unavailable
      expect(availability.status).toBe("unavailable");
      expect(availability.message).toContain("not registered");
    });
  });

  describe("checkAllAvailability()", () => {
    it("should check availability for all registered analyzers", async () => {
      // Given: Registry with all analyzers
      // When: Checking all availability
      const availabilityMap = await registry.checkAllAvailability();

      // Then: Should have entry for each analyzer
      const ids = registry.getIds();
      for (const id of ids) {
        expect(availabilityMap.has(id)).toBe(true);
      }
    });

    it("should return Map with correct structure", async () => {
      // Given: Registry
      // When: Checking all availability
      const availabilityMap = await registry.checkAllAvailability();

      // Then: Each entry should have required fields
      for (const [id, availability] of availabilityMap) {
        expect(availability.analyzerId).toBe(id);
        expect(availability.status).toBeDefined();
        expect(availability.message).toBeDefined();
      }
    });
  });

  describe("getAvailable()", () => {
    it("should return at least built-in analyzers", async () => {
      // Given: Registry with built-in analyzers
      // When: Getting available analyzers
      const available = await registry.getAvailable();

      // Then: Should include at least slang and gas (always available)
      const ids = available.map((a) => a.id);
      expect(ids).toContain("slang");
      expect(ids).toContain("gas");
    });
  });

  // ==========================================================================
  // Summary
  // ==========================================================================

  describe("getSummary()", () => {
    it("should return formatted summary string", () => {
      // Given: Registry with analyzers
      // When: Getting summary
      const summary = registry.getSummary();

      // Then: Should contain analyzer information
      expect(summary).toContain("Registered Analyzers");
      expect(summary).toContain("slither");
      expect(summary).toContain("aderyn");
      expect(summary).toContain("slang");
      expect(summary).toContain("gas");
    });

    it("should indicate external vs built-in", () => {
      // Given: Registry
      // When: Getting summary
      const summary = registry.getSummary();

      // Then: Should have labels
      expect(summary).toContain("external");
      expect(summary).toContain("built-in");
    });
  });

  // ==========================================================================
  // Reset
  // ==========================================================================

  describe("reset()", () => {
    it("should restore to initial state after modifications", () => {
      // Given: Registry with custom analyzer unregistered
      registry.unregister("slither");
      expect(registry.get("slither")).toBeUndefined();

      // When: Resetting
      registry.reset();

      // Then: Slither should be back
      expect(registry.get("slither")).toBeDefined();
    });
  });
});
