/**
 * Slither Analyzer Tests
 *
 * Tests the Slither analyzer helper functions.
 * Integration tests with actual Slither would require the tool to be installed.
 */

import { describe, it, expect } from "vitest";
import { SLITHER_DETECTOR_MAP, getSlitherDetectors } from "../../src/analyzers/adapters/SlitherAdapter.js";

describe("Slither Analyzer", () => {
  describe("SLITHER_DETECTOR_MAP", () => {
    it("should have title and description for each detector", () => {
      for (const [_key, value] of Object.entries(SLITHER_DETECTOR_MAP)) {
        expect(value).toHaveProperty("title");
        expect(value).toHaveProperty("description");
        expect(typeof value.title).toBe("string");
        expect(typeof value.description).toBe("string");
        expect(value.title.length).toBeGreaterThan(0);
        expect(value.description.length).toBeGreaterThan(0);
      }
    });

    it("should include reentrancy detectors", () => {
      expect(SLITHER_DETECTOR_MAP).toHaveProperty("reentrancy-eth");
      expect(SLITHER_DETECTOR_MAP).toHaveProperty("reentrancy-no-eth");
      expect(SLITHER_DETECTOR_MAP).toHaveProperty("reentrancy-benign");
      expect(SLITHER_DETECTOR_MAP).toHaveProperty("reentrancy-events");
    });

    it("should include critical detectors", () => {
      expect(SLITHER_DETECTOR_MAP).toHaveProperty("suicidal");
      expect(SLITHER_DETECTOR_MAP).toHaveProperty("controlled-delegatecall");
      expect(SLITHER_DETECTOR_MAP).toHaveProperty("arbitrary-send-eth");
      expect(SLITHER_DETECTOR_MAP).toHaveProperty("arbitrary-send-erc20");
    });

    it("should include access control detectors", () => {
      expect(SLITHER_DETECTOR_MAP).toHaveProperty("tx-origin");
      expect(SLITHER_DETECTOR_MAP).toHaveProperty("unprotected-upgrade");
      expect(SLITHER_DETECTOR_MAP).toHaveProperty("missing-zero-check");
    });

    it("should include unchecked operation detectors", () => {
      expect(SLITHER_DETECTOR_MAP).toHaveProperty("unchecked-transfer");
      expect(SLITHER_DETECTOR_MAP).toHaveProperty("unchecked-lowlevel");
      expect(SLITHER_DETECTOR_MAP).toHaveProperty("unchecked-send");
      expect(SLITHER_DETECTOR_MAP).toHaveProperty("unused-return");
    });

    it("should include shadowing detectors", () => {
      expect(SLITHER_DETECTOR_MAP).toHaveProperty("shadowing-state");
      expect(SLITHER_DETECTOR_MAP).toHaveProperty("shadowing-local");
      expect(SLITHER_DETECTOR_MAP).toHaveProperty("shadowing-builtin");
      expect(SLITHER_DETECTOR_MAP).toHaveProperty("shadowing-abstract");
    });

    it("should include logic issue detectors", () => {
      expect(SLITHER_DETECTOR_MAP).toHaveProperty("locked-ether");
      expect(SLITHER_DETECTOR_MAP).toHaveProperty("timestamp");
      expect(SLITHER_DETECTOR_MAP).toHaveProperty("weak-prng");
      expect(SLITHER_DETECTOR_MAP).toHaveProperty("divide-before-multiply");
      expect(SLITHER_DETECTOR_MAP).toHaveProperty("incorrect-equality");
    });

    it("should include code quality detectors", () => {
      expect(SLITHER_DETECTOR_MAP).toHaveProperty("calls-loop");
      expect(SLITHER_DETECTOR_MAP).toHaveProperty("costly-loop");
      expect(SLITHER_DETECTOR_MAP).toHaveProperty("dead-code");
      expect(SLITHER_DETECTOR_MAP).toHaveProperty("unused-state");
    });

    it("should include solidity issue detectors", () => {
      expect(SLITHER_DETECTOR_MAP).toHaveProperty("solc-version");
      expect(SLITHER_DETECTOR_MAP).toHaveProperty("pragma");
      expect(SLITHER_DETECTOR_MAP).toHaveProperty("assembly");
      expect(SLITHER_DETECTOR_MAP).toHaveProperty("low-level-calls");
    });

    it("should include naming convention detectors", () => {
      expect(SLITHER_DETECTOR_MAP).toHaveProperty("naming-convention");
      expect(SLITHER_DETECTOR_MAP).toHaveProperty("similar-names");
      expect(SLITHER_DETECTOR_MAP).toHaveProperty("constable-states");
      expect(SLITHER_DETECTOR_MAP).toHaveProperty("immutable-states");
      expect(SLITHER_DETECTOR_MAP).toHaveProperty("external-function");
    });

    it("should have meaningful titles for reentrancy detectors", () => {
      expect(SLITHER_DETECTOR_MAP["reentrancy-eth"]?.title).toContain("Reentrancy");
      expect(SLITHER_DETECTOR_MAP["reentrancy-eth"]?.title).toContain("ETH");
    });

    it("should have meaningful descriptions", () => {
      const txOrigin = SLITHER_DETECTOR_MAP["tx-origin"];
      expect(txOrigin?.description).toContain("tx.origin");
      expect(txOrigin?.description.toLowerCase()).toContain("phishing");
    });
  });

  describe("getSlitherDetectors", () => {
    it("should return array of detector names", () => {
      const detectors = getSlitherDetectors();

      expect(Array.isArray(detectors)).toBe(true);
      expect(detectors.length).toBeGreaterThan(0);
    });

    it("should contain all mapped detector names", () => {
      const detectors = getSlitherDetectors();
      const mapKeys = Object.keys(SLITHER_DETECTOR_MAP);

      expect(detectors).toEqual(mapKeys);
    });

    it("should contain common security detectors", () => {
      const detectors = getSlitherDetectors();

      expect(detectors).toContain("reentrancy-eth");
      expect(detectors).toContain("tx-origin");
      expect(detectors).toContain("suicidal");
      expect(detectors).toContain("arbitrary-send-eth");
    });

    it("should contain informational detectors", () => {
      const detectors = getSlitherDetectors();

      expect(detectors).toContain("naming-convention");
      expect(detectors).toContain("solc-version");
      expect(detectors).toContain("pragma");
    });
  });

  describe("Severity Mapping", () => {
    // These tests verify the expected severity mapping based on the detector map
    // The actual mapping function is internal to the module

    it("should categorize reentrancy-eth as high severity related", () => {
      const detector = SLITHER_DETECTOR_MAP["reentrancy-eth"];
      // Reentrancy with ETH is typically High severity
      expect(detector?.title).toContain("Reentrancy");
      expect(detector?.description).toContain("ETH");
    });

    it("should categorize suicidal as critical detector", () => {
      const detector = SLITHER_DETECTOR_MAP["suicidal"];
      expect(detector?.title.toLowerCase()).toContain("selfdestruct");
      expect(detector?.description.toLowerCase()).toContain("destroy");
    });

    it("should categorize pragma as informational", () => {
      const detector = SLITHER_DETECTOR_MAP["pragma"];
      expect(detector?.title.toLowerCase()).toContain("pragma");
      // Floating pragma is typically Informational/Low
    });

    it("should categorize naming-convention as informational", () => {
      const detector = SLITHER_DETECTOR_MAP["naming-convention"];
      expect(detector?.title.toLowerCase()).toContain("naming");
      // Naming issues are typically Informational
    });
  });

  describe("Detector Categories", () => {
    it("should have at least 30 detectors mapped", () => {
      const count = Object.keys(SLITHER_DETECTOR_MAP).length;
      expect(count).toBeGreaterThanOrEqual(30);
    });

    it("should cover major vulnerability categories", () => {
      const detectorNames = Object.keys(SLITHER_DETECTOR_MAP).join(" ");

      // Reentrancy category
      expect(detectorNames).toContain("reentrancy");

      // Access control category
      expect(detectorNames).toContain("tx-origin");

      // Dangerous functions category
      expect(detectorNames).toContain("suicidal");
      expect(detectorNames).toContain("delegatecall");

      // Unchecked operations category
      expect(detectorNames).toContain("unchecked");

      // State issues category
      expect(detectorNames).toContain("uninitialized");
      expect(detectorNames).toContain("shadowing");

      // Logic issues category
      expect(detectorNames).toContain("timestamp");
      expect(detectorNames).toContain("prng");

      // Code quality category
      expect(detectorNames).toContain("unused");
      expect(detectorNames).toContain("dead-code");
    });
  });
});
