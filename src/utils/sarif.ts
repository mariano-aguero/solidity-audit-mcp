/**
 * SARIF Report Generator
 *
 * Generates Static Analysis Results Interchange Format (SARIF) reports
 * for integration with GitHub Code Scanning and other SARIF-compatible tools.
 *
 * SARIF Specification: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
 */

import { basename } from "path";
import { Finding, Severity } from "../types/index.js";

// ============================================================================
// SARIF Types
// ============================================================================

interface SarifReport {
  $schema: string;
  version: string;
  runs: SarifRun[];
}

interface SarifRun {
  tool: SarifTool;
  results: SarifResult[];
  artifacts?: SarifArtifact[];
}

interface SarifTool {
  driver: SarifDriver;
}

interface SarifDriver {
  name: string;
  version: string;
  informationUri: string;
  rules: SarifRule[];
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: {
    text: string;
  };
  fullDescription?: {
    text: string;
  };
  helpUri?: string;
  help?: {
    text: string;
    markdown?: string;
  };
  defaultConfiguration: {
    level: SarifLevel;
  };
  properties?: {
    tags?: string[];
    precision?: string;
    "security-severity"?: string;
  };
}

interface SarifResult {
  ruleId: string;
  ruleIndex: number;
  level: SarifLevel;
  message: {
    text: string;
  };
  locations: SarifLocation[];
  fingerprints?: Record<string, string>;
  properties?: Record<string, unknown>;
}

interface SarifLocation {
  physicalLocation: {
    artifactLocation: {
      uri: string;
      uriBaseId?: string;
    };
    region?: {
      startLine: number;
      endLine?: number;
      startColumn?: number;
      endColumn?: number;
    };
  };
  logicalLocations?: Array<{
    name?: string;
    fullyQualifiedName?: string;
    kind?: string;
  }>;
}

interface SarifArtifact {
  location: {
    uri: string;
  };
  sourceLanguage?: string;
}

type SarifLevel = "none" | "note" | "warning" | "error";

// ============================================================================
// SARIF Generation
// ============================================================================

/**
 * Generate a SARIF report from findings.
 */
export function generateSarifReport(findings: Finding[], contractPath: string): SarifReport {
  const rules = extractRules(findings);
  const results = findings.map((finding, index) => convertFindingToResult(finding, rules, index));

  return {
    $schema:
      "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "solidity-audit-mcp",
            version: "1.0.0",
            informationUri: "https://github.com/anthropics/solidity-audit-mcp",
            rules,
          },
        },
        results,
        artifacts: [
          {
            location: {
              uri: contractPath,
            },
            sourceLanguage: "solidity",
          },
        ],
      },
    ],
  };
}

/**
 * Extract unique rules from findings.
 */
function extractRules(findings: Finding[]): SarifRule[] {
  const rulesMap = new Map<string, SarifRule>();

  for (const finding of findings) {
    const ruleId = getRuleId(finding);

    if (!rulesMap.has(ruleId)) {
      rulesMap.set(ruleId, {
        id: ruleId,
        name: finding.title,
        shortDescription: {
          text: finding.title,
        },
        fullDescription: {
          text: finding.description,
        },
        help: {
          text: finding.recommendation,
          markdown: `**Recommendation:** ${finding.recommendation}`,
        },
        defaultConfiguration: {
          level: severityToLevel(finding.severity),
        },
        properties: {
          tags: getTagsForFinding(finding),
          precision: finding.confidence === "high" ? "very-high" : finding.confidence,
          "security-severity": getSecuritySeverityScore(finding.severity),
        },
      });
    }
  }

  return Array.from(rulesMap.values());
}

/**
 * Convert a finding to a SARIF result.
 */
function convertFindingToResult(finding: Finding, rules: SarifRule[], _index: number): SarifResult {
  const ruleId = getRuleId(finding);
  const ruleIndex = rules.findIndex((r) => r.id === ruleId);

  const locations: SarifLocation[] = [];

  // Physical location
  const physicalLocation: SarifLocation["physicalLocation"] = {
    artifactLocation: {
      uri: finding.location.file,
    },
  };

  if (finding.location.lines) {
    physicalLocation.region = {
      startLine: finding.location.lines[0],
      endLine: finding.location.lines[1],
    };
  }

  const location: SarifLocation = { physicalLocation };

  // Add logical location if function is specified
  if (finding.location.function) {
    location.logicalLocations = [
      {
        name: finding.location.function,
        fullyQualifiedName: `${basename(finding.location.file, ".sol")}.${finding.location.function}`,
        kind: "function",
      },
    ];
  }

  locations.push(location);

  return {
    ruleId,
    ruleIndex: ruleIndex >= 0 ? ruleIndex : 0,
    level: severityToLevel(finding.severity),
    message: {
      text: `${finding.description}\n\nRecommendation: ${finding.recommendation}`,
    },
    locations,
    fingerprints: {
      primaryLocationLineHash: createFingerprint(finding),
    },
    properties: {
      detector: finding.detector,
      confidence: finding.confidence,
      swcId: finding.swcId,
    },
  };
}

/**
 * Get rule ID from finding.
 */
function getRuleId(finding: Finding): string {
  // Use detector + title to create a stable rule ID
  const baseId = finding.detector.replace(/[^a-zA-Z0-9]/g, "-");
  return `${baseId}/${finding.id.split("-")[0] ?? "unknown"}`;
}

/**
 * Convert severity to SARIF level.
 */
function severityToLevel(severity: Severity): SarifLevel {
  switch (severity) {
    case Severity.CRITICAL:
    case Severity.HIGH:
      return "error";
    case Severity.MEDIUM:
      return "warning";
    case Severity.LOW:
    case Severity.INFORMATIONAL:
      return "note";
    default:
      return "note";
  }
}

/**
 * Get security severity score (0.0-10.0 scale for GitHub).
 */
function getSecuritySeverityScore(severity: Severity): string {
  switch (severity) {
    case Severity.CRITICAL:
      return "9.0";
    case Severity.HIGH:
      return "7.0";
    case Severity.MEDIUM:
      return "5.0";
    case Severity.LOW:
      return "3.0";
    case Severity.INFORMATIONAL:
      return "1.0";
    default:
      return "1.0";
  }
}

/**
 * Get tags for a finding based on its type and content.
 */
function getTagsForFinding(finding: Finding): string[] {
  const tags: string[] = ["security", "smart-contract", "solidity"];

  // Add detector-based tags
  if (finding.detector.includes("slither")) {
    tags.push("slither");
  } else if (finding.detector.includes("aderyn")) {
    tags.push("aderyn");
  } else if (finding.detector.includes("gas")) {
    tags.push("gas-optimization");
  } else if (finding.detector.includes("custom")) {
    tags.push("custom-detector");
  }

  // Add SWC tag if present
  if (finding.swcId) {
    tags.push(finding.swcId);
  }

  // Add common vulnerability tags based on content
  const lowerDesc = finding.description.toLowerCase();
  const lowerTitle = finding.title.toLowerCase();

  if (lowerDesc.includes("reentrancy") || lowerTitle.includes("reentrancy")) {
    tags.push("reentrancy");
  }
  if (lowerDesc.includes("overflow") || lowerTitle.includes("overflow")) {
    tags.push("integer-overflow");
  }
  if (lowerDesc.includes("access control") || lowerTitle.includes("access")) {
    tags.push("access-control");
  }
  if (lowerDesc.includes("denial of service") || lowerDesc.includes("dos")) {
    tags.push("denial-of-service");
  }

  return tags;
}

/**
 * Create a fingerprint for the finding.
 */
function createFingerprint(finding: Finding): string {
  const parts = [
    finding.detector,
    finding.title,
    finding.location.file,
    finding.location.function ?? "",
    finding.location.lines?.join("-") ?? "",
  ];

  // Simple hash
  let hash = 0;
  const str = parts.join("|");
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = (hash << 5) - hash + char;
    hash = hash & hash; // Convert to 32-bit integer
  }

  return Math.abs(hash).toString(16).padStart(8, "0");
}

// ============================================================================
// Exports
// ============================================================================

export type { SarifReport, SarifRun, SarifResult, SarifRule };
