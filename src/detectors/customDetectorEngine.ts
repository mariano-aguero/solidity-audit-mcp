/**
 * Custom Detector Engine
 *
 * Allows users to define custom security detectors in a config file
 * (.audit-detectors.json or .audit-detectors.yml) at the project root.
 *
 * Supports multiple detector types:
 * - regex: Pattern matching in source code
 * - ast-pattern: Function/modifier/state analysis
 * - complexity: Function complexity metrics
 * - naming: Naming convention checks
 */

import { z } from "zod";
import { existsSync } from "fs";
import { readFile } from "fs/promises";
import { join, relative, basename, dirname } from "path";
import { fileURLToPath } from "url";
import { parse as parseYaml } from "yaml";
import { Finding, Severity } from "../types/index.js";
import { logger } from "../utils/logger.js";

// Get the directory of this module for resolving presets
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const PRESETS_DIR = join(__dirname, "presets");

// ============================================================================
// Schema Definitions
// ============================================================================

const SeveritySchema = z.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]);

const RegexDetectorSchema = z.object({
  id: z.string(),
  title: z.string(),
  description: z.string(),
  severity: SeveritySchema,
  type: z.literal("regex"),
  pattern: z.string(),
  exclude: z.array(z.string()).optional(),
  recommendation: z.string(),
  multiline: z.boolean().optional(),
  caseInsensitive: z.boolean().optional(),
});

const AstPatternMatchSchema = z.object({
  hasModifier: z.string().optional(),
  notHasModifier: z.string().optional(),
  hasVisibility: z.enum(["public", "external", "internal", "private"]).optional(),
  modifiesState: z.boolean().optional(),
  isPayable: z.boolean().optional(),
  hasParameter: z.string().optional(),
  callsFunction: z.string().optional(),
  usesAssembly: z.boolean().optional(),
});

const AstPatternDetectorSchema = z.object({
  id: z.string(),
  title: z.string(),
  description: z.string(),
  severity: SeveritySchema,
  type: z.literal("ast-pattern"),
  match: AstPatternMatchSchema,
  exclude: z.array(z.string()).optional(),
  recommendation: z.string(),
});

const ComplexityThresholdSchema = z.object({
  maxLines: z.number().optional(),
  maxDepth: z.number().optional(),
  maxParameters: z.number().optional(),
  maxStatements: z.number().optional(),
});

const ComplexityDetectorSchema = z.object({
  id: z.string(),
  title: z.string(),
  description: z.string(),
  severity: SeveritySchema,
  type: z.literal("complexity"),
  threshold: ComplexityThresholdSchema,
  exclude: z.array(z.string()).optional(),
  recommendation: z.string(),
});

const NamingRuleSchema = z.object({
  target: z.enum(["function", "variable", "constant", "event", "modifier", "parameter"]),
  pattern: z.string(),
  shouldMatch: z.boolean().default(true),
  scope: z.enum(["internal", "private", "public", "external", "all"]).optional(),
});

const NamingDetectorSchema = z.object({
  id: z.string(),
  title: z.string(),
  description: z.string(),
  severity: SeveritySchema,
  type: z.literal("naming"),
  rules: z.array(NamingRuleSchema),
  exclude: z.array(z.string()).optional(),
  recommendation: z.string(),
});

const CustomDetectorSchema = z.discriminatedUnion("type", [
  RegexDetectorSchema,
  AstPatternDetectorSchema,
  ComplexityDetectorSchema,
  NamingDetectorSchema,
]);

const DetectorConfigSchema = z.object({
  detectors: z.array(CustomDetectorSchema),
  version: z.string().optional(),
  extends: z.array(z.string()).optional(),
});

// ============================================================================
// Types
// ============================================================================

export type CustomDetector = z.infer<typeof CustomDetectorSchema>;
export type RegexDetector = z.infer<typeof RegexDetectorSchema>;
export type AstPatternDetector = z.infer<typeof AstPatternDetectorSchema>;
export type ComplexityDetector = z.infer<typeof ComplexityDetectorSchema>;
export type NamingDetector = z.infer<typeof NamingDetectorSchema>;
export type DetectorConfig = z.infer<typeof DetectorConfigSchema>;
export type NamingRule = z.infer<typeof NamingRuleSchema>;

// ============================================================================
// Main Functions
// ============================================================================

/**
 * Load a preset by name from the presets directory.
 */
async function loadPreset(presetName: string): Promise<CustomDetector[]> {
  const presetPath = join(PRESETS_DIR, `${presetName}.json`);

  if (!existsSync(presetPath)) {
    logger.warn(`[custom-detectors] Preset not found: ${presetName}`);
    return [];
  }

  try {
    const content = await readFile(presetPath, "utf-8");
    const parsed = JSON.parse(content);

    // Preset files have a slightly different schema with name/description
    const PresetSchema = z.object({
      name: z.string(),
      description: z.string().optional(),
      version: z.string().optional(),
      detectors: z.array(CustomDetectorSchema),
    });

    const preset = PresetSchema.parse(parsed);
    logger.info(
      `[custom-detectors] Loaded preset '${presetName}' with ${preset.detectors.length} detectors`
    );
    return preset.detectors;
  } catch (error) {
    if (error instanceof z.ZodError) {
      const issues = error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ");
      logger.error(`[custom-detectors] Invalid preset '${presetName}': ${issues}`);
    } else {
      logger.error(
        `[custom-detectors] Failed to load preset '${presetName}': ${error instanceof Error ? error.message : String(error)}`
      );
    }
    return [];
  }
}

/**
 * Get list of available presets.
 */
export async function getAvailablePresets(): Promise<string[]> {
  try {
    const { readdir } = await import("fs/promises");
    const files = await readdir(PRESETS_DIR);
    return files.filter((f) => f.endsWith(".json")).map((f) => f.replace(".json", ""));
  } catch {
    return [];
  }
}

/**
 * Load custom detectors from the project's config file.
 * Looks for .audit-detectors.json or .audit-detectors.yml in the project root.
 * Supports extending presets via the "extends" field.
 */
export async function loadCustomDetectors(projectRoot: string): Promise<CustomDetector[]> {
  const jsonPath = join(projectRoot, ".audit-detectors.json");
  const ymlPath = join(projectRoot, ".audit-detectors.yml");
  const yamlPath = join(projectRoot, ".audit-detectors.yaml");

  let configPath: string | null = null;
  let isYaml = false;

  if (existsSync(jsonPath)) {
    configPath = jsonPath;
  } else if (existsSync(ymlPath)) {
    configPath = ymlPath;
    isYaml = true;
  } else if (existsSync(yamlPath)) {
    configPath = yamlPath;
    isYaml = true;
  }

  if (!configPath) {
    return [];
  }

  try {
    const content = await readFile(configPath, "utf-8");
    let parsed: unknown;

    if (isYaml) {
      parsed = parseYaml(content);
    } else {
      parsed = JSON.parse(content);
    }

    const config = DetectorConfigSchema.parse(parsed);

    // Load detectors from extended presets
    const allDetectors: CustomDetector[] = [];
    const loadedPresets: string[] = [];

    if (config.extends && config.extends.length > 0) {
      for (const presetName of config.extends) {
        const presetDetectors = await loadPreset(presetName);
        allDetectors.push(...presetDetectors);
        if (presetDetectors.length > 0) {
          loadedPresets.push(presetName);
        }
      }
    }

    // Add custom detectors (these can override preset detectors with same ID)
    const customIds = new Set(config.detectors.map((d) => d.id));

    // Filter out preset detectors that are overridden by custom ones
    const filteredPresetDetectors = allDetectors.filter((d) => !customIds.has(d.id));

    // Combine: preset detectors first, then custom detectors
    const finalDetectors = [...filteredPresetDetectors, ...config.detectors];

    // Log summary
    if (loadedPresets.length > 0) {
      logger.info(
        `[custom-detectors] Loaded ${finalDetectors.length} detectors (presets: ${loadedPresets.join(", ")}, custom: ${config.detectors.length})`
      );
    } else {
      logger.info(
        `[custom-detectors] Loaded ${config.detectors.length} custom detectors from ${basename(configPath)}`
      );
    }

    return finalDetectors;
  } catch (error) {
    if (error instanceof z.ZodError) {
      const issues = error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ");
      logger.error(`[custom-detectors] Invalid config: ${issues}`);
    } else {
      logger.error(
        `[custom-detectors] Failed to load config: ${error instanceof Error ? error.message : String(error)}`
      );
    }
    return [];
  }
}

/**
 * Run all custom detectors against a source file.
 */
export function runCustomDetectors(
  source: string,
  contractPath: string,
  detectors: CustomDetector[],
  projectRoot?: string
): Finding[] {
  const findings: Finding[] = [];
  const relativePath = projectRoot ? relative(projectRoot, contractPath) : contractPath;

  for (const detector of detectors) {
    // Check if file should be excluded
    if (shouldExclude(relativePath, detector.exclude)) {
      continue;
    }

    const detectorFindings = runDetector(source, contractPath, detector);
    findings.push(...detectorFindings);
  }

  return findings;
}

// ============================================================================
// Detector Runners
// ============================================================================

function runDetector(source: string, contractPath: string, detector: CustomDetector): Finding[] {
  switch (detector.type) {
    case "regex":
      return runRegexDetector(source, contractPath, detector);
    case "ast-pattern":
      return runAstPatternDetector(source, contractPath, detector);
    case "complexity":
      return runComplexityDetector(source, contractPath, detector);
    case "naming":
      return runNamingDetector(source, contractPath, detector);
  }
}

/**
 * Run a regex-based detector.
 */
function runRegexDetector(
  source: string,
  contractPath: string,
  detector: RegexDetector
): Finding[] {
  const findings: Finding[] = [];
  const fileName = basename(contractPath);

  let flags = "g";
  if (detector.multiline) flags += "m";
  if (detector.caseInsensitive) flags += "i";

  const lines = source.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    // Use exec in a loop for line-by-line matching
    const lineRegex = new RegExp(detector.pattern, flags);
    let match: RegExpExecArray | null;

    while ((match = lineRegex.exec(line)) !== null) {
      findings.push({
        id: `CUSTOM-${detector.id}-${i + 1}`,
        title: detector.title,
        severity: mapSeverity(detector.severity),
        description: `${detector.description}\n\nMatched: \`${match[0]}\``,
        location: {
          file: fileName,
          lines: [i + 1, i + 1],
        },
        recommendation: detector.recommendation,
        detector: `custom:${detector.id}`,
        confidence: "high",
      });
    }
  }

  // Also check multiline patterns
  if (detector.multiline) {
    const multilineRegex = new RegExp(detector.pattern, flags);
    let match: RegExpExecArray | null;

    while ((match = multilineRegex.exec(source)) !== null) {
      const lineNumber = source.substring(0, match.index).split("\n").length;
      const endLineNumber = source.substring(0, match.index + match[0].length).split("\n").length;

      // Avoid duplicates with line-by-line matches
      const isDuplicate = findings.some(
        (f) =>
          f.location.lines &&
          f.location.lines[0] === lineNumber &&
          f.location.lines[1] === lineNumber
      );

      if (!isDuplicate) {
        findings.push({
          id: `CUSTOM-${detector.id}-${lineNumber}`,
          title: detector.title,
          severity: mapSeverity(detector.severity),
          description: `${detector.description}\n\nMatched: \`${match[0].substring(0, 100)}${match[0].length > 100 ? "..." : ""}\``,
          location: {
            file: fileName,
            lines: [lineNumber, endLineNumber],
          },
          recommendation: detector.recommendation,
          detector: `custom:${detector.id}`,
          confidence: "high",
        });
      }
    }
  }

  return findings;
}

/**
 * Run an AST-pattern based detector.
 * Analyzes function declarations for modifier/visibility/state patterns.
 */
function runAstPatternDetector(
  source: string,
  contractPath: string,
  detector: AstPatternDetector
): Finding[] {
  const findings: Finding[] = [];
  const fileName = basename(contractPath);
  const functions = extractFunctions(source);

  for (const func of functions) {
    if (matchesAstPattern(func, detector.match, source)) {
      findings.push({
        id: `CUSTOM-${detector.id}-${func.name}`,
        title: detector.title,
        severity: mapSeverity(detector.severity),
        description: `${detector.description}\n\nFunction: \`${func.name}\``,
        location: {
          file: fileName,
          lines: [func.startLine, func.endLine],
          function: func.name,
        },
        recommendation: detector.recommendation,
        detector: `custom:${detector.id}`,
        confidence: "medium",
      });
    }
  }

  return findings;
}

/**
 * Run a complexity-based detector.
 */
function runComplexityDetector(
  source: string,
  contractPath: string,
  detector: ComplexityDetector
): Finding[] {
  const findings: Finding[] = [];
  const fileName = basename(contractPath);
  const functions = extractFunctions(source);

  for (const func of functions) {
    const metrics = calculateComplexity(func.body);
    const violations: string[] = [];

    if (detector.threshold.maxLines && metrics.lines > detector.threshold.maxLines) {
      violations.push(`Lines: ${metrics.lines} (max: ${detector.threshold.maxLines})`);
    }
    if (detector.threshold.maxDepth && metrics.maxDepth > detector.threshold.maxDepth) {
      violations.push(`Nesting depth: ${metrics.maxDepth} (max: ${detector.threshold.maxDepth})`);
    }
    if (
      detector.threshold.maxParameters &&
      func.parameterCount > detector.threshold.maxParameters
    ) {
      violations.push(
        `Parameters: ${func.parameterCount} (max: ${detector.threshold.maxParameters})`
      );
    }
    if (detector.threshold.maxStatements && metrics.statements > detector.threshold.maxStatements) {
      violations.push(
        `Statements: ${metrics.statements} (max: ${detector.threshold.maxStatements})`
      );
    }

    if (violations.length > 0) {
      findings.push({
        id: `CUSTOM-${detector.id}-${func.name}`,
        title: detector.title,
        severity: mapSeverity(detector.severity),
        description: `${detector.description}\n\nFunction: \`${func.name}\`\nViolations:\n${violations.map((v) => `- ${v}`).join("\n")}`,
        location: {
          file: fileName,
          lines: [func.startLine, func.endLine],
          function: func.name,
        },
        recommendation: detector.recommendation,
        detector: `custom:${detector.id}`,
        confidence: "high",
      });
    }
  }

  return findings;
}

/**
 * Run a naming convention detector.
 */
function runNamingDetector(
  source: string,
  contractPath: string,
  detector: NamingDetector
): Finding[] {
  const findings: Finding[] = [];
  const fileName = basename(contractPath);

  for (const rule of detector.rules) {
    const violations = checkNamingRule(source, rule);

    for (const violation of violations) {
      findings.push({
        id: `CUSTOM-${detector.id}-${violation.name}`,
        title: detector.title,
        severity: mapSeverity(detector.severity),
        description: `${detector.description}\n\n${violation.type}: \`${violation.name}\` ${rule.shouldMatch ? "should match" : "should not match"} pattern \`${rule.pattern}\``,
        location: {
          file: fileName,
          lines: [violation.line, violation.line],
        },
        recommendation: detector.recommendation,
        detector: `custom:${detector.id}`,
        confidence: "high",
      });
    }
  }

  return findings;
}

// ============================================================================
// Helper Functions
// ============================================================================

function shouldExclude(filePath: string, excludePatterns?: string[]): boolean {
  if (!excludePatterns || excludePatterns.length === 0) {
    return false;
  }

  const normalizedPath = filePath.replace(/\\/g, "/");

  for (const pattern of excludePatterns) {
    const normalizedPattern = pattern.replace(/\\/g, "/");

    // Simple glob matching
    if (normalizedPattern.endsWith("/")) {
      // Directory pattern
      if (
        normalizedPath.startsWith(normalizedPattern) ||
        normalizedPath.includes(`/${normalizedPattern}`)
      ) {
        return true;
      }
    } else if (normalizedPattern.includes("*")) {
      // Wildcard pattern
      const regexPattern = normalizedPattern.replace(/\*/g, ".*").replace(/\?/g, ".");
      if (new RegExp(regexPattern).test(normalizedPath)) {
        return true;
      }
    } else {
      // Exact or prefix match
      if (normalizedPath.includes(normalizedPattern)) {
        return true;
      }
    }
  }

  return false;
}

function mapSeverity(severity: string): Severity {
  switch (severity.toUpperCase()) {
    case "CRITICAL":
      return Severity.CRITICAL;
    case "HIGH":
      return Severity.HIGH;
    case "MEDIUM":
      return Severity.MEDIUM;
    case "LOW":
      return Severity.LOW;
    case "INFORMATIONAL":
    default:
      return Severity.INFORMATIONAL;
  }
}

// ============================================================================
// Function Extraction
// ============================================================================

interface ExtractedFunction {
  name: string;
  visibility: string;
  modifiers: string[];
  isPayable: boolean;
  parameterCount: number;
  parameters: string[];
  startLine: number;
  endLine: number;
  body: string;
  signature: string;
}

function extractFunctions(source: string): ExtractedFunction[] {
  const functions: ExtractedFunction[] = [];
  const lines = source.split("\n");

  // Regex to match start of function declaration
  const funcStartPattern = /^\s*function\s+(\w+)\s*\(/;
  // Full function pattern for single-line declarations
  const funcFullPattern = /function\s+(\w+)\s*\(([^)]*)\)\s*([^{]*)\{/;

  let braceDepth = 0;
  let parenDepth = 0;
  let currentFunc: Partial<ExtractedFunction> | null = null;
  let funcStartLine = 0;
  let funcBody: string[] = [];
  let funcDeclaration = "";
  let collectingDeclaration = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;

    if (!currentFunc && !collectingDeclaration) {
      const startMatch = line.match(funcStartPattern);
      if (startMatch) {
        collectingDeclaration = true;
        funcDeclaration = line;
        funcStartLine = i + 1;
        parenDepth = 0;
        // Count parens in this line
        for (const char of line) {
          if (char === "(") parenDepth++;
          else if (char === ")") parenDepth--;
        }
        // Check if declaration is complete (has opening brace)
        if (line.includes("{") && parenDepth === 0) {
          const fullMatch = funcDeclaration.match(funcFullPattern);
          if (fullMatch) {
            const [, name, params, modifiersStr] = fullMatch;
            currentFunc = {
              name: name!,
              parameters: params!
                .split(",")
                .map((p) => p.trim())
                .filter((p) => p.length > 0),
              parameterCount: params!.split(",").filter((p) => p.trim().length > 0).length,
              visibility: extractVisibility(modifiersStr!),
              modifiers: extractModifiers(modifiersStr!),
              isPayable: /\bpayable\b/.test(modifiersStr!),
              signature: `${name}(${params})`,
            };
            braceDepth = 0;
            collectingDeclaration = false;
          }
        }
      }
    } else if (collectingDeclaration) {
      funcDeclaration += " " + line.trim();
      for (const char of line) {
        if (char === "(") parenDepth++;
        else if (char === ")") parenDepth--;
      }
      // Check if declaration is complete
      if (line.includes("{") && parenDepth === 0) {
        const fullMatch = funcDeclaration.match(funcFullPattern);
        if (fullMatch) {
          const [, name, params, modifiersStr] = fullMatch;
          currentFunc = {
            name: name!,
            parameters: params!
              .split(",")
              .map((p) => p.trim())
              .filter((p) => p.length > 0),
            parameterCount: params!.split(",").filter((p) => p.trim().length > 0).length,
            visibility: extractVisibility(modifiersStr!),
            modifiers: extractModifiers(modifiersStr!),
            isPayable: /\bpayable\b/.test(modifiersStr!),
            signature: `${name}(${params})`,
          };
          braceDepth = 0;
          collectingDeclaration = false;
        }
      }
    }

    if (currentFunc) {
      funcBody.push(line);

      for (const char of line) {
        if (char === "{") braceDepth++;
        else if (char === "}") braceDepth--;
      }

      if (braceDepth === 0 && funcBody.length > 0) {
        functions.push({
          ...currentFunc,
          startLine: funcStartLine,
          endLine: i + 1,
          body: funcBody.join("\n"),
        } as ExtractedFunction);

        currentFunc = null;
        funcBody = [];
        funcDeclaration = "";
      }
    }
  }

  // Also extract constructor
  const constructorPattern = /^\s*constructor\s*\(([^)]*)\)\s*([^{]*)\{/;
  let inConstructor = false;
  let constructorStartLine = 0;
  let constructorBody: string[] = [];
  braceDepth = 0;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;

    if (!inConstructor) {
      const match = line.match(constructorPattern);
      if (match) {
        const [, params, modifiersStr] = match;
        currentFunc = {
          name: "constructor",
          parameters: params!
            .split(",")
            .map((p) => p.trim())
            .filter((p) => p.length > 0),
          parameterCount: params!.split(",").filter((p) => p.trim().length > 0).length,
          visibility: "public",
          modifiers: extractModifiers(modifiersStr!),
          isPayable: /\bpayable\b/.test(modifiersStr!),
          signature: `constructor(${params})`,
        };
        constructorStartLine = i + 1;
        inConstructor = true;
        braceDepth = 0;
      }
    }

    if (inConstructor) {
      constructorBody.push(line);

      for (const char of line) {
        if (char === "{") braceDepth++;
        else if (char === "}") braceDepth--;
      }

      if (braceDepth === 0 && constructorBody.length > 0) {
        functions.push({
          ...currentFunc,
          startLine: constructorStartLine,
          endLine: i + 1,
          body: constructorBody.join("\n"),
        } as ExtractedFunction);

        inConstructor = false;
        constructorBody = [];
        currentFunc = null;
      }
    }
  }

  return functions;
}

function extractVisibility(modifiersStr: string): string {
  if (/\bexternal\b/.test(modifiersStr)) return "external";
  if (/\bpublic\b/.test(modifiersStr)) return "public";
  if (/\binternal\b/.test(modifiersStr)) return "internal";
  if (/\bprivate\b/.test(modifiersStr)) return "private";
  return "internal"; // default
}

function extractModifiers(modifiersStr: string): string[] {
  const keywords = [
    "public",
    "private",
    "internal",
    "external",
    "pure",
    "view",
    "payable",
    "virtual",
    "override",
    "returns",
  ];

  const modifiers: string[] = [];
  const tokens = modifiersStr.split(/\s+/).filter((t) => t.length > 0);

  for (const token of tokens) {
    const cleanToken = token.replace(/\([^)]*\)/, "");
    if (!keywords.includes(cleanToken.toLowerCase()) && /^[a-zA-Z_]\w*$/.test(cleanToken)) {
      modifiers.push(cleanToken);
    }
  }

  return modifiers;
}

// ============================================================================
// AST Pattern Matching
// ============================================================================

interface AstPatternMatch {
  hasModifier?: string;
  notHasModifier?: string;
  hasVisibility?: string;
  modifiesState?: boolean;
  isPayable?: boolean;
  hasParameter?: string;
  callsFunction?: string;
  usesAssembly?: boolean;
}

function matchesAstPattern(
  func: ExtractedFunction,
  pattern: AstPatternMatch,
  _source: string
): boolean {
  // Check hasModifier
  if (pattern.hasModifier && !func.modifiers.includes(pattern.hasModifier)) {
    return false;
  }

  // Check notHasModifier
  if (pattern.notHasModifier && func.modifiers.includes(pattern.notHasModifier)) {
    return false;
  }

  // Check visibility
  if (pattern.hasVisibility && func.visibility !== pattern.hasVisibility) {
    return false;
  }

  // Check isPayable
  if (pattern.isPayable !== undefined && func.isPayable !== pattern.isPayable) {
    return false;
  }

  // Check hasParameter
  if (pattern.hasParameter) {
    const hasParam = func.parameters.some((p) => p.includes(pattern.hasParameter!));
    if (!hasParam) {
      return false;
    }
  }

  // Check modifiesState
  if (pattern.modifiesState !== undefined) {
    const modifies = detectsStateModification(func.body);
    if (modifies !== pattern.modifiesState) {
      return false;
    }
  }

  // Check callsFunction
  if (pattern.callsFunction) {
    const calls = new RegExp(`\\b${pattern.callsFunction}\\s*\\(`).test(func.body);
    if (!calls) {
      return false;
    }
  }

  // Check usesAssembly
  if (pattern.usesAssembly !== undefined) {
    const usesAsm = /\bassembly\s*\{/.test(func.body);
    if (usesAsm !== pattern.usesAssembly) {
      return false;
    }
  }

  return true;
}

function detectsStateModification(body: string): boolean {
  // Common patterns that indicate state modification
  const stateModPatterns = [
    /\w+\s*=\s*[^=]/, // Assignment (not comparison)
    /\w+\s*\+=/, // Compound assignment
    /\w+\s*-=/, // Compound assignment
    /\w+\s*\*=/, // Compound assignment
    /\w+\s*\/=/, // Compound assignment
    /\+\+\w+/, // Pre-increment
    /\w+\+\+/, // Post-increment
    /--\w+/, // Pre-decrement
    /\w+--/, // Post-decrement
    /\.push\s*\(/, // Array push
    /\.pop\s*\(/, // Array pop
    /delete\s+\w+/, // Delete
    /emit\s+\w+/, // Event emission (indicates state change context)
    /\.transfer\s*\(/, // ETH transfer
    /\.send\s*\(/, // ETH send
    /\.call\s*\{/, // Low-level call with value
    /\.call\s*\(/, // Low-level call
    /selfdestruct\s*\(/, // Self destruct
  ];

  // Exclude view/pure patterns
  if (/\bpure\b|\bview\b/.test(body.split("\n")[0] ?? "")) {
    return false;
  }

  for (const pattern of stateModPatterns) {
    if (pattern.test(body)) {
      return true;
    }
  }

  return false;
}

// ============================================================================
// Complexity Calculation
// ============================================================================

interface ComplexityMetrics {
  lines: number;
  maxDepth: number;
  statements: number;
}

function calculateComplexity(body: string): ComplexityMetrics {
  const lines = body.split("\n").filter((l) => l.trim().length > 0).length;

  let maxDepth = 0;
  let currentDepth = 0;
  let statements = 0;

  for (const char of body) {
    if (char === "{") {
      currentDepth++;
      if (currentDepth > maxDepth) {
        maxDepth = currentDepth;
      }
    } else if (char === "}") {
      currentDepth--;
    } else if (char === ";") {
      statements++;
    }
  }

  return { lines, maxDepth, statements };
}

// ============================================================================
// Naming Convention Checking
// ============================================================================

interface NamingViolation {
  name: string;
  type: string;
  line: number;
}

function checkNamingRule(source: string, rule: NamingRule): NamingViolation[] {
  const violations: NamingViolation[] = [];
  const lines = source.split("\n");
  const regex = new RegExp(rule.pattern);

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    const items = extractNamingTargets(line, rule.target, rule.scope);

    for (const item of items) {
      const matches = regex.test(item.name);
      const shouldViolate = rule.shouldMatch ? !matches : matches;

      if (shouldViolate) {
        violations.push({
          name: item.name,
          type: rule.target,
          line: i + 1,
        });
      }
    }
  }

  return violations;
}

interface NamingTarget {
  name: string;
  visibility?: string;
}

function extractNamingTargets(line: string, target: string, scope?: string): NamingTarget[] {
  const targets: NamingTarget[] = [];

  switch (target) {
    case "function": {
      const funcMatch = line.match(/\bfunction\s+(\w+)/);
      if (funcMatch) {
        const visibility = extractLineVisibility(line);
        if (matchesScope(visibility, scope)) {
          targets.push({ name: funcMatch[1]!, visibility });
        }
      }
      break;
    }

    case "variable": {
      // Match state variables
      const varMatch = line.match(
        /^\s*(?:mapping\s*\([^)]+\)|[\w[\]]+)\s+(public|private|internal|external)?\s*(?:constant|immutable)?\s*(\w+)\s*(?:=|;)/
      );
      if (varMatch) {
        const visibility = varMatch[1] ?? "internal";
        if (matchesScope(visibility, scope)) {
          targets.push({ name: varMatch[2]!, visibility });
        }
      }
      break;
    }

    case "constant": {
      const constMatch = line.match(/\bconstant\s+(\w+)/);
      if (constMatch) {
        targets.push({ name: constMatch[1]! });
      }
      break;
    }

    case "event": {
      const eventMatch = line.match(/\bevent\s+(\w+)/);
      if (eventMatch) {
        targets.push({ name: eventMatch[1]! });
      }
      break;
    }

    case "modifier": {
      const modMatch = line.match(/\bmodifier\s+(\w+)/);
      if (modMatch) {
        targets.push({ name: modMatch[1]! });
      }
      break;
    }

    case "parameter": {
      // Extract function parameters
      const paramMatch = line.match(/function\s+\w+\s*\(([^)]*)\)/);
      if (paramMatch) {
        const params = paramMatch[1]!.split(",");
        for (const param of params) {
          const paramName = param.trim().split(/\s+/).pop();
          if (paramName && /^\w+$/.test(paramName)) {
            targets.push({ name: paramName });
          }
        }
      }
      break;
    }
  }

  return targets;
}

function extractLineVisibility(line: string): string {
  if (/\bexternal\b/.test(line)) return "external";
  if (/\bpublic\b/.test(line)) return "public";
  if (/\binternal\b/.test(line)) return "internal";
  if (/\bprivate\b/.test(line)) return "private";
  return "internal";
}

function matchesScope(visibility: string, scope?: string): boolean {
  if (!scope || scope === "all") return true;
  return visibility === scope;
}

// ============================================================================
// Exports
// ============================================================================

export { DetectorConfigSchema, CustomDetectorSchema };
