/**
 * Gas Optimizer Adapter
 *
 * Self-contained adapter for gas optimization analysis.
 * Includes the full pattern detection implementation and the
 * IAnalyzer-compatible adapter class.
 *
 * This is a pure JavaScript analyzer that uses regex patterns
 * to detect gas inefficiencies.
 */

import { readFile } from "fs/promises";
import { basename } from "path";
import { BaseAnalyzer } from "../IAnalyzer.js";
import type { AnalyzerInput, AnalyzerResult, AnalyzerCapabilities, GasOptions } from "../types.js";
import { Severity, type Finding, type Confidence } from "../../types/index.js";
import { logger } from "../../utils/logger.js";

// ============================================================================
// Gas Pattern Types
// ============================================================================

interface GasPattern {
  id: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  estimatedSavings: string;
  recommendation: string;
}

interface StructField {
  name: string;
  type: string;
  size: number;
  line: number;
}

interface StructInfo {
  name: string;
  fields: StructField[];
  line: number;
  currentSlots: number;
  optimalSlots: number;
}

interface StateVariable {
  name: string;
  type: string;
  line: number;
  isConstant: boolean;
  isImmutable: boolean;
}

interface FunctionWithBody {
  name: string;
  body: string;
  startLine: number;
  endLine: number;
  isExternal: boolean;
  params: string;
}

// ============================================================================
// Pattern Definitions
// ============================================================================

const PATTERNS: Record<string, GasPattern> = {
  STORAGE_READ_IN_LOOP: {
    id: "GAS-001",
    title: "Storage Read in Loop",
    severity: Severity.MEDIUM,
    confidence: "medium",
    estimatedSavings: "~100 gas per iteration",
    recommendation:
      "Cache the storage variable in a local memory variable before the loop to avoid repeated SLOAD operations.",
  },
  STORAGE_WRITE_IN_LOOP: {
    id: "GAS-002",
    title: "Storage Write in Loop",
    severity: Severity.HIGH,
    confidence: "high",
    estimatedSavings: "~5000 gas per write avoided",
    recommendation:
      "Accumulate changes in a memory variable and write to storage once after the loop completes.",
  },
  MEMORY_VS_CALLDATA: {
    id: "GAS-003",
    title: "Use calldata Instead of memory",
    severity: Severity.LOW,
    confidence: "high",
    estimatedSavings: "~300-600 gas per parameter",
    recommendation:
      "For external functions with array/string parameters that are not modified, use calldata instead of memory.",
  },
  MISSING_IMMUTABLE: {
    id: "GAS-004",
    title: "Variable Should Be Immutable",
    severity: Severity.LOW,
    confidence: "medium",
    estimatedSavings: "~2100 gas per read (SLOAD vs PUSH)",
    recommendation:
      "Mark this variable as immutable since it is only set in the constructor and never modified.",
  },
  GT_ZERO_VS_NE_ZERO: {
    id: "GAS-005",
    title: "Use != 0 Instead of > 0",
    severity: Severity.INFORMATIONAL,
    confidence: "high",
    estimatedSavings: "~6 gas",
    recommendation: "For uint comparisons, use != 0 instead of > 0 as it is slightly cheaper.",
  },
  STRING_VS_BYTES32: {
    id: "GAS-006",
    title: "Use bytes32 Instead of string",
    severity: Severity.INFORMATIONAL,
    confidence: "medium",
    estimatedSavings: "Variable (storage slot + operations)",
    recommendation:
      "For short strings (< 32 bytes) that don't need string operations, consider using bytes32.",
  },
  POST_INCREMENT: {
    id: "GAS-007",
    title: "Use ++i Instead of i++",
    severity: Severity.INFORMATIONAL,
    confidence: "high",
    estimatedSavings: "~5 gas per iteration (pre-0.8.12)",
    recommendation:
      "Use pre-increment (++i) instead of post-increment (i++) in loops for gas savings in Solidity < 0.8.12.",
  },
  STRUCT_PACKING: {
    id: "GAS-008",
    title: "Inefficient Struct Packing",
    severity: Severity.MEDIUM,
    confidence: "high",
    estimatedSavings: "~2100 gas per slot saved",
    recommendation:
      "Reorder struct fields to pack smaller types together and minimize storage slots used.",
  },
  UNCHECKED_LOOP_INCREMENT: {
    id: "GAS-009",
    title: "Loop Increment Can Be Unchecked",
    severity: Severity.LOW,
    confidence: "medium",
    estimatedSavings: "~30-40 gas per iteration",
    recommendation:
      "When loop bounds are checked (e.g., i < array.length), the increment cannot overflow. Wrap in unchecked { ++i; }.",
  },
  MULTIPLE_ADDRESS_MAPPINGS: {
    id: "GAS-010",
    title: "Multiple Mappings With Same Key",
    severity: Severity.LOW,
    confidence: "medium",
    estimatedSavings: "~2100 gas per combined access",
    recommendation:
      "Combine multiple mappings with the same key type into a single mapping to a struct to save on storage slot calculations.",
  },
};

/**
 * Public export of gas patterns for introspection and testing.
 */
export { PATTERNS as GAS_PATTERNS };

// ============================================================================
// Helper Functions
// ============================================================================

function extractPragmaVersion(source: string): string | null {
  const match = source.match(/pragma\s+solidity\s+[\^~>=<]*(\d+\.\d+\.\d+)/);
  return match?.[1] ?? null;
}

function extractContractBody(source: string): string {
  const match = source.match(/\b(?:contract|library)\s+\w+[^{]*\{/);
  if (!match) return source;

  const startIndex = match.index! + match[0].length;
  let braceCount = 1;
  let endIndex = startIndex;

  for (let i = startIndex; i < source.length && braceCount > 0; i++) {
    if (source[i] === "{") braceCount++;
    else if (source[i] === "}") braceCount--;
    endIndex = i;
  }

  return source.slice(startIndex, endIndex);
}

function extractStateVariables(source: string): StateVariable[] {
  const variables: StateVariable[] = [];
  const lines = source.split("\n");

  const functionBodies = new Set<number>();
  let braceDepth = 0;
  let inFunction = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (/\bfunction\s+\w+/.test(line) || /\bconstructor\s*\(/.test(line)) {
      inFunction = true;
    }
    for (const char of line) {
      if (char === "{") braceDepth++;
      else if (char === "}") braceDepth--;
    }
    if (inFunction && braceDepth > 0) {
      functionBodies.add(i);
    }
    if (braceDepth === 0) inFunction = false;
  }

  for (let i = 0; i < lines.length; i++) {
    if (functionBodies.has(i)) continue;

    const line = lines[i]!;
    const match = line.match(
      /^\s*((?:mapping\s*\([^)]+\)|[\w[\]]+))\s+(?:public|private|internal)?\s*(constant|immutable)?\s*(\w+)\s*(?:=|;)/
    );

    if (match) {
      variables.push({
        name: match[3]!,
        type: match[1]!.trim(),
        line: i + 1,
        isConstant: match[2] === "constant",
        isImmutable: match[2] === "immutable",
      });
    }
  }

  return variables;
}

function extractFunctionsWithBodies(contractBody: string, _allLines: string[]): FunctionWithBody[] {
  const functions: FunctionWithBody[] = [];
  const funcRegex = /\b(function\s+(\w+)\s*\(([^)]*)\)\s*([^{]*)\{)/g;

  let match;
  while ((match = funcRegex.exec(contractBody)) !== null) {
    const funcStart = match.index + match[0].length;
    const name = match[2]!;
    const params = match[3]!;
    const modifiers = match[4]!;

    let braceCount = 1;
    let funcEnd = funcStart;
    for (let i = funcStart; i < contractBody.length && braceCount > 0; i++) {
      if (contractBody[i] === "{") braceCount++;
      else if (contractBody[i] === "}") braceCount--;
      funcEnd = i;
    }

    const body = contractBody.slice(funcStart, funcEnd);

    const beforeFunc = contractBody.slice(0, match.index);
    const startLine = beforeFunc.split("\n").length;
    const endLine = startLine + body.split("\n").length;

    functions.push({
      name,
      body,
      startLine,
      endLine,
      isExternal: /\bexternal\b/.test(modifiers),
      params,
    });
  }

  return functions;
}

function extractStructs(source: string, _lines: string[]): StructInfo[] {
  const structs: StructInfo[] = [];
  const structRegex = /\bstruct\s+(\w+)\s*\{([^}]+)\}/g;

  let match;
  while ((match = structRegex.exec(source)) !== null) {
    const name = match[1]!;
    const fieldsStr = match[2]!;
    const beforeStruct = source.slice(0, match.index);
    const line = beforeStruct.split("\n").length;

    const fields: StructField[] = [];
    const fieldLines = fieldsStr.split(";").filter((f) => f.trim());

    for (const fieldLine of fieldLines) {
      const fieldMatch = fieldLine.trim().match(/^\s*(\w+(?:\[\d*\])?)\s+(\w+)\s*$/);
      if (fieldMatch) {
        const type = fieldMatch[1]!;
        const fieldName = fieldMatch[2]!;
        fields.push({
          name: fieldName,
          type,
          size: getTypeSize(type),
          line: line,
        });
      }
    }

    if (fields.length > 0) {
      const currentSlots = calculateSlots(fields);
      const optimalSlots = calculateOptimalSlots(fields);

      structs.push({
        name,
        fields,
        line,
        currentSlots,
        optimalSlots,
      });
    }
  }

  return structs;
}

function getTypeSize(type: string): number {
  if (type.startsWith("uint")) {
    const bits = parseInt(type.replace("uint", "") || "256");
    return bits / 8;
  }
  if (type.startsWith("int")) {
    const bits = parseInt(type.replace("int", "") || "256");
    return bits / 8;
  }
  if (type.startsWith("bytes") && !type.includes("[")) {
    const num = parseInt(type.replace("bytes", "") || "32");
    return num;
  }
  if (type === "bool") return 1;
  if (type === "address") return 20;
  return 32;
}

function calculateSlots(fields: StructField[]): number {
  if (fields.length === 0) return 0;

  let slots = 1;
  let currentSlotUsed = 0;

  for (const field of fields) {
    if (field.size === 32) {
      if (currentSlotUsed > 0) {
        slots++;
      }
      slots++;
      currentSlotUsed = 0;
    } else if (currentSlotUsed + field.size > 32) {
      slots++;
      currentSlotUsed = field.size;
    } else {
      currentSlotUsed += field.size;
    }
  }

  if (currentSlotUsed === 0 && slots > 0) {
    slots--;
  }

  return Math.max(slots, 1);
}

function calculateOptimalSlots(fields: StructField[]): number {
  const sorted = [...fields].sort((a, b) => b.size - a.size);
  return calculateSlots(sorted);
}

function getLineNumber(source: string, index: number): number {
  return source.slice(0, index).split("\n").length;
}

function createFinding(
  pattern: GasPattern,
  description: string,
  file: string,
  line: number,
  functionName?: string
): Finding {
  return {
    id: pattern.id,
    title: pattern.title,
    severity: pattern.severity,
    description: `${description}\n\nEstimated savings: ${pattern.estimatedSavings}`,
    location: {
      file,
      lines: [line, line],
      function: functionName,
    },
    recommendation: pattern.recommendation,
    detector: "gas-optimizer",
    confidence: pattern.confidence,
  };
}

// ============================================================================
// Pattern Detection Functions
// ============================================================================

function detectStorageReadsInLoops(
  functions: FunctionWithBody[],
  stateVars: StateVariable[],
  fileName: string
): Finding[] {
  const findings: Finding[] = [];
  const stateVarNames = new Set(stateVars.map((v) => v.name));

  for (const func of functions) {
    const loopRegex = /\b(for|while)\s*\([^)]*\)\s*\{/g;
    let loopMatch;

    while ((loopMatch = loopRegex.exec(func.body)) !== null) {
      const loopStart = loopMatch.index + loopMatch[0].length;

      let braceCount = 1;
      let loopEnd = loopStart;
      for (let i = loopStart; i < func.body.length && braceCount > 0; i++) {
        if (func.body[i] === "{") braceCount++;
        else if (func.body[i] === "}") braceCount--;
        loopEnd = i;
      }

      const loopBody = func.body.slice(loopStart, loopEnd);

      for (const varName of stateVarNames) {
        const readPattern = new RegExp(
          `(?<!\\.)\\b${varName}\\b(?!\\s*=(?!=))(?!\\.length\\s*;)`,
          "g"
        );
        if (readPattern.test(loopBody)) {
          const conditionMatch = loopMatch[0].match(/\b(\w+)\.length\b/);
          if (conditionMatch?.[1] === varName) {
            const line = func.startLine + func.body.slice(0, loopMatch.index).split("\n").length;
            findings.push(
              createFinding(
                PATTERNS.STORAGE_READ_IN_LOOP!,
                `State variable '${varName}.length' is read in every loop iteration. ` +
                  `Cache it in a local variable before the loop: 'uint256 len = ${varName}.length;'`,
                fileName,
                line,
                func.name
              )
            );
          } else {
            const line = func.startLine + func.body.slice(0, loopMatch.index).split("\n").length;
            findings.push(
              createFinding(
                PATTERNS.STORAGE_READ_IN_LOOP!,
                `State variable '${varName}' is accessed inside a loop. ` +
                  `Consider caching it in a memory variable before the loop.`,
                fileName,
                line,
                func.name
              )
            );
          }
          break;
        }
      }
    }
  }

  return findings;
}

function detectStorageWritesInLoops(
  functions: FunctionWithBody[],
  stateVars: StateVariable[],
  fileName: string
): Finding[] {
  const findings: Finding[] = [];
  const stateVarNames = new Set(stateVars.map((v) => v.name));

  for (const func of functions) {
    const loopRegex = /\b(for|while)\s*\([^)]*\)\s*\{/g;
    let loopMatch;

    while ((loopMatch = loopRegex.exec(func.body)) !== null) {
      const loopStart = loopMatch.index + loopMatch[0].length;

      let braceCount = 1;
      let loopEnd = loopStart;
      for (let i = loopStart; i < func.body.length && braceCount > 0; i++) {
        if (func.body[i] === "{") braceCount++;
        else if (func.body[i] === "}") braceCount--;
        loopEnd = i;
      }

      const loopBody = func.body.slice(loopStart, loopEnd);

      for (const varName of stateVarNames) {
        const writePattern = new RegExp(`\\b${varName}\\s*(?:\\+|-|\\*|/)?=`, "g");
        if (writePattern.test(loopBody)) {
          const line = func.startLine + func.body.slice(0, loopMatch.index).split("\n").length;
          findings.push(
            createFinding(
              PATTERNS.STORAGE_WRITE_IN_LOOP!,
              `State variable '${varName}' is written inside a loop. Each SSTORE costs ~5000 gas. ` +
                `Accumulate changes in a memory variable and write once after the loop.`,
              fileName,
              line,
              func.name
            )
          );
          break;
        }
      }
    }
  }

  return findings;
}

function detectMemoryVsCalldata(source: string, _lines: string[], fileName: string): Finding[] {
  const findings: Finding[] = [];

  const funcRegex =
    /\bfunction\s+(\w+)\s*\(([^)]+)\)\s*(?:external|public\s+virtual|virtual\s+public)[^{]*\{/g;

  let match;
  while ((match = funcRegex.exec(source)) !== null) {
    const funcName = match[1]!;
    const params = match[2]!;

    const memoryParams = params.match(/(\w+(?:\[\])?)\s+memory\s+(\w+)/g);
    if (memoryParams) {
      for (const param of memoryParams) {
        const paramMatch = param.match(/(\w+(?:\[\])?)\s+memory\s+(\w+)/);
        if (paramMatch) {
          const type = paramMatch[1];
          const name = paramMatch[2];

          if (
            type?.includes("[]") ||
            type === "string" ||
            type === "bytes" ||
            type?.startsWith("bytes")
          ) {
            const line = getLineNumber(source, match.index);
            findings.push(
              createFinding(
                PATTERNS.MEMORY_VS_CALLDATA!,
                `Parameter '${name}' of type '${type}' in external function '${funcName}' uses memory. ` +
                  `If the parameter is not modified, use calldata instead.`,
                fileName,
                line,
                funcName
              )
            );
          }
        }
      }
    }
  }

  return findings;
}

function detectMissingImmutable(
  _source: string,
  stateVars: StateVariable[],
  contractBody: string,
  fileName: string,
  _lines: string[]
): Finding[] {
  const findings: Finding[] = [];

  const constructorMatch = contractBody.match(/\bconstructor\s*\([^)]*\)\s*[^{]*\{([^}]+)\}/s);
  if (!constructorMatch) return findings;

  const constructorBody = constructorMatch[1]!;

  for (const variable of stateVars) {
    if (variable.isConstant || variable.isImmutable) continue;
    if (variable.type.includes("mapping") || variable.type.includes("[]")) continue;

    const setInConstructor = new RegExp(`\\b${variable.name}\\s*=`).test(constructorBody);
    if (!setInConstructor) continue;

    const assignmentRegex = new RegExp(`\\b${variable.name}\\s*(?:\\+|-|\\*|/)?=`, "g");

    const withoutConstructor = contractBody.replace(
      /\bconstructor\s*\([^)]*\)\s*[^{]*\{[^}]+\}/s,
      ""
    );

    if (!assignmentRegex.test(withoutConstructor)) {
      findings.push(
        createFinding(
          PATTERNS.MISSING_IMMUTABLE!,
          `State variable '${variable.name}' is only set in the constructor and never modified. ` +
            `Consider marking it as immutable to save gas on reads.`,
          fileName,
          variable.line
        )
      );
    }
  }

  return findings;
}

function detectGtZeroVsNeZero(source: string, _lines: string[], fileName: string): Finding[] {
  const findings: Finding[] = [];
  const foundLines = new Set<number>();

  const gtZeroRegex = /\b(\w+)\s*>\s*0\b/g;

  let match;
  while ((match = gtZeroRegex.exec(source)) !== null) {
    const line = getLineNumber(source, match.index);
    if (foundLines.has(line)) continue;
    foundLines.add(line);

    const varName = match[1];
    const context = source.slice(Math.max(0, match.index - 50), match.index);

    if (/(?:require|if|assert|while)\s*\(/.test(context) || /[&|?]/.test(context)) {
      findings.push(
        createFinding(
          PATTERNS.GT_ZERO_VS_NE_ZERO!,
          `Comparison '${varName} > 0' can be replaced with '${varName} != 0' for slight gas savings.`,
          fileName,
          line
        )
      );
    }
  }

  return findings;
}

function detectStringVsBytes32(source: string, _lines: string[], fileName: string): Finding[] {
  const findings: Finding[] = [];

  const stringRegex = /\bstring\s+(public\s+)?(constant|immutable)\s+(\w+)\s*=\s*"([^"]*)"/g;

  let match;
  while ((match = stringRegex.exec(source)) !== null) {
    const varName = match[3]!;
    const value = match[4]!;

    if (value.length < 32) {
      const line = getLineNumber(source, match.index);
      findings.push(
        createFinding(
          PATTERNS.STRING_VS_BYTES32!,
          `Constant string '${varName}' has ${value.length} characters and could fit in a bytes32. ` +
            `Consider using bytes32 if string operations are not needed.`,
          fileName,
          line
        )
      );
    }
  }

  return findings;
}

function detectPostIncrement(
  source: string,
  _lines: string[],
  fileName: string,
  pragmaVersion: string | null
): Finding[] {
  const findings: Finding[] = [];

  if (pragmaVersion) {
    const [major, minor, patch] = pragmaVersion.split(".").map(Number);
    if (major! > 0 || minor! > 8 || (minor === 8 && patch! >= 12)) {
      return findings;
    }
  }

  const postIncRegex = /\bfor\s*\([^;]*;[^;]*;\s*(\w+)\s*\+\+\s*\)/g;

  let match;
  while ((match = postIncRegex.exec(source)) !== null) {
    const varName = match[1];
    const line = getLineNumber(source, match.index);

    findings.push(
      createFinding(
        PATTERNS.POST_INCREMENT!,
        `Loop uses post-increment '${varName}++' instead of pre-increment '++${varName}'. ` +
          `Pre-increment is cheaper in Solidity < 0.8.12.`,
        fileName,
        line
      )
    );
  }

  return findings;
}

function detectStructPacking(structs: StructInfo[], fileName: string): Finding[] {
  const findings: Finding[] = [];

  for (const struct of structs) {
    if (struct.currentSlots > struct.optimalSlots) {
      const fieldList = struct.fields.map((f) => `${f.type} ${f.name}`).join(", ");
      const optimalOrder = [...struct.fields]
        .sort((a, b) => b.size - a.size)
        .map((f) => `${f.type} ${f.name}`)
        .join(", ");

      findings.push(
        createFinding(
          PATTERNS.STRUCT_PACKING!,
          `Struct '${struct.name}' uses ${struct.currentSlots} storage slots but could use ${struct.optimalSlots} with better field ordering.\n` +
            `Current order: { ${fieldList} }\n` +
            `Optimal order: { ${optimalOrder} }`,
          fileName,
          struct.line
        )
      );
    }
  }

  return findings;
}

function detectUncheckedLoopIncrement(
  source: string,
  _lines: string[],
  fileName: string,
  pragmaVersion: string | null
): Finding[] {
  const findings: Finding[] = [];

  if (pragmaVersion) {
    const [major, minor] = pragmaVersion.split(".").map(Number);
    if (major! < 0 || (major === 0 && minor! < 8)) {
      return findings;
    }
  }

  const loopRegex =
    /\bfor\s*\(\s*(?:uint\d*\s+)?(\w+)\s*=\s*0\s*;\s*\w+\s*<\s*\w+(?:\.length)?\s*;/g;

  let match;
  while ((match = loopRegex.exec(source)) !== null) {
    const hasUnchecked = /unchecked\s*\{/.test(
      source.slice(match.index, source.indexOf("}", match.index + match[0].length))
    );

    if (!hasUnchecked) {
      const varName = match[1];
      const line = getLineNumber(source, match.index);

      findings.push(
        createFinding(
          PATTERNS.UNCHECKED_LOOP_INCREMENT!,
          `Loop counter '${varName}' increment can be wrapped in unchecked block since overflow is impossible with bounded iteration.`,
          fileName,
          line
        )
      );
    }
  }

  return findings;
}

function detectMultipleAddressMappings(stateVars: StateVariable[], fileName: string): Finding[] {
  const findings: Finding[] = [];

  const mappingsByKey = new Map<string, StateVariable[]>();

  for (const variable of stateVars) {
    const mappingMatch = variable.type.match(/^mapping\s*\(\s*(\w+)\s*=>/);
    if (mappingMatch) {
      const keyType = mappingMatch[1]!;
      if (!mappingsByKey.has(keyType)) {
        mappingsByKey.set(keyType, []);
      }
      mappingsByKey.get(keyType)!.push(variable);
    }
  }

  for (const [keyType, mappings] of mappingsByKey) {
    if (mappings.length >= 2) {
      const names = mappings.map((m) => m.name).join(", ");
      const line = mappings[0]!.line;

      findings.push(
        createFinding(
          PATTERNS.MULTIPLE_ADDRESS_MAPPINGS!,
          `Multiple mappings with '${keyType}' key: ${names}. ` +
            `Consider combining into a single mapping to a struct to save gas on storage slot calculations.`,
          fileName,
          line
        )
      );
    }
  }

  return findings;
}

// ============================================================================
// Main Analysis Function (public — used by optimizeGas.ts and tests)
// ============================================================================

/**
 * Analyze a Solidity contract for gas optimization opportunities.
 *
 * @param contractPath - Path to the .sol file
 * @returns Array of findings with gas optimization recommendations
 */
export async function analyzeGasPatterns(contractPath: string): Promise<Finding[]> {
  const source = await readFile(contractPath, "utf-8");
  const lines = source.split("\n");
  const fileName = basename(contractPath);

  const findings: Finding[] = [];

  const pragmaVersion = extractPragmaVersion(source);
  const contractBody = extractContractBody(source);
  const stateVariables = extractStateVariables(source);
  const functions = extractFunctionsWithBodies(contractBody, lines);
  const structs = extractStructs(source, lines);

  findings.push(
    ...detectStorageReadsInLoops(functions, stateVariables, fileName),
    ...detectStorageWritesInLoops(functions, stateVariables, fileName),
    ...detectMemoryVsCalldata(source, lines, fileName),
    ...detectMissingImmutable(source, stateVariables, contractBody, fileName, lines),
    ...detectGtZeroVsNeZero(source, lines, fileName),
    ...detectStringVsBytes32(source, lines, fileName),
    ...detectPostIncrement(source, lines, fileName, pragmaVersion),
    ...detectStructPacking(structs, fileName),
    ...detectUncheckedLoopIncrement(source, lines, fileName, pragmaVersion),
    ...detectMultipleAddressMappings(stateVariables, fileName)
  );

  return findings;
}

// ============================================================================
// Gas Optimizer Adapter
// ============================================================================

export class GasAdapter extends BaseAnalyzer<GasOptions> {
  readonly id = "gas" as const;
  readonly name = "Gas Optimizer";
  readonly description =
    "Pattern-based gas optimization analyzer that detects common inefficiencies " +
    "like storage reads in loops, missing immutable/constant, and suboptimal data types.";

  readonly capabilities: AnalyzerCapabilities = {
    requiresExternalTool: false,
    supportsSourceInput: true,
    supportsOptions: true,
    supportsParallel: true,
    detectorCount: 10,
  };

  getDefaultOptions(): GasOptions {
    return {
      timeout: 30_000,
      includeInformational: true,
    };
  }

  protected async doAnalyze(input: AnalyzerInput, options: GasOptions): Promise<AnalyzerResult> {
    const warnings: string[] = [];

    logger.info(`[GasAdapter] Analyzing ${input.contractPath}`);

    try {
      const findings = await analyzeGasPatterns(input.contractPath);

      let filteredFindings = findings;
      if (options.patterns && options.patterns.length > 0) {
        filteredFindings = findings.filter((f) =>
          options.patterns!.some(
            (p) => f.id.includes(p) || f.title.toLowerCase().includes(p.toLowerCase())
          )
        );
      }

      if (!options.includeInformational) {
        filteredFindings = filteredFindings.filter((f) => f.severity !== "informational");
      }

      logger.info(`[GasAdapter] Found ${filteredFindings.length} gas optimization opportunities`);

      return {
        ...this.createSuccessResult(
          filteredFindings,
          {
            detectorCount: this.capabilities.detectorCount,
          },
          warnings
        ),
        analyzerId: this.id,
        executionTime: 0,
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      logger.error(`[GasAdapter] Analysis failed: ${errorMessage}`);
      throw error;
    }
  }
}

// Export singleton instance
export const gasAdapter = new GasAdapter();
