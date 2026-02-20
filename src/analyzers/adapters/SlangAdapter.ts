/**
 * Slang Adapter
 *
 * Self-contained adapter using @nomicfoundation/slang for precise AST-based detection.
 *
 * Includes the full Slang analyzer implementation (security detectors, contract info
 * extraction, pattern detection) and the IAnalyzer-compatible adapter class.
 *
 * Benefits over regex:
 * - Precise AST matching (no false positives from comments/strings)
 * - Multi-version Solidity support
 * - Error-tolerant parsing
 */

import { Parser } from "@nomicfoundation/slang/parser";
import { Query, NonterminalKind } from "@nomicfoundation/slang/cst";
import { readFile } from "node:fs/promises";
import { basename } from "node:path";
import { BaseAnalyzer } from "../IAnalyzer.js";
import type {
  AnalyzerInput,
  AnalyzerResult,
  AnalyzerCapabilities,
  SlangOptions,
} from "../types.js";
import { logger } from "../../utils/logger.js";
import {
  Finding,
  Severity,
  type ContractInfo,
  type FunctionInfo,
  type VariableInfo,
  type Visibility,
  type StateMutability,
} from "../../types/index.js";

// ============================================================================
// Public Types
// ============================================================================

export interface SlangDetector {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  recommendation: string;
  query: Query;
  /** Optional capture name (defaults to "match") */
  captureName?: string;
  /** Optional function to extract additional context from the match */
  getContext?: (matchText: string) => string;
}

export interface SlangAnalysisResult {
  findings: Finding[];
  parseErrors: string[];
  executionTime: number;
  detectorCount: number;
}

export interface SlangAnalysisOptions {
  /** Solidity version (e.g., "0.8.22"). Auto-detected if not provided */
  version?: string;
  /** Specific detector IDs to run. Runs all if not specified */
  detectorIds?: string[];
  /** Include informational findings */
  includeInformational?: boolean;
}

export interface ParsedContract extends ContractInfo {
  imports: string[];
  events: string[];
  errors: string[];
  modifiers: string[];
  /** All contract/interface/library names defined in the file (when > 1) */
  contractsInFile?: string[];
}

export interface PatternMatch {
  pattern: string;
  line: number;
  code: string;
  risk: "high" | "medium" | "low" | "info";
  description: string;
}

// ============================================================================
// Security Detectors
// ============================================================================

const SECURITY_DETECTORS: Omit<SlangDetector, "query">[] = [
  {
    id: "SLANG-002",
    title: "Use of selfdestruct",
    description:
      "The selfdestruct function destroys the contract and sends all funds to the specified address. " +
      "This can be dangerous if access control is not properly implemented.",
    severity: Severity.HIGH,
    recommendation:
      "Avoid using selfdestruct. If necessary, ensure strict access control and consider using a withdrawal pattern instead.",
  },
  {
    id: "SLANG-009",
    title: "Inline Assembly Usage",
    description:
      "Inline assembly bypasses Solidity's safety features and type checking. " +
      "Errors in assembly code can lead to serious vulnerabilities.",
    severity: Severity.LOW,
    recommendation:
      "Minimize assembly usage. If necessary, thoroughly test and audit assembly code.",
  },
];

const QUERY_STRINGS: Record<string, string> = {
  "SLANG-002": `@match [FunctionCallExpression]`,
  "SLANG-009": `@match [YulBlock]`,
};

export { SECURITY_DETECTORS, QUERY_STRINGS };

// ============================================================================
// Internal Helper Functions
// ============================================================================

export function detectSolidityVersion(source: string): string {
  const pragmaMatch = source.match(/pragma\s+solidity\s+[\^>=<]*\s*(\d+\.\d+\.\d+)/);
  if (pragmaMatch?.[1]) {
    return pragmaMatch[1];
  }
  return "0.8.28";
}

function getLineAndColumn(source: string, offset: number): { line: number; column: number } {
  const lines = source.slice(0, offset).split("\n");
  return {
    line: lines.length,
    column: (lines[lines.length - 1]?.length ?? 0) + 1,
  };
}

export function buildDetectors(): SlangDetector[] {
  const detectors: SlangDetector[] = [];

  for (const detector of SECURITY_DETECTORS) {
    const queryString = QUERY_STRINGS[detector.id];
    if (!queryString) {
      logger.warn(`No query defined for detector ${detector.id}`);
      continue;
    }

    try {
      const query = Query.create(queryString);
      detectors.push({ ...detector, query });
    } catch (error) {
      let errorMessage: string;
      if (error instanceof Error) {
        errorMessage = error.message;
      } else if (typeof error === "object" && error !== null) {
        errorMessage = JSON.stringify(error, null, 2);
      } else {
        errorMessage = String(error);
      }
      logger.error(`Failed to parse query for ${detector.id}: ${errorMessage}`);
    }
  }

  return detectors;
}

function detectSlangPatterns(source: string, fileName: string): Finding[] {
  const findings: Finding[] = [];
  const lines = source.split("\n");

  const patterns: Array<{
    id: string;
    title: string;
    regex: RegExp;
    severity: Severity;
    description: string;
    recommendation: string;
  }> = [
    {
      id: "SLANG-001",
      title: "Use of tx.origin for Authorization",
      regex: /\btx\.origin\b/g,
      severity: Severity.HIGH,
      description:
        "Using tx.origin for authorization is vulnerable to phishing attacks. " +
        "An attacker can trick a user into calling a malicious contract that then calls your contract.",
      recommendation: "Use msg.sender instead of tx.origin for authorization checks.",
    },
    {
      id: "SLANG-002",
      title: "Use of selfdestruct",
      regex: /\b(selfdestruct|suicide)\s*\(/g,
      severity: Severity.HIGH,
      description:
        "The selfdestruct function destroys the contract and sends all funds to the specified address. " +
        "This can be dangerous if access control is not properly implemented. Note: selfdestruct is deprecated in newer EVM versions.",
      recommendation:
        "Avoid using selfdestruct. If necessary, ensure strict access control and consider using a withdrawal pattern instead.",
    },
    {
      id: "SLANG-003",
      title: "Use of delegatecall",
      regex: /\.delegatecall\s*\(/g,
      severity: Severity.HIGH,
      description:
        "delegatecall executes code in the context of the calling contract, which can be dangerous " +
        "if the target address is user-controlled or if storage layouts don't match.",
      recommendation:
        "Ensure delegatecall targets are trusted and storage layouts are compatible. Consider using a proxy pattern with proper safeguards.",
    },
    {
      id: "SLANG-004",
      title: "Unchecked Low-Level Call",
      regex: /\.call\s*\{[^}]*\}\s*\([^)]*\)\s*;/g,
      severity: Severity.MEDIUM,
      description:
        "Low-level calls (call, delegatecall, staticcall) return a boolean indicating success. " +
        "Failing to check this return value can lead to silent failures.",
      recommendation:
        "Always check the return value of low-level calls: (bool success, ) = addr.call(...); require(success);",
    },
    {
      id: "SLANG-005",
      title: "Use of block.timestamp",
      regex: /\bblock\.timestamp\b/g,
      severity: Severity.LOW,
      description:
        "block.timestamp can be manipulated by miners within a ~15 second window. " +
        "Using it for critical logic like random number generation or time-sensitive operations can be exploited.",
      recommendation:
        "Avoid using block.timestamp for randomness. For time-sensitive operations, consider using a larger time window or external time oracles.",
    },
    {
      id: "SLANG-006",
      title: "Use of block.number for Time",
      regex: /\bblock\.number\b/g,
      severity: Severity.LOW,
      description:
        "Using block.number to measure time is unreliable as block times can vary, " +
        "especially after the merge and with different L2s.",
      recommendation:
        "Use block.timestamp instead of block.number for time measurements, with appropriate safety margins.",
    },
    {
      id: "SLANG-008",
      title: "Use of transfer() or send()",
      regex: /\.(transfer|send)\s*\(/g,
      severity: Severity.MEDIUM,
      description:
        "transfer() and send() forward only 2300 gas, which may not be enough for contracts " +
        "with receive/fallback functions that use more gas. This can cause unexpected failures.",
      recommendation:
        "Use call() with proper reentrancy protection instead of transfer() or send().",
    },
    {
      id: "SLANG-010",
      title: "Use of ecrecover",
      regex: /\becrecover\s*\(/g,
      severity: Severity.MEDIUM,
      description:
        "ecrecover can return address(0) for invalid signatures. " +
        "Failing to check for this can lead to signature verification bypasses.",
      recommendation:
        "Always check that the address returned by ecrecover is not address(0) and matches the expected signer.",
    },
    {
      id: "SLANG-011",
      title: "Unchecked ERC20 Transfer Return Value",
      regex: /(?:IERC20|ERC20|token)\s*\([^)]*\)\s*\.\s*transfer\s*\([^)]*\)\s*;/gi,
      severity: Severity.HIGH,
      description:
        "ERC20 transfer() returns a boolean indicating success. Some tokens (like USDT) don't revert on failure. " +
        "Failing to check the return value can lead to silent transfer failures and loss of funds.",
      recommendation:
        "Use OpenZeppelin's SafeERC20 library with safeTransfer() and safeTransferFrom().",
    },
    {
      id: "SLANG-012",
      title: "Unchecked Block in Arithmetic",
      regex: /\bunchecked\s*\{[^}]*[+\-*/][^}]*\}/gs,
      severity: Severity.MEDIUM,
      description:
        "Unchecked blocks disable overflow/underflow checks in Solidity 0.8+. " +
        "While useful for gas optimization, they can reintroduce integer overflow vulnerabilities.",
      recommendation:
        "Only use unchecked blocks when you are certain overflow/underflow cannot occur. Document the reasoning.",
    },
  ];

  for (const pattern of patterns) {
    let match;
    pattern.regex.lastIndex = 0;

    while ((match = pattern.regex.exec(source)) !== null) {
      const beforeMatch = source.slice(0, match.index);
      const lineNumber = (beforeMatch.match(/\n/g) || []).length + 1;

      const line = lines[lineNumber - 1] || "";
      if (line.trim().startsWith("//") || line.trim().startsWith("*")) {
        continue;
      }

      findings.push({
        id: `${pattern.id}-L${lineNumber}`,
        title: pattern.title,
        severity: pattern.severity,
        description: pattern.description,
        location: {
          file: fileName,
          lines: [lineNumber, lineNumber],
        },
        recommendation: pattern.recommendation,
        detector: `slang:${pattern.id}`,
        confidence: "high",
      });

      if (match.index === pattern.regex.lastIndex) {
        pattern.regex.lastIndex++;
      }
    }
  }

  return findings;
}

// ============================================================================
// Main Analysis Function
// ============================================================================

export async function analyzeWithSlang(
  source: string,
  contractPath: string,
  options: SlangAnalysisOptions = {}
): Promise<SlangAnalysisResult> {
  const startTime = Date.now();
  const fileName = basename(contractPath);
  const findings: Finding[] = [];
  const parseErrors: string[] = [];

  const version = options.version ?? detectSolidityVersion(source);
  logger.info(`Slang analyzing with Solidity version ${version}`, { contractPath });

  let parser: Parser;
  try {
    parser = Parser.create(version);
  } catch {
    logger.warn(`Slang doesn't support version ${version}, falling back to 0.8.28`);
    try {
      parser = Parser.create("0.8.28");
    } catch (fallbackError) {
      return {
        findings: [],
        parseErrors: [
          `Failed to create parser: ${fallbackError instanceof Error ? fallbackError.message : String(fallbackError)}`,
        ],
        executionTime: Date.now() - startTime,
        detectorCount: 0,
      };
    }
  }

  const parseOutput = parser.parseNonterminal(NonterminalKind.SourceUnit, source);

  if (parseOutput.errors().length > 0) {
    for (const error of parseOutput.errors()) {
      parseErrors.push(`Parse error at offset ${error.textRange.start.utf8}: ${error.message}`);
    }
    logger.warn(`Slang found ${parseErrors.length} parse errors`, { contractPath });
  }

  const patternFindings = detectSlangPatterns(source, fileName);

  let filteredFindings = patternFindings;
  if (options.detectorIds && options.detectorIds.length > 0) {
    const detectorSet = new Set(options.detectorIds);
    filteredFindings = patternFindings.filter((f) => {
      const detectorId = f.detector?.replace("slang:", "") || "";
      return detectorSet.has(detectorId);
    });
  }

  if (!options.includeInformational) {
    filteredFindings = filteredFindings.filter((f) => f.severity !== Severity.INFORMATIONAL);
  }

  findings.push(...filteredFindings);

  const astDetectors = buildDetectors();
  const cursor = parseOutput.createTreeCursor();

  for (const detector of astDetectors) {
    if (findings.some((f) => f.detector === `slang:${detector.id}`)) {
      continue;
    }

    try {
      const matches = cursor.query([detector.query]);
      const captureName = detector.captureName ?? "match";

      for (const match of matches) {
        const captures = match.captures;
        const capturedNodes = captures[captureName];

        if (!capturedNodes || capturedNodes.length === 0) {
          continue;
        }

        for (const node of capturedNodes) {
          const textRange = node.textRange;
          const { line } = getLineAndColumn(source, textRange.start.utf8);
          const matchedText = source.slice(textRange.start.utf8, textRange.end.utf8);

          if (detector.id === "SLANG-002" && !matchedText.includes("selfdestruct")) {
            continue;
          }

          const context = detector.getContext ? detector.getContext(matchedText) : "";

          findings.push({
            id: `${detector.id}-L${line}`,
            title: detector.title,
            severity: detector.severity,
            description: detector.description + (context ? `\n\nContext: ${context}` : ""),
            location: {
              file: fileName,
              lines: [line, line],
            },
            recommendation: detector.recommendation,
            detector: `slang:${detector.id}`,
            confidence: "high",
          });
        }
      }
    } catch {
      logger.debug(`AST detector ${detector.id} skipped (pattern matching used instead)`);
    }
  }

  const seen = new Set<string>();
  const uniqueFindings = findings.filter((f) => {
    const key = `${f.detector}-${f.location?.lines?.[0]}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  const executionTime = Date.now() - startTime;
  logger.info(`Slang analysis completed`, {
    findings: uniqueFindings.length,
    parseErrors: parseErrors.length,
    executionTime,
    detectorCount: 12,
  });

  return {
    findings: uniqueFindings,
    parseErrors,
    executionTime,
    detectorCount: 12,
  };
}

// ============================================================================
// Contract Info Extraction
// ============================================================================

export async function parseContractInfo(contractPath: string): Promise<ParsedContract> {
  const source = await readFile(contractPath, "utf-8");
  return parseContractInfoFromSource(source, contractPath);
}

export function parseContractInfoFromSource(source: string, contractPath: string): ParsedContract {
  const version = detectSolidityVersion(source);

  let parser: Parser;
  try {
    parser = Parser.create(version);
  } catch {
    parser = Parser.create("0.8.28");
  }

  const parseOutput = parser.parseNonterminal(NonterminalKind.SourceUnit, source);
  const cursor = parseOutput.createTreeCursor();

  const pragma = extractPragmaFromSource(source);
  const imports = extractImportsFromSource(source);

  const contractQuery = Query.create(`@contract [ContractDefinition]`);

  interface ContractEntry {
    name: string;
    body: string;
    inherits: string[];
    isAbstract: boolean;
    isLibrary: boolean;
    isInterface: boolean;
    functionCount: number;
  }

  const allContracts: ContractEntry[] = [];

  for (const match of cursor.query([contractQuery])) {
    const captures = match.captures;
    const contractNodes = captures["contract"];

    if (!contractNodes || contractNodes.length === 0) continue;

    for (const node of contractNodes) {
      const textRange = node.textRange;
      const contractText = source.slice(textRange.start.utf8, textRange.end.utf8);

      const nameMatch = contractText.match(
        /^\s*(?:abstract\s+)?(contract|interface|library)\s+(\w+)/m
      );

      if (nameMatch) {
        const matchedType = nameMatch[1] as "contract" | "interface" | "library";
        const name = nameMatch[2] ?? basename(contractPath, ".sol");
        const entryIsAbstract = contractText.trim().startsWith("abstract");
        const entryIsLibrary = matchedType === "library";
        const entryIsInterface = matchedType === "interface";

        const contractDeclMatch = contractText.match(
          /^\s*(?:abstract\s+)?(?:contract|interface|library)\s+\w+\s+is\s+([^{]+)/m
        );
        const entryInherits = contractDeclMatch
          ? contractDeclMatch[1]!
              .split(",")
              .map((s) => s.trim().split("(")[0]!.trim())
              .filter((s) => Boolean(s) && /^\w+$/.test(s))
          : [];

        const fnCount = (contractText.match(/\bfunction\s+\w+/g) || []).length;

        allContracts.push({
          name,
          body: contractText,
          inherits: entryInherits,
          isAbstract: entryIsAbstract,
          isLibrary: entryIsLibrary,
          isInterface: entryIsInterface,
          functionCount: fnCount,
        });
      }
    }
  }

  if (allContracts.length === 0) {
    const contractRegex =
      /^\s*(?:abstract\s+)?(contract|interface|library)\s+(\w+)(?:\s+is\s+([^{]+))?\s*\{/gm;
    let m;
    while ((m = contractRegex.exec(source)) !== null) {
      const matchedType = m[1] as "contract" | "interface" | "library";
      const name = m[2] ?? basename(contractPath, ".sol");
      const entryInherits = m[3]
        ? m[3]
            .split(",")
            .map((s) => s.trim().split("(")[0]!.trim())
            .filter(Boolean)
        : [];
      const body = extractContractBodyFromSource(source, name);
      const fnCount = (body.match(/\bfunction\s+\w+/g) || []).length;
      allContracts.push({
        name,
        body,
        inherits: entryInherits,
        isAbstract: source.slice(0, m.index).trimEnd().endsWith("abstract"),
        isLibrary: matchedType === "library",
        isInterface: matchedType === "interface",
        functionCount: fnCount,
      });
    }
  }

  const primaryEntry =
    allContracts.find((c) => !c.isInterface && !c.isLibrary) ??
    allContracts.find((c) => !c.isInterface) ??
    allContracts[0];

  let contractName = basename(contractPath, ".sol");
  let inherits: string[] = [];
  let contractBody = "";
  let isAbstract = false;
  let isLibrary = false;

  if (primaryEntry) {
    contractName = primaryEntry.name;
    inherits = primaryEntry.inherits;
    contractBody = primaryEntry.body;
    isAbstract = primaryEntry.isAbstract;
    isLibrary = primaryEntry.isLibrary;
  }

  if (!contractBody) {
    contractBody = source;
  }

  const allContractNames = allContracts.map((c) => c.name);

  const functions = extractFunctionsFromBody(contractBody);
  const stateVariables = extractStateVariablesFromBody(contractBody);
  const events = extractEventsFromBody(contractBody);
  const errors = extractErrorsFromBody(contractBody);
  const modifierDefs = extractModifierDefsFromBody(contractBody);

  const hasConstructor = /\bconstructor\s*\(/.test(contractBody);
  const usesProxy = detectProxyPattern(source, inherits);
  const interfaces = detectImplementedInterfaces(inherits, imports);

  return {
    name: contractName,
    path: contractPath,
    compiler: pragma ?? "unknown",
    functions,
    stateVariables,
    inherits,
    interfaces,
    hasConstructor,
    usesProxy,
    imports,
    events,
    errors,
    modifiers: modifierDefs,
    isAbstract,
    isLibrary,
    contractsInFile: allContractNames.length > 1 ? allContractNames : undefined,
  };
}

// ============================================================================
// Extraction Helpers
// ============================================================================

function extractPragmaFromSource(source: string): string | undefined {
  const match = source.match(/pragma\s+solidity\s+([^;]+);/);
  return match?.[1]?.trim();
}

function extractImportsFromSource(source: string): string[] {
  const imports: string[] = [];
  const regex = /import\s+(?:(?:\{[^}]+\}|[\w*]+(?:\s+as\s+\w+)?)\s+from\s+)?["']([^"']+)["']/g;

  let match;
  while ((match = regex.exec(source)) !== null) {
    if (match[1]) {
      imports.push(match[1]);
    }
  }

  return imports;
}

function extractContractBodyFromSource(source: string, contractName: string): string {
  const contractRegex = new RegExp(
    `\\b(?:abstract\\s+)?(?:contract|library|interface)\\s+${contractName || "\\w+"}[^{]*\\{`
  );
  const startMatch = source.match(contractRegex);
  if (!startMatch) return source;

  const startIndex = startMatch.index! + startMatch[0].length;
  let braceCount = 1;
  let endIndex = startIndex;

  for (let i = startIndex; i < source.length && braceCount > 0; i++) {
    if (source[i] === "{") braceCount++;
    else if (source[i] === "}") braceCount--;
    endIndex = i;
  }

  return source.slice(startIndex, endIndex);
}

function extractFunctionsFromBody(contractBody: string): FunctionInfo[] {
  const functions: FunctionInfo[] = [];

  const functionRegex = /\bfunction\s+(\w+)\s*\(([^)]*)\)\s*([^{;]*?)(?:\{|;)/g;

  let match;
  while ((match = functionRegex.exec(contractBody)) !== null) {
    const name = match[1]!;
    const modifiersStr = match[3]!;

    functions.push({
      name,
      visibility: extractVisibilityFromStr(modifiersStr),
      modifiers: extractModifiersFromStr(modifiersStr),
      stateMutability: extractMutabilityFromStr(modifiersStr),
    });
  }

  const constructorMatch = contractBody.match(/\bconstructor\s*\(([^)]*)\)\s*([^{]*)\{/);
  if (constructorMatch) {
    const modifiersStr = constructorMatch[2] ?? "";
    functions.unshift({
      name: "constructor",
      visibility: extractVisibilityFromStr(modifiersStr) || "public",
      modifiers: extractModifiersFromStr(modifiersStr),
      stateMutability: modifiersStr.includes("payable") ? "payable" : "nonpayable",
    });
  }

  if (/\breceive\s*\(\s*\)\s*external\s+payable/.test(contractBody)) {
    functions.push({
      name: "receive",
      visibility: "external",
      modifiers: [],
      stateMutability: "payable",
    });
  }

  const fallbackMatch = contractBody.match(/\bfallback\s*\(\s*\)\s*external\s*(payable)?/);
  if (fallbackMatch) {
    functions.push({
      name: "fallback",
      visibility: "external",
      modifiers: [],
      stateMutability: fallbackMatch[1] ? "payable" : "nonpayable",
    });
  }

  return functions;
}

function extractVisibilityFromStr(modifiersStr: string): Visibility {
  if (/\bexternal\b/.test(modifiersStr)) return "external";
  if (/\bpublic\b/.test(modifiersStr)) return "public";
  if (/\binternal\b/.test(modifiersStr)) return "internal";
  if (/\bprivate\b/.test(modifiersStr)) return "private";
  return "internal";
}

function extractMutabilityFromStr(modifiersStr: string): StateMutability {
  if (/\bpure\b/.test(modifiersStr)) return "pure";
  if (/\bview\b/.test(modifiersStr)) return "view";
  if (/\bpayable\b/.test(modifiersStr)) return "payable";
  return "nonpayable";
}

function extractModifiersFromStr(modifiersStr: string): string[] {
  const modifiers: string[] = [];

  const cleaned = modifiersStr
    .replace(/\b(public|private|internal|external)\b/g, "")
    .replace(/\b(pure|view|payable)\b/g, "")
    .replace(/\b(virtual|override)\b/g, "")
    .replace(/\breturns\s*\([^)]*\)/g, "")
    .trim();

  const parts = cleaned.split(/\s+/).filter((p) => p.length > 0);

  for (const part of parts) {
    const modName = part.replace(/\([^)]*\)/, "").trim();
    if (modName && /^[a-zA-Z_]/.test(modName)) {
      modifiers.push(modName);
    }
  }

  if (/\bvirtual\b/.test(modifiersStr)) modifiers.push("virtual");
  if (/\boverride\b/.test(modifiersStr)) modifiers.push("override");

  return modifiers;
}

function extractStateVariablesFromBody(contractBody: string): VariableInfo[] {
  const variables: VariableInfo[] = [];

  const withoutFunctions = contractBody.replace(/\bfunction\s+\w+[^{]*\{[^}]*\}/g, "");

  const varRegex =
    /^\s*((?:mapping\s*\([^)]+\)|[\w[\]]+))\s+(public|private|internal|external)?\s*(constant|immutable)?\s*(\w+)\s*(?:=|;)/gm;

  let match;
  while ((match = varRegex.exec(withoutFunctions)) !== null) {
    const type = match[1]!.trim();
    const visibility = (match[2] as Visibility) ?? "internal";
    const name = match[4]!;

    if (name.startsWith("_") && type.includes("memory")) continue;

    variables.push({ name, type, visibility });
  }

  const simpleVarRegex = /^\s*(uint\d*|int\d*|address|bool|bytes\d*|string)\s+(\w+)\s*[;=]/gm;

  while ((match = simpleVarRegex.exec(withoutFunctions)) !== null) {
    const type = match[1]!;
    const name = match[2]!;

    if (!variables.some((v) => v.name === name)) {
      variables.push({ name, type, visibility: "internal" });
    }
  }

  return variables;
}

function extractEventsFromBody(contractBody: string): string[] {
  const events: string[] = [];
  const regex = /\bevent\s+(\w+)\s*\([^)]*\)/g;

  let match;
  while ((match = regex.exec(contractBody)) !== null) {
    if (match[1]) events.push(match[1]);
  }

  return events;
}

function extractErrorsFromBody(contractBody: string): string[] {
  const errors: string[] = [];
  const regex = /\berror\s+(\w+)\s*\([^)]*\)/g;

  let match;
  while ((match = regex.exec(contractBody)) !== null) {
    if (match[1]) errors.push(match[1]);
  }

  return errors;
}

function extractModifierDefsFromBody(contractBody: string): string[] {
  const modifiers: string[] = [];
  const regex = /\bmodifier\s+(\w+)\s*(?:\([^)]*\))?\s*\{/g;

  let match;
  while ((match = regex.exec(contractBody)) !== null) {
    if (match[1]) modifiers.push(match[1]);
  }

  return modifiers;
}

function detectProxyPattern(source: string, inherits: string[]): boolean {
  const proxyPatterns = [
    "Proxy",
    "TransparentUpgradeableProxy",
    "UUPSUpgradeable",
    "BeaconProxy",
    "ERC1967Proxy",
    "ERC1967Upgrade",
    "Initializable",
    "StorageSlot",
  ];

  for (const parent of inherits) {
    for (const pattern of proxyPatterns) {
      if (parent.includes(pattern)) return true;
    }
  }

  const proxyCodePatterns = [
    /\bdelegatecall\b/,
    /\b_implementation\b/,
    /\bimplementation\(\)/,
    /_IMPLEMENTATION_SLOT/,
    /IMPLEMENTATION_SLOT/,
    /upgradeTo\(/,
    /upgradeToAndCall\(/,
    /\binitialize\s*\(/,
    /\breinitializer\s*\(/,
  ];

  for (const pattern of proxyCodePatterns) {
    if (pattern.test(source)) return true;
  }

  return false;
}

function detectImplementedInterfaces(inherits: string[], imports: string[]): string[] {
  const interfaces: string[] = [];

  const interfacePatterns = [
    "IERC20",
    "IERC721",
    "IERC1155",
    "IERC165",
    "IERC2981",
    "IERC4626",
    "IAccessControl",
    "IGovernor",
    "IERC3156FlashLender",
    "IERC3156FlashBorrower",
  ];

  for (const parent of inherits) {
    if (parent.startsWith("I") && parent[1]?.toUpperCase() === parent[1]) {
      interfaces.push(parent);
    }
    for (const iface of interfacePatterns) {
      if (parent.includes(iface.slice(1))) {
        interfaces.push(iface);
      }
    }
  }

  for (const imp of imports) {
    const match = imp.match(/\/(I[A-Z]\w+)\.sol/);
    if (match) {
      interfaces.push(match[1]!);
    }
  }

  return [...new Set(interfaces)];
}

// ============================================================================
// Pattern Detection
// ============================================================================

export function detectPatterns(source: string): PatternMatch[] {
  const patterns: PatternMatch[] = [];
  const lines = source.split("\n");

  const patternDefs: Array<{
    name: string;
    regex: RegExp;
    risk: PatternMatch["risk"];
    description: string;
  }> = [
    {
      name: "tx.origin",
      regex: /\btx\.origin\b/,
      risk: "high",
      description: "Using tx.origin for authorization is vulnerable to phishing attacks",
    },
    {
      name: "selfdestruct",
      regex: /\b(selfdestruct|suicide)\s*\(/,
      risk: "high",
      description: "selfdestruct can destroy the contract and send funds to arbitrary address",
    },
    {
      name: "delegatecall",
      regex: /\.delegatecall\s*\(/,
      risk: "high",
      description: "delegatecall executes code in the context of the calling contract",
    },
    {
      name: "arbitrary-call",
      regex: /\.call\s*\{[^}]*\}\s*\(\s*[^)]*\)/,
      risk: "high",
      description: "Low-level call with arbitrary data may be dangerous",
    },
    {
      name: "inline-assembly",
      regex: /\bassembly\s*\{/,
      risk: "medium",
      description: "Inline assembly bypasses Solidity safety checks",
    },
    {
      name: "block.timestamp",
      regex: /\bblock\.timestamp\b/,
      risk: "medium",
      description: "block.timestamp can be manipulated by miners within ~15 seconds",
    },
    {
      name: "blockhash",
      regex: /\bblockhash\s*\(/,
      risk: "medium",
      description: "blockhash is only available for the last 256 blocks",
    },
    {
      name: "transfer",
      regex: /\.transfer\s*\(/,
      risk: "medium",
      description: "transfer() forwards only 2300 gas, may fail with contracts",
    },
    {
      name: "send",
      regex: /\.send\s*\(/,
      risk: "medium",
      description: "send() forwards only 2300 gas and returns bool, prefer call()",
    },
    {
      name: "unchecked",
      regex: /\bunchecked\s*\{/,
      risk: "medium",
      description: "unchecked block disables overflow/underflow checks",
    },
    {
      name: "abi.encodePacked",
      regex: /abi\.encodePacked\s*\([^)]*,[^)]*\)/,
      risk: "medium",
      description: "abi.encodePacked with multiple dynamic types can cause hash collisions",
    },
    {
      name: "block.number",
      regex: /\bblock\.number\b/,
      risk: "info",
      description: "block.number used - ensure it's not for critical timing",
    },
    {
      name: "ecrecover",
      regex: /\becrecover\s*\(/,
      risk: "low",
      description: "ecrecover can return zero address for invalid signatures",
    },
    {
      name: "extcodesize",
      regex: /\bextcodesize\b/,
      risk: "low",
      description: "extcodesize returns 0 for contracts during construction",
    },
    {
      name: "require-without-message",
      regex: /\brequire\s*\([^,)]+\)\s*;/,
      risk: "info",
      description: "require() without error message makes debugging harder",
    },
    {
      name: "assert",
      regex: /\bassert\s*\(/,
      risk: "info",
      description: "assert() consumes all gas on failure, prefer require()",
    },
    {
      name: "while-loop",
      regex: /\bwhile\s*\([^)]+\)\s*\{/,
      risk: "info",
      description: "while loops should have bounded iterations",
    },
    {
      name: "for-loop-unbounded",
      regex: /\bfor\s*\([^;]+;\s*\w+\s*<\s*\w+\.length\s*;/,
      risk: "low",
      description: "Loop over array.length may exceed gas limit for large arrays",
    },
    {
      name: "low-level-call",
      regex: /\.call\s*\(/,
      risk: "low",
      description: "Low-level call used - ensure return value is checked",
    },
  ];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    const lineNum = i + 1;

    if (line.trim().startsWith("//") || line.trim().startsWith("*")) {
      continue;
    }

    for (const def of patternDefs) {
      if (def.regex.test(line)) {
        const existing = patterns.find((p) => p.line === lineNum && p.pattern === def.name);
        if (!existing) {
          patterns.push({
            pattern: def.name,
            line: lineNum,
            code: line.trim().slice(0, 100),
            risk: def.risk,
            description: def.description,
          });
        }
      }
    }
  }

  const riskOrder: Record<PatternMatch["risk"], number> = {
    high: 0,
    medium: 1,
    low: 2,
    info: 3,
  };

  patterns.sort((a, b) => {
    const riskDiff = riskOrder[a.risk] - riskOrder[b.risk];
    if (riskDiff !== 0) return riskDiff;
    return a.line - b.line;
  });

  return patterns;
}

export function summarizePatterns(patterns: PatternMatch[]): Record<PatternMatch["risk"], number> {
  const summary: Record<PatternMatch["risk"], number> = {
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };

  for (const pattern of patterns) {
    summary[pattern.risk]++;
  }

  return summary;
}

export function formatPatterns(patterns: PatternMatch[]): string {
  if (patterns.length === 0) {
    return "No risky patterns detected.";
  }

  const lines: string[] = ["## Detected Patterns\n"];

  const byRisk: Record<PatternMatch["risk"], PatternMatch[]> = {
    high: [],
    medium: [],
    low: [],
    info: [],
  };

  for (const p of patterns) {
    byRisk[p.risk].push(p);
  }

  const riskLabels: Record<PatternMatch["risk"], string> = {
    high: "High Risk",
    medium: "Medium Risk",
    low: "Low Risk",
    info: "Informational",
  };

  for (const risk of ["high", "medium", "low", "info"] as const) {
    const riskPatterns = byRisk[risk];
    if (riskPatterns.length === 0) continue;

    lines.push(`### ${riskLabels[risk]} (${riskPatterns.length})\n`);

    for (const p of riskPatterns) {
      lines.push(`- **Line ${p.line}**: ${p.pattern}`);
      lines.push(`  - ${p.description}`);
      lines.push(`  - Code: \`${p.code}\``);
    }

    lines.push("");
  }

  return lines.join("\n");
}

// ============================================================================
// Slang Adapter
// ============================================================================

export class SlangAdapter extends BaseAnalyzer<SlangOptions> {
  readonly id = "slang" as const;
  readonly name = "Slang AST Analyzer";
  readonly description =
    "AST-based analyzer using @nomicfoundation/slang for deep code analysis, " +
    "detecting patterns that require understanding of code structure.";

  readonly capabilities: AnalyzerCapabilities = {
    requiresExternalTool: false,
    supportsSourceInput: true,
    supportsOptions: true,
    supportsParallel: true,
    detectorCount: 12,
  };

  // checkAvailability is inherited from BaseAnalyzer (always available)

  getDefaultOptions(): SlangOptions {
    return {
      timeout: 60_000,
      includeInformational: true,
    };
  }

  protected async doAnalyze(input: AnalyzerInput, options: SlangOptions): Promise<AnalyzerResult> {
    const warnings: string[] = [];

    logger.info(`[SlangAdapter] Analyzing ${input.contractPath}`);

    try {
      let source = input.source;
      if (!source) {
        source = await readFile(input.contractPath, "utf-8");
      }

      const result = await analyzeWithSlang(source, input.contractPath, {
        version: input.solidityVersion,
        detectorIds: options.detectorIds,
        includeInformational: options.includeInformational,
      });

      if (result.parseErrors.length > 0) {
        warnings.push(...result.parseErrors.map((e) => `Parse warning: ${e}`));
      }

      const filteredFindings = options.includeInformational
        ? result.findings
        : result.findings.filter((f) => f.severity !== "informational");

      logger.info(
        `[SlangAdapter] Found ${filteredFindings.length} findings ` +
          `from ${result.detectorCount} detectors`
      );

      return {
        ...this.createSuccessResult(
          filteredFindings,
          {
            detectorCount: result.detectorCount,
            parseErrors: result.parseErrors,
          },
          warnings
        ),
        analyzerId: this.id,
        executionTime: result.executionTime,
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      logger.error(`[SlangAdapter] Analysis failed: ${errorMessage}`);
      throw error;
    }
  }
}

// Export singleton instance
export const slangAdapter = new SlangAdapter();
