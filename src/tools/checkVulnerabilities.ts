/**
 * Check Vulnerabilities Tool
 *
 * Analyzes Solidity contracts against the SWC Registry patterns.
 * Performs pattern-based detection without requiring compilation.
 */

import { readFile, access } from "fs/promises";
import { z } from "zod";
import { Severity } from "../types/index.js";
import { logger } from "../utils/logger.js";

// ============================================================================
// Types
// ============================================================================

export const CheckVulnerabilitiesInputSchema = z.object({
  contractPath: z.string().describe("Path to the Solidity contract file"),
  detectors: z
    .array(z.string())
    .optional()
    .describe("Specific SWC IDs to check (e.g., ['SWC-107', 'SWC-115'])"),
});

export type CheckVulnerabilitiesInput = z.infer<typeof CheckVulnerabilitiesInputSchema>;

export interface VulnerabilityMatch {
  swcId: string;
  title: string;
  description: string;
  severity: Severity;
  matches: Array<{
    line: number;
    code: string;
    context: string;
  }>;
  remediation: string;
  references: string[];
}

export interface VulnerabilityReport {
  contractPath: string;
  totalVulnerabilities: number;
  bySeverity: Record<string, number>;
  vulnerabilities: VulnerabilityMatch[];
  scannedDetectors: string[];
}

// ============================================================================
// SWC Registry Patterns
// ============================================================================

interface SWCPattern {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  patterns: RegExp[];
  negativePatterns?: RegExp[];
  remediation: string;
  references: string[];
}

/**
 * SWC Registry patterns for Solidity vulnerabilities.
 * See: https://swcregistry.io/
 */
const SWC_PATTERNS: SWCPattern[] = [
  // SWC-100: Function Default Visibility
  {
    id: "SWC-100",
    title: "Function Default Visibility",
    description:
      "Functions without explicit visibility are public by default in older Solidity versions. " +
      "This can lead to unauthorized access.",
    severity: Severity.MEDIUM,
    patterns: [
      /function\s+\w+\s*\([^)]*\)\s*(?:(?:pure|view|payable|virtual|override)\s+)*(?:returns\s*\([^)]*\)\s*)?{/g,
    ],
    negativePatterns: [/function\s+\w+\s*\([^)]*\)\s*(?:public|private|internal|external)/g],
    remediation:
      "Always explicitly declare function visibility (public, private, internal, or external).",
    references: ["https://swcregistry.io/docs/SWC-100"],
  },

  // SWC-101: Integer Overflow/Underflow
  {
    id: "SWC-101",
    title: "Integer Overflow and Underflow",
    description:
      "Arithmetic operations can overflow or underflow. Solidity 0.8+ has built-in checks, " +
      "but unchecked blocks bypass them.",
    severity: Severity.HIGH,
    patterns: [/unchecked\s*\{[^}]*[+\-*][^}]*\}/gs],
    remediation: "Use SafeMath for Solidity < 0.8, or be careful with unchecked blocks in 0.8+.",
    references: ["https://swcregistry.io/docs/SWC-101"],
  },

  // SWC-103: Floating Pragma
  {
    id: "SWC-103",
    title: "Floating Pragma",
    description:
      "Contracts should be deployed with the same compiler version they were tested with. " +
      "Floating pragmas allow different versions.",
    severity: Severity.LOW,
    patterns: [/pragma\s+solidity\s*\^/g, /pragma\s+solidity\s*>=/g],
    remediation: "Lock the pragma to a specific version, e.g., 'pragma solidity 0.8.20;'",
    references: ["https://swcregistry.io/docs/SWC-103"],
  },

  // SWC-104: Unchecked Call Return Value
  {
    id: "SWC-104",
    title: "Unchecked Call Return Value",
    description:
      "The return value of low-level calls (call, delegatecall, send) must be checked " +
      "to handle failures properly.",
    severity: Severity.HIGH,
    patterns: [
      /\.call\s*\{[^}]*\}\s*\([^)]*\)\s*;/g,
      /\.delegatecall\s*\([^)]*\)\s*;/g,
      /\.send\s*\([^)]*\)\s*;/g,
    ],
    negativePatterns: [/\(\s*bool\s+\w+\s*,\s*\)\s*=.*\.call/g, /require\s*\(.*\.send/g],
    remediation:
      "Always check the return value of low-level calls: (bool success, ) = addr.call(...); require(success);",
    references: ["https://swcregistry.io/docs/SWC-104"],
  },

  // SWC-105: Unprotected Ether Withdrawal
  {
    id: "SWC-105",
    title: "Unprotected Ether Withdrawal",
    description:
      "Functions that withdraw Ether should have proper access control to prevent " +
      "unauthorized fund draining.",
    severity: Severity.CRITICAL,
    patterns: [/function\s+withdraw[^{]*\{[^}]*(?:\.transfer|\.send|\.call\{value)[^}]*\}/gs],
    negativePatterns: [/onlyOwner|onlyAdmin|require\s*\(\s*msg\.sender\s*==|_checkOwner/g],
    remediation:
      "Add access control (onlyOwner, require(msg.sender == owner)) to withdrawal functions.",
    references: ["https://swcregistry.io/docs/SWC-105"],
  },

  // SWC-106: Unprotected SELFDESTRUCT
  {
    id: "SWC-106",
    title: "Unprotected SELFDESTRUCT",
    description:
      "SELFDESTRUCT can destroy the contract and send its Ether to an arbitrary address. " +
      "Must be protected with access control.",
    severity: Severity.CRITICAL,
    patterns: [/selfdestruct\s*\(/g],
    remediation:
      "Add strict access control and consider if selfdestruct is really needed. " +
      "Note: selfdestruct is deprecated in newer EVM versions.",
    references: ["https://swcregistry.io/docs/SWC-106"],
  },

  // SWC-107: Reentrancy
  {
    id: "SWC-107",
    title: "Reentrancy",
    description:
      "Functions making external calls before updating state can be vulnerable to reentrancy attacks.",
    severity: Severity.HIGH,
    patterns: [
      // External call followed by state change (simplified pattern)
      /\.call\{value[^}]*\}[^;]*;[^}]*\w+\s*(?:\+|-)?=/gs,
      /\.transfer\s*\([^)]*\)[^;]*;[^}]*\w+\s*(?:\+|-)?=/gs,
    ],
    remediation:
      "Use the Checks-Effects-Interactions pattern. Consider using ReentrancyGuard from OpenZeppelin.",
    references: ["https://swcregistry.io/docs/SWC-107"],
  },

  // SWC-108: State Variable Default Visibility
  {
    id: "SWC-108",
    title: "State Variable Default Visibility",
    description:
      "State variables without explicit visibility default to internal. " +
      "This should be intentional, not accidental.",
    severity: Severity.LOW,
    patterns: [/^\s*(?:uint|int|address|bool|bytes|string|mapping)\d*\s+\w+\s*[;=]/gm],
    negativePatterns: [
      /(?:public|private|internal)\s+(?:uint|int|address|bool|bytes|string|mapping)/g,
    ],
    remediation: "Always explicitly declare state variable visibility.",
    references: ["https://swcregistry.io/docs/SWC-108"],
  },

  // SWC-110: Assert Violation
  {
    id: "SWC-110",
    title: "Assert Violation",
    description:
      "Assert should only be used to test for internal errors. Failed asserts consume all gas.",
    severity: Severity.MEDIUM,
    patterns: [/assert\s*\([^)]*(?:msg\.sender|tx\.origin|block\.)[^)]*\)/g],
    remediation: "Use require() for input validation and assert() only for internal invariants.",
    references: ["https://swcregistry.io/docs/SWC-110"],
  },

  // SWC-111: Use of Deprecated Functions
  {
    id: "SWC-111",
    title: "Use of Deprecated Solidity Functions",
    description:
      "Deprecated functions like sha3(), suicide(), throw, etc. should be replaced with modern equivalents.",
    severity: Severity.INFORMATIONAL,
    patterns: [
      /\bsha3\s*\(/g,
      /\bsuicide\s*\(/g,
      /\bthrow\s*;/g,
      /\bblock\.blockhash\s*\(/g,
      /\bconstant\s+function\b/g,
    ],
    remediation:
      "Replace sha3 with keccak256, suicide with selfdestruct, throw with revert(), etc.",
    references: ["https://swcregistry.io/docs/SWC-111"],
  },

  // SWC-112: Delegatecall to Untrusted Callee
  {
    id: "SWC-112",
    title: "Delegatecall to Untrusted Callee",
    description:
      "Delegatecall executes code in the context of the calling contract. " +
      "Calling untrusted contracts can lead to storage manipulation.",
    severity: Severity.CRITICAL,
    patterns: [/\.delegatecall\s*\(/g, /delegatecall\s*\(\s*abi\.encodeWithSignature/g],
    remediation:
      "Only use delegatecall with trusted, audited contracts. Consider using a proxy pattern with immutable implementation.",
    references: ["https://swcregistry.io/docs/SWC-112"],
  },

  // SWC-113: DoS with Failed Call
  {
    id: "SWC-113",
    title: "DoS with Failed Call",
    description:
      "Loops that make external calls can be DoS'd if one call fails. " +
      "This is common in refund or distribution patterns.",
    severity: Severity.MEDIUM,
    patterns: [
      /for\s*\([^)]*\)\s*\{[^}]*\.(?:transfer|send|call)[^}]*\}/gs,
      /while\s*\([^)]*\)\s*\{[^}]*\.(?:transfer|send|call)[^}]*\}/gs,
    ],
    remediation:
      "Use a pull payment pattern instead of push. Store amounts and let users withdraw.",
    references: ["https://swcregistry.io/docs/SWC-113"],
  },

  // SWC-114: Transaction Order Dependence
  {
    id: "SWC-114",
    title: "Transaction Order Dependence (Front-Running)",
    description:
      "Transactions are public in the mempool. Sensitive operations like approve() " +
      "can be front-run by attackers.",
    severity: Severity.MEDIUM,
    patterns: [/function\s+approve\s*\([^)]*\)[^{]*\{[^}]*allowance[^}]*=[^}]*\}/gs],
    remediation:
      "Use increaseAllowance/decreaseAllowance pattern or commit-reveal schemes for sensitive operations.",
    references: ["https://swcregistry.io/docs/SWC-114"],
  },

  // SWC-115: Authorization through tx.origin
  {
    id: "SWC-115",
    title: "Authorization through tx.origin",
    description:
      "tx.origin returns the original sender of a transaction, not the immediate caller. " +
      "Using it for authorization is vulnerable to phishing attacks.",
    severity: Severity.HIGH,
    patterns: [
      /require\s*\(\s*tx\.origin\s*==\s*/g,
      /if\s*\(\s*tx\.origin\s*==\s*/g,
      /tx\.origin\s*==\s*owner/g,
    ],
    remediation: "Use msg.sender instead of tx.origin for authorization checks.",
    references: ["https://swcregistry.io/docs/SWC-115"],
  },

  // SWC-116: Block values as Time Proxy
  {
    id: "SWC-116",
    title: "Block values as a Proxy for Time",
    description:
      "block.timestamp and block.number can be manipulated by miners within limits. " +
      "Don't use them for critical time-dependent logic.",
    severity: Severity.LOW,
    patterns: [/block\.timestamp\s*[<>=]/g, /block\.number\s*[<>=]/g, /now\s*[<>=]/g],
    remediation:
      "Avoid tight time constraints. Use time windows instead of exact timestamps. " +
      "Consider using an oracle for critical timing.",
    references: ["https://swcregistry.io/docs/SWC-116"],
  },

  // SWC-117: Signature Malleability
  {
    id: "SWC-117",
    title: "Signature Malleability",
    description:
      "ECDSA signatures can be malleable. An attacker can modify (v, r, s) to create " +
      "a valid but different signature.",
    severity: Severity.MEDIUM,
    patterns: [/ecrecover\s*\(/g, /ECDSA\.recover\s*\(/g],
    negativePatterns: [/require\s*\(\s*s\s*<=.*0x7FFFFFFF/g, /SignatureChecker/g],
    remediation:
      "Use OpenZeppelin's ECDSA library which handles signature malleability. " +
      "Include a nonce to prevent replay attacks.",
    references: ["https://swcregistry.io/docs/SWC-117"],
  },

  // SWC-119: Shadowing State Variables
  {
    id: "SWC-119",
    title: "Shadowing State Variables",
    description:
      "Local variables with the same name as state variables can lead to confusion and bugs.",
    severity: Severity.LOW,
    patterns: [
      // Hard to detect with regex without full AST, but common patterns:
      /function\s+\w+\s*\([^)]*(\w+)[^)]*\)[^{]*\{[^}]*\1\s*=[^;]*;/gs,
    ],
    remediation:
      "Avoid using the same name for local and state variables. Use prefixes like '_' for local variables.",
    references: ["https://swcregistry.io/docs/SWC-119"],
  },

  // SWC-120: Weak Randomness
  {
    id: "SWC-120",
    title: "Weak Randomness",
    description:
      "Using block variables (timestamp, difficulty, blockhash) for randomness is predictable " +
      "and can be manipulated by miners.",
    severity: Severity.HIGH,
    patterns: [/keccak256\s*\(\s*abi\.encodePacked\s*\(\s*block\./g, /uint\s*\(\s*blockhash\s*\(/g],
    remediation: "Use a verifiable random function (VRF) like Chainlink VRF for secure randomness.",
    references: ["https://swcregistry.io/docs/SWC-120"],
  },

  // SWC-121: Re-Entrancy via Transfer/Send
  {
    id: "SWC-121",
    title: "Re-Entrancy via Transfer/Send",
    description:
      "While transfer/send only forward 2300 gas, re-entrancy is still possible if the " +
      "receiver has a fallback that fits in that gas or if used with certain tokens.",
    severity: Severity.MEDIUM,
    patterns: [/\.(?:transfer|send)\s*\(/g],
    remediation: "Follow Checks-Effects-Interactions and use ReentrancyGuard.",
    references: ["https://swcregistry.io/docs/SWC-121"],
  },

  // SWC-123: Requirement Violation
  {
    id: "SWC-123",
    title: "Requirement Violation",
    description:
      "Failing to properly validate requirements can lead to unexpected state transitions.",
    severity: Severity.MEDIUM,
    patterns: [/require\s*\([^,)]*\)\s*;/g], // Require without message
    remediation: "Always provide descriptive error messages in require().",
    references: ["https://swcregistry.io/docs/SWC-123"],
  },

  // SWC-124: Write to Arbitrary Storage Location
  {
    id: "SWC-124",
    title: "Write to Arbitrary Storage Location",
    description: "Allowing users to write to arbitrary storage slots can compromise the contract.",
    severity: Severity.CRITICAL,
    patterns: [
      /assembly\s*\{[^}]*sstore\s*\([^,)]*,[^)]*\)/gs,
      /\w+\[[^\]]*\]\s*=\s*\w+/g, // Array/mapping access (very broad)
    ],
    remediation: "Strictly validate all storage indices and offsets, especially in assembly.",
    references: ["https://swcregistry.io/docs/SWC-124"],
  },

  // SWC-125: Incorrect Inheritance Order
  {
    id: "SWC-125",
    title: "Incorrect Inheritance Order",
    description:
      "Solidity uses C3 Linearization. Incorrect order can cause the wrong function " +
      "to be called in the inheritance hierarchy.",
    severity: Severity.MEDIUM,
    patterns: [/contract\s+\w+\s+is\s+[\w\s,]+\{/g],
    remediation: "List base contracts from 'most base-like' to 'most derived'.",
    references: ["https://swcregistry.io/docs/SWC-125"],
  },

  // SWC-127: Arbitrary Jump with Function Type Variable
  {
    id: "SWC-127",
    title: "Arbitrary Jump with Function Type Variable",
    description: "Function type variables can be manipulated to jump to arbitrary code locations.",
    severity: Severity.HIGH,
    patterns: [/function\s*\([^)]*\)\s*(?:internal|external)\s+\w+;/g],
    remediation: "Avoid using function type variables if possible.",
    references: ["https://swcregistry.io/docs/SWC-127"],
  },

  // SWC-128: DoS with Block Gas Limit
  {
    id: "SWC-128",
    title: "DoS with Block Gas Limit",
    description: "Operations that iterate over unbounded arrays can exceed the block gas limit.",
    severity: Severity.MEDIUM,
    patterns: [/for\s*\([^;]*;\s*[^;]*\.length;\s*[^)]*\)/g, /while\s*\([^)]*\.length\s*[^)]*\)/g],
    remediation: "Avoid unbounded loops. Use pagination or fixed-size arrays.",
    references: ["https://swcregistry.io/docs/SWC-128"],
  },

  // SWC-129: Typographical Error
  {
    id: "SWC-129",
    title: "Typographical Error",
    description: "Typos in operators (e.g., =+ instead of +=) or variable names can lead to bugs.",
    severity: Severity.LOW,
    patterns: [/\w+\s*=\+\s*/g, /\w+\s*=-\s*/g],
    remediation: "Use a linter and perform thorough code reviews.",
    references: ["https://swcregistry.io/docs/SWC-129"],
  },

  // SWC-130: Right-To-Left-Override character (U+202E)
  {
    id: "SWC-130",
    title: "Right-To-Left-Override character (U+202E)",
    description: "Malicious actors can use the U+202E character to disguise the actual code.",
    severity: Severity.HIGH,
    patterns: [/\u202E/g],
    remediation: "Never use hidden or misleading characters in source code.",
    references: ["https://swcregistry.io/docs/SWC-130"],
  },

  // SWC-132: Unexpected Ether balance
  {
    id: "SWC-132",
    title: "Unexpected Ether balance",
    description:
      "Contracts should not assume their balance is zero or only increased through " +
      "payable functions. Ether can be forced via selfdestruct or coinbase rewards.",
    severity: Severity.MEDIUM,
    patterns: [/address\s*\(this\)\.balance\s*==/g, /this\.balance\s*==/g],
    remediation:
      "Don't rely on strict equality for balance checks. Use >= or a separate accounting variable.",
    references: ["https://swcregistry.io/docs/SWC-132"],
  },

  // SWC-133: Hash Collisions with Multiple Variable Length Arguments
  {
    id: "SWC-133",
    title: "Hash Collisions with Multiple Variable Length Arguments",
    description:
      "Using abi.encodePacked with multiple dynamic types can result in the same output " +
      "for different inputs.",
    severity: Severity.MEDIUM,
    patterns: [/abi\.encodePacked\s*\([^)]*(?:string|bytes)[^)]*(?:string|bytes)[^)]*\)/g],
    remediation: "Use abi.encode() instead of abi.encodePacked().",
    references: ["https://swcregistry.io/docs/SWC-133"],
  },

  // SWC-134: Message call with hardcoded gas amount
  {
    id: "SWC-134",
    title: "Message call with hardcoded gas amount",
    description: "Hardcoding gas can cause calls to fail if EVM gas costs change.",
    severity: Severity.MEDIUM,
    patterns: [/\.call\{[^}]*gas:\s*\d+/g],
    remediation: "Avoid hardcoding gas amounts unless absolutely necessary.",
    references: ["https://swcregistry.io/docs/SWC-134"],
  },

  // SWC-135: Code Injection via delegatecall
  {
    id: "SWC-135",
    title: "Code Injection via delegatecall",
    description:
      "Passing user-supplied data to delegatecall can allow them to execute arbitrary code.",
    severity: Severity.CRITICAL,
    patterns: [/\.delegatecall\s*\(\s*msg\.data\s*\)/g],
    remediation: "Never use delegatecall with user-supplied data.",
    references: ["https://swcregistry.io/docs/SWC-135"],
  },

  // SWC-136: Unencrypted Private Data On-Chain
  {
    id: "SWC-136",
    title: "Unencrypted Private Data On-Chain",
    description: "All data on the blockchain is public, including variables marked 'private'.",
    severity: Severity.INFORMATIONAL,
    patterns: [/private\s+(?:uint|int|address|bool|bytes|string|mapping)/g],
    remediation: "Don't store sensitive data on-chain. Encrypt if necessary.",
    references: ["https://swcregistry.io/docs/SWC-136"],
  },

  // SWC-118: Incorrect Constructor Name
  {
    id: "SWC-118",
    title: "Incorrect Constructor Name",
    description:
      "In older Solidity versions, constructors used the contract name. " +
      "Typos make the function callable by anyone.",
    severity: Severity.CRITICAL,
    patterns: [
      /function\s+\w+\s*\([^)]*\)\s*(?:public|external)?\s*\{[^}]*owner\s*=\s*msg\.sender[^}]*\}/gs,
    ],
    negativePatterns: [/constructor\s*\(/g],
    remediation: "Use the 'constructor' keyword (Solidity >= 0.4.22) instead of a named function.",
    references: ["https://swcregistry.io/docs/SWC-118"],
  },

  // SWC-119: Shadowing State Variables
  {
    id: "SWC-119",
    title: "Shadowing State Variables",
    description:
      "A derived contract can declare a variable with the same name as one in a base contract, " +
      "hiding the original variable.",
    severity: Severity.MEDIUM,
    patterns: [], // This requires inheritance analysis, can't easily detect with regex
    remediation:
      "Use different names for variables in derived contracts. Be explicit about which variable you're accessing.",
    references: ["https://swcregistry.io/docs/SWC-119"],
  },

  // SWC-120: Weak Sources of Randomness
  {
    id: "SWC-120",
    title: "Weak Sources of Randomness from Chain Attributes",
    description:
      "Using block.timestamp, block.difficulty, blockhash, etc. for randomness is predictable " +
      "and can be manipulated by miners.",
    severity: Severity.HIGH,
    patterns: [
      /block\.(?:timestamp|difficulty|number|coinbase|gaslimit)/g,
      /blockhash\s*\(/g,
      /keccak256\s*\([^)]*block\./g,
    ],
    remediation:
      "Use Chainlink VRF or commit-reveal schemes for randomness. Never use on-chain data for lotteries or games.",
    references: ["https://swcregistry.io/docs/SWC-120"],
  },

  // SWC-123: Requirement Violation
  {
    id: "SWC-123",
    title: "Requirement Violation",
    description: "Empty require statements or requires that are always true/false are bugs.",
    severity: Severity.MEDIUM,
    patterns: [/require\s*\(\s*true\s*\)/g, /require\s*\(\s*false\s*\)/g, /require\s*\(\s*\)/g],
    remediation: "Ensure require statements have meaningful conditions.",
    references: ["https://swcregistry.io/docs/SWC-123"],
  },

  // SWC-124: Write to Arbitrary Storage Location
  {
    id: "SWC-124",
    title: "Write to Arbitrary Storage Location",
    description:
      "Assembly code that writes to storage based on user input can overwrite critical data.",
    severity: Severity.CRITICAL,
    patterns: [/assembly\s*\{[^}]*sstore\s*\([^)]*\)[^}]*\}/gs, /sstore\s*\(\s*\w+\s*,/g],
    remediation: "Validate storage slots carefully. Avoid user-controlled storage writes.",
    references: ["https://swcregistry.io/docs/SWC-124"],
  },

  // SWC-125: Incorrect Inheritance Order
  {
    id: "SWC-125",
    title: "Incorrect Inheritance Order",
    description:
      "Solidity uses C3 linearization. Incorrect inheritance order can cause unexpected behavior " +
      "with multiple inheritance.",
    severity: Severity.MEDIUM,
    patterns: [], // Requires AST analysis
    remediation:
      "Order inheritance from most base-like to most derived. " +
      "List interfaces first, then abstract contracts, then concrete implementations.",
    references: ["https://swcregistry.io/docs/SWC-125"],
  },

  // SWC-126: Insufficient Gas Griefing
  {
    id: "SWC-126",
    title: "Insufficient Gas Griefing",
    description:
      "Relayers can provide just enough gas for the outer call but not enough for subcalls, " +
      "causing unexpected failures.",
    severity: Severity.MEDIUM,
    patterns: [/\.call\{[^}]*gas\s*:/g, /gasleft\s*\(\s*\)/g],
    remediation: "Use EIP-150 aware patterns. Consider checking gasleft() before making subcalls.",
    references: ["https://swcregistry.io/docs/SWC-126"],
  },

  // SWC-127: Arbitrary Jump with Function Type Variable
  {
    id: "SWC-127",
    title: "Arbitrary Jump with Function Type Variable",
    description:
      "Function type variables can be manipulated in assembly to jump to arbitrary code.",
    severity: Severity.HIGH,
    patterns: [
      /function\s*\([^)]*\)\s*(?:internal|external)\s+\w+\s*;/g,
      /assembly\s*\{[^}]*jump[^}]*\}/gs,
    ],
    remediation:
      "Avoid using function type variables with assembly. Validate function pointers carefully.",
    references: ["https://swcregistry.io/docs/SWC-127"],
  },

  // SWC-128: DoS with Block Gas Limit
  {
    id: "SWC-128",
    title: "DoS with Block Gas Limit",
    description:
      "Loops over unbounded arrays can exceed block gas limit, making functions unusable.",
    severity: Severity.MEDIUM,
    patterns: [/for\s*\([^)]*;\s*\w+\s*<\s*\w+\.length\s*;/g, /while\s*\([^)]*\.length/g],
    remediation:
      "Limit loop iterations. Use pagination patterns. Consider off-chain computation with on-chain verification.",
    references: ["https://swcregistry.io/docs/SWC-128"],
  },

  // SWC-129: Typographical Error
  {
    id: "SWC-129",
    title: "Typographical Error",
    description: "Common typos like =+ instead of += can lead to unexpected behavior.",
    severity: Severity.HIGH,
    patterns: [/\w+\s*=\+\s*\d/g, /\w+\s*=-\s*\d/g],
    remediation: "Use proper compound assignment operators: +=, -=, *=, /=",
    references: ["https://swcregistry.io/docs/SWC-129"],
  },

  // SWC-130: Right-To-Left-Override Control Character
  {
    id: "SWC-130",
    title: "Right-To-Left-Override Control Character",
    description:
      "The RTLO character (U+202E) can make code appear different than it executes, " +
      "hiding malicious logic.",
    severity: Severity.HIGH,
    patterns: [/\u202E/g],
    remediation: "Remove all RTLO characters. Use tools that detect Unicode attacks.",
    references: ["https://swcregistry.io/docs/SWC-130"],
  },

  // SWC-131: Presence of Unused Variables
  {
    id: "SWC-131",
    title: "Presence of Unused Variables",
    description: "Unused variables indicate incomplete code, bugs, or unnecessary gas consumption.",
    severity: Severity.INFORMATIONAL,
    patterns: [], // Requires semantic analysis
    remediation: "Remove unused variables or implement their intended usage.",
    references: ["https://swcregistry.io/docs/SWC-131"],
  },

  // SWC-132: Unexpected Ether Balance
  {
    id: "SWC-132",
    title: "Unexpected Ether Balance",
    description:
      "Contracts can receive Ether via selfdestruct or coinbase rewards, " +
      "bypassing receive/fallback functions.",
    severity: Severity.MEDIUM,
    patterns: [
      /require\s*\(\s*address\s*\(\s*this\s*\)\.balance\s*==\s*/g,
      /assert\s*\(\s*address\s*\(\s*this\s*\)\.balance\s*==\s*/g,
    ],
    remediation:
      "Don't rely on exact balance checks. Use >= instead of == for balance comparisons.",
    references: ["https://swcregistry.io/docs/SWC-132"],
  },

  // SWC-133: Hash Collision with Multiple Variable Length Arguments
  {
    id: "SWC-133",
    title: "Hash Collisions With Multiple Variable Length Arguments",
    description:
      "abi.encodePacked with multiple variable-length arguments can create hash collisions.",
    severity: Severity.MEDIUM,
    patterns: [/keccak256\s*\(\s*abi\.encodePacked\s*\([^)]*,\s*[^)]*\)/g],
    remediation:
      "Use abi.encode instead of abi.encodePacked for hashing, or add delimiters between arguments.",
    references: ["https://swcregistry.io/docs/SWC-133"],
  },

  // SWC-134: Message Call with Hardcoded Gas Amount
  {
    id: "SWC-134",
    title: "Message Call with Hardcoded Gas Amount",
    description:
      "transfer() and send() forward only 2300 gas, which may not be enough for " +
      "receiving contracts after EIP-1884.",
    severity: Severity.LOW,
    patterns: [/\.transfer\s*\(/g, /\.send\s*\(/g],
    remediation:
      "Use call{value: amount}('') instead of transfer/send. Always check the return value.",
    references: ["https://swcregistry.io/docs/SWC-134"],
  },

  // SWC-135: Code With No Effects
  {
    id: "SWC-135",
    title: "Code With No Effects",
    description:
      "Code that doesn't change state or have side effects indicates bugs or leftover code.",
    severity: Severity.INFORMATIONAL,
    patterns: [/^\s*\w+\s*;\s*$/gm, /^\s*\w+\s*\+\s*\w+\s*;\s*$/gm],
    remediation: "Remove dead code or implement its intended effect.",
    references: ["https://swcregistry.io/docs/SWC-135"],
  },

  // SWC-136: Unencrypted Private Data On-Chain
  {
    id: "SWC-136",
    title: "Unencrypted Private Data On-Chain",
    description:
      "Private variables are not actually private on the blockchain. " +
      "Anyone can read storage directly.",
    severity: Severity.HIGH,
    patterns: [
      /private\s+(?:string|bytes)\s+\w*(?:password|secret|key|private)\w*/gi,
      /private\s+\w+\s+\w*(?:password|secret|key|private)\w*/gi,
    ],
    remediation:
      "Never store sensitive data on-chain. Use hash commitments or off-chain storage with proofs.",
    references: ["https://swcregistry.io/docs/SWC-136"],
  },
];

// ============================================================================
// Main Function
// ============================================================================

/**
 * Check a Solidity contract against SWC Registry patterns.
 *
 * @param input - Input containing contract path and optional detector filter
 * @returns Vulnerability report with matches
 */
export async function checkVulnerabilities(input: CheckVulnerabilitiesInput): Promise<string> {
  logger.info(`[checkVulnerabilities] Scanning ${input.contractPath}`);

  // Validate file exists
  try {
    await access(input.contractPath);
  } catch {
    return formatError(`Contract file not found: ${input.contractPath}`);
  }

  // Read contract source
  let source: string;
  try {
    source = await readFile(input.contractPath, "utf-8");
  } catch (err) {
    return formatError(
      `Failed to read contract: ${err instanceof Error ? err.message : String(err)}`
    );
  }

  // Filter patterns by requested detectors
  let patternsToCheck = SWC_PATTERNS;
  if (input.detectors && input.detectors.length > 0) {
    const detectorSet = new Set(
      input.detectors.map((d) => d.toUpperCase().replace(/[^A-Z0-9]/g, ""))
    );
    patternsToCheck = SWC_PATTERNS.filter((p) => {
      const normalizedId = p.id.toUpperCase().replace(/[^A-Z0-9]/g, "");
      return detectorSet.has(normalizedId);
    });

    if (patternsToCheck.length === 0) {
      return formatError(
        `No valid detectors found. Available: ${SWC_PATTERNS.map((p) => p.id).join(", ")}`
      );
    }
  }

  // Split source into lines for context
  const lines = source.split("\n");

  // Run pattern matching
  const vulnerabilities: VulnerabilityMatch[] = [];

  for (const pattern of patternsToCheck) {
    if (pattern.patterns.length === 0) {
      // Some patterns require semantic analysis, skip them
      continue;
    }

    const matches: VulnerabilityMatch["matches"] = [];

    for (const regex of pattern.patterns) {
      // Reset regex state
      regex.lastIndex = 0;

      let match;
      while ((match = regex.exec(source)) !== null) {
        // Check negative patterns (things that indicate the issue is handled)
        let isHandled = false;
        if (pattern.negativePatterns) {
          for (const negRegex of pattern.negativePatterns) {
            negRegex.lastIndex = 0;
            if (negRegex.test(source)) {
              isHandled = true;
              break;
            }
          }
        }

        if (!isHandled) {
          // Find line number
          const beforeMatch = source.slice(0, match.index);
          const lineNumber = (beforeMatch.match(/\n/g) || []).length + 1;

          // Get context (3 lines before and after)
          const startLine = Math.max(0, lineNumber - 3);
          const endLine = Math.min(lines.length, lineNumber + 3);
          const context = lines
            .slice(startLine, endLine)
            .map((l, i) => {
              const ln = startLine + i + 1;
              const prefix = ln === lineNumber ? ">>> " : "    ";
              return `${prefix}${ln}: ${l}`;
            })
            .join("\n");

          matches.push({
            line: lineNumber,
            code: match[0].trim().slice(0, 100),
            context,
          });
        }

        // Prevent infinite loop for zero-width matches
        if (match.index === regex.lastIndex) {
          regex.lastIndex++;
        }
      }
    }

    if (matches.length > 0) {
      // Deduplicate matches by line number
      const uniqueMatches = Array.from(new Map(matches.map((m) => [m.line, m])).values());

      vulnerabilities.push({
        swcId: pattern.id,
        title: pattern.title,
        description: pattern.description,
        severity: pattern.severity,
        matches: uniqueMatches,
        remediation: pattern.remediation,
        references: pattern.references,
      });
    }
  }

  // Sort by severity
  const severityOrder: Record<Severity, number> = {
    [Severity.CRITICAL]: 0,
    [Severity.HIGH]: 1,
    [Severity.MEDIUM]: 2,
    [Severity.LOW]: 3,
    [Severity.INFORMATIONAL]: 4,
  };

  vulnerabilities.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  // Build report
  const bySeverity: Record<string, number> = {
    [Severity.CRITICAL]: 0,
    [Severity.HIGH]: 0,
    [Severity.MEDIUM]: 0,
    [Severity.LOW]: 0,
    [Severity.INFORMATIONAL]: 0,
  };

  for (const vuln of vulnerabilities) {
    bySeverity[vuln.severity] = (bySeverity[vuln.severity] || 0) + 1;
  }

  const report: VulnerabilityReport = {
    contractPath: input.contractPath,
    totalVulnerabilities: vulnerabilities.length,
    bySeverity,
    vulnerabilities,
    scannedDetectors: patternsToCheck.map((p) => p.id),
  };

  logger.info(`[checkVulnerabilities] Found ${vulnerabilities.length} potential issues`);

  return formatOutput(report);
}

// ============================================================================
// Output Formatting
// ============================================================================

function formatError(message: string): string {
  return JSON.stringify({ success: false, error: message }, null, 2);
}

function formatOutput(report: VulnerabilityReport): string {
  const lines: string[] = [];

  // Header
  lines.push("═══════════════════════════════════════════════════════════════════════════════");
  lines.push("  SWC REGISTRY VULNERABILITY SCAN");
  lines.push("═══════════════════════════════════════════════════════════════════════════════");
  lines.push("");

  // Summary
  lines.push("┌─────────────────────────────────────────────────────────────────────────────┐");
  lines.push("│  SUMMARY                                                                    │");
  lines.push("└─────────────────────────────────────────────────────────────────────────────┘");

  const severityEmoji: Record<string, string> = {
    [Severity.CRITICAL]: "🔴",
    [Severity.HIGH]: "🟠",
    [Severity.MEDIUM]: "🟡",
    [Severity.LOW]: "🔵",
    [Severity.INFORMATIONAL]: "⚪",
  };

  lines.push(`  Contract: ${report.contractPath}`);
  lines.push(`  Total issues: ${report.totalVulnerabilities}`);
  lines.push(`  Detectors scanned: ${report.scannedDetectors.length}`);
  lines.push("");

  for (const [severity, count] of Object.entries(report.bySeverity)) {
    if (count > 0) {
      const emoji = severityEmoji[severity] || "⚪";
      lines.push(`  ${emoji} ${severity}: ${count}`);
    }
  }
  lines.push("");

  // Vulnerabilities
  if (report.vulnerabilities.length === 0) {
    lines.push("  ✅ No vulnerabilities detected by pattern matching");
    lines.push("");
    lines.push("  Note: This scan uses regex patterns and may miss issues.");
    lines.push("  For comprehensive analysis, also run Slither and Aderyn.");
  } else {
    for (const vuln of report.vulnerabilities) {
      const emoji = severityEmoji[vuln.severity] || "⚪";

      lines.push("┌─────────────────────────────────────────────────────────────────────────────┐");
      lines.push(`│  ${emoji} ${vuln.swcId}: ${vuln.title}`);
      lines.push("└─────────────────────────────────────────────────────────────────────────────┘");

      lines.push(`  Severity: ${vuln.severity}`);
      lines.push("");
      lines.push(`  Description:`);
      // Word wrap description at 70 chars
      const words = vuln.description.split(" ");
      let currentLine = "  ";
      for (const word of words) {
        if (currentLine.length + word.length > 75) {
          lines.push(currentLine);
          currentLine = "  " + word;
        } else {
          currentLine += (currentLine === "  " ? "" : " ") + word;
        }
      }
      if (currentLine !== "  ") {
        lines.push(currentLine);
      }
      lines.push("");

      lines.push(`  Matches (${vuln.matches.length}):`);
      for (const match of vuln.matches.slice(0, 5)) {
        lines.push(`    Line ${match.line}: ${match.code}`);
        lines.push("");
        lines.push("    Context:");
        for (const contextLine of match.context.split("\n")) {
          lines.push(`      ${contextLine}`);
        }
        lines.push("");
      }

      if (vuln.matches.length > 5) {
        lines.push(`    ... and ${vuln.matches.length - 5} more matches`);
        lines.push("");
      }

      lines.push(`  Remediation:`);
      lines.push(`    ${vuln.remediation}`);
      lines.push("");

      lines.push(`  References:`);
      for (const ref of vuln.references) {
        lines.push(`    - ${ref}`);
      }
      lines.push("");
    }
  }

  // Security notes
  lines.push("┌─────────────────────────────────────────────────────────────────────────────┐");
  lines.push("│  IMPORTANT NOTES                                                            │");
  lines.push("└─────────────────────────────────────────────────────────────────────────────┘");
  lines.push("");
  lines.push("  • This is a pattern-based scan with potential false positives");
  lines.push("  • Some SWC patterns require AST analysis and are not covered");
  lines.push("  • Always verify findings manually before acting on them");
  lines.push("  • Use this in combination with Slither/Aderyn for best results");
  lines.push("");

  lines.push("═══════════════════════════════════════════════════════════════════════════════");

  // JSON data
  lines.push("");
  lines.push("JSON DATA:");
  lines.push(
    JSON.stringify(
      {
        success: true,
        contractPath: report.contractPath,
        totalVulnerabilities: report.totalVulnerabilities,
        bySeverity: report.bySeverity,
        vulnerabilities: report.vulnerabilities.map((v) => ({
          swcId: v.swcId,
          title: v.title,
          severity: v.severity,
          matchCount: v.matches.length,
          lines: v.matches.map((m) => m.line),
        })),
        scannedDetectors: report.scannedDetectors,
      },
      null,
      2
    )
  );

  return lines.join("\n");
}
