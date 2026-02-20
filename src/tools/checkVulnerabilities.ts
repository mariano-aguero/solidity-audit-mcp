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

  // CUSTOM-001: Array Length Mismatch
  {
    id: "CUSTOM-001",
    title: "Array Length Mismatch",
    description:
      "Functions accepting multiple array parameters without validating their lengths are equal. " +
      "This can lead to out-of-bounds access, incorrect data processing, or denial of service.",
    severity: Severity.HIGH,
    patterns: [
      // Function with two array parameters (common patterns)
      /function\s+\w+\s*\([^)]*\[\s*\]\s*(?:calldata|memory)?\s+(\w+)[^)]*\[\s*\]\s*(?:calldata|memory)?\s+(\w+)[^)]*\)\s*(?:external|public|internal|private)?[^{]*\{(?:(?!require\s*\(\s*\1\.length\s*==\s*\2\.length)(?!require\s*\(\s*\2\.length\s*==\s*\1\.length)(?!if\s*\(\s*\1\.length\s*!=\s*\2\.length)(?!if\s*\(\s*\2\.length\s*!=\s*\1\.length)[\s\S])*?\}/gs,
    ],
    remediation:
      'Always validate array lengths match at the start of the function: require(array1.length == array2.length, "Length mismatch");',
    references: [
      "https://github.com/crytic/slither/wiki/Detector-Documentation",
      "https://consensys.github.io/smart-contract-best-practices/development-recommendations/solidity-specific/complex-inheritance/",
    ],
  },

  // CUSTOM-002: Proxy Storage Collision Risk (Missing Gap)
  {
    id: "CUSTOM-002",
    title: "Proxy Storage Collision Risk - Missing Gap",
    description:
      "Upgradeable contracts using proxy patterns must maintain consistent storage layout. " +
      "Adding new state variables in the wrong position or changing variable order can corrupt storage. " +
      "The __gap pattern should be used, and new variables should only be added at the end.",
    severity: Severity.HIGH,
    patterns: [
      // Detects contracts that inherit from upgradeable patterns but might have storage issues
      // Contract inherits Initializable/UUPSUpgradeable but has state variables after functions
      /contract\s+\w+[^{]*(?:Initializable|UUPSUpgradeable|TransparentUpgradeable|Upgradeable)[^{]*\{(?:[\s\S]*?function[\s\S]*?)(?:uint|int|address|bool|bytes|string|mapping)\s+(?:public|private|internal)?\s+\w+\s*[;=]/gs,
    ],
    negativePatterns: [
      /__gap/g, // Has storage gap (good practice)
    ],
    remediation:
      "Use the storage gap pattern: uint256[50] private __gap; " +
      "Only add new state variables at the end of the contract. " +
      "Consider using OpenZeppelin's storage gap helpers or ERC-7201 namespaced storage.",
    references: [
      "https://docs.openzeppelin.com/upgrades-plugins/1.x/writing-upgradeable#storage-gaps",
      "https://eips.ethereum.org/EIPS/eip-7201",
    ],
  },

  // CUSTOM-002a: Insufficient Storage Gap Size
  {
    id: "CUSTOM-002a",
    title: "Insufficient Storage Gap Size",
    description:
      "Storage gap is smaller than recommended. A gap of at least 50 slots is recommended " +
      "to allow for future upgrades. Smaller gaps limit the number of state variables " +
      "that can be added in future versions.",
    severity: Severity.MEDIUM,
    patterns: [
      // Gap with size less than 50 (matches [1] through [49])
      /uint256\s*\[\s*([1-9]|[1-4][0-9])\s*\]\s*(?:private|internal)?\s*__gap/g,
    ],
    remediation:
      "Increase the storage gap to at least 50 slots: uint256[50] private __gap; " +
      "When adding new state variables, reduce the gap size accordingly.",
    references: [
      "https://docs.openzeppelin.com/upgrades-plugins/1.x/writing-upgradeable#storage-gaps",
    ],
  },

  // CUSTOM-002b: State Variables After Gap
  {
    id: "CUSTOM-002b",
    title: "State Variables Declared After Storage Gap",
    description:
      "State variables declared after the __gap array will have unpredictable storage slots " +
      "when the contract is upgraded. All state variables should be declared before the gap.",
    severity: Severity.CRITICAL,
    patterns: [
      // Any state variable declaration after __gap
      /__gap\s*;[\s\S]*?(?:uint|int|address|bool|bytes|string|mapping)\d*\s+(?:public|private|internal)?\s+(?!__gap)\w+\s*[;=]/gs,
    ],
    remediation:
      "Move all state variables before the __gap declaration. " +
      "The __gap should always be the last state variable in the contract.",
    references: [
      "https://docs.openzeppelin.com/upgrades-plugins/1.x/writing-upgradeable#storage-gaps",
    ],
  },

  // CUSTOM-002c: Gap Not at End of Contract
  {
    id: "CUSTOM-002c",
    title: "Storage Gap Not at End of State Variables",
    description:
      "The __gap array should be the last state variable before functions. " +
      "Having state variables after the gap defeats its purpose and can cause storage collisions.",
    severity: Severity.HIGH,
    patterns: [
      // Gap followed by more state variables (not functions)
      /__gap\s*;[^}]*?(?:(?:uint|int|address|bool|bytes|string|mapping)\d*\s+(?:public|private|internal)\s+\w+\s*[;=])/gs,
    ],
    negativePatterns: [
      // Ignore if followed by function, modifier, event, or end of contract
      /__gap\s*;\s*(?:function|modifier|event|constructor|\})/gs,
    ],
    remediation:
      "Reorganize state variables so __gap is declared last, just before functions begin.",
    references: [
      "https://docs.openzeppelin.com/upgrades-plugins/1.x/writing-upgradeable#storage-gaps",
    ],
  },

  // CUSTOM-002d: Initializable Without Disable Initializers
  {
    id: "CUSTOM-002d",
    title: "Upgradeable Contract Missing _disableInitializers",
    description:
      "Implementation contracts should call _disableInitializers() in the constructor " +
      "to prevent the implementation from being initialized directly, which could allow " +
      "an attacker to take control of the implementation contract.",
    severity: Severity.HIGH,
    patterns: [
      // Contract with Initializable but constructor doesn't have _disableInitializers
      /contract\s+\w+[^{]*Initializable[^{]*\{[\s\S]*?constructor\s*\([^)]*\)\s*\{[^}]*\}/gs,
    ],
    negativePatterns: [/_disableInitializers\s*\(\s*\)/g],
    remediation:
      "Add _disableInitializers() call in the constructor: " +
      "constructor() { _disableInitializers(); }",
    references: [
      "https://docs.openzeppelin.com/upgrades-plugins/1.x/writing-upgradeable#initializing_the_implementation_contract",
    ],
  },

  // CUSTOM-003: Reentrancy Risk - External Call Before State Update
  {
    id: "CUSTOM-003",
    title: "Reentrancy Risk - External Call Before State Update",
    description:
      "Function makes an external call (via interface or low-level call) followed by state changes. " +
      "This violates the Checks-Effects-Interactions pattern and may allow reentrancy attacks.",
    severity: Severity.HIGH,
    patterns: [
      // Interface call followed by state change (balanceOf, totalSupply, mappings)
      /\w+\s*\([^)]*\)\s*\.\s*\w+\s*\([^)]*\)\s*;[\s\S]*?(?:balanceOf|totalSupply|allowance)\s*\[[^\]]+\]\s*(?:\+|-)?=/gs,
      // State change followed by external call without reentrancy guard
      /(?:balanceOf|totalSupply|allowance)\s*\[[^\]]+\]\s*(?:\+|-)=[\s\S]*?\w+\s*\([^)]*\)\s*\.\s*\w+\s*\([^)]*\)\s*;/gs,
    ],
    negativePatterns: [/nonReentrant/g, /ReentrancyGuard/g, /_nonReentrant/g],
    remediation:
      "Follow Checks-Effects-Interactions pattern: perform all state changes before external calls. " +
      "Consider using OpenZeppelin's ReentrancyGuard.",
    references: [
      "https://swcregistry.io/docs/SWC-107",
      "https://consensys.github.io/smart-contract-best-practices/attacks/reentrancy/",
    ],
  },

  // CUSTOM-004: Stale/Manipulable Price Oracle
  {
    id: "CUSTOM-004",
    title: "Stale or Manipulable Price Data",
    description:
      "Price data fetched earlier in a transaction and used later for critical calculations " +
      "can be stale or manipulated via flash loans. Attackers can manipulate spot prices " +
      "within a single transaction to exploit price-dependent logic.",
    severity: Severity.HIGH,
    patterns: [
      // Price variable used in arithmetic with debt/collateral calculations
      /price\s*[*/][\s\S]*?(?:collateral|debt|liquidat|borrow|lend)/gis,
      /(?:collateral|debt|liquidat|borrow|lend)[\s\S]*?price\s*[*/]/gis,
      // getPrice/latestAnswer followed by state changes
      /(?:getPrice|latestAnswer|latestRoundData)\s*\([^)]*\)[\s\S]*?(?:\w+\s*(?:\+|-|\*|\/)?=)/gs,
      // Direct reserve/balance reads for pricing
      /getReserves\s*\(\s*\)[\s\S]*?(?:price|value|amount)\s*=/gis,
    ],
    negativePatterns: [
      /TWAP/gi,
      /timeWeightedAverage/gi,
      /updatedAt\s*[<>]/g,
      /staleness/gi,
      /require\s*\([^)]*timestamp/gi,
    ],
    remediation:
      "Use time-weighted average prices (TWAP) instead of spot prices. " +
      "Validate price freshness with staleness checks. " +
      "Consider using Chainlink oracles with proper round validation.",
    references: [
      "https://blog.openzeppelin.com/secure-smart-contract-guidelines-the-dangers-of-price-oracles",
      "https://samczsun.com/so-you-want-to-use-a-price-oracle/",
    ],
  },

  // CUSTOM-005: Missing Zero Address Validation
  {
    id: "CUSTOM-005",
    title: "Missing Zero Address Validation",
    description:
      "Functions that accept address parameters should validate that the address is not zero. " +
      "Sending tokens or assigning permissions to the zero address can result in permanent loss of funds " +
      "or broken access control.",
    severity: Severity.MEDIUM,
    patterns: [
      // Function setting delegate/owner/admin without zero check
      /function\s+(?:set|update|change)(?:Delegate|Owner|Admin|Operator|Manager|Controller)\s*\(\s*address\s+(\w+)\s*\)[^{]*\{(?:(?!require\s*\(\s*\1\s*!=\s*address\s*\(0\))(?!if\s*\(\s*\1\s*==\s*address\s*\(0\))[\s\S])*?\}/gs,
      // Direct assignment to mappings with address key without validation
      /function\s+\w+\s*\([^)]*address\s+(\w+)[^)]*\)[^{]*\{(?:(?!require\s*\(\s*\1\s*!=\s*address\s*\(0\))[\s\S])*?\w+\s*\[\s*(?:msg\.sender|\1)\s*\]\s*=\s*\1/gs,
    ],
    negativePatterns: [
      /require\s*\([^)]*!=\s*address\s*\(\s*0\s*\)/g,
      /if\s*\([^)]*==\s*address\s*\(\s*0\s*\)/g,
      /revert\s+ZeroAddress/g,
    ],
    remediation:
      'Add zero address validation: require(addr != address(0), "Zero address"); ' +
      "Or use custom errors: if (addr == address(0)) revert ZeroAddress();",
    references: [
      "https://consensys.github.io/smart-contract-best-practices/development-recommendations/solidity-specific/zero-address/",
    ],
  },

  // CUSTOM-006: Missing Event for Critical State Change
  {
    id: "CUSTOM-006",
    title: "Missing Event for Critical State Change",
    description:
      "Critical state changes (owner, admin, delegate, paused status, fees) should emit events " +
      "for off-chain monitoring and transparency. Missing events make it difficult to track " +
      "important changes and can hide malicious activity.",
    severity: Severity.LOW,
    patterns: [
      // Setter functions without emit
      /function\s+(?:set|update|change)(?:Owner|Admin|Delegate|Fee|Paused|Manager|Operator)\s*\([^)]*\)[^{]*\{(?:(?!emit\s+\w+)[\s\S])*?\}/gs,
      // Direct assignment to critical variables without event
      /(?:owner|admin|paused|feeRate|treasury)\s*=\s*[^;]+;(?:(?!emit)[\s\S])*?\}/gs,
    ],
    negativePatterns: [/emit\s+\w+/g],
    remediation:
      "Emit an event after critical state changes: " +
      "emit DelegateChanged(msg.sender, oldDelegate, newDelegate);",
    references: [
      "https://consensys.github.io/smart-contract-best-practices/development-recommendations/solidity-specific/event-monitoring/",
    ],
  },

  // CUSTOM-007: Price Calculation Before Validation
  {
    id: "CUSTOM-007",
    title: "Price Calculation Before Validation",
    description:
      "Calculations using price data are performed before validating the result or collateralization. " +
      "An attacker could manipulate the price to pass validation checks with favorable terms.",
    severity: Severity.HIGH,
    patterns: [
      // Calculation with price followed by require/if check
      /\w+\s*=\s*[^;]*price[^;]*;[\s\S]*?(?:require|if)\s*\([^)]*(?:collateral|debt|min|max|threshold)/gis,
      // Collateral check after calculation
      /(?:minCollateral|maxBorrow|liquidation)\s*=[\s\S]*?price[\s\S]*?;[\s\S]*?require\s*\(/gis,
    ],
    remediation:
      "Fetch fresh price data immediately before use. " +
      "Add staleness checks for oracle data. " +
      "Consider using Chainlink's latestRoundData with round validation.",
    references: ["https://docs.chain.link/data-feeds/price-feeds"],
  },

  // CUSTOM-008: Liquidation Threshold Without Slippage Protection
  {
    id: "CUSTOM-008",
    title: "Liquidation Without Slippage Protection",
    description:
      "Liquidation calculations without slippage protection can be exploited. " +
      "The price can change between transaction submission and execution, " +
      "leading to unfavorable liquidations or failed transactions.",
    severity: Severity.MEDIUM,
    patterns: [
      // Liquidation function without minOutput/slippage parameter
      /function\s+liquidate\s*\([^)]*\)[^{]*\{(?:(?!minOutput|slippage|minAmount|deadline)[\s\S])*?\}/gs,
      // Liquidation threshold check without bounds
      /LIQUIDATION_THRESHOLD[\s\S]*?\/\s*\(?price/gis,
    ],
    negativePatterns: [/minOutput/g, /slippage/g, /maxSlippage/g, /deadline/g],
    remediation:
      "Add slippage protection parameters (minOutput, deadline). " +
      "Use price bounds or TWAP for liquidation calculations.",
    references: ["https://blog.chain.link/defi-security-best-practices/"],
  },

  // CUSTOM-009: Double Approval in Multisig
  {
    id: "CUSTOM-009",
    title: "Double Approval Vulnerability in Multisig",
    description:
      "Approval count increments without checking if the signer has already approved. " +
      "A single signer could approve multiple times to bypass the threshold requirement.",
    severity: Severity.CRITICAL,
    patterns: [
      // Setting hasApproved and incrementing count without prior check
      /hasApproved\s*\[[^\]]+\]\s*\[[^\]]+\]\s*=\s*true\s*;[\s\S]*?approvalCount\s*\[[^\]]+\]\s*\+\+/gs,
      /approvalCount\s*\[[^\]]+\]\s*\+\+[\s\S]*?hasApproved\s*\[[^\]]+\]\s*\[[^\]]+\]\s*=\s*true/gs,
    ],
    negativePatterns: [
      /require\s*\(\s*!?\s*hasApproved/g,
      /if\s*\(\s*hasApproved/g,
      /revert\s+AlreadyApproved/g,
    ],
    remediation:
      "Check if the signer has already approved before incrementing: " +
      'require(!hasApproved[id][msg.sender], "Already approved");',
    references: [
      "https://consensys.github.io/smart-contract-best-practices/development-recommendations/general/access-control/",
    ],
  },

  // CUSTOM-010: Missing Execution Guard in Multisig
  {
    id: "CUSTOM-010",
    title: "Missing Execution Guard - Can Execute Multiple Times",
    description:
      "Multisig or timelock operations can be executed multiple times because there's no check " +
      "whether the operation was already executed. This can drain funds or cause unexpected state changes.",
    severity: Severity.CRITICAL,
    patterns: [
      // Execute function with call but no executed check
      /function\s+execute\w*\s*\([^)]*\)[^{]*\{(?:(?!executed\s*\[|isExecuted|wasExecuted)[\s\S])*?\.call\s*\{/gs,
      // Withdrawal with approvalCount check but no execution flag
      /require\s*\(\s*approvalCount[\s\S]*?\.call\s*\{value/gs,
    ],
    negativePatterns: [
      /executed\s*\[/g,
      /isExecuted/g,
      /wasExecuted/g,
      /require\s*\(\s*!executed/g,
    ],
    remediation:
      "Track execution status and check before executing: " +
      'require(!executed[id], "Already executed"); executed[id] = true;',
    references: [
      "https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/governance/TimelockController.sol",
    ],
  },

  // CUSTOM-011: Signature Without Replay Protection
  {
    id: "CUSTOM-011",
    title: "Signature Without Replay Protection",
    description:
      "Signature-based functions without proper nonce tracking or domain separator " +
      "are vulnerable to replay attacks. The same signature could be used multiple times " +
      "or across different chains/contracts.",
    severity: Severity.HIGH,
    patterns: [
      // ecrecover without nonce validation
      /ecrecover\s*\([^)]*\)(?:(?!nonces\s*\[|usedNonces|require\s*\(\s*nonce)[\s\S])*?;/gs,
      // Signature function without chainId in hash
      /keccak256\s*\(\s*abi\.encodePacked\s*\([^)]*(?:msg\.sender|amount)[^)]*\)\s*\)(?:(?!block\.chainid|chainId)[\s\S])*?ecrecover/gs,
    ],
    negativePatterns: [
      /nonces\s*\[\s*\w+\s*\]\s*\+\+/g,
      /usedSignatures\s*\[/g,
      /DOMAIN_SEPARATOR/g,
      /EIP712/g,
    ],
    remediation:
      "Use EIP-712 typed data signing with domain separator including chainId. " +
      "Track used nonces: require(nonce == nonces[signer]++); " +
      "Or track used signatures: require(!usedSignatures[sig]); usedSignatures[sig] = true;",
    references: ["https://eips.ethereum.org/EIPS/eip-712", "https://swcregistry.io/docs/SWC-121"],
  },

  // CUSTOM-012: Signature Malleability Risk
  {
    id: "CUSTOM-012",
    title: "ECDSA Signature Malleability",
    description:
      "Raw ecrecover usage without malleability checks. For every valid ECDSA signature, " +
      "there exists another valid signature (with flipped s value). If signatures are used " +
      "as unique identifiers, this can be exploited.",
    severity: Severity.MEDIUM,
    patterns: [
      // Direct ecrecover without OpenZeppelin ECDSA
      /ecrecover\s*\(\s*\w+\s*,\s*v\s*,\s*r\s*,\s*s\s*\)/g,
      // Manual signature splitting without s validation
      /assembly\s*\{[^}]*:=\s*mload[^}]*\}[\s\S]*?ecrecover/gs,
    ],
    negativePatterns: [
      /ECDSA\.recover/g,
      /SignatureChecker/g,
      /require\s*\(\s*uint256\s*\(\s*s\s*\)\s*<=/g,
      /s\s*>\s*0x7FFFFFFF/g,
    ],
    remediation:
      "Use OpenZeppelin's ECDSA library which handles malleability: " +
      "address signer = ECDSA.recover(hash, signature); " +
      "Or manually check s value: require(uint256(s) <= 0x7FFFFFFFFFFFFFFF...);",
    references: [
      "https://swcregistry.io/docs/SWC-117",
      "https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/cryptography/ECDSA.sol",
    ],
  },

  // CUSTOM-013: encodePacked with Multiple Dynamic Types
  {
    id: "CUSTOM-013",
    title: "Hash Collision Risk with encodePacked",
    description:
      "Using abi.encodePacked with multiple dynamic types (string, bytes, arrays) " +
      "can create hash collisions. Different inputs can produce the same hash.",
    severity: Severity.MEDIUM,
    patterns: [
      // encodePacked with msg.sender and amount in signature context
      /keccak256\s*\(\s*abi\.encodePacked\s*\(\s*msg\.sender\s*,\s*\w+\s*,/g,
      // encodePacked in signature hash creation
      /abi\.encodePacked\s*\([^)]*signature[^)]*\)/gi,
    ],
    negativePatterns: [/abi\.encode\s*\(/g],
    remediation:
      "Use abi.encode instead of abi.encodePacked for hashing: " +
      "keccak256(abi.encode(param1, param2, param3));",
    references: ["https://swcregistry.io/docs/SWC-133"],
  },

  // CUSTOM-014: Flash Loan/Mint Without Proper Repayment
  {
    id: "CUSTOM-014",
    title: "Flash Loan/Mint Without Proper Repayment Check",
    description:
      "Flash loan or flash mint implementation that doesn't properly verify repayment. " +
      "Common issues: checking balance instead of actual repayment, not burning minted tokens, " +
      "or allowing the borrower to manipulate the check.",
    severity: Severity.CRITICAL,
    patterns: [
      // Flash mint that checks balance but doesn't burn
      /function\s+flash(?:Mint|Loan)\s*\([^)]*\)[^{]*\{(?:(?!burn|_burn)[\s\S])*?balanceOf[\s\S]*?require/gs,
      // totalSupply increase without corresponding decrease
      /totalSupply\s*\+=[\s\S]*?\.on(?:Flash|Loan)[\s\S]*?(?!totalSupply\s*-=)/gs,
    ],
    negativePatterns: [/burn\s*\(/g, /_burn\s*\(/g, /totalSupply\s*-=/g],
    remediation:
      "Flash mints must burn the minted tokens after the callback. " +
      "Flash loans must verify actual token return, not just balance. " +
      "Consider implementing ERC-3156 standard for flash loans.",
    references: [
      "https://eips.ethereum.org/EIPS/eip-3156",
      "https://www.euler.finance/blog/getting-the-most-out-of-euler-flash-loans",
    ],
  },

  // CUSTOM-015: Precision Loss - Division Before Multiplication
  {
    id: "CUSTOM-015",
    title: "Precision Loss - Division Before Multiplication",
    description:
      "Performing division before multiplication in integer arithmetic causes precision loss. " +
      "In Solidity, integer division truncates, so dividing first loses precision that " +
      "subsequent multiplication cannot recover.",
    severity: Severity.MEDIUM,
    patterns: [
      // Division followed by multiplication on same line or adjacent
      /\w+\s*\/\s*\d+\s*\*\s*\d+/g,
      /\(\s*\w+\s*\/\s*\d+\s*\)\s*\*/g,
      // Common pattern: amount / X * Y instead of amount * Y / X
      /(?:debt|amount|balance|value)\s*\/\s*\d+\s*\*\s*\d+/gi,
    ],
    remediation:
      "Always multiply before dividing: (amount * rate) / PRECISION instead of amount / PRECISION * rate. " +
      "Use higher precision intermediate values when possible.",
    references: [
      "https://consensys.github.io/smart-contract-best-practices/development-recommendations/solidity-specific/integer-division/",
    ],
  },

  // CUSTOM-016: Permit Without Deadline
  {
    id: "CUSTOM-016",
    title: "Signature/Permit Without Deadline",
    description:
      "Permit or signature-based approval without a deadline parameter. " +
      "Signatures remain valid forever, allowing them to be used at any future time, " +
      "potentially when conditions have changed unfavorably for the signer.",
    severity: Severity.MEDIUM,
    patterns: [
      // Permit/approve with signature but no deadline parameter
      /function\s+permit\w*\s*\([^)]*(?:uint8\s+v|bytes\s+(?:memory\s+)?signature)[^)]*\)(?:(?!deadline|expiry|validUntil)[\s\S])*?\{/gs,
      // ecrecover in function without deadline check
      /function\s+\w+\s*\([^)]*\)[^{]*\{(?:(?!deadline|expiry|block\.timestamp\s*<)[\s\S])*?ecrecover/gs,
    ],
    negativePatterns: [
      /require\s*\([^)]*deadline/g,
      /require\s*\([^)]*expiry/g,
      /require\s*\([^)]*block\.timestamp\s*</g,
    ],
    remediation:
      "Add a deadline parameter and validate it: " +
      'require(block.timestamp <= deadline, "Signature expired"); ' +
      "Consider implementing EIP-2612 for permit functionality.",
    references: ["https://eips.ethereum.org/EIPS/eip-2612"],
  },

  // CUSTOM-017: Missing Access Control on Critical Function
  {
    id: "CUSTOM-017",
    title: "Missing Access Control on Critical Function",
    description:
      "Functions that modify critical protocol state (add tokens, set parameters, mint, pause) " +
      "lack access control modifiers. Anyone can call these functions.",
    severity: Severity.CRITICAL,
    patterns: [
      // Functions that sound critical but have no access control
      /function\s+(?:add|remove|set|update|change|pause|unpause|mint|burn|upgrade)\w*\s*\([^)]*\)\s*(?:external|public)(?:(?!onlyOwner|onlyAdmin|onlyRole|require\s*\(\s*msg\.sender)[\s\S])*?\{/gs,
    ],
    negativePatterns: [
      /onlyOwner/g,
      /onlyAdmin/g,
      /onlyRole/g,
      /require\s*\(\s*msg\.sender\s*==/g,
      /require\s*\(\s*hasRole/g,
      /_checkOwner/g,
    ],
    remediation:
      "Add access control: require(msg.sender == owner) or use OpenZeppelin's Ownable/AccessControl.",
    references: ["https://docs.openzeppelin.com/contracts/access-control"],
  },

  // CUSTOM-018: ERC-7702 Unprotected Initializer After setCode
  {
    id: "CUSTOM-018",
    title: "ERC-7702 Unprotected Initializer After setCode",
    description:
      "ERC-7702 allows EOAs to delegate execution to a smart contract via setCode. " +
      "If the delegated contract exposes an initialize() function without checking whether " +
      "it was already called, an attacker can call initialize() on a victim's EOA after delegation " +
      "and take ownership of it. This is analogous to the uninitialized proxy attack.",
    severity: Severity.CRITICAL,
    patterns: [
      // initialize() function without initializer modifier or already-initialized guard
      /function\s+initialize\s*\([^)]*\)\s*(?:external|public)(?:(?!initializer|_initialized|initialized\s*=|require\s*\(\s*!initialized|if\s*\(\s*initialized)[\s\S])*?\{/gs,
      // reinitializer without version check
      /function\s+initialize\w*\s*\([^)]*\)\s*(?:external|public)\s*(?:virtual\s*)?(?:override\s*)?\{(?:(?!reinitializer|_initialized)[\s\S])*?owner\s*=/gs,
    ],
    negativePatterns: [
      /initializer/g,
      /reinitializer/g,
      /_initialized/g,
      /require\s*\(\s*!initialized/g,
      /if\s*\(\s*initialized\s*\)\s*revert/g,
    ],
    remediation:
      "Guard initialize() with OpenZeppelin's Initializable.initializer modifier. " +
      "Call _disableInitializers() in the constructor to prevent re-initialization. " +
      "For ERC-7702 contexts, verify the caller is the EOA itself: require(msg.sender == address(this));",
    references: [
      "https://eips.ethereum.org/EIPS/eip-7702",
      "https://docs.openzeppelin.com/upgrades-plugins/1.x/writing-upgradeable#initializing_the_implementation_contract",
    ],
  },

  // CUSTOM-019: ERC-7702 Cross-Chain Signature Replay (chainId = 0)
  {
    id: "CUSTOM-019",
    title: "ERC-7702 Cross-Chain Signature Replay via chainId=0",
    description:
      "ERC-7702 authorization tuples include a chain_id field. When chain_id is set to 0, " +
      "the authorization is valid on ALL chains. Contracts that verify ERC-7702 delegations " +
      "without checking the chain ID allow replay attacks across chains: a delegation signed " +
      "on a testnet can be replayed on mainnet to take control of the EOA.",
    severity: Severity.HIGH,
    patterns: [
      // Signature verification without chainId or block.chainid check
      /ecrecover\s*\([^)]*\)(?:(?!block\.chainid|chainId|chain_id)[\s\S])*?(?:setCode|delegation|authorize)/gis,
      // EIP-712 domain without chainId field
      /DOMAIN_SEPARATOR\s*=\s*keccak256\s*\(\s*abi\.encode\s*\([^)]*(?!block\.chainid|chainId)[^)]*\)\s*\)/gs,
    ],
    negativePatterns: [/block\.chainid/g, /chainId\s*:/g, /require\s*\([^)]*chainid/gi],
    remediation:
      "Always include block.chainid in the EIP-712 domain separator and in any signature hash " +
      "used for ERC-7702 authorization. Reject authorizations with chain_id=0 if cross-chain " +
      "delegation is not intended: require(chainId == block.chainid || chainId != 0);",
    references: [
      "https://eips.ethereum.org/EIPS/eip-7702",
      "https://eips.ethereum.org/EIPS/eip-712",
    ],
  },

  // CUSTOM-020: Transient Storage Reentrancy Guard Bypass via delegatecall
  {
    id: "CUSTOM-020",
    title: "Transient Storage Reentrancy Guard Bypass via delegatecall",
    description:
      "EIP-1153 transient storage (tstore/tload) is cleared at the end of each transaction, " +
      "but NOT when a new execution frame is entered via delegatecall. " +
      "If a reentrancy guard stores its lock in transient storage and the contract uses delegatecall, " +
      "the delegated code runs in the same execution context but the tstore slot may be in " +
      "a different position depending on the callee's layout, effectively clearing the guard. " +
      "An attacker can exploit this to bypass the reentrancy lock.",
    severity: Severity.HIGH,
    patterns: [
      // tstore used as reentrancy guard combined with delegatecall
      /tstore\s*\(/g,
      // Assembly with tstore near delegatecall
      /assembly\s*\{[^}]*tstore[^}]*\}[\s\S]*?\.delegatecall/gs,
      /\.delegatecall[\s\S]*?assembly\s*\{[^}]*tstore[^}]*\}/gs,
    ],
    negativePatterns: [],
    remediation:
      "Do not use transient storage (tstore/tload) as a reentrancy guard in contracts that " +
      "also use delegatecall. Use OpenZeppelin's ReentrancyGuard (regular storage slot) instead. " +
      "If you must use transient storage, ensure the guard slot cannot be cleared by delegatecall " +
      "by using a well-known, namespaced slot (ERC-7201).",
    references: [
      "https://eips.ethereum.org/EIPS/eip-1153",
      "https://eips.ethereum.org/EIPS/eip-7201",
    ],
  },

  // CUSTOM-021: Transient Storage Cross-Function State Leak
  {
    id: "CUSTOM-021",
    title: "Transient Storage Cross-Function State Leak",
    description:
      "Transient storage persists for the entire transaction, not just a single call. " +
      "A value written with tstore in one function call is readable in subsequent calls " +
      "within the same transaction. If an internal function reads transient storage assuming " +
      "it is empty, but a previous call in the same transaction set it, the function may " +
      "behave unexpectedly — allowing attackers to pre-set values via a crafted call sequence.",
    severity: Severity.MEDIUM,
    patterns: [
      // tload without a corresponding tstore reset after use
      /tload\s*\(/g,
      // Mixing tstore and tload in different functions (hard to detect precisely, flag for review)
      /assembly\s*\{[^}]*tload\s*\(/g,
    ],
    negativePatterns: [],
    remediation:
      "After reading transient storage with tload, immediately reset the slot to zero with tstore(slot, 0). " +
      "Document which transient slots are used and their expected lifecycle. " +
      "Consider adding invariant tests that call functions in different orders within the same transaction " +
      "to detect unexpected transient state interactions.",
    references: [
      "https://eips.ethereum.org/EIPS/eip-1153",
      "https://soliditylang.org/blog/2024/01/26/transient-storage/",
    ],
  },

  // =========================================================================
  // UNISWAP V4 HOOKS
  // =========================================================================

  // CUSTOM-022: V4 Hook Token Drain via beforeSwap/afterSwap
  {
    id: "CUSTOM-022",
    title: "Uniswap V4 Hook Token Drain via Delta Manipulation",
    description:
      "Uniswap V4 hooks can manipulate token deltas in beforeSwap/afterSwap callbacks. " +
      "A malicious or misconfigured hook can call PoolManager.take() to drain tokens " +
      "from the pool beyond the legitimate swap amount. " +
      "If the hook does not validate that the delta it takes matches the expected swap output, " +
      "liquidity providers' funds can be extracted.",
    severity: Severity.CRITICAL,
    patterns: [
      // take() called inside a hook callback without validation
      /function\s+(?:before|after)Swap[^{]*\{[^}]*\.take\s*\([^)]*\)/gs,
      // settle() + take() pattern without checking deltas
      /\.take\s*\([^)]*\)[^;]*;[^}]*\.settle\s*\(/gs,
    ],
    negativePatterns: [
      /delta\.amount0\s*\(\s*\)/g,
      /delta\.amount1\s*\(\s*\)/g,
      /require\s*\([^)]*delta/gi,
    ],
    remediation:
      "Always validate the BalanceDelta returned by the PoolManager before calling take(). " +
      "Ensure the amount taken equals the expected swap delta: " +
      "require(delta.amount0() == expectedDelta, 'Invalid delta'); " +
      "Use beforeSwapReturnDelta / afterSwapReturnDelta flags correctly and never take more than the swap output.",
    references: [
      "https://docs.uniswap.org/contracts/v4/concepts/hooks",
      "https://github.com/Uniswap/v4-core/blob/main/src/interfaces/IPoolManager.sol",
    ],
  },

  // CUSTOM-023: V4 Hook Reentrancy via unlock()
  {
    id: "CUSTOM-023",
    title: "Uniswap V4 Hook Reentrancy via unlock() Callback",
    description:
      "Uniswap V4's PoolManager uses an unlock() mechanism where the caller provides " +
      "a callback that executes inside the unlock context. If a hook or contract calls " +
      "PoolManager.unlock() from within a hook callback (or from a function that is itself " +
      "called by a hook), reentrancy can occur. The V4 locker pattern does not prevent " +
      "nested unlock() calls in all scenarios.",
    severity: Severity.HIGH,
    patterns: [
      // unlock() called inside hook callbacks
      /function\s+(?:before|after)(?:Swap|AddLiquidity|RemoveLiquidity|Initialize)[^{]*\{[^}]*\.unlock\s*\(/gs,
      // IPoolManager.unlock in a hook contract
      /(?:IPoolManager|poolManager)\s*\.\s*unlock\s*\(/g,
    ],
    negativePatterns: [/nonReentrant/g, /ReentrancyGuard/g],
    remediation:
      "Avoid calling PoolManager.unlock() from within hook callbacks. " +
      "Design hook logic to complete within a single unlock context. " +
      "If re-entry into the pool is needed, structure operations as a single atomic callback " +
      "rather than nested unlock() calls.",
    references: ["https://docs.uniswap.org/contracts/v4/concepts/hooks#hook-callbacks"],
  },

  // CUSTOM-024: V4 Hook Permission Misconfiguration
  {
    id: "CUSTOM-024",
    title: "Uniswap V4 Hook Permission Misconfiguration",
    description:
      "Uniswap V4 hooks declare permissions via the Hooks.Permissions struct returned by " +
      "getHookPermissions(). If a hook declares it does NOT need a callback (e.g., beforeSwap=false) " +
      "but still implements the function, or vice versa — declares a permission but does not " +
      "implement the guard — behavior is undefined. " +
      "Over-permissioned hooks increase the attack surface unnecessarily.",
    severity: Severity.MEDIUM,
    patterns: [
      // Hook contract implementing callbacks not declared in permissions
      /function\s+(?:before|after)(?:Swap|AddLiquidity|RemoveLiquidity|Initialize|Donate)\s*\([^)]*\)/g,
    ],
    negativePatterns: [/getHookPermissions\s*\(\s*\)/g, /Hooks\.Permissions/g],
    remediation:
      "Implement getHookPermissions() accurately — only declare permissions for callbacks " +
      "your hook actually uses. Review the Hooks.validateHookPermissions() function to ensure " +
      "your hook address bits match the declared permissions.",
    references: [
      "https://github.com/Uniswap/v4-core/blob/main/src/libraries/Hooks.sol",
      "https://docs.uniswap.org/contracts/v4/concepts/hook-flags",
    ],
  },

  // CUSTOM-025: V4 Pool Initialization Front-Running
  {
    id: "CUSTOM-025",
    title: "Uniswap V4 Pool Initialization Front-Running",
    description:
      "When a new V4 pool is initialized, the initial sqrtPriceX96 determines the starting price. " +
      "If hook logic runs onInitialize and trusts this price for any state mutation " +
      "(e.g., setting oracle prices, minting initial positions), an attacker can front-run " +
      "the initialization with a different price to manipulate initial state.",
    severity: Severity.HIGH,
    patterns: [
      // afterInitialize hook that uses sqrtPriceX96 for state writes
      /function\s+afterInitialize\s*\([^)]*sqrtPriceX96[^)]*\)[^{]*\{[^}]*(?:price|oracle|twap|mint)\s*=/gis,
      // beforeInitialize writing state based on pool key
      /function\s+beforeInitialize\s*\([^)]*\)[^{]*\{[^}]*=\s*[^;]+;/gs,
    ],
    negativePatterns: [/onlyPoolManager/g, /require\s*\(\s*msg\.sender\s*==.*poolManager/gi],
    remediation:
      "Never trust the initial sqrtPriceX96 from pool initialization for critical state. " +
      "Add access control to hook callbacks so only the PoolManager can call them. " +
      "If price initialization is required, use a TWAP or delay-based mechanism.",
    references: ["https://docs.uniswap.org/contracts/v4/concepts/pools#initialization"],
  },

  // =========================================================================
  // RESTAKING / LRT (EigenLayer style)
  // =========================================================================

  // CUSTOM-026: Slashing Propagation Without Proper Accounting
  {
    id: "CUSTOM-026",
    title: "Restaking Slashing Propagation Without Accounting",
    description:
      "In restaking protocols (EigenLayer style), operators can be slashed by AVSs. " +
      "If the LRT/restaking contract does not properly propagate slashing events to " +
      "the share price or underlying accounting, stakers may withdraw more than they " +
      "are entitled to after a slash event, leading to insolvency.",
    severity: Severity.CRITICAL,
    patterns: [
      // withdraw/redeem without checking if slashing has occurred
      /function\s+(?:withdraw|redeem|unstake)\s*\([^)]*\)[^{]*\{(?:(?!slash|penalty|loss|haircut)[\s\S])*?transfer/gis,
      // shares calculation without accounting for slashing
      /shares\s*=\s*(?:amount|assets)\s*\*\s*totalShares\s*\/\s*totalAssets(?:(?!slash|penalt)[\s\S])*?;/gis,
    ],
    negativePatterns: [/slashingFactor/g, /penaltyMultiplier/g, /haircut/gi, /lossAccumulator/gi],
    remediation:
      "Implement a slashing factor that reduces share value upon slash events. " +
      "Add a pendingSlash state that must be processed before withdrawals. " +
      "Consider implementing ERC-4626 with a slashing-aware totalAssets() that accounts for pending losses.",
    references: [
      "https://docs.eigenlayer.xyz/eigenlayer/avs-guides/slashing",
      "https://eips.ethereum.org/EIPS/eip-4626",
    ],
  },

  // CUSTOM-027: LRT Withdrawal Queue Race Condition
  {
    id: "CUSTOM-027",
    title: "LRT Withdrawal Queue Race Condition",
    description:
      "Liquid Restaking Tokens (LRT) that implement withdrawal queues may be vulnerable " +
      "to race conditions. If multiple users request withdrawals simultaneously and " +
      "the queue does not properly serialize or snapshot state at request time, " +
      "users may receive different amounts than expected due to price changes or " +
      "slashing events between request and fulfillment.",
    severity: Severity.HIGH,
    patterns: [
      // Withdrawal request without snapshotting the exchange rate
      /function\s+requestWithdraw\w*\s*\([^)]*\)[^{]*\{(?:(?!exchangeRate|pricePerShare|sharePrice|snapshot)[\s\S])*?withdrawalQueue/gis,
      // Queue processing without rate lock
      /function\s+processWithdraw\w*\s*\([^)]*\)[^{]*\{(?:(?!lockPrice|snapshotRate|priceAt)[\s\S])*?transfer/gis,
    ],
    negativePatterns: [/snapshotRate/g, /requestPrice/g, /priceAtRequest/g],
    remediation:
      "Snapshot the exchange rate at the time of withdrawal request, not fulfillment. " +
      "Store the locked rate per withdrawal request: " +
      "withdrawals[id].rate = currentRate(); " +
      "Process fulfillments using the stored rate, not the current one.",
    references: ["https://docs.eigenlayer.xyz/eigenlayer/restaking-guides/restaking-user-guide"],
  },

  // CUSTOM-028: Operator Concentration Risk
  {
    id: "CUSTOM-028",
    title: "Restaking Operator Concentration Risk",
    description:
      "Restaking protocols that allow arbitrary stake concentration in a single operator " +
      "create systemic risk. If one operator controls a large portion of delegated stake " +
      "and gets slashed (or acts maliciously), the impact propagates to all delegators. " +
      "Missing maximum stake per operator limits amplify this risk.",
    severity: Severity.MEDIUM,
    patterns: [
      // Delegation without checking operator limits
      /function\s+delegate\w*\s*\([^)]*address\s+operator[^)]*\)[^{]*\{(?:(?!maxStake|operatorCap|maxDelegation|limit)[\s\S])*?operatorShares/gis,
      // stake/deposit to operator without cap check
      /function\s+(?:stake|deposit)\w*\s*\([^)]*\)[^{]*\{(?:(?!maxOperator|cap|limit)[\s\S])*?operator\[/gis,
    ],
    negativePatterns: [
      /maxOperatorStake/g,
      /operatorCap/g,
      /maxDelegation/g,
      /require\s*\([^)]*limit/gi,
    ],
    remediation:
      "Implement per-operator maximum stake limits. " +
      "require(operatorShares[operator] + amount <= maxOperatorStake, 'Operator cap exceeded'); " +
      "Consider governance-controlled operator whitelisting and periodic rebalancing.",
    references: ["https://github.com/Layr-Labs/eigenlayer-contracts"],
  },

  // =========================================================================
  // POINTS / AIRDROP PROTOCOLS
  // =========================================================================

  // CUSTOM-029: Merkle Airdrop Double-Claim
  {
    id: "CUSTOM-029",
    title: "Merkle Airdrop Double-Claim Vulnerability",
    description:
      "Merkle tree-based airdrop contracts that do not properly track claimed leaves " +
      "allow users to claim multiple times. Common mistakes include: " +
      "using a bitmap that is too small, not setting the claimed bit before transferring, " +
      "or using a mapping keyed only by index (not by recipient address).",
    severity: Severity.CRITICAL,
    patterns: [
      // claim function without a claimed mapping/bitmap check before transfer
      /function\s+claim\w*\s*\([^)]*\)[^{]*\{(?:(?!claimed\[|isClaimed|BitMaps)[\s\S])*?(?:transfer|mint)\s*\(/gis,
      // MerkleProof.verify without marking as claimed
      /MerkleProof\.verify\s*\([^)]*\)(?:(?!claimed\s*\[|setClaimed|_setClaimed)[\s\S])*?transfer/gs,
    ],
    negativePatterns: [
      /claimed\s*\[/g,
      /isClaimed\s*\(/g,
      /BitMaps\.\w+/g,
      /require\s*\(\s*!claimed/g,
    ],
    remediation:
      "Mark the claim as used BEFORE transferring tokens (CEI pattern): " +
      "require(!claimed[index], 'Already claimed'); claimed[index] = true; token.transfer(account, amount); " +
      "Use OpenZeppelin's BitMaps for gas-efficient storage of large claim sets.",
    references: [
      "https://docs.openzeppelin.com/contracts/api/utils#MerkleProof",
      "https://github.com/Uniswap/merkle-distributor",
    ],
  },

  // CUSTOM-030: Points Vesting Bypass via Transfer
  {
    id: "CUSTOM-030",
    title: "Points/Vesting Bypass via Token Transfer",
    description:
      "Points or reward systems that vest over time can be bypassed if the underlying " +
      "token is freely transferable. A user can transfer their vesting position to " +
      "a fresh address to reset cooldowns, or claim points accumulated from a " +
      "position they no longer hold by front-running the transfer.",
    severity: Severity.HIGH,
    patterns: [
      // Points claimed based on balance without checking transfer history
      /function\s+claim(?:Points|Rewards|Emissions)\w*\s*\([^)]*\)[^{]*\{(?:(?!lastTransfer|transferBlock|vestedAt|lockPeriod)[\s\S])*?balanceOf/gis,
      // Vesting schedule not invalidated on transfer
      /function\s+(?:transfer|transferFrom)\s*\([^)]*\)[^{]*\{(?:(?!vestingStart|resetVest|clearRewards)[\s\S])*?super\.transfer/gs,
    ],
    negativePatterns: [/vestingStart\s*\[/g, /lastTransfer\s*\[/g, /lockPeriod/g, /soulbound/gi],
    remediation:
      "Track points per address with a snapshot of when the position was acquired. " +
      "On transfer, reset or pro-rate the vesting schedule for the recipient. " +
      "Consider non-transferable (soulbound) receipt tokens for vesting positions. " +
      "Use ERC-4626 vaults where the vault tracks the original depositor.",
    references: ["https://eips.ethereum.org/EIPS/eip-5192"],
  },

  // CUSTOM-031: Sybil-Vulnerable Points Accumulation
  {
    id: "CUSTOM-031",
    title: "Sybil-Vulnerable Points Accumulation",
    description:
      "Points protocols that award points based on on-chain actions without Sybil resistance " +
      "allow attackers to create many wallets to multiply their points. " +
      "Common patterns: points per deposit/withdrawal (can be split across wallets), " +
      "points per transaction (atomic splits), or points capped per address (bypassed with multiple addresses).",
    severity: Severity.MEDIUM,
    patterns: [
      // Points awarded per action without minimum threshold or rate limiting
      /points\s*\[\s*msg\.sender\s*\]\s*\+=\s*\w+/g,
      /function\s+earn(?:Points|Rewards)\w*\s*\([^)]*\)[^{]*\{(?:(?!minimumAmount|minDeposit|rateLimit|cooldown)[\s\S])*?points\s*\[/gis,
    ],
    negativePatterns: [/minimumDeposit/g, /minAmount/g, /cooldown\s*\[/g, /rateLimit/g, /KYC/gi],
    remediation:
      "Implement minimum deposit thresholds to make Sybil attacks economically unattractive. " +
      "Add cooldown periods between point-earning actions per address. " +
      "Consider off-chain Sybil resistance (Gitcoin Passport, Proof of Humanity) for high-value airdrops.",
    references: [
      "https://medium.com/dragonfly-research/the-anatomy-of-a-sybil-attack-7e50d8e53bb9",
    ],
  },

  // =========================================================================
  // ACCOUNT ABSTRACTION (ERC-4337)
  // =========================================================================

  // CUSTOM-032: Paymaster Drain via Malicious UserOperation
  {
    id: "CUSTOM-032",
    title: "ERC-4337 Paymaster Drain via Malicious UserOperation",
    description:
      "ERC-4337 Paymasters sponsor gas for UserOperations. A paymaster that does not " +
      "properly validate the UserOperation before sponsoring it can be drained. " +
      "Common vulnerabilities: not checking the sender's entitlement to sponsorship, " +
      "not limiting the gas sponsorship per user, or not validating the callData " +
      "that the paymaster is expected to subsidize.",
    severity: Severity.CRITICAL,
    patterns: [
      // validatePaymasterUserOp without checking sender or callData
      /function\s+validatePaymasterUserOp\s*\([^)]*\)[^{]*\{(?:(?!userOp\.sender|userOp\.callData|allowlist|whitelist|limit)[\s\S])*?return\s*\(/gis,
      // Paymaster approving without amount limit
      /function\s+validatePaymasterUserOp[^{]*\{(?:(?!maxGas|gasLimit|budget|quota)[\s\S])*?abi\.encode\s*\(/gs,
    ],
    negativePatterns: [
      /allowedSender\s*\[/g,
      /require\s*\([^)]*sender/gi,
      /gasQuota\s*\[/g,
      /budgetUsed\s*\[/g,
    ],
    remediation:
      "In validatePaymasterUserOp, always validate: " +
      "(1) the sender is whitelisted or meets sponsorship criteria; " +
      "(2) the callData targets an allowed contract; " +
      "(3) the gas limit is within the paymaster's per-user budget. " +
      "Track and enforce per-address gas budgets to prevent drain.",
    references: [
      "https://eips.ethereum.org/EIPS/eip-4337",
      "https://docs.stackup.sh/docs/paymaster-overview",
    ],
  },

  // CUSTOM-033: Session Key Scope Bypass in Smart Account
  {
    id: "CUSTOM-033",
    title: "ERC-4337 Session Key Scope Bypass",
    description:
      "Smart accounts (ERC-4337) often support session keys — temporary keys with limited " +
      "permissions (e.g., only interact with specific contracts, maximum spend). " +
      "If session key validation does not strictly enforce the scope (allowed contracts, " +
      "token limits, expiry), a compromised session key can be used for actions " +
      "outside its intended scope.",
    severity: Severity.HIGH,
    patterns: [
      // Session key validation without checking target or value
      /function\s+validateUserOp\s*\([^)]*\)[^{]*\{[^}]*sessionKey[^}]*\{(?:(?!allowedTarget|allowedContract|maxValue|expiry|deadline)[\s\S])*?return\s*0/gis,
      // Session key without expiry check
      /sessionKeys?\s*\[[^\]]+\](?:(?!expir|deadline|validUntil)[\s\S])*?=\s*true/gis,
    ],
    negativePatterns: [
      /sessionKey\.expiry/g,
      /sessionKey\.validUntil/g,
      /allowedTarget/g,
      /require\s*\([^)]*expir/gi,
    ],
    remediation:
      "Enforce strict session key scopes: " +
      "require(block.timestamp < sessionKey.expiry, 'Session expired'); " +
      "require(target == sessionKey.allowedContract, 'Target not allowed'); " +
      "require(value <= sessionKey.maxValue, 'Value exceeds limit'); " +
      "Consider ERC-7715 (Permission Grants) for standardized session key management.",
    references: [
      "https://eips.ethereum.org/EIPS/eip-4337",
      "https://eips.ethereum.org/EIPS/eip-7715",
    ],
  },

  // CUSTOM-034: Bundler Griefing via Gas Estimation Manipulation
  {
    id: "CUSTOM-034",
    title: "ERC-4337 Bundler Griefing via Gas Manipulation",
    description:
      "ERC-4337 bundlers simulate UserOperations before including them in a bundle. " +
      "If validateUserOp passes during simulation but reverts during execution " +
      "(due to state changes between simulation and execution), the bundler loses gas. " +
      "Contracts that intentionally behave differently during simulation vs execution " +
      "(e.g., checking block.number or using different code paths for EntryPoint calls) " +
      "can grief bundlers.",
    severity: Severity.MEDIUM,
    patterns: [
      // validateUserOp checking block number or timestamp (simulation vs execution difference)
      /function\s+validateUserOp\s*\([^)]*\)[^{]*\{[^}]*block\.(?:number|timestamp)/gs,
      // Different behavior based on msg.sender in validateUserOp
      /function\s+validateUserOp\s*\([^)]*\)[^{]*\{[^}]*if\s*\(\s*msg\.sender\s*(?:==|!=)/gs,
    ],
    negativePatterns: [/IEntryPoint/g, /entryPoint\s*\(/g],
    remediation:
      "Ensure validateUserOp is deterministic — the same result during simulation and execution. " +
      "Avoid state-dependent conditionals in validation. " +
      "Use the nonce and signature for all validation logic, not block variables. " +
      "Follow the ERC-4337 forbidden opcodes list (TIMESTAMP, NUMBER, BLOCKHASH, etc.) in validation.",
    references: [
      "https://eips.ethereum.org/EIPS/eip-4337#forbidden-opcodes",
      "https://docs.stackup.sh/docs/erc-4337-overview",
    ],
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
