/**
 * Generate Invariants Tool
 *
 * Analyzes a Solidity contract and generates Foundry invariant test suggestions
 * based on detected patterns: token balances, access control, state machines,
 * DeFi primitives (vault shares, lending, AMM), and protocol-specific invariants.
 */

import { readFile, access } from "fs/promises";
import { z } from "zod";
import { parseContractInfoFromSource } from "../analyzers/slangAnalyzer.js";
import { logger } from "../utils/logger.js";

// ============================================================================
// Types
// ============================================================================

export const GenerateInvariantsInputSchema = z.object({
  contractPath: z.string().describe("Path to the Solidity contract file"),
  protocolType: z
    .enum(["auto", "erc20", "erc721", "vault", "lending", "amm", "governance", "staking"])
    .optional()
    .default("auto")
    .describe("Protocol type for targeted invariants (auto-detected if omitted)"),
  includeStateful: z
    .boolean()
    .optional()
    .default(true)
    .describe("Include stateful invariant suggestions (forge test --invariant)"),
});

export type GenerateInvariantsInput = z.infer<typeof GenerateInvariantsInputSchema>;

interface InvariantSuggestion {
  id: string;
  name: string;
  description: string;
  severity: "critical" | "high" | "medium";
  code: string;
  category: string;
}

// ============================================================================
// Invariant Pattern Detectors
// ============================================================================

function detectProtocolType(source: string, inherits: string[]): string {
  const src = source.toLowerCase();
  const inh = inherits.join(" ").toLowerCase();

  if (inh.includes("erc4626") || /vault|totalassets|totalshares/.test(src)) return "vault";
  if (src.includes("borrow") && src.includes("collateral") && src.includes("liquidat"))
    return "lending";
  if (src.includes("swap") && (src.includes("reserve0") || src.includes("amountout"))) return "amm";
  if (inh.includes("governor") || src.includes("proposal") || src.includes("quorum"))
    return "governance";
  if (src.includes("stake") && src.includes("reward")) return "staking";
  if (inh.includes("erc721") || src.includes("tokenid") || src.includes("ownerof")) return "erc721";
  if (inh.includes("erc20") || (src.includes("totalsupply") && src.includes("balanceof")))
    return "erc20";

  return "generic";
}

function generateGenericInvariants(contractName: string): InvariantSuggestion[] {
  return [
    {
      id: "INV-001",
      name: "invariant_noEtherLeak",
      description:
        "Contract ETH balance should never decrease unexpectedly (only via explicit withdrawals)",
      severity: "critical",
      category: "ETH accounting",
      code: `// Track ETH going in vs out
function invariant_etherAccounting() public {
    // If your contract tracks ETH via a variable, check consistency
    assertGe(address(target).balance, 0);
}`,
    },
    {
      id: "INV-002",
      name: "invariant_noUnauthorizedStateChange",
      description: "Only authorized callers should be able to change critical state",
      severity: "high",
      category: "Access control",
      code: `function invariant_ownerIsSet() public {
    // Owner should never be zero address after initialization
    assertNotEq(${contractName}(target).owner(), address(0));
}`,
    },
  ];
}

function generateERC20Invariants(contractName: string): InvariantSuggestion[] {
  return [
    {
      id: "INV-010",
      name: "invariant_totalSupplyEqualsBalanceSum",
      description: "totalSupply must equal the sum of all balances",
      severity: "critical",
      category: "Token accounting",
      code: `function invariant_totalSupplyIntegrity() public {
    uint256 sumBalances = 0;
    for (uint i = 0; i < holders.length; i++) {
        sumBalances += ${contractName}(target).balanceOf(holders[i]);
    }
    assertEq(${contractName}(target).totalSupply(), sumBalances);
}`,
    },
    {
      id: "INV-011",
      name: "invariant_balanceNeverOverflows",
      description: "Individual balances plus totalSupply should never overflow uint256",
      severity: "high",
      category: "Arithmetic",
      code: `function invariant_noOverflow() public {
    IERC20 token = IERC20(target);
    assertLe(token.totalSupply(), type(uint256).max);
    assertLe(token.balanceOf(address(this)), token.totalSupply());
}`,
    },
    {
      id: "INV-012",
      name: "invariant_approvalDoesNotChangeTotalSupply",
      description: "approve() should never change totalSupply",
      severity: "medium",
      category: "Token accounting",
      code: `function invariant_approveSafe() public {
    uint256 supplyBefore = IERC20(target).totalSupply();
    // Handler calls approve() — totalSupply should be unchanged
    assertEq(IERC20(target).totalSupply(), supplyBefore);
}`,
    },
  ];
}

function generateVaultInvariants(_contractName: string): InvariantSuggestion[] {
  return [
    {
      id: "INV-020",
      name: "invariant_totalAssetsGeTotalShareValue",
      description: "totalAssets() must always be >= the redemption value of all shares",
      severity: "critical",
      category: "ERC-4626 accounting",
      code: `function invariant_solvency() public {
    IERC4626 vault = IERC4626(target);
    uint256 totalShares = vault.totalSupply();
    uint256 totalAssets = vault.totalAssets();
    if (totalShares > 0) {
        // Conversion must be non-negative
        assertGe(totalAssets, vault.convertToAssets(totalShares));
    }
}`,
    },
    {
      id: "INV-021",
      name: "invariant_sharePriceNeverDecreases",
      description: "Share price (assets per share) should never decrease except due to slashing",
      severity: "critical",
      category: "ERC-4626 accounting",
      code: `uint256 public lastPricePerShare;

function setUp() public {
    lastPricePerShare = 1e18; // initial 1:1
}

function invariant_sharePriceMonotonicallyIncreases() public {
    IERC4626 vault = IERC4626(target);
    if (vault.totalSupply() > 0) {
        uint256 currentPrice = vault.convertToAssets(1e18);
        assertGe(currentPrice, lastPricePerShare);
        lastPricePerShare = currentPrice;
    }
}`,
    },
    {
      id: "INV-022",
      name: "invariant_depositWithdrawRoundtrip",
      description:
        "Depositing and immediately withdrawing should return <= original amount (no profit)",
      severity: "high",
      category: "Inflation attack",
      code: `function invariant_noFreeLunch() public {
    IERC4626 vault = IERC4626(target);
    uint256 assets = 1e18;
    // User deposits assets -> gets shares
    uint256 shares = vault.previewDeposit(assets);
    // User redeems shares -> should get <= assets back
    uint256 assetsBack = vault.previewRedeem(shares);
    assertLe(assetsBack, assets);
}`,
    },
  ];
}

function generateLendingInvariants(_contractName: string): InvariantSuggestion[] {
  return [
    {
      id: "INV-030",
      name: "invariant_protocolAlwaysSolvent",
      description: "Total collateral value must always exceed total debt value",
      severity: "critical",
      category: "Lending solvency",
      code: `function invariant_solvency() public {
    uint256 totalCollateralValue = 0;
    uint256 totalDebtValue = 0;
    for (uint i = 0; i < borrowers.length; i++) {
        totalCollateralValue += getCollateralValue(borrowers[i]);
        totalDebtValue += getBorrowedValue(borrowers[i]);
    }
    // Protocol should always be overcollateralized
    assertGe(totalCollateralValue, totalDebtValue);
}`,
    },
    {
      id: "INV-031",
      name: "invariant_liquidatablePositionsExist",
      description: "Any position below liquidation threshold must be liquidatable",
      severity: "high",
      category: "Lending liquidation",
      code: `function invariant_liquidatablePositionsAreLiquidatable() public {
    for (uint i = 0; i < borrowers.length; i++) {
        address borrower = borrowers[i];
        if (isUndercollateralized(borrower)) {
            // Must be able to liquidate — no revert
            assertTrue(canLiquidate(borrower));
        }
    }
}`,
    },
    {
      id: "INV-032",
      name: "invariant_interestAccrualNeverNegative",
      description: "Accrued interest must always be non-negative",
      severity: "medium",
      category: "Interest accounting",
      code: `function invariant_positiveInterest() public {
    for (uint i = 0; i < borrowers.length; i++) {
        assertGe(getDebt(borrowers[i]), getInitialBorrow(borrowers[i]));
    }
}`,
    },
  ];
}

function generateAMMInvariants(_contractName: string): InvariantSuggestion[] {
  return [
    {
      id: "INV-040",
      name: "invariant_constantProductK",
      description:
        "For Uniswap V2-style AMMs: reserve0 * reserve1 must never decrease after a swap",
      severity: "critical",
      category: "AMM invariant",
      code: `uint256 public kLast;

function setUp() public {
    (uint112 r0, uint112 r1,) = IUniswapV2Pair(target).getReserves();
    kLast = uint256(r0) * uint256(r1);
}

function invariant_constantProduct() public {
    (uint112 r0, uint112 r1,) = IUniswapV2Pair(target).getReserves();
    uint256 k = uint256(r0) * uint256(r1);
    // K should never decrease (swaps should maintain or increase K due to fees)
    assertGe(k, kLast);
    kLast = k;
}`,
    },
    {
      id: "INV-041",
      name: "invariant_noFreeArbitrage",
      description: "Swapping tokenA for tokenB and back should result in <= original amount",
      severity: "high",
      category: "AMM price integrity",
      code: `function invariant_roundtripSwapLoss() public {
    uint256 amountIn = 1e18;
    uint256 amountOut = getAmountOut(amountIn, reserveA, reserveB);
    uint256 amountBack = getAmountOut(amountOut, reserveB, reserveA);
    // Round-trip should always result in a loss (fees taken)
    assertLt(amountBack, amountIn);
}`,
    },
  ];
}

function generateGovernanceInvariants(contractName: string): InvariantSuggestion[] {
  return [
    {
      id: "INV-050",
      name: "invariant_quorumNeverZero",
      description: "Quorum should never be set to zero (would allow trivial governance attacks)",
      severity: "critical",
      category: "Governance safety",
      code: `function invariant_nonZeroQuorum() public {
    assertGt(${contractName}(target).quorumNumerator(), 0);
}`,
    },
    {
      id: "INV-051",
      name: "invariant_timelockEnforced",
      description: "Proposals should never be executable before the timelock delay",
      severity: "high",
      category: "Governance timelock",
      code: `function invariant_timelockEnforced() public {
    uint256 proposalId = lastProposalId;
    if (proposalId != 0) {
        uint256 eta = ${contractName}(target).proposalEta(proposalId);
        if (eta > 0) {
            assertGe(eta, block.timestamp + minDelay);
        }
    }
}`,
    },
  ];
}

function generateStakingInvariants(contractName: string): InvariantSuggestion[] {
  return [
    {
      id: "INV-060",
      name: "invariant_totalStakedEqualsSum",
      description: "Total staked amount must equal sum of all individual stakes",
      severity: "critical",
      category: "Staking accounting",
      code: `function invariant_totalStakedIntegrity() public {
    uint256 sumStakes = 0;
    for (uint i = 0; i < stakers.length; i++) {
        sumStakes += ${contractName}(target).stakedBalance(stakers[i]);
    }
    assertEq(${contractName}(target).totalStaked(), sumStakes);
}`,
    },
    {
      id: "INV-061",
      name: "invariant_rewardsNeverExceedBudget",
      description: "Total rewards distributed must never exceed the total reward budget",
      severity: "high",
      category: "Reward accounting",
      code: `function invariant_rewardsBudget() public {
    uint256 distributed = ${contractName}(target).totalRewardsDistributed();
    uint256 budget = ${contractName}(target).rewardBudget();
    assertLe(distributed, budget);
}`,
    },
  ];
}

// ============================================================================
// Main Function
// ============================================================================

export async function generateInvariants(input: GenerateInvariantsInput): Promise<string> {
  logger.info(`[generateInvariants] Analyzing ${input.contractPath}`);

  try {
    await access(input.contractPath);
  } catch {
    return JSON.stringify({ success: false, error: `File not found: ${input.contractPath}` });
  }

  const source = await readFile(input.contractPath, "utf-8");
  const info = parseContractInfoFromSource(source, input.contractPath);

  const detectedType =
    input.protocolType === "auto" ? detectProtocolType(source, info.inherits) : input.protocolType;

  const contractName = info.name;
  const suggestions: InvariantSuggestion[] = [];

  // Always include generic invariants
  suggestions.push(...generateGenericInvariants(contractName));

  // Add protocol-specific invariants
  switch (detectedType) {
    case "erc20":
      suggestions.push(...generateERC20Invariants(contractName));
      break;
    case "vault":
      suggestions.push(...generateVaultInvariants(contractName));
      break;
    case "lending":
      suggestions.push(...generateLendingInvariants(contractName));
      break;
    case "amm":
      suggestions.push(...generateAMMInvariants(contractName));
      break;
    case "governance":
      suggestions.push(...generateGovernanceInvariants(contractName));
      break;
    case "staking":
      suggestions.push(...generateStakingInvariants(contractName));
      break;
    default:
      // Generic only
      break;
  }

  return formatOutput(contractName, detectedType, suggestions, input.includeStateful ?? true);
}

// ============================================================================
// Output Formatting
// ============================================================================

function formatOutput(
  contractName: string,
  protocolType: string,
  suggestions: InvariantSuggestion[],
  includeStateful: boolean
): string {
  const lines: string[] = [];

  lines.push("═══════════════════════════════════════════════════════════════════════════════");
  lines.push(`  INVARIANT TEST SUGGESTIONS: ${contractName}`);
  lines.push(`  Protocol Type: ${protocolType}`);
  lines.push("═══════════════════════════════════════════════════════════════════════════════");
  lines.push("");

  lines.push("┌─────────────────────────────────────────────────────────────────────────────┐");
  lines.push("│  OVERVIEW                                                                   │");
  lines.push("└─────────────────────────────────────────────────────────────────────────────┘");
  lines.push(`  ${suggestions.length} invariant suggestions generated`);
  lines.push(`  Critical: ${suggestions.filter((s) => s.severity === "critical").length}`);
  lines.push(`  High:     ${suggestions.filter((s) => s.severity === "high").length}`);
  lines.push(`  Medium:   ${suggestions.filter((s) => s.severity === "medium").length}`);
  lines.push("");

  if (includeStateful) {
    lines.push("┌─────────────────────────────────────────────────────────────────────────────┐");
    lines.push("│  HOW TO RUN                                                                 │");
    lines.push("└─────────────────────────────────────────────────────────────────────────────┘");
    lines.push("  # Run invariant tests");
    lines.push("  forge test --match-test invariant_ --invariant-runs 10000");
    lines.push("");
    lines.push("  # Run with more depth");
    lines.push("  forge test --match-test invariant_ --invariant-runs 10000 --invariant-depth 50");
    lines.push("");
  }

  const bySeverity = ["critical", "high", "medium"] as const;
  const severityEmoji = { critical: "🔴", high: "🟠", medium: "🟡" };

  for (const sev of bySeverity) {
    const group = suggestions.filter((s) => s.severity === sev);
    if (group.length === 0) continue;

    lines.push(`┌─────────────────────────────────────────────────────────────────────────────┐`);
    lines.push(
      `│  ${severityEmoji[sev]} ${sev.toUpperCase()} INVARIANTS (${group.length})                                          │`.slice(
        0,
        79
      ) + "│"
    );
    lines.push(`└─────────────────────────────────────────────────────────────────────────────┘`);

    for (const inv of group) {
      lines.push("");
      lines.push(`  [${inv.id}] ${inv.name}`);
      lines.push(`  Category: ${inv.category}`);
      lines.push(`  ${inv.description}`);
      lines.push("");
      lines.push("  ```solidity");
      for (const codeLine of inv.code.split("\n")) {
        lines.push(`  ${codeLine}`);
      }
      lines.push("  ```");
      lines.push("");
    }
  }

  lines.push("┌─────────────────────────────────────────────────────────────────────────────┐");
  lines.push("│  FOUNDRY SETUP TEMPLATE                                                     │");
  lines.push("└─────────────────────────────────────────────────────────────────────────────┘");
  lines.push("");
  lines.push("  ```solidity");
  lines.push("  // SPDX-License-Identifier: MIT");
  lines.push("  pragma solidity ^0.8.20;");
  lines.push("");
  lines.push('  import {Test} from "forge-std/Test.sol";');
  lines.push(`  import {${contractName}} from "src/${contractName}.sol";`);
  lines.push("");
  lines.push(`  contract ${contractName}InvariantTest is Test {`);
  lines.push(`      ${contractName} public target;`);
  lines.push("      address[] public actors;");
  lines.push("");
  lines.push("      function setUp() public {");
  lines.push(`          target = new ${contractName}(/* constructor args */);`);
  lines.push("          actors.push(makeAddr('alice'));");
  lines.push("          actors.push(makeAddr('bob'));");
  lines.push("          // Add target to invariant test scope");
  lines.push("          targetContract(address(target));");
  lines.push("      }");
  lines.push("");
  lines.push("      // Paste invariant functions above here");
  lines.push("  }");
  lines.push("  ```");
  lines.push("");
  lines.push("═══════════════════════════════════════════════════════════════════════════════");

  return lines.join("\n");
}
