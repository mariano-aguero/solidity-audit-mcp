# Solidity Audit MCP

[![CI](https://github.com/mariano-aguero/solidity-audit-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/mariano-aguero/solidity-audit-mcp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen)](https://nodejs.org/)
[![Claude](https://img.shields.io/badge/Claude-MCP%20Compatible-blueviolet?logo=anthropic)](https://claude.ai)

A Model Context Protocol (MCP) server for automated security analysis of Solidity smart contracts. Integrates with industry-standard tools like Slither and Aderyn, plus built-in pattern matching against the SWC Registry.

## Quick Start: Add Auditing to Your Project

Add automated security audits to any Solidity project in 2 minutes:

### 1. Copy the workflow to your project

Create `.github/workflows/audit.yml` in your Solidity project:

```yaml
name: Smart Contract Audit

on:
  pull_request:
    paths: ["**.sol"]
  push:
    branches: [main]
    paths: ["**.sol"]

permissions:
  contents: read
  pull-requests: write
  security-events: write
  checks: write

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: actions/setup-node@v4
        with:
          node-version: "20"

      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install audit tools
        run: |
          pip install slither-analyzer
          curl -L https://foundry.paradigm.xyz | bash
          ~/.foundry/bin/foundryup
          echo "$HOME/.foundry/bin" >> $GITHUB_PATH
          npm install -g solidity-audit-mcp

      - name: Run Audit
        run: |
          audit-cli audit contracts/ --format markdown
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### 2. That's it!

Every PR that touches `.sol` files will be automatically audited.

### How It Works

```
┌─────────────────────────────────────────────────────────────────────┐
│                        YOUR PROJECT                                 │
│                  (e.g., smart-contract-audit-example)               │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. You modify Token.sol and create a PR                            │
│                                                                     │
│  2. GitHub triggers the audit workflow                              │
│                                                                     │
│  3. MCP Audit Server runs ALL analyzers on changed .sol files       │
│     (Slither, Aderyn, Slang AST, SWC patterns, Gas optimizer)       │
│                                                                     │
│  4. Results appear directly in your PR:                             │
│     ├── ✓ Inline annotations on problematic lines                   │
│     ├── ✓ Summary comment with all findings                         │
│     ├── ✓ Check status (pass/fail based on severity)                │
│     └── ✓ Security tab integration (SARIF)                          │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### What You See in the PR

**Inline annotations on each vulnerable line:**

```solidity
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount);

    (bool success, ) = msg.sender.call{value: amount}("");
    // ▲ 🟠 HIGH: Reentrancy vulnerability
    // │  State change after external call allows reentrancy attack.
    // │  Recommendation: Use checks-effects-interactions pattern.
    // └─ Detector: slither

    require(success);
    balances[msg.sender] -= amount;  // ← State change should be BEFORE the call
}
```

**PR comment with full report:**

```
┌────────────────────────────────────────────────────────────┐
│  🔍 Smart Contract Audit Report                            │
│                                                            │
│  Risk Level: 🟠 HIGH                                       │
│  Findings: 0 critical, 2 high, 3 medium                    │
│  Gas Optimizations: 5 suggestions (~500 gas savings)       │
│                                                            │
│  ┌──────────┬─────────────────────┬─────────────┬───────┐  │
│  │ Severity │ Title               │ Location    │ Tool  │  │
│  ├──────────┼─────────────────────┼─────────────┼───────┤  │
│  │ HIGH     │ Reentrancy          │ Token.sol:45│slither│  │
│  │ HIGH     │ Unprotected withdraw│ Token.sol:32│aderyn │  │
│  │ MEDIUM   │ Floating pragma     │ Token.sol:1 │slang  │  │
│  └──────────┴─────────────────────┴─────────────┴───────┘  │
└────────────────────────────────────────────────────────────┘
```

**Check status on the PR:**
- 🔴 **Failed** - If critical or high severity findings exist
- 🟢 **Passed** - If no findings above your configured threshold

### Optional: On-Demand Audits via Issues

Want to trigger audits by creating an issue or comment? Add `.github/workflows/audit-on-demand.yml`:

```yaml
name: On-Demand Audit

on:
  issues:
    types: [opened]
  issue_comment:
    types: [created]

permissions:
  contents: read
  issues: write

jobs:
  audit:
    if: contains(github.event.issue.title, 'audit') || contains(github.event.comment.body, 'audit')
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install tools
        run: |
          pip install slither-analyzer
          npm install -g solidity-audit-mcp

      - name: Run Audit
        id: audit
        run: |
          audit-cli audit contracts/ --format markdown > report.md

      - name: Post Report
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const report = fs.readFileSync('report.md', 'utf8');
            await github.rest.issues.createComment({
              owner: context.repo.owner,
              repo: context.repo.repo,
              issue_number: context.issue.number,
              body: report
            });
```

Now create an issue with "audit" in the title, and get a full security report as a comment.

---

## What It Does

The Solidity Audit MCP provides AI assistants (like Claude) with the ability to perform comprehensive security audits on Solidity smart contracts. It combines multiple analysis approaches:

**External Analyzers (require installation):**
- **Slither** - Trail of Bits' static analysis framework with 90+ vulnerability detectors
- **Aderyn** - Cyfrin's Rust-based analyzer for fast, accurate detection
- **Foundry** - Run forge tests and get coverage reports

**Built-in Analysis (no external dependencies):**
- **Slang Parser** - Nomic Foundation's Solidity parser (`@nomicfoundation/slang`) for precise AST-based vulnerability detection. Included as npm dependency.
- **SWC Pattern Matching** - Detection against the Smart Contract Weakness Classification registry

Findings from multiple tools are automatically deduplicated and sorted by severity, giving you a unified view of potential issues.

## Prerequisites

### Node.js 20+

```bash
# Using nvm (recommended)
nvm install 20
nvm use 20

# Or download from https://nodejs.org/
```

### Slither

Static analysis framework by Trail of Bits.

```bash
# Using pip (requires Python 3.8+)
pip install slither-analyzer

# Or using pipx for isolated installation
pipx install slither-analyzer

# Verify installation
slither --version
```

**Note:** Slither requires `solc` (Solidity compiler) to be installed.

### Aderyn

Rust-based analyzer by Cyfrin.

```bash
# Using cargo (requires Rust)
cargo install aderyn

# Or using curl (Linux/macOS)
curl -L https://raw.githubusercontent.com/Cyfrin/aderyn/dev/cyfrinup/install | bash
cyfrinup

# Verify installation
aderyn --version
```

### Foundry

Development toolkit for Ethereum (includes forge, cast, anvil).

```bash
# Install foundryup
curl -L https://foundry.paradigm.xyz | bash

# Then run foundryup to install forge, cast, anvil
foundryup

# Verify installation
forge --version
```

### solc (Solidity Compiler)

Required by Slither for compilation.

```bash
# Using solc-select (recommended - allows multiple versions)
pip install solc-select
solc-select install 0.8.20
solc-select use 0.8.20

# Or on macOS with Homebrew
brew install solidity

# Or on Ubuntu/Debian
sudo add-apt-repository ppa:ethereum/ethereum
sudo apt-get update
sudo apt-get install solc

# Verify installation
solc --version
```

## Installation

```bash
# Clone the repository
git clone https://github.com/mariano-aguero/solidity-audit-mcp.git
cd solidity-audit-mcp

# Install dependencies
npm install

# Build the project
npm run build

# Verify the build
node dist/index.js
# Should output: [INFO] Starting solidity-audit-mcp v1.6.0
# Press Ctrl+C to exit
```

## Docker

For a complete environment with all tools pre-installed, use Docker:

```bash
# Build the image
npm run docker:build

# Run MCP server
npm run docker:run

# Run CLI audit
npm run docker:cli -- analyze /contracts/MyContract.sol

# Interactive shell with all tools
npm run docker:shell
```

### Docker with Claude Desktop

```json
{
  "mcpServers": {
    "audit": {
      "command": "docker",
      "args": ["run", "-i", "-v", "/path/to/contracts:/contracts", "solidity-audit-mcp"]
    }
  }
}
```

### What's Included

The Docker image includes:
- Node.js 20
- Slither (Python) — static analysis
- Aderyn v0.6.8 (Rust) — fast AST-based detection
- Foundry (forge, cast, anvil) — testing & coverage
- solc-select with common Solidity versions (0.8.28, 0.8.24, 0.8.20, and more)
- Halmos — symbolic execution (x86_64 only; ARM64 skipped gracefully)
- Echidna — property fuzzer (x86_64 only; ARM64 skipped gracefully)

**Platform notes:**
- All tools work on x86_64 (standard CI/CD environments)
- On ARM64 (Apple Silicon), Slither, Aderyn, and Forge are fully available; Echidna and Halmos require x86_64

## SaaS Mode (Remote Server)

Run the MCP server as a remote service that any MCP client can connect to via HTTP/SSE.

### Quick Start

```bash
# Build and start the SaaS server
npm run saas:build
npm run saas:up

# Check status
curl http://localhost:3000/health

# View logs
npm run saas:logs

# Stop
npm run saas:down
```

### Configuration

```bash
# 1. Copy example environment file
cp .env.example .env

# 2. Generate a secure API key
openssl rand -hex 32

# 3. Edit .env and set your API key
# MCP_API_KEY=your-generated-key

# 4. Start the server
npm run saas:up
```

Or set the API key inline:

```bash
MCP_API_KEY=your-secret-key npm run saas:up
```

### MCP Client Configuration (SSE Transport)

Configure your MCP client to connect to the remote server:

```json
{
  "mcpServers": {
    "audit": {
      "transport": {
        "type": "sse",
        "url": "http://localhost:3000/sse"
      }
    }
  }
}
```

With API key authentication:

```json
{
  "mcpServers": {
    "audit": {
      "transport": {
        "type": "sse",
        "url": "http://your-server.com:3000/sse",
        "headers": {
          "X-API-Key": "your-secret-key"
        }
      }
    }
  }
}
```

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Full health check with analyzer status |
| `/health/quick` | GET | Quick health check (no analyzer verification) |
| `/info` | GET | Server info and available tools |
| `/sse` | GET | SSE connection for MCP |
| `/message` | POST | Message handler for MCP |
| `/api/analyze` | POST | Analyze contract from source code |
| `/api/check` | POST | Quick vulnerability check from source |
| `/api/ci/review` | POST | CI: Analyze & post inline PR comments |

#### Health Check Response

```json
{
  "status": "healthy",
  "server": "solidity-audit-mcp",
  "version": "1.6.0",
  "uptime": 3600,
  "tools": 10,
  "analyzers": {
    "slither":  { "available": true,  "version": "0.11.5" },
    "aderyn":   { "available": true,  "version": "0.6.8" },
    "forge":    { "available": true,  "version": "1.5.1-stable" },
    "solc":     { "available": true,  "version": "0.8.28" },
    "echidna":  { "available": false, "error": "..." },
    "halmos":   { "available": false, "error": "..." },
    "slang":    { "available": true,  "version": "available" }
  },
  "timestamp": "2026-01-15T10:30:00.000Z"
}
```

Status values:
- `healthy` — Core analyzers (Slither + Forge) available
- `degraded` — Only one core analyzer available, or only Slang (built-in)
- `unhealthy` — No analyzers available (returns HTTP 503)

> **Note:** `echidna` and `halmos` are opt-in fuzzers that require explicit setup. Their absence does not affect the overall status.

### Environment Variables

Copy `.env.example` to `.env` and configure:

```bash
cp .env.example .env
```

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | 3000 | Server port |
| `HOST` | 0.0.0.0 | Server host |
| `MCP_API_KEY` | (none) | API key for authentication (recommended for production) |
| `MCP_AUDIT_LOG_LEVEL` | info | Log level (debug, info, warn, error) |
| `NODE_ENV` | production | Node environment |

**Authentication methods supported:**
- Header: `X-API-Key: your-key`
- Bearer: `Authorization: Bearer your-key`

### Production Deployment

For production, consider:

1. **Use HTTPS** - Put behind a reverse proxy (nginx) with SSL
2. **Enable authentication** - Set `MCP_API_KEY`
3. **Mount contracts** - Mount your contracts directory into the container
4. **Resource limits** - Set memory/CPU limits in docker-compose

Example with nginx SSL:

```bash
docker-compose -f docker/docker-compose.saas.yml --profile with-ssl up -d
```

## Configuration

### Option 1: Project-level configuration (`.mcp.json`)

Create a `.mcp.json` file in your project root:

```json
{
  "mcpServers": {
    "audit": {
      "command": "node",
      "args": ["/path/to/solidity-audit-mcp/dist/index.js"]
    }
  }
}
```

### Option 2: Global configuration (`~/.claude/mcp.json`)

For system-wide availability, add to your Claude MCP configuration:

```json
{
  "mcpServers": {
    "audit": {
      "command": "node",
      "args": ["/path/to/solidity-audit-mcp/dist/index.js"]
    }
  }
}
```

### Option 3: Using npx (if published)

```json
{
  "mcpServers": {
    "audit": {
      "command": "npx",
      "args": ["solidity-audit-mcp"]
    }
  }
}
```

## Usage with Claude Code

Once configured, the audit tools become available in Claude Code. Here are some example prompts:

```
Analyze the security of contracts/Token.sol
```

```
Check contracts/Vault.sol for vulnerabilities against SWC-107 and SWC-115
```

```
Get the attack surface info for src/MyContract.sol
```

```
Run the full audit pipeline on contracts/Protocol.sol including tests
```

## Available Tools

### `analyze_contract`

Runs a complete security analysis pipeline on a Solidity contract.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `contractPath` | string | Yes | Path to the `.sol` file |
| `projectRoot` | string | No | Root directory of the project (auto-detected if not provided) |
| `runTests` | boolean | No | Whether to run forge tests as part of analysis (default: false) |
| `analyzers` | string[] | No | Specific analyzers to run: `"slither"`, `"aderyn"`, `"slang"`, `"gas"`, `"echidna"`, `"halmos"` (runs all available if omitted) |

**What it does:**
1. Parses contract metadata (functions, state variables, inheritance)
2. Runs Slither and Aderyn in parallel
3. Detects risky code patterns
4. Deduplicates findings from multiple tools
5. Sorts findings by severity
6. Returns a formatted report with JSON data

---

### `get_contract_info`

Extracts metadata and attack surface information without running full analysis.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `contractPath` | string | Yes | Path to the `.sol` file |

**Returns:**
- Contract name, compiler version, inheritance chain
- Functions grouped by visibility (external, public, internal, private)
- State variables and their visibility
- Events, errors, and modifiers
- Attack surface metrics (payable functions, delegatecall usage, etc.)
- Security considerations based on detected patterns

---

### `check_vulnerabilities`

Scans a contract against the SWC Registry patterns using regex-based detection.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `contractPath` | string | Yes | Path to the `.sol` file |
| `detectors` | string[] | No | Array of specific SWC IDs to check (e.g., `["SWC-107", "SWC-115"]`) |

**Supported SWC Patterns:**
- SWC-100: Function Default Visibility
- SWC-101: Integer Overflow/Underflow (unchecked blocks)
- SWC-103: Floating Pragma
- SWC-104: Unchecked Call Return Value
- SWC-105: Unprotected Ether Withdrawal
- SWC-106: Unprotected SELFDESTRUCT
- SWC-107: Reentrancy
- SWC-115: Authorization through tx.origin
- SWC-116: Block values as Time Proxy
- And 20+ more...

---

### `run_tests`

Executes forge tests and returns results with optional coverage.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `projectRoot` | string | Yes | Root directory of the Foundry project |
| `contractName` | string | No | Specific contract to test (runs all if omitted) |

**Returns:**
- Test pass/fail/skip counts
- Coverage percentage (if configured)
- Gas report
- Execution time

---

### `generate_report`

Generates a formatted audit report from findings and contract metadata.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `findings` | Finding[] | Yes | Array of Finding objects from analysis |
| `contractInfo` | ContractInfo | Yes | ContractInfo object with contract metadata |
| `format` | string | No | Output format - `"markdown"` (default) or `"json"` |
| `projectName` | string | No | Name of the project being audited |
| `auditorName` | string | No | Name of the auditor (default: "Solidity Audit MCP") |

**Returns:**
- Executive summary with risk level
- Contract overview
- Detailed findings with recommendations
- Remediation guidance

---

### `optimize_gas`

Analyzes a contract for gas optimization opportunities.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `contractPath` | string | Yes | Path to the `.sol` file |
| `includeInformational` | boolean | No | Include low-impact suggestions (default: false) |

**Returns:**
- Storage optimizations (packing, caching)
- Loop optimizations
- Function visibility suggestions
- Calldata vs memory recommendations
- Estimated gas savings

---

### `diff_audit`

Compares two versions of a contract and audits only the changes.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `oldContractPath` | string | Yes | Path to the old version |
| `newContractPath` | string | Yes | Path to the new version |
| `focusOnly` | boolean | No | Only report issues in changed code (default: true) |

**Returns:**
- Functions added/removed/modified
- New vulnerabilities introduced
- Issues resolved by changes
- Risk assessment of changes

---

### `audit_project`

Scans an entire project directory for Solidity contracts and audits all of them.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `projectRoot` | string | Yes | Root directory of the project |
| `pattern` | string | No | Glob pattern for contracts (default: `**/*.sol`) |
| `exclude` | string[] | No | Patterns to exclude (default: `["node_modules/**", "test/**"]`) |

**Returns:**
- Summary of all contracts found
- Aggregated findings across all contracts
- Per-contract breakdown
- Project-level risk assessment

---

### `generate_invariants`

Analyzes a Solidity contract and generates ready-to-use Foundry invariant test templates. Auto-detects the protocol type from source code and inheritance to produce targeted invariants.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `contractPath` | string | Yes | Path to the `.sol` file |
| `protocolType` | string | No | Protocol type: `"auto"` (default), `"erc20"`, `"erc721"`, `"vault"`, `"lending"`, `"amm"`, `"governance"`, `"staking"` |
| `includeStateful` | boolean | No | Include stateful invariant suggestions with `forge test --invariant` run commands (default: true) |

**Supported protocol types:**
- **ERC-20** — totalSupply conservation, approve safety, transfer solvency
- **ERC-4626 Vault** — totalAssets ≥ total share value, share price non-decreasing, deposit/withdraw round-trip
- **Lending** — protocol solvency, liquidatable positions, non-negative interest accrual
- **AMM** — constant product k, no free lunch on swap, LP share conservation
- **Governance** — proposal state machine, quorum immutability, vote weight conservation
- **Staking** — reward monotonicity, total staked balance, slash accounting
- **Generic** — balance conservation, access control, no unauthorized mint/burn

**Returns:**
- Severity-classified invariant suggestions (Critical / High / Medium)
- Ready-to-paste `invariant_*()` function bodies
- Foundry setup template with handler contract
- Run commands for `forge test --invariant`

---

### `explain_finding`

Returns a detailed explanation of a security finding. Accepts SWC Registry IDs, custom detector IDs, or free-text keywords.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `findingId` | string | Yes | Finding ID or keyword — e.g. `"SWC-107"`, `"CUSTOM-032"`, `"reentrancy"`, `"flash loan"`, `"paymaster"` |
| `severity` | string | No | Severity level for additional context (`"critical"`, `"high"`, `"medium"`, `"low"`, `"informational"`) |
| `contractContext` | string | No | Brief description of the contract to tailor the explanation |

**Supported finding IDs (19 total):**

| ID | Title | Severity |
|----|-------|----------|
| `SWC-101` | Integer Overflow/Underflow | High |
| `SWC-103` | Floating Pragma | Low |
| `SWC-104` | Unchecked Return Value | High |
| `SWC-107` | Reentrancy | Critical |
| `SWC-112` | Delegatecall to Untrusted Callee | Critical |
| `SWC-115` | Authorization through tx.origin | High |
| `SWC-116` | Block Timestamp Dependence | Medium |
| `CUSTOM-001` | Array Length Mismatch | High |
| `CUSTOM-004` | Price Oracle Manipulation / Flash Loan Attack | Critical |
| `CUSTOM-005` | Missing Zero Address Validation | Medium |
| `CUSTOM-006` | Missing Events for Critical State Changes | Low |
| `CUSTOM-011` | Signature Without Replay Protection | High |
| `CUSTOM-013` | Hash Collision via abi.encodePacked | Medium |
| `CUSTOM-015` | Division Before Multiplication | Medium |
| `CUSTOM-016` | Permit Without Deadline | Medium |
| `CUSTOM-017` | Missing Access Control on Critical Function | Critical |
| `CUSTOM-018` | ERC-7702 Unprotected Initializer | Critical |
| `CUSTOM-029` | Merkle Double-Claim | High |
| `CUSTOM-032` | ERC-4337 Paymaster Drain | Critical |

**Supported keywords:** `reentrancy`, `overflow`, `underflow`, `pragma`, `unchecked return`, `timestamp`, `delegatecall`, `tx.origin`, `array length`, `zero address`, `missing events`, `replay`, `nonce`, `encodepacked`, `hash collision`, `precision loss`, `permit`, `access control`, `merkle`, `airdrop`, `flash loan`, `oracle`, `erc-7702`, `paymaster`, `erc-4337`

**Returns:**
- Root cause analysis
- Concrete impact description
- Step-by-step exploit scenario
- Vulnerable code example vs. secure code example
- Foundry PoC test template
- Remediation steps
- References (SWC Registry, audit reports, research)

## CLI Usage

The audit server includes a CLI for running audits outside of Claude Code, useful for CI/CD pipelines.

### Installation

```bash
# Global installation
npm install -g solidity-audit-mcp

# Or run directly
npx solidity-audit-mcp
```

### Commands

```bash
# Run security audit
solidity-audit-cli audit ./contracts/Token.sol

# Compare contract versions
solidity-audit-cli diff ./old/Token.sol ./new/Token.sol

# Analyze gas optimizations
solidity-audit-cli gas ./contracts/Token.sol

# Output formats
solidity-audit-cli audit ./contracts/Token.sol --format json
solidity-audit-cli audit ./contracts/Token.sol --format sarif --output results.sarif
solidity-audit-cli audit ./contracts/Token.sol --format markdown

# Filter by severity
solidity-audit-cli audit ./contracts/Token.sol --severity-threshold high
```

### CLI Options

| Option | Short | Description |
|--------|-------|-------------|
| `--format <type>` | `-f` | Output format: markdown, json, sarif |
| `--output <file>` | `-o` | Write output to file instead of stdout |
| `--severity-threshold <level>` | `-s` | Minimum severity: critical, high, medium, low, informational |
| `--quiet` | `-q` | Suppress progress messages |
| `--no-color` | | Disable colored output |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No findings above threshold |
| 1 | Findings detected above threshold |
| 2 | Execution error |

## GitHub Code Scanning Integration

The audit server can upload results to GitHub's Security tab using SARIF format. This enables:

- **Security tab alerts** - View all findings in the Security > Code scanning section
- **PR annotations** - Inline annotations on affected lines in pull requests
- **Security overview** - Repository-level security insights

### Enabling GitHub Code Scanning

1. **Enable GitHub Advanced Security** (free for public repositories)
   - Go to **Settings > Security > Code security and analysis**
   - Enable **Code scanning**

2. **Add the workflow** to your repository:

```yaml
# .github/workflows/code-scanning.yml
name: Code Scanning

on:
  push:
    branches: [main]
    paths: ["**.sol"]
  pull_request:
    paths: ["**.sol"]

permissions:
  contents: read
  security-events: write

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: "20"

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install tools
        run: |
          pip install slither-analyzer
          npm install -g solidity-audit-mcp

      - name: Run Audit
        run: |
          solidity-audit-cli audit contracts/ --format sarif --output results.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
          category: "smart-contract-security"
```

3. **View results** in the Security tab after the workflow runs

### SARIF Output

The SARIF format includes:

- Rule definitions with severity mapping
- Precise file locations with line numbers
- Security severity scores (0-10 scale)
- Fingerprints for tracking findings across runs
- Tags for categorization (reentrancy, access-control, etc.)

```bash
# Generate SARIF locally
solidity-audit-cli audit contracts/Token.sol --format sarif --output audit.sarif

# View the structure
cat audit.sarif | jq '.runs[0].results | length'
```

## CI/CD Integration

### GitHub Actions

Use the provided reusable action for comprehensive PR auditing:

```yaml
# .github/workflows/audit.yml
name: Smart Contract Audit

on:
  pull_request:
    paths: ["contracts/**", "src/**/*.sol"]

permissions:
  contents: read
  pull-requests: write
  security-events: write

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: "20"

      - name: Install tools
        run: |
          pip install slither-analyzer
          curl -L https://foundry.paradigm.xyz | bash
          ~/.foundry/bin/foundryup

      - name: Run Audit
        uses: ./.github/actions/audit
        with:
          contracts-path: contracts/
          severity-threshold: high
          include-gas: "true"
          diff-only: "true"
          comment-on-pr: "true"
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### Action Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `contracts-path` | `contracts/` | Path to contracts directory |
| `severity-threshold` | `high` | Minimum severity to fail |
| `include-gas` | `true` | Run gas optimization analysis |
| `diff-only` | `true` | Only audit changed files in PRs |
| `comment-on-pr` | `true` | Post results as PR comment |
| `fail-on-findings` | `true` | Fail the action if findings detected |
| `sarif-output` | `true` | Generate SARIF for Code Scanning |

### Action Outputs

| Output | Description |
|--------|-------------|
| `findings-count` | Total number of security findings |
| `critical-count` | Number of critical findings |
| `high-count` | Number of high severity findings |
| `risk-level` | Overall risk: critical, high, medium, low, clean |
| `sarif-file` | Path to generated SARIF file |

### PR Comment Format

The action posts a formatted comment on PRs:

```
## Smart Contract Audit Report

![Risk](https://img.shields.io/badge/Risk-HIGH-orange)

**Risk Level:** HIGH
**Findings:** 0 critical, 2 high, 3 medium
**Gas Optimizations:** 5 suggestions (~500 gas savings)

<details>
<summary>Security Findings (5)</summary>
| Severity | Title | Location | Detector |
|----------|-------|----------|----------|
| HIGH | Reentrancy | Token.sol:45 | slither |
...
</details>

<details>
<summary>Gas Optimizations (5)</summary>
...
</details>
```

## Findings Tracking

The audit server includes a SQLite-based system for tracking findings over time.

### Features

- **Persistence** - Findings are stored locally in `.audit-history/findings.db`
- **Status tracking** - Mark findings as `open`, `acknowledged`, `fixed`, `false_positive`, or `wont_fix`
- **Trend analysis** - Track new vs resolved findings over time
- **Deduplication** - Same finding across runs is tracked as one entry with occurrence count

### Usage

```typescript
import {
  initDb,
  recordAuditRun,
  updateFindingStatus,
  getOpenFindings,
  getFindingTrend,
  getStats,
} from "solidity-audit-mcp/storage";

// Initialize database
initDb("/path/to/project");

// Record an audit run
const summary = recordAuditRun(
  "/path/to/project",
  findings, // Array of Finding objects
  "contracts/Token.sol",
  ["slither", "aderyn"]
);

console.log(`New: ${summary.newFindings}`);
console.log(`Resolved: ${summary.resolvedFindings}`);
console.log(`Total Open: ${summary.totalOpen}`);

// Mark a finding as false positive
updateFindingStatus(
  "/path/to/project",
  "finding-id",
  "false_positive",
  "Not exploitable in our context"
);

// Get open findings
const open = getOpenFindings("/path/to/project");

// Get trend data for last 30 days
const trend = getFindingTrend("/path/to/project", 30);
// { dates: [...], openCounts: [...], newCounts: [...], resolvedCounts: [...] }

// Get statistics
const stats = getStats("/path/to/project");
// { totalFindings, openFindings, fixedFindings, bySeverity, byDetector, ... }
```

### Database Schema

**findings table:**
| Column | Type | Description |
|--------|------|-------------|
| id | TEXT | SHA256 hash of finding attributes |
| contract_path | TEXT | Path to the contract file |
| title | TEXT | Finding title |
| severity | TEXT | critical, high, medium, low, informational |
| status | TEXT | open, acknowledged, fixed, false_positive, wont_fix |
| first_seen | TEXT | ISO timestamp of first detection |
| last_seen | TEXT | ISO timestamp of last detection |
| occurrences | INTEGER | Number of times detected |

**audit_runs table:**
| Column | Type | Description |
|--------|------|-------------|
| id | TEXT | UUID |
| timestamp | TEXT | ISO timestamp |
| total_findings | INTEGER | Total findings in this run |
| new_findings | INTEGER | New findings detected |
| resolved_findings | INTEGER | Findings fixed since last run |
| commit_hash | TEXT | Git commit hash (if available) |

### Git Integration

By default, `.audit-history/` is commented out in `.gitignore`. You can:

1. **Keep it ignored** - Each developer/CI has their own local history
2. **Commit it** - Share findings history across the team (uncomment in `.gitignore`)

## Example Output

```
===============================================================================
  SECURITY ANALYSIS REPORT: VulnerableVault
===============================================================================

  Contract: VulnerableVault
  Path: contracts/VulnerableVault.sol
  Compiler: ^0.8.20
  Analysis time: 12.5s
  Tools: slither (5 findings), aderyn (3 findings)

-------------------------------------------------------------------------------
  SUMMARY
-------------------------------------------------------------------------------

  Total findings: 6
  Critical: 1
  High: 2
  Medium: 2
  Low: 1
  Informational: 0

  CRITICAL ISSUES FOUND - DO NOT DEPLOY

-------------------------------------------------------------------------------
  HIGH-RISK PATTERNS DETECTED
-------------------------------------------------------------------------------
  Line 45: tx.origin - Using tx.origin for authorization is vulnerable to phishing
  Line 78: delegatecall - delegatecall executes code in the context of calling contract
  Line 92: selfdestruct - selfdestruct can destroy the contract

-------------------------------------------------------------------------------
  TOP FINDINGS
-------------------------------------------------------------------------------

  [CRITICAL] Reentrancy Vulnerability
     Location: contracts/VulnerableVault.sol:45
     State change after external call in withdraw() allows reentrancy attack

  [HIGH] Authorization through tx.origin
     Location: contracts/VulnerableVault.sol:32
     tx.origin used for authentication is vulnerable to phishing attacks

  [HIGH] Unprotected SELFDESTRUCT
     Location: contracts/VulnerableVault.sol:92
     selfdestruct can be called by any address matching owner check
```

## Severity Levels

| Level | Icon | Description |
|-------|------|-------------|
| Critical | :red_circle: | Exploitable vulnerabilities that can lead to direct fund loss |
| High | :orange_circle: | Security issues that could lead to significant impact |
| Medium | :yellow_circle: | Issues that could lead to unexpected behavior |
| Low | :large_blue_circle: | Minor issues or deviations from best practices |
| Informational | :white_circle: | Suggestions and code quality improvements |

## Limitations

### This is NOT a replacement for formal audits

- Automated tools can miss complex vulnerabilities
- Business logic issues require human review
- Always engage professional auditors for mainnet deployments

### Tool dependency

- Full analysis requires Slither and/or Aderyn to be installed
- Without these tools, only basic pattern matching is available
- Test execution requires Foundry (forge)

### Parser limitations

- Uses @nomicfoundation/slang for AST-based parsing with regex fallbacks
- First contract in file is parsed when multiple contracts exist
- Some edge cases in complex inheritance may not be fully detected

### False positives

- Pattern matching can flag legitimate code patterns
- Always review findings in context
- Use the confidence level to prioritize review
- Some detectors are intentionally aggressive

## Development

```bash
# Run in development mode (with hot reload)
npm run dev

# Run CLI in development
npm run cli -- analyze ./contracts/MyContract.sol

# Type check
npm run typecheck

# Run tests (vitest)
npm test

# Run single test file
npx vitest run __tests__/analyzers/slither.test.ts

# Run tests matching a pattern
npx vitest run -t "deduplication"

# Run tests in watch mode
npm run test:watch

# Run tests with coverage
npm run test:coverage

# Lint the code
npm run lint

# Format code
npm run format

# Run all checks (typecheck + lint + test)
npm run check

# Clean build artifacts
npm run clean
```

## Project Structure

```
solidity-audit-mcp/
├── src/
│   ├── index.ts              # MCP server entry point (stdio) - ~40 lines
│   ├── server.ts             # HTTP/SSE server entry point - ~280 lines
│   ├── cli.ts                # CLI entry point (solidity-audit-cli)
│   │
│   ├── server/               # Server module (modular architecture)
│   │   ├── index.ts          # Public API exports
│   │   ├── config.ts         # Server configuration
│   │   ├── McpServer.ts      # MCP server factory
│   │   ├── schemas/          # Zod validation schemas
│   │   ├── tools/            # MCP tool definitions
│   │   ├── handlers/         # Tool & HTTP handlers
│   │   ├── health/           # Health check logic
│   │   └── middleware/       # Auth & CORS
│   │
│   ├── analyzers/            # Analyzer adapters (Adapter pattern)
│   │   ├── IAnalyzer.ts      # Interface + BaseAnalyzer
│   │   ├── AnalyzerRegistry.ts   # Factory + Registry
│   │   ├── AnalyzerOrchestrator.ts # Parallel execution
│   │   └── adapters/         # Self-contained adapters (each owns its full implementation)
│   │       ├── SlitherAdapter.ts  # Slither runner + detector map
│   │       ├── AderynAdapter.ts   # Aderyn runner + deduplication
│   │       ├── SlangAdapter.ts    # AST parsing with @nomicfoundation/slang
│   │       ├── GasAdapter.ts      # Gas optimization patterns
│   │       ├── EchidnaAdapter.ts  # Property fuzzer (opt-in)
│   │       └── HalmosAdapter.ts   # Symbolic execution (opt-in)
│   │
│   ├── tools/                # MCP tool implementations
│   │   ├── analyzeContract.ts
│   │   ├── getContractInfo.ts
│   │   ├── checkVulnerabilities.ts
│   │   ├── runTests.ts
│   │   ├── generateReport.ts
│   │   ├── optimizeGas.ts
│   │   ├── diffAudit.ts
│   │   └── auditProject.ts
│   │
│   ├── templates/            # Markdown report templates
│   │   ├── index.ts          # Template utilities
│   │   ├── reportTemplate.md
│   │   ├── findingTemplate.md
│   │   ├── prSummaryTemplate.md
│   │   ├── prLineCommentTemplate.md
│   │   └── diffAuditTemplate.md
│   │
│   ├── detectors/            # Custom detector system
│   │   ├── customDetectorEngine.ts
│   │   └── presets/          # Detector presets (web3, defi)
│   │
│   ├── ci/                   # CI/CD integration
│   │   ├── index.ts
│   │   └── githubComment.ts  # PR comment generator
│   │
│   ├── storage/              # Persistence layer
│   │   ├── index.ts
│   │   └── findingsDb.ts     # SQLite findings tracker
│   │
│   ├── types/                # TypeScript type definitions
│   │   ├── index.ts
│   │   ├── analyzer.ts       # Analyzer types
│   │   ├── result.ts         # Rust-style Result<T, E> type
│   │   └── tools.ts          # Tool registry pattern
│   │
│   └── utils/                # Utility functions
│       ├── executor.ts       # Command execution
│       ├── logger.ts         # Structured logging
│       ├── severity.ts       # Severity utilities
│       └── sarif.ts          # SARIF report generator
│
├── __tests__/                # Test files (486 tests)
│   ├── analyzers/            # Adapter & orchestrator tests
│   ├── tools/                # Tool integration tests
│   ├── ci/                   # GitHub comment tests
│   ├── detectors/            # Custom detector tests
│   ├── utils/                # Utility tests
│   └── fixtures/             # Test Solidity contracts
│
├── docs/
│   └── ARCHITECTURE.md       # Architecture guide with diagrams
│
├── .github/
│   ├── actions/audit/        # Reusable GitHub Action
│   └── workflows/            # Example workflows
│
├── docker/
│   ├── Dockerfile.saas            # SaaS Docker (HTTP/SSE) — all tools included
│   ├── Dockerfile.dev             # Development Docker (hot-reload)
│   ├── docker-compose.yml         # Local container orchestration
│   └── docker-compose.saas.yml    # SaaS deployment orchestration
├── .env.example            # Environment variables template
├── package.json
├── tsconfig.json
├── vitest.config.ts        # Test configuration
├── CLAUDE.md               # Claude Code instructions
└── README.md
```

## Contributing

### Adding new SWC detectors

Edit `src/tools/checkVulnerabilities.ts` and add to the `SWC_PATTERNS` array:

```typescript
{
  id: "SWC-XXX",
  title: "Your Detector Title",
  description: "What this vulnerability is about",
  severity: Severity.HIGH,
  patterns: [/your-regex-pattern/g],
  negativePatterns: [/pattern-that-indicates-safe-code/g], // optional
  remediation: "How to fix this issue",
  references: ["https://swcregistry.io/docs/SWC-XXX"],
}
```

### Adding Slither detector mappings

Edit `src/analyzers/adapters/SlitherAdapter.ts` and add to `SLITHER_DETECTOR_MAP`:

```typescript
"detector-name": {
  title: "Human-readable title",
  description: "What this detector finds",
}
```

### Adding code pattern detection

Edit `src/analyzers/adapters/SlangAdapter.ts`:

**For AST-based detection (preferred):** Add to `SECURITY_DETECTORS` and `QUERY_STRINGS`:

```typescript
// In SECURITY_DETECTORS array
{
  id: "SLANG-XXX",
  title: "Your Detector Title",
  description: "What this vulnerability is about",
  severity: Severity.HIGH,
  recommendation: "How to fix this issue",
}

// In QUERY_STRINGS object
"SLANG-XXX": `
  @match [YourASTPattern]
`
```

**For regex-based detection:** Add to `patternDefs` in the `detectPatterns()` function:

```typescript
{
  name: "pattern-name",
  regex: /your-regex/,
  risk: "high" | "medium" | "low" | "info",
  description: "Why this pattern is risky",
}
```

### Running the test suite

```bash
# Run all tests
npm test

# Run specific test file
npm test -- __tests__/analyzers/slither.test.ts

# Run tests matching a pattern
npm test -- -t "deduplication"
```

## License

MIT

## Acknowledgments

- [Slither](https://github.com/crytic/slither) by Trail of Bits
- [Aderyn](https://github.com/Cyfrin/aderyn) by Cyfrin
- [Slang](https://github.com/NomicFoundation/slang) by Nomic Foundation
- [SWC Registry](https://swcregistry.io/) by SmartContractSecurity
- [Foundry](https://github.com/foundry-rs/foundry) by Paradigm
