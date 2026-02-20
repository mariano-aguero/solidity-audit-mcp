# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.4.0] - 2026-02-20

### Added
- **Echidna in Docker** — both `Dockerfile.dev` and `Dockerfile.saas` now install the Echidna property fuzzer binary at build time (x86_64 only; ARM64 skipped gracefully since no official pre-built binary exists)
- **Halmos in Docker** — both Dockerfiles now install Halmos via `pip install halmos` alongside Slither (works on x86_64 and ARM64)
- **`libgmp-dev` system dependency** — added to both Dockerfiles; required by the Echidna binary (Haskell runtime)

### Changed
- Bumped version from `1.3.0` to `1.4.0`

---

## [1.3.0] - 2026-02-20

### Added
- **Tests for `generate_invariants`** — 19 tests covering auto-detection for ERC-20/lending protocols, explicit protocol types, stateful invariant inclusion, and error handling
- **Tests for `explain_finding`** — 34 tests covering all 5 knowledge-base entries (SWC-107, SWC-115, CUSTOM-018, CUSTOM-004, CUSTOM-032), keyword matching, unknown IDs, and optional fields
- **README documentation** for `generate_invariants` and `explain_finding` tools (previously undocumented)
- **`analyzers` parameter** documented in `analyze_contract` README section (includes echidna/halmos)

### Changed
- Updated `AnalyzerRegistry` test to reflect 6 built-in analyzers (was hardcoded to 4 before Echidna/Halmos were added)
- Bumped patch dependencies: `@nomicfoundation/slang` 1.3.2→1.3.3, `@types/node` 22.19.10→22.19.11, `@typescript-eslint/*` 8.55.0→8.56.0
- Fixed version reference in README (`v1.0.0` → `v1.2.0`)
- Bumped version from `1.2.0` to `1.3.0`

---

## [1.2.0] - 2026-02-19

### Added
- **13 new security detectors** (`CUSTOM-022` through `CUSTOM-034`):
  - **Uniswap V4 hooks** (`CUSTOM-022` to `CUSTOM-025`) — token drain via delta manipulation, `unlock()` reentrancy, permission misconfiguration, pool initialization front-running
  - **Restaking / LRT** (`CUSTOM-026` to `CUSTOM-028`) — slashing propagation without accounting, withdrawal queue race conditions, operator concentration risk
  - **Points & Airdrop** (`CUSTOM-029` to `CUSTOM-031`) — Merkle double-claim, vesting bypass via transfer, Sybil-vulnerable accumulation
  - **ERC-4337 Account Abstraction** (`CUSTOM-032` to `CUSTOM-034`) — paymaster drain, session key scope bypass, bundler griefing via gas manipulation
- **`generate_invariants` MCP tool** — auto-detects protocol type (ERC-20, ERC-4626, lending, AMM, governance, staking) and generates ready-to-use Foundry `invariant_*()` test templates with severity classification
- **`explain_finding` MCP tool** — knowledge base with root cause, impact, exploit scenario, vulnerable/secure code comparison, Foundry PoC template, and remediation for SWC and custom finding IDs; supports free-text keyword search (e.g. "reentrancy", "flash loan", "paymaster")
- **`EchidnaAdapter`** — Echidna property fuzzer integration (Trail of Bits); auto-writes YAML config, parses JSON/text output, returns `Finding[]` for violated `echidna_` prefixed properties
- **`HalmosAdapter`** — Halmos symbolic execution engine integration (a16z); runs `check_*` functions, extracts counterexamples, returns `Finding[]` for violated symbolic properties
- **`"echidna"` and `"halmos"` analyzer IDs** — registered in `AnalyzerRegistry`, selectable via `analyze_contract`'s `analyzers` parameter

### Changed
- Extended `DetectorSource` type to include `"echidna"` and `"halmos"` values
- Extended `AnalyzerId` union to include `"echidna"` and `"halmos"`
- `analyze_contract` tool `analyzers` enum now includes `"echidna"` and `"halmos"` options
- Bumped version from `1.1.0` to `1.2.0`

---

## [1.1.0] - 2026-02-19

### Added
- **ERC-7702 detectors** (`CUSTOM-018`, `CUSTOM-019`) — malicious delegation, unprotected `initialize()` after `setCode`, and cross-chain signature replay via `chainId=0`
- **Transient storage detectors** (`CUSTOM-020`, `CUSTOM-021`) — reentrancy guard bypass via delegatecall clearing `tstore` slots, and cross-function transient state leaks
- **CHANGELOG.md** — formal changelog following Keep a Changelog format
- **Coverage thresholds** — enforced 60% minimum coverage in vitest config (lines, functions, branches, statements)
- **Multi-contract file support** in `getContractInfo` — now detects and reports all contracts defined in a single `.sol` file

### Changed
- Bumped version from `1.0.0` to `1.1.0`

---

## [1.0.0] - 2026-02

### Added

#### MCP Tools (8 total)
- `analyze_contract` — full security analysis pipeline (Slither + Aderyn + Slang AST + gas analysis)
- `get_contract_info` — extract metadata: functions, state variables, inheritance, modifiers, attack surface
- `check_vulnerabilities` — SWC Registry pattern scanning (SWC-100 through SWC-136 + 17 custom detectors)
- `run_tests` — execute Foundry forge tests with coverage reports
- `generate_report` — format findings into markdown/JSON audit reports
- `optimize_gas` — detect gas optimization opportunities with savings estimates
- `diff_audit` — compare two contract versions and audit only changes
- `audit_project` — scan entire project, prioritize by risk, generate consolidated report

#### Deployment Modes
- **stdio transport** — local Claude Desktop / Claude Code integration
- **HTTP/SSE transport** — remote SaaS deployment with API key auth, health checks, REST API
- **CLI** — `solidity-audit-cli` for CI/CD pipelines with `audit`, `diff`, `gas` commands

#### Analyzer Architecture
- `SlitherAdapter` — wraps Slither CLI with SARIF output support
- `AderynAdapter` — wraps Aderyn CLI for complementary static analysis
- `SlangAdapter` — `@nomicfoundation/slang` AST-based precise detection
- `GasAdapter` — gas optimization pattern detection
- `AnalyzerOrchestrator` — parallel execution with finding deduplication
- `AnalyzerRegistry` — factory pattern for analyzer management

#### Security Detection
- 30+ SWC Registry patterns (SWC-100 through SWC-136)
- 17 custom detectors (CUSTOM-001 through CUSTOM-017):
  - Array length mismatch
  - Proxy storage collision / missing gap
  - Reentrancy risk (CEI violation)
  - Stale/manipulable price oracle
  - Missing zero address validation
  - Missing events for critical state changes
  - Price calculation before validation
  - Liquidation without slippage protection
  - Double approval in multisig
  - Missing execution guard in multisig
  - Signature without replay protection
  - ECDSA signature malleability
  - Hash collision with encodePacked
  - Flash loan/mint without repayment check
  - Division before multiplication (precision loss)
  - Permit without deadline
  - Missing access control on critical function

#### CI/CD Integration
- GitHub Actions workflow for PR audits with inline annotations
- On-demand audit via GitHub Issues
- GitHub Code Scanning (SARIF) integration
- Exit codes: 0 (clean), 1 (findings), 2 (error)

#### Infrastructure
- SQLite persistence for findings history and trend analysis
- Custom detector engine with DeFi and Web3 presets
- Docker support: dev image and production SaaS image
- `fly.toml`, `railway.json`, `render.yaml` for cloud deployment
- Structured JSON logging
- SARIF report generation
- Full TypeScript with strict mode

#### Output Formats
- Markdown audit reports
- JSON structured data
- SARIF (GitHub Code Scanning)
- PR summary comments
- Inline PR line comments

[1.1.0]: https://github.com/mariano-aguero/mcp-audit-server/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/mariano-aguero/mcp-audit-server/releases/tag/v1.0.0
