# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
