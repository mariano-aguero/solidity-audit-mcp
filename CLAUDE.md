# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Solidity Audit MCP is a Model Context Protocol (MCP) server for automated security audits of Solidity smart contracts. It integrates with Slither, Aderyn, Foundry, and uses @nomicfoundation/slang for AST-based analysis.

## Commands

```bash
# Development
npm run dev              # Run MCP server (stdio) with hot-reload
npm run server:dev       # Run HTTP/SSE server with hot-reload
npm run cli              # Run CLI directly

# Build
npm run build            # TypeScript compile + make executables
npm run typecheck        # Type check without emitting

# Testing
npm test                 # Run all tests (vitest)
npm run test:watch       # Watch mode
npm run test:coverage    # With coverage report
npx vitest run __tests__/analyzers/slither.test.ts  # Single test file
npx vitest run -t "deduplication"                   # Tests matching pattern

# Quality
npm run lint             # ESLint
npm run lint:fix         # ESLint with auto-fix
npm run format           # Prettier format
npm run check            # typecheck + lint + test

# Docker (local)
npm run docker:build     # Build local image
npm run docker:run       # Run MCP server (stdio)
npm run docker:shell     # Interactive shell with tools

# Docker SaaS (HTTP/SSE)
npm run saas:build       # Build SaaS image
npm run saas:up          # Start HTTP server (uses .env)
npm run saas:down        # Stop server
npm run saas:logs        # View logs
```

## Architecture

### Entry Points
- `src/index.ts` - MCP server (stdio transport) for local use with Claude Desktop
- `src/server.ts` - HTTP/SSE server for remote/SaaS deployment
- `src/cli.ts` - CLI entry point using native `node:util` parseArgs

### Core Analysis Pipeline
The main analysis in `src/tools/analyzeContract.ts`:
1. Validates contract path and auto-detects project root
2. Runs analyzers in parallel: Slither, Aderyn, Slang AST, Gas optimizer, Custom detectors
3. Deduplicates findings across tools (`src/analyzers/aderyn.ts:deduplicateFindings`)
4. Sorts by severity and formats output

### MCP Tools (8 total)
- `analyze_contract` - Full security analysis pipeline
- `get_contract_info` - Contract metadata and attack surface
- `check_vulnerabilities` - SWC Registry pattern scanning
- `run_tests` - Forge test execution with coverage
- `generate_report` - Format findings into audit reports
- `optimize_gas` - Gas optimization analysis
- `diff_audit` - Compare two contract versions
- `audit_project` - Scan entire project directory

### Key Modules
- `src/analyzers/slangAnalyzer.ts` - AST-based analysis using @nomicfoundation/slang, also handles contract parsing
- `src/analyzers/slither.ts` / `aderyn.ts` - External tool wrappers with output parsing
- `src/detectors/customDetectorEngine.ts` - User-defined detector patterns from `.audit-detectors.yml`
- `src/storage/findingsDb.ts` - SQLite-based findings persistence (better-sqlite3)
- `src/ci/githubComment.ts` - PR comment and SARIF report generation

### Utilities
- `src/utils/logger.ts` - Structured JSON logging to stderr (stdout reserved for MCP protocol)
- `src/utils/executor.ts` - Command execution with timeout and project root detection
- `src/types/result.ts` - Rust-style `Result<T, E>` for error handling
- `src/types/tools.ts` - Tool registry pattern with Zod validation

### External Tool Dependencies
The server gracefully degrades when tools are missing:
- **Slither** (Python) - 90+ vulnerability detectors
- **Aderyn** (Rust) - Fast static analysis
- **Foundry/forge** - Test execution and coverage
- **solc-select** (Python) - Solidity version management (required by Slither)

## Testing

Tests use Vitest with fixtures in `__tests__/fixtures/` containing intentionally vulnerable contracts.

Test structure mirrors src/:
```
__tests__/
├── analyzers/   # Parser and analyzer tests
├── tools/       # Tool integration tests
├── detectors/   # Custom detector tests
├── ci/          # GitHub comment generation tests
└── fixtures/    # Test Solidity contracts
```

## Adding New Detectors

- **Slang AST detectors**: `src/analyzers/slangAnalyzer.ts` - add to `SECURITY_DETECTORS` and `QUERY_STRINGS`
- **SWC patterns**: `src/tools/checkVulnerabilities.ts` - add to `SWC_PATTERNS` array
- **Slither mappings**: `src/analyzers/slither.ts` - add to `SLITHER_DETECTOR_MAP`
- **Pattern detection**: `src/analyzers/slangAnalyzer.ts:detectPatterns()` - add regex patterns

## Docker

Two Docker configurations available:

- `Dockerfile` - Local use with stdio transport
- `Dockerfile.saas` - HTTP/SSE server with health checks at `/health` (full analyzer status) and `/health/quick`

Configuration via `.env` file (copy from `.env.example`). Key variables:
- `MCP_API_KEY` - Authentication for SSE endpoints
- `PORT` - Server port (default: 3000)
- `MCP_AUDIT_LOG_LEVEL` - Log level (debug, info, warn, error)
