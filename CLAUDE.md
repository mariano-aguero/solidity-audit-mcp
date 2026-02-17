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
- `src/index.ts` - Thin wrapper (~40 lines) for stdio transport
- `src/server.ts` - Thin wrapper (~280 lines) for HTTP/SSE transport
- `src/cli.ts` - CLI entry point using native `node:util` parseArgs

### Server Module (`src/server/`)
The server logic is modularized into reusable components:

```
src/server/
├── index.ts              # Public exports
├── config.ts             # Server configuration (name, version, env vars)
├── McpServer.ts          # MCP server factory
├── schemas/
│   └── inputSchemas.ts   # Zod validation schemas (shared)
├── tools/
│   └── toolDefinitions.ts # MCP tool definitions (shared)
├── handlers/
│   ├── toolHandlers.ts   # Tool execution logic
│   └── httpHandlers.ts   # REST API handlers
├── health/
│   └── healthCheck.ts    # Health check with analyzer status
└── middleware/
    ├── auth.ts           # API key authentication
    └── cors.ts           # CORS configuration
```

### Core Analysis Pipeline
The main analysis in `src/tools/analyzeContract.ts`:
1. Validates contract path and auto-detects project root
2. Uses `AnalyzerOrchestrator` to run analyzers in parallel
3. Deduplicates findings across tools
4. Sorts by severity and formats output

### Analyzer Architecture (`src/analyzers/`)
Uses Adapter pattern for unified analyzer interface:

```
src/analyzers/
├── IAnalyzer.ts          # Interface + BaseAnalyzer abstract class
├── AnalyzerRegistry.ts   # Factory + Registry (singleton)
├── AnalyzerOrchestrator.ts # Parallel execution coordinator
├── types.ts              # Analyzer type definitions
└── adapters/
    ├── SlitherAdapter.ts
    ├── AderynAdapter.ts
    ├── SlangAdapter.ts
    └── GasAdapter.ts
```

### MCP Tools (8 total)
- `analyze_contract` - Full security analysis pipeline
- `get_contract_info` - Contract metadata and attack surface
- `check_vulnerabilities` - SWC Registry pattern scanning
- `run_tests` - Forge test execution with coverage
- `generate_report` - Format findings into audit reports
- `optimize_gas` - Gas optimization analysis
- `diff_audit` - Compare two contract versions
- `audit_project` - Scan entire project directory

### Templates (`src/templates/`)
Markdown templates for reports and PR comments:
- `reportTemplate.md` - Full audit report
- `findingTemplate.md` - Individual finding
- `prSummaryTemplate.md` - PR summary comment
- `prLineCommentTemplate.md` - Inline code comments
- `diffAuditTemplate.md` - Diff audit report
- `index.ts` - Template loading utilities

### Utilities
- `src/utils/logger.ts` - Structured JSON logging to stderr
- `src/utils/executor.ts` - Command execution with timeout
- `src/utils/severity.ts` - Centralized severity utilities
- `src/types/result.ts` - Rust-style `Result<T, E>` for error handling
- `src/types/analyzer.ts` - Analyzer type definitions

### External Tool Dependencies
The server gracefully degrades when tools are missing:
- **Slither** (Python) - 90+ vulnerability detectors
- **Aderyn** (Rust) - Fast static analysis
- **Foundry/forge** - Test execution and coverage
- **solc-select** (Python) - Solidity version management

## Testing

Tests use Vitest with fixtures in `__tests__/fixtures/` containing intentionally vulnerable contracts.

Test structure mirrors src/:
```
__tests__/
├── analyzers/        # Parser, adapter, and orchestrator tests
├── tools/            # Tool integration tests
├── detectors/        # Custom detector tests
├── ci/               # GitHub comment generation tests
├── utils/            # Utility function tests
└── fixtures/         # Test Solidity contracts
```

## Adding New Analyzers

1. Create adapter in `src/analyzers/adapters/YourAdapter.ts` implementing `IAnalyzer`
2. Register in `src/analyzers/adapters/index.ts`
3. Add to `AnalyzerRegistry` initialization
4. Add tests in `__tests__/analyzers/adapters.test.ts`

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
