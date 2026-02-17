<div align="center">

# Security Audit Report

<img src="https://img.shields.io/badge/Status-{{auditStatus}}-{{statusColor}}?style=for-the-badge" alt="Audit Status" />
<img src="https://img.shields.io/badge/Risk_Level-{{riskLevel}}-{{riskColor}}?style=for-the-badge" alt="Risk Level" />
<img src="https://img.shields.io/badge/Findings-{{totalFindings}}-blue?style=for-the-badge" alt="Total Findings" />

---

**`{{contractName}}`**

*Automated Security Analysis Report*

{{timestamp}}

</div>

---

## Overview

<table>
<tr>
<td width="50%">

### Contract Details

| Property | Value |
|:---------|:------|
| **Contract** | `{{contractName}}` |
| **Path** | `{{contractPath}}` |
| **Compiler** | `{{compiler}}` |
| **Analysis Date** | {{timestamp}} |

</td>
<td width="50%">

### Analysis Tools

| Tool | Status |
|:-----|:------:|
{{#each toolDetails}}
| {{name}} | {{#if available}}:white_check_mark:{{else}}:x:{{/if}} `{{version}}` |
{{/each}}

</td>
</tr>
</table>

---

## Executive Summary

### Risk Distribution

```
{{riskChart}}
```

<table>
<tr>
<td align="center" width="20%">
<h3>:rotating_light:</h3>
<h2>{{criticalCount}}</h2>
<sub>Critical</sub>
</td>
<td align="center" width="20%">
<h3>:red_circle:</h3>
<h2>{{highCount}}</h2>
<sub>High</sub>
</td>
<td align="center" width="20%">
<h3>:orange_circle:</h3>
<h2>{{mediumCount}}</h2>
<sub>Medium</sub>
</td>
<td align="center" width="20%">
<h3>:yellow_circle:</h3>
<h2>{{lowCount}}</h2>
<sub>Low</sub>
</td>
<td align="center" width="20%">
<h3>:blue_circle:</h3>
<h2>{{informationalCount}}</h2>
<sub>Info</sub>
</td>
</tr>
</table>

{{#if criticalCount}}
> [!CAUTION]
> **{{criticalCount}} Critical Issue(s) Found** — Deployment is NOT recommended until these are resolved.
{{/if}}

{{#if highCount}}
> [!WARNING]
> **{{highCount}} High Severity Issue(s)** require immediate attention before deployment.
{{/if}}

{{#if testCoverage}}
> [!NOTE]
> **Test Coverage:** {{testCoverage}}% {{#if testCoverageLow}}— Below recommended 80% threshold{{/if}}
{{/if}}

---

## Contract Architecture

{{#if contractInfo}}

<details open>
<summary><h3>Contract Metrics</h3></summary>

<table>
<tr>
<td align="center" width="25%">
<h3>{{contractInfo.functions.length}}</h3>
<sub>Functions</sub>
</td>
<td align="center" width="25%">
<h3>{{contractInfo.stateVariables.length}}</h3>
<sub>State Variables</sub>
</td>
<td align="center" width="25%">
<h3>{{contractInfo.inherits.length}}</h3>
<sub>Inherited Contracts</sub>
</td>
<td align="center" width="25%">
<h3>{{contractInfo.interfaces.length}}</h3>
<sub>Interfaces</sub>
</td>
</tr>
</table>

</details>

<details>
<summary><h3>Contract Characteristics</h3></summary>

| Feature | Status | Risk Indicator |
|:--------|:------:|:---------------|
| Has Constructor | {{#if contractInfo.hasConstructor}}:white_check_mark: Yes{{else}}:large_blue_circle: No{{/if}} | — |
| Uses Proxy Pattern | {{#if contractInfo.usesProxy}}:warning: Yes{{else}}:white_check_mark: No{{/if}} | {{#if contractInfo.usesProxy}}Requires upgrade security review{{/if}} |
| Is Abstract | {{#if contractInfo.isAbstract}}:large_blue_circle: Yes{{else}}:white_check_mark: No{{/if}} | — |
| Is Library | {{#if contractInfo.isLibrary}}:large_blue_circle: Yes{{else}}:white_check_mark: No{{/if}} | — |
| Uses Assembly | {{#if contractInfo.usesAssembly}}:warning: Yes{{else}}:white_check_mark: No{{/if}} | {{#if contractInfo.usesAssembly}}Manual review required{{/if}} |
| External Calls | {{#if contractInfo.hasExternalCalls}}:warning: Yes{{else}}:white_check_mark: No{{/if}} | {{#if contractInfo.hasExternalCalls}}Reentrancy check required{{/if}} |

</details>

{{#if contractInfo.inherits.length}}
<details>
<summary><h3>Inheritance Hierarchy</h3></summary>

```mermaid
graph BT
    {{contractName}}
{{#each contractInfo.inherits}}
    {{this}} --> {{../contractName}}
{{/each}}
```

</details>
{{/if}}

{{/if}}

---

## Detailed Findings

{{#each findingsByCategory}}

<details {{#if isCriticalOrHigh}}open{{/if}}>
<summary>
<h3>{{emoji}} {{category}} Severity <code>{{count}} finding{{#if plural}}s{{/if}}</code></h3>
</summary>

{{#each findings}}
{{> findingTemplate}}
{{/each}}

</details>

{{/each}}

{{#unless hasFindings}}
> [!TIP]
> **No security issues detected** — The automated analysis did not find any vulnerabilities. Consider a manual review for comprehensive coverage.
{{/unless}}

---

{{#if gasOptimizations}}
## Gas Optimizations

<details open>
<summary><strong>:zap: Potential Savings: ~{{totalGasSavings}} gas per transaction</strong></summary>

| # | Optimization | Est. Savings | Location | Impact |
|:-:|:-------------|-------------:|:---------|:------:|
{{#each gasOptimizations}}
| {{index}} | {{title}} | ~{{estimatedSavings}} gas | `{{location.file}}:{{location.lines.[0]}}` | {{impact}} |
{{/each}}

</details>

---
{{/if}}

## Priority Actions

> [!IMPORTANT]
> Address findings in order of priority to minimize security risk.

| Priority | Action Items | Rationale |
|:--------:|:-------------|:----------|
{{#if criticalCount}}| :rotating_light: **P0** | Fix all {{criticalCount}} Critical issues | Direct fund loss or contract takeover risk |{{/if}}
{{#if highCount}}| :red_circle: **P1** | Address {{highCount}} High severity issues | Significant security impact |{{/if}}
{{#if mediumCount}}| :orange_circle: **P2** | Review {{mediumCount}} Medium severity issues | Potential vulnerabilities requiring attention |{{/if}}
{{#if lowCount}}| :yellow_circle: **P3** | Consider {{lowCount}} Low severity items | Best practices and minor optimizations |{{/if}}

---

## Recommendations

<details>
<summary><h3>General Security Practices</h3></summary>

- [ ] **Testing** — Achieve >80% test coverage with fuzz testing for critical functions
- [ ] **Documentation** — Add NatSpec comments for all public and external functions
- [ ] **Access Control** — Review and document all privileged operations
- [ ] **Upgrades** — If using proxy patterns, implement secure upgrade procedures
- [ ] **Monitoring** — Set up on-chain monitoring for critical state changes
- [ ] **Circuit Breakers** — Implement pause functionality for emergency situations

</details>

---

## Methodology

<details>
<summary><h3>Analysis Approach</h3></summary>

| Category | Description |
|:---------|:------------|
| **Static Analysis** | Pattern matching and control flow analysis |
| **AST Analysis** | Syntax tree inspection for code patterns |
| **SWC Compliance** | Cross-reference with [SWC Registry](https://swcregistry.io/) |
| **Gas Optimization** | Bytecode-level efficiency patterns |
| **Best Practices** | Industry standard security patterns |

</details>

<details>
<summary><h3>Severity Definitions</h3></summary>

| Level | Description | Examples |
|:------|:------------|:---------|
| :rotating_light: **Critical** | Direct fund loss, contract takeover, or irreversible damage | Reentrancy, access control bypass, overflow |
| :red_circle: **High** | Significant security impact or potential fund loss | Incorrect state management, privilege escalation |
| :orange_circle: **Medium** | Moderate risk requiring attention | DoS vectors, front-running opportunities |
| :yellow_circle: **Low** | Minor issues or best practice violations | Gas inefficiencies, code clarity |
| :blue_circle: **Informational** | Suggestions and optimizations | Documentation, code style |

</details>

---

## Disclaimer

> [!NOTE]
> This automated audit report does not constitute a guarantee of security. The analysis represents a point-in-time assessment based on static analysis tools. For production deployments handling significant value, **a manual expert review is strongly recommended**.

---

<div align="center">

<sub>

Generated by **[MCP Audit Server](https://github.com/mcp-audit-server)** on {{timestamp}}

:shield: Automated Smart Contract Security Analysis

</sub>

</div>
