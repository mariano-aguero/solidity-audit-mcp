---

<table>
<tr>
<td width="4%" align="center">

{{severityEmoji}}

</td>
<td width="96%">

**{{#if index}}#{{index}} — {{/if}}{{title}}**

<sup>{{severity}} · {{confidence}} confidence · `{{detector}}`{{#if swcId}} · [SWC-{{swcId}}](https://swcregistry.io/docs/{{swcId}}){{/if}}</sup>

</td>
</tr>
</table>

<details {{#if isHighPriority}}open{{/if}}>
<summary><strong>Details</strong></summary>

| Property | Value |
|:---------|:------|
| **Finding ID** | `{{id}}` |
| **Severity** | {{severityEmoji}} {{severity}} |
| **Confidence** | {{confidenceEmoji}} {{confidence}} |
| **Detector** | `{{detector}}` |
{{#if swcId}}| **SWC ID** | [SWC-{{swcId}}](https://swcregistry.io/docs/{{swcId}}) |{{/if}}
{{#if gasImpact}}| **Gas Impact** | ~{{gasImpact}} gas |{{/if}}

</details>

**Description**

{{description}}

**Location**

> `{{location.file}}{{#if location.lines}}:{{location.lines.[0]}}{{#if location.lines.[1]}}-{{location.lines.[1]}}{{/if}}{{/if}}`
{{#if location.function}}
>
> Function: `{{location.function}}()`
{{/if}}

{{#if codeSnippet}}
```solidity
{{codeSnippet}}
```
{{/if}}

{{#if recommendation}}
> [!TIP]
> **Recommendation**
>
> {{recommendation}}
{{/if}}

{{#if suggestedFix}}
<details>
<summary><strong>Suggested Fix</strong></summary>

```solidity
{{suggestedFix}}
```

</details>
{{/if}}

{{#if references}}
<details>
<summary><strong>References</strong></summary>

{{#each references}}
- {{this}}
{{/each}}

</details>
{{/if}}

