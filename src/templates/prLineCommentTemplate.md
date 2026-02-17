{{severityEmoji}} **{{severity}}** — {{title}}

---

{{description}}

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

{{#if swcId}}

---

:link: [SWC-{{swcId}}](https://swcregistry.io/docs/{{swcId}}) | :robot: `{{detector}}` | {{confidenceEmoji}} {{confidence}}
{{else}}

---

:robot: `{{detector}}` | {{confidenceEmoji}} {{confidence}}
{{/if}}
