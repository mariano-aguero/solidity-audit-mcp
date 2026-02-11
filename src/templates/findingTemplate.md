#### {{index}}. {{title}}

| Property | Value |
|----------|-------|
| **ID** | `{{id}}` |
| **Severity** | {{severityEmoji}} {{severity}} |
| **Confidence** | {{confidence}} |
| **Detector** | {{detector}} |
{{#if swcId}}
| **SWC** | [{{swcId}}](https://swcregistry.io/docs/{{swcId}}) |
{{/if}}

**Description:**

{{description}}

**Location:**

- File: `{{location.file}}`
{{#if location.lines}}
- Lines: {{location.lines.[0]}}-{{location.lines.[1]}}
{{/if}}
{{#if location.function}}
- Function: `{{location.function}}`
{{/if}}

**Recommendation:**

{{recommendation}}

{{#if references}}
**References:**

{{#each references}}
- {{this}}
{{/each}}
{{/if}}

---
