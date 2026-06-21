# @logicgridai/saferelay-sdk

Zero-trust DLP primitives and React helpers for paste-time redaction of secrets and regulated identifiers.

[![npm](https://img.shields.io/npm/v/@logicgridai/saferelay-sdk)](https://www.npmjs.com/package/@logicgridai/saferelay-sdk)
[![License](https://img.shields.io/badge/license-PROPRIETARY-red)](https://saferelay.ai)

## Install

```bash
npm install @logicgridai/saferelay-sdk react react-dom
```

## Usage

Wrap your app with `SafePasteProvider`, then use `SafeInput` / `SafeTextArea` or the `useSafePaste()` hook for programmatic sanitization.

```tsx
import { SafePasteProvider, SafeInput, SafeTextArea } from '@logicgridai/saferelay-sdk'

function App() {
  return (
    <SafePasteProvider
      tier="pro"
      licenseKey={process.env.REACT_APP_SAFERELAY_KEY}
    >
      {/* SafeInput and SafeTextArea auto-redact on paste */}
      <SafeInput placeholder="Paste anything safely..." />
      <SafeTextArea placeholder="Logs, configs, API responses..." />
    </SafePasteProvider>
  )
}
```

## Programmatic sanitization

```tsx
import { useSafePaste } from '@logicgridai/saferelay-sdk'

function MyComponent() {
  const { sanitize, vault } = useSafePaste()

  const handleSubmit = (text: string) => {
    const { sanitized, count, matches } = sanitize(text)
    // sanitized: "OPENAI_KEY=sk-proj-abc" → "OPENAI_KEY=[OPENAI_KEY_1]"
    // count: number of redactions
    // matches: array of { type, placeholder, original }
    console.log(`Redacted ${count} sensitive values`)
    sendToAI(sanitized) // safe to send
  }
}
```

## Choosing what to redact

Patterns are organized into groups: `devsec`, `fintech`, `corporate`, and `civic`.
Enable only the groups (or specific types) your app needs via `enabledPatterns`:

```tsx
<SafePasteProvider
  tier="pro"
  licenseKey={process.env.REACT_APP_SAFERELAY_KEY}
  enabledPatterns={['fintech', 'corporate']}  // e.g. a FinTech app
>
```

You can also work directly with the registry:

```ts
import { THREAT_PATTERNS, FREE_PATTERNS, PRO_PATTERNS, PATTERN_TYPES } from '@logicgridai/saferelay-sdk'

const fintechOnly = THREAT_PATTERNS.filter(p => p.group === 'fintech')
console.log(PATTERN_TYPES) // ['IP', 'OPENAI_KEY', 'AWS_KEY', ...]
```

## Named API key labels (v0.4.0+)

Each provider gets its own placeholder type — making redacted output self-documenting:

| Input | Placeholder |
|-------|-------------|
| `sk-proj-abc...` | `[OPENAI_KEY_1]` |
| `sk-ant-abc...` | `[ANTHROPIC_KEY_1]` |
| `AKIA1234ABCD` | `[AWS_KEY_1]` |
| `wJalrX...` (bare secret) | `[AWS_SECRET_1]` |
| `ghp_abc123` | `[GITHUB_PAT_1]` |
| `github_pat_abc` | `[GITHUB_PAT_FG_1]` |
| `xoxb-abc...` | `[SLACK_KEY_1]` |
| `hooks.slack.com/...` | `[SLACK_WEBHOOK_1]` |
| `AIzaXXX...` | `[GEMINI_KEY_1]` |
| `sk_live_abc` | `[STRIPE_KEY_1]` |
| `GOCSPX-abc...` | `[GOOGLE_OAUTH_1]` |
| `dckr_pat_abc...` | `[DOCKER_KEY_1]` |
| `npm_abc...` | `[NPM_TOKEN_1]` |
| `SG.abc.xyz` | `[SENDGRID_KEY_1]` |
| `SKabc...` | `[TWILIO_KEY_1]` |
| `Bearer eyJ...` | `[BEARER_1]` |

## Context-aware Nigerian identifiers

NIN and BVN are both 11-digit numbers and can't be told apart by length alone.
The SDK uses the surrounding label to assign the correct type, and preserves the label:

```text
"BVN: 12345678901"           → "BVN: [NG_BVN_1]"
"NIN: 12345678901"           → "NIN: [NG_NIN_1]"
"National ID 12345678901"    → "National ID [NG_NIN_1]"
```

A bare, unlabeled 11-digit number is still redacted (as `[NG_NIN_1]`) so nothing leaks —
it just receives a generic label when no context is present.

## What gets redacted (53 types)

Free tier covers developer secrets; Pro adds regulated PII and compliance identifiers.

| Pattern | Group | Free | Pro |
|---------|-------|------|-----|
| IPv4 addresses | devsec | ✓ | ✓ |
| OpenAI / Anthropic / Gemini keys | devsec | ✓ | ✓ |
| AWS access keys + secret keys | devsec | ✓ | ✓ |
| GitHub PAT / fine-grained / OAuth | devsec | ✓ | ✓ |
| Slack tokens + webhook URLs | devsec | ✓ | ✓ |
| Google OAuth credentials | devsec | ✓ | ✓ |
| Stripe secret + publishable keys | devsec | ✓ | ✓ |
| Docker / npm / Twilio / SendGrid tokens | devsec | ✓ | ✓ |
| Bearer tokens, generic API keys | devsec | ✓ | ✓ |
| Bitcoin / Ethereum addresses | devsec | ✓ | ✓ |
| Solana addresses, WIF crypto keys | devsec | ✓ | ✓ |
| Seed phrases (12 / 24 word) | devsec | ✓ | ✓ |
| PEM private keys | devsec | ✓ | ✓ |
| .env file values | devsec | ✓ | ✓ |
| MAC addresses | devsec | — | ✓ |
| 64-char hex crypto keys | devsec | — | ✓ |
| Credit cards (Luhn-validated) | fintech | — | ✓ |
| US SSN | fintech | — | ✓ |
| Email addresses | fintech | — | ✓ |
| EU IBAN | fintech | — | ✓ |
| UK NINO | fintech | — | ✓ |
| Nigeria NIN / BVN / Bank / Phone | fintech | — | ✓ |
| Canada SIN | fintech | — | ✓ |
| India Aadhaar / PAN | fintech | — | ✓ |
| South Africa ID | fintech | — | ✓ |
| Australia TFN | fintech | — | ✓ |
| Brazil CPF | fintech | — | ✓ |
| Singapore NRIC | fintech | — | ✓ |
| Germany Tax ID | fintech | — | ✓ |
| US Green Card | fintech | — | ✓ |
| EIN / DUNS / EU VAT | corporate | — | ✓ |
| GPS coordinates | civic | — | ✓ |
| UNHCR registration IDs | civic | — | ✓ |
| Donor / beneficiary case IDs | civic | ✓ | ✓ |
| Custom Protected Terms | — | — | ✓ |

## Core modules

`Vault`, `Tokenizer`, and `THREAT_PATTERNS` are free of browser APIs and run in Node.js or the browser — use them in CI/CD pipelines, serverless functions, or anywhere React isn't available.

```ts
import { THREAT_PATTERNS, FREE_PATTERNS, PRO_PATTERNS, PATTERN_TYPES } from '@logicgridai/saferelay-sdk'

const freeOnly = THREAT_PATTERNS.filter(p => p.freeTier)
console.log(PATTERN_TYPES.length) // 53
```

## Pricing

| Tier | Price | Get it |
|------|-------|--------|
| Free | $0 | [Chrome Web Store](https://chromewebstore.google.com/detail/odeoilooelkodahbbdokbollgahdcaag) |
| Pro | $7.99/mo or $59/yr | [safepaste.app/#pricing](https://safepaste.app/#pricing) |
| SafeRelay Suite | $99 one-time | [safepaste.app/saferelay](https://safepaste.app/saferelay) |

## Related packages

- **Browser Extension** — SafeRelay — Local AI DLP (Chrome & Firefox)
- **Python CLI** — [`pip install saferelay`](https://pypi.org/project/saferelay/)
- **Docker** — [`docker pull logicgridai/saferelay`](https://hub.docker.com/r/logicgridai/saferelay)

## License

PROPRIETARY — LogicGrid AI, LLC — [support@logicgrid.ai](mailto:support@logicgrid.ai)