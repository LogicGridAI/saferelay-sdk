# @logicgridai/saferelay-sdk

Zero-trust DLP primitives and React helpers for paste-time redaction of secrets and regulated identifiers.

[![npm](https://img.shields.io/npm/v/@logicgridai/safepaste-sdk)](https://www.npmjs.com/package/@logicgridai/safepaste-sdk)
[![License](https://img.shields.io/badge/license-PROPRIETARY-red)](https://safepaste.app)

## Install

```bash
npm install @logicgridai/saferelay-sdk react react-dom
```

## Usage

Wrap your app with `SafePasteProvider`, then use `SafeInput` / `SafeTextArea` or the `useSafePaste()` hook for programmatic sanitization.

```tsx
import { SafePasteProvider, SafeInput, SafeTextArea } from '@logicgridai/safepaste-sdk'

function App() {
  return (
    <SafePasteProvider
      tier="pro"
      licenseKey={process.env.REACT_APP_SAFEPASTE_KEY}
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
import { useSafePaste } from '@logicgridai/safepaste-sdk'

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

## Named API key labels (v0.2.0+)

Each provider gets its own placeholder type — making redacted output self-documenting:

| Input | Placeholder |
|-------|-------------|
| `sk-proj-abc...` | `[OPENAI_KEY_1]` |
| `sk-ant-abc...` | `[ANTHROPIC_KEY_1]` |
| `AKIA1234ABCD` | `[AWS_KEY_1]` |
| `ghp_abc123` | `[GITHUB_PAT_1]` |
| `github_pat_abc` | `[GITHUB_PAT_FG_1]` |
| `xoxb-abc...` | `[SLACK_KEY_1]` |
| `AIzaXXX...` | `[GEMINI_KEY_1]` |
| `sk_live_abc` | `[STRIPE_KEY_1]` |
| `Bearer eyJ...` | `[BEARER_1]` |
| Other API tokens | `[API_KEY_1]` |

## What gets redacted

| Pattern | Free | Pro |
|---------|------|-----|
| IPv4 addresses | ✓ | ✓ |
| Named API keys (OpenAI, Anthropic, AWS, GitHub, Slack, Gemini, Stripe) | ✓ | ✓ |
| Bearer tokens | ✓ | ✓ |
| Bitcoin / Ethereum addresses | ✓ | ✓ |
| Seed phrases (12/24 word) | ✓ | ✓ |
| PEM private keys | ✓ | ✓ |
| .env file values | ✓ | ✓ |
| MAC addresses | — | ✓ |
| ETH private keys | — | ✓ |
| Solana addresses | — | ✓ |
| Credit cards (Luhn-validated) | — | ✓ |
| US SSN | — | ✓ |
| EU IBAN | — | ✓ |
| UK NINO | — | ✓ |
| Nigeria NIN / Bank / Phone | — | ✓ |
| Canada SIN | — | ✓ |
| India Aadhaar / PAN | — | ✓ |
| South Africa ID | — | ✓ |
| Australia TFN | — | ✓ |
| Brazil CPF | — | ✓ |
| Singapore NRIC | — | ✓ |
| Germany Tax ID | — | ✓ |
| US Green Card | — | ✓ |
| Custom NDA keywords | — | ✓ |

## Core modules

`Vault`, `Tokenizer`, and `THREAT_PATTERNS` are free of browser APIs and run in Node.js or the browser — use them in CI/CD pipelines, serverless functions, or anywhere React isn't available.

```ts
import { THREAT_PATTERNS, FREE_PATTERNS, PRO_PATTERNS } from '@logicgridai/safepaste-sdk'

// Filter by tier
const freeOnly = THREAT_PATTERNS.filter(p => p.freeTier)

// Get all unique pattern types
import { PATTERN_TYPES } from '@logicgridai/safepaste-sdk'
console.log(PATTERN_TYPES) // ['IP', 'OPENAI_KEY', 'AWS_KEY', ...]
```

## Pricing

| Tier | Price | Get it |
|------|-------|--------|
| Free | $0 | [Chrome Web Store](https://chromewebstore.google.com/detail/safepaste-enterprise/ibdihcmplmiekaoofbcgeebkleafbkcn) |
| Pro | $7.99/mo or $59/yr | [safepaste.app/#pricing](https://safepaste.app/#pricing) |
| SafeRelay Suite | $99 one-time | [safepaste.app/saferelay](https://safepaste.app/saferelay) |

## Related packages

- **Chrome Extension** — [safepaste.app](https://safepaste.app)
- **Python CLI** — [`pip install safepaste-enterprise`](https://pypi.org/project/safepaste-enterprise/)
- **Docker** — [`docker pull logicgridai/safepaste`](https://hub.docker.com/r/logicgridai/safepaste)

## License

PROPRIETARY — LogicGrid AI, LLC — [support@logicgrid.ai](mailto:support@logicgrid.ai)