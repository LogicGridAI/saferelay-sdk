import type { Pattern, PatternGroup } from './types'

// ── Validators ────────────────────────────────────────────────────────────────

function isPureHex(s: string): boolean {
  return /^[a-f0-9]+$/i.test(s)
}

function isFalsePositiveApiMatch(match: string): boolean {
  const lower = String(match).toLowerCase()
  if (lower.startsWith('bearer ')) {
    const t = lower.slice(7).trim()
    return t.length >= 16 && isPureHex(t)
  }
  if (/^sk-|^pk-/i.test(match)) {
    const t = lower.replace(/^(sk|pk)-/, '').trim()
    return t.length >= 16 && isPureHex(t)
  }
  return false
}

function luhnValid(digitsOnly: string): boolean {
  if (digitsOnly.length !== 15 && digitsOnly.length !== 16) return false
  let sum = 0
  let alt = false
  for (let i = digitsOnly.length - 1; i >= 0; i--) {
    let n = parseInt(digitsOnly[i]!, 10)
    if (Number.isNaN(n)) return false
    if (alt) { n *= 2; if (n > 9) n -= 9 }
    sum += n
    alt = !alt
  }
  return sum % 10 === 0
}

function validIpv4(match: string): boolean {
  const octets = match.split('.').map(Number)
  if (octets[0] === 127 || octets[0] === 255) return false
  return octets.every((o) => o >= 0 && o <= 255)
}

function validCreditCard(match: string): boolean {
  const d = match.replace(/\D/g, '')
  return (d.length === 15 || d.length === 16) && luhnValid(d)
}

// ── v3.5 Named API Key Patterns ───────────────────────────────────────────────
// Each provider gets its own type so placeholders are self-documenting:
// sk-proj-abc → [OPENAI_KEY_1], AKIA1234 → [AWS_KEY_1], ghp_abc → [GITHUB_PAT_1]

export const THREAT_PATTERNS: Pattern[] = [

  // ── DevSec — Free tier ────────────────────────────────────────────────────

  {
    type: 'IP',
    group: 'devsec',
    freeTier: true,
    basic: true,
    regex: /\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b/g,
    validate: validIpv4,
  },

  // ── Named API Keys (Free tier) ────────────────────────────────────────────

  {
    type: 'OPENAI_KEY',
    group: 'devsec',
    freeTier: true,
    basic: true,
    regex: /\bsk-proj-[a-zA-Z0-9_-]{20,}\b/g,
  },
  {
    type: 'OPENAI_KEY',
    group: 'devsec',
    freeTier: true,
    basic: true,
    // Legacy OpenAI keys (sk- but not sk-proj- and not sk-ant-)
    regex: /\bsk-(?!proj-|ant-)[a-zA-Z0-9_-]{16,}\b/g,
    validate: (m) => !isFalsePositiveApiMatch(m),
  },
  {
    type: 'ANTHROPIC_KEY',
    group: 'devsec',
    freeTier: true,
    basic: true,
    regex: /\bsk-ant-[a-zA-Z0-9_-]{10,}\b/g,
  },
  {
    type: 'AWS_KEY',
    group: 'devsec',
    freeTier: true,
    basic: true,
    regex: /\bAKIA[0-9A-Z]{16}\b/g,
  },
  {
    type: 'AWS_KEY',
    group: 'devsec',
    freeTier: true,
    basic: true,
    // AWS STS temporary keys
    regex: /\bASIA[0-9A-Z]{16}\b/g,
  },
  {
    type: 'GITHUB_PAT',
    group: 'devsec',
    freeTier: true,
    basic: true,
    // Classic personal access tokens
    regex: /\bghp_[a-zA-Z0-9]{20,}\b/g,
  },
  {
    type: 'GITHUB_PAT_FG',
    group: 'devsec',
    freeTier: true,
    basic: true,
    // Fine-grained personal access tokens
    regex: /\bgithub_pat_[a-zA-Z0-9_]{20,}\b/g,
  },
  {
    type: 'GITHUB_OAUTH',
    group: 'devsec',
    freeTier: true,
    basic: true,
    // GitHub OAuth / app / server tokens
    regex: /\bgh[osux]_[a-zA-Z0-9]{20,}\b/g,
  },
  {
    type: 'SLACK_KEY',
    group: 'devsec',
    freeTier: true,
    basic: true,
    regex: /\bxox[bap]-[a-zA-Z0-9-]{10,}\b/g,
  },
  {
    type: 'GEMINI_KEY',
    group: 'devsec',
    freeTier: true,
    basic: true,
    regex: /\bAIza[0-9A-Za-z\-_]{35}\b/g,
  },
  {
    type: 'STRIPE_KEY',
    group: 'devsec',
    freeTier: true,
    basic: true,
    // Stripe secret keys (live and test)
    regex: /\bsk_(?:live|test)_[a-zA-Z0-9]{24,}\b/g,
  },
  {
    type: 'STRIPE_PK',
    group: 'devsec',
    freeTier: true,
    basic: true,
    // Stripe publishable keys
    regex: /\bpk_(?:live|test)_[a-zA-Z0-9]{24,}\b/g,
  },
  {
    type: 'BEARER',
    group: 'devsec',
    freeTier: true,
    basic: true,
    regex: /\bbearer\s+[a-zA-Z0-9._~+/=-]{16,}\b/gi,
    validate: (m) => !isFalsePositiveApiMatch(m),
  },
  {
    // Catch-all for any remaining API-style key patterns
    type: 'API_KEY',
    group: 'devsec',
    freeTier: true,
    basic: true,
    regex: /\bpk-[a-zA-Z0-9_-]{16,}\b/g,
    validate: (m) => !isFalsePositiveApiMatch(m),
  },

  // ── Crypto — Free tier ────────────────────────────────────────────────────

  {
    type: 'BTC_ADDRESS',
    group: 'devsec',
    freeTier: true,
    basic: true,
    regex: /\b1[a-km-zA-HJ-NP-Z1-9]{25,34}\b/g,
  },
  {
    type: 'BTC_ADDRESS',
    group: 'devsec',
    freeTier: true,
    basic: true,
    regex: /\b3[a-km-zA-HJ-NP-Z1-9]{25,34}\b/g,
  },
  {
    type: 'BTC_ADDRESS',
    group: 'devsec',
    freeTier: true,
    basic: true,
    regex: /\bbc1[a-z0-9]{6,87}\b/gi,
  },
  {
    type: 'ETH_ADDRESS',
    group: 'devsec',
    freeTier: true,
    basic: true,
    regex: /\b0x[a-fA-F0-9]{40}\b/g,
  },
  {
    type: 'SEED_PHRASE',
    group: 'devsec',
    freeTier: true,
    basic: true,
    regex: /\b([a-z]+\s){11}[a-z]+\b/g,
    validate(m: string) {
      return m.trim().split(/\s+/).length === 12
    },
  },
  {
    type: 'SEED_PHRASE',
    group: 'devsec',
    freeTier: true,
    basic: true,
    regex: /\b([a-z]+\s){23}[a-z]+\b/g,
    validate(m: string) {
      return m.trim().split(/\s+/).length === 24
    },
  },
  {
    type: 'PEM_KEY',
    group: 'devsec',
    freeTier: true,
    basic: true,
    regex: /-----BEGIN\s(?:RSA\s|EC\s|OPENSSH\s)?PRIVATE KEY-----/g,
  },
  {
    type: 'ENV_VALUE',
    group: 'devsec',
    freeTier: true,
    basic: true,
    regex: /(?<=^[A-Z][A-Z0-9_]*=).+$/gm,
  },

  // ── DevSec — Pro tier ─────────────────────────────────────────────────────

  {
    type: 'MAC_ADDRESS',
    group: 'devsec',
    freeTier: false,
    basic: false,
    regex: /\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b/g,
  },
  {
    type: 'ETH_PRIVATE_KEY',
    group: 'devsec',
    freeTier: false,
    basic: false,
    regex: /\b0x[a-fA-F0-9]{64}\b/g,
  },
  {
    type: 'CRYPTO_KEY',
    group: 'devsec',
    freeTier: false,
    basic: false,
    // WIF private keys
    regex: /\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b/g,
  },
  {
    type: 'SOL_ADDRESS',
    group: 'devsec',
    freeTier: false,
    basic: false,
    regex: /\b[1-9A-HJ-NP-Za-km-z]{44}\b/g,
  },

  // ── FinTech — Pro tier ────────────────────────────────────────────────────

  {
    type: 'CREDIT_CARD',
    group: 'fintech',
    freeTier: false,
    basic: false,
    regex: /\b(?:\d{4}[-\s]?){3}\d{3,4}\b/g,
    validate: validCreditCard,
  },
  {
    type: 'US_SSN',
    group: 'fintech',
    freeTier: false,
    basic: false,
    regex: /\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g,
  },
  {
    type: 'EU_IBAN',
    group: 'fintech',
    freeTier: false,
    basic: false,
    regex: /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/gi,
  },
  {
    type: 'UK_NINO',
    group: 'fintech',
    freeTier: false,
    basic: false,
    regex: /\b[A-Z]{2}\d{6}[A-Z]\b/g,
  },
  {
    type: 'NG_BANK',
    group: 'fintech',
    freeTier: false,
    basic: false,
    regex: /\b\d{10}\b/g,
  },
  {
    type: 'NG_PHONE',
    group: 'fintech',
    freeTier: false,
    basic: false,
    regex: /\b0[789][01]\d{8}\b/g,
  },
  {
    type: 'NG_NIN',
    group: 'fintech',
    freeTier: false,
    basic: false,
    regex: /\b(?!0[789][01]\d{8})\d{11}\b/g,
  },
  {
    type: 'CA_SIN',
    group: 'fintech',
    freeTier: false,
    basic: false,
    regex: /\b[1-79]\d{2}-\d{3}-\d{3}\b/g,
  },
  {
    type: 'IN_AADHAAR',
    group: 'fintech',
    freeTier: false,
    basic: false,
    regex: /\b[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}\b/g,
    validate(m) {
      return m.replace(/[\s-]/g, '').length === 12
    },
  },
  {
    type: 'IN_PAN',
    group: 'fintech',
    freeTier: false,
    basic: false,
    regex: /\b[A-Z]{5}[0-9]{4}[A-Z]\b/g,
  },
  {
    type: 'ZA_ID',
    group: 'fintech',
    freeTier: false,
    basic: false,
    regex: /\b\d{13}\b/g,
    validate(m) {
      const month = parseInt(m.slice(2, 4), 10)
      const day = parseInt(m.slice(4, 6), 10)
      return month >= 1 && month <= 12 && day >= 1 && day <= 31
    },
  },
  {
    type: 'AU_TFN',
    group: 'fintech',
    freeTier: false,
    basic: false,
    regex: /\b\d{3}[\s-]?\d{3}[\s-]?\d{2,3}\b/g,
    validate(m) {
      const d = m.replace(/[\s-]/g, '')
      return d.length === 8 || d.length === 9
    },
  },
  {
    type: 'BR_CPF',
    group: 'fintech',
    freeTier: false,
    basic: false,
    regex: /\b\d{3}\.\d{3}\.\d{3}-\d{2}\b/g,
  },
  {
    type: 'SG_NRIC',
    group: 'fintech',
    freeTier: false,
    basic: false,
    regex: /\b[STFG]\d{7}[A-Z]\b/g,
  },
  {
    type: 'DE_TAX_ID',
    group: 'fintech',
    freeTier: false,
    basic: false,
    regex: /\b[1-9]\d{10}\b/g,
  },
  {
    type: 'US_GREEN_CARD',
    group: 'fintech',
    freeTier: false,
    basic: false,
    regex: /\b[A-Z]{2,3}\d{9,10}\b/g,
    validate(m) {
      const prefixes = ['LIN', 'EAC', 'WAC', 'SRC', 'MSC', 'IOE']
      const upper = m.toUpperCase()
      if (prefixes.some((p) => upper.startsWith(p))) return true
      if (/^A\d{8,9}$/.test(upper)) return true
      if (/^[A-Z]{3}\d{10}$/.test(upper)) return true
      return false
    },
  },
]

// ── Pattern count by tier ─────────────────────────────────────────────────────
export const FREE_PATTERNS = THREAT_PATTERNS.filter((p) => p.freeTier)
export const PRO_PATTERNS = THREAT_PATTERNS
export const PATTERN_TYPES = [...new Set(THREAT_PATTERNS.map((p) => p.type))]
