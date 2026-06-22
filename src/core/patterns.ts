import type { Pattern } from './types'

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
  if (match.length === 40 && isPureHex(match)) return true
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
  if (octets.length !== 4) return false
  if (octets[0] === 127 || octets[0] === 255) return false
  return octets.every((o) => o >= 0 && o <= 255)
}

function validCreditCard(match: string): boolean {
  const d = match.replace(/\D/g, '')
  return (d.length === 15 || d.length === 16) && luhnValid(d)
}

// ── Canonical pattern registry ──────────────────────────────────────────────
// Mirrors patterns.js (browser extension) and boomerang_snip.py (desktop).
// freeTier/basic flags match the shipped extension exactly:
//   devsec (API keys, secrets, crypto, IPs, env) → free
//   fintech / corporate / civic (regulated PII)  → Pro
// Each provider gets its own type so placeholders are self-documenting.

export const THREAT_PATTERNS: Pattern[] = [

  // ── Connection-string credentials (scheme://user:PASSWORD@host) ─────────
  // Lookbehind matches ONLY the password, so whole-match replacement redacts
  // just it and keeps scheme/user/host visible. Runs first.
  {
    type: 'CONN_STRING', group: 'devsec', freeTier: true, basic: true,
    regex: /(?<=\b[a-z][a-z0-9+.\-]*:\/\/[^:/\s@]+:)[^\s]+?(?=@[a-zA-Z0-9.\-]+(?::\d+)?(?:[/\s]|$))/gi,
  },

  // ── DevSec — Free tier ──────────────────────────────────────────────────
  {
    type: 'IP', group: 'devsec', freeTier: true, basic: true,
    regex: /\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b/g,
    validate: validIpv4,
  },

  // ── Named API Keys (Free) ───────────────────────────────────────────────
  {
    type: 'OPENAI_KEY', group: 'devsec', freeTier: true, basic: true,
    regex: /\bsk-proj-[a-zA-Z0-9_-]{20,}\b/g,
  },
  {
    type: 'OPENAI_KEY', group: 'devsec', freeTier: true, basic: true,
    regex: /\bsk-(?!proj-|ant-)[a-zA-Z0-9_-]{16,}\b/g,
    validate: (m) => !isFalsePositiveApiMatch(m),
  },
  {
    type: 'ANTHROPIC_KEY', group: 'devsec', freeTier: true, basic: true,
    regex: /\bsk-ant-[a-zA-Z0-9_-]{10,}\b/g,
  },
  {
    type: 'AWS_KEY', group: 'devsec', freeTier: true, basic: true,
    regex: /\bAKIA[0-9A-Z]{16}\b/g,
  },
  {
    type: 'AWS_KEY', group: 'devsec', freeTier: true, basic: true,
    regex: /\bASIA[0-9A-Z]{16}\b/g,
  },
  {
    type: 'AWS_SECRET', group: 'devsec', freeTier: true, basic: true,
    regex: /(?:AWS_SECRET_ACCESS_KEY|aws_secret_access_key|SecretAccessKey)\s*[=:"'\s]+["']?([A-Za-z0-9/+=]{40})["']?/g,
  },
  {
    type: 'AWS_SECRET', group: 'devsec', freeTier: true, basic: true,
    regex: /(?<![A-Za-z0-9/+])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])/g,
    validate: (m) => !/^[0-9a-fA-F]{40}$/.test(m),
  },
  {
    type: 'GITHUB_PAT', group: 'devsec', freeTier: true, basic: true,
    regex: /\bghp_[a-zA-Z0-9]{20,}\b/g,
  },
  {
    type: 'GITHUB_PAT_FG', group: 'devsec', freeTier: true, basic: true,
    regex: /\bgithub_pat_[a-zA-Z0-9_]{20,}\b/g,
  },
  {
    type: 'GITHUB_OAUTH', group: 'devsec', freeTier: true, basic: true,
    regex: /\bgh[osux]_[a-zA-Z0-9]{20,}\b/g,
  },
  {
    type: 'SLACK_KEY', group: 'devsec', freeTier: true, basic: true,
    regex: /\bxox[bap]-[a-zA-Z0-9-]{10,}\b/g,
  },
  {
    type: 'SLACK_WEBHOOK', group: 'devsec', freeTier: true, basic: true,
    regex: /https:\/\/hooks\.slack\.com\/services\/[A-Z0-9]+\/[A-Z0-9]+\/[A-Za-z0-9]+/g,
  },
  {
    type: 'STRIPE_KEY', group: 'devsec', freeTier: true, basic: true,
    regex: /\bsk_(?:live|test)_[a-zA-Z0-9]{24,}\b/g,
  },
  {
    type: 'STRIPE_PK', group: 'devsec', freeTier: true, basic: true,
    regex: /\bpk_(?:live|test)_[a-zA-Z0-9]{24,}\b/g,
  },
  {
    type: 'BEARER', group: 'devsec', freeTier: true, basic: true,
    regex: /\bbearer\s+[a-zA-Z0-9._~+/=-]{16,}\b/gi,
    validate: (m) => !isFalsePositiveApiMatch(m),
  },
  {
    type: 'DOCKER_KEY', group: 'devsec', freeTier: true, basic: true,
    regex: /\bdckr_pat_[a-zA-Z0-9_-]{20,}\b/g,
  },
  {
    type: 'NPM_TOKEN', group: 'devsec', freeTier: true, basic: true,
    regex: /\bnpm_[a-zA-Z0-9]{36,}\b/g,
  },
  {
    type: 'TWILIO_KEY', group: 'devsec', freeTier: true, basic: true,
    regex: /\bSK[a-f0-9]{32}\b/g,
  },
  {
    type: 'SENDGRID_KEY', group: 'devsec', freeTier: true, basic: true,
    regex: /\bSG\.[a-zA-Z0-9_-]{22,}\.[a-zA-Z0-9_-]{43,}\b/g,
  },
  {
    type: 'GEMINI_KEY', group: 'devsec', freeTier: true, basic: true,
    regex: /\bAIza[0-9A-Za-z\-_]{35}\b/g,
  },
  // Google OAuth (client id / secret / refresh token)
  {
    type: 'GOOGLE_OAUTH', group: 'devsec', freeTier: true, basic: true,
    regex: /\b\d{6,}-[a-z0-9]+\.apps\.googleusercontent\.com\b/gi,
  },
  {
    type: 'GOOGLE_OAUTH', group: 'devsec', freeTier: true, basic: true,
    regex: /\bGOCSPX-[A-Za-z0-9_-]{20,}\b/g,
  },
  {
    type: 'GOOGLE_OAUTH', group: 'devsec', freeTier: true, basic: true,
    regex: /\b1\/\/[A-Za-z0-9_\-]{10,}\b/g,
  },
  {
    type: 'API_KEY', group: 'devsec', freeTier: true, basic: true,
    regex: /\bpk-[a-zA-Z0-9_-]{16,}\b/g,
    validate: (m) => !isFalsePositiveApiMatch(m),
  },
  {
    type: 'PEM_KEY', group: 'devsec', freeTier: true, basic: true,
    regex: /-----BEGIN\s(?:RSA\s|EC\s|OPENSSH\s)?PRIVATE KEY-----/g,
  },

  // ── Crypto — Free tier ──────────────────────────────────────────────────
  {
    type: 'BTC_ADDRESS', group: 'devsec', freeTier: true, basic: true,
    regex: /\b1[a-km-zA-HJ-NP-Z1-9]{25,34}\b/g,
  },
  {
    type: 'BTC_ADDRESS', group: 'devsec', freeTier: true, basic: true,
    regex: /\b3[a-km-zA-HJ-NP-Z1-9]{25,34}\b/g,
  },
  {
    type: 'BTC_ADDRESS', group: 'devsec', freeTier: true, basic: true,
    regex: /\bbc1[a-z0-9]{6,87}\b/gi,
  },
  // ETH_PRIVATE_KEY before ETH_ADDRESS so the 64-hex case wins
  {
    type: 'ETH_PRIVATE_KEY', group: 'devsec', freeTier: true, basic: true,
    regex: /\b0x[a-fA-F0-9]{64}\b/g,
  },
  {
    type: 'ETH_ADDRESS', group: 'devsec', freeTier: true, basic: true,
    regex: /\b0x[a-fA-F0-9]{40}\b/g,
  },
  {
    type: 'CRYPTO_KEY', group: 'devsec', freeTier: true, basic: true,
    regex: /\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b/g,
  },
  {
    type: 'SOL_ADDRESS', group: 'devsec', freeTier: true, basic: true,
    regex: /\b[1-9A-HJ-NP-Za-km-z]{44}\b/g,
  },
  {
    type: 'SEED_PHRASE', group: 'devsec', freeTier: true, basic: true,
    regex: /\b([a-z]+\s){11}[a-z]+\b/g,
    validate: (m) => m.trim().split(/\s+/).length === 12,
  },
  {
    type: 'SEED_PHRASE', group: 'devsec', freeTier: true, basic: true,
    regex: /\b([a-z]+\s){23}[a-z]+\b/g,
    validate: (m) => m.trim().split(/\s+/).length === 24,
  },
  {
    type: 'ENV_VALUE', group: 'devsec', freeTier: true, basic: true,
    regex: /(?<=^[A-Z][A-Z0-9_]*=)(?!sk-proj-|sk-ant-|AKIA|ASIA|ghp_|github_pat_|gh[osux]_|xox[bap]-|AIza|sk_live_|sk_test_|pk_live_|pk_test_|dckr_pat_|npm_|SG\.|SK[0-9a-f]).+$/gm,
  },

  // ── DevSec — Pro tier ───────────────────────────────────────────────────
  {
    type: 'MAC_ADDRESS', group: 'devsec', freeTier: false, basic: false,
    regex: /\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b/g,
  },
  {
    // Bare 64-char hex; Pro. (Context-aware SHA filtering lives in the
    // extension/CLI; SDK keeps the simpler form per the shipped JS.)
    type: 'CRYPTO_KEY', group: 'devsec', freeTier: false, basic: false,
    regex: /\b[a-fA-F0-9]{64}\b/g,
  },

  // ── FinTech — Pro tier ──────────────────────────────────────────────────
  {
    type: 'CREDIT_CARD', group: 'fintech', freeTier: false, basic: false,
    regex: /\b(?:\d{4}[-\s]?){3}\d{3,4}\b/g,
    validate: validCreditCard,
  },
  {
    type: 'US_SSN', group: 'fintech', freeTier: false, basic: false,
    regex: /\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g,
  },
  {
    type: 'EU_IBAN', group: 'fintech', freeTier: false, basic: false,
    regex: /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/gi,
  },
  {
    type: 'EMAIL', group: 'fintech', freeTier: false, basic: false,
    regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    validate: (m) => !/\.(png|jpg|jpeg|gif|svg|webp|css|js|json|html?)$/i.test(m),
  },
  {
    type: 'UK_NINO', group: 'fintech', freeTier: false, basic: false,
    regex: /\b[A-Z]{2}\d{6}[A-Z]\b/g,
  },
  {
    type: 'CA_SIN', group: 'fintech', freeTier: false, basic: false,
    regex: /\b[1-79]\d{2}-\d{3}-\d{3}\b/g,
  },
  {
    type: 'IN_AADHAAR', group: 'fintech', freeTier: false, basic: false,
    regex: /\b[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}\b/g,
    validate: (m) => m.replace(/[\s-]/g, '').length === 12,
  },
  {
    type: 'IN_PAN', group: 'fintech', freeTier: false, basic: false,
    regex: /\b[A-Z]{5}[0-9]{4}[A-Z]\b/g,
  },
  {
    type: 'ZA_ID', group: 'fintech', freeTier: false, basic: false,
    regex: /\b\d{13}\b/g,
    validate(m) {
      const month = parseInt(m.slice(2, 4), 10)
      const day = parseInt(m.slice(4, 6), 10)
      return month >= 1 && month <= 12 && day >= 1 && day <= 31
    },
  },
  {
    type: 'AU_TFN', group: 'fintech', freeTier: false, basic: false,
    regex: /\b\d{3}[\s-]?\d{3}[\s-]?\d{2,3}\b/g,
    validate(m) {
      const d = m.replace(/[\s-]/g, '')
      return d.length === 8 || d.length === 9
    },
  },
  {
    type: 'BR_CPF', group: 'fintech', freeTier: false, basic: false,
    regex: /\b\d{3}\.\d{3}\.\d{3}-\d{2}\b/g,
  },
  {
    type: 'SG_NRIC', group: 'fintech', freeTier: false, basic: false,
    regex: /\b[STFG]\d{7}[A-Z]\b/g,
  },
  {
    type: 'US_GREEN_CARD', group: 'fintech', freeTier: false, basic: false,
    regex: /\b[A-Z]{2,3}\d{9,10}\b/g,
    validate(m) {
      const upper = m.toUpperCase()
      const prefixes = ['LIN', 'EAC', 'WAC', 'SRC', 'MSC', 'IOE']
      if (prefixes.some((p) => upper.startsWith(p))) return true
      if (/^A\d{8,9}$/.test(upper)) return true
      if (/^[A-Z]{3}\d{10}$/.test(upper)) return true
      return false
    },
  },
  // ── Nigeria — context-aware (labeled) identifiers, Pro tier ─────────────
  // Lookbehind requires a BVN/NIN label immediately before the number, but
  // the label is NOT part of the match — so whole-match replacement consumes
  // only the 11 digits and the label is preserved in output:
  //   "BVN: 12345678901"  ->  "BVN: [NG_BVN_1]"
  // These MUST run before NG_NIN bare + DE_TAX_ID so labeled numbers win.
  {
    type: 'NG_BVN', group: 'fintech', freeTier: false, basic: false,
    regex: /(?<=\b(?:BVN|Bank[\s-]?Verification(?:[\s-]?(?:Number|No|#))?)\s*[:#-]?\s*)\d{11}\b/gi,
  },
  {
    type: 'NG_NIN', group: 'fintech', freeTier: false, basic: false,
    regex: /(?<=\b(?:NIN|National[\s-]?(?:Identification|Identity|ID)(?:[\s-]?(?:Number|No|#))?)\s*[:#-]?\s*)\d{11}\b/gi,
  },
  // ── Nigeria — bare-digit fallbacks, Pro tier ────────────────────────────
  {
    type: 'NG_PHONE', group: 'fintech', freeTier: false, basic: false,
    regex: /\b0[789][01]\d{8}\b/g,
  },
  {
    type: 'NG_BANK', group: 'fintech', freeTier: false, basic: false,
    regex: /\b\d{10}\b/g,
  },
  {
    type: 'NG_NIN', group: 'fintech', freeTier: false, basic: false,
    regex: /\b(?!0[789][01]\d{8})\d{11}\b/g,
  },
  // DE_TAX_ID runs AFTER the NG block so a bare 11-digit NIN is labeled
  // NG_NIN, not DE_TAX_ID. (Both match 11 digits; order decides the label.)
  {
    type: 'DE_TAX_ID', group: 'fintech', freeTier: false, basic: false,
    regex: /\b[1-9]\d{10}\b/g,
  },

  // ── Corporate ID Shield — Pro tier ──────────────────────────────────────
  {
    type: 'DUNS', group: 'corporate', freeTier: false, basic: false,
    regex: /(?:D[-\s]?U[-\s]?N[-\s]?S|D&B|Dun\s*&\s*Bradstreet)[^0-9]{0,50}(\d{2}-\d{3}-\d{4}|\d{9})/gi,
  },
  {
    type: 'EIN', group: 'corporate', freeTier: false, basic: false,
    regex: /\b(?:EIN|Tax\s*ID|Federal\s*Tax\s*ID)[^0-9]{0,20}(\d{2}-\d{7})\b/gi,
  },
  {
    type: 'VAT_EU', group: 'corporate', freeTier: false, basic: false,
    regex: /\b(ATU\d{8}|BE0\d{9}|BG\d{9,10}|CY\d{8}L|CZ\d{8,10}|DE\d{9}|DK\d{8}|EE\d{9}|EL\d{9}|ES[A-Z0-9]\d{7}[A-Z0-9]|FI\d{8}|FR[A-Z0-9]{2}\d{9}|HR\d{11}|HU\d{8}|IE\d{7}[A-Z]{1,2}|IT\d{11}|LT\d{9,12}|LU\d{8}|LV\d{11}|MT\d{8}|NL\d{9}B\d{2}|PL\d{10}|PT\d{9}|RO\d{2,10}|SE\d{12}|SI\d{8}|SK\d{10})\b/g,
  },

  // ── Mission & Civic Shield ──────────────────────────────────────────────
  {
    type: 'DONOR_ID', group: 'civic', freeTier: true, basic: true,
    regex: /\b(?:Donor|Beneficiary|Bene|Case|Client|Member|Ref)[-\s]?(?:ID|No|#|Number|Code)[-\s:]*([A-Z0-9]{4,16})\b/gi,
  },
  {
    type: 'GPS_COORDS', group: 'civic', freeTier: false, basic: false,
    regex: /\b(-?(?:[1-8]?\d(?:\.\d+)?|90(?:\.0+)?)),\s*(-?(?:1[0-7]\d(?:\.\d+)?|(?:[1-9]?\d(?:\.\d+)?)|180(?:\.0+)?))\b/g,
  },
  {
    type: 'UNHCR_ID', group: 'civic', freeTier: false, basic: false,
    regex: /\b(?:UNHCR[-\s]?(?:ID|Reg(?:istration)?)?[-\s#:]*)?([A-Z]{3}-\d{2}-\d{6,8}C?\d?)\b/gi,
  },
]

// ── Tier / introspection helpers ────────────────────────────────────────────
export const FREE_PATTERNS = THREAT_PATTERNS.filter((p) => p.freeTier)
export const PRO_PATTERNS = THREAT_PATTERNS
export const PATTERN_TYPES = [...new Set(THREAT_PATTERNS.map((p) => p.type))]
