export type PatternGroup = 'devsec' | 'fintech' | 'corporate' | 'civic' | 'basic'

export type Tier = 'free' | 'pro' | 'enterprise'

export interface Pattern {
  type: string
  group: PatternGroup
  freeTier: boolean
  basic: boolean
  regex: RegExp
  validate?: (match: string) => boolean
}

export interface SanitizeResult {
  sanitized: string
  count: number
  matches: Array<{
    type: string
    placeholder: string
    original: string
  }>
}

export interface ViolationEvent {
  type: 'PASTE_INTERCEPTED' | 'COPY_BLOCKED' | 'BULK_COPY_BLOCKED'
  count: number
  patterns: string[]
  timestamp: number
  url?: string
}

export interface SafePasteConfig {
  licenseKey?: string
  tier?: Tier
  enabledPatterns?: string[]
  onViolation?: (event: ViolationEvent) => void
  webhookUrl?: string
}

export interface SafePasteContextValue {
  sanitize: (text: string) => SanitizeResult
  vault: VaultInterface
  config: SafePasteConfig
  stats: {
    totalRedacted: number
    sessionCount: number
  }
}

export interface VaultInterface {
  store(type: string, value: string): string
  resolve(token: string): string | null
  clear(): void
  size(): number
  keys(): string[]
}
