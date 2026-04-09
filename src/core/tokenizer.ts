import type { Pattern, SafePasteConfig, SanitizeResult } from './types'
import { THREAT_PATTERNS } from './patterns'
import type { Vault } from './vault'

function getActivePatterns(config: SafePasteConfig): Pattern[] {
  const tier = config.tier ?? 'free'
  let list = [...THREAT_PATTERNS]
  if (tier === 'free') {
    list = list.filter((p) => p.freeTier && p.basic)
  }
  const enabled = config.enabledPatterns
  if (enabled && enabled.length > 0) {
    const allow = new Set(enabled)
    list = list.filter((p) => allow.has(p.type))
  }
  return list
}

export class Tokenizer {
  constructor(
    private readonly vault: Vault,
    private readonly config: SafePasteConfig
  ) {}

  sanitize(text: string): SanitizeResult {
    const active = getActivePatterns(this.config)
    let sanitized = text
    const matches: SanitizeResult['matches'] = []
    let count = 0

    for (const pattern of active) {
      const re = new RegExp(pattern.regex.source, pattern.regex.flags)
      sanitized = sanitized.replace(re, (match) => {
        if (pattern.validate && !pattern.validate(match)) {
          return match
        }
        count++
        const placeholder = this.vault.store(pattern.type, match)
        matches.push({
          type: pattern.type,
          placeholder,
          original: match,
        })
        return placeholder
      })
    }

    return { sanitized, count, matches }
  }
}
