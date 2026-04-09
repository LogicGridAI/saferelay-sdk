import React, { useCallback, useMemo, useRef, useState } from 'react'
import { Tokenizer } from '../core/tokenizer'
import { Vault } from '../core/vault'
import type { SafePasteConfig, SanitizeResult, ViolationEvent } from '../core/types'
import { SafePasteContext } from './context'

function tokenizerConfigSignature(
  tier: SafePasteConfig['tier'],
  enabledPatterns: SafePasteConfig['enabledPatterns'],
  licenseKey: SafePasteConfig['licenseKey']
): string {
  return `${tier ?? 'free'}:${licenseKey ?? ''}:${(enabledPatterns ?? []).join('\0')}`
}

export function SafePasteProvider({
  children,
  licenseKey,
  tier = 'free',
  enabledPatterns,
  onViolation,
  webhookUrl,
}: SafePasteConfig & { children: React.ReactNode }) {
  const vaultRef = useRef<Vault | null>(null)
  if (vaultRef.current == null) {
    vaultRef.current = new Vault()
  }
  const vault = vaultRef.current

  const tokenizerRef = useRef<Tokenizer | null>(null)
  const lastTokenizerSig = useRef<string>('')
  const sig = tokenizerConfigSignature(tier, enabledPatterns, licenseKey)
  if (tokenizerRef.current == null || lastTokenizerSig.current !== sig) {
    lastTokenizerSig.current = sig
    tokenizerRef.current = new Tokenizer(vault, {
      licenseKey,
      tier,
      enabledPatterns,
      onViolation,
      webhookUrl,
    })
  }

  const [stats, setStats] = useState({ totalRedacted: 0, sessionCount: 0 })

  const config: SafePasteConfig = useMemo(
    () => ({ licenseKey, tier, enabledPatterns, onViolation, webhookUrl }),
    [licenseKey, tier, enabledPatterns, onViolation, webhookUrl]
  )

  const sanitize = useCallback((text: string): SanitizeResult => {
    const tokenizer = tokenizerRef.current
    if (tokenizer == null) {
      return { sanitized: text, count: 0, matches: [] }
    }
    const result = tokenizer.sanitize(text)
    if (result.count > 0) {
      setStats((s) => ({
        totalRedacted: s.totalRedacted + result.count,
        sessionCount: s.sessionCount + 1,
      }))
      const patternTypes = [...new Set(result.matches.map((m) => m.type))]
      const violation: ViolationEvent = {
        type: 'PASTE_INTERCEPTED',
        count: result.count,
        patterns: patternTypes,
        timestamp: Date.now(),
        url: typeof window !== 'undefined' ? window.location.href : undefined,
      }
      onViolation?.(violation)
      if (webhookUrl) {
        void fetch(webhookUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(violation),
        }).catch(() => {})
      }
    }
    return result
  }, [onViolation, webhookUrl])

  const value = useMemo(
    () => ({
      sanitize,
      vault,
      config,
      stats,
    }),
    [sanitize, vault, config, stats]
  )

  return (
    <SafePasteContext.Provider value={value}>
      {children}
    </SafePasteContext.Provider>
  )
}
