import React, { useCallback, useMemo, useRef, useState } from 'react'
import { Tokenizer } from '../core/tokenizer'
import { Vault } from '../core/vault'
import type { SafePasteConfig, SanitizeResult, ViolationEvent } from '../core/types'
import { SafePasteContext } from './context'

function insertText(target: EventTarget | null, text: string): void {
  if (target == null) return
  if (target instanceof HTMLInputElement || target instanceof HTMLTextAreaElement) {
    const el = target
    const start = el.selectionStart ?? 0
    const end = el.selectionEnd ?? 0
    el.focus()
    el.setRangeText(text, start, end, 'end')
    el.dispatchEvent(new Event('input', { bubbles: true }))
    el.dispatchEvent(new Event('change', { bubbles: true }))
  } else if (target instanceof HTMLElement && target.isContentEditable) {
    const sel = window.getSelection()
    if (sel == null || sel.rangeCount === 0) return
    const range = sel.getRangeAt(0)
    range.deleteContents()
    const node = document.createTextNode(text)
    range.insertNode(node)
    range.setStartAfter(node)
    range.setEndAfter(node)
    sel.removeAllRanges()
    sel.addRange(range)
  }
}

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

  const handlePasteCapture = useCallback(
    (e: React.ClipboardEvent<HTMLDivElement>) => {
      const text = e.clipboardData?.getData('text/plain') ?? ''
      if (!text) return
      const tokenizer = tokenizerRef.current
      if (tokenizer == null) return
      const result = tokenizer.sanitize(text)
      if (result.count === 0) return
      e.preventDefault()
      e.stopPropagation()
      const active =
        (e.target as Node | null)?.ownerDocument?.activeElement ?? null
      insertText(active, result.sanitized)
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
    },
    [onViolation, webhookUrl]
  )

  const config: SafePasteConfig = useMemo(
    () => ({ licenseKey, tier, enabledPatterns, onViolation, webhookUrl }),
    [licenseKey, tier, enabledPatterns, onViolation, webhookUrl]
  )

  const sanitize = useCallback((text: string): SanitizeResult => {
    const tokenizer = tokenizerRef.current
    if (tokenizer == null) {
      return { sanitized: text, count: 0, matches: [] }
    }
    return tokenizer.sanitize(text)
  }, [])

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
      <div style={{ display: 'contents' }} onPasteCapture={handlePasteCapture}>
        {children}
      </div>
    </SafePasteContext.Provider>
  )
}
