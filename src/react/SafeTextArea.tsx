import React, { forwardRef } from 'react'
import type { SanitizeResult } from '../core/types'
import { useSafePasteContext } from './context'

function insertTextAtTextArea(el: HTMLTextAreaElement, text: string): void {
  const start = el.selectionStart ?? 0
  const end = el.selectionEnd ?? 0
  el.focus()
  el.setRangeText(text, start, end, 'end')
  el.dispatchEvent(new Event('input', { bubbles: true }))
  el.dispatchEvent(new Event('change', { bubbles: true }))
}

export interface SafeTextAreaProps
  extends React.TextareaHTMLAttributes<HTMLTextAreaElement> {
  onSanitized?: (result: SanitizeResult) => void
}

export const SafeTextArea = forwardRef<
  HTMLTextAreaElement,
  SafeTextAreaProps
>(function SafeTextArea({ onPaste, onSanitized, ...rest }, ref) {
  const { sanitize } = useSafePasteContext()
  const handlePaste = (e: React.ClipboardEvent<HTMLTextAreaElement>) => {
    onPaste?.(e)
    if (e.defaultPrevented) return
    const text = e.clipboardData.getData('text/plain')
    if (!text) return
    const result = sanitize(text)
    if (result.count > 0) {
      e.preventDefault()
      insertTextAtTextArea(e.currentTarget, result.sanitized)
      onSanitized?.(result)
    }
  }
  return <textarea ref={ref} {...rest} onPaste={handlePaste} />
})

SafeTextArea.displayName = 'SafeTextArea'
