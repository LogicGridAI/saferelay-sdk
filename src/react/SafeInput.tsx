import React, { forwardRef } from 'react'
import type { SanitizeResult } from '../core/types'
import { useSafePasteContext } from './context'

function insertTextAtInput(el: HTMLInputElement, text: string): void {
  const start = el.selectionStart ?? 0
  const end = el.selectionEnd ?? 0
  el.focus()
  el.setRangeText(text, start, end, 'end')
  el.dispatchEvent(new Event('input', { bubbles: true }))
  el.dispatchEvent(new Event('change', { bubbles: true }))
}

export interface SafeInputProps
  extends React.InputHTMLAttributes<HTMLInputElement> {
  onSanitized?: (result: SanitizeResult) => void
}

export const SafeInput = forwardRef<HTMLInputElement, SafeInputProps>(
  function SafeInput({ onPaste, onSanitized, ...rest }, ref) {
    const { sanitize } = useSafePasteContext()
    const handlePaste = (e: React.ClipboardEvent<HTMLInputElement>) => {
      onPaste?.(e)
      if (e.defaultPrevented) return
      const text = e.clipboardData.getData('text/plain')
      if (!text) return
      const result = sanitize(text)
      if (result.count > 0) {
        e.preventDefault()
        insertTextAtInput(e.currentTarget, result.sanitized)
        onSanitized?.(result)
      }
    }
    return <input ref={ref} {...rest} onPaste={handlePaste} />
  }
)

SafeInput.displayName = 'SafeInput'
