import { createContext, useContext } from 'react'
import type { SafePasteContextValue } from '../core/types'

export const SafePasteContext = createContext<SafePasteContextValue | null>(null)

export function useSafePasteContext(): SafePasteContextValue {
  const ctx = useContext(SafePasteContext)
  if (ctx == null) {
    throw new Error('useSafePasteContext must be used within SafePasteProvider')
  }
  return ctx
}
