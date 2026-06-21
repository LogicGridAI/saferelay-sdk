import { useSafePasteContext } from './context'

export function useSafeRelay() {
  const ctx = useSafePasteContext()
  return {
    sanitize: ctx.sanitize,
    vault: ctx.vault,
    stats: ctx.stats,
    sanitizeText: (text: string) => ctx.sanitize(text),
  }
}

/**
 * @deprecated Use `useSafeRelay` instead. Kept as an alias for backward
 * compatibility; will be removed in a future major version.
 */
export const useSafePaste = useSafeRelay