import { useSafePasteContext } from './context'

export function useSafePaste() {
  const ctx = useSafePasteContext()
  return {
    sanitize: ctx.sanitize,
    vault: ctx.vault,
    stats: ctx.stats,
    sanitizeText: (text: string) => ctx.sanitize(text),
  }
}
