// Primary (SafeRelay-branded) API
export { SafeRelayProvider } from './SafeRelayProvider'
export { SafeInput } from './SafeInput'
export { SafeTextArea } from './SafeTextArea'
export { useSafeRelay } from './useSafeRelay'

// Deprecated aliases — kept for backward compatibility, removed in a future
// major version. Prefer the SafeRelay-prefixed names above.
export { SafeRelayProvider as SafePasteProvider } from './SafeRelayProvider'
export { useSafePaste } from './useSafeRelay'