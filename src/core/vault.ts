import type { VaultInterface } from './types'

export class Vault implements VaultInterface {
  private readonly storage = new Map<string, string>()
  private readonly counters = new Map<string, number>()

  store(type: string, value: string): string {
    const next = (this.counters.get(type) ?? 0) + 1
    this.counters.set(type, next)
    const placeholder = `[${type}_${next}]`
    this.storage.set(placeholder, value)
    return placeholder
  }

  resolve(token: string): string | null {
    return this.storage.get(token) ?? null
  }

  clear(): void {
    this.storage.clear()
    this.counters.clear()
  }

  size(): number {
    return this.storage.size
  }

  keys(): string[] {
    return [...this.storage.keys()]
  }
}
