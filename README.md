# @logicgridai/safepaste-sdk

Zero-trust DLP (data loss prevention) primitives and React helpers for paste-time redaction of secrets and regulated identifiers.

## Install

```bash
npm install @logicgridai/safepaste-sdk react react-dom
```

## Usage

Wrap your app (or a subtree) with `SafePasteProvider`, optionally set `tier` (`free` | `pro` | `enterprise`) and `enabledPatterns`. Use `SafeInput` / `SafeTextArea` or rely on the provider’s capture-phase paste handler. Call `useSafePaste()` for programmatic `sanitize` and vault access.

Core modules (`Vault`, `Tokenizer`, `THREAT_PATTERNS`) are free of browser APIs and run in Node or the browser.

## License

PROPRIETARY — LogicGrid AI LLC.
