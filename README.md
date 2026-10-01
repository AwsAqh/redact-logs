# redact-logs

**An Express middleware + core library that redacts PII and secrets from data before it reaches your logs.**

## The Problem

Logging request bodies, headers, and query params is essential for debugging—but it accidentally captures passwords, credit cards, emails, tokens, and other sensitive data. `redact-logs` automatically strips PII and secrets *before* they hit your log files, SIEM, or observability platform.

## Install

```bash
npm install @awsaqh/redact-logs
```

## Quick Start (3 lines)

```js
const express = require('express');
const { redactLogs } = require('@awsaqh/redact-logs');

const app = express();
app.use(express.json());
app.use(redactLogs());  // ← That's it!

app.post('/login', (req, res) => {
  // Safe to log: req.redacted.body has emails, cards, tokens replaced
  console.log('Login attempt:', req.redacted.body);
  // Original req.body is untouched for your app logic
  res.json({ ok: true });
});
```

## Before / After

**Request:**
```json
POST /login
{
  "email": "alice@example.com",
  "phone": "+1-555-123-4567",
  "password": "hunter2",
  "card": "4111 1111 1111 1111",
  "token": "eyJhbGciOiJIUzI1NiIs..."
}
```

**Logged via `req.redacted.body`:**
```json
{
  "email": "[REDACTED_EMAIL]",
  "phone": "[REDACTED_PHONE]",
  "password": "[REDACTED]",
  "card": "[REDACTED_CARD]",
  "token": "[REDACTED_JWT]"
}
```

## API Reference

### `redact(input, options?)`

Core function. Accepts a string, array, or nested object and returns a **new** redacted copy (never mutates input).

```js
const { redact } = require('@awsaqh/redact-logs');

redact('Email: user@test.com');
// → 'Email: [REDACTED_EMAIL]'

redact({ password: 'secret', user: { email: 'a@b.com' } });
// → { password: '[REDACTED]', user: { email: '[REDACTED_EMAIL]' } }
```

**Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `keys` | `string[]` | `[]` | Additional key names to redact (case-insensitive) |
| `patterns` | `Object` | `{}` | Custom regex patterns to add/override |
| `replacement` | `Function` | built-in | Custom replacement: `(match, patternName) => string` |
| `maxDepth` | `number` | `10` | Maximum recursion depth (circular protection) |

---

### `redactLogs(options?)`

Express middleware. Attaches `req.redacted = { body, query, params, headers }` with redacted copies. **Does not modify** the real `req` object.

```js
const { redactLogs } = require('@awsaqh/redact-logs');
app.use(redactLogs());
```

**Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `keys` | `string[]` | `[]` | Extra keys to redact |
| `patterns` | `Object` | `{}` | Custom patterns |
| `replacement` | `Function` | built-in | Custom replacement function |
| `maxDepth` | `number` | `10` | Recursion limit |
| `include` | `string[]` | `['body','query','params','headers']` | Which req properties to redact |

---

### `redactFormat(options?)`

Helper for morgan/winston/pino. Returns a function `(req) => redactedObject`.

```js
const { redactFormat } = require('@awsaqh/redact-logs');
const morgan = require('morgan');

const format = redactFormat();
app.use(morgan((tokens, req, res) => {
  return JSON.stringify(format(req));
}));
```

## How It Works

### Value-Based Redaction (Regex Patterns)
Scans **string values** for known PII formats and replaces them:

| Pattern | Replacement | Notes |
|---------|-------------|-------|
| Email | `[REDACTED_EMAIL]` | RFC 5322 compliant |
| Phone | `[REDACTED_PHONE]` | Intl + local formats |
| Credit Card | `[REDACTED_CARD]` | 13-19 digits, **validated with Luhn** |
| JWT | `[REDACTED_JWT]` | Standard `header.payload.signature` |
| Bearer Token | `[REDACTED_TOKEN]` | 20+ char alphanumeric |

### Key-Based Redaction (Field Names)
Redacts **entire value** regardless of content if key name matches (case-insensitive):

```
password, passwd, secret, token, authorization,
api_key, apikey, cookie, set-cookie,
access_token, refresh_token, client_secret,
private_key, auth
```

Key-based redaction takes priority over value-based.

## Custom Patterns

```js
const { redact } = require('@awsaqh/redact-logs');

const result = redact('SSN: 123-45-6789', {
  patterns: {
    ssn: {
      regex: /\b\d{3}-\d{2}-\d{4}\b/g,
      replacement: '[REDACTED_SSN]'
    }
  }
});
// → 'SSN: [REDACTED_SSN]'
```

## Custom Replacement Function

```js
redact('user@test.com', {
  replacement: (match, patternName) => `[FILTERED:${patternName.toUpperCase()}]`
});
// → '[FILTERED:EMAIL]'
```

## Limitations

- **Regex-based detection** can miss edge cases or produce false positives
- **Not a compliance guarantee** — use as a defense-in-depth layer, not sole protection
- **Does not parse** multipart/form-data, XML, or binary protocols
- **Performance**: Very large payloads (>1MB) may add latency; consider sampling

## Design Decisions

1. **Zero runtime dependencies** — Only `node:test` for testing; keeps supply chain small
2. **Immutability by default** — Never mutates input; safe for concurrent request handling
3. **Luhn validation for cards** — Reduces false positives on 16-digit numbers that aren't cards
4. **Non-enumerable `req.redacted`** — Won't accidentally appear in `JSON.stringify(req)` or default loggers
5. **Separate core + middleware** — Core `redact()` works standalone (CLI tools, workers, tests)

## Roadmap

- **v0.3**: ASP.NET Core port (`RedactLogs.AspNetCore` NuGet package)
- **v0.4**: Structured logging integrations (pino, winston, bunyan presets)
- **v1.0**: Stable API, WASM build for edge runtimes

## License

MIT © redact-logs contributors