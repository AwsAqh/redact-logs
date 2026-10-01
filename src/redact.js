/**
 * @file redact.js
 * Core redaction library - redacts PII and secrets from data structures.
 * Never mutates input; returns a new redacted copy.
 */

const {
  PATTERNS,
  DEFAULT_REDACT_KEYS
} = require('./patterns');

/**
 * Default options for redaction
 * @typedef {Object} RedactOptions
 * @property {string[]} [keys] - Additional keys to redact (case-insensitive)
 * @property {Object<string, {regex: RegExp, validator?: Function, replacement: string}>} [patterns] - Custom patterns to add/override
 * @property {Function} [replacement] - Custom replacement function (match, patternName) => string
 * @property {number} [maxDepth=10] - Maximum recursion depth to prevent stack overflow
 */

/**
 * Redacts sensitive data from a value (string, object, array, primitive)
 * @param {*} input - The value to redact (string, object, array, or primitive)
 * @param {RedactOptions} [options] - Redaction options
 * @returns {*} A NEW redacted copy of the input (never mutates original)
 */
function redact(input, options = {}) {
  const opts = {
    keys: [...DEFAULT_REDACT_KEYS, ...(options.keys || [])],
    patterns: { ...PATTERNS, ...(options.patterns || {}) },
    replacement: options.replacement,
    maxDepth: options.maxDepth ?? 10
  };

  // Normalize keys to lowercase for case-insensitive matching
  const redactKeys = new Set(opts.keys.map(k => k.toLowerCase()));

  // Track seen objects for circular reference detection
  const seen = new WeakSet();

  /**
   * Redacts a string value using all configured patterns
   * @param {string} str - String to redact
   * @returns {string} Redacted string
   */
  function redactString(str) {
    if (typeof str !== 'string' || str.length === 0) return str;

    let result = str;

    for (const [patternName, patternConfig] of Object.entries(opts.patterns)) {
      const { regex, validator, replacement } = patternConfig;
      const replacer = opts.replacement || (() => replacement);

      // Reset regex lastIndex for global regexes
      regex.lastIndex = 0;

      result = result.replace(regex, (match, ...args) => {
        // If validator exists, only redact if it passes
        if (validator && !validator(match)) {
          return match;
        }
        return replacer(match, patternName, ...args);
      });
    }

    return result;
  }

  /**
   * Main recursive redaction function
   * @param {*} value - Value to redact
   * @param {number} depth - Current recursion depth
   * @param {string|null} parentKey - Key name of parent (for key-based redaction)
   * @returns {*} Redacted value
   */
  function redactValue(value, depth = 0, parentKey = null) {
    // Handle primitives and null/undefined
    if (value === null || value === undefined) return value;
    if (typeof value !== 'object') {
      // Redact strings, leave other primitives (numbers, booleans, symbols) as-is
      if (typeof value === 'string') {
        // Check if parent key should trigger redaction
        if (parentKey && redactKeys.has(parentKey.toLowerCase())) {
          return '[REDACTED]';
        }
        return redactString(value);
      }
      return value;
    }

    // Handle Date objects
    if (value instanceof Date) return value;

    // Handle Buffer/Uint8Array
    if (Buffer.isBuffer(value) || value instanceof Uint8Array) return value;

    // Check recursion depth
    if (depth >= opts.maxDepth) {
      return '[MAX_DEPTH_EXCEEDED]';
    }

    // Check for circular references
    if (seen.has(value)) {
      return '[Circular]';
    }

    // Track this object
    seen.add(value);

    try {
      // Handle arrays
      if (Array.isArray(value)) {
        return value.map((item, index) => redactValue(item, depth + 1, String(index)));
      }

      // Handle plain objects
      const result = {};
      for (const [key, val] of Object.entries(value)) {
        const lowerKey = key.toLowerCase();
        const shouldRedactKey = redactKeys.has(lowerKey);

        if (shouldRedactKey) {
          // Key-based redaction: fully replace the value
          result[key] = '[REDACTED]';
        } else {
          // Recursively redact the value, passing the key for context
          result[key] = redactValue(val, depth + 1, key);
        }
      }
      return result;
    } finally {
      // Clean up: remove from seen set to allow same object in different branches
      seen.delete(value);
    }
  }

  return redactValue(input);
}

module.exports = { redact };