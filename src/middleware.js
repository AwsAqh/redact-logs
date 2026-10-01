/**
 * @file middleware.js
 * Express middleware for automatic request redaction.
 * Attaches redacted copies to req.redacted without modifying original req.
 */

const { redact } = require('./redact');

/**
 * Default options for middleware
 * @typedef {Object} MiddlewareOptions
 * @property {string[]} [keys] - Additional keys to redact
 * @property {Object} [patterns] - Custom patterns
 * @property {Function} [replacement] - Custom replacement function
 * @property {number} [maxDepth=10] - Maximum recursion depth
 * @property {string[]} [include] - Which req properties to redact (default: ['body', 'query', 'params', 'headers'])
 */

/**
 * Express middleware that attaches redacted request data to req.redacted
 * Uses a getter so params are available when accessed (after routing)
 * @param {MiddlewareOptions} [options] - Middleware options
 * @returns {Function} Express middleware function
 */
function redactLogs(options = {}) {
  const opts = {
    keys: options.keys,
    patterns: options.patterns,
    replacement: options.replacement,
    maxDepth: options.maxDepth,
    include: options.include || ['body', 'query', 'params', 'headers']
  };

  return function redactLogsMiddleware(req, res, next) {
    // Define req.redacted as a getter that computes on demand
    // This ensures req.params is populated (router runs before route handler)
    // Use 'prop in req' instead of hasOwnProperty because Express uses getters for headers, params, etc.
    Object.defineProperty(req, 'redacted', {
      get() {
        const redacted = {};
        for (const prop of opts.include) {
          if (prop in this && this[prop] !== undefined) {
            redacted[prop] = redact(this[prop], {
              keys: opts.keys,
              patterns: opts.patterns,
              replacement: opts.replacement,
              maxDepth: opts.maxDepth
            });
          }
        }
        return redacted;
      },
      enumerable: false,
      configurable: true
    });

    next();
  };
}

/**
 * Creates a log format function for use with morgan, winston, pino, etc.
 * Returns a function that takes req and returns a redacted object suitable for logging.
 * @param {MiddlewareOptions} [options] - Redaction options
 * @returns {Function} Format function: (req) => redactedObject
 */
function redactFormat(options = {}) {
  const opts = {
    keys: options.keys,
    patterns: options.patterns,
    replacement: options.replacement,
    maxDepth: options.maxDepth,
    include: options.include || ['body', 'query', 'params', 'headers']
  };

  return function formatRedacted(req) {
    const redacted = {};

    for (const prop of opts.include) {
      if (prop in req && req[prop] !== undefined) {
        redacted[prop] = redact(req[prop], {
          keys: opts.keys,
          patterns: opts.patterns,
          replacement: opts.replacement,
          maxDepth: opts.maxDepth
        });
      }
    }

    return redacted;
  };
}

module.exports = { redactLogs, redactFormat };