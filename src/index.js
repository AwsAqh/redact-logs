/**
 * @file index.js
 * Main entry point - exports all public APIs
 */

const { redact } = require('./redact');
const { redactLogs, redactFormat } = require('./middleware');
const { PATTERNS, DEFAULT_REDACT_KEYS } = require('./patterns');

module.exports = {
  redact,
  redactLogs,
  redactFormat,
  PATTERNS,
  DEFAULT_REDACT_KEYS
};