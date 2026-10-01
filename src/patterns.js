/**
 * @file patterns.js
 * Regex patterns and Luhn algorithm for PII/secret detection.
 * All patterns are designed to be conservative to minimize false positives.
 */

// Email regex - RFC 5322 compliant (simplified for practical use)
// Matches standard email formats including subdomains and TLDs
const EMAIL_REGEX = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;

// Phone number regex - International and local formats
// Matches: +1-555-123-4567, +44 20 7946 0958, (555) 123-4567, 555-123-4567, 555.123.4567
// Conservative: matches standard 3-3-4 (US) or 2-4-4 (UK) digit groupings with separators
// Avoids matching long digit sequences (credit cards have 13-19 digits, typically 4-4-4-4)
const PHONE_REGEX = /(?:\+?\d{1,3}[\s.-])?(?:\(\d{3}\)[\s.-]?|\d{3}[\s.-])\d{3}[\s.-]\d{4}\b|(?:\+?\d{1,3}[\s.-])\d{2}[\s.-]\d{4}[\s.-]\d{4}\b/g;

// Credit card regex - 13-19 digits (major card brands)
// Luhn validation is applied separately to avoid false positives
// Matches: 4111 1111 1111 1111, 5555-5555-5555-5555, 378282246310005
const CARD_REGEX = /\b(?:\d[ -]*?){13,19}\b/g;

// JWT regex - Matches standard JWT format: header.payload.signature
// Each part is base64url encoded, separated by dots
const JWT_REGEX = /\beyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\b/g;

// Bearer token regex - Matches "Bearer " followed by token
// Common in Authorization headers, also catches bare tokens that look like bearer tokens
// Avoids matching long repetitive strings (e.g., 'aaaaaaaa...') by requiring mixed content
const BEARER_REGEX = /\b(?:Bearer\s+)?(?=.*[A-Za-z])(?=.*\d)[A-Za-z0-9_-]{20,}\b/g;

/**
 * Luhn algorithm (mod 10) checksum validation
 * Used to validate credit card numbers and reduce false positives
 * @param {string} digits - String containing only digits
 * @returns {boolean} True if valid Luhn checksum
 */
function luhnCheck(digits) {
  let sum = 0;
  let isEven = false;

  // Process from right to left
  for (let i = digits.length - 1; i >= 0; i--) {
    let digit = parseInt(digits[i], 10);

    if (isEven) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }

    sum += digit;
    isEven = !isEven;
  }

  return sum % 10 === 0;
}

/**
 * Validates a potential credit card number using Luhn algorithm
 * First strips non-digits, then validates length (13-19) and checksum
 * @param {string} candidate - Potential credit card number
 * @returns {boolean} True if valid credit card number
 */
function isValidCard(candidate) {
  const digits = candidate.replace(/\D/g, '');
  if (digits.length < 13 || digits.length > 19) return false;
  return luhnCheck(digits);
}

/**
 * All built-in patterns for value-based redaction
 * Order matters: more specific patterns (card, jwt) should run before general ones (phone, bearer)
 * @type {Object<string, {regex: RegExp, validator?: Function, replacement: string}>}
 */
const PATTERNS = {
  email: {
    regex: EMAIL_REGEX,
    replacement: '[REDACTED_EMAIL]'
  },
  card: {
    regex: CARD_REGEX,
    validator: isValidCard,
    replacement: '[REDACTED_CARD]'
  },
  jwt: {
    regex: JWT_REGEX,
    replacement: '[REDACTED_JWT]'
  },
  phone: {
    regex: PHONE_REGEX,
    replacement: '[REDACTED_PHONE]'
  },
  bearer: {
    regex: BEARER_REGEX,
    replacement: '[REDACTED_TOKEN]'
  }
};

/**
 * Keys that trigger redaction regardless of value (case-insensitive)
 * These are common secret/password field names
 * @type {string[]}
 */
const DEFAULT_REDACT_KEYS = [
  'password',
  'passwd',
  'secret',
  'token',
  'authorization',
  'api_key',
  'apikey',
  'cookie',
  'set-cookie',
  'access_token',
  'refresh_token',
  'client_secret',
  'private_key',
  'auth'
];

module.exports = {
  PATTERNS,
  DEFAULT_REDACT_KEYS,
  EMAIL_REGEX,
  PHONE_REGEX,
  CARD_REGEX,
  JWT_REGEX,
  BEARER_REGEX,
  luhnCheck,
  isValidCard
};