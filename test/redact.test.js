/**
 * @file redact.test.js
 * Tests for the core redact library
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { redact } = require('../src/redact');

describe('redact()', () => {
  describe('primitives and nullish', () => {
    it('returns null unchanged', () => {
      assert.equal(redact(null), null);
    });

    it('returns undefined unchanged', () => {
      assert.equal(redact(undefined), undefined);
    });

    it('returns numbers unchanged', () => {
      assert.equal(redact(42), 42);
      assert.equal(redact(0), 0);
      assert.equal(redact(-1.5), -1.5);
    });

    it('returns booleans unchanged', () => {
      assert.equal(redact(true), true);
      assert.equal(redact(false), false);
    });

    it('returns empty string unchanged', () => {
      assert.equal(redact(''), '');
    });

    it('returns symbols unchanged', () => {
      const sym = Symbol('test');
      assert.equal(redact(sym), sym);
    });
  });

  describe('string value-based redaction', () => {
    it('redacts email addresses', () => {
      const input = 'Contact us at user@example.com or admin@test.org';
      const result = redact(input);
      assert.ok(result.includes('[REDACTED_EMAIL]'));
      assert.ok(!result.includes('user@example.com'));
      assert.ok(!result.includes('admin@test.org'));
    });

    it('redacts phone numbers (US format)', () => {
      const input = 'Call 555-123-4567 or (555) 987-6543';
      const result = redact(input);
      assert.ok(result.includes('[REDACTED_PHONE]'));
      assert.ok(!result.includes('555-123-4567'));
    });

    it('redacts international phone numbers', () => {
      const input = 'Call +1-555-123-4567 or +44 20 7946 0958';
      const result = redact(input);
      assert.ok(result.includes('[REDACTED_PHONE]'));
    });

    it('redacts credit card numbers (valid Luhn)', () => {
      const input = 'Card: 4111 1111 1111 1111';
      const result = redact(input);
      assert.ok(result.includes('[REDACTED_CARD]'));
      assert.ok(!result.includes('4111 1111 1111 1111'));
    });

    it('does NOT redact invalid credit card numbers (fails Luhn)', () => {
      const input = 'Card: 4111 1111 1111 1112';
      const result = redact(input);
      assert.ok(!result.includes('[REDACTED_CARD]'));
      assert.ok(result.includes('4111 1111 1111 1112'));
    });

    it('redacts JWT tokens', () => {
      const jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
      const input = `Token: ${jwt}`;
      const result = redact(input);
      assert.ok(result.includes('[REDACTED_JWT]'));
      assert.ok(!result.includes(jwt));
    });

    it('redacts Bearer tokens', () => {
      const input = 'Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456';
      const result = redact(input);
      assert.ok(result.includes('[REDACTED_TOKEN]'));
    });

    it('redacts multiple patterns in one string', () => {
      const input = 'Email: user@test.com, Phone: 555-123-4567, Card: 4111111111111111';
      const result = redact(input);
      assert.ok(result.includes('[REDACTED_EMAIL]'));
      assert.ok(result.includes('[REDACTED_PHONE]'));
      assert.ok(result.includes('[REDACTED_CARD]'));
    });
    describe('nested objects and arrays', () => {
      it('redacts nested object values', () => {
        const input = {
          user: {
            email: 'user@test.com',
            profile: {
              phone: '555-123-4567'
            }
          }
        };
        const result = redact(input);
        assert.equal(result.user.email, '[REDACTED_EMAIL]');
        assert.equal(result.user.profile.phone, '[REDACTED_PHONE]');
      });

      it('redacts array elements', () => {
        const input = {
          emails: ['a@test.com', 'b@test.com'],
          phones: ['555-123-4567']
        };
        const result = redact(input);
        assert.equal(result.emails[0], '[REDACTED_EMAIL]');
        assert.equal(result.emails[1], '[REDACTED_EMAIL]');
        assert.equal(result.phones[0], '[REDACTED_PHONE]');
      });

      it('redacts nested arrays', () => {
        const input = {
          data: [
            { email: 'nested@test.com' },
            ['deep@test.com', '555-123-4567']
          ]
        };
        const result = redact(input);
        assert.equal(result.data[0].email, '[REDACTED_EMAIL]');
        assert.equal(result.data[1][0], '[REDACTED_EMAIL]');
        assert.equal(result.data[1][1], '[REDACTED_PHONE]');
      });

      it('redacts keys in nested objects', () => {
        const input = {
          user: {
            credentials: {
              password: 'secret'
            }
          }
        };
        const result = redact(input);
        assert.equal(result.user.credentials.password, '[REDACTED]');
      });
    });

    describe('immutability', () => {
      it('does not mutate input object', () => {
        const input = { password: 'secret', email: 'user@test.com' };
        const originalPassword = input.password;
        const originalEmail = input.email;
        redact(input);
        assert.equal(input.password, originalPassword);
        assert.equal(input.email, originalEmail);
      });

      it('does not mutate input array', () => {
        const input = ['user@test.com', '555-123-4567'];
        const original0 = input[0];
        const original1 = input[1];
        redact(input);
        assert.equal(input[0], original0);
        assert.equal(input[1], original1);
      });

      it('returns new object (not same reference)', () => {
        const input = { email: 'user@test.com' };
        const result = redact(input);
        assert.notStrictEqual(result, input);
      });

      it('returns new array (not same reference)', () => {
        const input = ['user@test.com'];
        const result = redact(input);
        assert.notStrictEqual(result, input);
      });
    });

    describe('circular references', () => {
      it('handles circular object references', () => {
        const obj = { name: 'test' };
        obj.self = obj;
        const result = redact(obj);
        assert.equal(result.self, '[Circular]');
      });

      it('handles circular array references', () => {
        const arr = ['item'];
        arr.push(arr);
        const result = redact(arr);
        assert.equal(result[1], '[Circular]');
      });

      it('handles complex circular structures', () => {
        const a = { name: 'a' };
        const b = { name: 'b', ref: a };
        a.ref = b;
        const result = redact(a);
        assert.equal(result.ref.ref, '[Circular]');
      });
    });
    describe('special objects', () => {
      it('preserves Date objects', () => {
        const date = new Date('2024-01-01');
        const input = { created: date };
        const result = redact(input);
        assert.ok(result.created instanceof Date);
        assert.equal(result.created.getTime(), date.getTime());
      });

      it('preserves Buffer objects', () => {
        const buf = Buffer.from('test');
        const input = { data: buf };
        const result = redact(input);
        assert.ok(Buffer.isBuffer(result.data));
        assert.equal(result.data.toString(), 'test');
      });

      it('preserves Uint8Array objects', () => {
        const arr = new Uint8Array([1, 2, 3]);
        const input = { data: arr };
        const result = redact(input);
        assert.ok(result.data instanceof Uint8Array);
      });

      it('handles very large strings', () => {
        const largeStr = 'a'.repeat(100000) + ' user@test.com ' + 'b'.repeat(100000);
        const result = redact(largeStr);
        assert.ok(result.includes('[REDACTED_EMAIL]'));
        assert.ok(result.length >= 100000);
      });
    });

    describe('custom options', () => {
      it('accepts custom keys to redact', () => {
        const input = { custom_secret: 'value', normal: 'keep' };
        const result = redact(input, { keys: ['custom_secret'] });
        assert.equal(result.custom_secret, '[REDACTED]');
        assert.equal(result.normal, 'keep');
      });

      it('accepts custom patterns', () => {
        const customPatterns = {
          ssn: {
            regex: /\b\d{3}-\d{2}-\d{4}\b/g,
            replacement: '[REDACTED_SSN]'
          }
        };
        const input = 'SSN: 123-45-6789';
        const result = redact(input, { patterns: customPatterns });
        assert.equal(result, 'SSN: [REDACTED_SSN]');
      });

      it('accepts custom replacement function', () => {
        const input = 'Email: user@test.com';
        const result = redact(input, {
          replacement: (match, patternName) => `[CUSTOM_${patternName.toUpperCase()}]`
        });
        assert.equal(result, 'Email: [CUSTOM_EMAIL]');
      });

      it('respects maxDepth option', () => {
        const deep = { level: 0 };
        let current = deep;
        for (let i = 1; i <= 15; i++) {
          current.nested = { level: i };
          current = current.nested;
        }
        current.email = 'deep@test.com';

        const result = redact(deep, { maxDepth: 5 });
        assert.ok(JSON.stringify(result).includes('[MAX_DEPTH_EXCEEDED]'));
      });

      it('defaults maxDepth to 10', () => {
        const deep = { level: 0 };
        let current = deep;
        for (let i = 1; i <= 12; i++) {
          current.nested = { level: i };
          current = current.nested;
        }
        current.email = 'deep@test.com';

        const result = redact(deep);
        assert.ok(JSON.stringify(result).includes('[MAX_DEPTH_EXCEEDED]'));
      });
    });

    describe('edge cases', () => {
      it('handles empty object', () => {
        assert.deepEqual(redact({}), {});
      });

      it('handles empty array', () => {
        assert.deepEqual(redact([]), []);
      });

      it('handles string with no PII', () => {
        const input = 'Hello world';
        assert.equal(redact(input), 'Hello world');
      });

      it('handles object with no sensitive data', () => {
        const input = { name: 'John', age: 30 };
        const result = redact(input);
        assert.deepEqual(result, input);
      });

      it('does not redact numbers that look like phones', () => {
        const input = { phone: 5551234567 };
        const result = redact(input);
        assert.equal(result.phone, 5551234567);
      });

      it('redacts string numbers that look like phones', () => {
        const input = { phone: '555-123-4567' };
        const result = redact(input);
        assert.equal(result.phone, '[REDACTED_PHONE]');
      });
    });
  });
});