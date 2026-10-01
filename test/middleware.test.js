/**
 * @file middleware.test.js
 * Tests for Express middleware
 */

const { describe, it, before } = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const request = require('supertest');
const { redactLogs, redactFormat } = require('../src/middleware');

describe('redactLogs middleware', () => {
  let app;

  before(() => {
    app = express();
    app.use(express.json());
    app.use(express.urlencoded({ extended: true }));
    app.use(redactLogs());

    app.post('/login', (req, res) => {
      res.json({
        received: req.body,
        redacted: req.redacted
      });
    });

    app.get('/search', (req, res) => {
      res.json({
        query: req.query,
        redacted: req.redacted
      });
    });

    app.get('/user/:id', (req, res) => {
      res.json({
        params: req.params,
        redacted: req.redacted
      });
    });

    app.post('/headers', (req, res) => {
      res.json({
        headers: req.headers,
        redacted: req.redacted
      });
    });
  });

  describe('req.body redaction', () => {
    it('redacts email in body', async () => {
      const res = await request(app)
        .post('/login')
        .send({ email: 'user@test.com', password: 'secret123' })
        .expect(200);

      assert.ok(res.body.redacted.body.email === '[REDACTED_EMAIL]');
      assert.ok(res.body.redacted.body.password === '[REDACTED]');
    });

    it('redacts phone in body', async () => {
      const res = await request(app)
        .post('/login')
        .send({ phone: '555-123-4567' })
        .expect(200);

      assert.ok(res.body.redacted.body.phone === '[REDACTED_PHONE]');
    });

    it('redacts credit card in body', async () => {
      const res = await request(app)
        .post('/login')
        .send({ card: '4111 1111 1111 1111' })
        .expect(200);

      assert.ok(res.body.redacted.body.card === '[REDACTED_CARD]');
    });

    it('does not modify original req.body', async () => {
      const res = await request(app)
        .post('/login')
        .send({ email: 'user@test.com', password: 'secret123' })
        .expect(200);

      assert.ok(res.body.received.email === 'user@test.com');
      assert.ok(res.body.received.password === 'secret123');
    });

    it('handles nested objects in body', async () => {
      const res = await request(app)
        .post('/login')
        .send({
          user: {
            email: 'nested@test.com',
            credentials: {
              password: 'nested-secret'
            }
          }
        })
        .expect(200);

      assert.ok(res.body.redacted.body.user.email === '[REDACTED_EMAIL]');
      assert.ok(res.body.redacted.body.user.credentials.password === '[REDACTED]');
    });

    it('handles arrays in body', async () => {
      const res = await request(app)
        .post('/login')
        .send({ emails: ['a@test.com', 'b@test.com'] })
        .expect(200);

      assert.ok(res.body.redacted.body.emails[0] === '[REDACTED_EMAIL]');
      assert.ok(res.body.redacted.body.emails[1] === '[REDACTED_EMAIL]');
    });
  });

  describe('req.query redaction', () => {
    it('redacts query parameters', async () => {
      const res = await request(app)
        .get('/search?q=user@test.com&api_key=secret')
        .expect(200);

      assert.ok(res.body.redacted.query.q === '[REDACTED_EMAIL]');
      assert.ok(res.body.redacted.query.api_key === '[REDACTED]');
    });

    it('does not modify original req.query', async () => {
      const res = await request(app)
        .get('/search?q=user@test.com')
        .expect(200);

      assert.ok(res.body.query.q === 'user@test.com');
    });
  });

  describe('req.params redaction', () => {
    it('redacts route parameters', async () => {
      const res = await request(app)
        .get('/user/555-123-4567')
        .expect(200);

      assert.ok(res.body.redacted.params.id === '[REDACTED_PHONE]');
    });

    it('does not modify original req.params', async () => {
      const res = await request(app)
        .get('/user/555-123-4567')
        .expect(200);

      assert.ok(res.body.params.id === '555-123-4567');
    });
  });

  describe('req.headers redaction', () => {
    it('redacts authorization header', async () => {
      const res = await request(app)
        .post('/headers')
        .set('Authorization', 'Bearer secret-token')
        .set('Cookie', 'session=abc123')
        .send({})
        .expect(200);

      assert.ok(res.body.redacted.headers.authorization === '[REDACTED]');
      assert.ok(res.body.redacted.headers.cookie === '[REDACTED]');
    });

    it('does not modify original req.headers', async () => {
      const res = await request(app)
        .post('/headers')
        .set('Authorization', 'Bearer secret-token')
        .send({})
        .expect(200);

      assert.ok(res.body.headers.authorization === 'Bearer secret-token');
    });
    describe('custom options', () => {
      it('accepts custom keys', () => {
        const customApp = express();
        customApp.use(express.json());
        customApp.use(redactLogs({ keys: ['custom_field'] }));
        customApp.post('/test', (req, res) => {
          res.json({ redacted: req.redacted });
        });

        return request(customApp)
          .post('/test')
          .send({ custom_field: 'secret', normal: 'keep' })
          .expect(200)
          .then(res => {
            assert.ok(res.body.redacted.body.custom_field === '[REDACTED]');
            assert.ok(res.body.redacted.body.normal === 'keep');
          });
      });

      it('accepts custom patterns', () => {
        const customApp = express();
        customApp.use(express.json());
        customApp.use(redactLogs({
          patterns: {
            ssn: {
              regex: /\b\d{3}-\d{2}-\d{4}\b/g,
              replacement: '[REDACTED_SSN]'
            }
          }
        }));
        customApp.post('/test', (req, res) => {
          res.json({ redacted: req.redacted });
        });

        return request(customApp)
          .post('/test')
          .send({ ssn: '123-45-6789' })
          .expect(200)
          .then(res => {
            assert.ok(res.body.redacted.body.ssn === '[REDACTED_SSN]');
          });
      });

      it('can exclude headers from redaction', () => {
        const customApp = express();
        customApp.use(express.json());
        customApp.use(redactLogs({ include: ['body', 'query'] }));
        customApp.post('/test', (req, res) => {
          res.json({ redacted: req.redacted });
        });

        return request(customApp)
          .post('/test')
          .set('Authorization', 'Bearer token')
          .send({ email: 'test@test.com' })
          .expect(200)
          .then(res => {
            assert.ok(res.body.redacted.body);
            assert.ok(!res.body.redacted.headers);
          });
      });
    });

    describe('req.redacted property', () => {
      it('is non-enumerable', async () => {
        const res = await request(app)
          .post('/login')
          .send({ email: 'user@test.com' })
          .expect(200);

        const keys = Object.keys(res.body.redacted);
        assert.ok(!keys.includes('redacted'));
      });

      it('is present on all requests', async () => {
        const res = await request(app)
          .get('/search?q=test')
          .expect(200);

        assert.ok(res.body.redacted);
        assert.ok(res.body.redacted.query);
      });
    });
  });

  describe('redactFormat helper', () => {
    let app;

    before(() => {
      app = express();
      app.use(express.json());
      const format = redactFormat();
      app.use((req, res, next) => {
        req.logData = format(req);
        next();
      });
      app.post('/test', (req, res) => {
        res.json({ logData: req.logData });
      });
    });

    it('returns redacted object for logging', async () => {
      const res = await request(app)
        .post('/test')
        .send({ email: 'user@test.com', password: 'secret' })
        .expect(200);

      assert.ok(res.body.logData.body.email === '[REDACTED_EMAIL]');
      assert.ok(res.body.logData.body.password === '[REDACTED]');
    });

    it('can be used with custom options', () => {
      const format = redactFormat({
        keys: ['custom_secret'],
        include: ['body']
      });

      const req = {
        body: { custom_secret: 'value', normal: 'keep' },
        query: {},
        params: {},
        headers: {}
      };

      const result = format(req);
      assert.ok(result.body.custom_secret === '[REDACTED]');
      assert.ok(result.body.normal === 'keep');
    });
  });
});