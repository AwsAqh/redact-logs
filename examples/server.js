/**
 * @file server.js
 * Demo Express application showing redact-logs in action.
 * Run with: node examples/server.js
 */

const express = require('express');
const { redactLogs, redactFormat } = require('../src/index');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Apply redaction middleware
app.use(redactLogs());

// Also demonstrate redactFormat for use with morgan/winston/pino
const logFormat = redactFormat();
app.use((req, res, next) => {
  // In real app, you'd pass logFormat(req) to your logger
  req.logData = logFormat(req);
  next();
});

// Simulated logger
function log(level, message, data) {
  console.log(`[${new Date().toISOString()}] ${level}: ${message}`, JSON.stringify(data, null, 2));
}

// Routes
app.get('/', (req, res) => {
  res.send(`
    <h1>redact-logs Demo</h1>
    <p>Try these endpoints:</p>
    <ul>
      <li><a href="/login">GET /login</a> - Shows login form</li>
      <li>POST /login - Submit credentials (check console)</li>
      <li>POST /api/data - Submit JSON with PII</li>
      <li>GET /search?q=test@email.com - Query params</li>
      <li>GET /user/555-123-4567 - Route params</li>
    </ul>
  `);
});

app.get('/login', (req, res) => {
  res.send(`
    <form method="POST" action="/login">
      <label>Email: <input name="email" type="email" value="user@example.com"></label><br>
      <label>Phone: <input name="phone" value="555-123-4567"></label><br>
      <label>Password: <input name="password" type="password" value="secret123"></label><br>
      <label>Credit Card: <input name="card" value="4111 1111 1111 1111"></label><br>
      <button type="submit">Submit</button>
    </form>
  `);
});

app.post('/login', (req, res) => {
  // Log the redacted version (safe for logs)
  log('INFO', 'Login attempt', req.redacted);
  
  // Also show what the logger would see via redactFormat
  log('INFO', 'Logger format output', req.logData);

  // Original req.body is untouched - app logic works normally
  const { email, password } = req.body;
  
  // Simulate auth
  const success = email && password;
  
  res.json({
    success,
    message: success ? 'Login successful' : 'Invalid credentials',
    // Show that original data is intact for business logic
    receivedEmail: email,
    // Show redacted version for comparison
    redacted: req.redacted.body
  });
});

app.post('/api/data', (req, res) => {
  log('INFO', 'API data received', req.redacted);
  
  res.json({
    message: 'Data received',
    redacted: req.redacted.body,
    originalKeys: Object.keys(req.body)
  });
});

app.get('/search', (req, res) => {
  log('INFO', 'Search request', req.redacted);
  
  res.json({
    query: req.query,
    redacted: req.redacted.query
  });
});

app.get('/user/:id', (req, res) => {
  log('INFO', 'User lookup', req.redacted);
  
  res.json({
    params: req.params,
    redacted: req.redacted.params
  });
});

app.post('/headers', (req, res) => {
  log('INFO', 'Headers test', req.redacted);
  
  res.json({
    headers: req.headers,
    redacted: req.redacted.headers
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n🚀 redact-logs demo server running on http://localhost:${PORT}`);
  console.log('Try submitting the login form or calling the API endpoints.');
  console.log('Check the console to see redacted logs.\n');
});