const express = require('express');
const router = express.Router();
const http = require('http');
const https = require('https');
const { rawQuery, safeAll, safeGet, run } = require('../db');
const jwtUtil = require('../jwtUtil');

// ---------------------------------------------------------------------------
// AUTH
// ---------------------------------------------------------------------------

// VULN: SQL Injection (classic, auth-bypass style) — username/password are
// concatenated directly into the query. Try: username = admin' -- 
router.post('/login', (req, res) => {
  const { username, password } = req.body;
  const sql = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  try {
    const rows = rawQuery(sql);
    if (rows.length > 0) {
      const user = rows[0];
      const token = jwtUtil.sign({ id: user.id, username: user.username, role: user.role });
      return res.json({ token, user: { id: user.id, username: user.username, role: user.role } });
    }
    return res.status(401).json({ error: 'invalid credentials' });
  } catch (e) {
    // VULN: verbose SQL error leakage back to the client — helps confirm/exploit SQLi
    return res.status(500).json({ error: 'query failed', detail: String(e) });
  }
});

router.post('/register', (req, res) => {
  const { username, password, email } = req.body;
  run('INSERT INTO users (username, password, email, role) VALUES (?,?,?,?)', [username, password, email, 'user']);
  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// MIDDLEWARE: "auth" that only checks the token is valid, never who owns what
// ---------------------------------------------------------------------------
function authRequired(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.replace('Bearer ', '');
  try {
    req.user = jwtUtil.verify(token);
    next();
  } catch (e) {
    res.status(401).json({ error: 'unauthorized' });
  }
}

// ---------------------------------------------------------------------------
// IDOR: /api/accounts/:id and /api/transactions/:id never check that the
// account/transaction belongs to req.user — any authenticated user can read
// (and in the transfer endpoint below, even write) any account by ID.
// ---------------------------------------------------------------------------
router.get('/accounts/:id', authRequired, (req, res) => {
  const acc = safeGet('SELECT * FROM accounts WHERE id = ?', [req.params.id]);
  if (!acc) return res.status(404).json({ error: 'not found' });
  res.json(acc); // no ownership check -> IDOR
});

router.get('/transactions/:id', authRequired, (req, res) => {
  const tx = safeGet('SELECT * FROM transactions WHERE id = ?', [req.params.id]);
  if (!tx) return res.status(404).json({ error: 'not found' });
  res.json(tx); // no ownership check -> IDOR
});

// VULN: Broken Access Control (function-level) — role is trusted from the
// client-supplied JWT payload only; there's no server-side re-check against
// a source of truth, and the /admin endpoints only "check" req.user.role
// which an attacker can forge if they crack the weak JWT secret.
router.get('/admin/users', authRequired, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'forbidden' });
  const rows = safeAll('SELECT id, username, role, email, balance, ssn FROM users'); // also: sensitive SSN over-exposure
  res.json(rows);
});

// VULN: IDOR + missing amount validation (business logic) on money transfer.
// Any authenticated user can move funds from ANY from_account to any
// to_account, including negative amounts (reverse a transfer / create money).
router.post('/transfer', authRequired, (req, res) => {
  const { from_account, to_account, amount, note } = req.body;
  const from = safeGet('SELECT * FROM accounts WHERE id = ?', [from_account]);
  const to = safeGet('SELECT * FROM accounts WHERE id = ?', [to_account]);
  if (!from || !to) return res.status(404).json({ error: 'account not found' });
  // no check that from.user_id === req.user.id
  // no check that amount > 0
  run('UPDATE accounts SET balance = balance - ? WHERE id = ?', [amount, from.id]);
  run('UPDATE accounts SET balance = balance + ? WHERE id = ?', [amount, to.id]);
  run('INSERT INTO transactions (from_account, to_account, amount, note, created_at) VALUES (?,?,?,?,datetime())',
    [from.id, to.id, amount, note || '']); // note is stored raw -> stored XSS when rendered on dashboard.html
  res.json({ ok: true });
});

// VULN: reflected XSS — 'q' is echoed back inside an HTML fragment unescaped.
router.get('/search', (req, res) => {
  const q = req.query.q || '';
  res.send(`<div class="search-results">Results for: ${q}</div>`); // no encoding
});

// VULN: stored XSS via support messages, rendered unescaped by the frontend.
router.post('/messages', authRequired, (req, res) => {
  run('INSERT INTO messages (user_id, body, created_at) VALUES (?,?,datetime())', [req.user.id, req.body.body]);
  res.json({ ok: true });
});
router.get('/messages', (req, res) => {
  res.json(safeAll('SELECT * FROM messages ORDER BY id DESC'));
});

// ---------------------------------------------------------------------------
// SSRF: "avatar import" / "invoice fetch" fetches a server-supplied URL with
// no allow-list, no protocol restriction, and no block on internal ranges.
// Try: http://127.0.0.1:4000/api/admin/users or http://169.254.169.254/ (cloud metadata)
// ---------------------------------------------------------------------------
router.post('/import-avatar', authRequired, (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'url required' });
  const lib = url.startsWith('https') ? https : http;
  try {
    lib.get(url, (upstream) => {
      let data = [];
      upstream.on('data', (c) => data.push(c));
      upstream.on('end', () => {
        // VULN (blind-SSRF-friendly too): even if we didn't return the body,
        // the fetch itself already happened server-side.
        res.json({
          status: upstream.statusCode,
          headers: upstream.headers,
          bodyPreview: Buffer.concat(data).toString('utf8').slice(0, 500),
        });
      });
    }).on('error', (e) => res.status(500).json({ error: String(e) }));
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

module.exports = router;
