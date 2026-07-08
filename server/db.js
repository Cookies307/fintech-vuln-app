const initSqlJs = require('sql.js');

let SQL, db;

// VULN NOTE: no parameter binding helper is exported on purpose here for the
// legacy REST routes below — routes/legacy.js builds raw SQL strings so you
// have a real, working SQL Injection to practice against.

async function initDb() {
  SQL = await initSqlJs();
  db = new SQL.Database();

  db.run(`
    CREATE TABLE users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password TEXT,          -- VULN: stored in plaintext (bad practice, also useful for SQLi UNION demo)
      role TEXT DEFAULT 'user',
      email TEXT,
      balance REAL DEFAULT 1000,
      ssn TEXT                -- sensitive field, should never be exposed - watch for over-fetching in GraphQL
    );

    CREATE TABLE accounts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      iban TEXT,
      balance REAL
    );

    CREATE TABLE transactions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      from_account INTEGER,
      to_account INTEGER,
      amount REAL,
      note TEXT,               -- stored XSS candidate: rendered unescaped on the dashboard
      created_at TEXT
    );

    CREATE TABLE messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      body TEXT,               -- stored XSS candidate: support chat / feedback box
      created_at TEXT
    );
  `);

  const users = [
    ['admin', 'S3cur3P@ssw0rd!', 'admin', 'admin@vulnbank.local', 500000, '111-11-1111'],
    ['alice', 'alice123', 'user', 'alice@vulnbank.local', 4200, '222-22-2222'],
    ['bob', 'bobpass', 'user', 'bob@vulnbank.local', 1500, '333-33-3333'],
    ['mostafa', 'mostafa2024', 'user', 'mostafa@vulnbank.local', 9800, '444-44-4444'],
  ];
  const insUser = db.prepare('INSERT INTO users (username,password,role,email,balance,ssn) VALUES (?,?,?,?,?,?)');
  for (const u of users) insUser.run(u);
  insUser.free();

  const accounts = [
    [1, 'EG-ADM-0001', 500000],
    [2, 'EG-ALC-1001', 4200],
    [3, 'EG-BOB-1002', 1500],
    [4, 'EG-MST-1003', 9800],
  ];
  const insAcc = db.prepare('INSERT INTO accounts (user_id, iban, balance) VALUES (?,?,?)');
  for (const a of accounts) insAcc.run(a);
  insAcc.free();

  const txs = [
    [2, 3, 100, 'lunch money', '2026-06-01'],
    [3, 2, 50, 'thanks!', '2026-06-02'],
    [4, 2, 300, 'rent share', '2026-06-03'],
  ];
  const insTx = db.prepare('INSERT INTO transactions (from_account, to_account, amount, note, created_at) VALUES (?,?,?,?,?)');
  for (const t of txs) insTx.run(t);
  insTx.free();

  return db;
}

function getDb() {
  if (!db) throw new Error('DB not initialized yet');
  return db;
}

// Helper to run a raw SQL string and return rows as objects (used deliberately
// by the vulnerable legacy routes to build realistic, exploitable SQLi).
function rawQuery(sql) {
  const results = db.exec(sql); // sql.js: no auto param binding here -> concatenated strings are truly vulnerable
  if (!results.length) return [];
  const { columns, values } = results[0];
  return values.map(row => Object.fromEntries(columns.map((c, i) => [c, row[i]])));
}

// Safe helper for internal, non-attacker-controlled queries (parameterized)
function safeAll(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}

function safeGet(sql, params = []) {
  const rows = safeAll(sql, params);
  return rows[0] || null;
}

function run(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.run(params);
  stmt.free();
}

module.exports = { initDb, getDb, rawQuery, safeAll, safeGet, run };
