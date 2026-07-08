const { buildSchema } = require('graphql');
const { rawQuery, safeAll, safeGet, run } = require('./db');
const jwtUtil = require('./jwtUtil');

// VULN: Introspection is left fully enabled (default) in index.js — in a real
// engagement/production app this is often disabled or gated. Run an
// introspection query first to map the whole schema, including fields
// nobody documented for you (e.g. `ssn`, `internalNotes`).

const schema = buildSchema(`
  type User {
    id: ID
    username: String
    email: String
    role: String
    balance: Float
    ssn: String            # sensitive, should never be schema-exposed like this
  }

  type Account {
    id: ID
    user_id: ID
    iban: String
    balance: Float
  }

  type Transaction {
    id: ID
    from_account: ID
    to_account: ID
    amount: Float
    note: String
    created_at: String
  }

  type LoginResult {
    token: String
    user: User
  }

  type Query {
    me(token: String): User
    user(id: ID!): User                       # IDOR: no auth/ownership check at all
    users(filter: String): [User]             # Injection playground: filter concatenated into SQL
    account(id: ID!): Account                 # IDOR
    transaction(id: ID!): Transaction         # IDOR
    accountsBatch(ids: [ID!]!): [Account]     # Batching / mass-IDOR / brute-force helper
  }

  type Mutation {
    login(username: String!, password: String!): LoginResult
    transfer(token: String!, from_account: ID!, to_account: ID!, amount: Float!, note: String): Transaction
    updateProfile(token: String!, userId: ID!, email: String, role: String): User   # mass-assignment: role is settable!
  }
`);

function userFromToken(token) {
  try { return jwtUtil.verify(token); } catch (e) { return null; }
}

const root = {
  // VULN: 'me' trusts whatever token you hand it and does zero cross-check
  // against a session store, so a forged/tampered JWT (weak secret, alg
  // confusion) is enough to become anyone.
  me: ({ token }) => {
    const decoded = userFromToken(token);
    if (!decoded) return null;
    return safeGet('SELECT * FROM users WHERE id = ?', [decoded.id]);
  },

  // VULN: classic GraphQL IDOR — any caller can fetch any user by ID with no
  // authentication or ownership check at all.
  user: ({ id }) => safeGet('SELECT * FROM users WHERE id = ?', [id]),

  // VULN: SQL injection through a GraphQL argument. `filter` is concatenated
  // directly. Try: filter = "1=1 UNION SELECT id,username,password,role,email,balance,ssn FROM users -- "
  users: ({ filter }) => {
    let sql = 'SELECT id, username, email, role, balance FROM users';
    if (filter) sql += ` WHERE ${filter}`;
    return rawQuery(sql);
  },

  account: ({ id }) => safeGet('SELECT * FROM accounts WHERE id = ?', [id]),       // IDOR
  transaction: ({ id }) => safeGet('SELECT * FROM transactions WHERE id = ?', [id]), // IDOR

  // VULN: batched IDOR / enumeration helper — lets you pull many accounts in
  // one request, which is also useful for testing GraphQL rate-limiting (or
  // the lack thereof) and query-cost controls.
  accountsBatch: ({ ids }) => ids.map(id => safeGet('SELECT * FROM accounts WHERE id = ?', [id])).filter(Boolean),

  login: ({ username, password }) => {
    // Same SQLi pattern as the REST /login, reachable via GraphQL too.
    const sql = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    const rows = rawQuery(sql);
    if (!rows.length) return null;
    const user = rows[0];
    const token = jwtUtil.sign({ id: user.id, username: user.username, role: user.role });
    return { token, user };
  },

  // VULN: IDOR + no amount validation, same business-logic flaw as REST.
  transfer: ({ token, from_account, to_account, amount, note }) => {
    const decoded = userFromToken(token);
    if (!decoded) throw new Error('unauthorized');
    const from = safeGet('SELECT * FROM accounts WHERE id = ?', [from_account]);
    const to = safeGet('SELECT * FROM accounts WHERE id = ?', [to_account]);
    if (!from || !to) throw new Error('account not found');
    // no check that `from` belongs to decoded.id, no amount > 0 check
    run('UPDATE accounts SET balance = balance - ? WHERE id = ?', [amount, from.id]);
    run('UPDATE accounts SET balance = balance + ? WHERE id = ?', [amount, to.id]);
    run('INSERT INTO transactions (from_account, to_account, amount, note, created_at) VALUES (?,?,?,?,datetime())',
      [from.id, to.id, amount, note || '']);
    return safeGet('SELECT * FROM transactions ORDER BY id DESC LIMIT 1');
  },

  // VULN: Mass Assignment — a normal user can pass role: "admin" and the
  // resolver happily writes it, no allow-list of updatable fields, no check
  // that userId === decoded.id.
  updateProfile: ({ token, userId, email, role }) => {
    const decoded = userFromToken(token);
    if (!decoded) throw new Error('unauthorized');
    if (email !== undefined) run('UPDATE users SET email = ? WHERE id = ?', [email, userId]);
    if (role !== undefined) run('UPDATE users SET role = ? WHERE id = ?', [role, userId]); // privilege escalation
    return safeGet('SELECT * FROM users WHERE id = ?', [userId]);
  },
};

module.exports = { schema, root };
