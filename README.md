## Included Vulnerabilities

| Category | Vulnerability | Severity |
|----------|---------------|----------|
| Authentication | SQL Injection (Authentication Bypass) | 🔴 Critical |
| Authentication | Weak JWT Signing Secret | 🔴 Critical |
| Access Control | JWT Privilege Escalation | 🔴 Critical |
| Access Control | IDOR – Account Enumeration | 🟠 High |
| Access Control | IDOR – Unauthorized Money Transfer | 🔴 Critical |
| Business Logic | Negative Amount Transfer | 🔴 Critical |
| GraphQL | GraphQL Introspection Enabled | 🟡 Medium |
| GraphQL | GraphQL IDOR | 🟠 High |
| GraphQL | GraphQL SQL Injection | 🔴 Critical |
| GraphQL | GraphQL Batch IDOR | 🟠 High |
| Cross-Site Scripting | Stored XSS | 🟠 High |
| Cross-Site Scripting | Reflected XSS | 🟡 Medium |
| Cross-Site Scripting | DOM-based XSS | 🟡 Medium |
| SSRF | Server-Side Request Forgery | 🔴 Critical |
## Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/Cookies307/fintech-vuln-app.git
```

### 2. Navigate to the project

```bash
cd fintech-vuln-app/server
```

### 3. Install dependencies

```bash
npm install
```

### 4. Start the application

```bash
npm start
```

If `npm start` is unavailable, run:

```bash
node index.js
```

### 5. Open the application

```
http://localhost:4000
```
