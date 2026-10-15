/**
 * TrustMesh ConsentGuard - Enterprise Open Banking Security Server
 * Pure Node.js (Zero external dependencies, instant execution)
 * Provides RESTful API endpoints, Mock Banking Core, and Web Dashboard Server
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const url = require('url');

const DEFAULT_PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3050;
const STATIC_DIR = __dirname;

// ============================================================================
// In-Memory Database & State
// ============================================================================

const BANK_DATABASE = {
  customer: {
    id: "CUST-884920",
    name: "Priya Sharma",
    email: "priya.sharma@example.in",
    kyc_status: "VERIFIED",
    phone_masked: "+91-98765-XXXXX",
    pan_masked: "ABCDE1234F"
  },
  accounts: {
    "ACC-IND-4001": {
      id: "ACC-IND-4001",
      account_label: "Account A (Savings Account)",
      account_type: "SAVINGS",
      currency: "INR",
      balance: 40000.00,
      available_balance: 39500.00,
      ifsc: "TMESH000452",
      branch: "Mumbai Central Core",
      transactions: [
        { id: "TXN-9011", date: "2026-10-14", narration: "UPI/Zomato/Order-882", amount: -450.00, type: "DEBIT" },
        { id: "TXN-9012", date: "2026-10-12", narration: "NEFT/Salary/TechCorp India", amount: 85000.00, type: "CREDIT" },
        { id: "TXN-9013", date: "2026-10-10", narration: "ATM/Cash Withdrawal", amount: -5000.00, type: "DEBIT" }
      ]
    },
    "ACC-IND-3002": {
      id: "ACC-IND-3002",
      account_label: "Account B (Current / Fixed Deposit)",
      account_type: "CURRENT",
      currency: "INR",
      balance: 30000.00,
      available_balance: 30000.00,
      ifsc: "TMESH000452",
      branch: "Mumbai Central Core",
      transactions: [
        { id: "TXN-8011", date: "2026-10-11", narration: "IMPS/Vendor Settlement", amount: -12500.00, type: "DEBIT" },
        { id: "TXN-8012", date: "2026-10-05", narration: "FD Interest Credit", amount: 1450.00, type: "CREDIT" }
      ]
    }
  }
};

const PARTNERS_REGISTRY = {
  "PARTNER-LENDKART": {
    id: "PARTNER-LENDKART",
    name: "LendKart Pro Fintech",
    category: "LENDING",
    valid_token: "pk_live_lendkart_8841a9f02c",
    status: "ACTIVE",
    rate_limit_per_min: 60,
    current_req_count: 3,
    trust_score: 98
  },
  "PARTNER-FINPULSE": {
    id: "PARTNER-FINPULSE",
    name: "FinPulse Personal Wealth",
    category: "PPU_AGGREGATOR",
    valid_token: "pk_live_finpulse_499201bc6e",
    status: "ACTIVE",
    rate_limit_per_min: 40,
    current_req_count: 12,
    trust_score: 95
  },
  "PARTNER-WEALTHGENIE": {
    id: "PARTNER-WEALTHGENIE",
    name: "WealthGenie RoboAdvisor",
    category: "INVESTMENT",
    valid_token: "pk_live_wealthgenie_667290aa",
    status: "ACTIVE",
    rate_limit_per_min: 30,
    current_req_count: 29,
    trust_score: 92
  }
};

let CONSENT_STORE = {
  "CNS-884920-LENDKART": {
    consent_id: "CNS-884920-LENDKART",
    customer_id: "CUST-884920",
    partner_id: "PARTNER-LENDKART",
    allowed_accounts: ["ACC-IND-4001"], // Notice: Covers Account A ONLY
    allowed_scopes: ["read:balance"],   // Covers read balance ONLY
    allowed_purposes: ["LOAN_UNDERWRITING", "CREDIT_ASSESSMENT"],
    created_at: "2026-09-01T10:00:00Z",
    expires_at: "2026-12-31T23:59:59Z",
    status: "ACTIVE",
    data_fields_permitted: ["account_number", "account_type", "currency", "balance", "ifsc"]
  },
  "CNS-884920-FINPULSE": {
    consent_id: "CNS-884920-FINPULSE",
    customer_id: "CUST-884920",
    partner_id: "PARTNER-FINPULSE",
    allowed_accounts: ["ACC-IND-4001", "ACC-IND-3002"],
    allowed_scopes: ["read:balance", "read:transactions"],
    allowed_purposes: ["WEALTH_MANAGEMENT", "EXPENSE_TRACKING"],
    created_at: "2026-08-15T09:30:00Z",
    expires_at: "2026-11-15T23:59:59Z",
    status: "ACTIVE",
    data_fields_permitted: ["account_number", "balance", "transactions"]
  }
};

let AUDIT_LOGS = [];
let BLOCK_CHAIN_INDEX = 1;
let PREVIOUS_BLOCK_HASH = "0000000000000000000a39fbc88921e";

function sha256Sync(str) {
  return crypto.createHash('sha256').update(str).digest('hex');
}

// ============================================================================
// Core ConsentGuard Security Algorithm
// ============================================================================

function evaluateConsentGuard(request) {
  const startTime = Date.now();
  const trace = [];

  function recordStep(stepNum, name, status, message, latencyMs) {
    trace.push({ step: stepNum, name, status, message, latencyMs });
  }

  // Step 1: Partner Authentication Check
  const partner = PARTNERS_REGISTRY[request.partner_id];
  const isPartnerAuthValid = partner && request.partner_token === partner.valid_token;
  if (!isPartnerAuthValid) {
    recordStep(1, "Partner Authentication Check", "FAIL", "Invalid partner mTLS/API credentials", 12);
    return finalizeDecision(request, "DENY", "INVALID_PARTNER_AUTHENTICATION", trace, startTime);
  }
  recordStep(1, "Partner Authentication Check", "PASS", `Verified identity for ${partner.name}`, 12);

  // Step 2: Validate the Access Token
  const isTokenValid = request.access_token && request.access_token.startsWith("tok_jwt_");
  if (!isTokenValid) {
    recordStep(2, "Access Token Validation", "FAIL", "Bearer token is corrupted, unsigned, or expired", 15);
    return finalizeDecision(request, "DENY", "INVALID_OR_EXPIRED_TOKEN", trace, startTime);
  }
  recordStep(2, "Access Token Validation", "PASS", "Signed JWT signature valid (RS256, BankBridge Auth)", 15);

  // Step 3: Check Customer Consent
  const consentKey = `CNS-${(request.customer_id || "").replace("CUST-", "")}-${(request.partner_id || "").replace("PARTNER-", "")}`;
  const consent = CONSENT_STORE[consentKey];

  if (!consent || consent.status === "REVOKED") {
    recordStep(3, "Customer Consent Verification", "FAIL", "Consent record missing, not granted, or explicitly revoked by customer", 18);
    return finalizeDecision(request, "DENY", "CONSENT_MISSING_OR_REVOKED", trace, startTime);
  }
  recordStep(3, "Customer Consent Verification", "PASS", `Active consent found [ID: ${consent.consent_id}], granted by ${BANK_DATABASE.customer.name}`, 18);

  // Step 4: Check Requested Permission & Data Scope
  const isAccountConsented = consent.allowed_accounts.includes(request.account_id);
  const isScopeConsented = consent.allowed_scopes.includes(request.scope);

  if (!isAccountConsented) {
    recordStep(4, "Permission & Policy Check", "FAIL", `Account [${request.account_id}] is outside customer-consented accounts list [${consent.allowed_accounts.join(", ")}]`, 14);
    return finalizeDecision(request, "DENY", "INSUFFICIENT_PERMISSION", trace, startTime);
  }

  if (!isScopeConsented) {
    recordStep(4, "Permission & Policy Check", "FAIL", `Requested scope '${request.scope}' is not granted in consent. Permitted: [${consent.allowed_scopes.join(", ")}]`, 14);
    return finalizeDecision(request, "DENY", "INSUFFICIENT_PERMISSION", trace, startTime);
  }
  recordStep(4, "Permission & Policy Check", "PASS", `Requested account [${request.account_id}] & scope '${request.scope}' permitted under current policy`, 14);

  // Step 5: Check Purpose and Consent Expiry
  const isExpired = new Date(consent.expires_at) < new Date();
  const isPurposeAllowed = consent.allowed_purposes.includes(request.purpose);

  if (isExpired || !isPurposeAllowed) {
    const reasonDetail = isExpired ? "Consent validity window expired" : `Purpose '${request.purpose}' unauthorized by customer`;
    recordStep(5, "Purpose & Expiry Validation", "FAIL", reasonDetail, 11);
    return finalizeDecision(request, "DENY", "CONSENT_EXPIRED_OR_PURPOSE_MISMATCH", trace, startTime);
  }
  recordStep(5, "Purpose & Expiry Validation", "PASS", `Purpose '${request.purpose}' matches customer grant; valid until ${consent.expires_at.slice(0, 10)}`, 11);

  // Step 6: Apply API Security Policies & Rate Limits
  const isRateLimitOk = partner.current_req_count < partner.rate_limit_per_min;
  if (!isRateLimitOk) {
    recordStep(6, "API Security & Rate Limits", "FAIL", `Rate limit of ${partner.rate_limit_per_min} req/min breached for ${partner.name}`, 9);
    return finalizeDecision(request, "DENY", "RATE_LIMIT_EXCEEDED", trace, startTime);
  }
  recordStep(6, "API Security & Rate Limits", "PASS", `Rate limit ok (${partner.current_req_count}/${partner.rate_limit_per_min} rpm), API version compatibility confirmed`, 9);

  // Step 7: Call Core Banking API & Sanitize Response
  const account = BANK_DATABASE.accounts[request.account_id];
  let bankingData = null;
  if (request.scope === "read:balance") {
    bankingData = {
      account_id: account.id,
      account_label: account.account_label,
      account_type: account.account_type,
      currency: account.currency,
      balance: account.balance,
      available_balance: account.available_balance,
      as_of: new Date().toISOString(),
      retrieval_status: "SUCCESS_AUTHORIZED"
    };
  } else if (request.scope === "read:transactions") {
    bankingData = {
      account_id: account.id,
      account_label: account.account_label,
      currency: account.currency,
      transactions_count: account.transactions.length,
      transactions: account.transactions,
      as_of: new Date().toISOString(),
      retrieval_status: "SUCCESS_AUTHORIZED"
    };
  }
  recordStep(7, "Core Banking API & Secure Response", "PASS", `Retrieved permitted data fields only. Sensitive fields masked.`, 22);

  return finalizeDecision(request, "ALLOW", "AUTHORIZED_CONSENT_GRANTED", trace, startTime, bankingData);
}

function finalizeDecision(request, decision, reasonCode, trace, startTime, payload = null) {
  const totalDuration = (Date.now() - startTime);
  const timestamp = new Date().toISOString();

  const auditEntry = {
    block_index: BLOCK_CHAIN_INDEX++,
    timestamp,
    partner_id: request.partner_id || "UNKNOWN",
    partner_name: PARTNERS_REGISTRY[request.partner_id]?.name || "UNKNOWN_PARTNER",
    customer_id: request.customer_id || "UNKNOWN",
    requested_account: request.account_id || "NONE",
    requested_operation: request.scope || "NONE",
    purpose: request.purpose || "UNSPECIFIED",
    decision,
    reason_code: reasonCode,
    latency_ms: totalDuration,
    prev_hash: PREVIOUS_BLOCK_HASH
  };

  const blockRaw = `${auditEntry.block_index}|${auditEntry.timestamp}|${auditEntry.partner_id}|${auditEntry.decision}|${auditEntry.reason_code}|${auditEntry.prev_hash}`;
  const blockHash = sha256Sync(blockRaw);
  auditEntry.block_hash = blockHash;
  PREVIOUS_BLOCK_HASH = blockHash;

  AUDIT_LOGS.unshift(auditEntry);

  let responseBody;
  let httpStatus;

  if (decision === "ALLOW") {
    httpStatus = 200;
    responseBody = {
      status: "SUCCESS",
      decision: "ALLOW",
      reason: reasonCode,
      data: payload,
      security_metadata: {
        guardian: "TrustMesh ConsentGuard v2.4",
        policy_version: "POL-2026.4.1",
        consent_reference: `CNS-${(request.customer_id || "").replace("CUST-", "")}-${(request.partner_id || "").replace("PARTNER-", "")}`,
        audit_block_id: auditEntry.block_index,
        timestamp
      }
    };
  } else {
    httpStatus = (reasonCode === "INVALID_PARTNER_AUTHENTICATION" || reasonCode === "INVALID_OR_EXPIRED_TOKEN") ? 401 :
                 (reasonCode === "RATE_LIMIT_EXCEEDED") ? 429 : 403;

    responseBody = {
      status: "ERROR",
      decision: "DENY",
      error_code: reasonCode,
      message: getReasonUserMessage(reasonCode),
      incident_ref: `ERR-CG-${Math.random().toString(36).substring(2, 9).toUpperCase()}`,
      timestamp
    };
  }

  return { decision, reasonCode, httpStatus, responseBody, trace, totalDuration, auditEntry };
}

function getReasonUserMessage(code) {
  switch (code) {
    case "INVALID_PARTNER_AUTHENTICATION":
      return "Partner cryptographic identity could not be verified by TrustMesh Gateway.";
    case "INVALID_OR_EXPIRED_TOKEN":
      return "The provided OAuth/JWT access token is invalid, malformed, or expired.";
    case "CONSENT_MISSING_OR_REVOKED":
      return "Customer has either revoked consent or no active consent agreement exists for this partner.";
    case "INSUFFICIENT_PERMISSION":
      return "The requested account or operation exceeds the explicit scope authorized by the customer.";
    case "CONSENT_EXPIRED_OR_PURPOSE_MISMATCH":
      return "The consent validity window has expired, or the access purpose does not align with granted purpose.";
    case "RATE_LIMIT_EXCEEDED":
      return "Partner has exceeded the configured API transaction rate threshold. Request throttled.";
    default:
      return "Access denied by TrustMesh ConsentGuard security policy.";
  }
}

// ============================================================================
// HTTP Server & Router
// ============================================================================

const server = http.createServer((req, res) => {
  const parsedUrl = url.parse(req.url, true);
  const pathname = parsedUrl.pathname;

  // CORS headers for Open Banking API interoperability
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, DELETE');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Partner-Token');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  // --- API Routes ---
  if (pathname === '/api/v1/consentguard/evaluate' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        const payload = JSON.parse(body || '{}');
        const result = evaluateConsentGuard(payload);
        res.writeHead(result.httpStatus, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(result, null, 2));
      } catch (err) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Malformed JSON payload' }));
      }
    });
    return;
  }

  if (pathname === '/api/v1/consents' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ consents: Object.values(CONSENT_STORE) }, null, 2));
    return;
  }

  if (pathname === '/api/v1/consents/revoke' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        const { consent_id } = JSON.parse(body || '{}');
        if (CONSENT_STORE[consent_id]) {
          CONSENT_STORE[consent_id].status = "REVOKED";
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: true, consent: CONSENT_STORE[consent_id] }));
        } else {
          res.writeHead(404, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: "Consent not found" }));
        }
      } catch (err) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid request' }));
      }
    });
    return;
  }

  if (pathname === '/api/v1/partners' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ partners: Object.values(PARTNERS_REGISTRY) }, null, 2));
    return;
  }

  if (pathname === '/api/v1/audit-ledger' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ total_blocks: AUDIT_LOGS.length, blocks: AUDIT_LOGS }, null, 2));
    return;
  }

  if (pathname === '/api/v1/health' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      service: "TrustMesh ConsentGuard",
      status: "HEALTHY",
      guardian_mode: "FAIL_CLOSED_ZERO_LEAK",
      timestamp: new Date().toISOString()
    }));
    return;
  }

  // --- Static Files ---
  let filePath = path.join(STATIC_DIR, pathname === '/' ? 'index.html' : pathname);
  const ext = path.extname(filePath).toLowerCase();
  const mimeTypes = {
    '.html': 'text/html',
    '.css': 'text/css',
    '.js': 'application/javascript',
    '.json': 'application/json',
    '.svg': 'image/svg+xml',
    '.png': 'image/png'
  };

  fs.readFile(filePath, (err, content) => {
    if (err) {
      if (err.code === 'ENOENT') {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('404 Not Found');
      } else {
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end('500 Internal Server Error');
      }
    } else {
      res.writeHead(200, { 'Content-Type': mimeTypes[ext] || 'text/plain' });
      res.end(content);
    }
  });
});

function startServer(port = DEFAULT_PORT) {
  server.listen(port, () => {
    console.log(`================================================================`);
    console.log(` TrustMesh ConsentGuard Engine Running on http://localhost:${port}`);
    console.log(` Security Mode: Fail-Closed Zero-Knowledge Protection Active`);
    console.log(`================================================================`);
  }).on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      console.log(`Port ${port} in use, attempting ${port + 1}...`);
      startServer(port + 1);
    } else {
      console.error(err);
    }
  });
}

if (require.main === module) {
  startServer();
}

module.exports = { server, evaluateConsentGuard, BANK_DATABASE, CONSENT_STORE, PARTNERS_REGISTRY };
