/**
 * TrustMesh ConsentGuard - Automated Regression & Security Test Suite
 * Tests all 7 security layers, fail-closed behavior, and zero-leak guarantees
 */

const assert = require('assert');
const { evaluateConsentGuard, CONSENT_STORE, PARTNERS_REGISTRY, BANK_DATABASE } = require('../server');

console.log("==================================================================");
console.log("  Running TrustMesh ConsentGuard Test Suite");
console.log("==================================================================");

let testsPassed = 0;
let testsFailed = 0;

function runTest(testName, fn) {
  try {
    fn();
    console.log(` \x1b[32m✔ PASS:\x1b[0m ${testName}`);
    testsPassed++;
  } catch (err) {
    console.error(` \x1b[31m✖ FAIL:\x1b[0m ${testName}`);
    console.error(`   Error: ${err.message}`);
    testsFailed++;
  }
}

// Ensure clean baseline state
CONSENT_STORE["CNS-884920-LENDKART"].status = "ACTIVE";
CONSENT_STORE["CNS-884920-LENDKART"].expires_at = "2026-12-31T23:59:59Z";
PARTNERS_REGISTRY["PARTNER-LENDKART"].current_req_count = 5;

// TEST 1: The Golden Path (Account A balance, valid auth, active consent)
runTest("Scenario 1: Active Consent + Valid Partner + Account A -> ALLOW (₹40,000)", () => {
  const req = {
    partner_id: "PARTNER-LENDKART",
    partner_token: "pk_live_lendkart_8841a9f02c",
    access_token: "tok_jwt_eyJhGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
    customer_id: "CUST-884920",
    account_id: "ACC-IND-4001", // Account A
    scope: "read:balance",
    purpose: "LOAN_UNDERWRITING"
  };

  const res = evaluateConsentGuard(req);
  assert.strictEqual(res.decision, "ALLOW", "Decision must be ALLOW");
  assert.strictEqual(res.httpStatus, 200, "HTTP Status must be 200");
  assert.strictEqual(res.responseBody.data.balance, 40000.00, "Account A balance must be ₹40,000");
  assert.strictEqual(res.reasonCode, "AUTHORIZED_CONSENT_GRANTED");
});

// TEST 2: Customer has Revoked Consent
runTest("Scenario 2: Customer Revoked Consent -> DENY (CONSENT_MISSING_OR_REVOKED)", () => {
  CONSENT_STORE["CNS-884920-LENDKART"].status = "REVOKED";

  const req = {
    partner_id: "PARTNER-LENDKART",
    partner_token: "pk_live_lendkart_8841a9f02c",
    access_token: "tok_jwt_eyJhGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
    customer_id: "CUST-884920",
    account_id: "ACC-IND-4001",
    scope: "read:balance",
    purpose: "LOAN_UNDERWRITING"
  };

  const res = evaluateConsentGuard(req);
  assert.strictEqual(res.decision, "DENY", "Must deny revoked consent");
  assert.strictEqual(res.httpStatus, 403, "HTTP Status must be 403");
  assert.strictEqual(res.reasonCode, "CONSENT_MISSING_OR_REVOKED");
  assert.strictEqual(res.responseBody.data, undefined, "No banking data may be disclosed");

  // Restore
  CONSENT_STORE["CNS-884920-LENDKART"].status = "ACTIVE";
});

// TEST 3: Requested Account B (Unconsented Account)
runTest("Scenario 3: Requested Account B (Only Account A consented) -> DENY (INSUFFICIENT_PERMISSION)", () => {
  const req = {
    partner_id: "PARTNER-LENDKART",
    partner_token: "pk_live_lendkart_8841a9f02c",
    access_token: "tok_jwt_eyJhGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
    customer_id: "CUST-884920",
    account_id: "ACC-IND-3002", // Account B
    scope: "read:balance",
    purpose: "LOAN_UNDERWRITING"
  };

  const res = evaluateConsentGuard(req);
  assert.strictEqual(res.decision, "DENY");
  assert.strictEqual(res.reasonCode, "INSUFFICIENT_PERMISSION");
  assert.strictEqual(res.responseBody.data, undefined, "Must NOT leak Account B data (₹30,000)");
});

// TEST 4: Requested Scope Unconsented (read:transactions requested when only balance consented)
runTest("Scenario 4: Requested Transactions (Only Balance Consented) -> DENY (INSUFFICIENT_PERMISSION)", () => {
  const req = {
    partner_id: "PARTNER-LENDKART",
    partner_token: "pk_live_lendkart_8841a9f02c",
    access_token: "tok_jwt_eyJhGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
    customer_id: "CUST-884920",
    account_id: "ACC-IND-4001",
    scope: "read:transactions", // Unconsented scope!
    purpose: "LOAN_UNDERWRITING"
  };

  const res = evaluateConsentGuard(req);
  assert.strictEqual(res.decision, "DENY");
  assert.strictEqual(res.reasonCode, "INSUFFICIENT_PERMISSION");
});

// TEST 5: Consent Expired
runTest("Scenario 5: Consent Validity Window Expired -> DENY (CONSENT_EXPIRED_OR_PURPOSE_MISMATCH)", () => {
  CONSENT_STORE["CNS-884920-LENDKART"].expires_at = "2024-01-01T00:00:00Z"; // In the past

  const req = {
    partner_id: "PARTNER-LENDKART",
    partner_token: "pk_live_lendkart_8841a9f02c",
    access_token: "tok_jwt_eyJhGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
    customer_id: "CUST-884920",
    account_id: "ACC-IND-4001",
    scope: "read:balance",
    purpose: "LOAN_UNDERWRITING"
  };

  const res = evaluateConsentGuard(req);
  assert.strictEqual(res.decision, "DENY");
  assert.strictEqual(res.reasonCode, "CONSENT_EXPIRED_OR_PURPOSE_MISMATCH");

  // Restore
  CONSENT_STORE["CNS-884920-LENDKART"].expires_at = "2026-12-31T23:59:59Z";
});

// TEST 6: Invalid Partner Authentication
runTest("Scenario 6: Invalid Partner Token -> DENY (INVALID_PARTNER_AUTHENTICATION)", () => {
  const req = {
    partner_id: "PARTNER-LENDKART",
    partner_token: "pk_forged_malicious_token_999",
    access_token: "tok_jwt_eyJhGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
    customer_id: "CUST-884920",
    account_id: "ACC-IND-4001",
    scope: "read:balance",
    purpose: "LOAN_UNDERWRITING"
  };

  const res = evaluateConsentGuard(req);
  assert.strictEqual(res.decision, "DENY");
  assert.strictEqual(res.httpStatus, 401);
  assert.strictEqual(res.reasonCode, "INVALID_PARTNER_AUTHENTICATION");
});

// TEST 7: Rate Limit Exceeded
runTest("Scenario 7: Partner Rate Limit Breached -> DENY (RATE_LIMIT_EXCEEDED)", () => {
  PARTNERS_REGISTRY["PARTNER-LENDKART"].current_req_count = 70; // Over 60 limit

  const req = {
    partner_id: "PARTNER-LENDKART",
    partner_token: "pk_live_lendkart_8841a9f02c",
    access_token: "tok_jwt_eyJhGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
    customer_id: "CUST-884920",
    account_id: "ACC-IND-4001",
    scope: "read:balance",
    purpose: "LOAN_UNDERWRITING"
  };

  const res = evaluateConsentGuard(req);
  assert.strictEqual(res.decision, "DENY");
  assert.strictEqual(res.httpStatus, 429);
  assert.strictEqual(res.reasonCode, "RATE_LIMIT_EXCEEDED");

  // Restore
  PARTNERS_REGISTRY["PARTNER-LENDKART"].current_req_count = 5;
});

// TEST 8: Zero-Leak Guarantee Check
runTest("Scenario 8: Fail-Closed Zero-Knowledge Audit Check", () => {
  const req = {
    partner_id: "PARTNER-LENDKART",
    partner_token: "pk_live_lendkart_8841a9f02c",
    access_token: "malformed_token_unsigned",
    customer_id: "CUST-884920",
    account_id: "ACC-IND-4001",
    scope: "read:balance",
    purpose: "LOAN_UNDERWRITING"
  };

  const res = evaluateConsentGuard(req);
  assert.strictEqual(res.decision, "DENY");
  assert.ok(res.auditEntry.block_hash, "Must compute cryptographic block hash");
  assert.ok(!JSON.stringify(res.responseBody).includes("40000"), "Must NOT reveal balance in error");
});

console.log("------------------------------------------------------------------");
console.log(`Results: ${testsPassed} Passed, ${testsFailed} Failed.`);
console.log("==================================================================");

if (testsFailed > 0) {
  process.exit(1);
}
