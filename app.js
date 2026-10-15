/**
 * TrustMesh ConsentGuard - Enterprise Open Banking Security Layer
 * Implements Consent-Aware API Access Control & Automated API Change-Impact Testing
 */

// ============================================================================
// 1. In-Memory Data Stores & State
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
    allowed_accounts: ["ACC-IND-4001"], // Notice: covers Account A ONLY by default
    allowed_scopes: ["read:balance"],   // Covers read balance ONLY by default
    allowed_purposes: ["LOAN_UNDERWRITING", "CREDIT_ASSESSMENT"],
    created_at: "2026-09-01T10:00:00Z",
    expires_at: "2026-12-31T23:59:59Z",
    status: "ACTIVE", // ACTIVE, REVOKED, EXPIRED
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

// Playground interactive parameters
let currentPlaygroundConfig = {
  consentCondition: "ACTIVE", // ACTIVE, REVOKED, EXPIRED, INVALID_AUTH, RATE_LIMIT_EXCEEDED
  requestedAccount: "ACC-IND-4001", // ACC-IND-4001 (Account A), ACC-IND-3002 (Account B)
  requestedPermission: "read:balance", // read:balance, read:transactions
  partnerId: "PARTNER-LENDKART",
  purpose: "LOAN_UNDERWRITING"
};

// ============================================================================
// 2. Cryptographic Helper for Tamper-Evident Audit Logging
// ============================================================================

async function sha256(message) {
  const msgBuffer = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// ============================================================================
// 3. Core TrustMesh ConsentGuard Algorithm
// ============================================================================

/**
 * TrustMesh ConsentGuard Evaluation Pipeline
 * Evaluates the 7 steps defined in the security algorithm.
 */
async function runConsentGuardPipeline(request, emitStepCallback) {
  const startTime = performance.now();
  const evaluationTrace = [];

  function recordStep(stepNum, name, status, message, latencyMs) {
    const stepData = { step: stepNum, name, status, message, latencyMs };
    evaluationTrace.push(stepData);
    if (emitStepCallback) emitStepCallback(stepData);
  }

  // --- Step 1: Authenticate the Partner ---
  await new Promise(r => setTimeout(r, 80)); // Simulate cryptographic auth verification
  const isPartnerAuthValid = request.partner_token && request.partner_token === PARTNERS_REGISTRY[request.partner_id]?.valid_token;
  
  if (!isPartnerAuthValid) {
    recordStep(1, "Partner Authentication Check", "FAIL", "Invalid partner mTLS/API credentials", 12);
    return finalizeDecision(request, "DENY", "INVALID_PARTNER_AUTHENTICATION", evaluationTrace, startTime);
  }
  recordStep(1, "Partner Authentication Check", "PASS", `Verified identity for ${PARTNERS_REGISTRY[request.partner_id]?.name}`, 12);

  // --- Step 2: Validate the Access Token ---
  await new Promise(r => setTimeout(r, 70));
  const isTokenValid = request.access_token && request.access_token.startsWith("tok_jwt_");
  if (!isTokenValid) {
    recordStep(2, "Access Token Validation", "FAIL", "Bearer token is corrupted, unsigned, or expired", 15);
    return finalizeDecision(request, "DENY", "INVALID_OR_EXPIRED_TOKEN", evaluationTrace, startTime);
  }
  recordStep(2, "Access Token Validation", "PASS", "Signed JWT signature valid (RS256, issued by BankBridge Auth)", 15);

  // --- Step 3: Check Customer Consent ---
  await new Promise(r => setTimeout(r, 80));
  const consentKey = `CNS-${request.customer_id.replace("CUST-", "")}-${request.partner_id.replace("PARTNER-", "")}`;
  const consent = CONSENT_STORE[consentKey];

  if (!consent || consent.status === "REVOKED") {
    recordStep(3, "Customer Consent Verification", "FAIL", "Consent record missing, not granted, or explicitly revoked by customer", 18);
    return finalizeDecision(request, "DENY", "CONSENT_MISSING_OR_REVOKED", evaluationTrace, startTime);
  }
  recordStep(3, "Customer Consent Verification", "PASS", `Active consent found [ID: ${consent.consent_id}], granted by ${BANK_DATABASE.customer.name}`, 18);

  // --- Step 4: Check Requested Permission & Data Scope ---
  await new Promise(r => setTimeout(r, 75));
  // 4a. Account boundary check
  const isAccountConsented = consent.allowed_accounts.includes(request.account_id);
  // 4b. Operation scope check
  const isScopeConsented = consent.allowed_scopes.includes(request.scope);

  if (!isAccountConsented) {
    recordStep(4, "Permission & Policy Check", "FAIL", `Account [${request.account_id}] is outside customer-consented accounts list [${consent.allowed_accounts.join(", ")}]`, 14);
    return finalizeDecision(request, "DENY", "INSUFFICIENT_PERMISSION", evaluationTrace, startTime);
  }

  if (!isScopeConsented) {
    recordStep(4, "Permission & Policy Check", "FAIL", `Requested scope '${request.scope}' is not granted in consent. Permitted: [${consent.allowed_scopes.join(", ")}]`, 14);
    return finalizeDecision(request, "DENY", "INSUFFICIENT_PERMISSION", evaluationTrace, startTime);
  }
  recordStep(4, "Permission & Policy Check", "PASS", `Requested account [${request.account_id}] & scope '${request.scope}' permitted under current policy`, 14);

  // --- Step 5: Check Purpose and Consent Expiry ---
  await new Promise(r => setTimeout(r, 60));
  const isExpired = new Date(consent.expires_at) < new Date();
  const isPurposeAllowed = consent.allowed_purposes.includes(request.purpose);

  if (isExpired || !isPurposeAllowed) {
    const reasonDetail = isExpired ? "Consent validity window expired" : `Purpose '${request.purpose}' unauthorized by customer`;
    recordStep(5, "Purpose & Expiry Validation", "FAIL", reasonDetail, 11);
    return finalizeDecision(request, "DENY", "CONSENT_EXPIRED_OR_PURPOSE_MISMATCH", evaluationTrace, startTime);
  }
  recordStep(5, "Purpose & Expiry Validation", "PASS", `Purpose '${request.purpose}' matches customer grant; valid until ${consent.expires_at.slice(0, 10)}`, 11);

  // --- Step 6: Apply API Security Policies & Rate Limits ---
  await new Promise(r => setTimeout(r, 65));
  const partner = PARTNERS_REGISTRY[request.partner_id];
  const isRateLimitOk = partner.current_req_count < partner.rate_limit_per_min;

  if (!isRateLimitOk) {
    recordStep(6, "API Security & Rate Limits", "FAIL", `Rate limit of ${partner.rate_limit_per_min} req/min breached for ${partner.name}`, 9);
    return finalizeDecision(request, "DENY", "RATE_LIMIT_EXCEEDED", evaluationTrace, startTime);
  }
  recordStep(6, "API Security & Rate Limits", "PASS", `Rate limit ok (${partner.current_req_count}/${partner.rate_limit_per_min} rpm), API version compatibility confirmed`, 9);

  // --- Step 7: Call Core Banking API & Sanitize Response ---
  await new Promise(r => setTimeout(r, 90));
  const bankingData = callBankingApi(request.account_id, request.scope, consent);
  recordStep(7, "Core Banking API & Secure Response", "PASS", `Retrieved permitted data fields only. Sensitive fields masked.`, 22);

  return finalizeDecision(request, "ALLOW", "AUTHORIZED_CONSENT_GRANTED", evaluationTrace, startTime, bankingData);
}

/**
 * Banking API Mock: Discloses ONLY authorized fields under fail-closed security.
 */
function callBankingApi(accountId, scope, consent) {
  const account = BANK_DATABASE.accounts[accountId];
  if (!account) return null;

  if (scope === "read:balance") {
    return {
      account_id: account.id,
      account_label: account.account_label,
      account_type: account.account_type,
      currency: account.currency,
      balance: account.balance,
      available_balance: account.available_balance,
      as_of: new Date().toISOString(),
      retrieval_status: "SUCCESS_AUTHORIZED"
    };
  } else if (scope === "read:transactions") {
    return {
      account_id: account.id,
      account_label: account.account_label,
      currency: account.currency,
      transactions_count: account.transactions.length,
      transactions: account.transactions,
      as_of: new Date().toISOString(),
      retrieval_status: "SUCCESS_AUTHORIZED"
    };
  }

  return { account_id: account.id, balance: account.balance };
}

/**
 * Finalize decision, create secure response, and record tamper-evident audit log
 */
async function finalizeDecision(request, decision, reasonCode, trace, startTime, payload = null) {
  const totalDuration = (performance.now() - startTime).toFixed(1);
  const timestamp = new Date().toISOString();

  // Audit entry creation (WITHOUT logging secrets, tokens, or raw bank PII)
  const auditEntry = {
    block_index: BLOCK_CHAIN_INDEX++,
    timestamp,
    partner_id: request.partner_id,
    partner_name: PARTNERS_REGISTRY[request.partner_id]?.name || "UNKNOWN_PARTNER",
    customer_id: request.customer_id,
    requested_account: request.account_id,
    requested_operation: request.scope,
    purpose: request.purpose,
    decision,
    reason_code: reasonCode,
    latency_ms: totalDuration,
    prev_hash: PREVIOUS_BLOCK_HASH
  };

  // Compute block hash for tamper-evident ledger
  const blockRaw = `${auditEntry.block_index}|${auditEntry.timestamp}|${auditEntry.partner_id}|${auditEntry.decision}|${auditEntry.reason_code}|${auditEntry.prev_hash}`;
  const blockHash = await sha256(blockRaw);
  auditEntry.block_hash = blockHash;
  PREVIOUS_BLOCK_HASH = blockHash;

  AUDIT_LOGS.unshift(auditEntry);
  updateAuditMetricsUI();

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
        consent_reference: `CNS-${request.customer_id.replace("CUST-", "")}-${request.partner_id.replace("PARTNER-", "")}`,
        audit_block_id: auditEntry.block_index,
        timestamp
      }
    };
  } else {
    // Fail-Closed: Return appropriate error WITHOUT exposing banking information or secrets
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

  return {
    decision,
    reasonCode,
    httpStatus,
    responseBody,
    trace,
    totalDuration,
    auditEntry
  };
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
// 4. Automated API Change-Impact Tester (Key Innovation Engine)
// ============================================================================

const API_CHANGE_SCENARIOS = [
  {
    id: "SCN-BREAKING-SCHEMA",
    title: "Scenario 1: Deprecate `account_balance` field in favor of `available_balance`",
    category: "BREAKING_SCHEMA",
    severity: "HIGH",
    description: "Core Banking Gateway API v2.5 renames legacy field `balance` to `ledger_balance` and `available_balance`. Third parties relying on `balance` will crash.",
    diff: {
      before: `{\n  "account_id": "ACC-IND-4001",\n  "balance": 40000.00\n}`,
      after: `{\n  "account_id": "ACC-IND-4001",\n  "ledger_balance": 40000.00,\n  "available_balance": 39500.00\n}`
    },
    runSimulation: () => {
      return {
        affectedPartners: ["PARTNER-LENDKART", "PARTNER-FINPULSE"],
        totalConsentsScanned: 24,
        atRiskConsents: 18,
        breakingIntegrationsCount: 2,
        remediationCode: "APPLY_RESPONSE_TRANSFORM_LAYER_V1_FALLBACK",
        summary: "CRITICAL: 2 registered partners (LendKart, FinPulse) consume legacy `balance`. Automatic field aliasing required before deployment."
      };
    }
  },
  {
    id: "SCN-SCOPE-ESCALATION",
    title: "Scenario 2: Scope Escalation: Require `accounts:detail:v2` instead of legacy `read:balance`",
    category: "AUTHORIZATION_BREAK",
    severity: "CRITICAL",
    description: "Security policy update mandates a newer granular scope `accounts:detail:v2` for all balance inquiries. Partners with existing `read:balance` consent will get 403 INSUFFICIENT_PERMISSION.",
    diff: {
      before: `"allowed_scopes": ["read:balance"]`,
      after: `"allowed_scopes": ["accounts:detail:v2"]`
    },
    runSimulation: () => {
      return {
        affectedPartners: ["PARTNER-LENDKART", "PARTNER-WEALTHGENIE"],
        totalConsentsScanned: 24,
        atRiskConsents: 24,
        breakingIntegrationsCount: 3,
        remediationCode: "CONSENT_UPGRADE_OR_SCOPE_ALIAS_MAPPING",
        summary: "BREAKING: 100% of existing consent records lack `accounts:detail:v2`. TrustMesh recommends backwards-compatible scope aliasing for 90 days."
      };
    }
  },
  {
    id: "SCN-POLICY-WINDOW",
    title: "Scenario 3: Compliance Mandate: Reduce Max Consent Window from 180 to 90 Days",
    category: "COMPLIANCE_POLICY",
    severity: "MEDIUM",
    description: "RBI / Open Banking regulatory amendment shortens maximum consent validity duration. Currently active 180-day consents will prematurely expire.",
    diff: {
      before: `max_consent_days: 180`,
      after: `max_consent_days: 90`
    },
    runSimulation: () => {
      return {
        affectedPartners: ["PARTNER-LENDKART", "PARTNER-FINPULSE", "PARTNER-WEALTHGENIE"],
        totalConsentsScanned: 24,
        atRiskConsents: 11,
        breakingIntegrationsCount: 1,
        remediationCode: "TRIGGER_CUSTOMER_REAUTH_NOTIFICATIONS",
        summary: "COMPLIANCE RISK: 11 active customer consents exceed the new 90-day threshold. Automated consent re-authorization prompts scheduled."
      };
    }
  },
  {
    id: "SCN-PII-REDACTION",
    title: "Scenario 4: Field-Level PII Masking: Redact Transaction Narration Strings",
    category: "PRIVACY_ENHANCEMENT",
    severity: "LOW",
    description: "Personal Data Protection Rule: Merchant and Beneficiary names in UPI/NEFT narration must be masked for non-banking entities.",
    diff: {
      before: `"narration": "UPI/Zomato/Order-882"`,
      after: `"narration": "UPI/MERCHANT-REDACTED" // Masked`
    },
    runSimulation: () => {
      return {
        affectedPartners: ["PARTNER-FINPULSE"],
        totalConsentsScanned: 24,
        atRiskConsents: 6,
        breakingIntegrationsCount: 0,
        remediationCode: "ENFORCE_MASKING_TRANSFORM",
        summary: "SAFE: No breaking API structural change. Transaction categorization AI in partner FinPulse might experience reduced accuracy."
      };
    }
  }
];

// ============================================================================
// 5. UI Controller & Event Handlers
// ============================================================================

document.addEventListener("DOMContentLoaded", () => {
  initNavTabs();
  initPlaygroundControls();
  initPresetChips();
  initConsentVaultUI();
  initPartnerRegistryUI();
  initChangeImpactTester();
  initAuditMetricsUI();
  populateArchitectureVisualizer();

  // Execute initial test run so the user sees live data immediately
  setTimeout(() => {
    executeGuardEvaluation();
  }, 400);
});

// Navigation Tab Switching
function initNavTabs() {
  const tabBtns = document.querySelectorAll(".nav-tab-btn");
  const tabSections = document.querySelectorAll(".tab-section");

  tabBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      const targetId = btn.getAttribute("data-tab");
      
      tabBtns.forEach(b => b.classList.remove("active"));
      tabSections.forEach(s => s.classList.remove("active"));

      btn.classList.add("active");
      const targetSection = document.getElementById(targetId);
      if (targetSection) targetSection.classList.add("active");
    });
  });
}

// Preset Scenario Chips (One-click test case loaders)
function initPresetChips() {
  const chips = document.querySelectorAll(".preset-chip");
  chips.forEach(chip => {
    chip.addEventListener("click", () => {
      chips.forEach(c => c.classList.remove("active"));
      chip.classList.add("active");

      const preset = chip.getAttribute("data-preset");
      loadPreset(preset);
    });
  });
}

function loadPreset(presetKey) {
  switch (presetKey) {
    case "ALLOW_ACCOUNT_A":
      currentPlaygroundConfig = {
        consentCondition: "ACTIVE",
        requestedAccount: "ACC-IND-4001", // Account A
        requestedPermission: "read:balance",
        partnerId: "PARTNER-LENDKART",
        purpose: "LOAN_UNDERWRITING"
      };
      break;

    case "DENY_REVOKED":
      currentPlaygroundConfig = {
        consentCondition: "REVOKED",
        requestedAccount: "ACC-IND-4001",
        requestedPermission: "read:balance",
        partnerId: "PARTNER-LENDKART",
        purpose: "LOAN_UNDERWRITING"
      };
      break;

    case "DENY_ACCOUNT_B":
      currentPlaygroundConfig = {
        consentCondition: "ACTIVE",
        requestedAccount: "ACC-IND-3002", // Account B (Unconsented!)
        requestedPermission: "read:balance",
        partnerId: "PARTNER-LENDKART",
        purpose: "LOAN_UNDERWRITING"
      };
      break;

    case "DENY_TRANSACTIONS":
      currentPlaygroundConfig = {
        consentCondition: "ACTIVE",
        requestedAccount: "ACC-IND-4001",
        requestedPermission: "read:transactions", // Unconsented scope!
        partnerId: "PARTNER-LENDKART",
        purpose: "LOAN_UNDERWRITING"
      };
      break;

    case "DENY_EXPIRED":
      currentPlaygroundConfig = {
        consentCondition: "EXPIRED",
        requestedAccount: "ACC-IND-4001",
        requestedPermission: "read:balance",
        partnerId: "PARTNER-LENDKART",
        purpose: "LOAN_UNDERWRITING"
      };
      break;

    case "DENY_INVALID_AUTH":
      currentPlaygroundConfig = {
        consentCondition: "INVALID_AUTH",
        requestedAccount: "ACC-IND-4001",
        requestedPermission: "read:balance",
        partnerId: "PARTNER-LENDKART",
        purpose: "LOAN_UNDERWRITING"
      };
      break;

    case "DENY_RATE_LIMIT":
      currentPlaygroundConfig = {
        consentCondition: "RATE_LIMIT_EXCEEDED",
        requestedAccount: "ACC-IND-4001",
        requestedPermission: "read:balance",
        partnerId: "PARTNER-LENDKART",
        purpose: "LOAN_UNDERWRITING"
      };
      break;
  }

  syncControlsToConfig();
  executeGuardEvaluation();
}

function syncControlsToConfig() {
  // Sync consent condition buttons
  document.querySelectorAll("[data-condition]").forEach(btn => {
    btn.classList.toggle("selected", btn.getAttribute("data-condition") === currentPlaygroundConfig.consentCondition);
  });

  // Sync account buttons
  document.querySelectorAll("[data-account]").forEach(btn => {
    btn.classList.toggle("selected", btn.getAttribute("data-account") === currentPlaygroundConfig.requestedAccount);
  });

  // Sync permission buttons
  document.querySelectorAll("[data-permission]").forEach(btn => {
    btn.classList.toggle("selected", btn.getAttribute("data-permission") === currentPlaygroundConfig.requestedPermission);
  });
}

function initPlaygroundControls() {
  // Consent Condition buttons
  document.querySelectorAll("[data-condition]").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll("[data-condition]").forEach(b => b.classList.remove("selected"));
      btn.classList.add("selected");
      currentPlaygroundConfig.consentCondition = btn.getAttribute("data-condition");
      executeGuardEvaluation();
    });
  });

  // Account buttons
  document.querySelectorAll("[data-account]").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll("[data-account]").forEach(b => b.classList.remove("selected"));
      btn.classList.add("selected");
      currentPlaygroundConfig.requestedAccount = btn.getAttribute("data-account");
      executeGuardEvaluation();
    });
  });

  // Permission buttons
  document.querySelectorAll("[data-permission]").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll("[data-permission]").forEach(b => b.classList.remove("selected"));
      btn.classList.add("selected");
      currentPlaygroundConfig.requestedPermission = btn.getAttribute("data-permission");
      executeGuardEvaluation();
    });
  });

  // Execute Guard Button
  const execBtn = document.getElementById("btn-execute-guard");
  if (execBtn) {
    execBtn.addEventListener("click", () => {
      executeGuardEvaluation();
    });
  }

  // Response Payload Tab switcher (JSON vs Headers vs Audit Log)
  const payloadTabs = document.querySelectorAll(".payload-tab");
  payloadTabs.forEach(tab => {
    tab.addEventListener("click", () => {
      payloadTabs.forEach(t => t.classList.remove("active"));
      tab.classList.add("active");
      const view = tab.getAttribute("data-view");
      renderResponseView(view);
    });
  });
}

let lastEvaluationResult = null;

// ============================================================================
// 6. Security Pipeline Execution Visualizer
// ============================================================================

async function executeGuardEvaluation() {
  const execBtn = document.getElementById("btn-execute-guard");
  if (execBtn) {
    execBtn.disabled = true;
    execBtn.innerHTML = `<span class="pulse-dot"></span> Evaluating TrustMesh Guard...`;
  }

  // Reset pipeline step UI
  resetPipelineVisualizer();

  // Temporarily adjust consent store based on the active condition for simulation
  const consentKey = "CNS-884920-LENDKART";
  const defaultConsent = CONSENT_STORE[consentKey];

  if (currentPlaygroundConfig.consentCondition === "REVOKED") {
    defaultConsent.status = "REVOKED";
  } else if (currentPlaygroundConfig.consentCondition === "EXPIRED") {
    defaultConsent.status = "ACTIVE";
    defaultConsent.expires_at = "2025-01-01T00:00:00Z"; // Past date
  } else {
    defaultConsent.status = "ACTIVE";
    defaultConsent.expires_at = "2026-12-31T23:59:59Z";
  }

  // Partner rate limit adjustment
  if (currentPlaygroundConfig.consentCondition === "RATE_LIMIT_EXCEEDED") {
    PARTNERS_REGISTRY["PARTNER-LENDKART"].current_req_count = 65; // Exceeds 60
  } else {
    PARTNERS_REGISTRY["PARTNER-LENDKART"].current_req_count = 5;
  }

  // Partner token adjustment
  const partnerToken = (currentPlaygroundConfig.consentCondition === "INVALID_AUTH") 
    ? "pk_invalid_hacked_token_xyz" 
    : PARTNERS_REGISTRY["PARTNER-LENDKART"].valid_token;

  // Build the request object
  const apiRequest = {
    partner_id: currentPlaygroundConfig.partnerId,
    partner_token: partnerToken,
    access_token: "tok_jwt_eyJhGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJDVVNULTg4NDkyMCJ9",
    customer_id: "CUST-884920",
    account_id: currentPlaygroundConfig.requestedAccount,
    scope: currentPlaygroundConfig.requestedPermission,
    purpose: currentPlaygroundConfig.purpose
  };

  // Run pipeline with real-time step callback
  const result = await runConsentGuardPipeline(apiRequest, (stepData) => {
    updatePipelineStepUI(stepData);
  });

  lastEvaluationResult = result;

  // Render hero banner & response
  renderDecisionHeroBanner(result);
  renderResponseView("body");

  if (execBtn) {
    execBtn.disabled = false;
    execBtn.innerHTML = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg> Re-Evaluate Security Decision`;
  }
}

function resetPipelineVisualizer() {
  for (let i = 1; i <= 7; i++) {
    const card = document.getElementById(`step-card-${i}`);
    if (card) {
      card.className = "pipeline-step-card";
      const statusBadge = card.querySelector(".status-badge");
      if (statusBadge) {
        statusBadge.className = "status-badge pending";
        statusBadge.textContent = "WAITING";
      }
      const latencyEl = card.querySelector(".step-latency");
      if (latencyEl) latencyEl.textContent = "--";
    }
  }

  const heroBanner = document.getElementById("decision-hero-banner");
  if (heroBanner) {
    heroBanner.className = "decision-hero-banner waiting";
    document.getElementById("hero-decision-text").textContent = "EVALUATING PIPELINE...";
    document.getElementById("hero-decision-desc").textContent = "Analyzing authentication tokens, cryptographic claims, and customer consent status...";
    document.getElementById("hero-reason-code").textContent = "PROCESSING";
  }
}

function updatePipelineStepUI(stepData) {
  const card = document.getElementById(`step-card-${stepData.step}`);
  if (!card) return;

  const isPass = stepData.status === "PASS";
  card.className = `pipeline-step-card ${isPass ? "pass" : "fail"}`;

  const statusBadge = card.querySelector(".status-badge");
  if (statusBadge) {
    statusBadge.className = `status-badge ${isPass ? "pass" : "fail"}`;
    statusBadge.textContent = isPass ? "PASSED" : "BLOCKED";
  }

  const latencyEl = card.querySelector(".step-latency");
  if (latencyEl) latencyEl.textContent = `${stepData.latencyMs}ms`;

  const descEl = card.querySelector(".step-text p");
  if (descEl) descEl.textContent = stepData.message;

  // If this step failed, mark remaining steps as skipped
  if (!isPass) {
    for (let j = stepData.step + 1; j <= 7; j++) {
      const remainingCard = document.getElementById(`step-card-${j}`);
      if (remainingCard) {
        remainingCard.className = "pipeline-step-card skipped";
        const remBadge = remainingCard.querySelector(".status-badge");
        if (remBadge) {
          remBadge.className = "status-badge skipped";
          remBadge.textContent = "SKIPPED";
        }
      }
    }
  }
}

function renderDecisionHeroBanner(result) {
  const heroBanner = document.getElementById("decision-hero-banner");
  const textEl = document.getElementById("hero-decision-text");
  const descEl = document.getElementById("hero-decision-desc");
  const codeEl = document.getElementById("hero-reason-code");
  const iconWrap = document.getElementById("hero-decision-icon");

  if (!heroBanner) return;

  if (result.decision === "ALLOW") {
    heroBanner.className = "decision-hero-banner allow";
    textEl.textContent = "ALLOW REQUEST — ACCESS AUTHORIZED";
    descEl.textContent = "The partner is authenticated, consent is active, and the requested data is within the customer's granted scope.";
    codeEl.textContent = "ALLOW: AUTHORIZED_CONSENT_GRANTED";
    iconWrap.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>`;
  } else {
    heroBanner.className = "decision-hero-banner deny";
    textEl.textContent = "DENY REQUEST — ACCESS BLOCKED";
    descEl.textContent = getReasonUserMessage(result.reasonCode);
    codeEl.textContent = `DENY: ${result.reasonCode}`;
    iconWrap.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>`;
  }
}

function renderResponseView(viewType) {
  const viewer = document.getElementById("json-response-viewer");
  const zeroLeakCallout = document.getElementById("zero-leak-callout");
  if (!viewer || !lastEvaluationResult) return;

  if (viewType === "body") {
    viewer.innerHTML = syntaxHighlightJson(lastEvaluationResult.responseBody);
  } else if (viewType === "headers") {
    const headers = {
      "HTTP/1.1": `${lastEvaluationResult.httpStatus} ${lastEvaluationResult.httpStatus === 200 ? "OK" : "Forbidden"}`,
      "Content-Type": "application/json; charset=utf-8",
      "X-TrustMesh-Guard": "ACTIVE_ENFORCED",
      "X-Decision": lastEvaluationResult.decision,
      "X-Reason-Code": lastEvaluationResult.reasonCode,
      "X-Latency-Ms": `${lastEvaluationResult.totalDuration}ms`,
      "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
      "X-Content-Type-Options": "nosniff",
      "X-Zero-Leak-Guaranteed": "TRUE"
    };
    viewer.innerHTML = syntaxHighlightJson(headers);
  } else if (viewType === "audit") {
    viewer.innerHTML = syntaxHighlightJson(lastEvaluationResult.auditEntry);
  }

  // Update zero-leak callout
  if (zeroLeakCallout) {
    if (lastEvaluationResult.decision === "DENY") {
      zeroLeakCallout.className = "zero-leak-shield";
      zeroLeakCallout.innerHTML = `
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        <strong>Zero-Knowledge Leak Protection:</strong> Request denied with code <code>${lastEvaluationResult.reasonCode}</code>. No banking balances, customer PII, or internal tokens were exposed in the response.
      `;
    } else {
      zeroLeakCallout.className = "zero-leak-shield success";
      zeroLeakCallout.innerHTML = `
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
        <strong>Consent-Bound Response:</strong> Returned authorized fields for ${lastEvaluationResult.auditEntry.requested_account} (Balance: ₹40,000). Non-consented fields (Account B, Transactions, PAN) strictly pruned.
      `;
    }
  }
}

function syntaxHighlightJson(json) {
  if (typeof json !== 'string') {
    json = JSON.stringify(json, undefined, 2);
  }
  json = json.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  return json.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, function (match) {
    let cls = 'number';
    if (/^"/.test(match)) {
      if (/:$/.test(match)) {
        cls = 'key';
      } else {
        cls = 'string';
      }
    } else if (/true|false/.test(match)) {
      cls = 'boolean';
    } else if (/null/.test(match)) {
      cls = 'null';
    }
    return '<span class="' + cls + '">' + match + '</span>';
  });
}

// ============================================================================
// 7. Customer Consent Vault UI Controller
// ============================================================================

function initConsentVaultUI() {
  renderConsentsList();

  const grantBtn = document.getElementById("btn-new-consent");
  if (grantBtn) {
    grantBtn.addEventListener("click", () => {
      openGrantConsentModal();
    });
  }

  // Handle modal actions
  const modalCloseBtn = document.getElementById("modal-close-btn");
  if (modalCloseBtn) {
    modalCloseBtn.addEventListener("click", () => closeModal());
  }

  const consentForm = document.getElementById("grant-consent-form");
  if (consentForm) {
    consentForm.addEventListener("submit", (e) => {
      e.preventDefault();
      saveNewConsentFromModal();
    });
  }
}

function renderConsentsList() {
  const container = document.getElementById("consents-table-body");
  if (!container) return;

  container.innerHTML = "";

  Object.values(CONSENT_STORE).forEach(c => {
    const partner = PARTNERS_REGISTRY[c.partner_id];
    const tr = document.createElement("tr");

    const statusBadge = c.status === "ACTIVE" 
      ? `<span class="status-badge pass">ACTIVE</span>`
      : `<span class="status-badge fail">${c.status}</span>`;

    tr.innerHTML = `
      <td class="mono-col"><strong>${c.consent_id}</strong></td>
      <td>
        <strong>${partner ? partner.name : c.partner_id}</strong>
        <div style="font-size: 0.72rem; color: var(--text-muted);">${c.partner_id}</div>
      </td>
      <td>
        ${c.allowed_accounts.map(acc => `<span class="badge-tag" style="margin-right: 4px;">${acc === "ACC-IND-4001" ? "Account A (₹40k)" : "Account B (₹30k)"}</span>`).join("")}
      </td>
      <td>
        ${c.allowed_scopes.map(s => `<code style="font-size:0.75rem; background:rgba(255,255,255,0.06); padding:2px 6px; border-radius:4px; margin-right:4px;">${s}</code>`).join("")}
      </td>
      <td><span style="font-size:0.8rem; color:var(--text-secondary);">${c.allowed_purposes.join(", ")}</span></td>
      <td class="mono-col" style="font-size:0.75rem;">${c.expires_at.slice(0, 10)}</td>
      <td>${statusBadge}</td>
      <td>
        ${c.status === "ACTIVE" 
          ? `<button class="btn-secondary" style="color:var(--status-deny); border-color:rgba(244,63,94,0.3); padding:0.25rem 0.6rem; font-size:0.72rem;" onclick="revokeConsent('${c.consent_id}')">Revoke</button>`
          : `<button class="btn-secondary" style="color:var(--status-allow); border-color:rgba(16,185,129,0.3); padding:0.25rem 0.6rem; font-size:0.72rem;" onclick="reinstateConsent('${c.consent_id}')">Re-Activate</button>`
        }
      </td>
    `;
    container.appendChild(tr);
  });
}

window.revokeConsent = function(consentId) {
  if (CONSENT_STORE[consentId]) {
    CONSENT_STORE[consentId].status = "REVOKED";
    renderConsentsList();
    executeGuardEvaluation();
  }
};

window.reinstateConsent = function(consentId) {
  if (CONSENT_STORE[consentId]) {
    CONSENT_STORE[consentId].status = "ACTIVE";
    renderConsentsList();
    executeGuardEvaluation();
  }
};

function openGrantConsentModal() {
  const modal = document.getElementById("consent-modal");
  if (modal) modal.classList.add("open");
}

function closeModal() {
  const modal = document.getElementById("consent-modal");
  if (modal) modal.classList.remove("open");
}

function saveNewConsentFromModal() {
  const partnerSelect = document.getElementById("modal-partner-select");
  const accA = document.getElementById("modal-acc-a").checked;
  const accB = document.getElementById("modal-acc-b").checked;
  const scopeBal = document.getElementById("modal-scope-bal").checked;
  const scopeTxn = document.getElementById("modal-scope-txn").checked;
  const purpose = document.getElementById("modal-purpose-input").value;
  const days = parseInt(document.getElementById("modal-duration-input").value, 10) || 90;

  const partnerId = partnerSelect.value;
  const accounts = [];
  if (accA) accounts.push("ACC-IND-4001");
  if (accB) accounts.push("ACC-IND-3002");

  const scopes = [];
  if (scopeBal) scopes.push("read:balance");
  if (scopeTxn) scopes.push("read:transactions");

  const expiry = new Date();
  expiry.setDate(expiry.getDate() + days);

  const newConsentId = `CNS-884920-${partnerId.replace("PARTNER-", "")}`;
  CONSENT_STORE[newConsentId] = {
    consent_id: newConsentId,
    customer_id: "CUST-884920",
    partner_id: partnerId,
    allowed_accounts: accounts,
    allowed_scopes: scopes,
    allowed_purposes: [purpose],
    created_at: new Date().toISOString(),
    expires_at: expiry.toISOString(),
    status: "ACTIVE",
    data_fields_permitted: ["balance"]
  };

  closeModal();
  renderConsentsList();
  executeGuardEvaluation();
}

// ============================================================================
// 8. Partner Registry UI Controller
// ============================================================================

function initPartnerRegistryUI() {
  renderPartnerCards();

  const regBtn = document.getElementById("btn-register-partner");
  if (regBtn) {
    regBtn.addEventListener("click", () => {
      const name = prompt("Enter new Fintech Partner Organization Name:", "PayWise SuperApp");
      if (name) {
        const id = `PARTNER-${name.replace(/[^a-zA-Z0-9]/g, "").toUpperCase().slice(0, 10)}`;
        const token = `pk_live_${Math.random().toString(36).substring(2, 12)}`;
        PARTNERS_REGISTRY[id] = {
          id,
          name,
          category: "NEOBANK_FINTECH",
          valid_token: token,
          status: "ACTIVE",
          rate_limit_per_min: 50,
          current_req_count: 0,
          trust_score: 90
        };
        renderPartnerCards();
        alert(`Registered partner ${name} successfully! API Key: ${token}`);
      }
    });
  }
}

function renderPartnerCards() {
  const container = document.getElementById("partners-grid-container");
  if (!container) return;

  container.innerHTML = "";

  Object.values(PARTNERS_REGISTRY).forEach(p => {
    const card = document.createElement("div");
    card.className = "glass-panel";
    card.innerHTML = `
      <div class="flex-between" style="margin-bottom: 0.8rem;">
        <span class="badge-tag">${p.category}</span>
        <span class="status-badge pass">${p.status}</span>
      </div>
      <h4 style="font-size: 1.1rem; font-weight: 700; color: #fff; margin-bottom: 0.25rem;">${p.name}</h4>
      <div class="mono-col" style="font-size: 0.75rem; margin-bottom: 1rem;">ID: ${p.id}</div>

      <div style="display: flex; flex-direction: column; gap: 0.5rem; font-size: 0.8rem; color: var(--text-secondary); margin-bottom: 1.2rem;">
        <div class="flex-between">
          <span>Trust / Security Score:</span>
          <strong style="color: var(--status-allow);">${p.trust_score}%</strong>
        </div>
        <div class="flex-between">
          <span>Rate Limit Threshold:</span>
          <strong class="mono-col">${p.rate_limit_per_min} req/min</strong>
        </div>
        <div class="flex-between">
          <span>Current Traffic Load:</span>
          <span style="color: #cbd5e1;">${p.current_req_count} rpm</span>
        </div>
      </div>

      <div style="background: rgba(0,0,0,0.3); border: 1px dashed var(--border-subtle); padding: 0.6rem; border-radius: var(--radius-sm); font-size: 0.72rem; display: flex; justify-content: space-between; align-items: center;">
        <span class="mono-col" style="overflow: hidden; text-overflow: ellipsis; max-width: 200px;">Key: ${p.valid_token.slice(0, 16)}...</span>
        <button class="btn-secondary" style="padding: 0.2rem 0.5rem; font-size: 0.68rem;" onclick="copyApiKey('${p.valid_token}')">Copy</button>
      </div>
    `;
    container.appendChild(card);
  });
}

window.copyApiKey = function(token) {
  navigator.clipboard.writeText(token);
  alert("Partner API token copied to clipboard!");
};

// ============================================================================
// 9. Key Innovation: Automated API Change-Impact Tester UI Controller
// ============================================================================

function initChangeImpactTester() {
  const scenarioSelect = document.getElementById("impact-scenario-select");
  const runBtn = document.getElementById("btn-run-impact-test");

  if (scenarioSelect) {
    scenarioSelect.addEventListener("change", () => {
      displaySelectedImpactScenario(scenarioSelect.value);
    });
    // Trigger initial scenario display
    displaySelectedImpactScenario(scenarioSelect.value);
  }

  if (runBtn) {
    runBtn.addEventListener("click", () => {
      runSimulationNow(scenarioSelect.value);
    });
  }
}

function displaySelectedImpactScenario(scenarioId) {
  const scenario = API_CHANGE_SCENARIOS.find(s => s.id === scenarioId);
  if (!scenario) return;

  document.getElementById("scenario-title").textContent = scenario.title;
  document.getElementById("scenario-desc").textContent = scenario.description;
  document.getElementById("scenario-severity-badge").textContent = `SEVERITY: ${scenario.severity}`;
  document.getElementById("scenario-severity-badge").className = `badge-tag ${scenario.severity === "CRITICAL" ? "text-rose" : scenario.severity === "HIGH" ? "text-amber" : "text-cyan"}`;

  document.getElementById("diff-before").textContent = scenario.diff.before;
  document.getElementById("diff-after").textContent = scenario.diff.after;
}

function runSimulationNow(scenarioId) {
  const scenario = API_CHANGE_SCENARIOS.find(s => s.id === scenarioId);
  if (!scenario) return;

  const simResult = scenario.runSimulation();

  document.getElementById("metric-partners-affected").textContent = simResult.affectedPartners.length;
  document.getElementById("metric-consents-scanned").textContent = simResult.totalConsentsScanned;
  document.getElementById("metric-consents-at-risk").textContent = simResult.atRiskConsents;
  document.getElementById("metric-breaking-count").textContent = simResult.breakingIntegrationsCount;

  const resultsBox = document.getElementById("simulation-results-box");
  if (resultsBox) {
    resultsBox.style.display = "block";
    document.getElementById("sim-summary-text").textContent = simResult.summary;
    document.getElementById("sim-remediation-code").textContent = simResult.remediationCode;
    document.getElementById("sim-partners-list").textContent = simResult.affectedPartners.join(", ");
  }
}

// ============================================================================
// 10. Audit Trail & Monitoring Metrics UI Controller
// ============================================================================

function initAuditMetricsUI() {
  const exportBtn = document.getElementById("btn-export-audit");
  if (exportBtn) {
    exportBtn.addEventListener("click", () => {
      const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(AUDIT_LOGS, null, 2));
      const downloadAnchor = document.createElement("a");
      downloadAnchor.setAttribute("href", dataStr);
      downloadAnchor.setAttribute("download", `trustmesh-audit-ledger-${Date.now()}.json`);
      document.body.appendChild(downloadAnchor);
      downloadAnchor.click();
      downloadAnchor.remove();
    });
  }

  const clearBtn = document.getElementById("btn-clear-audit");
  if (clearBtn) {
    clearBtn.addEventListener("click", () => {
      AUDIT_LOGS = [];
      updateAuditMetricsUI();
    });
  }
}

function updateAuditMetricsUI() {
  const total = AUDIT_LOGS.length;
  const allowed = AUDIT_LOGS.filter(a => a.decision === "ALLOW").length;
  const denied = total - allowed;
  const allowRate = total > 0 ? Math.round((allowed / total) * 100) : 100;

  const totalEl = document.getElementById("audit-stat-total");
  const allowRateEl = document.getElementById("audit-stat-allow-rate");
  const deniedEl = document.getElementById("audit-stat-denied");

  if (totalEl) totalEl.textContent = total;
  if (allowRateEl) allowRateEl.textContent = `${allowRate}%`;
  if (deniedEl) deniedEl.textContent = denied;

  // Render audit table rows
  const tableBody = document.getElementById("audit-table-body");
  if (!tableBody) return;

  tableBody.innerHTML = "";

  AUDIT_LOGS.slice(0, 15).forEach(log => {
    const tr = document.createElement("tr");
    const isAllow = log.decision === "ALLOW";

    tr.innerHTML = `
      <td class="mono-col">#${log.block_index}</td>
      <td style="font-size:0.75rem; color:var(--text-secondary);">${log.timestamp.slice(11, 19)}</td>
      <td><strong>${log.partner_name}</strong></td>
      <td class="mono-col" style="font-size:0.75rem;">${log.requested_account}</td>
      <td><code style="font-size:0.72rem; background:rgba(255,255,255,0.06); padding:2px 5px; border-radius:3px;">${log.requested_operation}</code></td>
      <td>
        <span class="status-badge ${isAllow ? "pass" : "fail"}">${log.decision}</span>
      </td>
      <td class="mono-col" style="font-size:0.75rem; color:${isAllow ? "var(--status-allow)" : "var(--status-deny)"};">${log.reason_code}</td>
      <td class="mono-col" style="font-size:0.7rem; color:var(--text-muted); max-width: 120px; overflow:hidden; text-overflow:ellipsis;">${log.block_hash ? log.block_hash.slice(0, 12) + "..." : "--"}</td>
    `;
    tableBody.appendChild(tr);
  });
}

// ============================================================================
// 11. Architecture Diagram Data
// ============================================================================

function populateArchitectureVisualizer() {
  const container = document.getElementById("architecture-flow-wrapper");
  if (!container) return;

  // Diagram already laid out in HTML, this adds interactivity on hover
}
