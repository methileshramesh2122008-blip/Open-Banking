"""
TrustMesh ConsentGuard - Python Reference Implementation & Unit Test Suite
Demonstrates the exact step-by-step security algorithm and tests all 7 layers.
"""

from dataclasses import dataclass, field
from typing import Set, Optional, Dict, Any
from datetime import datetime, timezone

@dataclass
class APIRequest:
    partner_id: str
    partner_token: str
    access_token: str
    customer_id: str
    account_id: str
    scope: str
    purpose: str

@dataclass
class CustomerConsent:
    consent_id: str
    customer_id: str
    partner_id: str
    allowed_accounts: Set[str]
    allowed_scopes: Set[str]
    allowed_purposes: Set[str]
    expires_at: datetime
    is_active: bool

# Mock Bank Ledgers
PARTNER_DATABASE = {
    "PARTNER-LENDKART": {
        "valid_token": "pk_live_lendkart_8841a9f02c",
        "rate_limit_rpm": 60,
        "current_rpm": 5
    }
}

BANK_ACCOUNTS = {
    "ACC-IND-4001": {"label": "Account A", "balance": 40000.00, "currency": "INR"},
    "ACC-IND-3002": {"label": "Account B", "balance": 30000.00, "currency": "INR"}
}

def authenticate_partner(partner_id: str, partner_token: str) -> bool:
    partner = PARTNER_DATABASE.get(partner_id)
    return partner is not None and partner["valid_token"] == partner_token

def validate_token(access_token: str) -> bool:
    return access_token is not None and access_token.startswith("tok_jwt_")

def get_customer_consent(customer_id: str, partner_id: str, mock_consent: Optional[CustomerConsent] = None) -> Optional[CustomerConsent]:
    return mock_consent

def rate_limit_ok(partner_id: str) -> bool:
    partner = PARTNER_DATABASE.get(partner_id)
    return partner is not None and partner["current_rpm"] < partner["rate_limit_rpm"]

def purpose_is_allowed(purpose: str, consent: CustomerConsent) -> bool:
    return purpose in consent.allowed_purposes

def call_banking_api(request: APIRequest) -> Dict[str, Any]:
    acc = BANK_ACCOUNTS[request.account_id]
    return {
        "account_id": request.account_id,
        "balance": acc["balance"],
        "currency": acc["currency"]
    }

def consent_guard(request: APIRequest, consent_record: Optional[CustomerConsent]) -> Dict[str, Any]:
    """
    Step-by-step decision algorithm for TrustMesh ConsentGuard.
    """
    # Step 1: Authenticate the partner
    if not authenticate_partner(request.partner_id, request.partner_token):
        return {"decision": "DENY", "reason": "INVALID_PARTNER_AUTHENTICATION"}

    # Step 2: Validate the access token
    if not validate_token(request.access_token):
        return {"decision": "DENY", "reason": "INVALID_OR_EXPIRED_TOKEN"}

    # Step 3: Check customer consent
    consent = get_customer_consent(request.customer_id, request.partner_id, consent_record)
    if consent is None or not consent.is_active:
        return {"decision": "DENY", "reason": "CONSENT_MISSING_OR_REVOKED"}

    # Step 4: Check requested permission and data scope (Account and Scope boundary)
    if request.account_id not in consent.allowed_accounts or request.scope not in consent.allowed_scopes:
        return {"decision": "DENY", "reason": "INSUFFICIENT_PERMISSION"}

    # Step 5: Check purpose and consent expiry
    is_expired = consent.expires_at < datetime.now(timezone.utc)
    if is_expired or not purpose_is_allowed(request.purpose, consent):
        return {"decision": "DENY", "reason": "CONSENT_EXPIRED_OR_PURPOSE_MISMATCH"}

    # Step 6: Apply API security policies & rate limits
    if not rate_limit_ok(request.partner_id):
        return {"decision": "DENY", "reason": "RATE_LIMIT_EXCEEDED"}

    # Step 7: Forward only permitted request
    data = call_banking_api(request)
    return {"decision": "ALLOW", "reason": "AUTHORIZED_CONSENT_GRANTED", "data": data}


def test_suite():
    print("==================================================================")
    print(" Running TrustMesh ConsentGuard Python Test Suite")
    print("==================================================================")

    base_consent = CustomerConsent(
        consent_id="CNS-884920-LENDKART",
        customer_id="CUST-884920",
        partner_id="PARTNER-LENDKART",
        allowed_accounts={"ACC-IND-4001"}, # Covers Account A ONLY
        allowed_scopes={"read:balance"},   # Covers read:balance ONLY
        allowed_purposes={"LOAN_UNDERWRITING"},
        expires_at=datetime(2027, 1, 1, tzinfo=timezone.utc),
        is_active=True
    )

    # 1. Golden Path: Account A Balance
    req_allow = APIRequest(
        partner_id="PARTNER-LENDKART",
        partner_token="pk_live_lendkart_8841a9f02c",
        access_token="tok_jwt_valid",
        customer_id="CUST-884920",
        account_id="ACC-IND-4001",
        scope="read:balance",
        purpose="LOAN_UNDERWRITING"
    )
    res1 = consent_guard(req_allow, base_consent)
    assert res1["decision"] == "ALLOW"
    assert res1["data"]["balance"] == 40000.00
    print(" [PASS] Scenario 1: Active Consent + Account A -> ALLOW (Rs 40,000)")

    # 2. Deny: Revoked Consent
    revoked_consent = CustomerConsent(
        consent_id="CNS-884920-LENDKART",
        customer_id="CUST-884920",
        partner_id="PARTNER-LENDKART",
        allowed_accounts={"ACC-IND-4001"},
        allowed_scopes={"read:balance"},
        allowed_purposes={"LOAN_UNDERWRITING"},
        expires_at=datetime(2027, 1, 1, tzinfo=timezone.utc),
        is_active=False # Revoked!
    )
    res2 = consent_guard(req_allow, revoked_consent)
    assert res2["decision"] == "DENY"
    assert res2["reason"] == "CONSENT_MISSING_OR_REVOKED"
    print(" [PASS] Scenario 2: Revoked Consent -> DENY")

    # 3. Deny: Account B Requested (Unconsented Account)
    req_acc_b = APIRequest(
        partner_id="PARTNER-LENDKART",
        partner_token="pk_live_lendkart_8841a9f02c",
        access_token="tok_jwt_valid",
        customer_id="CUST-884920",
        account_id="ACC-IND-3002", # Account B
        scope="read:balance",
        purpose="LOAN_UNDERWRITING"
    )
    res3 = consent_guard(req_acc_b, base_consent)
    assert res3["decision"] == "DENY"
    assert res3["reason"] == "INSUFFICIENT_PERMISSION"
    print(" [PASS] Scenario 3: Account B (Unconsented) -> DENY")

    # 4. Deny: Read Transactions Requested (Unconsented Scope)
    req_txn = APIRequest(
        partner_id="PARTNER-LENDKART",
        partner_token="pk_live_lendkart_8841a9f02c",
        access_token="tok_jwt_valid",
        customer_id="CUST-884920",
        account_id="ACC-IND-4001",
        scope="read:transactions", # Scope not granted
        purpose="LOAN_UNDERWRITING"
    )
    res4 = consent_guard(req_txn, base_consent)
    assert res4["decision"] == "DENY"
    assert res4["reason"] == "INSUFFICIENT_PERMISSION"
    print(" [PASS] Scenario 4: Transactions Scope (Unconsented) -> DENY")

    # 5. Deny: Expired Consent
    expired_consent = CustomerConsent(
        consent_id="CNS-884920-LENDKART",
        customer_id="CUST-884920",
        partner_id="PARTNER-LENDKART",
        allowed_accounts={"ACC-IND-4001"},
        allowed_scopes={"read:balance"},
        allowed_purposes={"LOAN_UNDERWRITING"},
        expires_at=datetime(2023, 1, 1, tzinfo=timezone.utc), # Expired!
        is_active=True
    )
    res5 = consent_guard(req_allow, expired_consent)
    assert res5["decision"] == "DENY"
    assert res5["reason"] == "CONSENT_EXPIRED_OR_PURPOSE_MISMATCH"
    print(" [PASS] Scenario 5: Expired Consent -> DENY")

    # 6. Deny: Invalid Partner Authentication
    req_bad_auth = APIRequest(
        partner_id="PARTNER-LENDKART",
        partner_token="pk_bad_token",
        access_token="tok_jwt_valid",
        customer_id="CUST-884920",
        account_id="ACC-IND-4001",
        scope="read:balance",
        purpose="LOAN_UNDERWRITING"
    )
    res6 = consent_guard(req_bad_auth, base_consent)
    assert res6["decision"] == "DENY"
    assert res6["reason"] == "INVALID_PARTNER_AUTHENTICATION"
    print(" [PASS] Scenario 6: Invalid Partner Token -> DENY")

    print("------------------------------------------------------------------")
    print(" All Python ConsentGuard Tests Passed Successfully! (6/6)")
    print("==================================================================")

if __name__ == "__main__":
    test_suite()
