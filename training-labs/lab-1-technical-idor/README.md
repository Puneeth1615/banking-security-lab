# Functional Training Lab 1: Eliminating IDOR in Core Banking REST APIs
**Track:** Technical Builders & Backend Engineers (Track A)  
**Curriculum Alignment:** Module 5 (Broken Access Control - A01:2025)  
**Duration:** 30 Minutes  
**Tooling Prerequisites:** Python 3.10+, `unittest`, `requests` / `flask`  

---

## 1. Lab Overview & Threat Context
In financial banking architectures, **Insecure Direct Object References (IDOR)** occur when an API endpoint uses client-supplied identifiers to retrieve financial records (such as account statements, wire history, or loan dossiers) without verifying whether the authenticated user holds legitimate access rights.

In this lab, you will audit a vulnerable banking statement retrieval endpoint, exploit the IDOR flaw to access unauthorized executive statements, refactor the endpoint using contextual session validation, and verify the patch with automated unit tests.

---

## 2. Sample Dataset (`banking_records.json`)
The laboratory testbed is seeded with the following customer accounts and statement records:

```json
[
  {"statement_id": 1001, "account_id": 101, "customer": "Alice Smith", "type": "Checking", "balance": 154200.50, "last_tx": "Client Retainer (+$15,000.00)"},
  {"statement_id": 1002, "account_id": 102, "customer": "Bob Johnson", "type": "Treasury", "balance": 2890400.00, "last_tx": "Cloud Vendor (-$42,500.00)"},
  {"statement_id": 1003, "account_id": 104, "customer": "David Sterling (CFO)", "type": "Corporate Settlement", "balance": 12450000.00, "last_tx": "Interbank Wire (-$500,000.00)"}
]
```

---

## 3. Vulnerable Code Implementation
Review the vulnerable route below from `banking_api.py`:

```python
# VULNERABLE ENDPOINT: Relies strictly on client-provided URL parameter
@app.route("/api/v1/statements/<int:statement_id>", methods=["GET"])
def get_statement(statement_id):
    # Authenticated user is present in session context, but NOT checked against the object!
    current_user_id = session.get("authenticated_account_id")
    
    statement = db.query("SELECT * FROM statements WHERE id = ?", (statement_id,)).fetchone()
    if not statement:
        return jsonify({"error": "Statement not found"}), 404
        
    # FLUID VULNERABILITY: Returns statement regardless of current_user_id
    return jsonify({
        "status": 200,
        "statement_id": statement["id"],
        "account_id": statement["account_id"],
        "details": statement["last_tx"],
        "balance": statement["balance"]
    }), 200
```

---

## 4. Hands-on Exercise: Exploit & Patch
### Step 1: Execute Unauthorized Access (Exploit Drill)
1. Authenticate as **Alice Smith** (`authenticated_account_id = 101`).
2. Send a request targeting Statement #1003: `GET /api/v1/statements/1003`.
3. Observe that the API returns CFO David Sterling's confidential $500,000 interbank wire details.

### Step 2: Implement Contextual Defensive Control (Remediation)
Refactor the route to enforce a multi-tenant ownership gate:

```python
# SECURE IMPLEMENTATION: Enforces object ownership gate
@app.route("/api/v1/statements/<int:statement_id>", methods=["GET"])
def get_statement_secure(statement_id):
    current_user_id = session.get("authenticated_account_id")
    if not current_user_id:
        return jsonify({"error": "Authentication Required"}), 401

    # SECURE GATE: Query explicitly binds statement_id AND authenticated account_id
    statement = db.query(
        "SELECT * FROM statements WHERE id = ? AND account_id = ?", 
        (statement_id, current_user_id)
    ).fetchone()
    
    if not statement:
        # Prevent user enumeration: return 403 Forbidden
        return jsonify({
            "error": "Access Denied: You do not possess permission to access this financial record."
        }), 403

    return jsonify({
        "status": 200,
        "statement_id": statement["id"],
        "details": statement["last_tx"]
    }), 200
```

---

## 5. Automated Unit Test Verification (`test_idor_remediation.py`)
Run the following test to verify that the patch passes automated CI/CD gates:

```python
import unittest

class TestStatementAuthorization(unittest.TestCase):
    def test_alice_cannot_view_cfo_statement(self):
        # Alice (Account 101) attempts to view Statement 1003 (CFO Account 104)
        response = client.get("/api/v1/statements/1003", session={"authenticated_account_id": 101})
        self.assertEqual(response.status_code, 403)
        self.assertIn("Access Denied", response.json["error"])

    def test_alice_can_view_own_statement(self):
        # Alice (Account 101) attempts to view Statement 1001 (Own Account 101)
        response = client.get("/api/v1/statements/1001", session={"authenticated_account_id": 101})
        self.assertEqual(response.status_code, 200)

if __name__ == "__main__":
    unittest.main()
```
