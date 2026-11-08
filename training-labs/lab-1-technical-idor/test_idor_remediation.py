import unittest
import json
import os

class MockBankingAPI:
    def __init__(self, data_file):
        with open(data_file, 'r', encoding='utf-8') as f:
            self.statements = json.load(f)

    def get_statement_vulnerable(self, statement_id, session_account_id):
        """Vulnerable endpoint: returns statement without verifying ownership."""
        for stmt in self.statements:
            if stmt["statement_id"] == statement_id:
                return 200, stmt
        return 404, {"error": "Statement not found"}

    def get_statement_secure(self, statement_id, session_account_id):
        """Secure endpoint: verifies object ownership against authenticated session."""
        if not session_account_id:
            return 401, {"error": "Authentication Required"}
            
        for stmt in self.statements:
            if stmt["statement_id"] == statement_id:
                if stmt["account_id"] != session_account_id:
                    return 403, {"error": "Access Denied: You do not possess permission to access this financial record."}
                return 200, stmt
        return 404, {"error": "Statement not found"}

class TestIDORRemediation(unittest.TestCase):
    def setUp(self):
        curr_dir = os.path.dirname(os.path.abspath(__file__))
        data_file = os.path.join(curr_dir, "banking_records.json")
        self.api = MockBankingAPI(data_file)

    def test_01_vulnerable_endpoint_leaks_cfo_statement(self):
        """Alice (Account 101) attempts to view CFO statement 1003 on vulnerable endpoint."""
        status, data = self.api.get_statement_vulnerable(statement_id=1003, session_account_id=101)
        self.assertEqual(status, 200)
        self.assertEqual(data["customer"], "David Sterling (CFO)")
        print("\n  [!] Confirmed IDOR Exploit: Alice (101) accessed CFO Statement 1003 ($12.45M)")

    def test_02_secure_endpoint_blocks_alice(self):
        """Alice (Account 101) attempts to view CFO statement 1003 on remediated secure endpoint."""
        status, data = self.api.get_statement_secure(statement_id=1003, session_account_id=101)
        self.assertEqual(status, 403)
        self.assertIn("Access Denied", data["error"])
        print("  [+] Confirmed IDOR Remediation: Horizontal access denied with HTTP 403 Forbidden")

    def test_03_alice_can_view_own_statement(self):
        """Alice (Account 101) accesses her own statement 1001."""
        status, data = self.api.get_statement_secure(statement_id=1001, session_account_id=101)
        self.assertEqual(status, 200)
        self.assertEqual(data["customer"], "Alice Smith")
        print("  [+] Confirmed Authorized Access: Alice (101) accessed own Statement 1001")

    def test_04_unauthenticated_request_rejected(self):
        """Unauthenticated request is rejected with HTTP 401."""
        status, data = self.api.get_statement_secure(statement_id=1001, session_account_id=None)
        self.assertEqual(status, 401)
        print("  [+] Confirmed Auth Gate: Unauthenticated request rejected with HTTP 401")

if __name__ == "__main__":
    print("=" * 70)
    print("RUNNING LAB 1 TEST HARNESS: IDOR REMEDIATION IN BANKING API")
    print("=" * 70)
    unittest.main()
