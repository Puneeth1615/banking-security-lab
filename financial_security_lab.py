# Internship project - First Quadrant Labs
"""
Financial Services Security Laboratory (Controlled Demonstration)
Simulating core banking web services for OWASP Top 10 vulnerability demonstration
and automated defensive verification.
"""
import sqlite3
import os
import json
import time

class FinancialSecurityLab:
    def __init__(self, db_path=":memory:"):
        self.conn = sqlite3.connect(db_path)
        self.init_db()
        self.failed_login_attempts = {}

    def init_db(self):
        c = self.conn.cursor()
        c.execute("""
            CREATE TABLE accounts (
                id INTEGER PRIMARY KEY,
                account_number TEXT,
                owner_name TEXT,
                account_type TEXT,
                balance REAL,
                secret_pin TEXT
            )
        """)
        c.execute("""
            CREATE TABLE statements (
                id INTEGER PRIMARY KEY,
                account_id INTEGER,
                transaction_date TEXT,
                description TEXT,
                amount REAL,
                pan_masked TEXT
            )
        """)
        # Seed realistic banking records
        accounts = [
            (101, "ACCT-992144", "Alice Smith", "Commercial Checking", 154200.50, "4892"),
            (102, "ACCT-883921", "Bob Johnson", "Treasury Reserve", 2890400.00, "1129"),
            (103, "ACCT-774102", "Carol White", "Private Wealth", 950000.00, "9032"),
            (104, "ACCT-665201", "David Sterling (CFO)", "Corporate Settlement", 12450000.00, "7714")
        ]
        c.executemany("INSERT INTO accounts VALUES (?, ?, ?, ?, ?, ?)", accounts)
        
        statements = [
            (1001, 101, "2026-10-15", "Wire Inflow - Client Retainer", 15000.00, "************4412"),
            (1002, 102, "2026-10-18", "Vendor Clearing - Cloud Host", -42500.00, "************8839"),
            (1003, 104, "2026-10-22", "Interbank Settlement - FX Batch", -500000.00, "************7714")
        ]
        c.executemany("INSERT INTO statements VALUES (?, ?, ?, ?, ?, ?)", statements)
        self.conn.commit()

    # --- 1. SQL INJECTION (OWASP A05) ---
    def vulnerable_search_account(self, query):
        """VULNERABLE: Direct string interpolation into SQL query"""
        sql = f"SELECT account_number, owner_name, account_type, balance FROM accounts WHERE owner_name = '{query}'"
        cursor = self.conn.cursor()
        cursor.execute(sql)
        return cursor.fetchall(), sql

    def secure_search_account(self, query):
        """SECURE: Parameterized SQL query using prepared statement"""
        sql = "SELECT account_number, owner_name, account_type, balance FROM accounts WHERE owner_name = ?"
        cursor = self.conn.cursor()
        cursor.execute(sql, (query,))
        return cursor.fetchall(), sql

    # --- 2. BROKEN ACCESS CONTROL / IDOR (OWASP A01) ---
    def vulnerable_get_statement(self, requested_statement_id, logged_in_account_id):
        """VULNERABLE: Direct object reference without verifying account ownership"""
        c = self.conn.cursor()
        c.execute("SELECT id, account_id, transaction_date, description, amount, pan_masked FROM statements WHERE id = ?", (requested_statement_id,))
        row = c.fetchone()
        if row:
            return {"status": 200, "data": row, "auth_check": "FAILED - Object accessed directly without ownership check"}
        return {"status": 404, "error": "Statement not found"}

    def secure_get_statement(self, requested_statement_id, logged_in_account_id):
        """SECURE: Multi-tenant tenant verification enforcing ownership gate"""
        c = self.conn.cursor()
        c.execute("SELECT id, account_id, transaction_date, description, amount, pan_masked FROM statements WHERE id = ? AND account_id = ?", 
                  (requested_statement_id, logged_in_account_id))
        row = c.fetchone()
        if row:
            return {"status": 200, "data": row, "auth_check": "PASSED - Ownership verified"}
        return {"status": 403, "error": "Access Denied: You do not have permission to view statements outside your authenticated account."}

    # --- 3. BROKEN AUTHENTICATION & RATE LIMITING (OWASP A07) ---
    def vulnerable_login(self, account_id, pin):
        """VULNERABLE: No rate limiting, allows infinite brute-force guesses"""
        c = self.conn.cursor()
        c.execute("SELECT id, owner_name FROM accounts WHERE id = ? AND secret_pin = ?", (account_id, pin))
        user = c.fetchone()
        if user:
            return {"status": 200, "message": f"Login successful as {user[1]}"}
        return {"status": 401, "message": "Invalid credentials"}

    def secure_login(self, account_id, pin, ip_address="192.168.1.100"):
        """SECURE: Rate limiting and account lockout after 3 failed attempts"""
        key = f"{account_id}:{ip_address}"
        attempts = self.failed_login_attempts.get(key, 0)
        if attempts >= 3:
            return {"status": 429, "message": "Account Locked: Exceeded maximum allowed authentication attempts (3). Security alert dispatched to SOC."}

        c = self.conn.cursor()
        c.execute("SELECT id, owner_name FROM accounts WHERE id = ? AND secret_pin = ?", (account_id, pin))
        user = c.fetchone()
        if user:
            self.failed_login_attempts[key] = 0
            return {"status": 200, "message": f"Login successful as {user[1]} (Phishing-resistant session issued)"}
        
        self.failed_login_attempts[key] = attempts + 1
        return {"status": 401, "message": f"Invalid credentials. Attempt {attempts + 1} of 3."}

    # --- 4. SECURITY MISCONFIGURATION (OWASP A02) ---
    def vulnerable_debug_endpoint(self, is_admin=False):
        """VULNERABLE: Debug endpoint accessible to untrusted callers exposing internal stack and environment"""
        return {
            "status": 200,
            "environment": "PRODUCTION-BANKING-CLUSTER-01",
            "db_connection": "postgresql://db_admin:MasterSecure2026!@10.0.4.12:5432/core_banking",
            "internal_ip": "10.0.12.54",
            "active_sessions": 342,
            "debug_trace": "DEBUG_MODE_ENABLED: Verbose stack logging active on public interface"
        }

    def secure_debug_endpoint(self, is_admin=False):
        """SECURE: Endpoint strictly restricted to internal loopback and disabled in production"""
        if not is_admin:
            return {"status": 404, "error": "Not Found"}
        return {"status": 403, "error": "Endpoint Disabled in Production Configuration"}

if __name__ == "__main__":
    import run_security_lab_tests
    run_security_lab_tests.run_all_tests()
