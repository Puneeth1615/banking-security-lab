# Internship project - First Quadrant Labs
"""
First Quadrant Commercial Bank - Automated Security Testing Harness
Demonstrates Two-Phase Testing:
  Phase 1: Baseline Vulnerability Assessment (Unmitigated Exploit Execution)
  Phase 2: Hardened Production Retest (Defensive Interception & Verification)

Supports CLI flags:
  python run_security_lab_tests.py --mode vulnerable
  python run_security_lab_tests.py --mode hardened
  python run_security_lab_tests.py --interactive
  python run_security_lab_tests.py
"""
import sys
import argparse
import urllib.request
import urllib.error
import urllib.parse
import json
from financial_security_lab import FinancialSecurityLab

BASE_URL = "http://127.0.0.1:5000"

def check_server_available():
    try:
        req = urllib.request.urlopen(f"{BASE_URL}/api/mode", timeout=1.5)
        return req.getcode() == 200
    except Exception:
        return False

def set_server_mode(mode):
    try:
        url = f"{BASE_URL}/api/mode?set={mode}"
        urllib.request.urlopen(url, timeout=2.0)
    except Exception:
        pass

def run_phase_1_vulnerable(use_http=True):
    print("=" * 80)
    print("   [ASSESSMENT PHASE 1: BASELINE PENETRATION TEST (VULNERABLE APPLICATION)]")
    print("=" * 80)
    print(f"[*] Target Architecture: First Quadrant Commercial Bank (Local Testbed)")
    print(f"[*] Execution Mode: VULNERABLE (Defensive filters, contextual gates, and rate limits disabled)")
    print(f"[*] Telemetry: Capturing unmitigated exploit execution across OWASP Top 10 vectors\n")

    lab = FinancialSecurityLab()
    if use_http:
        set_server_mode("vulnerable")

    # TEST 1: SQL INJECTION
    print("[TEST 1 / 4] Vector: SQL Injection in Customer Account Directory (A03 / A05)")
    print("-" * 75)
    exploit_payload = "Alice Smith' OR '1'='1"
    print(f"[*] Injecting malicious SQL syntax into search field: \"{exploit_payload}\"")
    
    if use_http:
        url = f"{BASE_URL}/api/search?q={urllib.parse.quote(exploit_payload)}&mode=vulnerable"
        with urllib.request.urlopen(url) as resp:
            data = json.loads(resp.read().decode())
        executed_sql = data.get("executed_sql")
        results = data.get("results", [])
        print(f"[*] Raw SQL Executed by Backend Database:")
        print(f"    --> {executed_sql}")
        print(f"[!] EXPLOIT COMPROMISE CONFIRMED: Database dumped {len(results)} accounts across all tenants:")
        for r in results:
            owner = r.get("owner_name")
            acct = r.get("account_number")
            bal = r.get("balance", 0.0)
            tag = " [CONFIDENTIAL EXECUTIVE RECORD]" if "CFO" in owner or "Sterling" in owner else ""
            print(f"    - Acct: {acct} | Holder: {owner:<22} | Balance: ${bal:,.2f}{tag}")
        assert len(results) >= 4, "Expected vulnerable SQLi to dump all records"
    else:
        records_vuln, sql_vuln = lab.vulnerable_search_account(exploit_payload)
        print(f"[*] Raw SQL Query Executed: {sql_vuln}")
        print(f"[!] EXPLOIT COMPROMISE CONFIRMED: Database dumped {len(records_vuln)} accounts across all tenants:")
        for r in records_vuln:
            print(f"    - Acct: {r[0]} | Holder: {r[1]:<22} | Balance: ${r[3]:,.2f}")
        assert len(records_vuln) >= 4

    # TEST 2: IDOR / BROKEN ACCESS CONTROL
    print("\n[TEST 2 / 4] Vector: Insecure Direct Object Reference (IDOR) on Bank Statements (A01)")
    print("-" * 75)
    alice_acct = 101
    target_cfo_stmt = 1003
    print(f"[*] Attacker Session Context: Authenticated as Alice Smith (Account #{alice_acct})")
    print(f"[*] Attacker Action: Requesting unowned Statement #{target_cfo_stmt} (Belonging to CFO David Sterling)")
    
    if use_http:
        url = f"{BASE_URL}/api/statements/{target_cfo_stmt}?mode=vulnerable"
        with urllib.request.urlopen(url) as resp:
            status_code = resp.getcode()
            stmt_data = json.loads(resp.read().decode()).get("statement", {})
        print(f"[!] EXPLOIT COMPROMISE CONFIRMED: HTTP {status_code} OK (Multi-Tenant Authorization Bypassed)")
        print(f"    - Statement Reference: STMT-{stmt_data.get('id')}")
        print(f"    - Transaction Date:    {stmt_data.get('transaction_date')}")
        print(f"    - Beneficiary / Payee: {stmt_data.get('recipient')}")
        print(f"    - Exposed Amount:      ${abs(stmt_data.get('amount', 0)):,.2f} USD [CONFIDENTIAL INTERBANK WIRE]")
        assert status_code == 200 and stmt_data.get("account_id") == 104
    else:
        resp_vuln = lab.vulnerable_get_statement(target_cfo_stmt, alice_acct)
        print(f"[!] EXPLOIT COMPROMISE CONFIRMED: HTTP {resp_vuln['status']} OK (Multi-Tenant Authorization Bypassed)")
        print(f"    - Statement ID: #{resp_vuln['data'][0]} | Date: {resp_vuln['data'][2]} | Amount: ${abs(resp_vuln['data'][4]):,.2f} USD")
        assert resp_vuln['status'] == 200

    # TEST 3: BRUTE FORCE & MISSING VELOCITY LIMITS
    print("\n[TEST 3 / 4] Vector: Automated Credential Brute-Force & Missing Velocity Controls (A07)")
    print("-" * 75)
    target_account = 101
    guesses = ["0000", "1234", "1111", "4892"]
    print(f"[*] Attacking High-Value Authorization PIN on Account #{target_account}")
    print(f"[*] Simulating automated dictionary attack (Payload list: {guesses})")
    
    cracked = False
    for idx, g in enumerate(guesses):
        if use_http:
            url = f"{BASE_URL}/api/login?pin={g}&mode=vulnerable"
            try:
                with urllib.request.urlopen(url) as resp:
                    status = resp.getcode()
                    msg = json.loads(resp.read().decode()).get("message")
                    print(f"    --> Attempt {idx+1} [PIN '{g}']: HTTP {status} -> {msg}")
                    if status == 200:
                        cracked = True
            except urllib.error.HTTPError as e:
                print(f"    --> Attempt {idx+1} [PIN '{g}']: HTTP {e.code}")
        else:
            res = lab.vulnerable_login(target_account, g)
            print(f"    --> Attempt {idx+1} [PIN '{g}']: HTTP {res['status']} -> {res['message']}")
            if res['status'] == 200:
                cracked = True
    assert cracked, "Expected brute-force dictionary attack to successfully crack PIN"
    print(f"[!] EXPLOIT COMPROMISE CONFIRMED: PIN 4892 cracked in 4 attempts without velocity lockouts.")

    # TEST 4: UNPROTECTED DEBUG ENDPOINT
    print("\n[TEST 4 / 4] Vector: Security Misconfiguration / Diagnostic Exposure (A05 / A02)")
    print("-" * 75)
    print(f"[*] Attacker scans administrative and diagnostic endpoints: GET /api/v1/admin/debug")
    if use_http:
        url = f"{BASE_URL}/api/v1/admin/debug?mode=vulnerable"
        with urllib.request.urlopen(url) as resp:
            dbg_status = resp.getcode()
            dbg_json = json.loads(resp.read().decode())
        print(f"[!] EXPLOIT COMPROMISE CONFIRMED: HTTP {dbg_status} OK (Internal Infrastructure Exposed!)")
        print(f"    - Environment:     {dbg_json.get('environment')}")
        print(f"    - Master DB URI:   {dbg_json.get('db_connection')}")
        print(f"    - Cluster IP:      {dbg_json.get('internal_ip')}")
        assert dbg_status == 200 and "db_connection" in dbg_json
    else:
        dbg_vuln = lab.vulnerable_debug_endpoint(is_admin=False)
        print(f"[!] EXPLOIT COMPROMISE CONFIRMED: HTTP {dbg_vuln['status']} OK (Internal Infrastructure Exposed!)")
        print(f"    - Master DB URI:   {dbg_vuln['db_connection']}")
        print(f"    - Cluster IP:      {dbg_vuln['internal_ip']}")
        assert dbg_vuln['status'] == 200

    print("\n" + "=" * 80)
    print("   [PHASE 1 SUMMARY] BASELINE PENETRATION TEST: 4/4 ATTACKS SUCCEEDED")
    print("   Status: CRITICAL VULNERABILITIES CONFIRMED ACROSS ALL ASSESSED VECTORS")
    print("   Recommendation: Immediate deployment of OWASP defensive controls.")
    print("=" * 80 + "\n")


def run_phase_2_hardened(use_http=True):
    print("=" * 80)
    print("   [ASSESSMENT PHASE 2: REMEDIATION VERIFICATION & DEFENSIVE RETEST]")
    print("=" * 80)
    print(f"[*] Target Architecture: First Quadrant Commercial Bank (Hardened Production)")
    print(f"[*] Execution Mode: HARDENED (Parameterized queries, contextual auth, velocity lockout active)")
    print(f"[*] Telemetry: Verifying defensive interception of identical attack suite\n")

    lab = FinancialSecurityLab()
    if use_http:
        set_server_mode("secure")

    # TEST 1: SQL INJECTION RETEST
    print("[TEST 1 / 4 RETEST] Vector: SQL Injection in Customer Account Directory (A03 / A05)")
    print("-" * 75)
    exploit_payload = "Alice Smith' OR '1'='1"
    print(f"[*] Re-injecting exploit payload: \"{exploit_payload}\"")
    
    if use_http:
        url = f"{BASE_URL}/api/search?q={urllib.parse.quote(exploit_payload)}&mode=secure"
        with urllib.request.urlopen(url) as resp:
            data = json.loads(resp.read().decode())
        executed_sql = data.get("executed_sql")
        results = data.get("results", [])
        print(f"[*] Secure Query Execution: Parameterized Prepared Statement:")
        print(f"    --> {executed_sql} (Parameters: ['{exploit_payload}'])")
        print(f"[+] DEFENSIVE CONTROL VERIFIED: Returned {len(results)} records.")
        print(f"    SQL injection completely neutralized; payload treated as literal search string.")
        assert len(results) == 0, "Security validation failed: records leaked under hardened mode!"
    else:
        records_sec, sql_sec = lab.secure_search_account(exploit_payload)
        print(f"[*] Secure Executed SQL Query: {sql_sec}")
        print(f"[+] DEFENSIVE CONTROL VERIFIED: Returned {len(records_sec)} records.")
        assert len(records_sec) == 0

    # TEST 2: IDOR RETEST
    print("\n[TEST 2 / 4 RETEST] Vector: Insecure Direct Object Reference (IDOR) on Bank Statements (A01)")
    print("-" * 75)
    alice_acct = 101
    target_cfo_stmt = 1003
    print(f"[*] Attacker Session Context: Authenticated as Alice Smith (Account #{alice_acct})")
    print(f"[*] Retesting unauthorized retrieval of CFO Statement #{target_cfo_stmt}")
    
    if use_http:
        url = f"{BASE_URL}/api/statements/{target_cfo_stmt}?mode=secure"
        try:
            resp = urllib.request.urlopen(url)
            status_code = resp.getcode()
            error_msg = "Unexpected 200 OK"
        except urllib.error.HTTPError as e:
            status_code = e.code
            error_data = json.loads(e.read().decode())
            error_msg = error_data.get("error")
        print(f"[+] DEFENSIVE CONTROL VERIFIED: HTTP {status_code} Forbidden")
        print(f"    - Interception Gate: Contextual Multi-Tenant Authorization")
        print(f"    - Gateway Telemetry: {error_msg}")
        assert status_code == 403, f"Expected HTTP 403, got {status_code}"
    else:
        resp_sec = lab.secure_get_statement(target_cfo_stmt, alice_acct)
        print(f"[+] DEFENSIVE CONTROL VERIFIED: HTTP {resp_sec['status']} Forbidden - {resp_sec['error']}")
        assert resp_sec['status'] == 403

    # TEST 3: BRUTE FORCE RETEST
    print("\n[TEST 3 / 4 RETEST] Vector: Automated Credential Brute-Force & Rate Limiting (A07)")
    print("-" * 75)
    target_account = 101
    guesses = ["0000", "1234", "1111", "4892"]
    print(f"[*] Re-executing dictionary attack with Velocity Rate Limiter active (Max 3 failed attempts):")
    
    lockout_engaged = False
    for idx, g in enumerate(guesses):
        if use_http:
            url = f"{BASE_URL}/api/login?pin={g}&mode=secure"
            try:
                with urllib.request.urlopen(url) as resp:
                    status = resp.getcode()
                    msg = json.loads(resp.read().decode()).get("message")
                    print(f"    --> Attempt {idx+1} [PIN '{g}']: HTTP {status} -> {msg}")
            except urllib.error.HTTPError as e:
                status = e.code
                data = json.loads(e.read().decode())
                msg = data.get("message")
                print(f"    --> Attempt {idx+1} [PIN '{g}']: HTTP {status} -> {msg}")
                if status == 429:
                    lockout_engaged = True
        else:
            res = lab.secure_login(target_account, g, ip_address="203.0.113.42")
            print(f"    --> Attempt {idx+1} [PIN '{g}']: HTTP {res['status']} -> {res['message']}")
            if res['status'] == 429:
                lockout_engaged = True
    assert lockout_engaged, "Expected velocity rate limiter to trigger HTTP 429 Account Locked!"
    print(f"[+] DEFENSIVE CONTROL VERIFIED: Account locked after 3 failures. Correct PIN 4892 blocked.")

    # TEST 4: UNPROTECTED DEBUG RETEST
    print("\n[TEST 4 / 4 RETEST] Vector: Security Misconfiguration / Diagnostic Exposure (A05 / A02)")
    print("-" * 75)
    print(f"[*] Probing diagnostic endpoint under hardened configuration: GET /api/v1/admin/debug")
    if use_http:
        url = f"{BASE_URL}/api/v1/admin/debug?mode=secure"
        try:
            resp = urllib.request.urlopen(url)
            dbg_status = resp.getcode()
            dbg_msg = "Route still accessible"
        except urllib.error.HTTPError as e:
            dbg_status = e.code
            dbg_msg = json.loads(e.read().decode()).get("error")
        print(f"[+] DEFENSIVE CONTROL VERIFIED: HTTP {dbg_status} Not Found")
        print(f"    - Hardening Control: Diagnostic endpoints stripped from production routing tables.")
        print(f"    - Telemetry: {dbg_msg}")
        assert dbg_status == 404, f"Expected HTTP 404, got {dbg_status}"
    else:
        dbg_sec = lab.secure_debug_endpoint(is_admin=False)
        print(f"[+] DEFENSIVE CONTROL VERIFIED: HTTP {dbg_sec['status']} Not Found - {dbg_sec['error']}")
        assert dbg_sec['status'] == 404

    print("\n" + "=" * 80)
    print("   [PHASE 2 SUMMARY] REMEDIATION VERIFICATION: 4/4 ATTACKS DEFENSIVELY MITIGATED")
    print("   Status: 100% DEFENSIVE SUCCESS - ALL OWASP THREATS SYSTEMICALLY NEUTRALIZED")
    print("   Validation: Zero unauthorized record disclosures, HTTP 403, HTTP 429, HTTP 404.")
    print("=" * 80 + "\n")


def main():
    parser = argparse.ArgumentParser(description="First Quadrant Bank - Automated Security Testing Harness")
    parser.add_argument("--mode", choices=["vulnerable", "hardened", "secure", "all"], default="all",
                        help="Select test phase to execute ('vulnerable', 'hardened', or 'all')")
    parser.add_argument("--interactive", action="store_true", help="Pause between Phase 1 and Phase 2")
    args = parser.parse_args()

    use_http = check_server_available()
    if use_http:
        print("[*] Live Web Application Detected at http://127.0.0.1:5000 - Executing over Live HTTP")
    else:
        print("[*] Live Web App Not Detected on port 5000 - Falling back to High-Fidelity Python Lab Engine")

    if args.mode == "vulnerable":
        run_phase_1_vulnerable(use_http)
    elif args.mode in ["hardened", "secure"]:
        run_phase_2_hardened(use_http)
    else:
        # Run Phase 1
        run_phase_1_vulnerable(use_http)
        if args.interactive:
            input("[PROMPT] Phase 1 Complete. Review compromised output above. Press ENTER to toggle hardened mode and execute retest...")
        else:
            print("\n>>> PROCEEDING TO REMEDIATION RETEST: HARDENED DEFENSIVE CONTROLS ENGAGED <<<\n")
        # Run Phase 2
        run_phase_2_hardened(use_http)

if __name__ == "__main__":
    main()
