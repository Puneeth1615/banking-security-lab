# First Quadrant Commercial Bank — Banking Security Lab
### Internship Project — First Quadrant Labs
**Author:** Bathala Puneeth  
**Project:** *Critical Infrastructure Cyber Attack: Cybersecurity Threats in the Finance Industry, an OWASP-Aligned Training Program, and an Infrastructure Security Integration Plan*

---

## Overview

**Banking Security Lab** is an operational financial services application and cybersecurity training lab suite engineered for **First Quadrant Labs**. It provides an interactive commercial banking portal with dynamic security switching, automated OWASP Top 10:2025 attack simulations, and role-based training labs for both technical engineers and non-technical banking employees.

---

## Key Capabilities

### 1. Dynamic Security Controller (Dual-State Architecture)
The application features a real-time **Security Audit & Compliance Controller** at the top of the portal, allowing instantaneous switching between:
* **Vulnerable Lab State (OWASP Demo):** Disables input parameterization, multi-tenant session checks, and velocity counters to simulate legacy unhardened core banking systems.
* **Hardened Defense Mode:** Activates parameterized prepared queries, contextual session-to-object ownership gates, velocity rate limiting, and route stripping.

### 2. Operational Banking Services
* **Commercial Wire Transfer Portal:** Real-time Fedwire / SWIFT commercial settlement simulator.
* **Account & Transaction Directory:** Cross-tier counterparty search demonstrating SQL injection vulnerability vs. parameterized defense.
* **Electronic Statements:** Multi-tenant statement access demonstrating horizontal Broken Access Control (IDOR).
* **PIN Verification & Lockout:** Brute-force authentication testing with stateful in-memory velocity limiting.
* **Live SOC / SIEM Telemetry Bar:** Real-time event streaming capturing attack payloads (`[CRITICAL] [SQL_INJECTION]`, `[CRITICAL] [IDOR]`) and defensive mitigations.

---

## Dual-Track Training Labs

### Track 1: Technical Hands-On Lab (Engineers & Developers)
* **Location:** [`training-labs/lab-1-technical-idor/`](training-labs/lab-1-technical-idor/)
* **Focus:** OWASP A01:2025 Broken Access Control (Horizontal IDOR on Banking APIs).
* **Components:**
  * `README.md` — Guided lab exercise & remediation walkthrough.
  * `banking_records.json` — Pre-seeded ledger containing commercial accounts and corporate wire statements (including `$2,450,000` wire statement `stmt_9901` belonging to *Horizon Capital Partners*).
  * `test_idor_remediation.py` — Automated `pytest` test harness verifying contextual ownership claims and HTTP 403 enforcement.

### Track 2: Non-Technical Hands-On Lab (Operations, Treasury & Finance Staff)
* **Location:** [`training-labs/lab-2-non-technical-phishing/`](training-labs/lab-2-non-technical-phishing/)
* **Focus:** OWASP Module N1 (Phishing & BEC) & Module N3 (Wire Fraud Defense).
* **Components:**
  * `inbox_samples.csv` — 12 real-world operational banking communications (urgent wire transfer lures from spoofed CFOs, vendor bank account alteration notices, thread-hijacking `.zip` files, and legitimate alerts).
  * `README.md` — Tabletop simulation guide and Facilitator Assessment Key outlining SAFE vs. IMMEDIATE ESCALATION criteria.

---

## Quickstart Guide

### 1. Clone & Install Dependencies
```bash
git clone https://github.com/Puneeth1615/banking-security-lab.git
cd banking-security-lab
pip install -r requirements.txt
```

### 2. Launch the Commercial Banking Portal
```bash
python banking_app.py
```
Open your web browser and navigate to:
```text
http://127.0.0.1:5000
```

### 3. Run Automated OWASP Exploit & Defensive Tests
In a separate terminal window, execute the automated penetration testing harness:
```bash
python run_security_lab_tests.py
```
This executes automated tests across:
1. **SQL Injection in Customer Directory (A05:2025)**
2. **Insecure Direct Object Reference (IDOR) on Bank Statements (A01:2025)**
3. **Automated Credential Brute-Force & Rate Limiting (A07:2025)**
4. **Information Disclosure & Diagnostic Route Stripping (A02:2025)**

---

## Automated DAST Scanning with WebSecAudit

The banking testbed is engineered to be scanned natively by [WebSecAudit](https://github.com/Puneeth1615/websecaudit):

```bash
# Execute full security posture and BIA compliance scan
python main.py http://127.0.0.1:5000 --pdf --json
```

---

## Institutional Governance

* **Sponsor:** First Quadrant Labs  
* **Project:** Capstone Internship Project  
* **Developer:** Bathala Puneeth  
* **License:** MIT License  
