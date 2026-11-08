# Internship project - First Quadrant Labs
"""
First Quadrant Commercial Bank - Controlled Cybersecurity Simulation Portal
Authentic Commercial Banking Web Application demonstrating OWASP Top 10 vulnerabilities
and production-grade defensive hardening with real-time SOC/SIEM telemetry.
"""
from flask import Flask, request, jsonify, render_template_string, session
import sqlite3
import os
import json

app = Flask(__name__)
app.secret_key = "first_quadrant_commercial_bank_secure_lab_key"

# Global server-wide security mode state: "vulnerable" or "secure" (hardened)
SERVER_CONFIG = {
    "mode": "vulnerable",
    "failed_logins": {}
}

DB_PATH = "banking_lab.db"

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute("DROP TABLE IF EXISTS accounts")
    c.execute("DROP TABLE IF EXISTS statements")
    c.execute("DROP TABLE IF EXISTS audit_logs")
    
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
            recipient TEXT
        )
    """)
    c.execute("""
        CREATE TABLE audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            event_type TEXT,
            severity TEXT,
            details TEXT
        )
    """)
    
    # Seed authentic commercial banking records
    c.executemany("INSERT INTO accounts VALUES (?, ?, ?, ?, ?, ?)", [
        (101, "ACCT-992144-USD", "Alice Smith", "Commercial Checking", 154200.50, "4892"),
        (102, "ACCT-883921-EUR", "Bob Johnson", "Treasury Reserve", 2890400.00, "1129"),
        (103, "ACCT-774102-GBP", "Carol White", "Private Wealth", 950000.00, "9032"),
        (104, "ACCT-665201-USD", "David Sterling (CFO)", "Corporate Settlement", 12450000.00, "7714")
    ])
    c.executemany("INSERT INTO statements VALUES (?, ?, ?, ?, ?, ?)", [
        (1001, 101, "2026-10-15", "Commercial Wire Inflow - Client Retainer", 15000.00, "First Quadrant Legal LLC"),
        (1002, 102, "2026-10-18", "Vendor Clearing - Cloud Infrastructure Hosting", -42500.00, "Global Cloud Services Inc"),
        (1003, 104, "2026-10-22", "Interbank Settlement - Cross-Border FX Batch", -500000.00, "Apex International Settlement")
    ])
    conn.commit()
    conn.close()

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>First Quadrant Commercial Bank | Online Banking Portal</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --primary-navy: #0F2043;
            --secondary-navy: #1E3A8A;
            --accent-blue: #0066CC;
            --bg-page: #F1F5F9;
            --card-border: #E2E8F0;
            --text-dark: #0F172A;
            --text-muted: #64748B;
        }
        body {
            background-color: var(--bg-page);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            color: var(--text-dark);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
        }
        /* Top Commercial Banking Brand Navbar */
        .navbar-brand-bar {
            background-color: var(--primary-navy);
            border-bottom: 2px solid #D97706; /* Gold trim */
            padding: 12px 24px;
        }
        .bank-brand {
            font-size: 1.25rem;
            font-weight: 700;
            letter-spacing: 0.5px;
            color: #FFFFFF !important;
            display: flex;
            align-items: center;
            gap: 12px;
            text-decoration: none;
        }
        .bank-brand i {
            color: #38BDF8;
            font-size: 1.5rem;
        }
        .customer-pill {
            background-color: rgba(255, 255, 255, 0.12);
            border: 1px solid rgba(255, 255, 255, 0.2);
            padding: 6px 14px;
            border-radius: 20px;
            color: #E2E8F0;
            font-size: 0.85rem;
        }
        /* Auditor Control Banner */
        .auditor-toolbar {
            background-color: #0B132B;
            border-bottom: 1px solid #1E293B;
            padding: 8px 24px;
            font-size: 0.85rem;
            color: #94A3B8;
        }
        .mode-badge-vuln {
            background-color: #DC2626;
            color: white;
            font-weight: 700;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 0.75rem;
            letter-spacing: 0.5px;
        }
        .mode-badge-sec {
            background-color: #16A34A;
            color: white;
            font-weight: 700;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 0.75rem;
            letter-spacing: 0.5px;
        }
        /* Corporate Sub-Navigation */
        .subnav {
            background-color: #FFFFFF;
            border-bottom: 1px solid var(--card-border);
            padding: 0 24px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.03);
        }
        .subnav .nav-link {
            color: var(--text-muted);
            font-weight: 600;
            padding: 16px 18px;
            border-bottom: 3px solid transparent;
            border-radius: 0;
            font-size: 0.95rem;
        }
        .subnav .nav-link:hover {
            color: var(--primary-navy);
        }
        .subnav .nav-link.active {
            color: var(--accent-blue);
            border-bottom-color: var(--accent-blue);
            background: transparent;
        }
        /* Card Styling */
        .card-portal {
            background: #FFFFFF;
            border: 1px solid var(--card-border);
            border-radius: 8px;
            box-shadow: 0 1px 4px rgba(0,0,0,0.04);
            margin-bottom: 24px;
        }
        .card-portal-header {
            padding: 16px 20px;
            border-bottom: 1px solid var(--card-border);
            font-weight: 700;
            color: var(--primary-navy);
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        .balance-figure {
            font-size: 1.85rem;
            font-weight: 700;
            color: var(--primary-navy);
            letter-spacing: -0.5px;
        }
        .btn-bank {
            background-color: var(--accent-blue);
            color: #FFFFFF;
            font-weight: 600;
            border-radius: 6px;
            padding: 8px 18px;
            border: none;
        }
        .btn-bank:hover {
            background-color: #0052A3;
            color: #FFFFFF;
        }
        /* Telemetry Console */
        .telemetry-card {
            background-color: #0F172A;
            color: #38BDF8;
            font-family: 'Consolas', 'Courier New', monospace;
            font-size: 0.8rem;
            border-radius: 8px;
            padding: 14px;
            max-height: 220px;
            overflow-y: auto;
            border: 1px solid #1E293B;
        }
        .telemetry-entry {
            margin-bottom: 6px;
            line-height: 1.4;
        }
        .telemetry-alert {
            color: #F87171;
            font-weight: bold;
        }
        .telemetry-pass {
            color: #4ADE80;
            font-weight: bold;
        }
        .shortcut-badge {
            cursor: pointer;
            font-size: 0.75rem;
            background-color: #F1F5F9;
            color: #475569;
            border: 1px solid #CBD5E1;
            padding: 2px 8px;
            border-radius: 4px;
        }
        .shortcut-badge:hover {
            background-color: #E2E8F0;
        }
    </style>
</head>
<body>

    <!-- TOP BRAND BAR -->
    <nav class="navbar-brand-bar">
        <div class="container-fluid d-flex justify-content-between align-items-center">
            <a class="bank-brand" href="/">
                <i class="fa-solid fa-building-columns"></i>
                <span>FIRST QUADRANT COMMERCIAL BANK <span class="badge bg-dark text-warning ms-2" style="font-size: 0.7rem; font-weight: normal; border: 1px solid #D97706;">Enterprise Portal</span></span>
            </a>
            <div class="d-flex align-items-center gap-3">
                <div class="customer-pill">
                    <i class="fa-solid fa-circle-user me-2 text-info"></i>
                    <span>Authenticated User: <strong>Alice Smith</strong> (Commercial Checking #101)</span>
                </div>
                <a href="#telemetry" class="btn btn-sm btn-outline-light" onclick="document.getElementById('telemetryConsole').scrollIntoView({behavior: 'smooth'})">
                    <i class="fa-solid fa-satellite-dish me-1"></i> SOC Telemetry
                </a>
            </div>
        </div>
    </nav>

    <!-- AUDITOR CONTROL BANNER -->
    <div class="auditor-toolbar d-flex justify-content-between align-items-center">
        <div class="d-flex align-items-center gap-2">
            <i class="fa-solid fa-shield-halved text-info"></i>
            <span class="fw-bold text-white">SECURITY AUDIT & COMPLIANCE CONTROLLER:</span>
            <span>Current Environment:</span>
            <span id="currentModeBadge" class="{{ 'mode-badge-vuln' if current_mode == 'vulnerable' else 'mode-badge-sec' }}">
                {{ 'VULNERABLE LAB STATE (OWASP DEMO)' if current_mode == 'vulnerable' else 'HARDENED PRODUCTION STATE (ACTIVE DEFENSE)' }}
            </span>
        </div>
        <div class="d-flex align-items-center gap-2">
            <span class="text-white-50 small">Target State:</span>
            <div class="btn-group btn-group-sm" role="group">
                <button type="button" class="btn btn-sm {{ 'btn-danger' if current_mode == 'vulnerable' else 'btn-outline-danger' }}" onclick="switchMode('vulnerable')">
                    <i class="fa-solid fa-biohazard me-1"></i> Vulnerable Mode
                </button>
                <button type="button" class="btn btn-sm {{ 'btn-success' if current_mode == 'secure' else 'btn-outline-success' }}" onclick="switchMode('secure')">
                    <i class="fa-solid fa-shield-check me-1"></i> Hardened Mode
                </button>
            </div>
            <button class="btn btn-sm btn-outline-secondary text-white" onclick="resetLab()" title="Reset DB and lockouts">
                <i class="fa-solid fa-rotate-right"></i> Reset
            </button>
        </div>
    </div>

    <!-- CORPORATE SUBNAV -->
    <div class="subnav">
        <ul class="nav" id="portalTabs" role="tablist">
            <li class="nav-item">
                <button class="nav-link active" id="tab-overview" data-bs-toggle="tab" data-bs-target="#view-overview" type="button">
                    <i class="fa-solid fa-wallet me-2"></i> Accounts & Treasury Overview
                </button>
            </li>
            <li class="nav-item">
                <button class="nav-link" id="tab-search" data-bs-toggle="tab" data-bs-target="#view-search" type="button">
                    <i class="fa-solid fa-magnifying-glass me-2"></i> Account & Transaction Directory
                </button>
            </li>
            <li class="nav-item">
                <button class="nav-link" id="tab-wire" data-bs-toggle="tab" data-bs-target="#view-wire" type="button">
                    <i class="fa-solid fa-money-bill-transfer me-2"></i> Wire Transfer Portal
                </button>
            </li>
            <li class="nav-item">
                <button class="nav-link" id="tab-statements" data-bs-toggle="tab" data-bs-target="#view-statements" type="button">
                    <i class="fa-solid fa-file-invoice-dollar me-2"></i> Electronic Statements
                </button>
            </li>
            <li class="nav-item">
                <button class="nav-link" id="tab-auth" data-bs-toggle="tab" data-bs-target="#view-auth" type="button">
                    <i class="fa-solid fa-key me-2"></i> PIN Verification & Lockout
                </button>
            </li>
            <li class="nav-item">
                <button class="nav-link" id="tab-diag" data-bs-toggle="tab" data-bs-target="#view-diag" type="button">
                    <i class="fa-solid fa-server me-2"></i> Infrastructure Diagnostics
                </button>
            </li>
        </ul>
    </div>

    <!-- MAIN BODY CONTENT -->
    <div class="container my-4 flex-grow-1">

        <div class="tab-content" id="portalContent">

            <!-- TAB 1: ACCOUNTS & TREASURY OVERVIEW -->
            <div class="tab-pane fade show active" id="view-overview" role="tabpanel">
                <div class="row">
                    <div class="col-md-8">
                        <div class="card-portal">
                            <div class="card-portal-header">
                                <span><i class="fa-solid fa-landmark me-2 text-primary"></i> Primary Commercial Operating Account</span>
                                <span class="badge bg-success-subtle text-success border border-success">Active / In Good Standing</span>
                            </div>
                            <div class="card-body p-4">
                                <div class="row align-items-center">
                                    <div class="col-md-7">
                                        <div class="text-muted small text-uppercase fw-semibold">Available Corporate Balance</div>
                                        <div class="balance-figure">$154,200.50 USD</div>
                                        <div class="small text-muted mt-1">Account Number: <strong>ACCT-992144-USD</strong> (Routing: 021000089)</div>
                                        <div class="small text-muted">Beneficiary Entity: First Quadrant Tech Ventures LLC</div>
                                    </div>
                                    <div class="col-md-5 text-end">
                                        <button class="btn btn-bank mb-2 w-100" onclick="document.getElementById('tab-wire').click()">
                                            <i class="fa-solid fa-paper-plane me-1"></i> Originate Wire Transfer
                                        </button>
                                        <button class="btn btn-outline-secondary w-100" onclick="document.getElementById('tab-statements').click()">
                                            <i class="fa-solid fa-download me-1"></i> View Statements
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <!-- Recent In-Session Activity -->
                        <div class="card-portal">
                            <div class="card-portal-header">
                                <span><i class="fa-solid fa-list-check me-2"></i> Recent Authorized Ledger Postings (Alice Smith #101)</span>
                                <span class="text-muted small">Updated in Real-Time</span>
                            </div>
                            <div class="card-body p-0">
                                <table class="table table-hover mb-0">
                                    <thead class="table-light">
                                        <tr>
                                            <th>Date</th>
                                            <th>Reference</th>
                                            <th>Description / Counterparty</th>
                                            <th class="text-end">Amount</th>
                                            <th>Status</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <tr>
                                            <td>2026-10-15</td>
                                            <td><code>STMT-1001</code></td>
                                            <td>Commercial Wire Inflow - Client Retainer</td>
                                            <td class="text-end text-success fw-bold">+$15,000.00</td>
                                            <td><span class="badge bg-success">Settled</span></td>
                                        </tr>
                                        <tr>
                                            <td>2026-10-12</td>
                                            <td><code>TXN-98441</code></td>
                                            <td>Payroll Clearing Batch - Senior Engineering</td>
                                            <td class="text-end text-danger fw-bold">-$34,200.00</td>
                                            <td><span class="badge bg-success">Settled</span></td>
                                        </tr>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>

                    <!-- Side Column: Corporate Treasury Summary -->
                    <div class="col-md-4">
                        <div class="card-portal">
                            <div class="card-portal-header">
                                <span><i class="fa-solid fa-chart-pie me-2 text-primary"></i> Treasury Security Notice</span>
                            </div>
                            <div class="card-body">
                                <p class="small text-muted">
                                    Commercial banking interfaces are strictly partitioned under ISO/IEC 27001 and PCI-DSS 4.0 multi-tenant isolation rules.
                                </p>
                                <div class="p-3 bg-light rounded border mb-3">
                                    <div class="fw-bold text-dark small"><i class="fa-solid fa-circle-info text-info me-1"></i> Pentest Testbed Architecture</div>
                                    <div class="small text-muted mt-1">
                                        This portal demonstrates both unmitigated OWASP Top 10 vulnerabilities (vulnerable state) and defensive controls including parameterized SQL, contextual access filters, and velocity lockout.
                                    </div>
                                </div>
                                <div class="d-grid gap-2">
                                    <button class="btn btn-sm btn-outline-primary" onclick="document.getElementById('tab-search').click()">
                                        <i class="fa-solid fa-magnifying-glass me-1"></i> Test Account Directory
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- TAB 2: ACCOUNT & TRANSACTION DIRECTORY (SQL Injection Vector) -->
            <div class="tab-pane fade" id="view-search" role="tabpanel">
                <div class="card-portal">
                    <div class="card-portal-header">
                        <span><i class="fa-solid fa-address-book me-2"></i> Account Directory & Counterparty Lookup</span>
                        <div class="d-flex align-items-center gap-2">
                            <span class="small text-muted">Quick Exploit Test:</span>
                            <span class="shortcut-badge" onclick="setSearchInput('Alice Smith')">Legitimate ('Alice Smith')</span>
                            <span class="shortcut-badge text-danger" onclick="setSearchInput(&quot;Alice Smith' OR '1'='1&quot;)">SQLi Payload (<code>' OR '1'='1</code>)</span>
                        </div>
                    </div>
                    <div class="card-body p-4">
                        <p class="text-muted small">
                            Corporate customers can search registered beneficiaries and internal commercial accounts by registered holder name.
                        </p>
                        <form onsubmit="event.preventDefault(); executeSearch();">
                            <div class="input-group mb-3">
                                <span class="input-group-text"><i class="fa-solid fa-magnifying-glass"></i></span>
                                <input type="text" id="searchQuery" class="form-control" placeholder="Search account by holder name..." value="Alice Smith">
                                <button type="submit" class="btn btn-bank"><i class="fa-solid fa-search me-1"></i> Query Directory</button>
                            </div>
                        </form>

                        <div id="searchResults" class="mt-4"></div>
                    </div>
                </div>
            </div>

            <!-- TAB 3: WIRE TRANSFER PORTAL -->
            <div class="tab-pane fade" id="view-wire" role="tabpanel">
                <div class="card-portal">
                    <div class="card-portal-header">
                        <span><i class="fa-solid fa-paper-plane me-2"></i> Originate Corporate Wire Transfer</span>
                        <span class="badge bg-primary-subtle text-primary border border-primary">Fedwire / SWIFT Network</span>
                    </div>
                    <div class="card-body p-4">
                        <form onsubmit="event.preventDefault(); submitWireTransfer();">
                            <div class="row g-3">
                                <div class="col-md-6">
                                    <label class="form-label small fw-bold">Originating Account</label>
                                    <input type="text" class="form-control bg-light" value="ACCT-992144-USD (Alice Smith - Commercial Checking)" readonly>
                                </div>
                                <div class="col-md-6">
                                    <label class="form-label small fw-bold">Beneficiary Entity / Payee Name</label>
                                    <input type="text" id="wireRecipient" class="form-control" placeholder="e.g. Apex International Settlement" value="Global Supply Chain Logistics Inc" required>
                                </div>
                                <div class="col-md-6">
                                    <label class="form-label small fw-bold">Beneficiary Account / IBAN</label>
                                    <input type="text" id="wireAccount" class="form-control" placeholder="e.g. US890210000890012345678" value="US440210000892231998412" required>
                                </div>
                                <div class="col-md-6">
                                    <label class="form-label small fw-bold">SWIFT / BIC / Routing Code</label>
                                    <input type="text" id="wireRouting" class="form-control" placeholder="e.g. FQBKUS33" value="FQBKUS33XXX" required>
                                </div>
                                <div class="col-md-6">
                                    <label class="form-label small fw-bold">Wire Transfer Amount (USD)</label>
                                    <div class="input-group">
                                        <span class="input-group-text">$</span>
                                        <input type="number" id="wireAmount" class="form-control" value="25000.00" step="0.01" min="1.00" required>
                                    </div>
                                </div>
                                <div class="col-md-6">
                                    <label class="form-label small fw-bold">Payment Purpose / Wire Memo</label>
                                    <input type="text" id="wireMemo" class="form-control" placeholder="e.g. Invoice #2026-9041 Clearing">
                                </div>
                                <div class="col-12 mt-4 text-end">
                                    <button type="button" class="btn btn-outline-secondary me-2" onclick="document.getElementById('tab-overview').click()">Cancel</button>
                                    <button type="submit" class="btn btn-bank"><i class="fa-solid fa-lock me-1"></i> Authorize & Transmit Wire</button>
                                </div>
                            </div>
                        </form>
                        <div id="wireStatus" class="mt-3"></div>
                    </div>
                </div>
            </div>

            <!-- TAB 4: ELECTRONIC STATEMENTS (IDOR Vector) -->
            <div class="tab-pane fade" id="view-statements" role="tabpanel">
                <div class="card-portal">
                    <div class="card-portal-header">
                        <span><i class="fa-solid fa-file-invoice-dollar me-2"></i> Account Statements & Electronic Records Archive</span>
                        <div class="d-flex align-items-center gap-2">
                            <span class="small text-muted">Test Statement IDs:</span>
                            <span class="shortcut-badge" onclick="loadStatement(1001)">My Statement (#1001)</span>
                            <span class="shortcut-badge text-danger" onclick="loadStatement(1003)">CFO Statement (#1003 - IDOR Exploit)</span>
                        </div>
                    </div>
                    <div class="card-body p-4">
                        <p class="text-muted small">
                            Review electronic settlement notices and official statements.
                        </p>
                        <div class="row align-items-center g-3 mb-4">
                            <div class="col-auto">
                                <label class="col-form-label small fw-bold">Lookup Statement ID:</label>
                            </div>
                            <div class="col-auto">
                                <input type="number" id="statementIdInput" class="form-control" value="1001" style="width: 140px;">
                            </div>
                            <div class="col-auto">
                                <button class="btn btn-bank" onclick="loadStatement(document.getElementById('statementIdInput').value)">
                                    <i class="fa-solid fa-file-arrow-down me-1"></i> Retrieve Statement
                                </button>
                            </div>
                        </div>

                        <div id="statementDisplay"></div>
                    </div>
                </div>
            </div>

            <!-- TAB 5: PIN VERIFICATION & LOCKOUT (Brute Force Vector) -->
            <div class="tab-pane fade" id="view-auth" role="tabpanel">
                <div class="card-portal">
                    <div class="card-portal-header">
                        <span><i class="fa-solid fa-key me-2"></i> High-Value Authorization PIN Verification</span>
                        <span class="shortcut-badge text-danger" onclick="runBruteForceSimulation()">
                            <i class="fa-solid fa-bolt me-1"></i> Run Automated Dictionary Attack
                        </span>
                    </div>
                    <div class="card-body p-4">
                        <p class="text-muted small">
                            Executing critical operations (wire releases, beneficiary updates) requires 4-digit PIN confirmation for Account <strong>#101</strong> (Alice Smith).
                        </p>
                        <div class="row g-3">
                            <div class="col-md-5">
                                <label class="form-label small fw-bold">Enter Account Security PIN:</label>
                                <div class="input-group mb-3">
                                    <input type="password" id="authPinInput" class="form-control" placeholder="4-digit PIN" maxlength="4" value="0000">
                                    <button class="btn btn-bank" onclick="testPin(document.getElementById('authPinInput').value)">
                                        <i class="fa-solid fa-check me-1"></i> Verify PIN
                                    </button>
                                </div>
                                <div id="pinResult"></div>
                            </div>
                            <div class="col-md-7">
                                <div class="p-3 bg-light rounded border">
                                    <div class="small fw-bold text-dark mb-1"><i class="fa-solid fa-shield-halved text-primary me-1"></i> Velocity Rate-Limiting Policy</div>
                                    <p class="small text-muted mb-2">
                                        In <strong>Vulnerable Mode</strong>, no rate limiting exists—attackers can brute force all 10,000 combinations without restriction.
                                    </p>
                                    <p class="small text-muted mb-0">
                                        In <strong>Hardened Mode</strong>, the system enforces a strict 3-failure lockout policy (HTTP 429) and immediately halts subsequent authentication attempts.
                                    </p>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- TAB 6: INFRASTRUCTURE DIAGNOSTICS (Security Misconfiguration Vector) -->
            <div class="tab-pane fade" id="view-diag" role="tabpanel">
                <div class="card-portal">
                    <div class="card-portal-header">
                        <span><i class="fa-solid fa-server me-2"></i> Internal Diagnostic & Telemetry Service</span>
                        <button class="btn btn-sm btn-outline-danger" onclick="probeDebugEndpoint()">
                            <i class="fa-solid fa-radar me-1"></i> Probe <code>/api/v1/admin/debug</code>
                        </button>
                    </div>
                    <div class="card-body p-4">
                        <p class="text-muted small">
                            Production financial microservices must never expose debugging endpoints, internal connection strings, or server environment topologies to client networks.
                        </p>
                        <div id="debugResult" class="p-3 bg-light rounded border">
                            <span class="text-muted small">Click the probe button to test whether the internal diagnostic endpoint is exposed.</span>
                        </div>
                    </div>
                </div>
            </div>

        </div>

        <!-- SOC / SIEM TELEMETRY DRAWER -->
        <div id="telemetryConsole" class="card-portal mt-4">
            <div class="card-portal-header bg-dark text-white d-flex justify-content-between align-items-center">
                <span><i class="fa-solid fa-satellite-dish me-2 text-info"></i> Live SIEM & Application Security Audit Telemetry</span>
                <span class="badge bg-secondary" id="eventCountBadge">0 Events Captured</span>
            </div>
            <div class="card-body p-0">
                <div class="telemetry-card" id="telemetryStream">
                    <div class="telemetry-entry text-muted">
                        [SYSTEM INIT] SIEM Telemetry daemon initialized. Listening on 127.0.0.1:5000. Operating Mode: <span class="text-info fw-bold">{{ current_mode.upper() }}</span>.
                    </div>
                </div>
            </div>
        </div>

    </div>

    <!-- JAVASCRIPT LOGIC -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        let currentMode = "{{ current_mode }}";
        let eventCount = 0;

        function logSIEM(type, severity, message) {
            eventCount++;
            document.getElementById('eventCountBadge').innerText = `${eventCount} Events Captured`;
            const stream = document.getElementById('telemetryStream');
            const now = new Date().toISOString().replace('T', ' ').substring(0, 19);
            const entry = document.createElement('div');
            entry.className = 'telemetry-entry';
            
            let colorClass = 'text-info';
            if (severity === 'CRITICAL' || severity === 'HIGH') colorClass = 'telemetry-alert';
            if (severity === 'DEFENSE') colorClass = 'telemetry-pass';
            
            entry.innerHTML = `[${now}] <span class="${colorClass}">[${severity}] [${type}]</span> ${message}`;
            stream.appendChild(entry);
            stream.scrollTop = stream.scrollHeight;
        }

        async function switchMode(newMode) {
            const res = await fetch(`/api/mode?set=${newMode}`);
            const data = await res.json();
            currentMode = data.mode;
            
            const badge = document.getElementById('currentModeBadge');
            if (currentMode === 'vulnerable') {
                badge.className = 'mode-badge-vuln';
                badge.innerText = 'VULNERABLE LAB STATE (OWASP DEMO)';
                logSIEM('MODE_CHANGE', 'WARNING', 'System switched to VULNERABLE LAB MODE. Security controls deactivated.');
            } else {
                badge.className = 'mode-badge-sec';
                badge.innerText = 'HARDENED PRODUCTION STATE (ACTIVE DEFENSE)';
                logSIEM('MODE_CHANGE', 'DEFENSE', 'System switched to HARDENED DEFENSE MODE. Parameterized queries, multi-tenant RBAC, and velocity lockouts active.');
            }
            setTimeout(() => window.location.reload(), 400);
        }

        async function resetLab() {
            await fetch('/api/reset');
            logSIEM('SYSTEM_RESET', 'INFO', 'Database and failed login attempts reset to baseline state.');
            setTimeout(() => window.location.reload(), 400);
        }

        function setSearchInput(val) {
            document.getElementById('searchQuery').value = val;
            executeSearch();
        }

        async function executeSearch() {
            const query = document.getElementById('searchQuery').value;
            const container = document.getElementById('searchResults');
            container.innerHTML = '<div class="text-muted small"><i class="fa-solid fa-spinner fa-spin me-2"></i> Querying accounts directory...</div>';

            const res = await fetch(`/api/search?q=${encodeURIComponent(query)}`);
            const data = await res.json();

            let html = `
                <div class="p-3 mb-3 rounded border" style="background-color: #0F172A; color: #E2E8F0; font-family: monospace; font-size: 0.85rem;">
                    <div class="text-info fw-bold mb-1">Executed SQL Statement:</div>
                    <div class="text-warning">${data.executed_sql}</div>
                </div>
            `;

            if (data.results && data.results.length > 0) {
                const leakedCount = data.results.length;
                const hasCFO = data.results.some(r => r.owner_name.includes('CFO') || r.owner_name.includes('Sterling'));
                
                if (leakedCount > 1 && hasCFO) {
                    logSIEM('SQL_INJECTION', 'CRITICAL', `SQL Injection succeeded! Query returned ${leakedCount} accounts including unauthorized CFO executive balances ($12,450,000).`);
                } else {
                    logSIEM('DIRECTORY_QUERY', 'INFO', `Legitimate query matched ${leakedCount} customer record(s).`);
                }

                html += `
                    <div class="table-responsive">
                        <table class="table table-bordered table-hover align-middle">
                            <thead class="table-light">
                                <tr>
                                    <th>Account Number</th>
                                    <th>Account Holder</th>
                                    <th>Type</th>
                                    <th class="text-end">Current Balance</th>
                                    <th>Security Status</th>
                                </tr>
                            </thead>
                            <tbody>
                `;
                data.results.forEach(r => {
                    const isAlice = r.owner_name.includes('Alice');
                    html += `
                        <tr class="${!isAlice ? 'table-danger' : ''}">
                            <td><code>${r.account_number}</code></td>
                            <td><strong>${r.owner_name}</strong> ${!isAlice ? '<span class="badge bg-danger ms-1">UNAUTHORIZED EXPOSURE</span>' : ''}</td>
                            <td>${r.account_type}</td>
                            <td class="text-end fw-bold ${r.balance > 1000000 ? 'text-danger' : 'text-success'}">$${r.balance.toLocaleString('en-US', {minimumFractionDigits: 2})}</td>
                            <td>${isAlice ? '<span class="badge bg-success">Authorized</span>' : '<span class="badge bg-danger">Breached Record</span>'}</td>
                        </tr>
                    `;
                });
                html += '</tbody></table></div>';
            } else {
                logSIEM('DEFENSE_PASS', 'DEFENSE', `Parameterized query prevented SQL injection. Input treated as literal string; 0 records matched.`);
                html += `
                    <div class="alert alert-success d-flex align-items-center">
                        <i class="fa-solid fa-shield-check fa-2x me-3 text-success"></i>
                        <div>
                            <strong>Defensive Control Active: 0 Records Returned.</strong>
                            <div class="small">The query was parameterized; SQL metacharacters (<code>' OR '1'='1</code>) were treated as harmless literal text rather than executable logic.</div>
                        </div>
                    </div>
                `;
            }
            container.innerHTML = html;
        }

        async function submitWireTransfer() {
            const recipient = document.getElementById('wireRecipient').value;
            const amount = document.getElementById('wireAmount').value;
            const memo = document.getElementById('wireMemo').value;
            const statusDiv = document.getElementById('wireStatus');

            statusDiv.innerHTML = `
                <div class="alert alert-success">
                    <i class="fa-solid fa-circle-check me-2"></i>
                    <strong>Wire Transfer Transmitted Successfully:</strong> Transferred <strong>$${parseFloat(amount).toLocaleString('en-US', {minimumFractionDigits: 2})} USD</strong> to <strong>${recipient}</strong>.
                </div>
            `;
            logSIEM('WIRE_TRANSMIT', 'INFO', `Commercial wire transfer of $${amount} authorized to beneficiary ${recipient}.`);
        }

        async function loadStatement(stmtId) {
            document.getElementById('statementIdInput').value = stmtId;
            const display = document.getElementById('statementDisplay');
            display.innerHTML = '<div class="text-muted small"><i class="fa-solid fa-spinner fa-spin me-2"></i> Fetching statement...</div>';

            const res = await fetch(`/api/statements/${stmtId}`);
            const data = await res.json();

            if (res.status === 200) {
                const s = data.statement;
                const isCFO = (stmtId == 1003 || s.account_id == 104);
                if (isCFO) {
                    logSIEM('IDOR_BREACH', 'CRITICAL', `Insecure Direct Object Reference (IDOR) exploit successful! Alice (Acct 101) retrieved CFO Statement #${stmtId} ($500,000 interbank wire) without authorization.`);
                } else {
                    logSIEM('STATEMENT_VIEW', 'INFO', `Authorized statement #${stmtId} retrieved for session owner Alice Smith.`);
                }

                display.innerHTML = `
                    <div class="card ${isCFO ? 'border-danger' : 'border-success'}">
                        <div class="card-header ${isCFO ? 'bg-danger text-white' : 'bg-success text-white'} d-flex justify-content-between">
                            <span><i class="fa-solid fa-file-invoice me-2"></i> Official Electronic Statement #${s.id}</span>
                            <span>${isCFO ? 'BREACH: CONFIDENTIAL CFO RECORD' : 'AUTHORIZED RECORD'}</span>
                        </div>
                        <div class="card-body">
                            <div class="row">
                                <div class="col-md-6">
                                    <div class="small text-muted">Statement Reference:</div>
                                    <div class="fw-bold">STMT-${s.id}-2026</div>
                                    <div class="small text-muted mt-2">Owner Account ID:</div>
                                    <div class="fw-bold">Account #${s.account_id} ${isCFO ? '(David Sterling - CFO)' : '(Alice Smith)'}</div>
                                </div>
                                <div class="col-md-6 text-end">
                                    <div class="small text-muted">Effective Date:</div>
                                    <div class="fw-bold">${s.transaction_date}</div>
                                    <div class="small text-muted mt-2">Transaction Amount:</div>
                                    <div class="fw-bold fs-5 ${s.amount < 0 ? 'text-danger' : 'text-success'}">$${Math.abs(s.amount).toLocaleString('en-US', {minimumFractionDigits: 2})} USD</div>
                                </div>
                            </div>
                            <hr>
                            <div class="small text-muted">Counterparty / Recipient:</div>
                            <div class="fw-bold">${s.recipient}</div>
                            <div class="small text-muted mt-2">Transaction Memo:</div>
                            <div>${s.description}</div>
                        </div>
                    </div>
                `;
            } else {
                logSIEM('DEFENSE_PASS', 'DEFENSE', `Horizontal IDOR prevented! Contextual Multi-Tenant Authorization gate rejected request for Statement #${stmtId} (HTTP 403 Forbidden).`);
                display.innerHTML = `
                    <div class="alert alert-danger d-flex align-items-center">
                        <i class="fa-solid fa-shield-halved fa-2x me-3 text-danger"></i>
                        <div>
                            <strong>HTTP 403 Forbidden - Access Denied</strong>
                            <div class="small">${data.error}</div>
                        </div>
                    </div>
                `;
            }
        }

        async function testPin(pin) {
            const resultDiv = document.getElementById('pinResult');
            const res = await fetch(`/api/login?pin=${pin}`);
            const data = await res.json();

            if (res.status === 200) {
                logSIEM('AUTH_SUCCESS', 'INFO', `PIN verification succeeded for Account #101.`);
                resultDiv.innerHTML = `<div class="alert alert-success py-2 px-3 small"><i class="fa-solid fa-check me-1"></i> ${data.message}</div>`;
            } else if (res.status === 429) {
                logSIEM('VELOCITY_LOCKOUT', 'CRITICAL', `Velocity rate limiter engaged! Account #101 locked after 3 failed attempts (HTTP 429). Incident alerted to SOC.`);
                resultDiv.innerHTML = `<div class="alert alert-danger py-2 px-3 small fw-bold"><i class="fa-solid fa-lock me-1"></i> ${data.message}</div>`;
            } else {
                logSIEM('AUTH_FAILURE', 'WARNING', `Invalid PIN authentication attempt (${pin}) on Account #101.`);
                resultDiv.innerHTML = `<div class="alert alert-warning py-2 px-3 small"><i class="fa-solid fa-triangle-exclamation me-1"></i> ${data.message}</div>`;
            }
        }

        async function runBruteForceSimulation() {
            const guesses = ['0000', '1234', '1111', '4892'];
            logSIEM('ATTACK_SIM', 'WARNING', `Initiating automated dictionary brute-force attack against Account #101...`);
            for (let i = 0; i < guesses.length; i++) {
                document.getElementById('authPinInput').value = guesses[i];
                await testPin(guesses[i]);
                await new Promise(r => setTimeout(r, 600));
                const res = await fetch(`/api/login?pin=${guesses[i]}`);
                if (res.status === 429) {
                    break;
                }
            }
        }

        async function probeDebugEndpoint() {
            const res = await fetch('/api/v1/admin/debug');
            const data = await res.json();
            const div = document.getElementById('debugResult');

            if (res.status === 200) {
                logSIEM('INFO_LEAK', 'CRITICAL', `Security Misconfiguration detected! Unauthenticated diagnostic route exposed database connection string: ${data.db_connection}`);
                div.innerHTML = `
                    <div class="alert alert-danger mb-0">
                        <div class="fw-bold mb-1"><i class="fa-solid fa-bug me-1"></i> HTTP 200 OK - SENSITIVE CLUSTER TOPOLOGY LEAKED:</div>
                        <ul class="small mb-0">
                            <li><strong>Cluster Environment:</strong> ${data.environment}</li>
                            <li><strong>Master DB URI:</strong> <code class="text-danger">${data.db_connection}</code></li>
                            <li><strong>Internal Cluster IP:</strong> ${data.internal_ip}</li>
                            <li><strong>Diagnostic Status:</strong> ${data.debug_trace}</li>
                        </ul>
                    </div>
                `;
            } else {
                logSIEM('DEFENSE_PASS', 'DEFENSE', `Security Misconfiguration prevented: Diagnostic routes stripped from production routing tables (HTTP 404 Not Found).`);
                div.innerHTML = `
                    <div class="alert alert-success mb-0">
                        <i class="fa-solid fa-circle-check me-2"></i>
                        <strong>HTTP 404 Not Found:</strong> ${data.error}
                    </div>
                `;
            }
        }
    </script>
</body>
</html>
"""

@app.route("/")
def home():
    mode = SERVER_CONFIG["mode"]
    return render_template_string(HTML_TEMPLATE, current_mode=mode)

@app.route("/api/mode")
def api_mode():
    set_val = request.args.get("set")
    if set_val:
        if set_val in ["vulnerable", "vuln"]:
            SERVER_CONFIG["mode"] = "vulnerable"
            SERVER_CONFIG["failed_logins"] = {}
        elif set_val in ["secure", "hardened", "sec"]:
            SERVER_CONFIG["mode"] = "secure"
            SERVER_CONFIG["failed_logins"] = {}
    return jsonify({
        "status": "success",
        "mode": SERVER_CONFIG["mode"]
    })

@app.route("/api/reset")
def api_reset():
    init_db()
    SERVER_CONFIG["failed_logins"] = {}
    return jsonify({"status": "reset_complete", "mode": SERVER_CONFIG["mode"]})

@app.route("/api/search")
def api_search():
    query = request.args.get("q", "")
    mode = request.args.get("mode", SERVER_CONFIG["mode"])
    conn = get_db()
    c = conn.cursor()
    
    if mode == "vulnerable":
        # Vulnerable Dynamic SQL String Concatenation (A05 / A03 Injection)
        sql = f"SELECT account_number, owner_name, account_type, balance FROM accounts WHERE owner_name = '{query}'"
        try:
            c.execute(sql)
            rows = c.fetchall()
            results = [dict(r) for r in rows]
        except Exception as e:
            results = []
            sql = f"SQL ERROR: {str(e)}"
    else:
        # Secure Parameterized Prepared Query
        sql = "SELECT account_number, owner_name, account_type, balance FROM accounts WHERE owner_name = ?"
        c.execute(sql, (query,))
        rows = c.fetchall()
        results = [dict(r) for r in rows]
        
    conn.close()
    return jsonify({"mode": mode, "executed_sql": sql, "results": results})

@app.route("/api/statements/<int:stmt_id>")
def api_statement(stmt_id):
    mode = request.args.get("mode", SERVER_CONFIG["mode"])
    # Session context: Alice Smith is authenticated as Account 101
    current_user_account = 101
    conn = get_db()
    c = conn.cursor()
    
    if mode == "vulnerable":
        # Insecure Direct Object Reference (A01 Broken Access Control)
        c.execute("SELECT * FROM statements WHERE id = ?", (stmt_id,))
        row = c.fetchone()
        conn.close()
        if row:
            return jsonify({"status": 200, "statement": dict(row)}), 200
        return jsonify({"status": 404, "error": "Statement not found"}), 404
    else:
        # Contextual Multi-Tenant Authorization Gate
        c.execute("SELECT * FROM statements WHERE id = ? AND account_id = ?", (stmt_id, current_user_account))
        row = c.fetchone()
        conn.close()
        if row:
            return jsonify({"status": 200, "statement": dict(row)}), 200
        return jsonify({
            "status": 403, 
            "error": "Access Denied: You do not have permission to view statements outside your authenticated account."
        }), 403

@app.route("/api/login")
def api_login():
    pin = request.args.get("pin", "")
    mode = request.args.get("mode", SERVER_CONFIG["mode"])
    account_id = 101
    client_ip = request.remote_addr or "127.0.0.1"
    
    if mode == "vulnerable":
        # Missing Rate Limiting & Velocity Controls (A07 Broken Authentication)
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT id, owner_name FROM accounts WHERE id = ? AND secret_pin = ?", (account_id, pin))
        user = c.fetchone()
        conn.close()
        if user:
            return jsonify({"status": 200, "message": f"PIN verified successfully for {user['owner_name']}"}), 200
        return jsonify({"status": 401, "message": "Invalid PIN credentials."}), 401
    else:
        # Defensive Velocity Rate Limiting (Lockout after 3 failures)
        key = f"{account_id}:{client_ip}"
        attempts = SERVER_CONFIG["failed_logins"].get(key, 0)
        if attempts >= 3:
            return jsonify({
                "status": 429,
                "message": "Account Locked: Exceeded maximum allowed authentication attempts (3). Security incident dispatched to SOC."
            }), 429
            
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT id, owner_name FROM accounts WHERE id = ? AND secret_pin = ?", (account_id, pin))
        user = c.fetchone()
        conn.close()
        
        if user:
            SERVER_CONFIG["failed_logins"][key] = 0
            return jsonify({"status": 200, "message": f"PIN verified successfully for {user['owner_name']}"}), 200
        
        SERVER_CONFIG["failed_logins"][key] = attempts + 1
        return jsonify({"status": 401, "message": f"Invalid PIN credentials. Attempt {attempts + 1} of 3."}), 401

@app.route("/api/v1/admin/debug")
def api_debug():
    mode = request.args.get("mode", SERVER_CONFIG["mode"])
    if mode == "vulnerable":
        # Security Misconfiguration (A05/A02): Unprotected debug endpoint exposes credentials
        return jsonify({
            "status": 200,
            "environment": "PRODUCTION-BANKING-CLUSTER-01",
            "db_connection": "postgresql://db_admin:MasterSecure2026!@10.0.4.12:5432/core_banking",
            "internal_ip": "10.0.12.54",
            "active_sessions": 342,
            "debug_trace": "DEBUG_MODE_ENABLED: Verbose stack logging active on public interface"
        }), 200
    else:
        # Hardened Production: Diagnostic routes stripped from routing table
        return jsonify({"status": 404, "error": "Not Found: Diagnostic route stripped in production configuration"}), 404

if __name__ == "__main__":
    init_db()
    print("=" * 75)
    print(" FIRST QUADRANT COMMERCIAL BANK - SIMULATED CYBERSECURITY PORTAL")
    print(" Local Web Application running at: http://127.0.0.1:5000")
    print(" Active Mode: " + SERVER_CONFIG["mode"].upper())
    print(" Press Ctrl+C in terminal to stop.")
    print("=" * 75)
    app.run(host="127.0.0.1", port=5000, debug=False)
