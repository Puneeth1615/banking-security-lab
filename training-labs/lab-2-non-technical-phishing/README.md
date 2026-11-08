# Functional Training Lab 2: Wire Transfer & BEC Inbox Triage Tabletop
**Track:** Operations, Treasury & Executive Assistants (Tracks D1, D2, D3)  
**Curriculum Alignment:** Module N1 (Phishing & BEC) & Module N3 (Wire Transfer Defense)  
**Duration:** 25 Minutes  
**Prerequisites:** Zero code; web browser or printed scenario cards  

---

## 1. Exercise Objectives
1. Identify subtle psychological manipulation levers (Urgency, Authority, Secrecy) in operational banking communications.
2. Detect technical impersonation indicators (homoglyphs, spoofed headers, thread hijacking, changed bank details).
3. Execute the mandatory out-of-band call-back verification protocol before releasing wire transfers.

---

## 2. Sample Dataset: 12 Real-World Operational Messages (`inbox_samples.csv`)

| ID | Sender Display & Address | Subject / Header | Message Body Summary | Participant Categorization |
| :--- | :--- | :--- | :--- | :--- |
| **MSG-01** | `David Sterling <david.sterling@bank-secure-corp.com>` | URGENT: Acquisition Settlement Wire | *"Boarding flight, cannot take calls. Process attached $480k invoice to our new partner today. Do not copy others."* | [Safe / Suspicious / Escalate] |
| **MSG-02** | `IT Service Desk <servicedesk@internal-portal.bank>` | Scheduled Maintenance: Core Banking Patch | *"Routine Sunday maintenance window 02:00-04:00 UTC. No password resets or employee action required."* | [Safe / Suspicious / Escalate] |
| **MSG-03** | `Global Cloud Solutions <billing@global-c1oud.com>` | Updated Banking Details for Invoice #8841 | *"We have switched clearing institutions. Effective immediately, route all future ACH wires to Account #9921."* | [Safe / Suspicious / Escalate] |
| **MSG-04** | `HR Benefits <benefits-update@external-survey.org>` | Mandatory Employee Pension Review | *"Click here to confirm your national tax ID and bank routing details within 24 hours to prevent salary freeze."* | [Safe / Suspicious / Escalate] |
| **MSG-05** | `Sarah Jenkins <sjenkins@bank.internal>` | Lunch Meeting Reschedule | *"Can we push our Q3 compliance sync to 2:30 PM today? Conference room B is booked."* | [Safe / Suspicious / Escalate] |
| **MSG-06** | `Microsoft Security <no-reply@security-alerts.bank.internal>` | Unusual Sign-in Activity Detected | *"Sign-in from Sofia, Bulgaria. If this was not you, tap 'Report Suspicious Activity' inside your Authenticator."* | [Safe / Suspicious / Escalate] |
| **MSG-07** | `Alex Mercer <alex.mercer@consulting-partners.com>` | Re: Audit Workpapers Follow-up | *Thread-hijack reply: "Following up on yesterday's call, please see the amended retainer breakdown attached (.zip)."* | [Safe / Suspicious / Escalate] |
| **MSG-08** | `First National Clearing <wire-alerts@firstnatclearing.com>` | Inbound Wire Confirmation #TX-90142 | *"Incoming credit of $1,250,000.00 confirmed for Client ACCT-665201. Standard value date applies."* | [Safe / Suspicious / Escalate] |
| **MSG-09** | `Executive Office <ceo-private@secure-proton-relay.com>` | Highly Confidential Project Titan | *"Need an immediate off-cycle wire for strategic retainer. Call my mobile for the code. Do not log in ERP yet."* | [Safe / Suspicious / Escalate] |
| **MSG-10** | `Treasury Ops <treasury-internal@bank.internal>` | Daily Liquidity Position Report | *"Attached daily FX balance sheet for October 31, 2026. Signed by settlement manager."* | [Safe / Suspicious / Escalate] |
| **MSG-11** | `SMS / Cell: +1 (555) 019-2831` | IT Alert: MFA Device Expiring | *"Your corporate token expires in 1 hour. Tap http://bank-sso-verify.mobi to refresh your certificate."* | [Safe / Suspicious / Escalate] |
| **MSG-12** | `Vendor AP Desk <invoices@staples-office-supplies.com>` | Monthly Paper & Supply Invoice | *"Invoice for routine office stationery ($342.18). Net 30 terms, existing banking details on file unchanged."* | [Safe / Suspicious / Escalate] |

---

## 3. Facilitator Assessment Key & Grading Criteria

| Message ID | Verified Classification | Critical Risk Indicators | Mandatory Operational Action |
| :--- | :--- | :--- | :--- |
| **MSG-01** | **IMMEDIATE ESCALATION (BEC)** | Homoglyph (`rn` for `m`); urgency; secrecy; refusal of phone contact. | **FREEZE PAYMENT.** Do not reply. Call CFO on corporate directory number. |
| **MSG-02** | **SAFE** | Internal authenticated domain; no credentials or funds requested; informational. | Standard delivery; no action needed. |
| **MSG-03** | **IMMEDIATE ESCALATION (Vendor BEC)** | Lookalike domain (`c1oud` with numeral 1); change of beneficiary banking details. | **HOLD INVOICE.** Call vendor finance controller using master contract phone number. |
| **MSG-04** | **SUSPICIOUS (Credential Phish)** | External domain asking for tax ID and banking credentials under penalty threat. | Click Phishing Report button. Alert SOC. |
| **MSG-05** | **SAFE** | Internal peer communication; no links, attachments, or funds. | Normal response. |
| **MSG-06** | **SAFE (Legitimate Alert)** | Official internal security notification directing user to authentic authenticator app. | Verify sign-in history inside corporate portal. |
| **MSG-07** | **SUSPICIOUS (Thread Hijacking)** | Legitimate external partner email chain hijacked; malicious `.zip` attachment. | Report to SOC. Do not extract archive. |
| **MSG-08** | **SAFE** | Standard transaction notification from established correspondent clearing network. | Verify against core ledger. |
| **MSG-09** | **IMMEDIATE ESCALATION (Executive Fraud)** | External anonymous relay address; requests ERP bypass and secrecy. | **ALERT ANTI-FRAUD DESK.** Enforce dual control. Never bypass ERP. |
| **MSG-10** | **SAFE** | Routine authenticated reporting flow with verified internal digital signature. | Archive per record retention policy. |
| **MSG-11** | **SUSPICIOUS (Smishing)** | SMS phishing; external mobile domain; urgent countdown timer. | Do not click. Forward screenshot to security hotline. |
| **MSG-12** | **SAFE** | Expected recurring vendor invoice; standard PO range; payment routing unchanged. | Process per standard AP batch workflow. |

---

## 4. Operational Learning Metrics
* **Target Cohort Passing Threshold:** Participants must correctly identify all 4 **Immediate Escalation** scenarios (100% detection) and achieve >= 85% overall triage accuracy.
* **Remediation Trigger:** Any participant approving a wire transfer on MSG-01 or MSG-03 is automatically assigned to a mandatory 15-minute 1-on-1 callback verification drill.
