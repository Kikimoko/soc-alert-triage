# Incident Response Runbook — Network-Flow Alerts Handled by the AI-Assisted Triage Pipeline

Scope: alerts produced by `src/triage.py` (ML score + Sigma-style rules) and enriched by `src/copilot.py`. Severity levels: CLOSE / INVESTIGATE / ESCALATE.
Targets in the last section are **proposed** service levels to be confirmed with the SOC; they are not measured results.

## 1. Detect and triage (Tier 1 — automated first pass)
1. Pipeline scores the alert; AUTO-CLOSE only if the score is below the out-of-fold policy threshold (keeps ≥ 95 % of attacks in the test data).
2. Copilot writes a summary from the alert fields only (payload text is masked and untrusted); a verifier rejects summaries with unsupported claims.
3. Guardrail: the model may raise, never lower, severity below the deterministic policy.
4. Alerts from the same source and trigger rule are grouped into one incident and a ticket is opened (`soar.py`).
**Hand-off:** ticket (severity, lead alert, rules fired, ATT&CK IDs, summary) → Tier-1 analyst.

## 2. Analyse (Tier 1 → Tier 2)
Analyst validates in SIEM/EDR: pivot on source, check asset criticality and recent change tickets, confirm or dismiss. Record the verdict in the ticket (it becomes labelled data for the next model review).
**Escalate to Tier 2** if ESCALATE severity, multiple assets, or lateral-movement indicators.

## 3. Contain (human approval required)
`soar.py` only *proposes* containment (e.g. block source) into `approval_queue.json`. Approver: on-call Tier-2/SOC lead. Safety checks: allow-listed and internal ranges are never auto-proposed; every action is written to `audit_log.jsonl`.

## 4. Eradicate and recover
Owner: system/asset owner with IT. Remove persistence, patch (use the vulnerability prioritization queue), rotate credentials, restore service, remove temporary blocks after verification.

## 5. Post-incident
Lessons learned, detection backlog (see `docs/ATTACK_COVERAGE.md` gaps), rule tuning, model re-evaluation, close the ticket with root cause.

## Roles / hand-offs
| Step | Responsible | Approves | Output |
|---|---|---|---|
| Automated triage + enrichment | Pipeline | — | ranked alerts, summaries |
| Validate / dismiss | Tier-1 analyst | — | verdict in ticket |
| Containment | Tier-2 | SOC lead | applied action + audit entry |
| Eradication / recovery | Asset owner + IT | SOC lead | change record |
| Review | Detection engineer | SOC lead | rule/model updates |

## Metrics to track (definitions)
- **Detection effectiveness:** recall by attack category; share of benign traffic kept for review (analyst noise).
- **Workload:** share of alerts auto-closed at ≥ 95 % attack recall (measured in the triage evaluation: 51 %).
- **Time to triage (MTTT) / time to contain (MTTC):** ticket-open minus alert time; containment-approved minus ticket-open. The pipeline's own compute time is milliseconds per alert; human timings must be measured in a live SOC.
- **Summary quality:** claim-level hallucination rate and action agreement (`copilot_eval.py`).
- **Proposed targets (to agree with the SOC):** ESCALATE tickets acknowledged within 15 min, contained or dismissed within 60 min.
