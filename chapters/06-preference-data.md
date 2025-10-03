---
prev-chapter: "Data Onboarding & Integration"
prev-url: "05-preferences"
page-title: Analytics & Detection Design
next-chapter: "AI-Augmented Operations"
next-url: "07-reward-models"
---

# Analytics & Detection Design

Microsoft Sentinel enables layered analytics combining rule-based detections, statistical models, and intelligence-driven insights. Designing an effective detection strategy balances coverage, precision, and operational workload.

## Analytics Rule Framework

1. **Out-of-the-Box Rule Templates**
   - Rapid deployment for ransomware, identity compromise, insider risk
   - Regularly updated by Microsoft research teams

2. **Custom Rule Development**
   - Use Kusto Query Language (KQL) to tailor detections to organizational context
   - Adopt naming conventions and metadata (severity, tactics) aligned to MITRE ATT&CK

3. **Anomaly & Behavior-Based Rules**
   - Enable UEBA for user/entity baselines and anomaly scoring
   - Tune thresholds based on pilot telemetry to minimize false positives

## Detection Lifecycle

1. **Hypothesis Formulation:** Identify threat scenarios tied to critical assets.
2. **Rule Creation & Testing:** Build KQL queries, validate against historical data, simulate incidents.
3. **Deployment & Tuning:** Gradually increase coverage, monitor hit rates, adjust thresholds.
4. **Operationalization:** Document response steps, integrate with playbooks, assign ownership.

## KQL Design Patterns

```kql
SecurityIncident
| where Title contains "Impossible Travel"
| summarize count() by bin(TimeGenerated, 1h), Impact
```

- Use functions and modular queries for reuse.
- Implement watchlists for VIP users and critical assets.
- Apply threat intelligence enrichment for context.

## False Positive Management

- Leverage incidents instead of raw alerts to correlate related events.
- Create suppression rules for benign patterns (e.g., approved admin tasks).
- Use automation rules to adjust severity or close known-good incidents.

## Measuring Detection Quality

- Track coverage across MITRE ATT&CK techniques.
- Monitor dwell time (alert-to-incident) and triage SLA adherence.
- Incorporate analyst feedback loops via tagging and comments.

A robust analytics program fuses curated Microsoft content with organization-specific intelligence to deliver high-fidelity detections.
