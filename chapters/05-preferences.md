---
prev-chapter: "Reference Architecture & Key Capabilities"
prev-url: "04-optimization"
page-title: Data Onboarding & Integration
next-chapter: "Analytics & Detection Design"
next-url: "06-preference-data"
---

# Data Onboarding & Integration

Effective security analytics start with high-fidelity telemetry. Microsoft Sentinel simplifies onboarding with guided wizards, automation templates, and APIs.

## Prioritizing Data Sources

1. **Tier 1 – High Value / High Risk:** Identity (Entra ID, on-prem AD), endpoint alerts, email security, cloud control plane logs.
2. **Tier 2 – Contextual Visibility:** Network flows, DNS, web proxies, VPN, SaaS audit logs.
3. **Tier 3 – Long-Term Analytics:** Application logs, OT/IoT telemetry, data from legacy systems.

## Connector Strategy

- **Out-of-the-Box Connectors:** Use Microsoft-provided connectors for Defender, Microsoft 365, and SaaS apps to accelerate onboarding.
- **Codeless Connectors:** Leverage REST APIs, Syslog, or Common Event Format (CEF) for systems without native connectors.
- **Zero Trust Alignment:** Map connectors to identity, device, application, network, and data pillars to ensure comprehensive coverage.

## Ingestion Best Practices

- **Normalize Early:** Apply normalization policies (Data Collection Rules) to ensure consistent fields and tagging.
- **Optimize Costs:** Use Basic Logs for low-priority data, archive rarely queried logs, and apply data caps.
- **Automate Enrollment:** ARM templates, Terraform modules, and Azure Policy enforce consistent onboarding across subscriptions.

## Integration with Existing Tools

- **ITSM Bridging:** Native connectors to ServiceNow, Jira, and Teams route incidents to existing ticketing workflows.
- **Security Ecosystem:** Integrate with Microsoft Defender, Purview, and third-party EDR for bidirectional alert sharing.
- **Custom Line-of-Business Apps:** Use the Sentinel REST API or Azure Functions to stream bespoke telemetry.

## Onboarding Checklist

| Step | Description | Owner |
| --- | --- | --- |
| Inventory | Catalog critical assets, regulatory obligations, existing telemetry | SOC Manager |
| Connector Enablement | Activate native connectors; configure credentials and scope | Security Engineer |
| Validation | Run sample incidents and confirm data availability | Analyst |
| Monitoring | Establish data health dashboards, alert on ingestion failures | SOC Manager |

Proper data onboarding ensures Sentinel analytics have the coverage needed to detect and respond to evolving threats.
