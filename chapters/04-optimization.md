---
prev-chapter: "Azure Sentinel Platform Overview"
prev-url: "03-setup"
page-title: Reference Architecture & Key Capabilities
next-chapter: "Data Onboarding & Integration"
next-url: "05-preferences"
---

# Reference Architecture & Key Capabilities

The reference architecture below positions Microsoft Sentinel as the analytics and automation hub for enterprise security operations.

## Layered Architecture

1. **Data Sources**
   - Cloud platforms: Azure, Microsoft 365, AWS, GCP
   - Identity: Microsoft Entra ID, Active Directory, SaaS identity providers
   - Endpoint & Network: Microsoft Defender, third-party firewalls, proxies, OT monitoring
   - SaaS & Business Apps: Salesforce, ServiceNow, Workday logs

2. **Ingestion & Normalization**
   - Data connectors stream telemetry into Azure Monitor Log Analytics
   - Custom parsers and normalization policies enforce a common schema
   - Azure Data Explorer provides high-throughput ingestion paths for specialized workloads

3. **Analytics & Detection**
   - Rule templates for emerging threats (e.g., ransomware, business email compromise)
   - User and Entity Behavior Analytics (UEBA) score anomalies
   - Fusion uses graph-based machine learning to correlate multi-stage attacks [@microsoftFusionAI]
   - Threat intelligence enrichment adds actor, campaign, and geo-context

4. **Orchestration & Response**
   - Playbooks (Logic Apps) trigger containment, notification, and ticketing workflows
   - Automation rules manage severity, assignment, and tagging
   - Microsoft Defender XDR bi-directional integration shares incidents for coordinated action

5. **Visualization & Governance**
   - Workbooks provide dashboards for leadership KPIs (MTTD, MTTR, incident volumes)
   - Watchlists centralize high-value indicators (VIP users, critical assets)
   - Role-based access with granular control over data and incident actions

## Key Capabilities Deep Dive

- **Security Copilot Integration:** Analysts receive natural-language summaries of incidents, suggested KQL queries, and recommended response steps, accelerating triage and knowledge transfer [@microsoftCopilotSecurity].
- **Automation at Scale:** Repeatable response workflows reduce toil—examples include isolating endpoints, resetting credentials, or opening change tickets.
- **Threat Hunting Workspace:** KQL query packs and notebooks enable proactive hunting for advanced threats.
- **Hybrid Support:** Azure Arc and Azure Lighthouse extend Sentinel visibility to multi-tenant and multi-cloud environments without heavy infrastructure.

## Architecture At-a-Glance

| Layer | Functions | Representative Capabilities |
| --- | --- | --- |
| Data Sources | Cloud platforms, identity, endpoint, SaaS | Azure, Microsoft 365, AWS, GCP, Defender, firewalls |
| Ingestion & Normalization | Connectors, parsers, schema alignment | Data Collection Rules, REST API, Log Analytics workspace |
| Analytics & AI | Rules, behavior analytics, threat intel | KQL analytics, Fusion ML, UEBA, threat intelligence enrichment |
| Orchestration & Response | Automation, collaboration, remediation | Logic Apps playbooks, automation rules, Teams, ITSM |
| Visualization & Governance | Dashboards, KPIs, RBAC, compliance | Workbooks, watchlists, RBAC, compliance packs |

The layered view ensures telemetry flows seamlessly into Sentinel, where analytics, AI, and automation converge to deliver rapid, consistent response.
