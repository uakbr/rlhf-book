---
prev-chapter: "Threat Landscape & SOC Challenges"
prev-url: "02-related-works"
page-title: Azure Sentinel Platform Overview
next-chapter: "Reference Architecture & Key Capabilities"
next-url: "04-optimization"
---

# Azure Sentinel Platform Overview

Microsoft Sentinel is a cloud-native SIEM and SOAR service built on Azure. It combines hyperscale telemetry ingestion with advanced analytics, automation, and investigation tools to modernize security operations.

## Core Components

1. **Data Connectors** – Over 200 out-of-the-box connectors ingest telemetry from Microsoft services (Defender, Entra ID, Purview) and third-party solutions (firewalls, EDR, SaaS). Connectors normalize data into the Azure Monitor Log Analytics workspace.
2. **Analytics Rules** – Prebuilt and custom rules leveraging Kusto Query Language (KQL) detect threats. Built-in templates cover emerging attack scenarios, while the rule wizard accelerates authoring.
3. **Workbench & Incident Queue** – Sentinel correlates alerts into incidents, providing analyst-friendly workbooks, timeline views, and guided investigation steps.
4. **Automation (SOAR)** – Playbooks orchestrated through Azure Logic Apps automate response actions, notifications, and evidence gathering.
5. **Machine Learning & AI** – Fusion, UEBA, anomaly detection, and Security Copilot augment analysts with prioritized incidents and natural language explanations [@microsoftFusionAI; @microsoftCopilotSecurity].
6. **Threat Intelligence** – Native integration with Microsoft threat intelligence and open TAXII sources enriches detections with actor context.

## Platform Differentiators

- **Cloud Scale:** Elastic ingestion supports bursty workloads without infrastructure management.
- **Integrated Ecosystem:** Sentinel natively links to Microsoft Defender XDR, Microsoft Entra, Microsoft Purview, and Azure Arc for unified governance.
- **Open & Extensible:** Connectors, REST APIs, and community content (workbooks, playbooks) enable rapid customization.
- **Security Analytics Foundation:** Sentinel builds on Azure Monitor’s log analytics engine, offering high-performance KQL queries and centralized governance.

## Licensing & Consumption Model

Sentinel uses consumption-based billing: data ingestion (per GB), automation rules, and AI enrichments. Cost control tactics include commitment tiers, basic logs for low-value data, and incident-based pricing for certain use cases. The TEI study reports 48% cost savings from tool consolidation compared to on-premises SIEM [@forresterTEISentinel2024].

## Success Prerequisites

- **Azure Tenant Readiness:** Confirm Azure AD/Entra governance, subscription structure, role-based access control (RBAC), and connectivity to critical workloads.
- **Data Strategy:** Prioritize high-value telemetry (identity, endpoint, network, cloud services) and define retention requirements aligned with compliance mandates.
- **SOC Process Alignment:** Establish incident response runbooks, escalation pathways, and automation policies that Sentinel playbooks will enforce.

This overview sets the stage for the detailed architecture and rollout guidance in subsequent sections.
