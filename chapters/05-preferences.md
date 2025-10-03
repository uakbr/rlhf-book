---
prev-chapter: "Reference Architecture & Key Capabilities"
prev-url: "04-optimization"
page-title: Data Onboarding & Integration
next-chapter: "Analytics & Detection Design"
next-url: "06-preference-data"
---

# Data Onboarding & Integration

Effective security analytics depend on comprehensive, high-quality telemetry from across the enterprise ecosystem. Microsoft Sentinel provides a robust framework for data onboarding that balances coverage, performance, and cost optimization. This chapter provides detailed guidance on prioritizing data sources, implementing connectors, and ensuring data quality for optimal security operations.

## Data Source Prioritization Framework

A structured approach to data source prioritization ensures that limited resources focus on the most valuable telemetry first, while establishing a roadmap for comprehensive coverage.

### Tiered Prioritization Model

**Tier 1: Critical Security Signals (Immediate Implementation)**
These data sources provide the highest value for threat detection and should be onboarded first:

#### Identity and Access Management
- **Azure Active Directory Sign-in Logs:** Authentication events, MFA challenges, and conditional access decisions
- **Active Directory Security Events:** Domain controller logs, privilege escalation, and account management activities
- **Cloud Identity Platforms:** Federation events, SSO activities, and identity provider audit trails

#### Endpoint Protection and Response
- **Microsoft Defender for Endpoint:** Alert data, behavioral detections, and threat intelligence matches
- **Third-Party EDR Platforms:** CrowdStrike, SentinelOne, Carbon Black, and Palo Alto Cortex XDR alerts
- **Endpoint Management:** Intune audit logs, device compliance status, and application inventory

#### Email and Communication Security
- **Exchange Online Protection:** Phishing detections, malware scanning results, and spam filtering decisions
- **Email Gateway Security:** Proofpoint, Mimecast, or Microsoft Defender for Office 365 threat reports
- **Collaboration Platform Logs:** Teams, Slack, and SharePoint access and sharing activities

#### Cloud Infrastructure Control Plane
- **Azure Activity Logs:** Resource creation, modification, and deletion events across all Azure services
- **AWS CloudTrail:** API calls, configuration changes, and authentication events
- **GCP Audit Logs:** Administrative activities, data access, and system events

**Tier 2: Contextual Visibility (1-3 Months Post-Deployment)**
These sources provide valuable context for investigations and should be added once Tier 1 is operational:

#### Network Security and Flow Data
- **Firewall Logs:** Next-generation firewall events from Palo Alto, Check Point, Fortinet, and Cisco
- **Web Proxy Data:** Secure web gateway logs from Zscaler, Blue Coat, or Forcepoint
- **DNS Query Logs:** Recursive DNS queries, NXDOMAIN responses, and suspicious domain resolutions
- **VPN and Remote Access:** Authentication events, connection logs, and geolocation data

#### SaaS Application Audit Trails
- **Productivity Suites:** Office 365, Google Workspace, and Salesforce operational logs
- **HR and Finance Systems:** Workday, SAP, Oracle HCM access and modification events
- **Development Tools:** GitHub, GitLab, Jira, and Confluence audit logs

#### Infrastructure Monitoring
- **Server and Application Logs:** Windows event logs, Linux syslog, and application-specific telemetry
- **Network Device Logs:** Router, switch, and wireless access point security events
- **Database Audit Logs:** SQL Server, Oracle, MySQL, and PostgreSQL access and modification logs

**Tier 3: Advanced Analytics and Compliance (3-6 Months)**
These sources support long-term analytics, compliance reporting, and advanced threat hunting:

#### Operational Technology (OT) and IoT
- **Industrial Control Systems:** SCADA, DCS, and PLC system logs and process data
- **IoT Device Telemetry:** Sensor data, device health metrics, and security events
- **Building Management Systems:** HVAC, access control, and physical security system logs

#### Legacy and Custom Applications
- **Mainframe and Legacy Systems:** CICS, IMS, and other legacy platform security events
- **Custom Business Applications:** Bespoke application logs and transaction data
- **Third-Party Business Systems:** ERP, CRM, and supply chain management system audit trails

#### External Intelligence and Context
- **Threat Intelligence Feeds:** Commercial threat intelligence platforms and open-source IOCs
- **Brand Monitoring:** Domain squatting, phishing site detections, and social media intelligence
- **Supply Chain Visibility:** Vendor security posture and third-party risk indicators

### Prioritization Decision Framework

When selecting data sources for implementation, consider these factors:

**Security Value Assessment**
- **Detection Coverage:** How well does this data source support MITRE ATT&CK technique detection?
- **Investigation Support:** Does this data provide context for incident investigation and response?
- **Threat Intelligence Correlation:** Can this data be enriched with external threat intelligence?

**Operational Considerations**
- **Data Volume and Velocity:** Expected events per second and storage requirements
- **Integration Complexity:** Effort required for connector deployment and maintenance
- **Cost Impact:** Ingestion, storage, and processing costs relative to security value

**Business Context**
- **Regulatory Requirements:** Mandated logging for compliance frameworks
- **Risk Profile:** Alignment with organizational risk assessment and critical assets
- **Stakeholder Requirements:** Input from security, IT, compliance, and business teams

## Connector Implementation Guide

Microsoft Sentinel provides multiple mechanisms for data ingestion, each suited to different scenarios and technical requirements.

### Native Connector Deployment

**Microsoft Ecosystem Connectors**
Most Microsoft services integrate natively with Sentinel through the Azure portal:

**Step-by-Step Azure AD Connector Setup:**
1. Navigate to Microsoft Sentinel > Data connectors
2. Search for "Azure Active Directory" and select the connector
3. Click "Open connector page" and then "Connect"
4. Configure log categories (SignInLogs, AuditLogs, etc.)
5. Set retention policies and enable data collection

**Configuration Example:**
```json
{
  "type": "AzureActiveDirectory",
  "properties": {
    "connectorDefinitionName": "AzureActiveDirectory",
    "dataTypes": {
      "logs": [
        {
          "name": "SignInLogs",
          "enabled": true,
          "retentionInDays": 90
        },
        {
          "name": "AuditLogs",
          "enabled": true,
          "retentionInDays": 365
        }
      ]
    }
  }
}
```

**Third-Party Security Platform Connectors**
Popular security tools integrate through dedicated connectors:

**CrowdStrike Falcon Integration:**
```bash
# Install CrowdStrike Streaming API connector
az sentinel data-connector create \
  --resource-group "security-rg" \
  --workspace-name "main-workspace" \
  --data-connector-name "CrowdStrikeFalcon" \
  --connector-definition-id "CrowdStrikeFalcon"
```

**Palo Alto Networks Cortex XSOAR:**
- Configure syslog forwarding from PAN-OS to Sentinel
- Use CEF format for structured log delivery
- Implement log filtering to reduce noise

### Agent-Based Collection

**Azure Monitor Agent (AMA) Deployment**
For comprehensive Windows and Linux server coverage:

**Windows Server Onboarding:**
```powershell
# Install Azure Monitor Agent
Install-Module -Name Az.ConnectedMachine
Connect-AzAccount
New-AzConnectedMachine -ResourceGroupName "security-rg" \
  -Name "server01" -Location "East US"

# Configure data collection rules
New-AzMonitorDataCollectionRule -ResourceGroupName "security-rg" \
  -Name "SecurityEvents-DCR" -Location "East US" \
  -DataCollectionEndpointId "/subscriptions/.../providers/Microsoft.Insights/dataCollectionEndpoints/default" \
  -DataSource @{
    WindowsEventLogs = @(
      @{
        Name = "Security"
        Streams = @("Microsoft-SecurityEvent")
      }
    )
  }
```

**Linux Server Configuration:**
```bash
# Install Azure Monitor Agent for Linux
wget https://aka.ms/azcmagent
sudo dpkg -i azcmagent.deb
azcmagent connect --resource-group "security-rg" \
  --tenant-id "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" \
  --location "East US" --subscription-id "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

# Configure syslog collection
az monitor data-collection rule create \
  --resource-group "security-rg" \
  --workspace-name "main-workspace" \
  --name "Syslog-DCR" \
  --syslog-facilities "auth,authpriv,kern,mail,user,local0,local1"
```

### Agentless and API-Based Collection

**REST API Integration**
For SaaS applications and cloud services without native connectors:

**Generic REST API Connector Template:**
```json
{
  "name": "CustomAPIConnector",
  "type": "Microsoft.SecurityInsights/dataConnectors",
  "apiVersion": "2021-03-01-preview",
  "properties": {
    "connectorDefinitionName": "CustomAPIConnector",
    "dataTypes": {
      "logs": {
        "state": "Enabled",
        "outputStream": "Custom_CL"
      }
    },
    "connectorUiConfig": {
      "title": "Custom API Data Source",
      "publisher": "Contoso Security",
      "descriptionMarkdown": "Collects security events from custom API endpoints",
      "graphQueriesTableName": "Custom_CL",
      "sampleQueries": [
        {
          "description": "Recent events",
          "query": "Custom_CL | limit 100"
        }
      ]
    },
    "pollingConfig": {
      "auth": {
        "type": "APIKey",
        "apiKeyName": "Authorization",
        "apiKey": "Bearer <token>"
      },
      "request": {
        "apiRoot": "https://api.example.com",
        "frequency": "PT5M",
        "query": "/v1/security/events"
      }
    }
  }
}
```

**Webhook Integration for Real-Time Events:**
```javascript
// Azure Function for webhook processing
const https = require('https');

module.exports = async function (context, req) {
    context.log('Processing webhook event');

    const eventData = req.body;
    const logEntry = {
        TimeGenerated: new Date().toISOString(),
        EventType: eventData.event_type,
        SourceIP: req.headers['x-forwarded-for'] || req.connection.remoteAddress,
        RawData: JSON.stringify(eventData)
    };

    context.bindings.outputDocument = JSON.stringify(logEntry);
    context.done();
};
```

### Custom Parser Development

**Kusto Query Language (KQL) Parsers**
Create custom parsers for proprietary log formats:

**Syslog Parser Example:**
```kql
// Custom syslog parser for proprietary format
.create function CustomSyslogParser(logMessage: string)
{
    let parsed = parse_json(logMessage);
    parsed
    | extend
        Timestamp = todatetime(parsed.timestamp),
        HostName = tostring(parsed.hostname),
        Process = tostring(parsed.process),
        Severity = toint(parsed.severity),
        Message = tostring(parsed.message)
    | project Timestamp, HostName, Process, Severity, Message
}
```

**CEF (Common Event Format) Parser:**
```kql
// CEF log parser for security events
.create function CEFParser(cefString: string)
{
    let cefParts = split(cefString, '|');
    let header = split(cefParts[0], ':');
    let extension = parse_csv(cefParts[7]);
    extension
    | extend
        CEFVersion = tostring(header[0]),
        DeviceVendor = tostring(header[1]),
        DeviceProduct = tostring(header[2]),
        DeviceVersion = tostring(header[3]),
        EventClassId = tostring(header[4]),
        Name = tostring(header[5]),
        Severity = tostring(header[6])
    | project CEFVersion, DeviceVendor, DeviceProduct, DeviceVersion,
              EventClassId, Name, Severity, extension
}
```

## Data Quality and Normalization

### Schema Standardization

**Common Data Model Implementation**
Sentinel normalizes all ingested data to a consistent schema:

```kql
// Standardized schema mapping
SecurityEvent
| extend
    EventTime = TimeGenerated,
    EventSource = Computer,
    EventType = EventID,
    EventCategory = Channel,
    UserName = iff(isnotempty(SubjectUserName), SubjectUserName, Account),
    SourceIP = iff(isnotempty(IpAddress), IpAddress, ClientIP),
    DestinationIP = iff(isnotempty(DestinationIp), DestinationIp, TargetServer),
    Severity = case(
        RenderedDescription contains "Error", "High",
        RenderedDescription contains "Warning", "Medium",
        "Low"
    )
| project EventTime, EventSource, EventType, EventCategory,
          UserName, SourceIP, DestinationIP, Severity
```

### Data Enrichment Strategies

**Geolocation and Network Context**
```kql
// IP geolocation enrichment
.create function IPGeolocationEnrichment(ipAddress: string)
{
    external_data(GeoData:string) [
        "https://api.ipgeolocationapi.com/geolocate/" + ipAddress
        with(format="json")
    ]
    | extend
        Country = GeoData.country_name,
        Region = GeoData.region_name,
        City = GeoData.city,
        ISP = GeoData.isp,
        ASN = GeoData.asn
}
```

**Threat Intelligence Matching**
```kql
// IOC matching and enrichment
.create function ThreatIntelEnrichment(indicator: string)
{
    ThreatIntelligenceIndicator
    | where IndicatorType in ("FileHash-MD5", "FileHash-SHA1", "FileHash-SHA256", "DomainName", "IPAddress")
    | where IndicatorValue == indicator
    | project
        IndicatorValue,
        IndicatorType,
        Description,
        ConfidenceScore,
        ThreatType,
        FirstSeen,
        LastSeen
}
```

## Integration with Existing Ecosystems

### ITSM and Ticketing Integration

**ServiceNow Bi-Directional Integration**
```javascript
// ServiceNow incident creation from Sentinel
const serviceNow = require('servicenow-rest-api');

module.exports = async function (context, incident) {
    const snowIncident = {
        short_description: incident.title,
        description: incident.description,
        urgency: mapSeverityToUrgency(incident.severity),
        assignment_group: 'Security Operations',
        u_incident_id: incident.id
    };

    const result = await serviceNow.createIncident(snowIncident);
    context.log(`Created ServiceNow incident: ${result.sys_id}`);
};
```

**Jira Integration for Security Workflows:**
```json
{
  "fields": {
    "project": {
      "key": "SEC"
    },
    "summary": "Security Incident: {{incident.title}}",
    "description": "{{incident.description}}",
    "issuetype": {
      "name": "Incident"
    },
    "priority": {
      "name": "{{incident.severity}}"
    },
    "labels": [
      "sentinel",
      "automated"
    ]
  }
}
```

### Security Tool Ecosystem Integration

**SIEM Migration Strategies**
For organizations migrating from legacy SIEM platforms:

**Splunk Data Migration:**
```bash
# Export Splunk data for Sentinel ingestion
curl -k -u admin:password \
  "https://splunk-server:8089/services/search/jobs/export" \
  -d search="search index=security earliest=-24h" \
  -d output_mode=json \
  | az monitor log-analytics workspace data-export create \
    --resource-group "security-rg" \
    --workspace-name "main-workspace" \
    --name "splunk-migration" \
    --data-source-type "Rest" \
    --data-source-auth '{"authType":"Basic","credentials":{"username":"admin","password":"password"}}'
```

**QRadar Integration:**
- Use QRadar's DSM Editor to configure CEF log forwarding
- Map QRadar event categories to Sentinel severity levels
- Implement correlation rules that span both platforms during migration

### Custom Application Integration

**Line-of-Business Application Logging**
For proprietary applications requiring custom telemetry:

**Application Logging Framework:**
```csharp
// .NET application security event logging
public class SecurityEventLogger
{
    private readonly ILogger _logger;

    public SecurityEventLogger(ILogger logger)
    {
        _logger = logger;
    }

    public void LogSecurityEvent(string eventType, string userId,
        string resource, Dictionary<string, object> context = null)
    {
        var securityEvent = new
        {
            EventTime = DateTime.UtcNow,
            EventType = eventType,
            UserId = userId,
            Resource = resource,
            SourceIP = GetClientIP(),
            UserAgent = GetUserAgent(),
            Context = context ?? new Dictionary<string, object>()
        };

        // Send to Sentinel via REST API
        SendToSentinel(securityEvent);
    }
}
```

## Cost Optimization and Performance Tuning

### Ingestion Cost Management

**Data Sampling Strategies**
```kql
// Intelligent sampling for high-volume logs
Heartbeat
| where Computer in (highVolumeServers)
| sample 10  // Sample 10% of events
| project Computer, OSType, Version, ComputerEnvironment
```

**Basic vs. Analytics Logs**
- **Basic Logs:** High-volume, low-value data (network flows, debug logs) - lower retention, cheaper storage
- **Analytics Logs:** Critical security events requiring advanced analytics and longer retention

**Retention Policy Optimization:**
```powershell
# Set different retention periods by data type
Set-AzOperationalInsightsRetention -ResourceGroupName "security-rg" \
  -WorkspaceName "main-workspace" \
  -TotalRetentionInDays 90 \
  -DataRetentionInDays @{SecurityEvent=365; Syslog=30; AzureActivity=180}
```

### Performance Monitoring and Alerting

**Ingestion Health Monitoring**
```kql
// Monitor data ingestion rates and failures
DataIngestionStats
| where TimeGenerated > ago(24h)
| where IngestionStatus !in ("Success")
| summarize
    FailedIngestionCount = count(),
    TotalIngestionCount = sum(IngestionCount)
    by bin(TimeGenerated, 1h), DataSource
| where FailedIngestionCount > 0
```

**Query Performance Optimization**
```kql
// Identify slow-running queries for optimization
Usage
| where TimeGenerated > ago(7d)
| where QueryText startswith "SecurityEvent"
| top 10 by Duration desc
| project QueryText, Duration, DataUsage
```

## Onboarding Project Management

### Phased Implementation Approach

**Week 1-2: Foundation Setup**
- [ ] Establish Log Analytics workspace and basic configuration
- [ ] Implement Azure AD and Microsoft 365 connectors
- [ ] Configure initial data collection rules and retention policies
- [ ] Set up basic RBAC and access controls

**Week 3-6: Core Security Sources**
- [ ] Deploy endpoint protection platform connectors
- [ ] Implement network security device integrations
- [ ] Configure email and communication security sources
- [ ] Establish data normalization and enrichment pipelines

**Week 7-12: Extended Ecosystem**
- [ ] Add SaaS application audit logs
- [ ] Implement ITSM and ticketing system integrations
- [ ] Deploy custom application logging where needed
- [ ] Configure cross-platform correlation rules

**Month 3-6: Optimization and Expansion**
- [ ] Fine-tune data collection rules based on operational feedback
- [ ] Implement advanced parsing and enrichment functions
- [ ] Add OT/IoT and legacy system integrations
- [ ] Establish continuous monitoring and alerting for data quality

### Success Metrics and Validation

**Data Quality Metrics**
- **Ingestion Success Rate:** Percentage of expected events successfully collected
- **Data Completeness:** Ratio of expected fields populated across event types
- **Timeliness:** Average latency from event generation to availability in Sentinel

**Coverage Validation**
- **Asset Coverage:** Percentage of critical assets with security telemetry
- **Detection Coverage:** MITRE ATT&CK techniques detectable with current data sources
- **Geographic Coverage:** Representation of global operations in telemetry

**Performance Benchmarks**
- **Query Response Time:** Average time for common security queries
- **Ingestion Throughput:** Events per second handled during peak periods
- **Storage Efficiency:** Cost per GB of security data stored and analyzed

## Troubleshooting and Common Issues

### Connector Deployment Issues

**Authentication Failures**
```bash
# Test connector authentication
az sentinel data-connector validate \
  --resource-group "security-rg" \
  --workspace-name "main-workspace" \
  --data-connector-name "AzureADConnector"
```

**Network Connectivity Problems**
- Verify Azure service endpoints and firewall rules
- Check DNS resolution for external data sources
- Validate certificate trust chains for HTTPS connectors

### Data Quality Problems

**Missing or Incomplete Data**
- Review data source configuration for filtering rules
- Check time synchronization across source systems
- Validate field mapping and parsing logic

**Performance Degradation**
- Monitor query patterns and optimize expensive operations
- Review workspace partitioning for large-scale deployments
- Implement data archiving for historical analysis

## Conclusion

Effective data onboarding establishes the foundation for successful Sentinel deployment. By following a structured prioritization framework, implementing robust connector strategies, and maintaining data quality, organizations can ensure comprehensive security visibility while optimizing costs and performance.

The tiered approach allows for rapid initial value realization while providing a roadmap for comprehensive coverage. When combined with proper integration strategies and ongoing optimization, Sentinel becomes a powerful platform for unified security operations across the entire enterprise ecosystem.

The following chapters build upon this data foundation, detailing how to transform raw telemetry into actionable security insights through advanced analytics and intelligent automation.
