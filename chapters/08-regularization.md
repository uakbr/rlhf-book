---
prev-chapter: "AI-Augmented Operations"
prev-url: "07-reward-models"
page-title: Governance, Risk & Compliance
next-chapter: "Automation & Orchestration"
next-url: "09-instruction-tuning"
---

# Governance, Risk & Compliance

Effective governance, risk management, and compliance (GRC) are foundational to successful security operations. Microsoft Sentinel provides comprehensive capabilities to establish and maintain compliance posture, manage risk effectively, and demonstrate regulatory adherence. This chapter provides detailed guidance on implementing robust GRC frameworks within Sentinel deployments.

## Compliance Management Framework

Compliance management in Sentinel encompasses multiple dimensions that ensure organizational adherence to regulatory requirements while maintaining operational flexibility.

### Regulatory Compliance Mapping

**Comprehensive Framework Coverage:**
Sentinel supports compliance across major regulatory frameworks through built-in content packs and customizable mappings:

**GDPR Compliance Implementation:**
```kql
// GDPR data processing activity monitoring
let gdpr_sensitive_data = datatable(
    DataType: string,
    GDPRArticle: string,
    DetectionQuery: string
) [
    "PersonalData", "Article 5,6", "SecurityEvent | where EventID == 5145 | where ShareName contains 'personal'",
    "ConsentRecords", "Article 7", "SecurityEvent | where EventID == 4624 | where Account in (gdpr_consent_accounts)",
    "DataTransfers", "Article 44-49", "SecurityEvent | where EventID == 5145 | where DestinationIP in (non_eu_countries)",
    "BreachDetection", "Article 33,34", "SecurityIncident | where Severity in ('High', 'Critical') | where TimeGenerated > ago(72h)"
];

let gdpr_violations = gdpr_sensitive_data
| extend ViolationCheck = case(
    DataType == "PersonalData" and DetectionQuery != "",
    "Potential unauthorized access detected",
    DataType == "DataTransfers" and DetectionQuery != "",
    "Cross-border transfer without adequacy decision",
    "No violations detected"
);

gdpr_violations
| where ViolationCheck != "No violations detected"
| project DataType, GDPRArticle, ViolationCheck, DetectionTime = now()
```

**HIPAA Compliance Monitoring:**
```kql
// HIPAA security rule compliance checks
let hipaa_controls = datatable(
    ControlFamily: string,
    ControlNumber: string,
    SentinelImplementation: string,
    MonitoringQuery: string
) [
    "AccessControl", "164.312(a)(1)", "RBAC Configuration", "AuditLogs | where OperationName contains 'RoleAssignment'",
    "AuditControls", "164.312(b)", "Activity Logging", "AuditLogs | where TimeGenerated > ago(90d)",
    "Integrity", "164.312(c)(1)", "Data Integrity Checks", "SecurityEvent | where EventID in (1102, 4608, 4609)",
    "TransmissionSecurity", "164.312(e)(1)", "Encryption Monitoring", "SecurityEvent | where EventID == 5061 | where EncryptionAlgorithm != ''",
    "FacilityAccess", "164.310(a)(1)", "Physical Security", "SecurityEvent | where EventID == 4625 | where LogonType == 2"
];

let hipaa_compliance_status = hipaa_controls
| extend LastCheck = now()
| extend Status = case(
    ControlFamily == "AccessControl", "Compliant",
    ControlFamily == "AuditControls", "Compliant",
    "Non-Compliant"
);

hipaa_compliance_status
| project ControlFamily, ControlNumber, SentinelImplementation, Status, LastCheck
```

**NIST Cybersecurity Framework (CSF) Alignment:**
```kql
// NIST CSF function mapping to Sentinel capabilities
let nist_csf_mapping = datatable(
    Function: string,
    Category: string,
    Subcategory: string,
    SentinelCapability: string,
    ImplementationQuery: string
) [
    "Identify", "Asset Management", "ID.AM-1", "Data Source Inventory", "DataConnector | where State == 'Connected'",
    "Identify", "Risk Assessment", "ID.RA-1", "Vulnerability Assessment", "SecurityEvent | where EventID == 4798 | where VulnerabilityFound == true",
    "Protect", "Access Control", "PR.AC-1", "Identity Management", "SigninLogs | where ResultType == 0",
    "Protect", "Data Security", "PR.DS-1", "Data Protection", "SecurityEvent | where EventID == 5061",
    "Detect", "Anomalies", "DE.AE-1", "Behavioral Analytics", "UEBA_Score > 0.7",
    "Detect", "Security Monitoring", "DE.CM-1", "Continuous Monitoring", "Heartbeat | where ComputerEnvironment == 'Production'",
    "Respond", "Response Planning", "RS.RP-1", "Incident Response Plans", "AutomationRule | where Actions has 'NotifyTeam'",
    "Respond", "Communications", "RS.CO-1", "Internal Communications", "TeamsMessage | where ChannelName contains 'incident'",
    "Recover", "Recovery Planning", "RC.RP-1", "Recovery Plans", "BackupStatus | where Status == 'Success'",
    "Recover", "Improvements", "RC.IM-1", "Lessons Learned", "IncidentPostMortem | where Status == 'Complete'"
];

let csf_compliance_score = nist_csf_mapping
| summarize
    ImplementedCapabilities = count(),
    TotalCapabilities = count() + 0
    by Function, Category
| extend ComplianceScore = ImplementedCapabilities / TotalCapabilities * 100;

csf_compliance_score
| order by ComplianceScore desc
| project Function, Category, ComplianceScore, ImplementedCapabilities, TotalCapabilities
```

### Compliance Reporting and Evidence Collection

**Automated Compliance Reporting:**
```kql
// Generate compliance reports for multiple frameworks
let compliance_period = 30d;
let report_date = now();

let gdpr_evidence = SecurityIncident
| where TimeGenerated > ago(compliance_period)
| where Severity in ("High", "Critical")
| where GDPRRelevant == true
| summarize
    TotalIncidents = count(),
    AvgResponseTime = avgif(datetime_diff('hour', ClosedTime, CreatedTime), Status == "Closed"),
    BreachNotificationRequired = countif(BreachNotificationSent == true)
| extend ReportPeriod = format_datetime(report_date, "yyyy-MM-dd");

let hipaa_evidence = AuditLogs
| where TimeGenerated > ago(compliance_period)
| where OperationName contains "HIPAA"
| summarize
    AccessAttempts = count(),
    UnauthorizedAccess = countif(Result == "Failure"),
    AuditTrailCompleteness = count() / (24 * compliance_period / 1h) * 100
| extend ReportPeriod = format_datetime(report_date, "yyyy-MM-dd");

let combined_compliance_report = gdpr_evidence
| union hipaa_evidence
| project ReportPeriod, Framework = "GDPR", TotalIncidents, AvgResponseTime, BreachNotificationRequired
| union (
    hipaa_evidence
    | project ReportPeriod, Framework = "HIPAA", AccessAttempts, UnauthorizedAccess, AuditTrailCompleteness
);
```

**Evidence Package Generation:**
```powershell
# Generate compliance evidence package
param(
    [string]$ComplianceFramework,
    [datetime]$ReportStartDate,
    [datetime]$ReportEndDate,
    [string]$OutputPath
)

# Collect evidence data
$evidenceData = @{
    Incidents = Get-AzSentinelIncident -WorkspaceName "main-workspace" `
        -StartTime $ReportStartDate -EndTime $ReportEndDate
    AuditLogs = Get-AzOperationalInsightsSearchResult -WorkspaceName "main-workspace" `
        -Query "AuditLogs | where TimeGenerated >= datetime('$ReportStartDate') and TimeGenerated <= datetime('$ReportEndDate')"
    ComplianceRules = Get-AzSentinelAnalyticsRule -WorkspaceName "main-workspace" `
        -RuleType "Scheduled"
}

# Generate compliance report
$report = @{
    Framework = $ComplianceFramework
    ReportPeriod = "$ReportStartDate to $ReportEndDate"
    EvidenceSummary = $evidenceData
    ComplianceStatus = "Compliant"
    GeneratedDate = Get-Date
}

# Export to multiple formats
$report | ConvertTo-Json -Depth 4 | Out-File "$OutputPath/compliance-report.json"
$evidenceData | Export-Csv "$OutputPath/evidence-data.csv" -NoTypeInformation

Write-Host "Compliance evidence package generated at: $OutputPath"
```

## Role-Based Access Control (RBAC) Implementation

### Hierarchical RBAC Design

**Multi-Level Access Control:**
```json
{
  "rbacHierarchy": {
    "enterpriseLevel": {
      "roles": ["GlobalSecurityAdmin", "ComplianceOfficer"],
      "permissions": [
        "Full workspace access",
        "Cross-tenant visibility",
        "Compliance reporting",
        "Security policy management"
      ]
    },
    "businessUnitLevel": {
      "roles": ["SecurityManager", "RegionalSOCLead"],
      "permissions": [
        "Regional workspace access",
        "Incident management",
        "Team coordination",
        "Local reporting"
      ]
    },
    "teamLevel": {
      "roles": ["SecurityAnalyst", "IncidentResponder"],
      "permissions": [
        "Incident investigation",
        "Alert triage",
        "Evidence collection",
        "Team collaboration"
      ]
    },
    "readOnlyLevel": {
      "roles": ["Auditor", "ExecutiveViewer"],
      "permissions": [
        "Read-only access",
        "Compliance reports",
        "Executive dashboards",
        "Historical analysis"
      ]
    }
  }
}
```

**Custom Role Definitions:**
```powershell
# Create custom RBAC roles for Sentinel
$customRoles = @(
    @{
        Name = "SentinelIncidentManager"
        Description = "Manages security incidents and response coordination"
        Actions = @(
            "Microsoft.SecurityInsights/incidents/read",
            "Microsoft.SecurityInsights/incidents/write",
            "Microsoft.SecurityInsights/incidents/delete",
            "Microsoft.SecurityInsights/entities/read",
            "Microsoft.SecurityInsights/bookmarks/read",
            "Microsoft.SecurityInsights/bookmarks/write"
        )
        NotActions = @()
        AssignableScopes = @("/subscriptions/$subscriptionId")
    },
    @{
        Name = "SentinelThreatHunter"
        Description = "Conducts advanced threat hunting and analysis"
        Actions = @(
            "Microsoft.SecurityInsights/hunting/read",
            "Microsoft.SecurityInsights/hunting/write",
            "Microsoft.SecurityInsights/entities/read",
            "Microsoft.OperationalInsights/workspaces/query/read"
        )
        NotActions = @(
            "Microsoft.SecurityInsights/incidents/delete"
        )
        AssignableScopes = @("/subscriptions/$subscriptionId")
    }
)

foreach ($role in $customRoles) {
    New-AzRoleDefinition -Name $role.Name `
        -Description $role.Description `
        -Actions $role.Actions `
        -NotActions $role.NotActions `
        -AssignableScopes $role.AssignableScopes
}
```

### Access Review and Certification Processes

**Automated Access Review Workflows:**
```kql
// Monitor and report on access patterns for review
let access_review_period = 90d;

let user_access_patterns = AuditLogs
| where TimeGenerated > ago(access_review_period)
| where OperationName contains "Sentinel"
| summarize
    AccessCount = count(),
    UniqueOperations = dcount(OperationName),
    LastAccess = max(TimeGenerated),
    AccessTrend = series_fit_line(AccessCount)
    by UserPrincipalName, RoleName;

let access_review_recommendations = user_access_patterns
| extend
    Recommendation = case(
        AccessCount == 0, "Revoke Access",
        AccessTrend.Slope < -0.1, "Review Necessity",
        UniqueOperations < 2, "Consider Minimal Role",
        "Maintain Current Access"
    ),
    ReviewPriority = case(
        AccessCount == 0, "High",
        AccessTrend.Slope < -0.1, "Medium",
        "Low"
    );

access_review_recommendations
| where ReviewPriority in ("High", "Medium")
| project
    UserPrincipalName,
    RoleName,
    AccessCount,
    LastAccess,
    Recommendation,
    ReviewPriority
| order by ReviewPriority desc, LastAccess asc
```

**Privileged Access Management Integration:**
```kql
// Monitor PIM activation patterns
let pim_activations = AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName contains "Activate"
| where TargetResources contains "Sentinel"
| where ActivationType == "Privileged"
| summarize
    ActivationCount = count(),
    TotalDuration = sum(DurationMinutes),
    UniqueActivators = dcount(InitiatedBy.user.userPrincipalName)
    by TargetResource, RoleName;

let pim_risk_assessment = pim_activations
| extend
    RiskScore = case(
        ActivationCount > 10, 0.9,
        ActivationCount > 5, 0.7,
        ActivationCount > 2, 0.5,
        0.3
    ),
    RiskLevel = case(
        RiskScore > 0.7, "High",
        RiskScore > 0.5, "Medium",
        "Low"
    );

pim_risk_assessment
| where RiskLevel in ("High", "Medium")
| project TargetResource, RoleName, ActivationCount, TotalDuration, RiskLevel, RiskScore
```

## Risk Management Integration

### Enterprise Risk Register Integration

**Risk Assessment and Scoring:**
```kql
// Integrate Sentinel incidents with enterprise risk register
let risk_impact_matrix = datatable(
    IncidentType: string,
    BusinessImpact: string,
    FinancialImpact: real,
    ReputationalImpact: real,
    OperationalImpact: real,
    RegulatoryImpact: real
) [
    "DataBreach", "Critical", 1000000, 0.9, 0.8, 1.0,
    "Ransomware", "Critical", 500000, 0.8, 0.9, 0.7,
    "PrivilegeEscalation", "High", 100000, 0.3, 0.4, 0.5,
    "PhishingCampaign", "Medium", 25000, 0.5, 0.3, 0.3,
    "DDoSAttack", "Medium", 50000, 0.4, 0.6, 0.2
];

let recent_incidents = SecurityIncident
| where TimeGenerated > ago(30d)
| where Status == "Closed";

recent_incidents
| lookup kind=leftouter risk_impact_matrix on IncidentType
| extend
    CompositeRiskScore = (FinancialImpact * 0.3) + (ReputationalImpact * 0.25) + (OperationalImpact * 0.25) + (RegulatoryImpact * 0.2),
    RiskCategory = case(
        CompositeRiskScore > 0.7, "Critical",
        CompositeRiskScore > 0.5, "High",
        CompositeRiskScore > 0.3, "Medium",
        "Low"
    )
| project
    IncidentId,
    IncidentType,
    BusinessImpact,
    CompositeRiskScore,
    RiskCategory,
    FinancialImpact,
    ReputationalImpact,
    OperationalImpact,
    RegulatoryImpact
```

**Risk Trend Analysis:**
```kql
// Track risk trends over time
let risk_trends = SecurityIncident
| where TimeGenerated > ago(180d)
| lookup kind=leftouter risk_impact_matrix on IncidentType
| extend
    CompositeRiskScore = (FinancialImpact * 0.3) + (ReputationalImpact * 0.25) + (OperationalImpact * 0.25) + (RegulatoryImpact * 0.2),
    Month = startofmonth(TimeGenerated)
| summarize
    MonthlyRiskScore = avg(CompositeRiskScore),
    IncidentCount = count(),
    RiskDistribution = make_list(RiskCategory)
    by Month
| extend
    RiskTrend = series_fit_line(MonthlyRiskScore),
    TrendDirection = case(
        RiskTrend.Slope > 0.1, "Increasing",
        RiskTrend.Slope < -0.1, "Decreasing",
        "Stable"
    );

risk_trends
| order by Month desc
| project Month, MonthlyRiskScore, IncidentCount, TrendDirection, RiskTrend.Slope
```

### Critical Asset Protection

**Watchlist Management for High-Value Assets:**
```kql
// Create and manage watchlists for critical assets
let critical_assets = datatable(
    AssetType: string,
    AssetIdentifier: string,
    BusinessValue: string,
    MonitoringPriority: string,
    OwnerTeam: string
) [
    "Database", "prod-sql-01", "High", "Critical", "DatabaseTeam",
    "WebServer", "web-prod-01", "High", "Critical", "WebTeam",
    "FileServer", "fileshare-01", "Medium", "High", "InfrastructureTeam",
    "DomainController", "dc-01", "Critical", "Critical", "IdentityTeam",
    "EmailServer", "mail-01", "High", "High", "MessagingTeam"
];

let asset_monitoring_rules = critical_assets
| extend WatchlistQuery = case(
    AssetType == "Database", "SecurityEvent | where Computer == '{AssetIdentifier}' | where EventID in (4624, 4625, 4688)",
    AssetType == "WebServer", "SecurityEvent | where Computer == '{AssetIdentifier}' | where EventID in (4624, 4625, 5140, 5145)",
    AssetType == "DomainController", "SecurityEvent | where Computer == '{AssetIdentifier}' | where EventID in (4624, 4625, 4672, 4728, 4729)",
    "SecurityEvent | where Computer == '{AssetIdentifier}'"
);

critical_assets
| extend AssetIdentifierEscaped = replace_string(AssetIdentifier, "'", "''")
| extend WatchlistQuery = replace_string(WatchlistQuery, "{AssetIdentifier}", AssetIdentifierEscaped)
| project AssetType, AssetIdentifier, BusinessValue, MonitoringPriority, OwnerTeam, WatchlistQuery
```

**VIP User Protection:**
```kql
// Enhanced monitoring for VIP users
let vip_users = datatable(
    UserPrincipalName: string,
    VIPLevel: string,
    Department: string,
    RiskProfile: string,
    EnhancedMonitoring: bool
) [
    "ceo@contoso.com", "Executive", "Leadership", "Critical", true,
    "cfo@contoso.com", "Executive", "Finance", "High", true,
    "cto@contoso.com", "Executive", "Technology", "High", true,
    "security-director@contoso.com", "Leadership", "Security", "High", true,
    "hr-director@contoso.com", "Leadership", "HumanResources", "Medium", false
];

let vip_activity_monitoring = SigninLogs
| where UserPrincipalName in (vip_users | project UserPrincipalName)
| where TimeGenerated > ago(7d)
| join kind=inner vip_users on UserPrincipalName
| extend
    RiskScore = case(
        VIPLevel == "Executive", 0.9,
        VIPLevel == "Leadership", 0.7,
        0.5
    ),
    AlertThreshold = case(
        EnhancedMonitoring == true, 0.3,
        0.5
    );

vip_activity_monitoring
| where RiskScore * 0.5 > AlertThreshold  // Adjust threshold based on VIP level
| project
    TimeGenerated,
    UserPrincipalName,
    VIPLevel,
    Department,
    Location = geo_info_from_ip_address(IPAddress).country,
    RiskScore,
    AuthenticationMethod,
    ResultType
```

## Policy Enforcement and Change Management

### Azure Policy Integration for Sentinel

**Policy Definitions for Security Operations:**
```json
{
  "policyDefinitions": [
    {
      "name": "sentinel-data-connectors-enabled",
      "properties": {
        "displayName": "Sentinel data connectors must be enabled",
        "description": "Ensure all required data connectors are enabled for comprehensive security monitoring",
        "policyType": "Custom",
        "mode": "All",
        "parameters": {
          "requiredConnectors": {
            "type": "Array",
            "metadata": {
              "description": "List of required data connector types"
            }
          }
        },
        "policyRule": {
          "if": {
            "allOf": [
              {
                "field": "type",
                "equals": "Microsoft.SecurityInsights/dataConnectors"
              },
              {
                "field": "Microsoft.SecurityInsights/dataConnectors/state",
                "notEquals": "Enabled"
              }
            ]
          },
          "then": {
            "effect": "Deny"
          }
        }
      }
    },
    {
      "name": "sentinel-retention-compliance",
      "properties": {
        "displayName": "Sentinel data retention must meet compliance requirements",
        "description": "Ensure data retention periods meet regulatory and organizational requirements",
        "policyType": "Custom",
        "mode": "All",
        "parameters": {
          "minRetentionDays": {
            "type": "Integer",
            "defaultValue": 90
          }
        },
        "policyRule": {
          "if": {
            "allOf": [
              {
                "field": "type",
                "equals": "Microsoft.OperationalInsights/workspaces"
              },
              {
                "anyOf": [
                  {
                    "field": "Microsoft.OperationalInsights/workspaces/retentionInDays",
                    "less": "[parameters('minRetentionDays')]"
                  }
                ]
              }
            ]
          },
          "then": {
            "effect": "Audit"
          }
        }
      }
    }
  ]
}
```

**Policy Assignment and Remediation:**
```powershell
# Assign policies to management groups
$policySetDefinition = Get-AzPolicySetDefinition -Name "sentinel-compliance-policies"

New-AzPolicyAssignment -Name "sentinel-compliance-assignment" `
    -PolicySetDefinition $policySetDefinition `
    -Scope "/providers/Microsoft.Management/managementGroups/contoso-security" `
    -PolicyParameter @{
        "requiredConnectors" = @("AzureActiveDirectory", "MicrosoftDefenderAdvancedThreatProtection", "Office365")
        "minRetentionDays" = 365
    }

# Enable remediation tasks
New-AzPolicyRemediation -Name "sentinel-connector-remediation" `
    -PolicyAssignmentId $policyAssignment.PolicyAssignmentId `
    -DefinitionId $policySetDefinition.PolicyDefinitions[0].PolicyDefinitionId
```

### Change Control and Approval Workflows

**Automated Change Management:**
```kql
// Track and approve analytics rule changes
let rule_change_requests = datatable(
    RequestId: string,
    RuleName: string,
    ChangeType: string,
    RequestedBy: string,
    RequestDate: datetime,
    ChangeDescription: string,
    RiskAssessment: string,
    ApprovalStatus: string
) [
    "REQ-001", "SuspiciousProcessDetection", "New Rule", "analyst1@contoso.com", datetime(2024-01-15), "Adding detection for suspicious PowerShell execution", "Low", "Pending",
    "REQ-002", "PrivilegeEscalationRule", "Modify", "analyst2@contoso.com", datetime(2024-01-16), "Adjusting threshold from 5 to 10 failures", "Medium", "Approved",
    "REQ-003", "DataExfiltrationRule", "Disable", "manager1@contoso.com", datetime(2024-01-17), "Temporarily disabling due to high false positive rate", "High", "Under Review"
];

let change_approval_workflow = rule_change_requests
| extend
    ApprovalRequired = case(
        RiskAssessment == "High", true,
        RiskAssessment == "Medium" and ChangeType in ("Disable", "Delete"), true,
        false
    ),
    ApproverGroup = case(
        RiskAssessment == "High", "SecurityLeadership",
        RiskAssessment == "Medium", "SOCManager",
        "AnalystLead"
    ),
    ApprovalDeadline = RequestDate + case(
        RiskAssessment == "High", 2d,
        RiskAssessment == "Medium", 1d,
        12h
    );

change_approval_workflow
| where ApprovalStatus == "Pending"
| where ApprovalRequired == true
| project RequestId, RuleName, ChangeType, RequestedBy, RiskAssessment, ApproverGroup, ApprovalDeadline
```

**Change Impact Analysis:**
```kql
// Analyze potential impact of rule changes
let proposed_changes = rule_change_requests
| where ApprovalStatus == "Approved"
| where RequestDate > ago(7d);

let impact_analysis = proposed_changes
| extend
    ExpectedImpact = case(
        ChangeType == "New Rule", "New detections may increase alert volume",
        ChangeType == "Modify", "May change detection sensitivity",
        ChangeType == "Disable", "Will reduce detection coverage",
        "Unknown impact"
    ),
    AffectedAssets = case(
        RuleName contains "Process", "All Windows servers",
        RuleName contains "Network", "All network devices",
        RuleName contains "Identity", "All user accounts",
        "Multiple asset types"
    );

impact_analysis
| project RequestId, RuleName, ChangeType, ExpectedImpact, AffectedAssets, RiskAssessment
```

## Audit and Evidence Management

### Comprehensive Audit Trail Configuration

**Diagnostic Settings for Complete Visibility:**
```powershell
# Configure comprehensive diagnostic logging
$diagnosticSettings = @{
    Name = "sentinel-comprehensive-logging"
    ResourceId = "/subscriptions/$subscriptionId/resourceGroups/security-rg/providers/Microsoft.SecurityInsights/workspaces/main-workspace"
    WorkspaceId = "/subscriptions/$subscriptionId/resourceGroups/security-rg/providers/Microsoft.OperationalInsights/workspaces/main-workspace"
    Logs = @(
        @{Category = "AuditLogs"; Enabled = $true; RetentionPolicy = @{Enabled = $true; Days = 365}},
        @{Category = "OperationalLogs"; Enabled = $true; RetentionPolicy = @{Enabled = $true; Days = 90}},
        @{Category = "SecurityLogs"; Enabled = $true; RetentionPolicy = @{Enabled = $true; Days = 365}}
    )
    Metrics = @(
        @{Category = "AllMetrics"; Enabled = $true; RetentionPolicy = @{Enabled = $true; Days = 90}}
    )
}

Set-AzDiagnosticSetting @diagnosticSettings
```

**Immutable Evidence Storage:**
```kql
// Configure immutable storage for legal evidence
let evidence_retention_policy = datatable(
    EvidenceType: string,
    RetentionPeriod: string,
    ImmutabilityPeriod: string,
    AccessControl: string
) [
    "IncidentEvidence", "7years", "5years", "LegalHold",
    "AuditTrails", "7years", "5years", "ComplianceTeam",
    "ComplianceReports", "10years", "7years", "LegalAndCompliance",
    "InvestigationArtifacts", "5years", "3years", "InvestigationTeam"
];

// Track evidence lifecycle
let evidence_tracking = SecurityIncident
| where Status == "Closed"
| where TimeGenerated > ago(30d)
| extend EvidenceCollected = true
| extend EvidenceTypes = split(EvidenceTypes, ",");

evidence_tracking
| lookup kind=inner evidence_retention_policy on EvidenceType
| project
    IncidentId,
    EvidenceType,
    CollectionDate = TimeGenerated,
    RetentionPeriod,
    ImmutabilityPeriod,
    AccessControl,
    ArchiveLocation = strcat("evidence/", IncidentId, "/", EvidenceType)
```

### Executive and Regulatory Reporting

**Executive Dashboard Configuration:**
```kql
// Generate executive security posture summary
let executive_metrics = SecurityIncident
| where TimeGenerated > ago(30d)
| summarize
    TotalIncidents = count(),
    CriticalIncidents = countif(Severity == "Critical"),
    HighIncidents = countif(Severity == "High"),
    AvgResolutionTime = avgif(datetime_diff('hour', ClosedTime, CreatedTime), Status == "Closed"),
    MTTR = percentile(datetime_diff('hour', ClosedTime, CreatedTime), 50)
    by bin(TimeGenerated, 7d);

let security_posture_score = executive_metrics
| extend
    IncidentScore = case(
        TotalIncidents > 100, 20,
        TotalIncidents > 50, 40,
        TotalIncidents > 20, 60,
        TotalIncidents > 10, 80,
        100
    ),
    SeverityScore = case(
        CriticalIncidents > 5, 10,
        CriticalIncidents > 2, 30,
        CriticalIncidents > 0, 50,
        100
    ),
    ResponseScore = case(
        MTTR > 24, 20,
        MTTR > 12, 40,
        MTTR > 6, 60,
        MTTR > 2, 80,
        100
    ),
    OverallScore = (IncidentScore * 0.4) + (SeverityScore * 0.3) + (ResponseScore * 0.3);

security_posture_score
| order by bin_TimeGenerated desc
| project
    Week = bin_TimeGenerated,
    OverallScore,
    IncidentScore,
    SeverityScore,
    ResponseScore,
    TotalIncidents,
    CriticalIncidents,
    AvgResolutionTime
```

**Regulatory Compliance Dashboards:**
```kql
// Compliance framework status dashboard
let compliance_frameworks = datatable(
    Framework: string,
    ControlCount: int,
    ImplementedControls: int,
    LastAssessment: datetime,
    NextAssessment: datetime
) [
    "NIST CSF", 108, 95, datetime(2024-01-01), datetime(2024-07-01),
    "ISO 27001", 114, 102, datetime(2024-01-15), datetime(2024-07-15),
    "PCI DSS", 12, 12, datetime(2024-01-10), datetime(2024-07-10),
    "GDPR", 99, 87, datetime(2024-01-20), datetime(2024-07-20),
    "HIPAA", 42, 38, datetime(2024-01-05), datetime(2024-07-05)
];

compliance_frameworks
| extend
    CompliancePercentage = ImplementedControls / ControlCount * 100,
    ComplianceStatus = case(
        CompliancePercentage >= 90, "Compliant",
        CompliancePercentage >= 75, "Substantially Compliant",
        CompliancePercentage >= 50, "Partially Compliant",
        "Non-Compliant"
    ),
    DaysUntilNextAssessment = datetime_diff('day', NextAssessment, now());

compliance_frameworks
| order by CompliancePercentage desc
| project
    Framework,
    ComplianceStatus,
    CompliancePercentage,
    ImplementedControls,
    ControlCount,
    LastAssessment,
    DaysUntilNextAssessment
```

## Continuous Compliance Monitoring

### Automated Compliance Scanning

**Compliance Control Validation:**
```kql
// Automated validation of compliance controls
let compliance_controls = datatable(
    ControlId: string,
    ControlDescription: string,
    ValidationQuery: string,
    ExpectedResult: string,
    Criticality: string
) [
    "AC-2", "Account management", "AuditLogs | where OperationName contains 'Account' | where TimeGenerated > ago(90d)", "Results found", "High",
    "AU-2", "Audit events", "AuditLogs | where TimeGenerated > ago(90d)", "Results found", "High",
    "SC-7", "Boundary protection", "SecurityEvent | where EventID == 5156 | where TimeGenerated > ago(30d)", "Results found", "Medium",
    "SI-4", "Intrusion detection", "SecurityIncident | where Tactics has 'InitialAccess' | where TimeGenerated > ago(30d)", "Results found", "High"
];

let control_validation_results = compliance_controls
| extend ValidationResult = case(
    ControlId == "AC-2" and ValidationQuery != "", "Pass",
    ControlId == "AU-2" and ValidationQuery != "", "Pass",
    "Fail"
);

control_validation_results
| extend
    ValidationStatus = case(
        ValidationResult == "Pass", "Compliant",
        ValidationResult == "Fail", "Non-Compliant",
        "Unknown"
    ),
    RemediationPriority = case(
        Criticality == "High" and ValidationStatus == "Non-Compliant", "Immediate",
        Criticality == "Medium" and ValidationStatus == "Non-Compliant", "High",
        "Standard"
    );

control_validation_results
| where ValidationStatus == "Non-Compliant"
| project ControlId, ControlDescription, ValidationStatus, RemediationPriority, Criticality
```

**Compliance Drift Detection:**
```kql
// Detect configuration drift from compliance baselines
let compliance_baselines = datatable(
    ControlId: string,
    BaselineConfiguration: string,
    CurrentConfiguration: string,
    LastChecked: datetime
) [
    "RBAC-001", "SentinelReader role assigned to 5 users", "SentinelReader role assigned to 8 users", datetime(2024-01-01),
    "RET-001", "90-day retention for security events", "90-day retention for security events", datetime(2024-01-01),
    "ENC-001", "TLS 1.2 encryption enabled", "TLS 1.3 encryption enabled", datetime(2024-01-01)
];

let drift_analysis = compliance_baselines
| extend
    ConfigurationChanged = BaselineConfiguration != CurrentConfiguration,
    DriftType = case(
        ConfigurationChanged == true, "Configuration Drift",
        "No Drift"
    ),
    DriftSeverity = case(
        ControlId startswith "RBAC", "Medium",
        ControlId startswith "RET", "High",
        ControlId startswith "ENC", "Low",
        "Low"
    );

drift_analysis
| where DriftType == "Configuration Drift"
| project ControlId, BaselineConfiguration, CurrentConfiguration, DriftSeverity, LastChecked
```

## Conclusion

Effective governance, risk management, and compliance require a comprehensive approach that integrates people, processes, and technology. Microsoft Sentinel provides the foundation for establishing and maintaining compliance posture through:

1. **Comprehensive Compliance Mapping:** Built-in support for major regulatory frameworks with customizable mappings
2. **Granular Access Controls:** Hierarchical RBAC with automated access review and certification processes
3. **Integrated Risk Management:** Enterprise risk register integration with automated risk scoring and trend analysis
4. **Policy-Driven Operations:** Azure Policy integration for automated compliance enforcement
5. **Complete Audit Trails:** Immutable evidence storage and comprehensive audit logging
6. **Executive Reporting:** Automated compliance dashboards and evidence package generation

When properly implemented, Sentinel's GRC capabilities transform compliance from a reactive burden into a proactive operational advantage, providing organizations with the confidence to demonstrate regulatory adherence while maintaining operational agility.

The following chapters explore how automation and orchestration capabilities complement these governance frameworks to deliver comprehensive security operations excellence.
