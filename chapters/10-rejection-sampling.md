---
prev-chapter: "Automation & Orchestration"
prev-url: "09-instruction-tuning"
page-title: Incident Response & Investigation
next-chapter: "Investigation Workspaces & Visualization"
next-url: "11-policy-gradients"
---

# Incident Response & Investigation

Effective incident response requires structured processes, comprehensive investigation capabilities, and seamless collaboration. Microsoft Sentinel provides an integrated incident response platform that combines automated correlation, intelligent investigation tools, and collaborative workflows to accelerate threat containment and remediation.

## Incident Response Lifecycle Framework

The incident response lifecycle in Sentinel follows a structured approach that ensures comprehensive coverage while maintaining operational efficiency:

```
┌─────────────────────────────────────────────────────────────────┐
│                    Incident Response Lifecycle                   │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ │
│  │   Detection │ │ Investigation│ │ Containment │ │ Remediation │ │
│  │  & Triage   │ │   & Analysis │ │   & Isolation│ │   & Recovery │ │
│  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                                │
┌─────────────────────────────────────────────────────────────────┐
│                    Supporting Processes                         │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ │
│  │ Documentation│ │ Communication│ │   Lessons   │ │   Metrics   │ │
│  │   & Audit    │ │   & Escalation│ │   Learned   │ │   Tracking  │ │
│  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

### 1. Detection and Triage Phase

**Automated Incident Creation:**
```kql
// Monitor alert correlation and incident creation
let alert_volume = SecurityAlert
| where TimeGenerated > ago(24h)
| summarize AlertCount = count() by AlertName, Severity;

let incident_creation = SecurityIncident
| where TimeGenerated > ago(24h)
| summarize
    IncidentCount = count(),
    AvgAlertsPerIncident = avg(AlertCount),
    UniqueEntities = dcount(Entities)
    by Severity, Status;

alert_volume
| join kind=inner incident_creation on AlertName
| extend CorrelationRate = IncidentCount / AlertCount
| project AlertName, Severity, AlertCount, IncidentCount, CorrelationRate, AvgAlertsPerIncident
```

**Intelligent Triage Automation:**
```kql
// Automated triage based on incident characteristics
let triage_rules = datatable(
    TriageRule: string,
    Conditions: dynamic,
    Actions: dynamic,
    Priority: int
) [
    "HighSeverityCredentialAccess", dynamic(["Severity=Critical", "Tactics=CredentialAccess"]), dynamic(["AssignToSeniorAnalyst", "NotifyManager", "CreateP1Ticket"]), 1,
    "MediumSeverityLateralMovement", dynamic(["Severity=Medium", "Tactics=LateralMovement"]), dynamic(["AssignToTeamLead", "ReviewIn2Hours"]), 2,
    "LowSeverityReconnaissance", dynamic(["Severity=Low", "Tactics=Reconnaissance"]), dynamic(["QueueForReview", "ReviewIn24Hours"]), 3,
    "FalsePositivePattern", dynamic(["EntityCount=1", "AlertCount<3"]), dynamic(["MarkForReview", "PotentialFalsePositive"]), 4
];

let new_incidents = SecurityIncident
| where Status == "New"
| where TimeGenerated > ago(1h);

new_incidents
| extend TriageProfile = case(
    Severity == "Critical" and Tactics has "CredentialAccess", "HighSeverityCredentialAccess",
    Severity == "Medium" and Tactics has "LateralMovement", "MediumSeverityLateralMovement",
    Severity == "Low" and Tactics has "Reconnaissance", "LowSeverityReconnaissance",
    array_length(split(Entities, ",")) == 1 and array_length(split(Alerts, ",")) < 3, "FalsePositivePattern",
    "StandardTriage"
)
| lookup kind=leftouter triage_rules on TriageRule
| where isnotempty(Actions)
| project IncidentId, Title, Severity, TriageProfile, Actions, Priority
| order by Priority asc
```

### 2. Investigation and Analysis Phase

**Investigation Workspace Configuration:**
```json
{
  "investigationWorkspace": {
    "enabled": true,
    "autoPopulateEntities": true,
    "suggestedQueries": [
      {
        "name": "EntityTimeline",
        "query": "SecurityEvent | where Account in (entities) or IPAddress in (entities) or Computer in (entities) | where TimeGenerated > ago(7d) | order by TimeGenerated desc",
        "description": "Timeline of events related to incident entities"
      },
      {
        "name": "RelatedIncidents",
        "query": "SecurityIncident | where Entities has_any (entities) | where IncidentId != current_incident_id | where TimeGenerated > ago(30d)",
        "description": "Related incidents involving same entities"
      },
      {
        "name": "ThreatIntelligence",
        "query": "ThreatIntelligenceIndicator | where IndicatorValue in (entities) | where IsActive == true",
        "description": "Threat intelligence related to incident entities"
      }
    ],
    "investigationSteps": [
      {
        "step": 1,
        "name": "Initial Assessment",
        "description": "Review incident details and affected entities",
        "required": true
      },
      {
        "step": 2,
        "name": "Timeline Analysis",
        "description": "Analyze chronological sequence of events",
        "required": true
      },
      {
        "step": 3,
        "name": "Entity Investigation",
        "description": "Deep dive into affected users, hosts, and IPs",
        "required": true
      },
      {
        "step": 4,
        "name": "Scope Assessment",
        "description": "Determine lateral movement and impact scope",
        "required": false
      },
      {
        "step": 5,
        "name": "Containment Planning",
        "description": "Plan containment and remediation actions",
        "required": true
      }
    ]
  }
}
```

**Entity Investigation Framework:**
```kql
// Comprehensive entity investigation
let incident_entities = SecurityIncident
| where IncidentId == "target-incident"
| mv-expand Entities
| extend EntityType = extract("([A-Za-z]+):", 1, Entities)
| extend EntityValue = extract(":(.+)", 1, Entities);

let entity_investigation = incident_entities
| extend InvestigationQuery = case(
    EntityType == "Account",
    strcat("SecurityEvent | where Account == '", EntityValue, "' | where TimeGenerated > ago(7d) | summarize EventTypes = make_set(EventID), ActivityCount = count() by bin(TimeGenerated, 1h)"),
    EntityType == "IPAddress",
    strcat("SecurityEvent | where IPAddress == '", EntityValue, "' | where TimeGenerated > ago(24h) | summarize Connections = count(), UniqueAccounts = dcount(Account), UniqueHosts = dcount(Computer) by Computer"),
    EntityType == "Hostname",
    strcat("SecurityEvent | where Computer == '", EntityValue, "' | where TimeGenerated > ago(48h) | summarize Processes = make_set(NewProcessName), LoginEvents = countif(EventID == 4624), FailedLogins = countif(EventID == 4625)"),
    EntityType == "FileHash",
    strcat("ThreatIntelligenceIndicator | where IndicatorType == 'FileHash-SHA256' | where IndicatorValue == '", EntityValue, "' | project Description, ThreatType, ConfidenceScore, FirstSeen, LastSeen"),
    "Generic investigation query"
);

entity_investigation
| project EntityType, EntityValue, InvestigationQuery, InvestigationPriority = case(
    EntityType == "Account", 1,
    EntityType == "IPAddress", 2,
    EntityType == "Hostname", 3,
    EntityType == "FileHash", 4,
    5
)
| order by InvestigationPriority asc
```

**Timeline Analysis and Attack Chain Reconstruction:**
```kql
// Reconstruct attack timeline and chain
let attack_timeline = SecurityEvent
| where TimeGenerated > ago(7d)
| where (Account in (incident_accounts) or IPAddress in (incident_ips) or Computer in (incident_hosts))
| extend EventType = case(
    EventID == 4624, "SuccessfulLogon",
    EventID == 4625, "FailedLogon",
    EventID == 4688, "ProcessCreation",
    EventID == 4672, "PrivilegeAssignment",
    EventID == 5145, "FileShareAccess",
    EventID == 5156, "WindowsFirewallChange",
    "Other"
)
| extend RiskScore = case(
    EventType == "PrivilegeAssignment" and PrivilegeList contains "SeDebugPrivilege", 0.9,
    EventType == "ProcessCreation" and CommandLine contains "powershell.exe -encodedcommand", 0.8,
    EventType == "FailedLogon" and AccountType == "User", 0.3,
    0.1
)
| order by TimeGenerated asc
| serialize
| extend TimeDiff = datetime_diff('minute', TimeGenerated, prev(TimeGenerated, 1))
| extend AttackStage = case(
    EventType == "SuccessfulLogon" and RiskScore > 0.7, "InitialAccess",
    EventType == "PrivilegeAssignment" and RiskScore > 0.8, "PrivilegeEscalation",
    EventType == "ProcessCreation" and CommandLine contains "mimikatz", "CredentialAccess",
    EventType == "FileShareAccess" and AccessMask has "0x2", "LateralMovement",
    "Unknown"
);

attack_timeline
| where RiskScore > 0.3
| project
    TimeGenerated,
    EventType,
    Computer,
    Account,
    IPAddress,
    RiskScore,
    AttackStage,
    TimeDiff,
    CommandLine,
    EventID
```

### 3. Containment and Isolation Phase

**Automated Containment Actions:**
```json
{
  "containmentPlaybooks": {
    "accountCompromise": {
      "actions": [
        {
          "type": "DisableAccount",
          "target": "affectedAccount",
          "parameters": {
            "forcePasswordChange": true,
            "notifyUser": false,
            "escalateToManager": true
          }
        },
        {
          "type": "ResetPassword",
          "target": "affectedAccount",
          "parameters": {
            "temporaryPassword": true,
            "expirationHours": 24
          }
        },
        {
          "type": "RevokeSessions",
          "target": "affectedAccount",
          "parameters": {
            "allDevices": true,
            "preserveCurrentSession": false
          }
        }
      ]
    },
    "hostCompromise": {
      "actions": [
        {
          "type": "NetworkIsolation",
          "target": "affectedHost",
          "parameters": {
            "isolationLevel": "Full",
            "duration": "24h",
            "notifyOwner": true
          }
        },
        {
          "type": "ProcessTermination",
          "target": "affectedHost",
          "parameters": {
            "suspiciousProcesses": ["malware.exe", "suspicious.ps1"],
            "forceKill": true
          }
        }
      ]
    },
    "networkCompromise": {
      "actions": [
        {
          "type": "IPBlocking",
          "target": "maliciousIP",
          "parameters": {
            "blockType": "Global",
            "duration": "Permanent",
            "notifySecurityTeam": true
          }
        },
        {
          "type": "DNSSinkhole",
          "target": "maliciousDomain",
          "parameters": {
            "sinkholeIP": "127.0.0.1",
            "notifyNetworkTeam": true
          }
        }
      ]
    }
  }
}
```

**Containment Verification:**
```kql
// Verify containment effectiveness
let containment_actions = SecurityIncident
| where Status == "Active"
| where TimeGenerated > ago(24h)
| mv-expand ContainmentActions
| extend ActionType = ContainmentActions.actionType
| extend TargetEntity = ContainmentActions.target
| extend ActionTime = ContainmentActions.timestamp;

let post_containment_activity = SecurityEvent
| where TimeGenerated > ago(24h)
| where (Account in (containment_actions | where ActionType == "DisableAccount" | project TargetEntity)
    or IPAddress in (containment_actions | where ActionType == "IPBlocking" | project TargetEntity)
    or Computer in (containment_actions | where ActionType == "NetworkIsolation" | project TargetEntity))
| summarize
    ActivityCount = count(),
    UniqueEvents = dcount(EventID),
    LastActivity = max(TimeGenerated)
    by EntityType, EntityValue;

containment_actions
| join kind=leftouter post_containment_activity on TargetEntity == EntityValue
| extend ContainmentStatus = case(
    ActivityCount == 0, "Effective",
    ActivityCount < 5, "PartiallyEffective",
    "Ineffective"
)
| project IncidentId, ActionType, TargetEntity, ContainmentStatus, ActivityCount, LastActivity
```

### 4. Remediation and Recovery Phase

**Remediation Workflow Management:**
```kql
// Track remediation progress and status
let remediation_tasks = datatable(
    TaskId: string,
    TaskName: string,
    AssignedTo: string,
    Priority: string,
    Status: string,
    DueDate: datetime,
    Dependencies: dynamic
) [
    "REM-001", "Password Reset for Affected Users", "IdentityTeam", "High", "InProgress", datetime(2024-01-20), dynamic([]),
    "REM-002", "Malware Removal from Infected Hosts", "EndpointTeam", "Critical", "Pending", datetime(2024-01-20), dynamic(["REM-001"]),
    "REM-003", "Firewall Rule Updates", "NetworkTeam", "High", "Pending", datetime(2024-01-21), dynamic([]),
    "REM-004", "Security Patch Deployment", "InfrastructureTeam", "Medium", "Pending", datetime(2024-01-22), dynamic(["REM-002"]),
    "REM-005", "User Security Awareness Training", "HRTeam", "Medium", "Pending", datetime(2024-01-25), dynamic([])
];

let task_dependencies = remediation_tasks
| mv-expand Dependencies
| extend DependsOn = Dependencies;

remediation_tasks
| join kind=leftouter task_dependencies on TaskId == DependsOn
| extend CanStart = case(
    Status == "Completed", true,
    isnull(DependsOn), true,
    false
)
| project TaskId, TaskName, AssignedTo, Priority, Status, DueDate, CanStart, DependsOn
```

**Recovery Validation:**
```kql
// Validate system recovery and normal operations
let baseline_metrics = SecurityEvent
| where TimeGenerated > ago(30d) and TimeGenerated < ago(7d)
| summarize
    AvgDailyLogins = avg(countif(EventID == 4624)) / 30,
    AvgDailyFailures = avg(countif(EventID == 4625)) / 30,
    AvgDailyProcesses = avg(countif(EventID == 4688)) / 30
    by Computer;

let post_incident_metrics = SecurityEvent
| where TimeGenerated > ago(7d)
| summarize
    DailyLogins = countif(EventID == 4624) / 7,
    DailyFailures = countif(EventID == 4625) / 7,
    DailyProcesses = countif(EventID == 4688) / 7
    by Computer;

baseline_metrics
| join kind=inner post_incident_metrics on Computer
| extend
    LoginRecovery = DailyLogins / AvgDailyLogins,
    FailureRecovery = DailyFailures / AvgDailyFailures,
    ProcessRecovery = DailyProcesses / AvgDailyProcesses,
    OverallRecovery = (LoginRecovery + FailureRecovery + ProcessRecovery) / 3
| extend RecoveryStatus = case(
    OverallRecovery >= 0.9, "FullyRecovered",
    OverallRecovery >= 0.7, "PartiallyRecovered",
    "RequiresAttention"
)
| project Computer, OverallRecovery, RecoveryStatus, LoginRecovery, FailureRecovery, ProcessRecovery
```

## Collaboration and Communication Features

### Integrated Teams Collaboration

**War Room Setup and Management:**
```json
{
  "warRoomConfiguration": {
    "autoCreate": true,
    "channelTemplate": {
      "name": "IR-{incidentId}-{severity}",
      "description": "Incident response coordination for {incidentTitle}",
      "privacy": "Private"
    },
    "memberRoles": {
      "IncidentCommander": ["incident-commander@contoso.com"],
      "TechnicalLead": ["technical-lead@contoso.com"],
      "SubjectMatterExperts": ["endpoint-team@contoso.com", "identity-team@contoso.com"],
      "Stakeholders": ["business-owner@contoso.com", "legal-team@contoso.com"]
    },
    "botIntegrations": {
      "statusUpdates": true,
      "evidenceSharing": true,
      "actionTracking": true,
      "escalationAlerts": true
    }
  }
}
```

**Real-Time Status Updates:**
```kql
// Automated status updates during incident response
let incident_updates = SecurityIncident
| where Status in ("Active", "InProgress", "Pending")
| where TimeGenerated > ago(2h)
| extend UpdateType = case(
    Status == "Active", "IncidentActivated",
    Status == "InProgress", "InvestigationStarted",
    Status == "Pending", "ActionRequired",
    "StatusUpdate"
);

let update_messages = incident_updates
| extend MessageTemplate = case(
    UpdateType == "IncidentActivated",
    "🚨 **Incident Activated**: {Title} - Severity: {Severity} - Entities: {EntityCount}",
    UpdateType == "InvestigationStarted",
    "🔍 **Investigation Started**: Analysts assigned - ETA: {InvestigationETA}",
    UpdateType == "ActionRequired",
    "⚠️ **Action Required**: {PendingActions} - Owner: {AssignedTo}",
    "📊 **Status Update**: {CurrentStatus} - Progress: {CompletionPercentage}%"
);

update_messages
| project IncidentId, UpdateType, Message = MessageTemplate, UpdateTime = TimeGenerated
```

### Evidence Collection and Documentation

**Automated Evidence Gathering:**
```kql
// Collect comprehensive evidence for incident documentation
let evidence_collection = datatable(
    EvidenceType: string,
    CollectionQuery: string,
    RetentionDays: int,
    LegalHold: bool
) [
    "AuthenticationLogs", "SecurityEvent | where Account in (incident_accounts) | where EventID in (4624, 4625) | where TimeGenerated > ago(7d)", 90, true,
    "ProcessExecution", "SecurityEvent | where Computer in (incident_hosts) | where EventID == 4688 | where TimeGenerated > ago(48h)", 30, false,
    "NetworkConnections", "SecurityEvent | where IPAddress in (incident_ips) | where EventID in (4624, 4625, 5156) | where TimeGenerated > ago(24h)", 60, true,
    "FileAccess", "SecurityEvent | where EventID == 5145 | where ShareName in (incident_shares) | where TimeGenerated > ago(72h)", 180, true,
    "EmailActivity", "OfficeActivity | where UserId in (incident_accounts) | where TimeGenerated > ago(30d)", 365, false
];

let incident_evidence = evidence_collection
| extend EvidenceId = new_guid()
| extend CollectionTime = now()
| extend IncidentId = "current-incident-id"
| extend CollectionStatus = "InProgress";

incident_evidence
| project EvidenceId, EvidenceType, CollectionQuery, IncidentId, CollectionTime, RetentionDays, LegalHold
```

**Evidence Chain of Custody:**
```kql
// Maintain evidence chain of custody
.create table EvidenceChainOfCustody (
    EvidenceId: string,
    IncidentId: string,
    EvidenceType: string,
    CollectedBy: string,
    CollectionTime: datetime,
    CollectionMethod: string,
    HashValue: string,
    StorageLocation: string,
    AccessLog: dynamic,
    RetentionExpiry: datetime,
    LegalHold: bool
);

// Log evidence access
let evidence_access_log = EvidenceChainOfCustody
| where IncidentId == "current-incident-id"
| mv-expand AccessLog
| extend AccessTime = AccessLog.accessTime
| extend AccessedBy = AccessLog.user
| extend AccessReason = AccessLog.reason;

evidence_access_log
| project EvidenceId, EvidenceType, AccessedBy, AccessTime, AccessReason, StorageLocation
```

## Case Studies and Real-World Examples

### Case Study 1: Ransomware Attack Response

**Incident Summary:**
- **Detection:** Fusion ML detected multi-stage attack pattern
- **Scope:** 15 Windows servers compromised across 3 departments
- **Impact:** Data encryption and exfiltration attempts
- **Response Time:** Contained within 45 minutes

**Response Timeline:**
```kql
// Document complete response timeline
let response_timeline = datatable(
    Timestamp: datetime,
    Phase: string,
    Action: string,
    Actor: string,
    Duration: string,
    Outcome: string
) [
    datetime(2024-01-15T10:00:00Z), "Detection", "Fusion ML Alert", "Automated", "0m", "Incident Created",
    datetime(2024-01-15T10:02:00Z), "Triage", "Severity Assessment", "Automated", "2m", "Critical - Ransomware",
    datetime(2024-01-15T10:05:00Z), "Investigation", "Entity Analysis", "Analyst", "3m", "15 hosts identified",
    datetime(2024-01-15T10:08:00Z), "Containment", "Network Isolation", "Automated", "3m", "All hosts isolated",
    datetime(2024-01-15T10:12:00Z), "Containment", "Process Termination", "Automated", "4m", "Malware processes killed",
    datetime(2024-01-15T10:15:00Z), "Investigation", "Root Cause Analysis", "Analyst", "3m", "Initial access via RDP",
    datetime(2024-01-15T10:20:00Z), "Remediation", "Password Reset", "Automated", "5m", "All accounts secured",
    datetime(2024-01-15T10:25:00Z), "Recovery", "System Restoration", "Infrastructure", "30m", "Clean systems restored",
    datetime(2024-01-15T10:55:00Z), "Closure", "Incident Review", "Team", "15m", "Lessons documented"
];

response_timeline
| extend CumulativeTime = row_cumsum(Duration)
| project Timestamp, Phase, Action, Actor, Duration, CumulativeTime, Outcome
```

**Key Success Factors:**
- Automated correlation reduced detection time from hours to minutes
- Pre-configured playbooks enabled rapid containment
- Integrated evidence collection preserved forensic data
- Cross-team collaboration ensured comprehensive response

### Case Study 2: Credential Stuffing Campaign

**Incident Summary:**
- **Detection:** UEBA identified unusual authentication patterns
- **Scope:** 200+ user accounts targeted across organization
- **Impact:** 15 successful compromises, potential data exfiltration
- **Response Time:** Contained within 2 hours

**Investigation Workflow:**
```kql
// Detailed investigation steps for credential stuffing
let investigation_steps = datatable(
    Step: int,
    StepName: string,
    Query: string,
    ExpectedFindings: string,
    Duration: string
) [
    1, "Pattern Analysis", "SecurityEvent | where EventID == 4625 | where TimeGenerated > ago(24h) | summarize Failures = count(), UniqueAccounts = dcount(Account), UniqueIPs = dcount(IPAddress) by bin(TimeGenerated, 1h)", "High failure rate from few IPs", "5m",
    2, "Source IP Analysis", "SecurityEvent | where EventID == 4625 | where TimeGenerated > ago(24h) | summarize AccountCount = dcount(Account), FailureCount = count() by IPAddress | where FailureCount > 100", "Few IPs targeting many accounts", "3m",
    3, "Account Impact Assessment", "SecurityEvent | where Account in (affected_accounts) | where EventID == 4624 | where TimeGenerated > ago(24h) | summarize SuccessCount = count(), UniqueIPs = dcount(IPAddress) by Account", "Successful logins from malicious IPs", "7m",
    4, "Lateral Movement Check", "SecurityEvent | where Account in (affected_accounts) | where EventID in (4688, 5145) | where TimeGenerated > ago(24h)", "Suspicious post-compromise activity", "10m",
    5, "Threat Intel Correlation", "ThreatIntelligenceIndicator | where IndicatorValue in (malicious_ips) | where IsActive == true", "Known malicious infrastructure", "2m"
];

investigation_steps
| extend StepStatus = case(
    Step == 1, "Completed",
    Step == 2, "Completed",
    Step == 3, "InProgress",
    "Pending"
)
| project Step, StepName, StepStatus, Duration, ExpectedFindings
```

**Response Actions:**
```kql
// Documented response actions and outcomes
let response_actions = datatable(
    ActionId: string,
    ActionType: string,
    Target: string,
    Status: string,
    ExecutedBy: string,
    ExecutionTime: datetime,
    Outcome: string
) [
    "ACT-001", "AccountDisablement", "15 compromised accounts", "Completed", "Automated", datetime(2024-01-15T11:30:00Z), "All accounts disabled",
    "ACT-002", "PasswordReset", "15 compromised accounts", "Completed", "Automated", datetime(2024-01-15T11:32:00Z), "Passwords reset, MFA enforced",
    "ACT-003", "IPBlocking", "23 malicious IPs", "Completed", "Automated", datetime(2024-01-15T11:35:00Z), "IPs blocked globally",
    "ACT-004", "UserNotification", "200 targeted users", "Completed", "Communications", datetime(2024-01-15T12:00:00Z), "Security awareness sent",
    "ACT-005", "MFAEnforcement", "All affected departments", "Completed", "Policy", datetime(2024-01-15T12:30:00Z), "MFA required for all users"
];

response_actions
| order by ExecutionTime asc
| project ActionId, ActionType, Target, ExecutedBy, ExecutionTime, Outcome
```

## Metrics and Performance Tracking

### Incident Response KPIs

**Response Time Metrics:**
```kql
// Track incident response performance
let response_metrics = SecurityIncident
| where Status == "Closed"
| where TimeGenerated > ago(90d)
| extend
    DetectionTime = CreatedTime,
    TriageTime = case(
        Status == "Active", CreatedTime,
        AssignedTime
    ),
    ResponseTime = ClosedTime,
    TotalResponseTime = datetime_diff('hour', ResponseTime, DetectionTime),
    TriageDuration = datetime_diff('minute', TriageTime, DetectionTime),
    InvestigationDuration = datetime_diff('hour', ResponseTime, TriageTime);

response_metrics
| summarize
    AvgTotalResponseTime = avg(TotalResponseTime),
    MedianResponseTime = percentile(TotalResponseTime, 50),
    P95ResponseTime = percentile(TotalResponseTime, 95),
    AvgTriageTime = avg(TriageDuration),
    SLACompliance = countif(TotalResponseTime <= 4) / count() * 100  // 4-hour SLA
    by Severity
| project Severity, AvgTotalResponseTime, MedianResponseTime, P95ResponseTime, AvgTriageTime, SLACompliance
```

**Quality and Effectiveness Metrics:**
```kql
// Measure response quality and effectiveness
let quality_metrics = SecurityIncident
| where Status == "Closed"
| where TimeGenerated > ago(90d)
| extend
    ReopenedIncidents = countif(Status == "Reopened"),
    FalsePositives = countif(Status == "False Positive"),
    Escalations = countif(SeverityChanged == "Increased"),
    CustomerImpact = case(
        BusinessImpact == "None", 0,
        BusinessImpact == "Low", 1,
        BusinessImpact == "Medium", 2,
        BusinessImpact == "High", 3,
        0
    );

quality_metrics
| summarize
    TotalIncidents = count(),
    FalsePositiveRate = FalsePositives / TotalIncidents * 100,
    ReopenRate = ReopenedIncidents / TotalIncidents * 100,
    EscalationRate = Escalations / TotalIncidents * 100,
    AvgCustomerImpact = avg(CustomerImpact)
| extend OverallQualityScore = (1 - FalsePositiveRate/100) * (1 - ReopenRate/100) * (1 - EscalationRate/100) * 100
```

## Continuous Improvement and Lessons Learned

### Post-Incident Review Process

**Structured Review Framework:**
```kql
// Document lessons learned and improvement opportunities
let post_incident_reviews = datatable(
    IncidentId: string,
    ReviewDate: datetime,
    Participants: dynamic,
    KeyFindings: dynamic,
    RootCause: string,
    ImprovementActions: dynamic,
    DueDates: dynamic
) [
    "INC-2024-001", datetime(2024-01-20), dynamic(["Analyst1", "TeamLead", "Manager"]), dynamic([
        "Detection rule missed initial reconnaissance",
        "Response playbook not triggered automatically",
        "Communication delays between teams"
    ]), "Insufficient detection coverage for T1595", dynamic([
        "Enhance reconnaissance detection rules",
        "Fix playbook trigger conditions",
        "Establish communication protocols"
    ]), dynamic([datetime(2024-02-01), datetime(2024-01-25), datetime(2024-01-22)])
];

let action_tracking = post_incident_reviews
| mv-expand ImprovementActions
| mv-expand DueDates
| extend ActionIndex = array_indexof(ImprovementActions, ImprovementActions)
| extend ActionDueDate = DueDates[ActionIndex];

post_incident_reviews
| project IncidentId, ReviewDate, Participants, KeyFindings, RootCause, ImprovementActions
| union (
    action_tracking
    | project IncidentId, Action = ImprovementActions, DueDate = ActionDueDate, Status = "Pending"
)
```

**Trend Analysis for Process Improvement:**
```kql
// Identify recurring issues and improvement opportunities
let incident_trends = SecurityIncident
| where TimeGenerated > ago(180d)
| summarize
    IncidentCount = count(),
    AvgResponseTime = avgif(datetime_diff('hour', ClosedTime, CreatedTime), Status == "Closed"),
    CommonTactics = make_set(Tactics),
    CommonTechniques = make_set(Techniques)
    by month = startofmonth(TimeGenerated);

let improvement_opportunities = incident_trends
| extend
    ResponseTimeTrend = series_fit_line(AvgResponseTime),
    IncidentVolumeTrend = series_fit_line(IncidentCount),
    ImprovementPriority = case(
        ResponseTimeTrend.Slope > 0.5, "High",
        IncidentVolumeTrend.Slope > 0.3, "Medium",
        "Low"
    );

improvement_opportunities
| where ImprovementPriority in ("High", "Medium")
| project month, IncidentCount, AvgResponseTime, CommonTactics, ImprovementPriority, ResponseTimeTrend.Slope
```

## Integration with External Systems

### SIEM and SOAR Integration

**Export to External SIEM:**
```powershell
# Export incident data to external SIEM
function Export-IncidentToSIEM {
    param(
        [string]$IncidentId,
        [string]$SIEMEndpoint,
        [string]$APIKey
    )

    $incident = Get-AzSentinelIncident -WorkspaceName "main-workspace" -IncidentId $IncidentId

    $exportData = @{
        incident_id = $incident.Id
        title = $incident.Title
        severity = $incident.Severity
        status = $incident.Status
        created_time = $incident.CreatedTime
        entities = $incident.Entities
        tactics = $incident.Tactics
        techniques = $incident.Techniques
        description = $incident.Description
        owner = $incident.Owner
        labels = $incident.Labels
    }

    $headers = @{
        "Authorization" = "Bearer $APIKey"
        "Content-Type" = "application/json"
    }

    Invoke-RestMethod -Method POST `
        -Uri "$SIEMEndpoint/api/incidents" `
        -Headers $headers `
        -Body ($exportData | ConvertTo-Json -Depth 3)

    Write-Host "Incident $IncidentId exported to external SIEM"
}
```

### Legal and Compliance Integration

**Legal Hold and Evidence Management:**
```kql
// Manage legal holds and evidence preservation
let legal_holds = datatable(
    CaseId: string,
    IncidentIds: dynamic,
    HoldType: string,
    InitiatedBy: string,
    StartDate: datetime,
    EndDate: datetime,
    Status: string
) [
    "CASE-2024-001", dynamic(["INC-2024-001", "INC-2024-002"]), "RegulatoryInvestigation", "LegalDepartment", datetime(2024-01-15), datetime(2024-07-15), "Active",
    "CASE-2024-002", dynamic(["INC-2024-003"]), "Litigation", "ExternalCounsel", datetime(2024-01-10), datetime(2024-04-10), "Active"
];

let evidence_preservation = legal_holds
| mv-expand IncidentIds
| extend IncidentId = IncidentIds
| extend PreservationRequirements = case(
    HoldType == "RegulatoryInvestigation", "7year_retention",
    HoldType == "Litigation", "case_duration",
    "standard_retention"
);

evidence_preservation
| project CaseId, IncidentId, HoldType, PreservationRequirements, StartDate, EndDate, Status
```

## Conclusion

Effective incident response requires a comprehensive framework that combines automated detection, structured investigation processes, rapid containment capabilities, and continuous improvement. Microsoft Sentinel provides the foundation for this through:

1. **Automated Correlation:** Intelligent grouping of related alerts into actionable incidents
2. **Guided Investigation:** Structured workflows with entity mapping and timeline analysis
3. **Rapid Containment:** Automated response actions with human oversight
4. **Comprehensive Documentation:** Evidence collection and chain of custody management
5. **Continuous Improvement:** Metrics tracking and lessons learned integration

When properly implemented, Sentinel's incident response capabilities can reduce mean time to respond (MTTR) by 70-90%, improve response consistency, and enhance organizational resilience against sophisticated threats. The following chapters explore how visualization and dashboarding capabilities complement these response processes to provide comprehensive operational visibility.
