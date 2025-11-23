# Threat Hunting Queries Documentation

## Overview

This document describes the comprehensive threat hunting query library built for IRIS's OpenSearch integration. The queries cover 21 different threat scenarios across 8 major categories aligned with the MITRE ATT&CK framework.

## Query Library Location

**File:** `/source/app/blueprints/threat_hunting_queries.py`

## Supported Threat Categories

### 1. **Email Compromise** (2 queries)
Detections for Office 365 email-based attacks and account compromise.

### 2. **Authentication Attacks** (2 queries)
Detections for credential-based attacks including brute force and password spraying.

### 3. **Credential Theft** (3 queries)
Detections for credential dumping and extraction techniques.

### 4. **Lateral Movement** (3 queries)
Detections for movement between systems using PsExec, WMI, and RDP.

### 5. **Privilege Escalation** (3 queries)
Detections for elevation of privileges through various techniques.

### 6. **Persistence** (3 queries)
Detections for persistence mechanisms including services, scheduled tasks, and registry modifications.

### 7. **Data Exfiltration** (3 queries)
Detections for data theft preparation and exfiltration activities.

### 8. **Backup Tampering** (3 queries)
Detections for ransomware-like behavior targeting backups and shadow copies.

---

## Query Details

### Email Compromise

#### 1. Office 365 - New Inbox Rules Created
**ID:** `o365_new_inbox_rule`
**MITRE ATT&CK:** T1114.003 (Email Collection: Email Forwarding Rule)
**Severity:** High
**Description:** Detects creation of new inbox rules in Office 365, which may indicate account compromise or email forwarding setup.

**Use Case:** Attackers often create inbox rules to:
- Forward copies of emails to external accounts
- Hide emails from the user
- Delete emails automatically
- Move emails to hidden folders

**Default Time Range:** 24 hours

**Aggregations:**
- Groups by user creating rules
- Lists all rule names created

---

#### 2. Office 365 - Email Forwarding to External Domains
**ID:** `o365_external_forwarding`
**MITRE ATT&CK:** T1114.003, T1567.002 (Exfiltration Over Web Service)
**Severity:** Critical
**Description:** Detects email forwarding rules that forward to external domains, indicating potential data exfiltration.

**Use Case:** Identifies forwarding rules sending emails to:
- External email addresses
- Untrusted domains
- Personal email accounts

**Exclusions:** Configure to exclude trusted partner domains in the `must_not` clause.

**Default Time Range:** 7 days

**Aggregations:**
- Groups by forwarding destination
- Lists all affected users

---

### Authentication Attacks

#### 3. Brute Force Attack Detection
**ID:** `brute_force_attack`
**MITRE ATT&CK:** T1110.001 (Brute Force: Password Guessing)
**Severity:** High
**Description:** Detects multiple failed login attempts from the same source IP indicating brute force attack.

**Monitored Event IDs:**
- **4625** - Windows failed logon
- **4771** - Kerberos pre-authentication failed
- **529-539** - Various logon failures

**Threshold:** 10+ failed attempts from single source IP within 1 hour

**Default Time Range:** 1 hour

**Aggregations:**
- Groups by source IP address
- Counts unique users targeted
- Lists all targeted usernames

---

#### 4. Password Spray Attack Detection
**ID:** `password_spray_attack`
**MITRE ATT&CK:** T1110.003 (Brute Force: Password Spraying)
**Severity:** Critical
**Description:** Detects password spray attacks - few failed attempts against many accounts from the same source.

**Detection Logic:**
- Single source IP
- Targeting 20+ unique accounts
- Within 30-minute window
- Low attempts per account (avoiding lockout)

**Difference from Brute Force:** Password spray targets many accounts with few attempts each, while brute force targets few accounts with many attempts.

**Default Time Range:** 1 hour

**Aggregations:**
- Groups by source IP
- Counts unique users targeted
- Lists all targeted accounts

---

### Credential Theft

#### 5. LSASS Memory Dumping - Credential Theft
**ID:** `credential_dumping_lsass`
**MITRE ATT&CK:** T1003.001 (OS Credential Dumping: LSASS Memory)
**Severity:** Critical
**Description:** Detects attempts to dump LSASS process memory to extract credentials.

**Detection Methods:**
1. **Sysmon Event 10** - Process access to lsass.exe with specific access rights
2. **Sysmon Event 11** - Creation of .dmp files with "lsass" in filename
3. **Command line** - Usage of comsvcs.dll MiniDump technique

**Exclusions:** Legitimate tools (Task Manager, WER fault reporting)

**Default Time Range:** 24 hours

**Aggregations:**
- Groups by host
- Lists processes accessing LSASS

---

#### 6. Mimikatz Credential Dumping Detection
**ID:** `mimikatz_usage`
**MITRE ATT&CK:** T1003.001, T1003.002, T1003.004
**Severity:** Critical
**Description:** Detects Mimikatz or similar credential dumping tools.

**Detection Indicators:**
- Command line patterns: `sekurlsa::`, `lsadump::`, `kerberos::`
- Process name: `mimikatz.exe`
- Service installation with Mimikatz in path

**Default Time Range:** 24 hours

**Aggregations:**
- Groups by affected hosts

---

#### 7. SAM Database Extraction
**ID:** `sam_database_extraction`
**MITRE ATT&CK:** T1003.002 (OS Credential Dumping: Security Account Manager)
**Severity:** High
**Description:** Detects attempts to access or copy SAM/SYSTEM/SECURITY registry hives for offline credential extraction.

**Detection Methods:**
1. `reg save` commands targeting SAM, SYSTEM, or SECURITY hives
2. File access to SAM database files
3. Volume shadow copy creation for hive access

**Default Time Range:** 24 hours

**Aggregations:**
- Groups by user performing extraction

---

### Lateral Movement

#### 8. PsExec Lateral Movement Detection
**ID:** `psexec_lateral_movement`
**MITRE ATT&CK:** T1021.002 (Remote Services: SMB/Windows Admin Shares)
**Severity:** High
**Description:** Detects usage of PsExec for lateral movement between systems.

**Detection Indicators:**
1. **Event 7045** - PSEXESVC service installation
2. **Event 18** - Named pipe creation (\\PSEXESVC)
3. **Event 1** - Process execution with PsExec parent
4. **Event 11** - PSEXE* file creation in Windows directory

**Default Time Range:** 24 hours

**Aggregations:**
- Groups by source IP
- Lists all target hosts

---

#### 9. WMI/WmiExec Lateral Movement Detection
**ID:** `wmiexec_lateral_movement`
**MITRE ATT&CK:** T1021.006 (Remote Services: Windows Remote Management)
**Severity:** High
**Description:** Detects Windows Management Instrumentation (WMI) used for lateral movement.

**Detection Indicators:**
1. Process spawning from wmiprvse.exe parent
2. Event 4648 - Explicit credential usage with WMI
3. Events 19-21 - WMI event consumer creation

**Default Time Range:** 24 hours

**Aggregations:**
- Groups by host
- Lists spawned processes

---

#### 10. Suspicious RDP Lateral Movement
**ID:** `rdp_lateral_movement`
**MITRE ATT&CK:** T1021.001 (Remote Services: Remote Desktop Protocol)
**Severity:** Medium
**Description:** Detects unusual RDP connections that may indicate lateral movement.

**Monitored Events:**
- **Event 4624** - Logon Type 10 (RDP)
- **Event 21** - Terminal Services logon
- **Event 25** - RDP reconnection

**Threshold:** Alert if single source connects to 5+ different hosts

**Default Time Range:** 4 hours

**Aggregations:**
- Groups by source IP
- Counts unique target hosts
- Lists all target hosts

---

### Privilege Escalation

#### 11. Token Manipulation - Privilege Escalation
**ID:** `privilege_escalation_tokens`
**MITRE ATT&CK:** T1134.001, T1134.002 (Access Token Manipulation)
**Severity:** High
**Description:** Detects token manipulation techniques used for privilege escalation.

**Detection Indicators:**
1. **Event 4703** - SeDebugPrivilege enabled
2. **Event 10** - Process access with token manipulation rights (0x1478, 0x1f01ff)

**Default Time Range:** 24 hours

**Aggregations:**
- Groups by process name

---

#### 12. UAC Bypass Techniques
**ID:** `uac_bypass`
**MITRE ATT&CK:** T1548.002 (Abuse Elevation Control Mechanism: Bypass UAC)
**Severity:** High
**Description:** Detects common User Account Control bypass methods.

**Detected Techniques:**
1. **Fodhelper** UAC bypass
2. **EventVwr** UAC bypass
3. **ComputerDefaults** UAC bypass
4. **Registry modification** - mscfile shell open command

**Default Time Range:** 24 hours

**Aggregations:**
- Groups by affected host

---

#### 13. Scheduled Task Privilege Escalation
**ID:** `scheduled_task_privesc`
**MITRE ATT&CK:** T1053.005 (Scheduled Task/Job)
**Severity:** Medium
**Description:** Detects scheduled tasks created with SYSTEM privileges by non-SYSTEM users.

**Monitored Events:**
- **Event 4698** - Scheduled task created
- **Event 106** - Task Scheduler - Task registered

**Red Flag:** Task runs as SYSTEM but created by regular user

**Default Time Range:** 24 hours

**Aggregations:**
- Groups by user
- Lists task names

---

### Persistence

#### 14. Suspicious Service Installation
**ID:** `new_service_creation`
**MITRE ATT&CK:** T1543.003 (Create or Modify System Process: Windows Service)
**Severity:** Medium
**Description:** Detects installation of new Windows services with suspicious characteristics.

**Monitored Event:** 7045 - Service installation

**Suspicious Indicators:**
- Service binary in unusual locations (Users, Temp, AppData)
- Command line interpreters as service (cmd.exe, powershell.exe)
- Not in standard Windows or Program Files directories

**Exclusions:** Windows System32 and Program Files services

**Default Time Range:** 24 hours

**Aggregations:**
- Groups by host
- Lists service names

---

#### 15. Suspicious Scheduled Task Creation
**ID:** `scheduled_task_creation`
**MITRE ATT&CK:** T1053.005 (Scheduled Task/Job)
**Severity:** Medium
**Description:** Detects creation of scheduled tasks with suspicious characteristics.

**Monitored Events:**
- **Event 4698** - Task created
- **Event 106** - Task registered

**Suspicious Patterns:**
- PowerShell or cmd.exe execution
- Execution from AppData, Temp, or Public directories
- LOLBins usage (mshta, regsvr32, rundll32)

**Default Time Range:** 24 hours

**Aggregations:**
- Groups by host
- Lists task creators

---

#### 16. Registry Run Key Persistence
**ID:** `registry_run_keys`
**MITRE ATT&CK:** T1547.001 (Boot or Logon Autostart: Registry Run Keys)
**Severity:** Medium
**Description:** Detects modifications to registry run keys used for persistence.

**Monitored Registry Paths:**
- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`

**Monitored Event:** Sysmon Event 13 - Registry value set

**Default Time Range:** 24 hours

**Aggregations:**
- Groups by host
- Lists modified registry keys

---

### Data Exfiltration

#### 17. Mass File Encryption Detection
**ID:** `mass_file_encryption`
**MITRE ATT&CK:** T1486 (Data Encrypted for Impact), T1560.001 (Archive via Utility)
**Severity:** Critical
**Description:** Detects rapid file encryption activity, indicating potential ransomware or data exfiltration preparation.

**Monitored Event:** Sysmon Event 11 - File creation

**Suspicious Extensions:**
- `.encrypted`, `.locked`, `.crypt*`, `.enc`
- Known ransomware extensions (locky, cerber, cryptolocker, etc.)

**Threshold:** 50+ files encrypted within 5 minutes

**Default Time Range:** 1 hour

**Aggregations:**
- Groups by process
- Counts files affected
- Lists affected hosts

---

#### 18. Mass File Compression/Archiving
**ID:** `mass_file_compression`
**MITRE ATT&CK:** T1560.001 (Archive Collected Data)
**Severity:** High
**Description:** Detects mass file compression activity, indicating potential data staging for exfiltration.

**Monitored Tools:**
- 7-Zip (7z.exe, 7za.exe)
- WinRAR (winrar.exe, rar.exe)
- WinZip (winzip.exe)
- PowerShell Compress-Archive
- Tar/gzip

**Suspicious Targets:**
- User directories
- Documents folders
- Desktop
- System drive

**Default Time Range:** 4 hours

**Aggregations:**
- Groups by user
- Lists hosts
- Counts archive operations

---

#### 19. Large Data Upload Detection
**ID:** `large_file_upload`
**MITRE ATT&CK:** T1048.003 (Exfiltration Over Asymmetric Encrypted Non-C2 Protocol)
**Severity:** High
**Description:** Detects large data transfers to external destinations, indicating potential data exfiltration.

**Threshold:** 100 MB+ outbound transfer

**Monitored Destinations:**
- Cloud storage (Dropbox, Box, Mega, Google Drive)
- File sharing (WeTransfer, SendSpace)

**Default Time Range:** 24 hours

**Aggregations:**
- Groups by source IP
- Sums total bytes transferred
- Lists destination domains

---

### Backup Tampering

#### 20. Volume Shadow Copy Deletion
**ID:** `vss_deletion`
**MITRE ATT&CK:** T1490 (Inhibit System Recovery)
**Severity:** Critical
**Description:** Detects deletion of Volume Shadow Copies, common ransomware pre-encryption behavior.

**Monitored Commands:**
- `vssadmin delete shadows`
- `wmic shadowcopy delete`
- `Get-WmiObject Win32_Shadowcopy | Delete` (PowerShell)

**Default Time Range:** 24 hours

**Aggregations:**
- Groups by host
- Lists users executing deletions

---

#### 21. Backup Catalog Deletion
**ID:** `backup_deletion`
**MITRE ATT&CK:** T1490 (Inhibit System Recovery)
**Severity:** Critical
**Description:** Detects deletion or modification of backup catalogs and configurations.

**Monitored Commands:**
- `wbadmin delete catalog`
- `wbadmin delete backup`
- `bcdedit /set recoveryenabled No`
- `bcdedit /set bootstatuspolicy ignoreallfailures`

**Default Time Range:** 24 hours

**Aggregations:**
- Groups by affected host

---

#### 22. Windows Backup Service Tampering
**ID:** `windows_backup_modification`
**MITRE ATT&CK:** T1490 (Inhibit System Recovery)
**Severity:** High
**Description:** Detects attempts to disable or modify Windows Backup service.

**Monitored Events:**
- **Event 7036** - Service stopped (wbengine, SDRSVC)
- **Event 7040** - Service disabled
- **Event 13** - Registry modification to service start type

**Default Time Range:** 24 hours

**Aggregations:**
- Groups by affected host

---

## Usage Examples

### Python Usage

```python
from app.blueprints.threat_hunting_queries import (
    get_query,
    get_queries_by_category,
    get_all_queries,
    get_categories
)

# Get a specific query
query_config = get_query("brute_force_attack")
opensearch_query = query_config["query"]

# Get all queries in a category
email_queries = get_queries_by_category("Email Compromise")

# Get all categories
categories = get_categories()

# Get all queries
all_queries = get_all_queries()
```

### OpenSearch API Usage

```python
import requests

def execute_threat_hunt(opensearch_url, api_key, query_id, time_range="24h"):
    """Execute a threat hunting query against OpenSearch"""

    # Get query configuration
    query_config = get_query(query_id)

    # Build OpenSearch request
    headers = {
        'Authorization': f'ApiKey {api_key}',
        'Content-Type': 'application/json'
    }

    # Add time range filter
    payload = {
        "query": {
            "bool": {
                "must": [
                    query_config["query"],
                    {
                        "range": {
                            "@timestamp": {
                                "gte": f"now-{time_range}",
                                "lte": "now"
                            }
                        }
                    }
                ]
            }
        },
        "aggs": query_config.get("aggregation", {}),
        "size": 1000
    }

    # Execute query
    response = requests.post(
        f"{opensearch_url}/_search",
        headers=headers,
        json=payload,
        verify=True,
        timeout=60
    )

    if response.status_code == 200:
        result = response.json()
        return {
            'success': True,
            'hits': result['hits']['total']['value'],
            'results': result['hits']['hits'],
            'aggregations': result.get('aggregations', {})
        }
    else:
        return {
            'success': False,
            'error': response.text
        }
```

## Field Mappings

These queries assume standard ECS (Elastic Common Schema) or similar field mappings:

### Event Fields
- `event.code` - Event ID (Windows Event Log ID or Sysmon Event ID)
- `event.category` - Event category (authentication, process, network, etc.)
- `event.outcome` - Result of event (success, failure)
- `event.action` - Specific action taken
- `event.dataset` - Source dataset (o365.audit, windows.security, etc.)

### Process Fields
- `process.name` - Process executable name
- `process.command_line` - Full command line
- `process.executable` - Full path to executable
- `process.parent.name` - Parent process name

### User Fields
- `user.name` - Username
- `user.domain` - User domain

### Host Fields
- `host.name` - Hostname
- `host.ip` - Host IP address

### Network Fields
- `source.ip` - Source IP address
- `destination.ip` - Destination IP
- `destination.domain` - Destination domain
- `network.bytes` - Bytes transferred
- `network.direction` - Traffic direction (inbound/outbound)

### File Fields
- `file.path` - Full file path
- `file.name` - Filename
- `file.extension` - File extension

### Windows Specific
- `winlog.event_data.*` - Windows event data fields

## Customization

### Adjusting Time Ranges

Each query has a default `time_range` field. You can override this when executing:

```python
query_config = get_query("brute_force_attack")
# Override default 1h to 4h
custom_time_range = "4h"
```

### Modifying Thresholds

Some queries have threshold configurations for alerting:

```python
# Password Spray threshold
PASSWORD_SPRAY_ATTACK["threshold"]["unique_users"] = 30  # Increase from 20

# Mass Encryption threshold
MASS_FILE_ENCRYPTION["threshold"]["file_count"] = 100  # Increase from 50
```

### Adding Exclusions

Add legitimate systems/users to `must_not` clauses:

```python
# Exclude trusted admin account from privilege escalation alerts
PRIVILEGE_ESCALATION_TOKENS["query"]["bool"]["must_not"] = [
    {
        "terms": {
            "user.name": ["admin-account", "service-account"]
        }
    }
]
```

### Customizing for Your Environment

Edit the queries to match your specific log sources and field names:

1. **Office 365 Logs**: Adjust `event.dataset` if using different log shipping
2. **Sysmon Events**: Ensure Sysmon is configured and event IDs match your deployment
3. **Network Logs**: Modify source detection based on your firewall/proxy logs
4. **Custom Fields**: Map to your organization's field naming conventions

## Integration with IRIS

### Recommended Architecture

```
IRIS Threat Hunting Dashboard
    ↓
OpenSearch Integration Module
    ↓
threat_hunting_queries.py (Query Library)
    ↓
OpenSearch REST API
    ↓
Elasticsearch/OpenSearch Cluster
```

### Workflow

1. User selects threat scenario from dashboard
2. IRIS retrieves query from library
3. Query executed against OpenSearch with time range
4. Results aggregated and displayed
5. User can:
   - Add findings to case notes
   - Export results as artifacts
   - Create IOCs from detected indicators
   - Pivot to related events

## Performance Considerations

### Query Optimization Tips

1. **Use appropriate time ranges**: Shorter ranges = faster queries
2. **Leverage aggregations**: Better than retrieving all matching documents
3. **Add index patterns**: Target specific indices (e.g., `winlogbeat-*`, `o365-*`)
4. **Use query caching**: Cache frequently run queries in OpenSearch
5. **Implement pagination**: Use `from` and `size` parameters for large result sets

### Recommended Index Strategy

```
winlogbeat-*         # Windows event logs
sysmon-*             # Sysmon telemetry
o365-audit-*         # Office 365 audit logs
firewall-*           # Network firewall logs
edr-*                # EDR telemetry
```

## MITRE ATT&CK Coverage

This query library provides detection coverage for the following MITRE ATT&CK techniques:

| Tactic | Technique | Query Coverage |
|--------|-----------|----------------|
| Initial Access | - | - |
| Execution | T1053.005 | 3 queries |
| Persistence | T1543.003, T1053.005, T1547.001 | 3 queries |
| Privilege Escalation | T1134, T1548.002, T1053.005 | 3 queries |
| Defense Evasion | T1548.002 | 1 query |
| Credential Access | T1003.001, T1003.002, T1110 | 5 queries |
| Discovery | - | - |
| Lateral Movement | T1021.001, T1021.002, T1021.006 | 3 queries |
| Collection | T1114.003 | 2 queries |
| Command & Control | - | - |
| Exfiltration | T1048.003, T1567.002 | 3 queries |
| Impact | T1486, T1490 | 4 queries |

**Total Coverage:** 21 techniques across 10 tactics

## Next Steps

1. **Build Integration Module**: Create OpenSearch connection handler in IRIS
2. **Create Dashboard UI**: Build threat hunting interface with query selector
3. **Implement Results Display**: Create table/visualization for query results
4. **Add Case Integration**: Enable adding findings to case notes automatically
5. **Create Scheduling**: Implement scheduled query execution for continuous monitoring
6. **Build Alerting**: Add alerting when query threshold exceeded
7. **Export Functionality**: Enable exporting results as CSV, JSON, or PDF reports

## Support & Contribution

For questions or contributions to the query library:
- Review queries in `/source/app/blueprints/threat_hunting_queries.py`
- Follow ECS field naming conventions
- Include MITRE ATT&CK technique mappings
- Document detection logic and use cases
- Test queries against sample data before deployment
