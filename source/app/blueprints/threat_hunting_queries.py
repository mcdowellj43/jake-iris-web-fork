#  IRIS Source Code
#  Copyright (C) 2025 - DFIR-IRIS
#  contact@dfir-iris.org
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU Lesser General Public
#  License as published by the Free Software Foundation; either
#  version 3 of the License, or (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#  Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public License
#  along with this program; if not, write to the Free Software Foundation,
#  Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

"""
Threat Hunting Query Library for OpenSearch Integration
Contains pre-built detection queries for common threat scenarios
"""

# ============================================================================
# OFFICE 365 EMAIL COMPROMISE DETECTIONS
# ============================================================================

OFFICE365_NEW_INBOX_RULE = {
    "query_name": "Office 365 - New Inbox Rules Created",
    "description": "Detects creation of new inbox rules in Office 365, which may indicate account compromise or email forwarding setup",
    "mitre_attack": ["T1114.003"],
    "severity": "high",
    "query": {
        "bool": {
            "must": [
                {
                    "match": {
                        "event.dataset": "o365.audit"
                    }
                },
                {
                    "terms": {
                        "event.action": [
                            "New-InboxRule",
                            "Set-InboxRule"
                        ]
                    }
                }
            ],
            "must_not": [
                {
                    "match": {
                        "user.name": "system"
                    }
                }
            ]
        }
    },
    "aggregation": {
        "by_user": {
            "terms": {
                "field": "user.name.keyword",
                "size": 50
            },
            "aggs": {
                "rule_names": {
                    "terms": {
                        "field": "o365.audit.Parameters.Name.keyword",
                        "size": 20
                    }
                }
            }
        }
    },
    "time_range": "24h"
}

OFFICE365_EXTERNAL_FORWARDING = {
    "query_name": "Office 365 - Email Forwarding to External Domains",
    "description": "Detects email forwarding rules that forward to external domains, potential data exfiltration",
    "mitre_attack": ["T1114.003", "T1567.002"],
    "severity": "critical",
    "query": {
        "bool": {
            "must": [
                {
                    "match": {
                        "event.dataset": "o365.audit"
                    }
                },
                {
                    "terms": {
                        "event.action": [
                            "New-InboxRule",
                            "Set-InboxRule",
                            "Set-Mailbox"
                        ]
                    }
                },
                {
                    "bool": {
                        "should": [
                            {
                                "wildcard": {
                                    "o365.audit.Parameters.ForwardTo": "*@*"
                                }
                            },
                            {
                                "wildcard": {
                                    "o365.audit.Parameters.ForwardAsAttachmentTo": "*@*"
                                }
                            },
                            {
                                "wildcard": {
                                    "o365.audit.Parameters.RedirectTo": "*@*"
                                }
                            }
                        ]
                    }
                }
            ],
            "must_not": [
                {
                    "terms": {
                        "o365.audit.Parameters.ForwardTo": [
                            "*@yourdomain.com",
                            "*@trusteddomain.com"
                        ]
                    }
                }
            ]
        }
    },
    "aggregation": {
        "by_forwarding_address": {
            "terms": {
                "field": "o365.audit.Parameters.ForwardTo.keyword",
                "size": 50
            },
            "aggs": {
                "users": {
                    "terms": {
                        "field": "user.name.keyword"
                    }
                }
            }
        }
    },
    "time_range": "7d"
}

# ============================================================================
# AUTHENTICATION ATTACK DETECTIONS
# ============================================================================

BRUTE_FORCE_ATTACK = {
    "query_name": "Brute Force Attack Detection",
    "description": "Detects multiple failed login attempts from the same source indicating brute force attack",
    "mitre_attack": ["T1110.001"],
    "severity": "high",
    "query": {
        "bool": {
            "must": [
                {
                    "terms": {
                        "event.category": ["authentication", "iam"]
                    }
                },
                {
                    "match": {
                        "event.outcome": "failure"
                    }
                },
                {
                    "terms": {
                        "event.code": [
                            "4625",  # Windows failed logon
                            "4771",  # Kerberos pre-auth failed
                            "529",   # Logon failure
                            "530",   # Logon outside allowed time
                            "531",   # Account disabled
                            "532",   # Account expired
                            "533",   # User not allowed to logon
                            "534",   # User not allowed - type
                            "535",   # Password expired
                            "539"    # Account locked out
                        ]
                    }
                }
            ]
        }
    },
    "aggregation": {
        "by_source_ip": {
            "terms": {
                "field": "source.ip",
                "size": 100,
                "min_doc_count": 10  # Alert if 10+ failures from same IP
            },
            "aggs": {
                "targeted_users": {
                    "cardinality": {
                        "field": "user.name.keyword"
                    }
                },
                "user_list": {
                    "terms": {
                        "field": "user.name.keyword",
                        "size": 50
                    }
                }
            }
        }
    },
    "time_range": "1h"
}

PASSWORD_SPRAY_ATTACK = {
    "query_name": "Password Spray Attack Detection",
    "description": "Detects password spray attacks - few failed attempts against many accounts from same source",
    "mitre_attack": ["T1110.003"],
    "severity": "critical",
    "query": {
        "bool": {
            "must": [
                {
                    "terms": {
                        "event.category": ["authentication", "iam"]
                    }
                },
                {
                    "match": {
                        "event.outcome": "failure"
                    }
                },
                {
                    "terms": {
                        "event.code": [
                            "4625",
                            "4771"
                        ]
                    }
                }
            ]
        }
    },
    "aggregation": {
        "by_source_ip": {
            "terms": {
                "field": "source.ip",
                "size": 100
            },
            "aggs": {
                "unique_users": {
                    "cardinality": {
                        "field": "user.name.keyword"
                    }
                },
                "failed_attempts": {
                    "value_count": {
                        "field": "event.id"
                    }
                },
                "targeted_accounts": {
                    "terms": {
                        "field": "user.name.keyword",
                        "size": 100
                    }
                }
            }
        }
    },
    "threshold": {
        "unique_users": 20,  # Alert if targeting 20+ unique accounts
        "time_window": "30m"
    },
    "time_range": "1h"
}

# ============================================================================
# CREDENTIAL THEFT DETECTIONS
# ============================================================================

CREDENTIAL_DUMPING_LSASS = {
    "query_name": "LSASS Memory Dumping - Credential Theft",
    "description": "Detects attempts to dump LSASS process memory to extract credentials",
    "mitre_attack": ["T1003.001"],
    "severity": "critical",
    "query": {
        "bool": {
            "should": [
                # Sysmon Event 10 - Process Access
                {
                    "bool": {
                        "must": [
                            {
                                "match": {
                                    "event.code": "10"
                                }
                            },
                            {
                                "match": {
                                    "winlog.event_data.TargetImage": "*\\lsass.exe"
                                }
                            },
                            {
                                "terms": {
                                    "winlog.event_data.GrantedAccess": [
                                        "0x1010",
                                        "0x1410",
                                        "0x147a",
                                        "0x143a"
                                    ]
                                }
                            }
                        ]
                    }
                },
                # MiniDump creation
                {
                    "bool": {
                        "must": [
                            {
                                "match": {
                                    "event.code": "11"
                                }
                            },
                            {
                                "wildcard": {
                                    "file.path": "*lsass*.dmp"
                                }
                            }
                        ]
                    }
                },
                # Comsvcs.dll method
                {
                    "bool": {
                        "must": [
                            {
                                "match": {
                                    "event.code": "1"
                                }
                            },
                            {
                                "wildcard": {
                                    "process.command_line": "*comsvcs.dll*MiniDump*"
                                }
                            }
                        ]
                    }
                }
            ],
            "must_not": [
                {
                    "terms": {
                        "process.executable": [
                            "C:\\Windows\\System32\\taskmgr.exe",
                            "C:\\Windows\\System32\\werfault.exe"
                        ]
                    }
                }
            ]
        }
    },
    "aggregation": {
        "by_host": {
            "terms": {
                "field": "host.name.keyword",
                "size": 50
            },
            "aggs": {
                "processes": {
                    "terms": {
                        "field": "process.name.keyword",
                        "size": 20
                    }
                }
            }
        }
    },
    "time_range": "24h"
}

MIMIKATZ_USAGE = {
    "query_name": "Mimikatz Credential Dumping Detection",
    "description": "Detects Mimikatz or similar credential dumping tools",
    "mitre_attack": ["T1003.001", "T1003.002", "T1003.004"],
    "severity": "critical",
    "query": {
        "bool": {
            "should": [
                # Process creation
                {
                    "wildcard": {
                        "process.command_line": "*sekurlsa::*"
                    }
                },
                {
                    "wildcard": {
                        "process.command_line": "*lsadump::*"
                    }
                },
                {
                    "wildcard": {
                        "process.command_line": "*kerberos::*"
                    }
                },
                {
                    "match": {
                        "process.name": "mimikatz.exe"
                    }
                },
                # Service installation
                {
                    "bool": {
                        "must": [
                            {
                                "match": {
                                    "event.code": "7045"
                                }
                            },
                            {
                                "wildcard": {
                                    "winlog.event_data.ImagePath": "*mimikatz*"
                                }
                            }
                        ]
                    }
                }
            ]
        }
    },
    "aggregation": {
        "by_host": {
            "terms": {
                "field": "host.name.keyword",
                "size": 50
            }
        }
    },
    "time_range": "24h"
}

SAM_DATABASE_EXTRACTION = {
    "query_name": "SAM Database Extraction",
    "description": "Detects attempts to access or copy SAM/SYSTEM/SECURITY registry hives for offline credential extraction",
    "mitre_attack": ["T1003.002"],
    "severity": "high",
    "query": {
        "bool": {
            "should": [
                # reg save commands
                {
                    "wildcard": {
                        "process.command_line": "*reg*save*HKLM\\SAM*"
                    }
                },
                {
                    "wildcard": {
                        "process.command_line": "*reg*save*HKLM\\SYSTEM*"
                    }
                },
                {
                    "wildcard": {
                        "process.command_line": "*reg*save*HKLM\\SECURITY*"
                    }
                },
                # File access to SAM files
                {
                    "bool": {
                        "must": [
                            {
                                "match": {
                                    "event.code": "11"
                                }
                            },
                            {
                                "wildcard": {
                                    "file.path": "*\\config\\SAM*"
                                }
                            }
                        ]
                    }
                },
                # Volume shadow copy access
                {
                    "wildcard": {
                        "process.command_line": "*vssadmin*create*shadow*"
                    }
                }
            ]
        }
    },
    "aggregation": {
        "by_user": {
            "terms": {
                "field": "user.name.keyword",
                "size": 50
            }
        }
    },
    "time_range": "24h"
}

# ============================================================================
# LATERAL MOVEMENT DETECTIONS
# ============================================================================

PSEXEC_LATERAL_MOVEMENT = {
    "query_name": "PsExec Lateral Movement Detection",
    "description": "Detects usage of PsExec for lateral movement between systems",
    "mitre_attack": ["T1021.002"],
    "severity": "high",
    "query": {
        "bool": {
            "should": [
                # PsExec service installation (Event ID 7045)
                {
                    "bool": {
                        "must": [
                            {
                                "match": {
                                    "event.code": "7045"
                                }
                            },
                            {
                                "wildcard": {
                                    "winlog.event_data.ServiceName": "PSEXESVC*"
                                }
                            }
                        ]
                    }
                },
                # Named pipe creation for PsExec
                {
                    "bool": {
                        "must": [
                            {
                                "match": {
                                    "event.code": "18"
                                }
                            },
                            {
                                "wildcard": {
                                    "winlog.event_data.PipeName": "*\\PSEXESVC*"
                                }
                            }
                        ]
                    }
                },
                # PsExec process execution
                {
                    "bool": {
                        "must": [
                            {
                                "match": {
                                    "event.code": "1"
                                }
                            },
                            {
                                "wildcard": {
                                    "process.parent.name": "*psexec*"
                                }
                            }
                        ]
                    }
                },
                # Remote file creation
                {
                    "bool": {
                        "must": [
                            {
                                "match": {
                                    "event.code": "11"
                                }
                            },
                            {
                                "wildcard": {
                                    "file.path": "*\\Windows\\PSEXE*"
                                }
                            }
                        ]
                    }
                }
            ]
        }
    },
    "aggregation": {
        "by_source_host": {
            "terms": {
                "field": "source.ip",
                "size": 50
            },
            "aggs": {
                "target_hosts": {
                    "terms": {
                        "field": "host.name.keyword",
                        "size": 50
                    }
                }
            }
        }
    },
    "time_range": "24h"
}

WMIEXEC_LATERAL_MOVEMENT = {
    "query_name": "WMI/WmiExec Lateral Movement Detection",
    "description": "Detects Windows Management Instrumentation (WMI) used for lateral movement",
    "mitre_attack": ["T1021.006"],
    "severity": "high",
    "query": {
        "bool": {
            "should": [
                # WMI process spawning
                {
                    "bool": {
                        "must": [
                            {
                                "match": {
                                    "event.code": "1"
                                }
                            },
                            {
                                "terms": {
                                    "process.parent.name": [
                                        "wmiprvse.exe",
                                        "WmiPrvSE.exe"
                                    ]
                                }
                            }
                        ],
                        "must_not": [
                            {
                                "terms": {
                                    "process.name": [
                                        "WmiPrvSE.exe",
                                        "wmiprvse.exe"
                                    ]
                                }
                            }
                        ]
                    }
                },
                # Remote WMI execution (Event ID 4648)
                {
                    "bool": {
                        "must": [
                            {
                                "match": {
                                    "event.code": "4648"
                                }
                            },
                            {
                                "match": {
                                    "winlog.event_data.ProcessName": "*\\wmiprvse.exe"
                                }
                            }
                        ]
                    }
                },
                # WMI event consumer
                {
                    "bool": {
                        "must": [
                            {
                                "terms": {
                                    "event.code": ["19", "20", "21"]
                                }
                            }
                        ]
                    }
                }
            ]
        }
    },
    "aggregation": {
        "by_host": {
            "terms": {
                "field": "host.name.keyword",
                "size": 50
            },
            "aggs": {
                "spawned_processes": {
                    "terms": {
                        "field": "process.name.keyword",
                        "size": 20
                    }
                }
            }
        }
    },
    "time_range": "24h"
}

RDP_LATERAL_MOVEMENT = {
    "query_name": "Suspicious RDP Lateral Movement",
    "description": "Detects unusual RDP connections that may indicate lateral movement",
    "mitre_attack": ["T1021.001"],
    "severity": "medium",
    "query": {
        "bool": {
            "should": [
                # RDP logon (Event ID 4624, Logon Type 10)
                {
                    "bool": {
                        "must": [
                            {
                                "match": {
                                    "event.code": "4624"
                                }
                            },
                            {
                                "match": {
                                    "winlog.event_data.LogonType": "10"
                                }
                            }
                        ]
                    }
                },
                # Terminal Services logon
                {
                    "match": {
                        "event.code": "21"
                    }
                },
                # RDP reconnection
                {
                    "match": {
                        "event.code": "25"
                    }
                }
            ]
        }
    },
    "aggregation": {
        "by_source_ip": {
            "terms": {
                "field": "source.ip",
                "size": 100
            },
            "aggs": {
                "unique_targets": {
                    "cardinality": {
                        "field": "host.name.keyword"
                    }
                },
                "target_hosts": {
                    "terms": {
                        "field": "host.name.keyword",
                        "size": 50
                    }
                }
            }
        }
    },
    "threshold": {
        "unique_targets": 5  # Alert if RDP to 5+ different hosts from same source
    },
    "time_range": "4h"
}

# ============================================================================
# PRIVILEGE ESCALATION DETECTIONS
# ============================================================================

PRIVILEGE_ESCALATION_TOKENS = {
    "query_name": "Token Manipulation - Privilege Escalation",
    "description": "Detects token manipulation techniques used for privilege escalation",
    "mitre_attack": ["T1134.001", "T1134.002"],
    "severity": "high",
    "query": {
        "bool": {
            "should": [
                # SeDebugPrivilege enabled
                {
                    "bool": {
                        "must": [
                            {
                                "match": {
                                    "event.code": "4703"
                                }
                            },
                            {
                                "match": {
                                    "winlog.event_data.EnabledPrivilegeList": "*SeDebugPrivilege*"
                                }
                            }
                        ]
                    }
                },
                # Token impersonation via Sysmon Event 10
                {
                    "bool": {
                        "must": [
                            {
                                "match": {
                                    "event.code": "10"
                                }
                            },
                            {
                                "terms": {
                                    "winlog.event_data.GrantedAccess": [
                                        "0x1478",
                                        "0x1f01ff"
                                    ]
                                }
                            }
                        ]
                    }
                }
            ]
        }
    },
    "aggregation": {
        "by_process": {
            "terms": {
                "field": "process.name.keyword",
                "size": 50
            }
        }
    },
    "time_range": "24h"
}

UAC_BYPASS = {
    "query_name": "UAC Bypass Techniques",
    "description": "Detects common User Account Control bypass methods",
    "mitre_attack": ["T1548.002"],
    "severity": "high",
    "query": {
        "bool": {
            "should": [
                # Fodhelper UAC bypass
                {
                    "wildcard": {
                        "process.command_line": "*fodhelper.exe*"
                    }
                },
                # EventVwr UAC bypass
                {
                    "bool": {
                        "must": [
                            {
                                "match": {
                                    "process.name": "eventvwr.exe"
                                }
                            },
                            {
                                "exists": {
                                    "field": "process.parent.name"
                                }
                            }
                        ],
                        "must_not": [
                            {
                                "terms": {
                                    "process.parent.name": [
                                        "mmc.exe",
                                        "explorer.exe"
                                    ]
                                }
                            }
                        ]
                    }
                },
                # ComputerDefaults UAC bypass
                {
                    "wildcard": {
                        "process.command_line": "*ComputerDefaults.exe*"
                    }
                },
                # Registry modification for UAC bypass
                {
                    "bool": {
                        "must": [
                            {
                                "match": {
                                    "event.code": "13"
                                }
                            },
                            {
                                "wildcard": {
                                    "winlog.event_data.TargetObject": "*mscfile\\shell\\open\\command*"
                                }
                            }
                        ]
                    }
                }
            ]
        }
    },
    "aggregation": {
        "by_host": {
            "terms": {
                "field": "host.name.keyword",
                "size": 50
            }
        }
    },
    "time_range": "24h"
}

SCHEDULED_TASK_PRIVESC = {
    "query_name": "Scheduled Task Privilege Escalation",
    "description": "Detects scheduled tasks created with SYSTEM privileges, potential privilege escalation",
    "mitre_attack": ["T1053.005"],
    "severity": "medium",
    "query": {
        "bool": {
            "must": [
                {
                    "terms": {
                        "event.code": [
                            "4698",  # Scheduled task created
                            "106"    # Task Scheduler - Task registered
                        ]
                    }
                },
                {
                    "wildcard": {
                        "winlog.event_data.TaskContent": "*SYSTEM*"
                    }
                }
            ],
            "must_not": [
                {
                    "terms": {
                        "user.name": [
                            "SYSTEM",
                            "NT AUTHORITY\\SYSTEM"
                        ]
                    }
                }
            ]
        }
    },
    "aggregation": {
        "by_user": {
            "terms": {
                "field": "user.name.keyword",
                "size": 50
            },
            "aggs": {
                "task_names": {
                    "terms": {
                        "field": "winlog.event_data.TaskName.keyword",
                        "size": 20
                    }
                }
            }
        }
    },
    "time_range": "24h"
}

# ============================================================================
# PERSISTENCE DETECTIONS
# ============================================================================

NEW_SERVICE_CREATION = {
    "query_name": "Suspicious Service Installation",
    "description": "Detects installation of new Windows services, potential persistence mechanism",
    "mitre_attack": ["T1543.003"],
    "severity": "medium",
    "query": {
        "bool": {
            "must": [
                {
                    "match": {
                        "event.code": "7045"
                    }
                }
            ],
            "must_not": [
                # Exclude common legitimate services
                {
                    "wildcard": {
                        "winlog.event_data.ServiceName": "MpKsl*"
                    }
                },
                {
                    "wildcard": {
                        "winlog.event_data.ImagePath": "*Windows\\System32\\*"
                    }
                },
                {
                    "wildcard": {
                        "winlog.event_data.ImagePath": "*Program Files\\*"
                    }
                }
            ],
            "should": [
                # Suspicious service characteristics
                {
                    "wildcard": {
                        "winlog.event_data.ImagePath": "*cmd.exe*"
                    }
                },
                {
                    "wildcard": {
                        "winlog.event_data.ImagePath": "*powershell*"
                    }
                },
                {
                    "wildcard": {
                        "winlog.event_data.ImagePath": "*\\Users\\*"
                    }
                },
                {
                    "wildcard": {
                        "winlog.event_data.ImagePath": "*\\Temp\\*"
                    }
                },
                {
                    "wildcard": {
                        "winlog.event_data.ImagePath": "*\\AppData\\*"
                    }
                }
            ],
            "minimum_should_match": 1
        }
    },
    "aggregation": {
        "by_host": {
            "terms": {
                "field": "host.name.keyword",
                "size": 50
            },
            "aggs": {
                "service_names": {
                    "terms": {
                        "field": "winlog.event_data.ServiceName.keyword",
                        "size": 20
                    }
                }
            }
        }
    },
    "time_range": "24h"
}

SCHEDULED_TASK_CREATION = {
    "query_name": "Suspicious Scheduled Task Creation",
    "description": "Detects creation of scheduled tasks that may be used for persistence or execution",
    "mitre_attack": ["T1053.005"],
    "severity": "medium",
    "query": {
        "bool": {
            "must": [
                {
                    "terms": {
                        "event.code": [
                            "4698",  # Task created
                            "106"    # Task registered
                        ]
                    }
                }
            ],
            "should": [
                # Suspicious task patterns
                {
                    "wildcard": {
                        "winlog.event_data.TaskContent": "*powershell*"
                    }
                },
                {
                    "wildcard": {
                        "winlog.event_data.TaskContent": "*cmd.exe*"
                    }
                },
                {
                    "wildcard": {
                        "winlog.event_data.TaskContent": "*\\AppData\\*"
                    }
                },
                {
                    "wildcard": {
                        "winlog.event_data.TaskContent": "*\\Temp\\*"
                    }
                },
                {
                    "wildcard": {
                        "winlog.event_data.TaskContent": "*\\Users\\Public\\*"
                    }
                },
                {
                    "wildcard": {
                        "winlog.event_data.TaskContent": "*mshta*"
                    }
                },
                {
                    "wildcard": {
                        "winlog.event_data.TaskContent": "*regsvr32*"
                    }
                },
                {
                    "wildcard": {
                        "winlog.event_data.TaskContent": "*rundll32*"
                    }
                }
            ],
            "minimum_should_match": 1
        }
    },
    "aggregation": {
        "by_host": {
            "terms": {
                "field": "host.name.keyword",
                "size": 50
            },
            "aggs": {
                "task_creators": {
                    "terms": {
                        "field": "user.name.keyword",
                        "size": 20
                    }
                }
            }
        }
    },
    "time_range": "24h"
}

REGISTRY_RUN_KEYS = {
    "query_name": "Registry Run Key Persistence",
    "description": "Detects modifications to registry run keys used for persistence",
    "mitre_attack": ["T1547.001"],
    "severity": "medium",
    "query": {
        "bool": {
            "must": [
                {
                    "match": {
                        "event.code": "13"  # Sysmon Registry value set
                    }
                },
                {
                    "bool": {
                        "should": [
                            {
                                "wildcard": {
                                    "winlog.event_data.TargetObject": "*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run*"
                                }
                            },
                            {
                                "wildcard": {
                                    "winlog.event_data.TargetObject": "*\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce*"
                                }
                            },
                            {
                                "wildcard": {
                                    "winlog.event_data.TargetObject": "*\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run*"
                                }
                            }
                        ]
                    }
                }
            ]
        }
    },
    "aggregation": {
        "by_host": {
            "terms": {
                "field": "host.name.keyword",
                "size": 50
            },
            "aggs": {
                "registry_keys": {
                    "terms": {
                        "field": "winlog.event_data.TargetObject.keyword",
                        "size": 20
                    }
                }
            }
        }
    },
    "time_range": "24h"
}

# ============================================================================
# DATA EXFILTRATION DETECTIONS
# ============================================================================

MASS_FILE_ENCRYPTION = {
    "query_name": "Mass File Encryption Detection",
    "description": "Detects rapid file encryption activity, potential ransomware or data exfiltration prep",
    "mitre_attack": ["T1486", "T1560.001"],
    "severity": "critical",
    "query": {
        "bool": {
            "must": [
                {
                    "match": {
                        "event.code": "11"  # Sysmon File creation
                    }
                },
                {
                    "bool": {
                        "should": [
                            # Common ransomware extensions
                            {
                                "wildcard": {
                                    "file.extension": "encrypted"
                                }
                            },
                            {
                                "wildcard": {
                                    "file.extension": "locked"
                                }
                            },
                            {
                                "wildcard": {
                                    "file.extension": "crypt*"
                                }
                            },
                            {
                                "wildcard": {
                                    "file.path": "*.enc"
                                }
                            },
                            # Known ransomware extensions
                            {
                                "terms": {
                                    "file.extension": [
                                        "locky",
                                        "cerber",
                                        "cryptolocker",
                                        "wannacry",
                                        "gandcrab"
                                    ]
                                }
                            }
                        ]
                    }
                }
            ]
        }
    },
    "aggregation": {
        "by_process": {
            "terms": {
                "field": "process.name.keyword",
                "size": 50
            },
            "aggs": {
                "file_count": {
                    "value_count": {
                        "field": "file.path.keyword"
                    }
                },
                "affected_hosts": {
                    "terms": {
                        "field": "host.name.keyword"
                    }
                }
            }
        }
    },
    "threshold": {
        "file_count": 50,  # Alert if 50+ files encrypted
        "time_window": "5m"
    },
    "time_range": "1h"
}

MASS_FILE_COMPRESSION = {
    "query_name": "Mass File Compression/Archiving",
    "description": "Detects mass file compression activity, potential data staging for exfiltration",
    "mitre_attack": ["T1560.001"],
    "severity": "high",
    "query": {
        "bool": {
            "must": [
                {
                    "match": {
                        "event.code": "1"  # Process creation
                    }
                },
                {
                    "bool": {
                        "should": [
                            # Archive tools
                            {
                                "terms": {
                                    "process.name": [
                                        "7z.exe",
                                        "7za.exe",
                                        "winrar.exe",
                                        "rar.exe",
                                        "winzip.exe"
                                    ]
                                }
                            },
                            # PowerShell compression
                            {
                                "wildcard": {
                                    "process.command_line": "*Compress-Archive*"
                                }
                            },
                            # Tar/gzip
                            {
                                "wildcard": {
                                    "process.command_line": "*tar*czf*"
                                }
                            }
                        ]
                    }
                },
                # Targeting sensitive directories
                {
                    "bool": {
                        "should": [
                            {
                                "wildcard": {
                                    "process.command_line": "*\\Users\\*"
                                }
                            },
                            {
                                "wildcard": {
                                    "process.command_line": "*\\Documents*"
                                }
                            },
                            {
                                "wildcard": {
                                    "process.command_line": "*\\Desktop*"
                                }
                            },
                            {
                                "wildcard": {
                                    "process.command_line": "*C:\\*"
                                }
                            }
                        ]
                    }
                }
            ]
        }
    },
    "aggregation": {
        "by_user": {
            "terms": {
                "field": "user.name.keyword",
                "size": 50
            },
            "aggs": {
                "hosts": {
                    "terms": {
                        "field": "host.name.keyword"
                    }
                },
                "archive_count": {
                    "value_count": {
                        "field": "event.id"
                    }
                }
            }
        }
    },
    "time_range": "4h"
}

LARGE_FILE_UPLOAD = {
    "query_name": "Large Data Upload Detection",
    "description": "Detects large data transfers to external destinations, potential data exfiltration",
    "mitre_attack": ["T1048.003"],
    "severity": "high",
    "query": {
        "bool": {
            "must": [
                {
                    "terms": {
                        "network.direction": ["outbound", "egress"]
                    }
                },
                {
                    "range": {
                        "network.bytes": {
                            "gte": 104857600  # 100 MB
                        }
                    }
                }
            ],
            "should": [
                # Cloud storage services
                {
                    "wildcard": {
                        "destination.domain": "*dropbox.com*"
                    }
                },
                {
                    "wildcard": {
                        "destination.domain": "*box.com*"
                    }
                },
                {
                    "wildcard": {
                        "destination.domain": "*mega.nz*"
                    }
                },
                {
                    "wildcard": {
                        "destination.domain": "*drive.google.com*"
                    }
                },
                # File sharing
                {
                    "wildcard": {
                        "destination.domain": "*wetransfer.com*"
                    }
                },
                {
                    "wildcard": {
                        "destination.domain": "*sendspace.com*"
                    }
                }
            ]
        }
    },
    "aggregation": {
        "by_source": {
            "terms": {
                "field": "source.ip",
                "size": 50
            },
            "aggs": {
                "total_bytes": {
                    "sum": {
                        "field": "network.bytes"
                    }
                },
                "destinations": {
                    "terms": {
                        "field": "destination.domain.keyword",
                        "size": 20
                    }
                }
            }
        }
    },
    "time_range": "24h"
}

# ============================================================================
# BACKUP & SHADOW COPY TAMPERING DETECTIONS
# ============================================================================

VSS_DELETION = {
    "query_name": "Volume Shadow Copy Deletion",
    "description": "Detects deletion of Volume Shadow Copies, common ransomware behavior",
    "mitre_attack": ["T1490"],
    "severity": "critical",
    "query": {
        "bool": {
            "must": [
                {
                    "match": {
                        "event.code": "1"
                    }
                }
            ],
            "should": [
                # vssadmin delete
                {
                    "wildcard": {
                        "process.command_line": "*vssadmin*delete*shadows*"
                    }
                },
                {
                    "wildcard": {
                        "process.command_line": "*vssadmin.exe*Delete*Shadows*/All*"
                    }
                },
                # wmic delete
                {
                    "wildcard": {
                        "process.command_line": "*wmic*shadowcopy*delete*"
                    }
                },
                # PowerShell deletion
                {
                    "wildcard": {
                        "process.command_line": "*Get-WmiObject*Win32_Shadowcopy*Delete*"
                    }
                },
                {
                    "wildcard": {
                        "process.command_line": "*gwmi*Win32_Shadowcopy*Delete*"
                    }
                }
            ],
            "minimum_should_match": 1
        }
    },
    "aggregation": {
        "by_host": {
            "terms": {
                "field": "host.name.keyword",
                "size": 50
            },
            "aggs": {
                "users": {
                    "terms": {
                        "field": "user.name.keyword"
                    }
                }
            }
        }
    },
    "time_range": "24h"
}

BACKUP_DELETION = {
    "query_name": "Backup Catalog Deletion",
    "description": "Detects deletion or modification of backup catalogs and configurations",
    "mitre_attack": ["T1490"],
    "severity": "critical",
    "query": {
        "bool": {
            "must": [
                {
                    "match": {
                        "event.code": "1"
                    }
                }
            ],
            "should": [
                # wbadmin delete catalog
                {
                    "wildcard": {
                        "process.command_line": "*wbadmin*delete*catalog*"
                    }
                },
                {
                    "wildcard": {
                        "process.command_line": "*wbadmin*delete*backup*"
                    }
                },
                # bcdedit modifications (disabling recovery)
                {
                    "wildcard": {
                        "process.command_line": "*bcdedit*/set*recoveryenabled*No*"
                    }
                },
                {
                    "wildcard": {
                        "process.command_line": "*bcdedit*/set*bootstatuspolicy*ignoreallfailures*"
                    }
                }
            ],
            "minimum_should_match": 1
        }
    },
    "aggregation": {
        "by_host": {
            "terms": {
                "field": "host.name.keyword",
                "size": 50
            }
        }
    },
    "time_range": "24h"
}

WINDOWS_BACKUP_MODIFICATION = {
    "query_name": "Windows Backup Service Tampering",
    "description": "Detects attempts to disable or modify Windows Backup service",
    "mitre_attack": ["T1490"],
    "severity": "high",
    "query": {
        "bool": {
            "should": [
                # Service stopped
                {
                    "bool": {
                        "must": [
                            {
                                "match": {
                                    "event.code": "7036"
                                }
                            },
                            {
                                "terms": {
                                    "winlog.event_data.param1": [
                                        "Windows Backup",
                                        "wbengine",
                                        "SDRSVC"
                                    ]
                                }
                            },
                            {
                                "match": {
                                    "winlog.event_data.param2": "stopped"
                                }
                            }
                        ]
                    }
                },
                # Service disabled
                {
                    "bool": {
                        "must": [
                            {
                                "match": {
                                    "event.code": "7040"
                                }
                            },
                            {
                                "terms": {
                                    "winlog.event_data.param1": [
                                        "Windows Backup",
                                        "wbengine",
                                        "SDRSVC"
                                    ]
                                }
                            },
                            {
                                "match": {
                                    "winlog.event_data.param3": "disabled"
                                }
                            }
                        ]
                    }
                },
                # Registry modification
                {
                    "bool": {
                        "must": [
                            {
                                "match": {
                                    "event.code": "13"
                                }
                            },
                            {
                                "wildcard": {
                                    "winlog.event_data.TargetObject": "*\\Services\\wbengine\\Start*"
                                }
                            }
                        ]
                    }
                }
            ]
        }
    },
    "aggregation": {
        "by_host": {
            "terms": {
                "field": "host.name.keyword",
                "size": 50
            }
        }
    },
    "time_range": "24h"
}

# ============================================================================
# QUERY REGISTRY
# ============================================================================

THREAT_HUNTING_QUERIES = {
    # Office 365 Email Compromise
    "o365_new_inbox_rule": OFFICE365_NEW_INBOX_RULE,
    "o365_external_forwarding": OFFICE365_EXTERNAL_FORWARDING,

    # Authentication Attacks
    "brute_force_attack": BRUTE_FORCE_ATTACK,
    "password_spray_attack": PASSWORD_SPRAY_ATTACK,

    # Credential Theft
    "credential_dumping_lsass": CREDENTIAL_DUMPING_LSASS,
    "mimikatz_usage": MIMIKATZ_USAGE,
    "sam_database_extraction": SAM_DATABASE_EXTRACTION,

    # Lateral Movement
    "psexec_lateral_movement": PSEXEC_LATERAL_MOVEMENT,
    "wmiexec_lateral_movement": WMIEXEC_LATERAL_MOVEMENT,
    "rdp_lateral_movement": RDP_LATERAL_MOVEMENT,

    # Privilege Escalation
    "privilege_escalation_tokens": PRIVILEGE_ESCALATION_TOKENS,
    "uac_bypass": UAC_BYPASS,
    "scheduled_task_privesc": SCHEDULED_TASK_PRIVESC,

    # Persistence
    "new_service_creation": NEW_SERVICE_CREATION,
    "scheduled_task_creation": SCHEDULED_TASK_CREATION,
    "registry_run_keys": REGISTRY_RUN_KEYS,

    # Data Exfiltration
    "mass_file_encryption": MASS_FILE_ENCRYPTION,
    "mass_file_compression": MASS_FILE_COMPRESSION,
    "large_file_upload": LARGE_FILE_UPLOAD,

    # Backup Tampering
    "vss_deletion": VSS_DELETION,
    "backup_deletion": BACKUP_DELETION,
    "windows_backup_modification": WINDOWS_BACKUP_MODIFICATION
}

# Query categories for UI organization
QUERY_CATEGORIES = {
    "Email Compromise": [
        "o365_new_inbox_rule",
        "o365_external_forwarding"
    ],
    "Authentication Attacks": [
        "brute_force_attack",
        "password_spray_attack"
    ],
    "Credential Theft": [
        "credential_dumping_lsass",
        "mimikatz_usage",
        "sam_database_extraction"
    ],
    "Lateral Movement": [
        "psexec_lateral_movement",
        "wmiexec_lateral_movement",
        "rdp_lateral_movement"
    ],
    "Privilege Escalation": [
        "privilege_escalation_tokens",
        "uac_bypass",
        "scheduled_task_privesc"
    ],
    "Persistence": [
        "new_service_creation",
        "scheduled_task_creation",
        "registry_run_keys"
    ],
    "Data Exfiltration": [
        "mass_file_encryption",
        "mass_file_compression",
        "large_file_upload"
    ],
    "Backup Tampering": [
        "vss_deletion",
        "backup_deletion",
        "windows_backup_modification"
    ]
}


def get_query(query_id):
    """
    Retrieve a specific threat hunting query by ID

    Args:
        query_id (str): The query identifier

    Returns:
        dict: The query configuration or None if not found
    """
    return THREAT_HUNTING_QUERIES.get(query_id)


def get_queries_by_category(category):
    """
    Retrieve all queries in a specific category

    Args:
        category (str): The category name

    Returns:
        list: List of query configurations
    """
    query_ids = QUERY_CATEGORIES.get(category, [])
    return [THREAT_HUNTING_QUERIES[qid] for qid in query_ids if qid in THREAT_HUNTING_QUERIES]


def get_all_queries():
    """
    Retrieve all threat hunting queries

    Returns:
        dict: All queries indexed by ID
    """
    return THREAT_HUNTING_QUERIES


def get_categories():
    """
    Retrieve all query categories

    Returns:
        list: List of category names
    """
    return list(QUERY_CATEGORIES.keys())
