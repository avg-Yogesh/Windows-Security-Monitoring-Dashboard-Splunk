# Windows Security Monitoring Dashboard Coverage

The dashboard contains **21 security monitoring panels** covering Windows Security Events and Sysmon detections.

### Authentication Monitoring
- Total Authentication Attempts
- Successful Logins
- Failed Logins
- Success vs Failed Logins
- Authentication Activity Trend
- Top Failed User Accounts
- Top Source IP Addresses (Failed Logins)
- Logon Type Analysis

### Account Management
- New User Accounts Created
- Deleted User Accounts
- User Added to Administrator Group
- Account Lockouts
- Locked-out Users

### Privilege Monitoring
- Privileged Logons

### Endpoint & Process Monitoring
- Top Executed Processes
- Suspicious LOLBins Execution
- Suspicious PowerShell Execution
- Encoded PowerShell Detection
- New Service Installation

### Threat Detection
- Potential Brute Force Detection
- Multiple Users Targeted from Same Source IP

# Lab Environment

| Component | Technology Used |
|-----------|-----------------|
| SIEM | Splunk Enterprise 10.x |
| Log Collection | Splunk Universal Forwarder |
| Endpoint | Windows 10 |
| Attacker Machine | Kali Linux |
| Additional Logging | Sysmon |
| Virtualization | Oracle VirtualBox |
| Operating System (SIEM) | Ubuntu Linux |

---

## Network Topology

```

                Kali Linux
             (Attack Machine)
                      │
                      │
        Brute Force / SMB / RDP / PowerShell
                      │
                      ▼
             Windows 10 Target
      Windows Security Logs + Sysmon
                      │
          Splunk Universal Forwarder
                      │
                  TCP Port 9997
                      │
                      ▼
          Ubuntu - Splunk Enterprise
                      │
                      ▼
      Windows Security Monitoring Dashboard

```
