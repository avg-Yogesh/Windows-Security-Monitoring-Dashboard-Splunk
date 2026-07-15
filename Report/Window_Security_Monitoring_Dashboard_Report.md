# Windows Security Monitoring Dashboard Report

## Project Information

**Project Name:** Windows Security Monitoring Dashboard using Splunk

**Project Type:** SOC Analyst Home Lab Project

**Name:** Yogesh

---

# Project Overview

The Windows Security Monitoring Dashboard is a Security Operations Center (SOC) home lab project developed using Splunk Enterprise. The dashboard collects Windows Security Logs and Sysmon logs from a Windows 10 endpoint through Splunk Universal Forwarder and provides real-time visibility into authentication events, privilege changes, PowerShell activity, account management events, and suspicious process execution.
The project focuses on detecting common Windows security events that SOC analysts investigate during incident response and threat hunting. It demonstrates practical experience with SIEM deployment, Windows event log analysis, SPL query development, and dashboard creation.

---

# Objectives

* Monitor Windows authentication events
* Detect failed and successful logins
* Detect account lockouts
* Detect privilege escalation
* Monitor PowerShell activity
* Detect Encoded PowerShell execution
* Detect LOLBins execution
* Detect new user account creation
* Detect deleted user accounts
* Detect administrator group modifications
* Detect suspicious Windows service installations
* Detect brute-force attack attempts
* Visualize security events using Splunk dashboards

---

# Home Lab Architecture

```
                Kali Linux
                     |
             Attack Simulation
                     |
             Windows 10 Home Target
          (Sysmon + Security Logs)
                     |
        Splunk Universal Forwarder
                     |
             Splunk Enterprise
                     |
      Windows Security Monitoring Dashboard
```

---

# Lab Environment

| Component           | Details                    |
| ------------------- | -------------------------- |
| Operating System    | Ubuntu                     |
| Target Machine      | Windows 10                 |
| Attacker Machine    | Kali Linux                 |
| SIEM Platform       | Splunk Enterprise 10.4.0         |
| Log Forwarder       | Splunk Universal Forwarder |
| Endpoint Monitoring | Sysmon                     |
| Virtualization      | VirtualBox                 |

---

# Data Sources

The dashboard collects logs from multiple Windows event sources.

### Windows Security Logs

* Event ID 4624 – Successful Logon
* Event ID 4625 – Failed Logon
* Event ID 4672 – Special Privileges Assigned
* Event ID 4688 – Process Creation
* Event ID 4697 – Service Installation
* Event ID 4720 – User Account Created
* Event ID 4726 – User Account Deleted
* Event ID 4732 – User Added to Local Administrator Group
* Event ID 4740 – Account Locked Out

### Sysmon Logs

* Process Creation
* Command Line Activity
* PowerShell Execution
* LOLBins Execution

---

# Dashboard Features

The dashboard contains 21 security monitoring panels.

1. Total Authentication Attempts
2. Successful Logins
3. Failed Logins
4. Account Lockouts
5. Locked-Out User
6. Privilege Assigned User
7. Authentication Activity Trend
8. Top Failed User Account
9. Top Source IP Address (Failed Logins)
10. Logon Type Logins
11. Potential Brute Force Detection
12. Suspicious PowerShell Execution
13. Encoded PowerShell Detection
14. Top Executed Process
15. Multiple Users Targeted By Same IP
16. Suspicious LOLBins Execution
17. New User Accounts Created
18. User Added To Administrator Group
19. New Services Installation
20. Deleted User Detection
21. Success vs Failed Logins

---

# Attack Simulation

The following attack scenarios were performed in the home lab to generate Windows Security Events.

* Failed Login Attempts
* Successful Login
* SMB Authentication Testing
* Brute Force Simulation
* New User Creation
* User Deletion
* Administrator Group Membership Modification
* Windows Service Installation
* PowerShell Execution
* Encoded PowerShell Execution
* LOLBins Execution
* Process Creation Events

---

# Detection Logic

Each dashboard panel uses SPL (Search Processing Language) to identify specific Windows Security events.

Examples include:

* Authentication Monitoring
* Account Management Detection
* Privilege Escalation Detection
* Process Monitoring
* PowerShell Monitoring
* LOLBins Detection
* Brute Force Detection

---

# MITRE ATT&CK Mapping

| Technique                         | ATT&CK ID |
| --------------------------------- | --------- |
| Brute Force                       | T1110     |
| Valid Accounts                    | T1078     |
| PowerShell                        | T1059.001 |
| Command and Scripting Interpreter | T1059     |
| Create Account                    | T1136     |
| Account Discovery                 | T1087     |
| Process Execution                 | T1059     |
| Windows Service                   | T1543     |

---

# Skills Demonstrated

* Splunk Enterprise
* SPL (Search Processing Language)
* Windows Event Log Analysis
* Sysmon Log Analysis
* Threat Detection
* Security Monitoring
* SIEM Dashboard Development
* Windows Security
* MITRE ATT&CK Framework
* SOC Operations
* Log Analysis
* Incident Investigation

---

# Challenges Faced

During the project several technical issues were encountered, including:

* Windows Security Logs not forwarding
* Universal Forwarder connectivity issues
* Splunk indexing verification
* Event generation and testing
* Dashboard optimization
* SPL query tuning
  

These issues were identified and resolved through troubleshooting, configuration validation, and log verification.

---

# Project Outcome

The completed dashboard provides centralized visibility into Windows Security events and enables rapid detection of suspicious activities such as authentication attacks, privilege escalation, account management changes, PowerShell abuse, and malicious process execution.

This project demonstrates practical SOC Analyst skills including log collection, SIEM configuration, SPL query development, dashboard creation, attack simulation, and Windows security monitoring.

---

# Future Improvements

Future enhancements may include:

* Risk-Based Alerting
* Splunk Enterprise Security Integration
* Sysmon Rule Optimization
* Sigma Rule Integration
* Automated Incident Response
* Threat Intelligence Integration

---

# Conclusion

This Windows Security Monitoring Dashboard successfully demonstrates a real-world SOC Analyst use case by collecting, analyzing, and visualizing Windows Security Logs and Sysmon events within Splunk Enterprise.

The project highlights practical experience in security monitoring, attack detection, log analysis, dashboard development, and incident investigation. It serves as a strong portfolio project for entry-level SOC Analyst, Cybersecurity Analyst, and Blue Team roles while showcasing hands-on experience with enterprise SIEM technologies.
