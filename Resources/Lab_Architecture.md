# Lab Environment

| Component | Technology Used |
|-----------|-----------------|
| SIEM | Splunk Enterprise 10.4.0|
| Log Collection | Splunk Universal Forwarder |
| Endpoint | Windows 10 Home |
| Attacker Machine | Kali Linux |
| Additional Logging | Sysmon |
| Virtualization | Oracle VirtualBox |
| Operating System (SIEM) | Ubuntu Linux |

---

## ARCHITECTURE

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
