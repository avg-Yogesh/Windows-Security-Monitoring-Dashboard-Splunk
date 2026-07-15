# New Service Installation

## Purpose

Detects newly installed Windows services observed in Windows Security Logs.

### Windows Event IDs

- **4697** (A Service Was Installed in the System)

### SPL Query

```spl
index=main (EventCode=4697 OR EventCode=7045)
| eval Severity="High"
| table _time host EventCode Service_Name Service_file_Name Service_Account Severity 
| sort -_time
```

## Detection Logic

Monitors **Windows Security Event ID 4697** to detect whenever a new Windows service is installed. Displays the service name, service path, account responsible for the installation, affected host, and event timestamp.

## MITRE ATT&CK

- **T1543.003 – Windows Service**
