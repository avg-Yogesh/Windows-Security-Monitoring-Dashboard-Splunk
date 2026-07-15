# Total Authentication Attempts

## Purpose

Displays the total number of authentication attempts observed in Windows Security Logs.

### Windows Event IDs

- **4624** (Successful Logon)
- **4625** (Failed Logon)

### SPL Query

```spl
host="window10-Target" source="WinEventLog:Security" (EventCode=4624 OR EventCode=4625)
| stats count as "Authentication Attempts"
```

## Detection Logic

Counts all successful and failed authentication attempts to provide an overview of authentication activity.

## MITRE ATT&CK

- **T1078 – Valid Accounts**
