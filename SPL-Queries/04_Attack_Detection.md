# Potential Brute Force Detection

## Purpose

Detects potential brute-force attacks by identifying multiple failed login attempts against the same user account.

### Windows Event IDs

- **4625** (Failed Logon)

### SPL Query

```spl
index=* host="window10-Target" source="WinEventLog:Security" EventCode=4625
| bucket _time span=5m | stats count as FailedAttempts values(src_ip) as SourceIP by _time Account_Name
| where FailedAttempts>=5
| sort - FailedAttempts
```

## Detection Logic

Identifies user accounts with multiple failed login attempts within the collected Windows Security Logs, helping detect potential brute-force attacks.

## MITRE ATT&CK

- **T1110 – Brute Force**

---

# Multiple Users Targeted By Same IP

## Purpose

Detects source IP addresses attempting to authenticate against multiple user accounts, which may indicate password spraying or credential attacks.

### Windows Event IDs

- **4625** (Failed Logon)

### SPL Query

```spl
index=main EventCode=4625
| stats dc(Account_Name) as UniqueUsers values(Account_Name) as TargetedUsers count as FailedAttempts by src_ip
| where UniqueUsers > 1
| sort - FailedAttempts
```

## Detection Logic

Identifies source IP addresses that generate failed login attempts against multiple user accounts, helping detect password spraying and other credential-based attacks.

## MITRE ATT&CK

- **T1110.003 – Password Spraying**
