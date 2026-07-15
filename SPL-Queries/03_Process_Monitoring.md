# Top Executed Process

## Purpose

Displays the most frequently executed processes observed in Sysmon logs.

### Windows Event IDs

- **Sysmon Event ID 1** (Process Creation)

### SPL Query

```spl
index=main EventCode=1
| rex field=Image "(?<ProcessName>[^\\\]+)$$"
| stats count by ProcessName
| sort - count
| head 10
```

## Detection Logic

Monitors Sysmon Process Creation events to identify the most frequently executed processes on the system.

---

# Suspicious LOLBins

## Purpose

Detects execution of commonly abused Living Off the Land Binaries (LOLBins) observed in Sysmon logs.

### Windows Event IDs

- **Sysmon Event ID 1** (Process Creation)

### SPL Query

```spl
index=main EventCode=1
| rex field=Image "(?<ProcessName>[^\\\\]+$$)"
| search ProcessName IN("powershell.exe", "cmd.exe" "wmic.exe","rundll32.exe","regsvr32.exe","certutil.exe","mshta.exe","bitsadmin.exe","net.exe","net1.exe")
| table _time host User ProcessName ParentImage CommandLine
| sort -_time
```

## Detection Logic

Monitors execution of commonly abused Windows LOLBins that attackers frequently use for execution, defense evasion, and persistence.

## MITRE ATT&CK

- **T1218 – System Binary Proxy Execution**

---

# Suspicious PowerShell

## Purpose

Detects suspicious PowerShell execution observed in Sysmon logs.

### Windows Event IDs

- **Sysmon Event ID 1** (Process Creation)

### SPL Query

```spl
index=main EventCode=1 Image="*powershell.exe" | table _time Computer User Image CommandLine ParentImage | sort -_time
```

## Detection Logic

Monitors PowerShell executions using suspicious command-line arguments commonly associated with attacker activity.

## MITRE ATT&CK

- **T1059.001 – PowerShell**

---

# Encoded PowerShell

## Purpose

Detects PowerShell commands executed with Base64-encoded command-line arguments.

### Windows Event IDs

- **Sysmon Event ID 1** (Process Creation)

### SPL Query

```spl
index=main EventCode=1 Image="*powershell.exe"
| search CommandLine="*-ence*" OR CommandLine="*-EncodedCommands*" OR CommandLine="*-e*"
| table _time host User CommandLine ParentImage
| sort -_time
```

## Detection Logic

Monitors PowerShell executions containing encoded commands, a common technique used to obfuscate malicious scripts and evade detection.

## MITRE ATT&CK

- **T1059.001 – PowerShell**
- **T1027 – Obfuscated Files or Information**
