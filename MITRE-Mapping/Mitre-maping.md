# MITRE ATT&CK Mapping

| Detection | Event ID | MITRE Technique | ATT&CK ID |
|-----------|----------|-----------------|-----------|
| Failed Logins | 4625 | Brute Force | T1110 |
| Account Lockout | 4740 | Brute Force | T1110 |
| New User Created | 4720 | Create Account | T1136 |
| Deleted User | 4726 | Create Account | T1136 |
| User Added to Administrator Group | 4732 | Account Manipulation | T1098 |
| Service Installation | 4697 | Create or Modify System Process | T1543 |
| RDP Login | 4624 (Type 10) | Remote Services | T1021.001 |
| Suspicious PowerShell | Sysmon Event ID 1 | PowerShell | T1059.001 |
| Encoded PowerShell | Sysmon Event ID 1 | PowerShell | T1059.001 |
| LOLBins Execution | Sysmon Event ID 1 | Signed Binary Proxy Execution | T1218 |
