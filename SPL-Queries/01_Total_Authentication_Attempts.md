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


# Failed Logins

## Purpose

Displays the total number of failed login attempts observed in Windows Security Logs.

### Windows Event IDs

- **4625** (Failed Logon)

### SPL Query

```spl
host="window10-Target" source="WinEventLog:Security" EventCode=4625
| stats count as "Failed Logins"
```

## Detection Logic

Counts all failed authentication attempts to help identify brute-force attacks, password spraying, or invalid login attempts.

## MITRE ATT&CK

- **T1110 – Brute Force**


# Successful Logins

## Purpose

Displays the total number of successful logins observed in Windows Security Logs.

### Windows Event IDs

- **4624** (Successful Logon)

### SPL Query

```spl
host="window10-Target" source="WinEventLog:Security" EventCode=4624
| stats count as "Successful Logins"
```

## Detection Logic

Counts all successful authentication events to provide visibility into user login activity.

## MITRE ATT&CK

- **T1078 – Valid Accounts**



# Account Lockouts

## Purpose

Displays the total number of account lockout events observed in Windows Security Logs.

### Windows Event IDs

- **4740** (A User Account Was Locked Out)

### SPL Query

```spl
host="window10-Target" source="WinEventLog:Security" EventCode=4740
| stats count as "Account Lockouts"
```

## Detection Logic

Monitors account lockout events to identify repeated failed login attempts that may indicate brute-force attacks.

## MITRE ATT&CK

- **T1110 – Brute Force**


# Authentication Activity Trend

## Purpose

Displays the authentication activity trend observed in Windows Security Logs.

### Windows Event IDs

- **4624** (Successful Logon)
- **4625** (Failed Logon)

### SPL Query

```spl
index=* host="window10-Target" source="WinEventLog:Security" (EventCode=4624 OR EventCode=4625)
| eval AuthenticationStatus=case(EventCode=4624,"Successful",EventCode=4625,"Failed")
| timechart span=5m count by AuthenticationStatus
```

## Detection Logic

Visualizes successful and failed authentication events over time to identify unusual login patterns or spikes.

## MITRE ATT&CK

- **T1078 – Valid Accounts**
- **T1110 – Brute Force**


# Success vs Failed Pie Chart

## Purpose

Displays the distribution of successful and failed login attempts observed in Windows Security Logs.

### Windows Event IDs

- **4624** (Successful Logon)
- **4625** (Failed Logon)

### SPL Query

```spl
host="window10-Target" source="WinEventLog:Security" (EventCode=4624 OR EventCode=4625)
| eval Status=if(EventCode=4624,"Successful Logins","Failed Logins")
| stats count by Status
```

## Detection Logic

Compares successful and failed authentication events to provide a quick overview of login activity.

## MITRE ATT&CK

- **T1078 – Valid Accounts**
- **T1110 – Brute Force**


# Top Failed User Accounts

## Purpose

Displays the user accounts with the highest number of failed login attempts.

### Windows Event IDs

- **4625** (Failed Logon)

### SPL Query

```spl
index=* host="window10-Target" source="WinEventLog:Security" EventCode=4625 Source_Network_Address!="-"
| search Account_Name!="ANONYMOUS LOGON"
| stats count as "Failed Attempts" by Account_Name
| sort -"Failed Attempts"
| head 10
```

## Detection Logic

Identifies user accounts with the highest number of failed login attempts to help detect brute-force or password spraying attacks.

## MITRE ATT&CK

- **T1110 – Brute Force**


# Top Source IP Address

## Purpose

Displays the source IP addresses responsible for the highest number of failed login attempts.

### Windows Event IDs

- **4625** (Failed Logon)

### SPL Query

```spl
index=* host="window10-Target" source="WinEventLog:Security" EventCode=4625 Source_Network_Address!="-"
| stats count as "Failed Attempts" by Source_Network_Address
| sort -"Failed Attempts"
| head 10
```

## Detection Logic

Identifies source IP addresses generating failed login attempts to help detect external attack sources.

## MITRE ATT&CK

- **T1110 – Brute Force**


# Locked-Out Users

## Purpose

Displays all locked-out user accounts observed in Windows Security Logs.

### Windows Event IDs

- **4740** (A User Account Was Locked Out)

### SPL Query

```spl
host="window10-Target" source="WinEventLog:Security" EventCode=4740
| table _time ComputerName Account_Locked_Out_Name CallerComputerName
```

## Detection Logic

Displays user accounts that have been locked out along with the source computer responsible for the lockout event.

## MITRE ATT&CK

- **T1110 – Brute Force**


# Logon Types

## Purpose

Displays the different Windows logon types observed in successful authentication events.

### Windows Event IDs

- **4624** (Successful Logon)

### SPL Query

```spl
index=* host="window10-Target" source="WinEventLog:Security" EventCode=4624
| stats count by Logon_Type Account_Name
| sort -count
```

## Detection Logic

Categorizes successful logon events by logon type to provide visibility into how users are authenticating to the system.

## MITRE ATT&CK

- **T1078 – Valid Accounts**
