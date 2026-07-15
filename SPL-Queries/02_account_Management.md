# New User Created

## Purpose

Displays all newly created user accounts observed in Windows Security Logs.

### Windows Event IDs

- **4720** (New User Created)

### SPL Query

```
index=main source="WinEventLog:Security" EventCode=4720
| eval Severity="High"
| table _time host New_Account_Account_Name Account_Name Severity
| rename New_Account_Account_Name as "New User", Account_Name as "Created By"
| sort - _time
```

## Detection Logic

Monitors **Windows Security Event ID 4720** to detect whenever a new user account is created. Displays the created account, the user who created it, the affected host, and the event timestamp.

## MITRE ATT&CK

- **T1136 – Create Account**



 # Deleted User

## Purpose

Displays all deleted user accounts observed in Windows Security Logs.

### Windows Event IDs

- **4726** (User Account Deleted)

### SPL Query

```
index=main source="WinEventLog:Security" EventCode=4726
| table _time host Account_Name Target_Account_Name
| rename Target_Account_Name as "Deleted User", Account_Name as "Deleted By"
| sort - _time

```

## Detection Logic

Monitors **Windows Security Event ID 4726** to detect whenever a user account is deleted. Displays the deleted account, the user who performed the deletion, the affected host, and the event timestamp.


# User Added to Administrator Group

## Purpose

Displays all users added to the local **Administrators** group observed in Windows Security Logs.

### Windows Event IDs

- **4732** (A member was added to a security-enabled local group)

### SPL Query

```
index=main source="WinEventLog:Security" (EventCode=4732 OR EventCode=4720)
| eval Severity="Critical"
| table _time host New_Account_Account_Name Group_Name Account_Name Severity
| rename New_Account_Account_Name as "ADDED USER", Account_Name as "ADDED BY"
| sort -_time
```

## Detection Logic

Monitors **Windows Security Event ID 4732** to detect whenever a user is added to the local **Administrators** group. Displays the added user, the account that performed the action, the affected host, and the event timestamp.

## MITRE ATT&CK

- **T1098 – Account Manipulation**


# Privilege Assigned User

## Purpose

Displays all privileged logons observed in Windows Security Logs.

### Windows Event IDs

- **4672** (Special Privileges Assigned to New Logon)

### SPL Query

```
index=* host="window10-Target" source="WinEventLog:Security" EventCode=4672
| table _time ComputerName Account_Name privilege
```

## Detection Logic

Monitors **Windows Security Event ID 4672** to detect when a user logs on with special administrative privileges. Displays the user account, assigned privileges, affected host, and the event timestamp.

## MITRE ATT&CK

- **T1078 – Valid Accounts**
