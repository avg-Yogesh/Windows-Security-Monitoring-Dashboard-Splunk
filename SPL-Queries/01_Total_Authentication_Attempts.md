# Total Authentication Attempts

#### Purpose

Displays the total number of authentication attempts observed in Windows Security Logs.

### SPL Query
host="window10-Target" source="WinEventLog:Security" (EventCode=4625 OR EventCode=4624) | stats count as "Authentication Attempts"


# Failed Logins

### Purpose

Displays all the Failed logins attempts observed in Windows Security Logs.

### SPL Query
host="window10-Target" source="WinEventLog:Security" EventCode=4625 | stats count as "Failed Logins"


# Successful Logins

### Purpose

Displays the total number of Successful logins attempts observed in Windows Security Logs.

### SPL Query
host="window10-Target" source="WinEventLog:Security" EventCode=4624 | stats count as "Successful Logins"


# Accounts Lockout

### Purpose

Displays all the Accounts lockout observed in Windows Security Logs.


### SPL Query
host="window10-Target" source="WinEventLog:Security" EventCode=4740 | stats count as "Account Lockouts"

# Authentication Activity Trend

### Purpose

Displays the activity trend of authentication observed in Windows Security Logs.

### SPL Query
index=* host="window10-Target" source="WinEventLog:Security" (EventCode=4625 OR EventCode=4624) | eval AuthenticationStatus=case(EventCode=4624,"Successful",EventCode=4625,"Failed") | timechart span=5m count by AuthenticationStatus


# Success vs Failed Pie chart

### Purpose

Displays the pie chart of success vs failed attempts in Windows Security Logs.

### SPL Query
host="window10-Target" source="WinEventLog:Security" (EventCode=4624 OR EventCode=4625) | eval Status = if(EventCode=4624,"Success Logins","Failed Attempts") | stats count by Status


# Top Failed User Account

### Purpose

Displays the Top user account in Windows Security Logs.

### SPL Query
index=* host="window10-Target" source="WinEventLog:Security" EventCode=4625 Source_Network_Address!="-" |search Account_Name!="ANONYMOUS LOGON" | stats count as "Failed Attempts" by Account_Name | sort -"Failed Attempts" | head 10


# Top Source IP Address

### Purpose

Displays the top source ip address observed in Windows Security Logs.

### SPL Query
index=* host="window10-Target" source="WinEventLog:Security" EventCode=4625 Source_Network_Address!="-" |stats count as "Failed Attempts" by Source_Network_Address | sort -"Failed Attempts" | head 10


# Locked-Out Users

### Purpose

Displays all the locked out user in Windows Security Logs.

### SPL Query
host="window10-Target" source="WinEventLog:Security" EventCode=4740 | table _time ComputerName Account_Locked_Out_Name CallerComputerName


# Logon Types

### Purpose

Displays the logon types observed in Windows Security Logs.

### SPL Query
index=* host="window10-Target" source="WinEventLog:Security" EventCode=4624 | stats count by _time Logon_Type Account_Name | sort -count
