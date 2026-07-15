# Total Authentication Attempts

## Purpose

Displays the total number of authentication attempts observed in Windows Security Logs.

## Windows Event IDs

- 4624 (Successful Logon)
- 4625 (Failed Logon)

## SPL Query
host="window10-Target" source="WinEventLog:Security" (EventCode=4625 OR EventCode=4624) | stats count as "Authentication Attempts"

## Detection Logic

Counts all successful and failed authentication attempts to provide an overview of authentication activity.

## Use Case

SOC analysts can quickly determine the authentication volume and identify spikes that may indicate suspicious activity.
