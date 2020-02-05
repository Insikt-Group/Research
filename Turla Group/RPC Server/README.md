# RPC Server Backdoor Powershell Commands

Insikt Group created a PowerShell script that can be run in an organization’s environment to detect Turla's RPC Server Backdoors.

* TurlaRPCServer.ps1

The script attempts to connect to the named pipes, "\\.\pipe\pnrsvc" or "\\.\pipe\atctl". If the connection succeeds, this indicates with high confidence that the host is running the RPC server backdoor. Additional network analysis is then required to examine the connections to the host and identify the RPC client.

To use, modify the "$computer_name = \<computername\>" and "$username = <username>" variables to include the computer you are scanning and the username for the connection.
  
The commands utilizes the “Invoke-Command” enabling the script to be remotely run against a single or list of hosts within your LAN. The command must be run as a domain account.
