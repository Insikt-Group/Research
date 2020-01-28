# RPC Server Backdoor Powershell Script(s)

Insikt Group created a PowerShell script that can be run on endpoint systems in an organization’s network to detect Turla's RPC Server Backdoors.

There are two PowerShell Scripts inlcuded. 

The scripts attempt to connect to the named pipes, "\\.\pipe\pnrsvc" or "\\.\pipe\atctl". If the connection succeeds, this indicates with high confidence that the host is running the RPC server backdoor. Additional network analysis is then required to examine the connections to the host and identify the RPC client.

The scripts utilizes the “Invoke-Command” enabling the script to be remotely run against a single or list of hosts within your LAN. The script must be run as a domain account and not a local.
