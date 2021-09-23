# KRYPTON Client
Use this client to interact with a KRYPTON webshell.

KRYPTON Commands Supported:
1. Put (Upload a file)
2. Update (Upload webshell)
3. Time (Copy time form file on filesystem)
4. Cmd (Execute a Windows Command)
5. Del (Delete a file)
6. Get (Get a file)

Run the script with the --url argument to supply the location of the KRYPTON webshell

<code>python3 KRYPTON_Client.py --url http://192.168.204[.]188/krypton.aspx</code>

KRYPTON commands are encrypted, by default the below key and IV are used. You can supply different key and iv by using the --key and --iv arguments.

1. Key: "J8fs4F4rnP7nFl#f"
2. IV: "D68gq#5p0(3Ndsk!"