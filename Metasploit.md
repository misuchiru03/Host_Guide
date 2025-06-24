# Metasploit   
---

## <u> General Information </u>  
| Syntax | Description | Example |  
|---|---|---|  
|| Metasploit is a free tool that has built in exploits which aids in gaining remote access to a system by exokiutubg a vulnerability in that server. ||  
|| Launch program | msfconsole |  
|| Display current version | version |  
|| Pull the weekly update | msfupdate |  
|| Saves recent commands to file | makerc<FILE.rc> |  
|| Loads a resource file | msfconsole-r<FILE.rc> |  

## <u> Executing an Exploit </u>  
| Syntax | Description | Example |  
|---|---|---|  
|| Set the exploit to use | use <MODULE> |  
|| Set the payload | set payload <PAYLOAD> |  
|| Show all options | show options |  
|| Set a setting | set <OPTION> <SETTING> |  
|| Execute the exploit | exploit or run |  

## <u> Session Handling </u>  
| Syntax | Description | Example |  
|---|---|---|  
|| List all sessions | sessions -l |  
|| Interact/attach to session | sessions -l <ID> |  
|| Detach from session | background or ^Z |  

## <u> Using the DB </u>  
| Syntax | Description | Example |  
|---|---|---|
|| The DB saves data found during exploitation. Auxiliary scan results, hasdumps, and credentials show up in the DB. First time Setup - Run from linux command line: ||  
|| Start DB | service postgresql start |  
|| Init the DB | msfdb init |  
|| Should say connected | db_status |  
|| Show hosts in DB | hosts |  
|| Show ports in DB | services |  
|| Show all vulns found | vulns |  
