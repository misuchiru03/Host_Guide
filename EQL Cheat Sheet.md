# EQL Cheat Sheet

**Boolean Operators**
Boolean Operators are used to connect and define the relationship between your EQL queries. These Boolean Operators can be utilized to either narrow or broaden your queries.

| Syntax | Definition | Example | 
|---|---|---|
| **and** | Utilized to combine two queries. | process where process_name == "powershell.exe" **and** command_line == "*download*" | 
| **or** | Used to broaden your query criteria. | process where process_name == "powershell.exe" **or** process_name == "wscript.exe" |  
| **not** | Used to exclude criteria from your query. | process where process_name == "powershell.exe" **and** **not** user_name == "jsmith" |  

**Comparative Operators**  
Comparative Operators are Utilzied to compare fields/value pairs to narrow or broaden your queries.
| Syntax | Definition | Example | 
|---|---|---|
| **<** | Less Than | network where total_in_bytes < 4000 |  
|**<=** | Less Than or equal to | network where total_in_bytes <= 4000 |  
| **==** | Equal to | process where process_name == "nmap.exe" |  
| **!=** | Not Equal to | process where process_name != "nmap.exe" |  
| **>** | Greater than | network where total_out_bytes > 4000 |  
| **>=** | Greater than or equal to | network where total_out_bytes >= 4000 |  

**Process Lineage**
Process Lineage generates an Endgame Resolver view to show a timeline of related parent/child process activity.
| Definition | Example | 
|---|---|
| Process lineage on wscript.exe wwith a PID of 452 on 192.168.1.239 | prcess lineage on wscrip.exe  PID 452 on 192.168.1.239 |  

- Process lineage must specify an endpoint or IP address to investigate. 
- It is recommended to slways specify the PUD of the target process.
- The process lineage tree will only show process creation events.

**Lookups**
Lookups allow for queries to be built that search for values specified in a list format. These lists can be dynamic (specify other fields) or a static list.

| Definition | Example | 
|---|---|
| Query for a list of users (static). | user_name in ("Administrator", "SYSTEM", "NETWORK SERVICE") |  
| Query for a list of processes (dynamic). | process_name in ("cmd.exe", parent_process_name) |  

**Event Relationships** 
Event Relationships ccan be itilized for stateful tracking within the respective query. If a related event exists that matches the criteria, it is then evaluated by the query. Relationships can be arbitrarily nested, allowed for complex behavior and state to be tracked. 

| Syntax | Definition | Example |  
|---|---|---|
| **child of** | Grandchild of WMI Provider Host. | process where child of [process where parent_process_name == "wmiprvse.exe"] |  
| **event of** | Text file modifications by command line redirection. | file where file_name == "*.txt" and event of [process where process_name == "cmd.exe" and command_line == "* > *"] |  
| **descendent of** | Network Activity for PowerShell processes not spawned from explorer.exe | network where process_name == "powershell.exe" and not descendant of [process where process_name == "explorer.exe"] |  

**Sequences** 
Sequences are utilized to query for a specified pattern of events within a defined amount of time or until a certain event has occurred. 

| Definition | Example | 
|---|---|
| Search for all instances of badd.exe utilizing port 443 within 1 second. | Squence with max span=1s <br /> [process where process_name == bad.exe] <br />  [network where destination_port == 443] |  
