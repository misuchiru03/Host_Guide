# **<ins>HOW TO SET UP YOUR MIP</ins>** 

## **Log into Confluence to view approved standards for CVA/H:** <br />
https://confluence.di2e.net or direct link: https://confluence.di2e.net/display/OJCCTM/Approved+Standards

**Read SPINs carefully, understand the intent of the day's mission, ROE's & constraints, relevant IP addresses to be concerned with, and most of all the specific tactical tasks to be accomplished**

Be Familiar with local emergency procedures (see end of this guide for specifics)

**<ins>Verbally</ins>** report personal ORM score to CCL before Starting: (See Coonfluence page under ORM - Personal Checklists)  

| **PERSONAL CHECKLIST A <br /> HEALTH & STRESS RISK <br /> FACTORS** | 0 Points <br /> Each (LOW) <br /> Green | 1 Point <br /> Each (MODERATE) <br /> Yellow | 2 Points <br /> Each (HIGH) <br /> Orange | 
|---|---|---|---|
| Personal Health Factors <br /> (hydration, nutrition, illness/injury, etc.) | Minor | Elevated | Serious |
| Personal/Family Stress <br /> (health, finance, relationship, etc.) | Minor | Elevated | Serious |  
| Work/Career Stress | Minor | Elevated | Serious |  
| Perceived Mission Perssure <br /> (external & internal) | Minor | Elevated | Serious |  
| | | **\*SCORE:**| |
| | **\*Health and Stress Scoring**| | 
| -Any Factor HIGH: overall score HIGH | | | 
| -Total of all four Factors **7-8** = SERVERE; **3-6** = HIGH; **1-2** = MODERATE; **0** = LOW | | | 


| **PERSONAL CHECKLIST A <br /> HEALTH & STRESS RISK <br /> FACTORS** | 0 Points <br /> Each (LOW) <br /> Green | 1 Point <br /> Each (MODERATE) <br /> Yellow | 2 Points <br /> Each (HIGH) <br /> Orange | 
|---|---|---|---|
| 12+ hr Work/Duty Days Past Week | 2 | 3 | >= 4 |  
| Combine Prior Sleep <br /> (past 72hrs/ 3 days) | > 18 hrs | 15-18 hrs | < 15 hrs |  
| Sleep in Last 12 hrs | > 6 hrs | 4-6 hrs | < 4 hrs |  
| | | **\*SCORE:**| |
| -Total of all four Factors **5-6** = SERVERE; **4** = HIGH; **1-3** = MODERATE; **0** = LOW | | |
| -Any Factor HIGH: overall score HIGH | | | 

**\*\*\* Just report score per chart above, CCL will assess risk and accept risk to continue or not **\*\*\* 

## **<ins>INITIAL MIP CONFIGURATION</ins>** 
*See confluence 2.1 Setup (Pre-Execution) for updated checklist as needed https://confluence.du2e.net/pages/viewpage.action?pageid=304065686 <br /> Https://confluence.di2e.net/display/ojcctm/orm+-+roes*

** Your MIP needs to start out <ins>UNPLUGGED</ins> from the network. Verify that your installed hard drive matches the appropriate classification of the network you're lookingto attach to (this may be specified in tactical task).**

### **<ins>SET THE HOSTNAME:</ins>** <br />
After logging into MIP, establish the hostname foor the RHEL machine per specification in SPINs:
- Open Linux terminal (Applications / Terminal) and use this command:<br />
	- sudo hostnamectl set-hostname \<specified name\>
- Verify that the hostname is set correctly by using command:
	- hostname
- Create a directory for yourself (optional but recommended):
	- mkdir \<last name\>

Unlike with Windows, hostnames set up this way won’t need a system reboot to take effect.

**<ins>CLEAR EXISTING / DEFAULT FIREWALL:</ins>** <br />
Before we specify our particular firewall rules on this machine (per provided SPINs), you need to clear out any existing rules in order to start from a blank slate.  Here’s how:
- Open MIP Configuration Tool (looks like Thor’s hammer)
	- Note:  Don’t just blindly enter commands here—verify what you’re doing first
    - Note 2:  You may need to exit out of the initial script menu for configuring IP/MAC info; once you do that, it’ll revert to the main script menu which uses the options below:
    - Option 1 for Firewall Options
    - Option 2 to Deny all Traffic
    - Option 7 to Save Configuration
    - Option x to Exit
- In the Terminal, enter the following commands to flush firewall rules and delete proxy chains:
    - sudo iptables –F
    - sudo iptables –X

### **<ins>DEFINE NEW FIREWALL CONFIGURATION:</ins>** <br />
Now we need to establish the new parameters for the firewall rules we want to implement based on the SPINs.  Again, read them carefully and understand the intent of the day’s mission and any specific tactical tasks relevant to the firewall:

- In terminal, enter these commands to create the configuration files:<br />
    - sudo nano /etc/target.hosts
    - sudo nano /etc/trusted.hosts
    - sudo nano /etc/exclude.hosts
- nano is a terrific Unix-based text editor that’s easy to use.  Into target.hosts, enter in the IP addresses of specific boxes / subnets that you need to connect to during the day’s mission (could be DIP components, and/or the DAL or Defended Assets List).  You can use CIDR notation to specify networks, if needed.  Into trusted.hosts, enter IP addresses of specific machines that need access to your MIP (should only be necessary to specify if you have instructions in your SPINs on doing this).  Into exclude.hosts, enter in IP addresses that you do not want your MIP to be able to connect to—generally referred to as an NSL (“no-strike list”).  This also may be specified in your SPINs
    - You can comment out any notes with a \#
	- Use Cntrl+X to exit and save (follow prompts at bottom) 
	- Use cat /etc/<file>.hosts to view and confirm your configuration files before proceeding…these must be correct!
	- **Open / click over to MIP Configuration Tool**
        - Option 1 for Firewall Options
        - Option 2 to configure firewall per specified parameters (target.hosts, trusted.hosts, and exclude.hosts)
        - Option 7 to Save
        - Option x to Exit
	- In the command line, use the following command to view/verify firewall settings (check against SPINs)
        - sudo iptables –nvL –line-numbers
**If NAT is not working for windows VM**
	- Netsh advfirewall show allprofiles state
	- Netsh advfirewall firewall delete rule name=all dir=out
	- Netsh advfirewall set all profiles firewall policy blockinboundalways,blockoutbound
	- Netsh advfirewall firewall delete rule name=all dir=\[in/out]
	- Netsh advfirewall firewall add rule name=\<name\> fir=\<in/out\> action=allow protocol=<icmpv4/tcp/udp>
		- list IP addresses separated by comma or in range using \–
	- Netsh advfirewall set currentprofile firewallpolicy blockinbound,allowoutbound
	- Netsh advfirewall show currentprofile
	- Netsh advfirewall firewall show rule name=all dir=in

### **<ins>CONFIGURE RHEL PARAMETERS:<ins>** <br />
Now that the hostname and firewall have been configured, we need to verify/configure IP settings for RHEL IAW SPINs:

- Two options here:  
    - From command line, enter sudo nm-connection-editor
    - Via the GUI, click the settings in upper-right corner (gear / Network / Wired)
- Find appropriate network interface (might be em1 or enp0s31f6)
- Select IPv4 Settings
- For manual configuration (i.e., static IP address specified per SPINs):
    - Select Manual
    - Select Add, enter in the IP address, subnet mask and gateway entries as required
    - Save & close
- For DHCP (specified in SPINs):
    - In Method, select Automatic (DHCP) – may already be set by default
    - Save & close


### **<ins>START LOGICAL ACCOUNTABILITY:</ins>** <br /> 
Now that our RHEL box is largely configured, we need to begin logical accountability to track network activity:
- Open up a new command line interface terminal (this will be dedicated to logical accountability:  
	- cd <user directory> (optional)
        - ifconfig to see interfaces available (if needed)
        - sudo tcpdump –i <interface> -nw <filename>

### **<ins>COONFIGURE WINDOWS VM:</ins>** <br />   
With the RHEL setup complete, we can now work with the Windows OS to configure it per SPINs: 
- Open up the VMWare Workstation icon on Linux
- On the menu bar, select VM / Settings
- Under Hardware tab, select Network Adapter
- Under Network Connection, ensure that NAT:  share host’s IP address is selected
  	- This essentially has the Windows VM “piggyback” off the RHEL machine’s IP settings, using the same IP address (and therefore firewall configuration) that the RHEL machine has
   	- This allows you to circumvent separately establishing Windows firewall rules, since all network traffic goes through the RHEL host machine
- Fire up the Windows VM
   	- Run PowerShell as Administrator
   	- rename-computer \<name specified in SPINs\>
   	- restart-computer
- Re-log back into the Windows VM
- Run ncpa.cpl to adjust Internet settings for the Windows VM, likely just to be specifying IP (either static or DHCP, per SPINs), DNS, etc.
- Select IPv4 properties, verify hostname, etc.

### **<ins>START OPERATOR ACCOUNTABILITY:</ins>** <br />
With both RHEL and Windows now configured, establish operator accountability (i.e., notes):
- On RHEL main menu bar, use Applications / Office / LibreOffice Calc
- Use the spreadsheet to establish operator notes per requirements, which may include:
	- Time, source, target, command, intent, observation, notes
- Save that spreadsheet into your user directory you created before
- Add new lines for any network interactions & commands entered as-needed

**With everything configured appropriately, request CCL permission to connect to the network before plugging in Ethernet cable**

### **<ins>CONNECT TO DIP & REPORT ORM / CCLL COMMUNICATION:</ins>** <br />
Once you’re all configured for both RHEL and Windows and connected to the network, go to DIP services by using the specified address in SPINs or https://services
- Now we need to report our ORM officially via Redmine & Mattermost
- CCL communication is likely to be specified via the SPINs—review them & ensure you comply with communication requirements & guidance in there
- Open up multiple tabs for Redmine and Mattermost and whatever other DIP services you need at the time
- Create a ticket in Redmine for your ORM score per scoresheet at the beginning of this guide (ensure you select the appropriate category, etc)
- Report ORM ticket # to CCL per instructions in SPINs
- Again, review SPIN guidance on communication procedures to understand what / when to use them
- Create Redmine tickets as required per the SPINs (likely if there are any DIP malfunctions or other issues that arise), then notify CCL via Mattermost per SPIN guidance
- Continue to monitor Mattermost for relevant crew traffic—you may be alerted via Mattermost to something important

### **<ins>OPS CHECK SERVICES:</ins>** <br />
Reference Confluence Section 2.2 for Ops Check information on the MIP and DIP; summary here:
- Mattermost:
  	- If you have connectivity to the web application and successfully log in, it’s green
   	- Report service status to CCL per SPIN requirements
- Kibana:
   	- Verify connectivity to the application, health status should display as green
   	- From Kibana Discover page, click Dev Tools
	- Locate Console on lower half of Dev Tools page
   		- Move to blank line & enter GET /_nodes
  		- Click the play button, check that all nodes are listed
  		- Move to blank line & enter GET /_cluster/health?pretty
  		- Click play button, check that cluster is listed and running
   		- Move to blank line & enter GET /_cat/indices?pretty
   		- Click play button, ensure Bro and Snort indices are listed
   	- On left side of Kibana webpage, click on Management
  		- Under Elasticsearch section, click on Index Management to view current health status
  		- Click on Monitoring (shows current health status of Kibana and Elasticsearch)
   		- Click on Nodes, which shows that the Nodes are ingesting network traffic
  		- Status column shows current status of each Node
   	- Click on Indices link, located at the top of the webpage
   		- This shows that the indices are ingesting network traffic
   		- Status column shows the current status of each index
   	- Report service status to CCL per SPIN requirements (via Redmine if malfunctioning—create a ticket)
- Moloch:
   	- Verify connectivity to the application from Services portal
  	- Verify that data is ingesting
  	- Verify that you can access PCAPs
   	- Click on Stats link, look at network traffic (should be observable)
  	- Click on ES Indices link
   	- **Report service status to CCL per SPIN requirements (via Redmine if malfunctioning—create a ticket)**
- Endgame:
   	- Verify connectivity to the application from Services portal
   	- Verify status of agents
  	- Report service status to CCL per SPIN requirements (via Redmine if malfunctioning—create a ticket)
- Redmine:
   	- Verify connectivity to the application from Services portal

### **<ins>OPS CHECK SENSOR:</ins>** <br />  
You may need to verify sensor connectivity / placement, which might be specified per network topology in the SPINs or other documentation.  It’s important to verify that the logical placement of the sensors are correct to ensure that they’re appropriately ingesting data into the weapons system.  To do this, one way is via Moloch:
- In Moloch, enter a query as follows:
   	- Node == sensor<#>
- This will filter out all traffic in Moloch (confirm time picker) to just traffic from that sensor
- Next, export source and destination IPs into a table to ascertain logical placement of the sensor
   	- Click on src / dst IP, select “Export unique src/dst IP w/ Counts”
   	- This will create a table of all IP traffic through the sensor based on source or destination, with the highest counted connections appearing at the top of the list
   	- Use this to determine what network(s) the sensor is connected to, which may take some examination of the network topology to determine
  	- If you have connectivity to the web application and successfully log in, it’s green

### **<ins>FILE TRANSFERS:</ins>**
If you need to transfer files to or from your MIP to a DIP server or other computer, follow these steps:
- In RHEL, open up a Terminal window
- To transfer a file out to another machine, use this command:
   	- cd <directory> to where the file is stored
  	- sudo scp <file> assessor@<ip><path>
  	- sudo scp tmp.txt assessor@192.168.1.1:/files/temp
  	- You will be prompted for password(s) – ensure you understand whether you’re entering the local password (for sudo, prompted first) vs. the password of remote host (included in SPINs)
   	- You’ll get confirmation of successful file transfer if complete
- To transfer a file in from another machine to your local host, use this syntax:
   	- sudo scp assessor@<ip><path><file> <local destination>
   	- sudo scp assessor@192.168.1.1:/files/temp/tmp.txt .
   	- sudo scp assessor@192.168.1.1:/files/temp/tmp.txt /home/assessor
   		- The . will place the file in the current directory
   		- Otherwise, specifying the precise path will place the file in the directory specified
    - You will be prompted for password(s) – ensure you understand whether you’re entering the local password (for sudo, prompted first) vs. the password of remote host (included in SPINs)
    	- You’ll get confirmation that the transfer is complete, but also double-check the file (by opening it and/or viewing it in the directory with ls) to verify successful file transfer
- You may need to use this command to begin SSH services if none of the above works:
   	- sudo systemctl start sshd
- PSSession Copy-Item (windows)
   	- $creds = Get-Credential
  	- $sess = New-PSSession –ComputerName <remoteIP. –Credential $creds
   	- Copy-Item –ToSession $sess –Destination C:\<path>

## **<ins>LINUX BASIC COMMANDS:</ins>** <br />
fping:
- fping [options] [targets] > [output file name]
- fping –ag –q 192.168.0.0/24 > alives.txt
   	- –a:  Shows systems that are alive
   	- –g:  Generate a target list from supplied IP netmask
   	- –q:  quiet, don’t show per-probe results or ICMP errors
nmap:
- sudo nmap –iL [target file name] [options] –oN [output file name]
- sudo nmap –iL targs –p1-65535 –sV –O –oN nmapscan
- sudo nmap –n –iL <target list> -T4 –A –oA AgressiveAFscan
   	- –iL [inputfilename]:  Input from list of hosts/networks
 	- –n:  Never do DNS resolution
   	- –p [port ranges]:  Only scan specified ports
   	- –sV:  Probe open ports to determine service/version info
  	- –O:  Enable OS detection
  	- –oN [filename]:  Output scan in normal format
   	- –oG [filename]:  Output scan in greppable format
   	- –oA [filename]:  Output scan in All formats
scp:
Local to remote Linux host (sending file)
- scp local_file user@remote_ip:remote_directory
- scp /local/file user@1.1.1.1:remote_path/file_name
Local host to remote Linux host (pulling file)
- scp remote_user@1.1.1.1:directory/file_name /local/path
- scp user@1.1.1.1:/home/test.txt /local/test.txt
SSH:
- ssh remote_user@192.168.1.1

## **<ins>NETWORK DEVICE CONFIGURATIONS:</ins>** <br />
Identifying device version:
- Cisco:  show version		Juniper:  show version		Vyatta:  show version
Identifying device configuration:
- Cisco:  show run		Juniper:  show configuration	Vyatta:  show configuration
   	- IGP (Interior Gateway Protocols) vs EGP (Exterior Gateway Protocols); static vs dynamic routing
   	- Link state calculates speed of path to destination & resource cost:  OSPF (Open Shortest Path First) vs Intermediate System-to-Intermediate System (IS-IS)
   	- Distance vector measures distance based on how many hops:  EIGRP (Enhanced Interior Gateway Routing Protocol) & IGRP (Interior Gateway Protocol); RIP (Routing Information Protocol); BGP (Border Gateway Protocol)
Routing table for device:
- Cisco:  show ip route		Juniper:  show route table <name> [protocol]	Vyatta:  show ip route x.x.x.x
   	- NAT – Network Address Translation:  One-to-one or Many-to-one; assigns an internal IP to an external IP, when external traffic is routed to external IP it knows which internal IP to send traffic to
   	- PAT – Port Address Translation:  Assigns many internal IPs to a single external IP and assigns a port so the device knows which internal IP to return traffic to; reduces number of required public IPs
- Cisco:  show ip nat translation	Juniper:  show security flow session nat		Vyatta:  show nat
Showing MAC addresses / CAM (Content Addressable Memory) table:
- Cisco:  show mac address-table	Juniper:  show Ethernet-switching table		Vyatta:  show interfaces detail
Switch port modes:
- Cisco:  show interface brief	Juniper:  show interfaces ethernet	Vyatta:  show Ethernet-switching interfaces ge-X/X/X detail
   	- Access = Direct connection (end device connected directly to the port)
   	- Trunk = Switch to switch, switch to router
VLAN setup and configuration
- Cisco:  show vlan, show interfaces vlan <#>, show interfaces trunk
- Juniper:  show vlans, show vlans detail
- Vyatta:  show interfaces
	- Five ways to assign:  Interface (VLANs configured on access ports = switch), MAC address, IP subnet, protocol, policy
Access Control Lists:
- Cisco:  show access-lists		Juniper:  show access-list		Vyatta:  show ip access-list
- Security control rules that permit or deny access to digital environments; stateless inspection (layer 2, 3, or 4—MAC address, IP or subnet, interface, protocol [port], VLAN)
- Standard = source IP only; access-list {name | 1-99} {permit | deny| {srcIP}
- Extended = access-list {name | 100-199} {permit | deny} {protocol [eq port]} {srcIP} {destIP} 
Alerting:
- {alert | block | alert + block} {protocol} {srcIP} {srcPort} -> {destIP} {destPort} (msg: “Words for the alert”; {ruleID}; content:”Something to search for”;)
- Cisco:  show running-config access-group	Juniper:  show security application-firewall rule-set all		Vyatta:  show firewall
- What is logged:  Cisco:  show logging		Juniper:  show system		Vyatta:  show log
- Where logs go:  Cisco:  trap logging: logging to	Juniper:  host: logging level	Vyatta:  show log

## **<ins>USING MOLOCH:</ins>**
Moloch filters:
- Destination IP:  ip.dst (ip.dst == 10.0.0.1); Source IP:  ip.src (ip.src != 10.0.0.1)
- Destination port:  port.dst (port.dst == 21); Source port:  port.src (port.src == 21)
- Protocol:  protocols (protocols == smb)
- TCP Flags:  tcpflags.syn, tcpflags.ack, tcpflags.rst (tcpflags.ack >= 1)
- HTTP URL:  http.uri (http.uri == *.com)
- SMB Filename:  smb.fm (smb.fm == EXISTS!
- DNS Links:  host.dns (host.dns == *facebook.com)
- Search Logic:  (== matches) (!= exclude) (>= greater/equal) (<= less/equal) (* wildcard) (EXISTS! Has content)
- Examples:
   	- MP Subnet to External IP via Port 4444:
   		- ip.dst != 172.16.6.0/24 && port.dst == 4444 && ip.src == 172.16.6.0/24
   	- MP Subnet using DNS protocol:
  		- ip.src == 172.16.6.0/24 && protocols == dns
   		- ip.src == 172.16.6.0/24 && port.dst == 53
  	- Find any SMB Filename in MP Network:
   		- ip.src == 172.16.6.0/24 && smb.fn == EXISTS!
  	- Find all HTTP/DNS links with certain keywords from internal IP:
   		- http.uri == *.espn.com* && ip.src == 172.16.6.0/24
   		- host.dns == *espn.com* && ip.src == 172.16.6.0/24
   	- MP host-to-host Network Connection:
   		- ip.src == 172.16.6.0/24 && ip.dst == 172.16.6.0
  	- External IP to MP Subnet:
   		- ip.src != 172.16.6.0/24 && ip.dst == 172.16.6.0/24
  	- MP Host to External Malicious IP:
   		- ip.src == 172.16.6.25 && ip.dst == 78.2.3.4
   	- DNS Protocol using different ports from DNS:
   		- protocols == dns && port.dst != 53
- HTTP:  By port (post.dst == 80), protocol (http.method == GET)
- SMB:  port.dst == 445, protocols == smb
   	- Use SPI view, load SMB data, click on file under “filename” tab then click “and <filename>”—adds query to search smb.fn == <filename>; pivot back to sessions—download entire PCAP for connection, use Wireshark for analysis
- FTP:  port.dst == 21, protocols == ftp
   	- Open carved PCAP from Moloch viewer, locate connection—follow FTP-Data stream, save resulting raw data as a file
- SMTP:  port.dst == 25
  	- Open carved PCAP from Moloch viewer, follow TCP stream, save resulting output in ASCII format; delete everything prior to file data at the top, delete all after file data ends at bottom
   	- Left with large block of base64 encoded data; base64 –d file > new_file
  	- Run “file” command to verify
To pull an HTTP object, filter / identify specific connection for HTTP, export PCAP, open with Wireshark, File / Export Objects, select HTTP, locate file in question and export appropriate one for analysis

## **<ins>USING KIBANA:</ins>**
Setting up a line chart:
- Under Basic Charts select “line” visualization
- Select or type in, the name of the index file to be used with this visualization.
- Under Buckets select “X-Axis”.
- Select Aggregation type “Date Histogram”.
- In Custom Label type the name for the X-Axis, “Timeline”.
- Select the button that looks like a play icon located on the top-left of the screen. The panel on the right will show a preview of what the visualization will look like.
- Select “Save” from the top-right menu. Enter a name for the visualization and select the “Save” button.
Setting up a bar chart:
- Under Basic Charts select the “Vertical Bar” visualization.
- Select or type in, the name of the index file to be used with this visualization.
- Under Buckets select “X-Axis”.
- Select Aggregation type “Terms”.
- Select Field type “source_ip”.
- Change Size count to “10”. (This is how many are displayed at once)
- In Custom Label type the name for the X-Axis, “Source IP”.
- Select “Add sub-buckets” followed by “Split Series”.
- Select Aggregation type “Terms”.
- Select Field type “source_ip”.
- Select the button that looks like a play icon located on the top-left of the screen. The panel on the right will show a preview of what the visualization will look like.
- Select “Save” from the top-right menu. Enter a name for the visualization and select the “Save” button
Setting up a pie chart:
- Under Basic Charts select the “Pie Chart” visualization.
- Select or type in, the name of the index file to be used with this visualization.
- In the Buckets pane, click Split Slices.
- In the Aggregation dropdown menu, select Terms
- Select Field type “protocol”
- Select the button that looks like a play icon located on the top-left of the screen. The panel on the right will show a preview of what the visualization will look like.
- Select “Save” from the top-right menu. Enter a name for the visualization and select the “Save” button.
Data table in Kibana:
- Under Data select the “Data Table” visualization.
- Select or type in, the name of the index file to be used with this visualization
- Under Buckets select “Add buckets” followed by “Split Rows”.
- Select Aggregation type “Terms”.
- Select Field type “source_ip”.
- Change Size count to “100”.
   	- NOTE: If using this for a baseline adjust the count size based on the number of devices on the Mission Partner Network.
- In Custom Label type the name for the column header, “Source IP”.
- Repeat Steps 3-7 for the fields “destination_ip” and “destination_port”.
- Select the button that looks like a play icon located on the top-left of the screen. The panel on the right will show a preview of what the visualization will look like.
- Select “Save” from the top-right menu. Enter a name for the visualization and select the “Save” button

## **<ins>USING POWERSHELLL:</ins>**
Creating new PS Session:
- $cred = Get-credential
- New-PSSession –Computername <computer> - Credential $cred -Name <namestring1>
- Enter-PSSession –Name <namestring1>

Interacting with services:
- Running services:	Get-Service \| Where-Object {$_.Status -eq “Running”}
- Show Services starting with WMI:	Get-Service “WMI*”
listing Processes:
- Formated process list for word/explorer	:	Get-Process winword explorer | Format-List *
Interacting with EventLog:
-  list logs		Get-EventLog -List
- List errors in system		Get-EventLog -LogName System -EntryType Error
- Eventlogs from multiple comps		Get-EventLog - LogName “Windows PowerShell” -ComputerName “local computer”, “Server1”, “Server2”.
Stop processes:
- Stop proc from get cmd:	Get-Process notepad,mspaint |stop-process -Verbose
- Stop proc from name:	Stop-Process -Name "notepad"
Copy-Item:
- Copy to new computer: 		Copy-item "source" -Destination \\server\C$\folderpath
RegistryKeys:
- Show all items in hive:	Get-ChildItem -Path HKCU:\ | Select-Object Name
- Recursive list of a hive:	Get-ChildItem -Path HKCU:\ -Recurse
- Advanced look - no more than 1 subkey with 4 values:	Get-ChildItem -Path HKCU:\Software -Recurse | Where-Object {($_.SubKeyCount -le 1) -and ($_.ValueCount -eq 4) }
- Remove Registry key:	Remove-Item -Path HKCU:\Software_DeleteMe
- List properties of all subkeys of registry:	Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion 
- List properties of a subkey by name:	Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion -Name "ProgramFilesDir"
- Get value of a specific key:	Get-ItemPropertyValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name ProductID
