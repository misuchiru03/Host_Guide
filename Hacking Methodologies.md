#  Hacking Methodologies 

<u> 7 Steps: </u>  
1. Footprint Analysis: basic information gathering. Verify target responds to a ping. Track down domain information (who registers, technical contact, who domain is registered with, and where domain exists). Performa traceroute to reveal network infrastructure. Firewall? Router? Same network submnet?  

2. Enumerate Information: Perform NMap scan to determine open ports and services. Look at source code for web pages.(user ID, pass, sensitive docs, recall rosters) Ongoing methdod.  

3. Obtain Access: Use social engineering to get username and password. Also, brute force attack to get a list of usernames and passwords.

4. Escalate Privileges: Create local admin acccount. Create rootkit or backdoor.

5. Gather Additional Information: Dump password hashes from the system. Tool sucah as Metasplooit Frameworkk dump hases and save locally to start cracking them. Note all user IDs and look for interesting files including, other network connections. 

6. Install Backkdoors:

7. Leverage Compromised System: Set-up port redirects to services, modify system firewall to bypass filters, router, and other firewalls. Pick off other systems and keep moving through network.

Cyberspace Exploitations includes maneivers & informationn collection.  

Cyberspace Attack: Create noticeable denial effects (degradation, disruption or destruction).  

	Denial: All functions of time. Prvent adversary from accessing data for some specified amount of time.  
	Destroy: Permanently and irreparably deny (time and amount) access to and operation of a target.  
	Degrade: To deny access to a target to a level represented as a percentage of capacity.  
	Disrupt: To completely, but temp, deny adversary access to a target for a period of time. Special case of degradation if level selected is 100%.  
	Manipulation: Control or change adversary's information that supports the commander's objectives.  
	
<u> Identigying the Target </u>  

<u> Whois: </u>  Service for obtaining information about a domain's data record. (Phone number, POC, Physical Address, Authoriative domain name servers) Whois (name of website) UNIX supplies but Windows does not. Download a Microsoft TechNet. Web-based clients include: https:\\whois.domaintools.com and https:\\whois.icann.org.

<u> DNS Zone: </u>  Portion of the DNS namespace where responibility has been delegated. Storage database for a single DNS domain name. Laid out in tree structure from right to left. Administrative- top level domains tracked by orgs and gov or Technial - responsible for the management or information within that zone.  

<u> Zone transfers: </u> 

Full (AXFR) duplicates every DNS entry.
Incremental (IXFR) only updates anything that has changed since last transfer.

<u> Tools: </u>

	1) Domain Information Groper (DIG): Flexible tool for interrogating DNS name servers.
	2) Nslookup: Utility found on both Windows and Linux designed to query DNS name servers.

<u> Scanning: </u> 

	1) Ping Sweeping: ICMP Sweeping, Identifies in-use IP addresses by sending probe packets to all network addresses. (CMD linee, fping or gping)
	2) Network TracingL Diagram this information into a topology map of network.
	3) Port ScanningL Probe network devices for any ports that are open on them. Identify possible avenues of attack on a system and verify security policies. 
	4) Operating system (OS) FingerprintingL typically used with Port Scanning. Determines the operating system used by a particular host.
		Active: Test packets are sent to a target host by software to analyze and determine the OS based on reply packets.
		Passive: Uses specialized software to "sniff" packets on network to determine OS. Have to reside on the same network as target host.
	5) Version Scanning: Probes ports to determine what service and version of serevicie are listening on that port. 
	6) Vulnerability Scanning: Examinatioon of computer in attempt to iddentify any exploits present. Related to mis-configuration or programs with flaws. Use NMap.

<u> NMAP (Netowrk Mapper): </u>  Open source tool for network exploration and security auditing. Uses raw IP packets to determine what hosts are available on the network and what services are offered. Determines OS version(s) & type of packets filters/firewalls etc. Can be used for network inventory, managing upgrade schedule and monitoring uptime. Identifies open ports.  

	namp [options] target(s)  
	a. Open ports using full scan. ex- nmap -sT 172.17.238.51  
	b. Scan alll systems on this network slowly and attempt to determine OS. ex- nmap -O -TO 172.17.238.0/24  

	1. -sT: Finds all open ports and completes three way handshake. Most graceful and gentle.
	2. -O: Attempts to figure out OS.
	3. -tO: Will limit scan speed to try to evade IDS detection. 

<u> NETCAT(Swiss Army Knife): </u>  Most Versatile. Reads and writes data across network connections using TCP/IP. Reliable "back-end" tool. Can be used directyl or easily progrram driven. Debugging and exploration tool that can create almost any kind of connection.  
	1. Tunneling mode: Allows for special tunneling such as UDP and TCP specifuing all netwokr parameters. (source port/interface, listeningg port/interface and remote host connect to tunnel)  
	2. Built-in port: scanning with randomizer  
	3. Buffered send-mode:(one line ever "N" second) and hex dump of transmitted and received data  

	Port Scans with NetCat: nc -v -w 2 -z targetIPstartPort-end port
	1. -v: Verbose
	2. -w "N": Timeout for connects (wait N seconds after closure of STDIN to make connection). If connection doesn't happen, NetCat stops running.
	3. -z: Prevents sending any TCP data and very little data to UDP connection. Fast but shows what is listening. Will try to connect to every port listed.
	4. -i: Limit scanning speed.

	Banner Grabber: Enumeration technique to extract information. (OS, web server and apps) ex - nc -v -n targetIP port#
	1. -v: Verbose
	2. -n: no DNS or service lookups on specified address/hostname
	*After commands are entered a GET request for http banner needs to be initiated. (GET HTTP); FTP automatically provides the banner.
