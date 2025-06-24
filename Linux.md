# Linux
---
## Export/Format Lists  
---
### CSV  
### TXT  
---

## Commands  
---
### <u> Basic Linux Commands </u>
| CMD | Flags| Description |
|---|---|---| 
| ls || List the current working directory|  
| |-r| Lists files in sub-directories as well|  
| |-a | Lists hidden files |
| |-al| Lists files and directories with detailed information like permissions, siz, owner, etc.|
| cd  || Change directories |
| |.. | Move one level up  |
| | /  | Move to the root directory  |
| cat > filename| | Creates a new file |
| cat filename  || displays te file content  |
| cat file1 file2 > file3 || Joins two files (files1, file2) and stores the output in a new file (file3) |
| mv file "new file path" || Moves the files to the new location |
| mv filename new_file_name || Renames the file to a new filename  |
| sudo  || Allows regular users to run programs with the secuirty privileges of the superuser or root |
| rm filename  || deletes a file  |
| man <command>|| gives help information on a command |
| history  || Gives a list of all past cmmands typed in the current terminal session |
| clear  || Clears the terminal  |
| mkdir <directoryname>  || Creates a new directory in the present working directory or at the specified path  |
| rmdir  || Deletes a directory  |
| apt-get || Command used to install and update packages  |


---

### <u> Partition & Disk Management </u>  
| CMD | Flags| Description |
|---|---|---|  
|Autogrow.sh ||After the virtual disk is increased, return to SSH session and run this command to automatically expand any logical volume for which the physical volumes are increased. |  
| df ||Disk Free - Show information about the file system on which each FILE resides of all file systems by default. |
||-a|Include pseudo, duplicate, inaccessible file systems|
||-h| Print size in power of 1024 (M)|  
||-H| Print size in power of 1000 (G)  |
||-i| List inode information instead of block usage|  
| du || Disk Usage|  
||-a| Writes all counts for file, not directories|
||-s| Only the summary of disk is shown|  
|| -h| Output is given "human-readable" form |  
| fdisk || Display, manage and manipulate partition table  
|| -l | Displays partitions |  
| lsscsi || List SCSI devices, followed by NVMe namespaces and controllers |  
| lvs || Display information about logical volume and Virtual Groups |  
| Lvdisplay || Display all information about a logical volume |  
| pvs || Display information about physical volumes and Virtual Groups |  
| vgs || Display information about volume groups |  
| Vgdisplay || Display volume group information | 


### <u> Identifying/Managing Command Shells </u>
| CMD | Flags| Description |
|---|---|---| 
| sh,bash,ksh,csh,tcsh,etc.. || Temp shell cahnge. 'exit' (Ctrl + D) to leave shell. |  
| $shell || Environmental variable that identifies the deault login shell for the currently logged in user. Does not tell you which shell you are currently in. |
| ps || Snapshot of current processes and will tell you how many bash shells are open. |  
| Chsh || Changes a users' login shell.  
|| -l | Displays a list of available shells |  

### <u> Streams, Pipes and Redirects </u>
| CMD | Description |
|---|---|
| < | Overwrite standard input |  
| 2> | Overwrite standard error | 


### <u> File Transfer </u>
| CMD | Flags| Description |
|---|---|---| 
| ssh || ssh <user>@<IP> | 
| scp <localfile> user@IP:directory || SCP (secure copy) is a command-line utilitu that allows you to scurely copy files and directories between two locations.  
|| -C |This option forces scp to scp to compresses the data as it is sent to the destination machine.|
|| -r |This option tells scp to copy directories recursively.|
|| -p |Preserves files modification and access times.
|| -3 |-route thhe traffic through the machine on which the command is issued. |  

**EXAMPLES:**  
scp <location from> <location going to>  
sudo scp -r <username>@<IP>:/nsm/*  
sudo scp win.tar.xz.part* <username>@<IP>:win/  
scp /data/pcap/sensor-p24.pcap.tar.xz <username>@10.11.3.9:/repository/202112_UAE/  
scp -pC /data/pcap/sensor-p24.pcap.tar.xz <username>@10.11.3.9:/repository/20211_UAE/  
scp -3 <username>@10.11.3.9://data/pcap/sensor-p24.pcap.tar.xz <username>@10.11.3.9:/repository/202112_UAE/   
 

### <u> Scanning </u>  
| CMD | Flags| Description |
|---|---|---| 
| fping | | Generates ICMP messages to multiple IP addresses and then waits to see which reply|  
|| -g | Allows you to supply a netmask or starting/ending IP|  
|| -f | Reads list of targets from a file.|  
|| -a | Show systems that are alive.|  
|| -r | Specifies the number of additional attempt at pinging a target.|  
| namp | | A -Aggressive scan (includes -O,-sV, and -sC (script scanning)|    
|| -T4 |Faster Speed|  
|| -v |Verbose|  
|| -O |Operating System|  
|| -sV |Service/Version|  
|| -Pn |Skip Host Discover|  
|| -sn |Ping Sweep|  
|| -oX |Output to XML format|  
|| -p | Full port scan or -p#-## for port range |  

### <u> Tar </u>
| CMD | Flags| Description |
|---|---|---|  
| tar | tar stores and extracts files from a tape or disk archive.  
|| -c | Create a new archive|  
|| -v | Verbosely list files processed|    
|| -x | Extract files from an archive|    
|| -J | Filter the archive through xz|  
|| -f | Use archive file or device archive|    
|| -t | List the contents of an archive|  

**[Export](AAA) below commands into .csv or .txt for analysis and reference.**  
### <u>Accounts </u>
| CMD | Description |
|---|---|
|cat /etc/passwd | List of local users|  
|cat /etc/sudoers | List of local admins| 
|cat /etc/passwd \| grep :0: | elevated/root access|
|sudo cat /etc/sudoers \| grep -v ^#  | elevated/root access|
|cat /etc/group \| grep :0: | elevated/root access|
|sudo find / -perm -4000 or -2000 | elevated/root access, can compare to baseline|
|grep root /etc/passwd \| tee -a | Read from standin, write to standout| 
|w|Current logged in users|
|last||
|lastb|Failed login attempts|
|cat /var/log/\<log that points to rsyslog\> \| grep -i failed | Failed login attempts|
|lastlog| Last time user logged in, if ever|
|sudo cat /var/log/secure \| grep -i failed | Look at all failed attempts|
|cat /etc/rsyslog.conf | Verify where authpriv is sent|
|grep bash /etc/passwd | User accounts with bash shell|




### <u>Hashes </u>
| CMD |Description |
|---|---|
|sudo md5sum /usr/sbin/* > filepath.txt|Exports md5 hash of all files in sbin to txt file |  
| |Exports SHA256 hash of all files in sbin to txt file  | 


### <u>Mount Storage </u>  
| CMD |Flags|Description |
|---|---|---|
|mount |--target /mountpoint|used to mount filesystem|  
||-l| Lists all the file systems mounted yet|
||-h|Displays options for command|
||-V|Displays the version information|
||-a|Mounts all devices described at /etc/fstab|
||-t|Type of filesystem device uses|
||-T|Describes an alternative fstab file|
||-r|Read-only mode mounted|
|unmount |--target /mountpoint|used to unmount filesystem|  
|cat /etc/fstab||Contains information about which device is needed to be mounted where|
|cat /etc/mstab|| Currently mounted shares|
|ssm mount||Single tool to manage your storage|
|showmount|-e| View NFS share|



### <u>Networking</u>

| CMD| Flag |Description |
|---|---|---|
|ifconfig||Display interface configuration|
|ip addr show||Display interface configuration|
|lsof|-i -nP| Displays sockets via open files vs networking services *Compare to netstat to reveal hidden processes/connections|
|netstat| | View ports/sockets|
|sudo netstat  |-pantu| Displays associated programs|
|cat /etc/resolve| |Displays DNS, Nameserver|
|sudo netstat |-rn | Displays routing table and socket activity with PID|
|ip route list | | Displays routing table|
|route |-n| Displays routing table|
|arp | -v | MAC address/IP |
|cat /etc/resolv.conf | |nameserver| 
|rpcinfo| |Display information for host running RPC services|  


### <u>PC Info</u>
| CMD | Flags |Description |
|---|---|---|
|Hostname| |Determine PC name |
|uname| -r |Information about OS version, IP, Hotfixes, DHCP server etc.. |
||-a||
|lsmod| |Kernel modules|
|date|||
|uptime|-s||
|cat /boot/grub/grub.conf||Grub configuration file|
|cat /etc/default/grub||Grub2 editable path|
|cat /boot/grunb/grub.cfg||Grub2 configuration file|  

### <u>Processes</u>  
| CMD | Description |
|---|---|
|Get-Process | List of running processes |
|Get-GetCimInstance Win32_Process |  List of running processes |

### <u>PSSession</u>  
| CMD | Description |
|---|---|
|New-PSSession | Creates New Powershell session on local or remote computer |
|Remove-PSSession |  Deletes all PSSessions in current session  |

### <u>Services</u>  
| CMD | Description |
|---|---|
|Get-Service | | List of running processes |
|Get-GetCimInstance -ClassName Win32_Service |  List of running processes |  

### <u>Startup Programs</u>  
| CMD | Description |
|---|---|
|Get-GetCimInstance -ClassName Win32_StartupCommand  \| Select-Object Name, command, Location, User \| Format-List | List of all startup programs|

## Bash Scripts  
---
## Tools  
---


