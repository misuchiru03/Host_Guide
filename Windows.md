# Windows
---
## Event IDs
---

#### <u>Application</u>
| Event ID | Description|
|---|---|
|   |   |
|   |   |

#### <u>Security</u>

| Event ID | Description|
|---|---|
|4624|Successful Login|
|4625|Failed Login|
|4688|Process Execution|
|4720|New user account creation|

#### <u>System</u>
| Event ID | Description|
|---|---|
|   |   |
|   |   |

## Export / Format lists
-----------
Choose between **Format-List** and **Format-Table.**

#### CSV
---------- 
    <COMMAND> | Format-List | Export-CSV C:\Path\to\File.csv

**EXAMPLE:**  

    Get-Process | Format-List | Export-CSV C:\Users\Assessor\Evidence\Targets.csv  

* CSV (Comma Separated Values) is a simple text file used to store tabular data. This format organizes large amounts of data and arranges tables by a specific structure divided into rows and columns.
* Use Excel to open a CSV file for analysis.
&nbsp;&nbsp;

## <u> Command Line </u>  
| Syntax | Description | Example |  
|---|---|---|
|| Determine PC Name | c:\> hostname |  
|| Information about OS version and other useful system information | c:\> systemiinformation |  
|| List all processes currently running | c:\> tasklist |  
|| List all processes currently running and the DLLs each has loaded | c:\> tasklist /m |  
|| List all prccesses currently runing which have the specified [dll] loaded | c:\> tasklist /m [dll] |  
|| list all processes currently running and the services hosted in those processes | c:\> tasklist /svc |  
|| Query brief status of all services | c:\> sc query |  
|| Query the configuration of a specifiied service | c:\> sc qc [ServiceName] | 
|| Show all TCP/UDP port usage and process ID | c:\> netstat -nao |  
|| Look for the usasge of a port [port] ever [n] seconds | c:\> netstat -nao [N] \| find [port] |
|| Dump detailed protoccol statistics | c:\> netstat -s -p [tcp\|udp\|ip\|icmp] |  
|| List network connections and the programs that are making those connections | c:\> netstat -nba |  
|| Search directory structure for a file in a specific directory | c:\> dir /b /s[Directory]\\[FileName] |  
|| Turn off built-in Windows Firewall | c:\> netsh firewall set opmode disable |  
|| Configure interface "Local Area Connection" with an IP/netmask/DFGW | c:\> netsh interface ip set address local static ip-address><netmask><DFGW>1 |  
|| Configure DNS server for "Local Area Connection" | c:\> netsh interface ip set dns local static <ip-address> |  
|| Configure interface to use DHCP | c:\> netsh interface ip set address local dhp |  
|| Remotely query registry for last logged in user | c:\> reg query "\\\\computername\\HKLM\\Microsoft\\Windows NT\\CurrenVersion\\WinLogon" /v DefaultUserName |  
|| List all computers in domain "blah" | c:\> dsquery computer "OU=example,DC=blah" -o rdm -limit 6000 &gt; output.txt |  
|| Determine who is apart of the administrators group || c:\> net localgroup administrators |  
|| Add a user where travis is the username and pasword is blah | c:\> net user travis blah /add |  


#### TXT
----------
    <COMMAND> | Format-List | Out-File C:\Path\to\File.txt   

**EXAMPLE:**  

    Get-Process | Format-List | Out-File C:\Users\Assessor\Evidence\Targets.txt  

* TXT file fields can be separated with commas, semicolons or tab.    

**Try multiple options to see which outcome you prefer.**  

## PowerShell Commands
---
**[Export](http://855-cyber-protection-team.pages.joust.lab/tools/_Windows/Export/) below commands into .csv or .txt for analysis and reference.**  
#### <u>Accounts </u>
| CMD | Description |
|---|---|
|net localgroup administrators| List of local admins |  
|Get-LocalUser| List of local users | 

#### <u>Hashes </u>
| CMD | Flags |Description |
|---|---|---|
|Get-FileHash|.\Path\to\file -Algorithm SHA1 |Displays SHA1 hash for specified file |  
||.\Path\to\file -Algorithm SHA256 |Displays SHA256 hash for specified file | 
||.\Path\to\file -Algorithm MD5 |Displays MD5 hash for specified file |  

#### <u>Mount File Share </u>  
| CMD |Description |
|---|---|
|net use z: \\IP\S PASSWORD /user:USER |Mount file share and change to the drive|  

#### <u>Networking</u>

| CMD| Flag |Description |
|---|---|---|
|netstat| | All TCP/UDP Connections|
|netstat |**-a**| All connections and listening ports|
| | **-n** |  List all addresses and Port IDs in numerical form|
| | **-o** | Displays owning process ID associatred with each connection|
| | **-b** |   Displays executable involved|
|Get-NetTCPConnections | | List of current connections| 
|Get-NetTCPConnections | **-State Established** | List of Established connections| 
|ipconfig| | List IP, subnet mask, and default gateway|


#### <u>PC Info</u>
| CMD | Description |
|---|---|
|Hostname| Determine PC name |
|systeminfo| Information about OS version, IP, Hotfixes, DHCP server etc.. |


#### <u>Processes</u>  
| CMD | Description |
|---|---|
|Get-Process | List of running processes |
|Get-GetCimInstance Win32_Process |  List of running processes |

#### <u>PSSession</u>  
| CMD | Description |
|---|---|
|New-PSSession | Creates New Powershell session on local or remote computer |
|Remove-PSSession |  Deletes all PSSessions in current session  |

#### <u>Services</u>  
| CMD | Description |
|---|---|
|Get-Service | | List of running processes |
|Get-GetCimInstance -ClassName Win32_Service |  List of running processes |  

#### <u>Startup Programs</u>  
| CMD | Description |
|---|---|
|Get-GetCimInstance -ClassName Win32_StartupCommand  \| Select-Object Name, command, Location, User \| Format-List | List of all startup programs|



## PowerShell Scripts
---


### [Csv](http://855-cyber-protection-team.pages.joust.lab/tools/_Windows/Export/) creation of all computers in Active Directory  

    Get-ADComputer -Filter * -Property * | Select-Object Name, OperatingSystem, OperatingSystemVersion, ipv4Address | Export-Csv ADcomputerslist.csv -NoTypeInformation -Encoding UTF8


### <u> VARIABLE CREATION</u>  

    $targets = Import-Csv ..\Path\to\CSV.csv | Where-Object {$_.field -eq "string"} | Select-Object -ExpandProperty IP   
    $creds = Get-Credential <domain\User> #Password


### <u> REMOTE SCRIPTS</u>
    Invoke-Command -computername $targets -Credentials $creds -FilePath..\Path\to\Powershell_script.ps1 | Export-Csv .\Path\to\new_CSV.csv    

    ICM -CN $targets -CR $creds -FilePath..\Path\to\Powershell_script.ps1 | Export-Csv .\Path\to\new_CSV.csv  

**Connect to IP remotely and execute a command**  

	Invoke-Command -computername <IP> {Command}

**Move a file from local machine to remote machine using PSSession**

	$session = New-PSSession -ComputerName 192.168.0.1 -Credential $creds 	

	Copy-Item -Path .\file.name.txt -ToSession $session -Destination C:\Users\student\Documents\file.name.txt

	Remove-PSSession *

**Move a file from remote machine to local machine using PSSession**

	$session = New-PSSession -ComputerName 192.168.0.1 -Credential $creds 	

	Copy-Item -Path C:\Users\student\Documents\file.name.txt -FromSession $session -Destination .	

	Remove-PSSession *
	

### <u>**EVENT LOGS**</u>  		

	Invoke-Command -ComputerName 192.168.0.1 -Credential $creds -ScriptBlock {

		$logfilter = @{
	        	LogName   = "Security"
	        	ID        = 4720
	        	StartTime = [datetime]"08/05/2022 00:00:00z"
	        	EndTime   = [datetime]"08/05/2022 00:00:00z"
	        	#Data      = "<SID>" #This is if you want to look for events related to a specific user
	    }
	
		Get-WinEvent -FilterHashtable $logfilter 	

		} | Select-Object -Property RecordID, Message |
	    		Format-Table -Wrap  
			  
### <u>**FILE LOCATION**</u>

	Invoke-Command -ComputerName 192.168.0.1 -Credential $creds -ScriptBlock {

		$Paths = "C:Windows\System32\Hidden", "C:\Program Files\Downloads"
		Get-ChildItem -Path $Paths -Recurse -File -Force


### <u>**REGULAR EXPRESSIONS**</u>
**Find important information within files using regular expressions.** 
	Invoke-Command -ComputerName 192.168.0.1 -Credential $creds -ScriptBlock {

		$ssn     = "\d{3}-\d{2}-\d{4}"
		$email   = "[\w\.-]+@[\w\.-]+\.[\w]{2,3}"
		$keyword = "(?=.*Str1)(?=.*Str2|.*Str3)"
		$paths   = "C:Windows\System32\Hidden", "C:\Program Files\Downloads"
	

		Get-ChildItem $paths -Recurse -File -Force |
	        	Select-String -Pattern $ssn,$email,$keyword -AllMatches |
	            	Select-Object -Property Path, Line
	}


### <u>**REFERENCE SCRIPTS**</u>   
SAVE BELOW COMMANDS AS .ps1 TO BE REFERENCED FOR REMOTE EXECUTION OR AUTOMATION  

####  <u> Accounts </u>
| CMD| Flags | Description |
|---|---|---|
| Get-CimInstance |**-ClassName Win32_UserAccount \| Select-Object -Property Name, Disabled, PasswordRequired, SID** | List of User Accounts w/specific properties|
| Net localgroup administrators | |List of local admin accounts |
| Net localgroup administrators | **/Domain**  | List of domain admins in "administrators" group|  

    Invoke-Command -computername $targets -Credentials $creds -FilePath..\Path\to\Accounts.ps1 | Export-Csv .\Path\to\Accounts.csv  

####  <u> Autoruns</u>
    param([string][] $AutoRunKey)

        foreach($key in Get-Item -Path $AutoRunKey -Error Actrion SilentlyContinue){
            $data = $key.GetValueNames() | 
                Select-Object -Property @{n="Key_Location"; e={$key}},
                                        @{n="Key_ValueName"; e={$_}},
                                        @{n="Key_Value"; e={$key.GetValue($_)}}

            if($null -ne $data){
            [pscustomobject]$data
            }

        }


####  <u> Firewall</u>
    $rules = Get-NetFirewallRule | Where-Object {$_.enabled}
	        $portfilter    = Get-NetFirewallPortFilter
	        $addressfilter = Get-NetFirewallAddressFilter
	

	        ForEach($rule in $rules){
	            $ruleport    = $portfilter | Where-Object {$_.InstanceID -eq $rule.InstanceID}
	            $ruleaddress = $addressfilter | Where-Object {$_.InstanceID -eq $rule.InstanceID}
	            $data        = @{
	                    InstanceID = $rule.InstanceID.ToString()
	                    Direction  = $rule.Direction.ToString()
	                    Action     = $rule.Action.ToString()
	                    LocalAddress = $ruleaddress.LocalAddress -join ","
	                    RemoteAddress = $ruleaddress.RemoteAddress -join ","
	                    Protocol = $ruleport.Protocol.ToString()
	                    LocalPort = $ruleport.LocalPort -join ","
	                    RemotePort = $ruleport.RemotePort -join ","
	                   }
	

	            New-Object -TypeName psobject -Property $data
	    }

####  <u> Processes </u>  
    Get-CimInstance -ClassName Win32_Process |
	             Select-Object -Property ProcessName,
	                            ProcessID,
	                            Path,
	                            CommandLine,
	                            @{n="Hash"; e={(Get-FileHash -Path $_.path).hash}}  


####  <u> Scheduled tasks</u>  
	schtasks /query /V /FO CSV | ConvertFrom-Csv |
	    	Where-Object {$_."Scheduled Task State" -eq "Enabled"} |
	        	Select-Object -Property TaskName,
	                                Status,
	                                "Run As User",
	                                "Schedule Time",
	                                "Next Run Time",
	                                "Last Run Time",
	                                "Start Time",
	                                "End Time",
	                                "End Date",
	                                "Task to Run",
	                                @{n="Hash";e={(Get-FileHash -Path (($_."Task to Run") -replace '\"','' -replace "\.exe.*","exe") -ErrorAction SilentlyContinue).	hash}}

####  <u> Services </u>  
	Get-CimInstance -ClassName Win32_Service |
	    		Select-Object -Property @{n="ServiceName";e={$_.name}},
	                            		@{n="Status";e={$_.state}},
	                            		@{n="StartType";e={$_.stertmode}},
	                            		PathName


### <u>**BASELINE SCRIPTS**</u>   

####  <u> Accounts</u>  
 	$targets = Import-Csv ..\ADcomputerslist.csv|
	  	Where-Object {$_.field -eq "string"}  |
	    	Select-Object -ExpandProperty IP

	ICM -CN $targets -CR $creds -FilePath ..\Path\to\accounts.ps1 | Export-Csv .\<OperatingSystrem>_AccountsBaseline.csv  

####  <u> Autoruns </u>  
 	$targets = Import-Csv ..\ADcomputerslist.csv|
	  	Where-Object {$_.field -eq "string"}  |
	    	Select-Object -ExpandProperty IP

	ICM -CN $targets -CR $creds -FilePath ..\Path\to\autoruns.ps1 | -ArgumentList (,(Get-Content .\Autoruns.txt)) | Export-Csv .\<OperatingSystrem>_AutoRunsBaseline.csv

####  <u> Firewall </u>  	
	$targets = Import-Csv ..\ADcomputerslist.csv|
	  	Where-Object {$_.field -eq "string"}  |
	    	Select-Object -ExpandProperty IP

	ICM -CN $targets -CR $creds -FilePath ..\Path\to\firewall.ps1 | Export-Csv .\<OperatingSystrem>_FirewallsBaseline.csv

####  <u> Processes </u>  	
	$targets = Import-Csv ..\ADcomputerslist.csv|
	  	Where-Object {$_.field -eq "string"}  |
	    	Select-Object -ExpandProperty IP

	ICM -CN $targets -CR $creds -FilePath ..\Path\to\processes.ps1 | Export-Csv .\<OperatingSystrem>_ProcessesBaseline.csv	

####  <u> Scheduled Tasks</u>  	
	$targets = Import-Csv ..\ADcomputerslist.csv|
	  	Where-Object {$_.field -eq "string"}  |
	    	Select-Object -ExpandProperty IP

	ICM -CN $targets -CR $creds -FilePath ..\Path\to\scheduled_tasks.ps1 | Export-Csv .\<OperatingSystrem>_ScheduledTasksBaseline.csv	

####  <u> Services</u>  	
	$targets = Import-Csv ..\ADcomputerslist.csv|
	  	Where-Object {$_.field -eq "string"}  |
	    	Select-Object -ExpandProperty IP

	ICM -CN $targets -CR $creds -FilePath ..\Path\to\services.ps1 | Export-Csv .\<OperatingSystrem>_ServicesBaseline.csv  

	
### <u>**COMPARE BASELINE SCRIPTS**</u>  

####  <u> Accounts </u>  

	$targets = Import-Csv ..\ADcomputerslist.csv|
	  	Where-Object {$_.field -eq "string"}  |
	    	Select-Object -ExpandProperty IP
	    
		$ht = @{
	 			ReferenceObject = Import-Csv ..\02_Create_Baseline_Scripts\Win10AccountsBaseline.csv
				Property        = "name"
	 			PassThru        = $true
		}

		$current = Invoke-Command -ComputerName $targets -Credential $creds -FilePath ..\01_Reference_Scripts\accounts.ps1
	

		ForEach ($ip in $targets){
	    	$ht.DifferenceObject = $current |
	        	Where-Object {$_.pscomputername -eq $ip} |
	                Sort-Object -Property name -Unique
	        Compare-Object @ht |
	        	Where-Object {$_.sideindicator -eq "=>"}
		}

####  <u> Autoruns </u>  

	$targets = Import-Csv ..\ADcomputerslist.csv|
	  	Where-Object {$_.field -eq "string"}  |
	    	Select-Object -ExpandProperty IP
	    
		$ht = @{
	  			ReferenceObject = Import-Csv ..\02_Create_Baseline_Scripts\Win10AutoRunsBaseline.csv
	  			Property        = "Key_ValueName"
	  			PassThru        = $true
		}	

		$current = Invoke-Command -ComputerName $targets -Credential $creds -FilePath ..\01_Reference_Scripts\autoruns.ps1 -ArgumentList (,(Get-Content ..		\Autorunkeys.txt))
	

		ForEach ($ip in $targets){
	    	$ht.DifferenceObject = $current |
	        	Where-Object {$_.pscomputername -eq $ip} |
	               Sort-Object -Property Key_Valuename -Unique
	        Compare-Object @ht |
	        	Where-Object {$_.sideindicator -eq "=>"}
		}


####  <u> Firewall </u>   

	$targets = Import-Csv ..\ADcomputerslist.csv|
	  	Where-Object {$_.field -eq "string"}  |
	    	Select-Object -ExpandProperty IP

		$ht = @{
	  			ReferenceObject = Import-Csv ..\02_Create_Baseline_Scripts\Win10AccountsBaseline.csv
	  			Property        = "direction", "action", "localaddress", "remoteaddress", "localport", "remoteport"
	  			PassThru        = $true
		}	

		$current = Invoke-Command -ComputerName $targets -Credential $creds -FilePath ..\01_Reference_Scripts\firewall.ps1
	

		ForEach ($ip in $targets){
	    	$ht.DifferenceObject = $current |
	    		Where-Object {$_.pscomputername -eq $ip} |
	            	Sort-Object -Property direction, action, localaddress, remoteaddress, localport, remoteport -Unique
	    	Compare-Object @ht |
	        	Select-Object -Property *, @{n = "IP"; e = {"$IP"}}
		}

####  <u> Processes </u>   

	$targets = Import-Csv ..\ADcomputerslist.csv|
	  	Where-Object {$_.field -eq "string"}  |
	    	Select-Object -ExpandProperty IP  

		$ht = @{
				ReferenceObject = Import-Csv ..\02_Create_Baseline_Scripts\Win10ProcessesBaseline.csv
				Property        = "hash", "path"
				PassThru        = $true
		}

		$current = Invoke-Command -ComputerName $targets -Credential $creds -FilePath ..\01_Reference_Scripts\processes.ps1
	

		ForEach ($ip in $targets){
	    	$ht.DifferenceObject = $current |
	        	Where-Object {$_.pscomputername -eq $ip} |
	            	Sort-Object -Property hash, path -Unique
	    	Compare-Object @ht |
	        	Where-Object {$_.sideindicator -eq "=>" -and $_.path -ne $null}
		}		

####  <u> Scheduled Tasks</u>   

	$targets = Import-Csv ..\ADcomputerslist.csv|
	  	Where-Object {$_.field -eq "string"}  |
	    	Select-Object -ExpandProperty IP

		$ht = @{
	  			ReferenceObject = Import-Csv ..\02_Create_Baseline_Scripts\Win10ScheduledTasksBaseline.csv
	  			Property        = "taskname"
	 			PassThru        = $true
		}
	

		$current = Invoke-Command -ComputerName $targets -Credential $creds -FilePath ..\01_Reference_Scripts\ScheduledTask.ps1 
	

		ForEach ($ip in $targets){
	    	$ht.DifferenceObject = $current |
	        	Where-Object {$_.pscomputername -eq $ip} |
	            	Sort-Object -Property taskname -Unique
	    	Compare-Object @ht |
	        	Where-Object {$_.sideindicator -eq "=>"}
		}

####  <u> Services </u>   

	$targets = Import-Csv ..\ADcomputerslist.csv|
	  	Where-Object {$_.field -eq "string"}  |
	    	Select-Object -ExpandProperty IP

		$ht = @{
				ReferenceObject = Import-Csv ..\02_Create_Baseline_Scripts\Win10ServicesBaseline.csv
				Property        = "ServiceName"
				PassThru        = $true
		}
	

		$current = Invoke-Command -ComputerName $targets -Credential $creds -FilePath ..\01_Reference_Scripts\services.ps1
	

		ForEach ($ip in $targets){
	    	$ht.DifferenceObject = $current |
	        	Where-Object {$_.pscomputername -eq $ip} |
	            	Sort-Object -Property ServiceName -Unique
	    	Compare-Object @ht |
	        	Where-Object {$_.sideindicator -eq "=>"}
		}  
### <u>**LFA SCRIPTS**</u>  

####  <u> AutoRuns </u>  

	$targets = Import-Csv ..\ADcomputerslist.csv|
	  		Where-Object {$_.field -eq "string"}  |
	    		Select-Object -ExpandProperty IP  	

			$current = Invoke-Command -ComputerName $targets -Credential $creds -FilePath ..\01_Reference_Scripts\autoruns.ps1 -ArgumentList (Get-Content ..\AutoRunKeys.txt)
	
			$current | Sort-Object -Property pscomputername, Key_ValueName -Unique |
	        	Group-Object Key_ValueName |
	                Where-Object {$_.count -le 2} |
	                    Select-Object -ExpandProperty Group


####  <u> Processes </u>  

	$targets = Import-Csv ..\ADcomputerslist.csv|
	  		Where-Object {$_.field -eq "string"}  |
	    		Select-Object -ExpandProperty IP  	

			$current = Invoke-Command -ComputerName $targets -Credential $creds -FilePath ..\01_Reference_Scripts\processes.ps1	

			$current | Sort-Object -Property pscomputername, hash -Unique |
	        	Group-Object hash |
	                Where-Object {$_.count -le 2} |
	                	Select-Object -ExpandProperty Group  

####  <u> Scheduled Tasks </u>  

	$targets = Import-Csv ..\ADcomputerslist.csv|
	  		Where-Object {$_.field -eq "string"}  |
	    		Select-Object -ExpandProperty IP  	

			$current = Invoke-Command -ComputerName $targets -Credential $creds -FilePath ..\01_Reference_Scripts\scheduledtask.ps1	

			$current | Sort-Object -Property pscomputername, taskname -Unique |
	        	Group-Object taskname |
	                Where-Object {$_.count -le 2} |
	                    Select-Object -ExpandProperty Group  

####  <u> Services </u>  

	$targets = Import-Csv ..\ADcomputerslist.csv|
	  		Where-Object {$_.field -eq "string"}  |
	    		Select-Object -ExpandProperty IP  	

			$current = Invoke-Command -ComputerName $targets -Credential $creds -FilePath ..\01_Reference_Scripts\services.ps1	

			$current | Sort-Object -Property pscomputername, ServiceName -Unique |
	        	Group-Object ServiceName |
	                Where-Object {$_.count -le 2} |
	                        Select-Object -ExpandProperty Group


## Tools  
---

### <u>**ACAS**</u>
> <u>**Description:**</u>  
> Vulnerability scanner

- [**Nessus Agent 10.1.4 Download .RPM** ](http://nextcloud.joust.lab/index.php/s/pH4bAcBn9nwyFM6/download/CM280064_Ness.usAgent-10.1.4-es8.x86_64.rpm)  
- [**Nessus 10.2.0 Download .RPM** ](http://nextcloud.joust.lab/index.php/s/WJiibJgsBfy4msr/download/CM280071_Ness_us-10.2.0-es8.x86.64.rpm)  
- [**Security Center 5.23.1 .RPM** ](http://nextcloud.joust.lab/index.php/s/Mf86osZjdNoxxLE/download/CM284906_SecurityCenter-5.23.1-el8.x86_64.rpm)  
- [**Security Center 5.23.1 .tar.gz** ](http://nextcloud.joust.lab/index.php/s/cYGNCAY7jWKKsnR/download/CM284909_SC-202209.2-5.23.1.tar.gz)  
- [**COAMS** ](http://nextcloud.joust.lab/index.php/s/czACT6bj4r7cSfo/download/CM-249836-COAMS_Viewer_1.2.zip) 
- [**nnm** ](http://nextcloud.joust.lab/index.php/s/yREnKM4KS83NsoM/download/CM-281277_nnm-6.0.1-es8.x86_64.rpm)  
- [**ACAS Config** ](http://nextcloud.joust.lab/index.php/s/oFqaBCfw5EHS6bP/download/CM-281699_acas_configure-22.06-1.noarch.rpm)  
- [**ACAS RPM .iso** ](http://nextcloud.joust.lab/index.php/s/nEmDdAqYSjNREEc/download/CVAH_ACAS_RPM.iso)  
- [**ACAS  .ova** ](http://nextcloud.joust.lab/index.php/s/aQcEFcaGsLLRyYP/download/CVAH-ACAS.ova)  
- [**dialog** ](http://nextcloud.joust.lab/index.php/s/bQNeKSoWHNkRPC7/download/dialog-1.3-13.20171209.el8.x86_64.rpm)  
- [**DISA STIG RED HAT** ](http://nextcloud.joust.lab/index.php/s/s2i8P5BiSy7bJSb/download/DISA_STIG_Red_Hat_Enterprise_Linux_8_v1r1.audit)  
- [**ipcalc** ](http://nextcloud.joust.lab/index.php/s/EpwDiTAnBfzBdis/download/ipcalc-0.2.4-4.el8.x86_64.rpm)  
- [**Network Scripts** ](http://nextcloud.joust.lab/index.php/s/cmnm67Xi3LCMzkK/download/network-scripts-10.00.15-1.el8.x86_64.rpm)  
- [**Network Scripts Team** ](http://nextcloud.joust.lab/index.php/s/t7sceHQr57BiqMz/download/network-scripts-team-1.31-2.el8.x86_64.rpm)  
- [**Read Me** ](http://nextcloud.joust.lab/index.php/s/8ZW7DspZtnwQzsw) 

### <u>**ADOBE ACROBAT PRO**</u> 
- [**Read ME** ](http://nextcloud.joust.lab/index.php/s/XRfeWWNaEZsckKW)  
- [**DOWNLOAD .TGZ** ](http://nextcloud.joust.lab/index.php/s/EnTeLbK6Qt5Bmft/download/SDC%20NIPR%20-%20Adobe%20Acrobat%20Professional%20DC%20-%20210512.zip)  

### <u>**COBALT STRIKE**</u> 
- [**DOWNLOAD .ZIP** ](http://nextcloud.joust.lab/index.php/s/R4JKbFjCX5DGeew/download/cobaltstrike-dist.zip)  
- [**DOWNLOAD .TGZ** ](http://nextcloud.joust.lab/index.php/s/beJNSoFP8oLr2TQ/download/cobaltstrike-dist.tgz)  
- [**INSTALLATION GUIDE** ](http://nextcloud.joust.lab/index.php/s/6P3gLm9WQwf8gGC/download/cobalt-strike-install.pdf)  
- [**READ ME** ](http://nextcloud.joust.lab/index.php/s/BeE26LrJnWa9MnB)  



