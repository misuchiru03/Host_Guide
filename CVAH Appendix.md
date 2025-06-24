# CVAH Appendix

## Appendix A

### Linux Configuration Commands
| Steps | Commands |
|---|---|
|Setting/Chaning hostname | hostnamecctl set-hostname <hostname>
|Firewall Setup:(editor: vi, vim, nano, gedit)  <br /> - /etc/target.hosts (DAL, targets, range) <br /> - /etc/trusted.host (MIP,, DIP, etc) <br /> - /etc/exclude.hosts (No-Strike List) | <br /> - sudo vi /etc/tarhet.host <br > - sudo vi /etc/trusted.hosts <br /> - sudo vi /etc/exclude.hosts |  
|Setting Firewall exceptions <br /> - -tt(utilizes all 3 .hosts files) <br /> - -it <port(s)> (inbound tcp allowed on those ports) <br /> - -ot <port(s)> (outbound tcp allowed on those ports) <br /> - -iu <port(s)> (inbound udp allowed on those ports) <br /> -ou <port(s)> (outbound udp allowed on those ports) <br /> - -ih (inbound dhosts - utilizes trusted.hosts) <br /> - -eh (exclude hosts 0 utilizes exclude.hosts) <br /> - -oh (outbound hosts - utilizes target.hosts) | <br /> - sudo set_firewall -tt -it <port,port,port> <br /> <br /> Note: All 3 hosts files MUST exist for this command syntax to work; otherwise, it defaults to a wide-open firewall (**CRITICAL**) |  
|Viewing firewalll exceptions | - sudo nft list table ip filter |  
|Network settings | Use GUI to set ip address, gateway, and dns | 
|Verification: <br /> - Hostname (name of host) <br /> - Network settings (ip and subnet) <br /> Routing settings (gateway)  <br /> Domain Name service (DNS) <br /> - Firewall |



