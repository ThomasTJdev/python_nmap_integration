Script wrapped around nmap for quick scanning
=============================================

Examples
--------
  Example: sudo ./nmap.sh 1 192.168.1.1 save  
  Example: sudo ./nmap.sh 1 192.168.1.1 save data-25 verbose3  
  Example: sudo ./nmap.sh {scantype} {DST IP} {arguments}  


Required arguments
------------------
  1 argument: scan type  
  2 argument: target ip  


Scan types
----------
  1) Intense scan  
  2) Intense scan plus UDP  
  3) Intense scan, all TCP ports  
  4) Intense scan, all TCP ports  
  5) Ping scan  
  6) Quick scan  
  7) Quick scan plus  
  8) Quick traceroute  
  9) Regular scan  
  10) Slow comprehensive scan  
  11) OS detection  
  12) OS detection limit  
  13) HTTP Service Information  
  14) Service detection  


Optional arguments
------------------
  save                = Save results to XML for zenmap import  
  defscript           = Use default scripts  
  decoy               = Randomize SRC ip  
  data-[bytesize]     = Append data to packets (avoiding firewall detection)  
  random              = Randomize host and port order (avoiding firewall detection)  
  mac                 = Spoof MAC address (random)  
  badsum              = Bad checksum, this might give a failure in scan (avoiding firewall detection)  
  zombie-[target ip]  = Idle zombie scan. Find a idle device, e.g. printer, and use as a host  
  sourceport-[port]   = Use other port for scan, might fail. Common ports 20,53 and 67.  
  verbose3            = Verbose level 3  
  port-[port]         = Scan specific port  


Optional scripts
----------------
  s-bfdns             = Find sub-domains. The dns-brute.nse script will find valid DNS (A) records by trying a list of common sub-domains and finding those that successfully resolve. (port 80 used)  
  s-hostsip           = Find virtual hosts on an IP address (port 80 used)  
  s-trgeo             = Traceroute ip (port 80 used)  
  s-bfpath            = Brute forces a web server path (WARNING NOT STEALTHY)  

