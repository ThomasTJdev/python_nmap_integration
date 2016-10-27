#!/bin/bash
#
# Script for faster predefined nmap scans
#


#The colour
cyan='\e[0;36m'
green='\e[0;34m'
okegreen='\033[92m'
lightgreen='\e[1;32m'
white='\e[1;37m'
red='\e[1;31m'
yellow='\e[1;33m'
BlueF='\e[1;34m'


# Required arguments
typeofscan=$1
ip=$2

clear

echo ""
echo "      _   __                            _____                                        _         __  "
echo "     / | / /____ ___   ____ _ ____     / ___/ _____ ____ _ ____   _____ _____ _____ (_)____   / /_ "
echo "    /  |/ // __  __ \ / __  // __ \    \__ \ / ___// __  // __ \ / ___// ___// ___// // __ \ / __/ "
echo "   / /|  // / / / / // /_/ // /_/ /   ___/ // /__ / /_/ // / / /(__  )/ /__ / /   / // /_/ // /_   "
echo "  /_/ |_//_/ /_/ /_/ \__ _//  ___/   /____/ \___/ \__ _//_/ /_//____/ \___//_/   /_//  ___/ \__/   "
echo "                          /_/                                                      /_/             "


# ================= #
#    Scan type
# ================= #
function scantype() {    

echo -e $okegreen"  #======= SCAN INITIATED =======#"
echo -e $okegreen"  [*]"$white":: Scan initiated "
sleep 1

# Scan type
case "$typeofscan" in
    1)
        echo -e $okegreen"  [+]"$white"::[ Scantype ]: Intense scan"
        SCAN="-T4 -A -v"
        ;;

    2)
        echo -e $okegreen"  [+]"$white"::[ Scantype ]: Intense scan plus UDP"
        SCAN="-sS -sU -T4 -A -v"
        ;;

    3)
        echo -e $okegreen"  [+]"$white"::[ Scantype ]: Instense scan, all TCP ports"
        SCAN="-p 1-65535 -T4 -A -v"
        ;;

    4)
        echo -e $okegreen"  [+]"$white"::[ Scantype ]: Intense scan, no ping"
        SCAN="-T4 -A -v -Pn"
        ;;

    5)
        echo -e $okegreen"  [+]"$white"::[ Scantype ]: Ping scan"
        SCAN="-sn"
        ;;

    6)
        echo -e $okegreen"  [+]"$white"::[ Scantype ]: Quick scan"
        SCAN="-T4 -F"
        ;;

    7)
        echo -e $okegreen"  [+]"$white"::[ Scantype ]: Quick scan plus"
        SCAN="-sV -T4 -O -F --version-light"
        ;;

    8)
        echo -e $okegreen"  [+]"$white"::[ Scantype ]: Quick traceroute"
        SCAN="-sn --traceroute"
        ;;

    9)
        echo -e $okegreen"  [+]"$white"::[ Scantype ]: Normal scan"
        SCAN=""
        ;;

    10)
        echo -e $okegreen"  [+]"$white"::[ Scantype ]: Slow comprehensive scan"
        SCAN='-sS -sU -T4 -A -v -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 --script "default or (discovery and safe)"'
        ;;

    11)
        echo -e $okegreen"  [+]"$white"::[ Scantype ]: OS detection"
        SCAN="-O"
        ;;

    12)
        echo -e $okegreen"  [+]"$white"::[ Scantype ]: OS detection limit"
        SCAN="-O --osscan-limit"
        ;;

    13)
        echo -e $okegreen"  [+]"$white"::[ Scantype ]: HTTP service information"
        SCAN="--script=http-title --script=http-headers"
        ;;

    14)
        echo -e $okegreen"  [+]"$white"::[ Scantype ]: Service detection"
        SCAN="-sV"
        ;;

    *)
        echo -e $red"  [+]"$yellow"::[ Scantype ]: Wrong scan type arguments."
        echo "Exiting"
        exit 1
        ;;
esac

# DST ip
if [ -z "$ip" ]; then
    echo "No target specificed"
    echo "Exiting"

    exit 1

else
    DST=$ip
fi

arguments # Go to function

}


# ================= #
#   Arguments
# ================= #
function arguments() {

# Arguments
for var in "$@"
do
case "$var" in

    #====================#
    # Optional arguments #
    #====================#
    save)
        tmpSAVE=$(echo "$var" | sed -e 's#.*save-\(\)#\1#')
        echo "Argument: Save to file (XML), Name: $tmpSAVE"
        argSAVE="-oX $tmpSAVE"
        ;;

    defscript)
        echo "Argument: Using default scripts"
        argDEFSCRIPT="-sC"
        ;;

    decoy)
        echo "Argument: Decoy - random ip's (20 rnd)"
        argDECOY="-D RND:20"
        ;;

    data-*)
        tmpDATA=$(echo "$var" | sed -e 's#.*data-\(\)#\1#')
        echo "Argument: Append data to packets ($tmpDATA bytes)"
        argDATA="--data-length $tmpDATA"
        ;;

    random)
        echo "Argument: Randomize order"
        argRANDOM="--randomize-hosts"
        ;;

    mac)
        echo "Argument: Spoof MAC"
        argMAC="--spoof-mac 0"
        ;;

    badsum)
        echo "Argument: Bad checksums"
        argBADSUM="--badsum"
        ;;

    zombie)
        tmpZOMBIE=$(echo "$var" | sed -e 's#.*zombie-\(\)#\1#')
        echo "Argument: Idle zombie scan (zombie: $tmpZOMBIE)"
        argZOMBIE="-sI $tmpZOMBIE"
        ;;

    sourceport-*)
        tmpPORT=$(echo "$var" | sed -e 's#.*sourceport-\(\)#\1#')
        echo "Argument: Change source port (port: $tmpPORT)"
        argSOURCEPORT="--source-port $tmpPORT"
        ;;

    verbose-*)
        tmpVERBOSE=$(echo "$var" | sed -e 's#.*verbose-\(\)#\1#')
        echo "Argument: Verbose level $tmpVERBOSE"
        if test $tmpVERBOSE == '1'; then
            argVERBOSE3="-v"
        elif test $tmpVERBOSE == '2'; then
            argVERBOSE3="-vv"
        elif test $tmpVERBOSE == '3'; then
            argVERBOSE3="-vvv"
        else
            echo -e $yellow ""
            echo -e $yellow "  -- Wrong verbose input --"
            echo -e $yellow "  Only verbose level 1, 2 and 3 are allowed"
            echo -e $yellow ""
            exit 1
        fi
        ;;

    port-*)
        tmpPORT=$(echo "$var" | sed -e 's#.*port-\(\)#\1#')
        echo "Argument: Scanning specific port (port: $tmpPORT)"
        argPORT="-p $tmpPORT"
        ;;

    #==================#
    # Optional scripts #
    #==================#
    s-bfdns)
        echo "Script: DNS bruteforce"
        scrBFDNS="-p 80 --script dns-brute.nse"
        ;;

    s-hostsip)
        echo "Script: Find hosts on ip"
        scrHOSTSIP="-p 80 --script hostmap-bfk.nse"
        ;;

    s-trgeo)
        echo "Script: Traceroute geolocation"
        scrTRGEO="--traceroute --script traceroute-geolocation.nse -p 80"
        ;;

    s-bfpath)
        echo "Script: Bruteforce path"
        scrBFPATH="--script http-enum"
        ;;

    *)
#        echo "Arguments: WRONG arguments"

esac
done

scannow # Go to function

}

# ================= #
#    Scan
# ================= #
function scannow() {
    
# Run
NMAPCOMMAND="nmap $SCAN $argSAVE $argDEFSCRIPT $argDECOY $argDATA $argRANDOM $argMAC $argBADSUM $argZOMBIE $argSOURCEPORT $argVERBOSE3 $argPORT $DST"
tmpCOM=$(echo "$NMAPCOMMAND" | sed -e 's/  */ /g' -e 's/^ *\(.*\) *$/\1/')
echo -e $okegreen"  [+]"$white"::[ Command  ]: $tmpCOM"
#echo -e $okegreen"  [+]"$white"::[ Command  ]: $NMAPCOMMAND" | sed -e 's/  */ /g' -e 's/^ *\(.*\) *$/\1/'
echo -e $okegreen"  [*]"$white":: Scanning "
echo ""
sudo nmap $SCAN $argSAVE $argDEFSCRIPT $argDECOY $argDATA $argRANDOM $argMAC $argBADSUM $argZOMBIE $argSOURCEPORT $argVERBOSE3 $argPORT $scrBFDNS $scrHOSTSIP $srcTRGEO $srcBFPATH $DST | sed  's/^/   /'

echo ""
echo ""
echo -e $okegreen"  #======= SCAN COMPLETED =======#"
echo ""
}


# ================= #
#   Requirements check
# ================= #
function checkreq() {

echo ""
echo ""
echo -e $red"  #==== CHECKING REQUIREMENTS ====#"

ping -c 1 google.com > /dev/null 2>&1
if [ "$?" != 0 ]; then
    echo -e $okegreen"  [✔]"$white"::[ Internet Connection ]: "$okegreen"DONE!"
    echo -e $red"  [x]"$white"::[ warning ]: "$red"No internet connection. Only LAN scans"
    sleep 1
else
    echo -e $okegreen"  [✔]"$white"::[ Internet Connection ]: "$okegreen"Connected!"
    sleep 1
fi

which nmap > /dev/null 2>&1
if [ -d $find ]; then
    echo -e $okegreen"  [✔]"$white"::[ Nmap ]: "$okegreen"Installation found!"
    sleep 1
else
   echo -e $red"  [x]"$white"::[ warning ]: "$red"This script require Nmap "
   echo ""
   sleep 2
   exit 1
fi

echo -e $okegreen"  #======= REQUIREMENTS OK =======#"

echo -e $white ""
echo -e $white ""
}



# ================= #
#       Info
# ================= #
if [[ ! "$typescan" && ! "$ip" ]]; then
    echo ""
    echo ""
    echo " Script wrapped around nmap for quick scanning"
    echo ""
    echo ""
    echo -e $BlueF" == EXAMPLES =="
    echo -e $white"  Example: "$okegreen"sudo ./nmap.sh 1 192.168.1.1 "$red"save"
    echo -e $white"  Example: "$okegreen"sudo ./nmap.sh 1 192.168.1.1 "$red"save data-25 verbose3"
    echo -e $white"  Example: "$okegreen"sudo ./nmap.sh {scantype} {target ip} "$red"{arguments}"
    echo ""
    echo ""
    echo -e $BlueF" == REQUIRED ARGUMENTS =="
    echo -e $white"  1 argument: "$okegreen"scan type"
    echo -e $white"  2 argument: "$okegreen"target ip"
    echo ""
    echo ""
    echo -e $BlueF" == SCAN TYPES == "
    echo -e $okegreen"  1) "$white"Intense scan"
    echo -e $okegreen"  2) "$white"Intense scan plus UDP"
    echo -e $okegreen"  3) "$white"Intense scan, all TCP ports"
    echo -e $okegreen"  4) "$white"Intense scan, all TCP ports"
    echo -e $okegreen"  5) "$white"Ping scan"
    echo -e $okegreen"  6) "$white"Quick scan"
    echo -e $okegreen"  7) "$white"Quick scan plus"
    echo -e $okegreen"  8) "$white"Quick traceroute"
    echo -e $okegreen"  9) "$white"Regular scan"
    echo -e $okegreen"  10) "$white"Slow comprehensive scan"
    echo -e $okegreen"  11) "$white"OS detection"
    echo -e $okegreen"  12) "$white"OS detection limit"
    echo -e $okegreen"  13) "$white"HTTP Service Information"
    echo -e $okegreen"  14) "$white"Service detection"
    echo ""
    echo ""
    echo -e $BlueF" == OPTIONAL ARGUMENTS == "
    echo -e $red"  save-{name}         "$white"= Save results to XML for zenmap import"
    echo -e $red"  defscript           "$white"= Use default scripts"
    echo -e $red"  decoy               "$white"= Randomize SRC ip"
    echo -e $red"  data-{bytesize}     "$white"= Append data to packets (avoiding firewall detection)"
    echo -e $red"  random              "$white"= Randomize host and port order (avoiding firewall detection)"
    echo -e $red"  mac                 "$white"= Spoof MAC address (random)"
    echo -e $red"  badsum              "$white"= Bad checksum, this might give a failure in scan (avoiding firewall detection)"
    echo -e $red"  zombie-{target ip}  "$white"= Idle zombie scan. Find a idle device, e.g. printer, and use as a host"
    echo -e $red"  sourceport-{port}   "$white"= Use other port for scan, might fail. Common ports 20,53 and 67."
    echo -e $red"  verbose3            "$white"= Verbose level 3"
    echo -e $red"  port-{port}         "$white"= Scan specific port"
    echo ""
    echo ""
    echo -e $BlueF" == OPTIONAL SCRIPTS =="
    echo -e $red"  s-bfdns             "$white"= Find sub-domains. The dns-brute.nse script will find valid DNS (A) records by trying a list of common sub-domains and finding those that successfully resolve. (port 80 used)"
    echo -e $red"  s-hostsip           "$white"= Find virtual hosts on an IP address (port 80 used)"
    echo -e $red"  s-trgeo             "$white"= Traceroute ip (port 80 used)"
    echo -e $red"  s-bfpath            "$white"= Brute forces a web server path (WARNING NOT STEALTHY)"
    echo ""
    echo ""
    echo -e $red"  \033[4mnmap@scanscript:\033[0m "
    echo -e $yellow"    No input"
    echo ""
    echo -e $yellow"  -- EXITING --"
    echo ""
    exit 1
else
    checkreq # Check requirements function
    scantype # Scan start
fi
