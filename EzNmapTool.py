import os
import time

#This a tool that uses everything on the NMAP cheat sheet and allows you to use these scans
#Thanks to who created NMAP, which I had no part in creating
#You can use, share, and edit this code however you want
#Thanks to StationX for the cheat sheet
#Link to NMAP https://nmap.org/
#Link to the StationX cheat sheet https://www.stationx.net/nmap-cheat-sheet/

def asciiArt():
    os.system("clear")
    print("_______     _   _ __  __          _____")
    print("|  ____|   | \ | |  \/  |   /\   |  __ \\")
    print("| |__   ___|  \| | \  / |  /  \  | |__) |")
    print("|  __| |_  / . ` | |\/| | / /\ \ |  ___/")
    print("| |____ / /| |\  | |  | |/ ____ \| |")
    print("|______/___|_| \_|_|  |_/_/    \_\_|")
    time.sleep(1)
    menuSystem()

def menuSystem():
    try:
        print("Welcome to EzNMAP using NMAP the simple way")
        print("Gain all the recon you need with pre-entered commands")
        print("[1]: Target Specification")
        print("[2]: Scan Techniques")
        print("[3]: Host Discovery")
        print("[4]: Port Specification")
        print("[5]: Service and Version Detection")
        print("[6]: Timing and Performance")
        print("[7]: NSE Scripts")
        print("[8]: Firewall / IDS Evasion and Spoofing")
        print("[9]: Output")
        print("[10]: Other Useful NMAP Commands")
        print("[11]: Exit")
        NmapScanSelection = int(raw_input("Please select an option between 1-11: "))
        if NmapScanSelection == 1:
            print("You have chosen Target Specification")
            print("***STARTING***")

            targetSpecification()
        elif NmapScanSelection == 2:
            print("You have chosen Scan Techniques")
            print("***STARTING***")

            scanTechniques()
        elif NmapScanSelection == 3:
            print("You have chosen Host Discovery")
            print("***STARTING***")

            hostDiscovery()
        elif NmapScanSelection == 4:
            print("You have chosen port Specification")
            print("***STARTING***")

            portSpecification()
        elif NmapScanSelection == 5:
            print("You have chosen Service and Version Detection")
            print("***STARTING***")

            serviceAndVersionDetection()
        elif NmapScanSelection == 6:
            print("You have chosen Timing and Performance")
            print("***STARTING***")

            timingAndPerformance()
        elif NmapScanSelection == 7:
            print("You have chosen NSE Scritps")
            print("***STARTING***")

            nseScripts()
        elif NmapScanSelection == 8:
            print("You have chosen Firewall IDS Evasion and Spoofing")
            print("***STARTING***")

            firewallIdsEvasionAndSpoofing()
        elif NmapScanSelection == 9:
            print("You have chosen Output")
            print("***STARTING***")

            NMAPoutput()
        elif NmapScanSelection == 10:
            print("You have chosen Other Useful NMAP Commands")
            print("***STARTING***")

            otherUsefulNmapCommands()
        elif NmapScanSelection == 11:
            print("***Thank you for using EzNMAP***")

            print("***GOODBYE***")
            exit()
        elif NmapScanSelection >= 12:
            print("Oof")
            os.system('clear')
            menuSystem()
        else:
            print("***An ERROR occured***")
            exit()
    except KeyboardInterrupt:
            print ("\n")
            print("***Thank you for using EzNMAP***")

            print("***GOODBYE***")
            exit()

def targetSpecification():
    os.system("clear")
    print("[1]: Scan a single IP")
    print("[2]: Scan specific IPs")
    print("[3]: Scan a range")
    print("[4]: Scan a domain")
    print("[5]: Scan using CIDR notation")
    print("[6]: Scan targets from a file")
    print("[7]: Scan 100 random hosts")
    print("[8]: Exclude listed hosts")
    print("[9]: Go back")
    targetSpecificationSelection = int(raw_input("Please select an option between 1-9: "))
    if targetSpecificationSelection == 1:
        print("Scan a single IP")
        singleIP = raw_input("What IP would you like to scan? Example: [192.168.1.1]: ")
        os.system("nmap {0}".format(singleIP))
    elif targetSpecificationSelection == 2:
        print("Scan specific IPs")
        specificIps = raw_input("What specific IPs would you like to scan? Example: [192.168.1.1 192.168.2.1]: ")
        os.system("nmap {0}".format(specificIps))
    elif targetSpecificationSelection == 3:
        print("Scan a range of IPs")
        rangeIPs = raw_input("What range of IPs would you like to scan? Example: [192.168.1.1-254]: ")
        os.system("nmap {0}".format(rangeIPs))
    elif targetSpecificationSelection == 4:
        print("Scan a domain")
        domain = raw_input("What domain would you like to scan? Example: [scanme.nmap.org]: ")
        os.system("nmap {0}".format(domain))
    elif targetSpecificationSelection == 5:
        print("Scan using CIDR notation")
        cidrNotation = raw_input("What ip would you like to scan using CIDR notation? Example: [192.168.1.0/24]: ")
        os.system("nmap {0}".format(cidrNotation))
    elif targetSpecificationSelection == 6:
        print("Scan targets from a file")
        filePath = raw_input("What file would you like to use? Example: [/root/Documents/Targets.txt]: ")
        os.system("nmap -iL {0}".format(filePath))
    elif targetSpecificationSelection == 7:
        print("Scan 100 random hosts")
        rUSure = raw_input("Do you really want to do this (Y/N): ")
        if rUSure == "y" or rUSure == "Y":
            print("***STARTING***")
            os.system("nmap -iR 100")
        elif rUSure == "n" or rUSure == "N":
            print("***GOODBYE***")
            time.sleep(2)
            exit()
    elif targetSpecificationSelection == 8:
        print("Exclude listed hosts")
        excluded = raw_input("What IPs would you like to exclude? Example: [192.168.1.1]: ")
        os.system("nmap --exclude {0}".format(excluded))
    elif targetSpecificationSelection == 9:
        menuSystem()
    elif targetSpecificationSelection >= 10:
        print("Oof")
        targetSpecification()
    else:
        print("***An ERROR occured***")
        exit()

def scanTechniques():
    os.system("clear")
    print("[1]: TCP SYN port scan (Default)")
    print("[2]: TCP connect port scan (Default without root privilege)")
    print("[3]: UDP port scan")
    print("[4]: TCP ACK port scan")
    print("[5]: TCP Window port scan")
    print("[6]: TCP Maimon port scan")
    print("[7]: Go back")
    scanTechniquesSelection = int(raw_input("Please make a selection between 1-7: "))
    if scanTechniquesSelection == 1:
        print("TCP SYN port scan (Default)")
        targetIP = raw_input("Please enter the target IP. Example: [192.168.1.1]: ")
        os.system("nmap {0} -sS".format(targetIP))
    elif scanTechniquesSelection == 2:
        print("TCP connect port scan (Default without root privilege)")
        targetIP = raw_input("Please enter the target IP. Example: [192.168.1.1]: ")
        os.system("nmap {0} -sT".format(targetIP))
    elif scanTechniquesSelection == 3:
        print("UDP port scan")
        targetIP = raw_input("Please enter the target IP. Example: [192.168.1.1]: ")
        os.system("nmap {0} -sU".format(targetIP))
    elif scanTechniquesSelection == 4:
        print("TCP ACK port scan")
        targetIP = raw_input("Please enter the target IP. Example: [192.168.1.1]: ")
        os.system("nmap {0} -sA".format(targetIP))
    elif scanTechniquesSelection == 5:
        print("TCP Window port scan")
        targetIP = raw_input("Please enter the target IP. Example: [192.168.1.1]: ")
        os.system("nmap {0} -sW".format(targetIP))
    elif scanTechniquesSelection == 6:
        print("TCP Maimon port scan")
        targetIP = raw_input("Please enter the target IP. Example: [192.168.1.1]: ")
        os.system("nmap {0} -sM".format(targetIP))
    elif scanTechniquesSelection == 7:
        menuSystem()
    elif scanTechniquesSelection >= 8:
        print("Oof")
        scanTechniques()
    else:
        print("***An ERROR occured***")
        exit()

def hostDiscovery():
    os.system("clear")
    print("[1]: No Scan. List targets only")
    print("[2]: Disable port scanning")
    print("[3]: Disable host discovery. Port scan only")
    print("[4]: TCP SYN discovery on port x. Port 80 by default")
    print("[5]: TCP ACK discovery on port x. Port 80 by default")
    print("[6]: UDP discovery on port x. Port 40125 by default")
    print("[7]: ARP discovery on local network")
    print("[8]: Never do DNS resolution")
    print("[9]: Go back")
    hostDiscoverySelection = int(raw_input("Please make a selection between 1-9: "))
    if hostDiscoverySelection == 1:
        print("No Scan. List targets only")
        targetIP = raw_input("Please enter the target IP. Example: [192.168.1.1-3]: ")
        os.system("nmap {0} -sL".format(targetIP))
    elif hostDiscoverySelection == 2:
        print("Disable port scanning")
        targetIP = raw_input("Please enter the target IP. Example: [192.168.1.1/24]: ")
        os.system("nmap {0} -sn".format(targetIP))
    elif hostDiscoverySelection == 3:
        print("Disable host discovery. Port scan only")
        targetIP = raw_input("Please enter the target IP. Example: [192.168.1.1-5]: ")
        os.system("nmap {0} -Pn".format(targetIP))
    elif hostDiscoverySelection == 4:
        print("TCP SYN discovery on port x. Port 80 by default")
        targetIP = raw_input("Please enter the target IP. Example: [192.168.1.1-5]: ")
        targetPort = raw_input("Please enter targets ports. Example: [25,80,43,20]: ")
        os.system("nmap {0} -PS22-{1}".format(targetIP, targetPort))
    elif hostDiscoverySelection == 5:
        print("TCP ACK discovery on port x. Port 80 by default")
        targetIP = raw_input("Please enter the target IP. Example: [192.168.1.1-5]: ")
        targetPort = raw_input("Please enter targets ports. Example: [25,80,43,20]: ")
        os.system("nmap {0} -PA22-{1}".format(targetIP, targetPort))
    elif hostDiscoverySelection == 6:
        print("UDP discovery on port x. Port 40125 by default")
        targetIP = raw_input("Please enter the target IP. Example: [192.168.1.1-5]: ")
        os.system("nmap {0} -PU53".format(targetIP))
    elif hostDiscoverySelection == 7:
        print("ARP discovery on local network")
        targetIP = raw_input("Please enter the target IP. Example: [192.168.1.1-1/24]: ")
        os.system("nmap {0} -PR".format(targetIP))
    elif hostDiscoverySelection == 8:
        print("Never do DNS resolution")
        targetIP = raw_input("Please enter the target IP. Example: [192.168.1.1]: ")
        os.system("nmap {0} -n".format(targetIP))
    elif hostDiscoverySelection == 9:
        menuSystem()
    elif hostDiscoverySelection >= 10:
        print("Oof")
        hostDiscovery()
    else:
        print("***An ERROR occured***")
        exit()

def portSpecification():
    os.system("clear")
    print("[1]: Port scan for port x")
    print("[2]: Port range")
    print("[3]: Port scan multiple TCP and UDP ports")
    print("[4]: Port scan all ports")
    print("[5]: Port scan from service name")
    print("[6]: Fast port scan (100 ports)")
    print("[7]: Port scan the top x ports")
    print("[8]: Leaving off initial port in range makes the scan start at port 1")
    print("[9]: Leaving off end port in range makes the scan go through to port 65535")
    print("[10]: Go back")
    portSpecificationSelection = int(raw_input("Please make a selection between 1-10: "))
    if portSpecificationSelection == 1:
        print("Port scan for port x")
        targetIP = raw_input("Enter the target IP. Example: [192.168.1.1]: ")
        targetPort = raw_input("Enter the target port. Example: [80]: ")
        os.system("nmap {0} -p {1}".format(targetIP, targetPort))
    elif portSpecificationSelection == 2:
        print("Port range")
        targetIP = raw_input("Enter the target IP. Example: [192.168.1.1]: ")
        targetPort = raw_input("Enter the target port. Example: [21-100]: ")
        os.system("nmap {0} -p {1}".format(targetIP, targetPort))
    elif portSpecificationSelection == 3:
        print("Port scan multiple TCP and UDP ports")
        targetIP = raw_input("Enter the target IP. Example: [192.168.1.1]: ")
        targetUDPPort = raw_input("Enter the target UDP port(s). Example: [80]: ")
        targetTCPPort = raw_input("Enter the target TCP port(s). Example: [21-25]: ")
        os.system("nmap {0} -p U:{1},T:{2}".format(targetIP, targetUDPPort, targetTCPPort))
    elif portSpecificationSelection == 4:
        print("Port scan all ports")
        targetIP = raw_input("Enter the target IP. Example: [192.168.1.1]: ")
        os.system("nmap {0} -p-".format(targetIP))
    elif portSpecificationSelection == 5:
        print("Port scan from service name")
        targetIP = raw_input("Enter the target IP. Example: [192.168.1.1]: ")
        targetService = raw_input("Enter the target services. Example: [http,https]: ")
        os.system("nmap {0} -p {1}".format(targetIP, targetService))
    elif portSpecificationSelection == 6:
        print("Fast port scan (100 ports)")
        targetIP = raw_input("Enter the target IP. Example: [192.168.1.1]: ")
        os.system("nmap {0} -F".format(targetIP))
    elif portSpecificationSelection == 7:
        print("Port scan the top x ports")
        targetIP = raw_input("Enter the target IP. Example: [192.168.1.1]: ")
        targetPort = raw_input("Enter the top ports you want to scan. Example: [2000]: ")
        os.system("nmap {0} --top-ports {1}".format(targetIP, targetPort))
    elif portSpecificationSelection == 8:
        print("Leaving off initial port in range makes the scan start at port 1")
        targetIP = raw_input("Enter the target IP. Example: [192.168.1.1]: ")
        targetPort = raw_input("Leave off the inital port in a range and the scan will start at 1. Example: [65535]: ")
        os.system("nmap {0} -p-{1}".format(targetIP, targetPort))
    elif portSpecificationSelection == 9:
        print("Leaving off end port in range makes the scan go through to port 65535")
        targetIP = raw_input("Enter the target IP. Example: [192.168.1.1]: ")
        os.system("nmap {0} -p0-".format(targetIP))
    elif portSpecificationSelection == 10:
        menuSystem()
    elif portSpecificationSelection >= 11:
        print("Oof")
        portSpecification()
    else:
        print("***An ERROR occured***")
        exit()

def serviceAndVersionDetection():
    os.system("clear")
    print("[1]: Attempts to determine the version of the service running on port")
    print("[2]: Intensity level 0 to 9. High number increases possibility of correctness")
    print("[3]: Enable light mode. Lower possibility of correctness. Faster")
    print("[4]: Enable intensity level 9. Higher possibility of correctness. Slower")
    print("[5]: Enables OS detection, version detection, script scanning, and traceroute")
    print("[6]: Remote OS detection using TCP/IP stack fingerprinting")
    print("[7]: If at least 1 open and 1 closed TCP port are not found it will not try OS detection against host")
    print("[8]: Makes Nmap guess more aggressively")
    print("[9]: Set the maximum number x of OS detection tries against a target")
    print("[10]: Go back")
    serviceAndVersionDetectionSelection = int(raw_input("Please make a selection between 1-10: "))
    if serviceAndVersionDetectionSelection == 1:
        print("Attempts to determine the version of the service running on port")
        targetIP = raw_input("Enter the target IP. Example: [192.168.1.1]: ")
        os.system("nmap {0} -sV".format(targetIP))
    elif serviceAndVersionDetectionSelection == 2:
        print("Intensity level 0 to 9. High number increases possibility of correctness")
        targetIP = raw_input("Enter the target IP. Example: [192.168.1.1]: ")
        intensityLevel = int(raw_input("Choose a scan intensity. [0-9]: "))
        if intensityLevel >= 9 and intensityLevel < 10:
            os.system("nmap {0} -sV --version-intensity {1}".format(targetIP, intensityLevel))
        else:
            print("***NICE TRY***")
            exit()
    elif serviceAndVersionDetectionSelection == 3:
        print("Enable light mode. Lower possibility of correctness. Faster")
        targetIP = raw_input("Enter the target IP. Example: [192.168.1.1]: ")
        os.system("nmap {0} -sV --version-light".format(targetIP))
    elif serviceAndVersionDetectionSelection == 4:
        print("Enable intensity level 9. Higher possibility of correctness. Slower")
        targetIP = raw_input("Enter the target IP. Example: [192.168.1.1]: ")
        os.system("nmap {0} -sV --version-all".format(targetIP))
    elif serviceAndVersionDetectionSelection == 5:
        print("Enables OS detection, version detection, script scanning, and traceroute")
        targetIP = raw_input("Enter the target IP. Example: [192.168.1.1]: ")
        os.system("nmap {0} -A".format(targetIP))
    elif serviceAndVersionDetectionSelection == 6:
        print("Remote OS detection using TCP/IP stack fingerprinting")
        targetIP = raw_input("Enter the target IP. Example: [192.168.1.1]: ")
        os.system("nmap {0} -O".format(targetIP))
    elif serviceAndVersionDetectionSelection == 7:
        print("If at least 1 open and 1 closed TCP port are not found it will not try OS detection against host")
        targetIP = raw_input("Enter the target IP. Example: [192.168.1.1]: ")
        os.system("nmap {0} -O --osscan-limit".format(targetIP))
    elif serviceAndVersionDetectionSelection == 8:
        print("Makes Nmap guess more aggressively")
        targetIP = raw_input("Enter the target IP. Example: [192.168.1.1]: ")
        os.system("nmap {0} -O --osscan-guess".format(targetIP))
    elif serviceAndVersionDetectionSelection == 9:
        print("Set the maximum number x of OS detection tries against a target")
        targetIP = raw_input("Enter the target IP. Example: [192.168.1.1]: ")
        maxOSTries = raw_input("Enter the max detection tries against a target. Example: [1]: ")
        os.system("nmap {0} -O --max-os-tries {1}".format(targetIP, maxOSTries))
    elif serviceAndVersionDetectionSelection == 10:
        menuSystem()
    elif serviceAndVersionDetectionSelection >= 11:
        print ("Oof")
        serviceAndVersionDetection()
    else:
        print("***An ERROR occured***")
        exit()

def timingAndPerformance():
    os.system("clear")
    print("[1]: Paranoid (0) Intrusion Detection System Evasion")
    print("[2]: Sneaky (1) Intrusion Detection System Evasion")
    print("[3]: Polite (2) slows down the scan to use less bandwidth and use less target machine resources")
    print("[4]: Normal (3) which is default speed")
    print("[5]: Aggressive (4) speeds scans; assumes you are on a reasonably fast and reliable network")
    print("[6]: Insane (5) speeds scan; assumes you are on an extraordinarily fast network")
    print("[7]: Go back")
    timingAndPerformanceSelection = int(raw_input("Please make a selection between 1-6: "))
    if timingAndPerformanceSelection == 1:
        print("Paranoid (0) Intrusion Detection System Evasion")
        targetIP = raw_input("Enter the target IP. Example: [192.168.1.1]: ")
        os.system("nmap {0} -T0".format(targetIP))
    elif timingAndPerformanceSelection == 2:
        print("Sneaky (1) Intrusion Detection System Evasion")
        targetIP = raw_input("Enter the target IP. Example: [192.168.1.1]: ")
        os.system("nmap {0} -T1".format(targetIP))
    elif timingAndPerformanceSelection == 3:
        print("Polite (2) slows down the scan to use less bandwidth and use less target machine resources")
        targetIP = raw_input("Enter the target IP. Example: [192.168.1.1]: ")
        os.system("nmap {0} -T2".format(targetIP))
    elif timingAndPerformanceSelection == 4:
        print("Normal (3) which is default speed")
        targetIP = raw_input("Enter the target IP. Example: [192.168.1.1]: ")
        os.system("nmap {0} -T3".format(targetIP))
    elif timingAndPerformanceSelection == 5:
        print("Aggressive (4) speeds scans; assumes you are on a reasonably fast and reliable network")
        targetIP = raw_input("Enter the target IP. Example: [192.168.1.1]: ")
        os.system("nmap {0} -T4".format(targetIP))
    elif timingAndPerformanceSelection == 6:
        print("Insane (5) speeds scan; assumes you are on an extraordinarily fast network")
        targetIP = raw_input("Enter the target IP. Example: [192.168.1.1]: ")
        os.system("nmap {0} -T5".format(targetIP))
    elif timingAndPerformanceSelection == 7:
        menuSystem()
    elif timingAndPerformanceSelection >= 8:
        print("Oof")
        timingAndPerformance()
    else:
        print("***An ERROR occured***")
        exit()

def nseScripts():
    os.system("clear")
    print("[1]: Scan with default NSE scripts. Considered useful for discovery and safe")
    print("[2]: Scan with a single script. Example: banner")
    print("[3]: Scan with a wildcard. Example http")
    print("[4]: Scan with 2 scripts. Example http and banner")
    print("[5]: Scan default, but remove intrusive scripts")
    print("[6]: NSE script with arguments")
    print("[7]: http site map generator")
    print("[8]: Fast search for random web servers")
    print("[9]: Brute force DNS hostnames guessing subdomains")
    print("[10]: Safe SMB scripts to run")
    print("[11]: Whois query")
    print("[12]: Detect cross site scripting vulnerabilites")
    print("[13]: Check for SQL injections")
    print("[14]: Go back")
    nseScriptsSelection = int(raw_input("Please make a selection between 1-14: "))
    if nseScriptsSelection == 1:
        print("Scan with default NSE scripts. Considered useful for discovery and safe")
        targetIP = raw_input("Enter the target IP. Example: [192.168.1.1]: ")
        os.system("nmap {0} -sC".format(targetIP))
    elif nseScriptsSelection == 2:
        print("Scan with a single script. Example: banner")
        targetIP = raw_input("Enter the target IP. Example: [192.168.1.1]: ")
        chooseScript = raw_input("Enter a script name. Example: [banner]: ")
        os.system("nmap {0} --script={1}".format(targetIP, chooseScript))
    elif nseScriptsSelection == 3:
        print("Scan with a wildcard. Example http")
        targetIP = raw_input("Enter the target IP. Example: [192.168.1.1]: ")
        chooseScript = raw_input("Enter a script name. Example: [http*]: ")
        os.system("nmap {0} --script={1}".format(targetIP, chooseScript))
    elif nseScriptsSelection == 4:
        print("Scan with 2 scripts. Example http and banner")
        targetIP = raw_input("Enter the target IP. Example: [192.168.1.1]: ")
        chooseScript = raw_input("Enter multiple script name(s). Example: [http,banner]: ")
        os.system("nmap {0} --script={1}".format(targetIP, chooseScript))
    elif nseScriptsSelection == 5:
        print("Scan default, but remove intrusive scripts")
        targetIP = raw_input("Enter the target IP. Example: [192.168.1.1]: ")
        chooseScript = raw_input("""Enter a script name. Example: ["not intrusive"]: """)
        os.system("nmap {0} --script {1}".format(targetIP, chooseScript))
    elif nseScriptsSelection == 6:
        print("NSE script with arguments")
        targetIP = raw_input("Enter the target IP. Example: [192.168.1.1]: ")
        os.system("nmap --script snmp-sysdescr --script-args snmpcommunity=admin {0}".format(targetIP))
    elif nseScriptsSelection == 7:
        print("Http site map generator")
        targetURL = raw_input("Enter the target URL. Example: [scanme.nmap.org]: ")
        os.system("nmap -Pn --script=http-sitemap-generator {0}".format(targetURL))
    elif nseScriptsSelection == 8:
        print("Fast search for random web servers")
        os.system("nmap -n -Pn -p 80 --open -sV -vvv --script banner,http-title -iR 1000")
    elif nseScriptsSelection == 9:
        print("Brute force DNS hostnames guessing subdomains")
        targetDNS = raw_input("Enter the target DNS. Example: [domain.com]: ")
        os.system("nmap -Pn --script=dns-brute {0}".format(targetDNS))
    elif nseScriptsSelection == 10:
        print("Safe SMB scripts to run")
        targetIP = raw_input("Enter the target IP. Example: [192.168.1.1]: ")
        os.system("nmap -n -Pn -vv -O -sV --script smb-enum*,smb-ls,smb-mbenum,smb-os-discovery,smb-s*,smb-vuln*,smbv2* -vv {0}".format(targetIP))
    elif nseScriptsSelection == 11:
        print("Whois query")
        targetDomain = raw_input("Enter the target domain. Example: [domain.com]: ")
        os.system("nmap --script whois* {0}".format(targetDomain))
    elif nseScriptsSelection == 12:
        print("Detect cross site scripting vulnerabilites")
        targetURL = raw_input("Enter the target URL. Example: [scanme.nmap.org]: ")
        os.system("nmap -p80 --script http-unsafe-output-escaping {0}".format(targetURL))
    elif nseScriptsSelection == 13:
        print("Check for SQL injections")
        targetURL = raw_input("Enter the target URL. Example: [scanme.nmap.org]: ")
        os.system("nmap -p80 --script http-sql-injection {0}".format(targetURL))
    elif nseScriptsSelection == 14:
        menuSystem()
    elif nseScriptsSelection >= 15:
        print("Oof")
        nseScripts()
    else:
        print("***An ERROR occured***")
        exit()

def firewallIdsEvasionAndSpoofing():
    os.system("clear")
    print("[1]: Tiny fragmented IP packets. Harder for packet filters")
    print("[2]: Set your own offset size")
    print("[3]: Send scans from spoofed IPs")
    print("[4]: Scan a website from another webiste")
    print("[5]: Use given source port number")
    print("[6]: Relay connections through HTTP/SOCKS4 proxies")
    print("[7]: Appends random data to sent packets")
    print("[8]: IDS evasion scan")
    print("[9]: Go back")
    fireEvasion = int(raw_input("Please make a selection between 1-9:"))
    if fireEvasion == 1: #Tiny fragmented IP packets. Harder for packet filters
        print("Tiny fragmented IP packets. Harder for packet filters")
        targetIP = raw_input("Enter the target IP. Example: [192.168.1.1]: ")
        os.system("nmap {0} -f".format(targetIP))
    elif fireEvasion == 2: #Set your own offset size
        print("Set your own offset size")
        targetIP = raw_input("Enter the target IP. Example: [192.168.1.1]: ")
        offsetSize = raw_input("Set the offset size. Example: [32]: ")
        os.system("nmap {0} --mtu {1}".format(targetIP, offsetSize))
    elif fireEvasion == 3: #Send scans from spoofed IPs
        print("Send scans from spoofed IPs")
        decoy1 = raw_input("Decoy IP 1 Example: [192.168.245.12]: ")
        decoy2 = raw_input("Decoy IP 2 Example: [192.168.245.13]: ")
        decoy3 = raw_input("Decoy IP 3. Example: [192.168.245.1]: ")
        decoy4 = raw_input("Decoy IP 4. Example: [192.168.245.111]: ")
        targetIP = raw_input("Enter the target IP. Example: [192.168.245.123]: ")
        hostIP = raw_input("Enter the target IP. Example: [192.168.1.20]: ")
        os.system("nmap -D {0},{1},{2},{3},{4} {5}".format(decoy1, decoy2, hostIP, decoy3, decoy4, targetIP))
    elif fireEvasion == 4: #Scan a website from another webiste
        print("Scan a website from another webiste")
        targetWebsite = raw_input("Please enter the target website. [www.microsoft.com]: ")
        websiteSpoof = raw_input("Please enter the website to scan the target from. [www.facebook.com]: ")
        targetPort = raw_input("Please enter a target port number. [8080]: ")
        networkInterface = raw_input("Enter the network interface your using. [eth0]: ")
        os.system("nmap -S {0} {1} -Pn {2} -e {3}".format(websiteSpoof, targetWebsite, targetPort, networkInterface))
    elif fireEvasion == 5: #Use given source port number
        print("Use given source port number")
        targetIP = raw_input("Enter the target IP. Example: [192.168.245.123]: ")
        targetPort = raw_input("Please enter a target port number. [8080]: ")
        os.system("nmap -g {0} {1}".format(targetPort, targetIP))
    elif fireEvasion == 6: #Relay connections through HTTP/SOCKS4 proxies
        print("Relay connections through HTTP/SOCKS4 proxies")
        proxies = raw_input("Enter any proxies being used. (Commas in between URLs if multiple): ")
        targetIP = raw_input("Enter the target IP. Example: [192.168.245.123]: ")
        os.system("nmap --proxies {0} {1}".format(proxies, targetIP))
    elif fireEvasion == 7: #Appends random data to sent packets
        print("Appends random data to sent packets")
        randData = raw_input("Enter a data length to send. [200]: ")
        targetIP = raw_input("Enter the target IP. Example: [192.168.245.123]: ")
        os.system("nmap --data-length {0} {1}".format(randData, targetIP))
    elif fireEvasion == 8: #IDS evasion scan
        print("IDS evasion scan")
        decoy1 = raw_input("Decoy IP 1 Example: [192.168.245.12]: ")
        decoy2 = raw_input("Decoy IP 2 Example: [192.168.245.13]: ")
        decoy3 = raw_input("Decoy IP 3. Example: [192.168.245.1]: ")
        decoy4 = raw_input("Decoy IP 4. Example: [192.168.245.111]: ")
        targetIP = raw_input("Enter the target IP. Example: [192.168.245.123]: ")
        hostIP = raw_input("Enter the target IP. Example: [192.168.1.20]: ")
        os.system("nmap -f -t 0 -n -Pn -data-length 200 -D {0},{1},{2},{3},{4} {5}".format(decoy1, decoy2, hostIP, decoy3, decoy4, targetIP))
    elif fireEvasion == 9:
        menuSystem()
    elif fireEvasion >= 10:
        print("Oof")
        firewallIdsEvasionAndSpoofing()
    else:
        print("***An ERROR occured***")
        exit()

def NMAPoutput():
    os.system("clear")
    print("[1]: Normal output to the file normal.file")
    print("[2]: XML output to the file xml.file")
    print("[3]: Grepable output to the file grep.file")
    print("[4]: Output in the three major formats at once")
    print("[5]: Grepable output to screen.")
    print("[6]: Append a scan to a previous scan file")
    print("[7]: Display the reason a port is in a particular state, same output as -vv")
    print("[8]: Only show open (or possibly open) ports")
    print("[9]: Show all packets sent and received")
    print("[10]: Shows the host interfaces and routes")
    print("[11]: Resume a scan")
    print("[12]: Scan for web servers and grep to show which IPs are running web servers")
    print("[13]: Generate a list of the IPs of live hosts")
    print("[14]: Compare output from nmap using the ndif")
    print("[15]: Convert nmap xml files to html files")
    print("[16]: Reverse sorted list of how often ports turn up")
    print("[17]: Go back")
    outputChoice = int(raw_input("Please make a selection between 1-17: "))
    if outputChoice == 1:
        print("Normal output to the file normal.file")
        targetIP = raw_input("Enter the target IP. Example: [192.168.245.123]: ")
        filePath = raw_input("What file would you like to use? Example: [/root/Documents/normal.file]: ")
        os.system("nmap {0} -oN {1}".format(targetIP, filePath))
    elif outputChoice == 2:
        print("XML output to the file xml.file")
        targetIP = raw_input("Enter the target IP. Example: [192.168.245.123]: ")
        filePath = raw_input("What file would you like to use? Example: [/root/Documents/xml.file]: ")
        os.system("nmap {0} -oX {1}".format(targetIP, filePath))
    elif outputChoice == 3:
        print("Grepable output to the file grep.file")
        targetIP = raw_input("Enter the target IP. Example: [192.168.245.123]: ")
        filePath = raw_input("What file would you like to use? Example: [/root/Documents/grep.file]: ")
        os.system("nmap {0} -oG {1}".format(targetIP, filePath))
    elif outputChoice == 4:
        print("Output in the three major formats at once")
        targetIP = raw_input("Enter the target IP. Example: [192.168.245.123]: ")
        os.system("nmap {0} -oA results".format(targetIP))
    elif outputChoice == 5:
        print("Grepable output to screen.")
        targetIP = raw_input("Enter the target IP. Example: [192.168.245.123]: ")
        os.system("nmap {0} -oG".format(targetIP))
    elif outputChoice == 6:
        print("Append a scan to a previous scan file")
        targetIP = raw_input("Enter the target IP. Example: [192.168.245.123]: ")
        filePath = raw_input("What file would you like to use? Example: [/root/Documents/grep.file]: ")
        os.system("nmap {0} -oN {1} --append-output")
    elif outputChoice == 7:
        print("Display the reason a port is in a particular state.")
        targetIP = raw_input("Enter the target IP. Example: [192.168.245.123]: ")
        os.system("nmap {0} --reason".format(targetIP))
    elif outputChoice == 8:
        print("Only show open (or possibly open) ports")
        targetIP = raw_input("Enter the target IP. Example: [192.168.245.123]: ")
        os.system("nmap {0} --open".format(targetIP))
    elif outputChoice == 9:
        print("Show all packets sent and received")
        targetIP = raw_input("Enter the target IP. Example: [192.168.245.123]: ")
        os.system("nmap {0} -T4 --packet-trace".format(targetIP))
    elif outputChoice == 10:
        print("Shows the host interfaces and routes")
        os.system("nmap -iflist")
    elif outputChoice == 11:
        print("Resume a scan")
        filePath = raw_input("What file would you like to use? Example: [/root/Documents/MyScan.file]: ")
        os.system("nmap --resume {0}".format(filePath))
    elif outputChoice == 12:
        print("Scan for web servers and grep to show which IPs are running web servers")
        targetIP = raw_input("Enter the target IP. Example: [192.168.245.123]: ")
        os.system("nmap -p80 -sV -oG- --open {0}/24 | grep open".format(targetIP))
    elif outputChoice == 13:
        print("Generate a list of the IPs of live hosts")
        filePath = raw_input("Where would you like this file? Example: [/root/Documents/MyScan.file]: ")
        os.system("""nmap -iR 10 -n -oX {0} | grep "Nmap" | cut -d "" -f5 > live-hosts.txt""".format(filePath))
    elif outputChoice == 14:
        print("Compare output from nmap using the ndif")
        filePath = raw_input("Please enter a file path to a scan? Example: [/root/Documents/MyScan.xml]: ")
        filePath2 = raw_input("Enter a file to compare file1 to? Example: [/root/Documents/MyScan2.xml]: ")
        os.system("ndiff {0} {1}".format(filePath, filePath2))
    elif outputChoice == 15:
        print("Convert nmap xml files to html files")
        filePath = raw_input("Please enter a file path to a scan? Example: [/root/Documents/MyScan.xml]: ")
        filePath2 = raw_input("Enter a file to compare file1 to? Example: [/root/Documents/MyScan2.html]: ")
        os.system("xsltproc {0} -o {1}".format(filePath, filePath2))
    elif outputChoice == 16:
        print("Reverse sorted list of how often ports turn up")
        filePath = raw_input("Please enter a file path to a scan? Example: [/root/Documents/MyScan.xml]: ")
        os.system("""grep " open " {0} | sed -r 's/ +//g' | sort | uniq -c | sort -rn | less""".format(filePath))
    elif outputChoice == 17:
        menuSystem()
    elif outputChoice >= 18:
        print("Oof")
        NMAPoutput()
    else:
        print("***An ERROR occured***")
        exit()


def otherUsefulNmapCommands():
    os.system("clear")
    print("[1]: Arp discovery only on local network, no port scan")
    print("[2]: Traceroute to random targets, no port scan")
    print("[3]: Query the Internal DNS for hosts, list targets only")
    print("[4]: Go back")
    otherUsefulSelection = int(raw_input("Please enter a choice between 1-4: "))
    if otherUsefulSelection == 1:
        print("Arp discovery only on local network, no port scan")
        targetIP = raw_input("Enter the target IP. Example: [192.168.245.123]: ")
        os.system("nmap {0}/24 -PR -sn -vv".format(targetIP))
    elif otherUsefulSelection == 2:
        print("Traceroute to random targets, no port scan")
        os.system("nmap -iR 10 -sn -traceroute")
    elif otherUsefulSelection == 3:
        print("Query the Internal DNS for hosts, list targets only")
        targetIP = raw_input("Enter the target IP. Example: [192.168.245.123]: ")
        targetDNSServer = raw_input("Enter the IP for target DNS server. Example: [192.168.1.1]: ")
        os.system("nmap {0}-50 -sL --dns-server {1}".format(targetIP, targetDNSServer))
    elif otherUsefulSelection == 4:
        menuSystem()
    elif otherUsefulSelection >= 5:
        print("Oof")
        otherUsefulNmapCommands()
    else:
        print("***An ERROR occured***")
        exit()

asciiArt()
