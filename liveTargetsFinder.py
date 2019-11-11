import json
import argparse
import subprocess
from pathlib import Path
import colorama
from colorama import Fore
from libnmap.process import NmapProcess
from libnmap.parser import NmapParser, NmapParserException
import sqlite3
import re

def parseMassDNS(filepath):
    domain_map = {}
    seenDomains = []
    with open(filepath) as f:
        for line in f:
            response = json.loads(line)
            if (response['resp_type'] == 'A'):
                domain = response['query_name']
                ip  = response['data']
                if (ip not in domain_map.keys()):
                    if domain.endswith('.'):
                        domain = domain[:-1]
                    if (domain not in seenDomains):
                        domain_map[ip] = domain
                        seenDomains.append(domain)
    return domain_map

def parseMasscan(masscan, domain_map):
    nmapInput = []
    targetUrls = []
    with open(masscan) as f:
        for line in f:
            response = json.loads(line)
            if (response['data']['status'] == 'open'):
                ip  = response['ip']
                port = response['port']
                if (ip in domain_map.keys()):
                    domain = domain_map[ip]
                    url = ""
                    if (port == 443):
                        url = 'https://' + domain
                    elif (port == 80):
                        url = 'http://' + domain
                    else:
                        url = 'http://' + domain + ":" + str(port)
                    
                    if (url not in targetUrls):
                        targetUrls.append(url)
                        nmapInput.append(domain)
    return targetUrls, nmapInput

def writeMassDNSOutput(domain_map, domainOutput, ipOutput):
    foundCount = 0
    domainFile = open(domainOutput, 'w')
    ipFile = open(ipOutput, 'w')

    for ip, domain in domain_map.items():
        foundCount += 1
        domainFile.write(domain)
        domainFile.write('\n')
        ipFile.write(ip)
        ipFile.write('\n')
    
    domainFile.close()
    ipFile.close()
    print(Fore.GREEN + "\n - Found " + Fore.YELLOW + str(foundCount) + Fore.GREEN + " resolvable domain/IP pairs")

def writeMasscanOutput(urls, outputFile):
    urlFile = open(outputFile, 'w')
    for targetUrl in urls:
        urlFile.write(targetUrl)
        urlFile.write('\n')
    
    urlFile.close()

def generateUrls(masscan, domain_map, urlOutput):
    try:
        targetUrls, nmapInput = parseMasscan(masscan, domain_map)
        writeMasscanOutput(targetUrls, urlOutput)
        print(Fore.GREEN + "\n - Wrote " + Fore.YELLOW + str(len(targetUrls)) + Fore.GREEN + " live URLs for targeting")
        return targetUrls, nmapInput
    except Exception as e:
        print("\033[91m" + "\033[1m" + "\nError - Unable to generate URL list")

def processMasscan(ipFile, domain_map, masscanOutput, masscanPath, urlOutput):
    print(Fore.BLUE + "\n - Starting masscan...")
    subprocess.run([masscanPath, '-iL', ipFile, '-oD', masscanOutput, '--open-only', '--max-rate', '5000', '-p80,443', '--max-retries', '10'])
    targetUrls, nmapInput = generateUrls(masscanOutput, domain_map, urlOutput)
    return nmapInput

def processMassDNS(targetHosts, massdnsOutput, massdnsPath, resolversPath, domainOutput, ipOutput):
    print(Fore.BLUE + "\n - Starting massdns...")
    subprocess.run([massdnsPath, '-c', '25', '-o', 'J', '-r', resolversPath if resolversPath != "" else './massdns/lists/resolvers.txt', '-s', '100', '-w', massdnsOutput, '-t', 'A', targetHosts])
    print(Fore.BLUE + "\n - Massdns complete, parsing results...")
    domain_map = parseMassDNS(massdnsOutput)
    writeMassDNSOutput(domain_map, domainOutput, ipOutput)
    return domain_map

def writeToDatabase(data, dbOutputPath):
    con = sqlite3.connect(dbOutputPath)
    cur = con.cursor()
    sqlInit = ''' CREATE TABLE IF NOT EXISTS targets (
      domain text PRIMARY KEY,
      port text NOT NULL,
      banner text,
      http_devframework text,
      x_powered_by text,
      http_server_header text
      )
      '''
    cur.execute(sqlInit)

    insertSql = "INSERT INTO targets(domain,port,banner,http_devframework,x_powered_by,http_server_header) VALUES (?,?,?,?,?,?)"
    checkExistsSql = "SELECT domain FROM targets WHERE domain = ?"
    insertCursor = con.cursor()
    checkCursor = con.cursor()

    for info in data:
        checkCursor.execute(checkExistsSql, (info["domain"],))
        row = checkCursor.fetchone()
        if row is not None:
            continue
        else:
            try:
                insertCursor.execute(insertSql, (info["domain"], info["port"], info["banner"], info["http-devframework"], info["X-Powered-By"], info["http-server-header"]))
            except Exception as e:
                print("DB Exception:")
                print(e)

    con.commit()

def updateListsWithNmapResults(nmapLiveHosts, nmapOutput):
    outputPrefix = nmapOutput.rsplit('/',1)[-1]
    outputPrefix = outputPrefix.replace(".xml", "")
    outputPrefix = outputPrefix.replace("_nmap", "")
    targetsList = "output/" + outputPrefix + "_targetUrls.txt"
    writeMasscanOutput(nmapLiveHosts, targetsList)

def parseNmapOutput(nmapOutput, hosts):
    result = []
    nmapLiveHosts = []
    report = NmapParser.parse_fromfile(nmapOutput)
    for host in report.hosts:
        hostRow = {"domain": "", "port": "", "banner": None, "http-devframework": None, "X-Powered-By": None, "http-server-header": None}
        ip = host.address
        if len(host.hostnames) != 0:
            hostname = host.hostnames[0]
            hostRow["domain"] = hostname
            if host.is_up():
                for p in host.get_open_ports():
                    if p[0] == 80:
                        url = "http://" + hostname
                    else:
                        url = "https://" + hostname
                    nmapLiveHosts.append(url)

                for s in host.services:
                    if (s.open()):
                        serviceName = ""
                        hostRow["port"] = s.port                    
                        if (len(s.scripts_results) > 0):
                            for script in s.scripts_results:
                                if ("id" not in script.keys() or "output" not in script.keys()):
                                    break
                                if (script["id"] == "http-devframework" and "detected" in script["output"]):
                                    hostRow[script["id"]] = script["output"]
                                elif script["id"] == "http-server-header":
                                    hostRow[script["id"]] = script["output"]
                                elif script["id"] == "http-headers":
                                    header = re.search('X-Powered-By:.*', script["output"], re.IGNORECASE)
                                    if (header):
                                        hostRow["X-Powered-By"] = header.group(0)
                        if (s.banner):
                            hostRow["banner"] = s.banner

        result.append(hostRow)

    updateListsWithNmapResults(nmapLiveHosts, nmapOutput)
    return result

def performVersionScan(nmapInput, nmapOutput, dbOutputPath):
    print(Fore.BLUE + "\n - Starting nmap scan...")
    scanner = NmapProcess(targets=nmapInput, options="--script http-server-header.nse,http-devframework.nse,http-headers -sV -T4 -p80,443 -oX " + nmapOutput, safe_mode=False)
    scanner.run()
    print(Fore.BLUE + "\n - Finished nmap scan!")
    data = parseNmapOutput(nmapOutput, nmapInput)
    writeToDatabase(data, dbOutputPath)

def writeFinalOutput(domainOutput, ipOutput, targetUrlsOutput, dbOutput, nmapOutput, massdnsOutput, masscanOutput):
    print("\u001b[38;5;46m" + "\u001b[1m" + "\n Done!")
    print("\u001b[38;5;200m" + '\n******************************************\n')
    print(" " + "\u001b[38;5;39m" + "\u001b[4m" + "Generated Files:\n")

    print("  Live domains: " + "\u001b[38;5;46m" + "\u001b[1m" + domainOutput)
    print("  Live IP addresses: " + "\u001b[38;5;46m" + "\u001b[1m" + ipOutput)
    print("  Live URLs: " + "\u001b[38;5;46m" + "\u001b[1m" + targetUrlsOutput)
    if (dbOutput != ""):
        print("  SQLite Database: " + "\u001b[38;5;46m" + "\u001b[1m" + dbOutput)
    print("\n\n")
    print(" " + "\u001b[38;5;39m" + "\u001b[4m" + "Raw Output:\n")
    print("  massdns: " + "\033[91m" + "\033[1m" + massdnsOutput)
    print("  masscan: " + "\033[91m" + "\033[1m" + masscanOutput)
    if (nmapOutput != ""):
        print("  nmap: " + "\033[91m" + "\033[1m" + nmapOutput)
    print("\u001b[38;5;200m" + '\n******************************************\n')



def main(targetHosts, massdnsPath, masscanPath, resolvers, useNmap, dbOutput):

        outputPrefix = targetHosts.rsplit('/',1)[-1]
        outputPrefix = outputPrefix.replace(".txt", "")

        # MassDNS Parsed output files
        domainOutput = "output/" + outputPrefix + "_domains_alive.txt"
        ipOutput = "output/" + outputPrefix + "_ips_alive.txt"
        massdnsOutput = "output/" + outputPrefix + "_massdns.txt"
        masscanOutput = "output/" + outputPrefix + '_masscan.txt'
        urlOutput = "output/" + outputPrefix + "_targetUrls.txt"

        # Run massDNS on the supplied host list
        domain_map = processMassDNS(targetHosts, massdnsOutput, massdnsPath, resolvers, domainOutput, ipOutput)

        # Run masscan on the live addresses collected from massdns
        nmapInput = processMasscan(ipOutput, domain_map, masscanOutput, masscanPath, urlOutput)
        
        nmapOutput = "" 
        if useNmap:
            if (dbOutput == ""):
                dbOutput = "output/" + "liveTargetsFinder.sqlite3"
            nmapOutput = "output/" + outputPrefix + '_nmap.xml'

            # Perform an nmap version scan
            performVersionScan(nmapInput, nmapOutput, dbOutput)
        writeFinalOutput(domainOutput, ipOutput, urlOutput, dbOutput, nmapOutput, massdnsOutput, masscanOutput)
        exit(0)


if __name__ == "__main__":
    colorama.init(autoreset=True)
    parser = argparse.ArgumentParser(
        description="LiveTargetsFinder",
    )

    parser.add_argument(
        '--target-list',
        help='Input file containing list of domains, e.g google.com',
        type=str,
        required=True
    )

    parser.add_argument(
        '--massdns-path',
        help='Path to the MassDNS executable, if not installed with this repo',
        type=str
    )
    parser.add_argument(
        '--masscan-path',
        help='Path to the Masscan executable, if not installed with this repo',
        type=str
    )

    parser.add_argument(
        '--nmap',
        dest='useNmap',
        help='Run an nmap version detection scan on the gathered live hosts, storing results in a SQLite database',
        action="store_true",
    )
    parser.add_argument(
        '--db-path',
        help='If using the --nmap option, supply the path to the database you would like to append to (will be created if does not exist)',
        type=str
    )

    args = parser.parse_args()
    if args.target_list:
        targetHosts = args.target_list
        massdnsPath = ""
        masscanPath = ""
        resolvers = ""
        dbOutputPath = ""

        massdnsPath = args.massdns_path if args.massdns_path else './massdns/bin/massdns'
        if not Path(massdnsPath).exists():
            print("\033[91m" + "\033[1m" + "\nError" + " - Unable to locate the MassDNS binary.")
            print(Fore.RED + 'Expected location: ' + str(Path(massdnsPath).resolve()) + "\n")
            exit(0)
        massdnsPath = str(Path(massdnsPath).resolve())

        traversedResolversPath = Path(massdnsPath + "/../../lists/resolvers.txt").resolve()
        if not traversedResolversPath.exists():
            print("\033[91m" + "\033[1m" + "\nError - Unable to locate the MassDNS resolvers list.")
            print(Fore.RED + "Expected location: " + str(traversedResolversPath) + "\n")
            exit(0)
        resolvers = str(traversedResolversPath)
        
        masscanPath = args.masscan_path if args.masscan_path else './masscan/bin/masscan'
        if not Path(masscanPath).exists():
            print("\033[91m" + "\033[1m" + "\nError - Unable to locate the Masscan binary.")
            print(Fore.RED + "Expected location: " + str(Path(masscanPath).resolve()) + "\n")
            exit(0)
        masscanPath = str(Path(masscanPath).resolve())
        
        useNmap = args.useNmap
        if (args.db_path):
            dbOutputPath = args.db_path

        main(targetHosts, massdnsPath, masscanPath, resolvers, useNmap, dbOutputPath)
    else:
        print("\033[91m" + "\033[1m" + "Error: Supply the domain list with the --target-list flag")
        exit(0)
