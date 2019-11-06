
# LiveTargetsFinder (Coming soon)
Generates lists of live hosts and URLs for targeting, automating the usage of Massdns, Masscan and nmap to filter out unreachable hosts

Given an input file of domain names, this script will automate the usage of MassDNS to filter out unresolvable hosts, and then pass the results on to Masscan to confirm that the hosts are reachable and on which ports. The script will then generate a list of full URLs to be used for further targeting (passing into tools like gobuster or dirsearch, or making HTTP requests), a list of reachable domain names, and a list of reachable IP addresses. As an optional last step, you can run an nmap version scan on this reduced host list, verifying that the earlier reachable hosts are up, and gathering service information from their open ports.

## Overview

This script is especially useful for large domain sets, such as subdomain enumerations gathered from an apex domain with thousands of subdomains. With these large lists, an nmap scan would simply take too long. The goal here is to first use the less accurate, but much faster, MassDNS to quickly reduce the size of your input list by removing unresolvable domains. Then, Masscan will be able to take the output from MassDNS, and further confirm that the hosts are reachable, and on which ports. The script will then parse these results and generate lists of the live hosts discovered.

Now, the list of hosts should be reduced enough to be suitable for further scanning/testing. If you want to go a step further, you can tell the script to run an nmap scan on the list of reachable hosts, which should take more reasonable amount of time with the shorter list of hosts. After running nmap, any false positives given from Masscan will be filtered out. Raw nmap output will be stored in the regular nmap XML format, and additional information from the version detection will be added to a SQLite database.

![ScreenShot](https://raw.githubusercontent.com/allyomalley/LiveTargetsFinder/master/livehosts_img.png)


## Installation

**If using the nmap scan option, this tool assumes that you already have nmap installed**

*Note*: Running the install script is only needed if you do not already have MassDNS and Masscan installed, or if you would like to reinstall them inside this repo. If you do not run the script, you can provide the paths to the respective executables as arguments. The script additionally expects that the resolvers list included with MassDNS be located at ```{massDNS_directory}/lists/resolvers.txt```.

```
git clone https://github.com/allyomalley/LiveTargetsFinder.git
cd LiveTargetsFinder
sudo pip3 install -r requirements.txt
```

*(OPTIONAL)*
```
chmod +x install_deps.sh
./install_deps.sh
```

If you do not already have MassDNS and Masscan installed, and would prefer to install them yourself, see the documentation for instructions:

[MassDNS](https://github.com/blechschmidt/massdns).
[Masscan](https://github.com/robertdavidgraham/masscan).

I have only tested this script on macOS and Linux - the python script itself should work on a Windows machine, though I believe the installation for MassDNS and Masscan will differ.

## Usage

```
python3 liveTargetsFinder.py [domainList] [options]
```

| Flag | Description | Default | Required |
| --- | --- | --- |
| `--target-list` | Input file containing list of domains, e.g google.com | | Yes |
| `--massdns-path` | Path to the MassDNS executable, if not installed with this repo | *./massdns/bin/massdns* | No |
| `--masscan-path` | Path to the Masscan executable, if not installed with this repo | *./masscan/bin/masscan* | No |
| `--nmap` | Run an nmap version detection scan on the gathered live hosts, storing results in a SQLite database  | *Disabled* | No |
| `--db-path` | If using the --nmap option, supply the path to the database you would like to append to (will be created if does not exist) | *inputFilename.sqlite3* | No |


* Note that the Masscan and MassDNS settings are hardcoded inside liveTargetsFinder.py. Feel free to edit them (lines 87 + 97).
* Since this tool was designed with very large lists in mind, I tweaked many of the settings to try to balance speed, accuracy, and network constraints - these can all be adjusted to suit your needs and bandwith.
* Default settings for Masscan **only scans ports 80 and 443**. 
  - *-s*, (*--hashmap-size*) in particular was chosen for performance reasons - you will likely be able to increase this.
  - Full MassDNS arguments:
    - ```-c 25 -o J -r ./massdns/lists/resolvers.txt -s 100 -w  massdnsOutput -t A targetHosts```
    - [Documentation](https://github.com/blechschmidt/massdns)
* Another setting of note is the ```--max-rate``` argument for Masscan - you will likely want to adjust this.
  - Full Masscan arguments:
    - ```-iL  ipFile -oD  masscanOutput --open-only --max-rate 10000 -p80,443 --max-retries 10```
    - [Documentation](https://github.com/robertdavidgraham/masscan)
* Default nmap settings **only scans ports 80 and 443**, with timing -T4 and a few NSE scripts.
  - Full nmap arguments:
    - ```--script http-server-header.nse,http-devframework.nse,http-headers -sV -T4 -p80,443 -oX {output.xml}```

## Example

Did run install script:

```
python3 liveTargetsFinder.py --target-list victim_domains.txt
```

Did NOT run the install script:

```
python3 liveTargetsFinder.py --target-list victim_domains.txt --massdns-path ../massdns/bin/massdns --masscan-path ../masscan/bin/masscan 
```

Perform an nmap scan and write to/append to the default DB path (liveTargetsFinder.sqlite3)

```
python3 liveTargetsFinder.py --target-list victim_domains.txt --nmap
```

Perform an nmap scan and write to/append to the specificed database

```
python3 liveTargetsFinder.py --target-list victim_domains.txt --nmap --db-path serviceinfo_victim.sqlite3
```

## Output

Input: victimDomains.txt

| File | Description | Examples |
| --- | --- | --- |
| victimDomains_targetUrls.txt | List of reachable, live URLs | https://github.com, http://github.com |
| victimDomains_domains_alive.txt | List of live domain names | github.com, google.com |
| victimDomains_ips_alive.txt | List of live IP addresses | 10.1.0.200, 52.3.1.166 |
| *Supplied or default DB Path* | SQLite database storing live hosts and information about their services running | |
| victimDomains_massdns.txt | The raw output from MassDNS, in ndjson format | |
| victimDomains_masscan.txt | The raw output from Masscan, in ndjson format | | 
| victimDomains_nmap.txt | The raw output from nmap, in XML format | | 

