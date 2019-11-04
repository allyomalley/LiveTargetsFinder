# LiveTargetsFinder (Coming soon)
Generates lists of live hosts and URLs for targeting, automating the usage of Massdns and Masscan to filter out unreachable hosts

Given an input file of domains names, this script will automate the usage of massDNS to filter out unresolvable hosts, and then pass the results on to masscan to confirm that the hosts are reachable and on which ports. The script will then generate a list of full URLs to be used for further targeting (passing into tools like gobuster or dirsearch, or making HTTP requests), a list of reachable domain names, and a list of reachable IP addresses.

This script is especially useful for large domain sets, such as subdomain enumerations gathered from an apex domain with thousands of subdomains. With these large lists, an nmap scan would simply take too long. massDNS is incredibly fast, but can also occasionally return innacurate results. Therefore, the resolvable hosts found by massDNS will next be passed to masscan, both to verify that the hosts are indeed reachable, and to determine which ports are open. 

The script will then parse these results and generate ready to go lists of the live hosts discovered.

![ScreenShot](https://raw.githubusercontent.com/allyomalley/LiveTargetsFinder/master/livehosts_img.png)


## Installation

*Note*: Running the install script is only needed if you do not already have massDNS and masscan installed, or if you would like to reinstall them inside this repo. If you do not run the script, you can provide the paths to the respective executables as arguments. The script additionally expects that the resolvers list included with massDNS to be located at '{massDNS_directory}/lists/resolvers.txt'.

```
git clone https://github.com/allyomalley/LiveTargetsFinder.git
cd LiveTargetsFinder
sudo pip install -r requirements.txt
./install_deps.sh (OPTIONAL)
```

## Usage

```
Usage: python3 liveTargetsFinder.py [domainList] [options]
```

| Flag | Description | Required |
| --- | --- | --- |
| `--target-list` | Input file containing list of domains, e.g google.com | Yes |
| `--massdns-path` | Path to the massdns executable, if not installed with this repo (Default: ../massdns/bin/massdns) | No |
| `--masscan-path` | Path to the masscan executable, if not installed with this repo (Default: ../masscan/bin/masscan) | No |

* Note that the masscan and massDNS settings are hardcoded inside liveTargetsFinder.py. Feel free to edit them (lines 87 + 97).
* Default settings for masscan **only scans ports 80, 443, and 8080**. 
* Another setting of note is the ```--max-rate``` argument for masscan - you will likely want to adjust this.


## Output

Input: victimDomains.txt

| File | Description | Example |
| --- | --- | --- |
| victimDomains_targetUrls.txt | List of reachable, live URLs | https://github.com |
| victimDomains_domains_alive.txt | List of live domain names | github.com |
| victimDomains_ips_alive.txt | List of live IP addresses | 10.1.0.200 |
| victimDomains_massdns.txt | The raw output from massDNS, in ndjson format | |
| victimDomains_masscan.txt | The raw output from masscan, in ndjson format | | 

## Example

Did run install script:

```
python3 liveTargetsFinder.py --target-list victim_domains.txt
```

Did NOT run the install script:

```
python3 liveTargetsFinder.py --target-list victim_domains.txt --massdns-path massdns/bin/massdns --masscan-path masscan/bin/masscan 
```
