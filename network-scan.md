# Network Scan

## <mark style="color:red;">Automatic Network Scan</mark>

### <mark style="color:blue;">Mynmap</mark>

Here's a very simple bash script I made myself. It is designed to automate the configuration and execution of port scans on a specified domain or IP address. The code is written to be run on Linux systems and requires the Nmap package to function correctly.

{% embed url="https://github.com/Astaruf/mynmap" %}

<details>

<summary>Usage</summary>

Mandatory arguments:

```bash
-t, --target <TARGET_IP>     #The IP address of the target to scan.
-d, --domain <DOMAIN_NAME>   #The domain name of the target to scan.
```

Optional arguments:

```bash
-nc, --no-colors             #Disable console coloring.
```

Examples:

```bash
./port-scan.sh -t 192.168.1.1 -d mydomain.com
./port-scan.sh -t 10.0.0.2 -d mydomain.com --no-colors
```

</details>

### <mark style="color:blue;">NmapAutomator</mark>

The main goal for this script is to automate the process of enumeration and recon that is run every time, and instead focus our attention on real pentesting.

{% embed url="https://github.com/21y4d/nmapAutomator" %}

## <mark style="color:red;">Manual Network Scan</mark>

### <mark style="color:blue;">Nmap</mark>

Nmap large scan

```bash
nmap -sVC -sS -sU -T4 -p- <IP_RANGE> -oG output.txt
```

Grep nmap output to search for live hosts

```bash
grep Up ping-sweep.txt | cut -d " " -f 2
```

Search for nse script for nmap:

```bash
cd /usr/share/nmap/scripts/
head -n 5 script.db
cat script.db  | grep '"vuln"\|"exploit"'
```

Use --script vuln to run all scripts in the "vuln" category against a target in the PWK labs:

```bash
sudo nmap --script vuln 10.11.1.10
```

### <mark style="color:blue;">Netcat</mark>

Netcat UDP scan

```bash
nc -nv -u -z -w 1 10.11.1.0/24 1-65535
```

Netcat TCP scan

```bash
nc -nvv -w 1 -z 10.11.1.0/24 1-65535
```

### <mark style="color:blue;">Masscan</mark>

Masscan&#x20;

```bash
sudo masscan -p80 10.11.1.0/24 --rate=1000 -e tap0 --router-ip 10.11.0.1
```
