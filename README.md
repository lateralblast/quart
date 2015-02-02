![alt tag](https://raw.githubusercontent.com/lateralblast/quart/master/quart.gif)

QUART
=====

QUalysguard Analysis Report Tool

A Ruby script to process QualysGuardEnterprise Suite Vulnerability Scan PDF report

Introduction
------------

This Ruby script can be used to search extract useful information out of the
QualysGuardEnterprise Suite Vulnerability Scan PDF report.

The main intention behind this script is to save time by not having to manually
extract information out of the PDF file. It can also dump the information into
a spreadsheet for simplifying the process of attending to the list of vulnerabilities.

License
-------

This software is licensed as CC-BA (Creative Commons By Attrbution)

http://creativecommons.org/licenses/by/4.0/legalcode

Features
--------

- Search for host
- Search for a tag (e.g. RESULTS)
- Search for a specific term (e.g. Vulnerability)
- Search for a specific QID
- Search for a specific CVE ID
- Search for a specific Bugtraq ID
- Search for a specific CVVS level
- Search for a specific Asset Group
- Search for a specific Status
- Search for a specific PCI vulnerability state
- Search for a specific OS
- Output to CVS
- Output to XLS
- Mask customer data

Packages
--------

Required Ruby Gems:

- rubygems
- pdf-reader
- getopt/long
- writeexcel

Usage
-----

```
$ quart.rb --help

Usage: quart.rb

"--help",       "-h"  Display usage information
"--version",    "-V"  Display version information
"--dump",       "-d"  Dump data from PDF to text
"--mask",       "-m"  Mask customer data
"--exploits",   "-X"  List of vulnerable servers listed by vulnerability
"--exploit",    "-x"  List of vulnerable servers listed by vulnerability
"--input",      "-i"  Input file
"--output",     "-o"  Output file
"--format",     "-f"  Output format (default is text)
"--host",       "-h"  Search for host
"--tag",        "-t"  Search for a tag (e.g. RESULTS)
"--search",     "-s"  Search for a specific term (e.g. Vulnerability)
"--qid",        "-q"  Search for a specific QID
"--cveid",      "-c"  Search for a specific CVE ID
"--bugtraqid",  "-b"  Search for a specific Bugtraq ID
"--cvvs",       "-C"  Search for a specific CVVS level
"--group",      "-g"  Search for a specific Asset Group
"--status",     "-S"  Search for a specific Status
"--pci",        "-p"  Search for a specific PCI vulnerability state
"--os",         "-O"  Search for a specific OS
```

Examples
--------

```
$ ./quart.rb --input=/Users/spindler/Documents/Results.pdf --tag="Hosts" --exploit="Degree of Randomness of TCP Initial Sequence Numbers" --mask
Searching for tag:  Hosts
Masking customer data
Searching for Vulnerability: Degree of Randomness of TCP Initial Sequence Numbers
Setting output type to: txt
Setting input file to:  /Users/spindler/Documents/Results.pdf
Vulnerability: Degree of Randomness of TCP Initial Sequence Numbers
Hosts:
host0
host1
host2
...
```

```
$ ./quart.rb --input=/Users/spindler/Documents/Results.pdf --exploits
EOL/Obsolete Software SNMP Version Detected
Writeable SNMP Information
IPMI 2.0 RAKP Authentication Remote Password Hash Retrieval Vulnerability
SSL Server Allows Cleartext Communication Vulnerability
How to Control the Ciphers for SSL and TLS on IIS
Null Session/Password NetBIOS Access
NTP "monlist"  Feature Denial of Service Vulnerability
...
```
