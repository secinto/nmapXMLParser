<h1 align="center">nmapXMLParser</h1>
<h4 align="center">Nmap XML output parser/converter</h4>
<p align="center">
  
  <img src="https://img.shields.io/github/watchers/secinto/nmapXMLParser?label=Watchers&style=for-the-badge" alt="GitHub Watchers">
  <img src="https://img.shields.io/github/stars/secinto/nmapXMLParser?style=for-the-badge" alt="GitHub Stars">
  <a href="https://twitter.com/skraxberger"><img src="https://img.shields.io/twitter/follow/pdiscoveryio.svg?logo=twitter"></a>
  <img src="https://img.shields.io/github/license/secinto/nmapXMLParser?style=for-the-badge" alt="GitHub License">
</p>

Developed by Jake Miller - https://twitter.com/LaconicWolf/  
Updated and extended by Stefan Kraxberger - https://twitter.com/skraxberger/  

Released as open source by secinto GmbH - https://secinto.com/  
Released under Apache License version 2.0 see LICENSE for more information

Description
----
Converts Nmap XML output to JSON or CSV files, and other useful functions. Ignores hosts that are down and ports that are not open.
Prints the parsed IP and port combinations in different formats

## Usage

### Convert Nmap output to JSON (exactly JSON line format) file
`python3 nmapXMLParser.py -f nmap_scan.xml -json nmap_scan.json`

### Convert Nmap output to CSV file
`python3 nmapXMLParser.py -f nmap_scan.xml -csv nmap_scan.csv`

### Display scan information to the terminal
`python3 nmapXMLParser.py -f nmap_scan.xml -p`

### Display only IP addresses
`python3 nmapXMLParser.py -f nmap_scan.xml -ip`

### Display IP addresses/ports in host friendly format
> Displays in format ipaddr:port 

`python3 nmapXMLParser.py -f nmap_scan.xml -pip`

### Display IP addresses/ports in URL friendly format
> Displays in format http(s)://ipaddr:port if port is a possible web port

`python3 nmapXMLParser.py -f nmap_scan.xml -pw`

### Display least common open ports
> Displays the 10 least common open ports

`python3 nmapXMLParser.py -f nmap_scan.xml -lc 10`

### Display most common open ports
> Displays the 10 most common open ports

`python3 nmapXMLParser.py -f nmap_scan.xml -mc 10`

### Display only IP addresses with a specified open port
> Displays only IP addresses where port 23 is open

`python3 nmapXMLParser.py -f nmap_scan.xml -fp 23`
