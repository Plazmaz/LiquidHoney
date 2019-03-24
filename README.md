# LiquidHoney
A small, fluid, low-interaction honeypot designed to spoof banners across thousands of ports. 
## Features
* Parsing and spoofing based on nmap's [nmap-service-probes](https://nmap.org/book/vscan-fileformat.html) file format.
* Support for ssl-wrapped protocols (See `create-cert.sh`)
* Hourly log rollover
* Supports for UDP and TCP based protocols
