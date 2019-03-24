# LiquidHoney
A small, fluid, low-interaction honeypot designed to spoof banners across thousands of ports. 

## Features
* Parsing and spoofing based on nmap's [nmap-service-probes](https://nmap.org/book/vscan-fileformat.html) file format.
* Support for ssl-wrapped protocols (See `create-cert.sh`)
* Hourly log rollover
* Support for UDP and TCP based protocols
* Works passively, can be used for recon/capturing in addition to being a honeypot

**Note**: 
Due to the sheer number of low-numbered ports LiquidHoney spoofs, we suggest running as root. It is possible to run 
without root access, but it will require changing the service probes file to operate on different ports, then forwarding each port manually.

## Setup
Setup is relatively simple. You will need Python 3 and pip installed to run this application.  
1. `pip install -r requirements.txt`  
2. `./create-cert.sh` to generate an SSL certificate
3. Run `sudo python3 honeypot_responder.py`
4. Watch the logs roll in!
