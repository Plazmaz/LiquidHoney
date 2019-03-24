# LiquidHoney
A small, fluid, low-interaction honeypot designed to spoof banners across thousands of ports. 

## Features
* Parsing and spoofing based on nmap's [nmap-service-probes](https://nmap.org/book/vscan-fileformat.html) file format.
* Support for ssl-wrapped protocols (See `create-cert.sh`)
* Hourly log rollover
* Support for UDP and TCP based protocols
* Works passively, can be used for recon/capturing in addition to being a honeypot
* Does not require root after setup

**Note**:   
While LiquidHoney will attempt to register iptables rules redirecting ports to itself, you may need to do this manually if
iptables is not present or is not usable. 

## Setup
Setup is relatively simple. You will need Python 3 and pip installed to run this application.  
1. `pip install -r requirements.txt`
2. `./create-cert.sh` to generate an SSL certificate
3. Install the iptables rules using `sudo python3 liquid_honey.py ----create-rules`
4. Run the server with `python3 liquid_honey.py`
5. Watch the logs roll in!
