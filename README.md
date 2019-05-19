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
1. Install nmap-service-probes. This file is under a different license (https://nmap.org/book/man-legal.html). Either of these options will work:
    * Intall nmap  
    * Download it here: https://raw.githubusercontent.com/nmap/nmap/master/nmap-service-probes.  
2. `pip install -r requirements.txt`
3. `./create-cert.sh` to generate an SSL certificate
4. Set up the iptables rules using `sudo python3 liquid_honey.py --create-rules`
5. Run the server with `python3 liquid_honey.py`
6. Watch the logs roll in!

**Note:** By default, LiquidHoney drops packets sent to the listen port from non-internal addresses, however it is highly
recommended that you block external traffic to that port (11337 by default).

## Configuration
LiquidHoney can be configured in more depth using the `config.yml` file. There are descriptions of the options in the default config.