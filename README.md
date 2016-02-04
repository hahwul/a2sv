# A2SV
Auto Scanning to SSL Vulnerability



         █████╗ ██████╗ ███████╗██╗   ██╗
        ██╔══██╗╚════██╗██╔════╝██║   ██║
        ███████║ █████╔╝███████╗██║   ██║
        ██╔══██║██╔═══╝ ╚════██║╚██╗ ██╔╝
        ██║  ██║███████╗███████║ ╚████╔╝ 
        ╚═╝  ╚═╝╚══════╝╚══════╝  ╚═══╝ 
      [Auto Scanning to SSL Vulnerability]
          [By Hahwul / www.hahwul.com]
________________________________________________

### 1. A2SV?
Auto Scanning to SSL Vulnerability.<br>
HeartBleed, CCS Injection, SSLv3 POODLE, FREAK... etc <br>
 + [OK] heartbleed
 + [OK] ccs injection
 + [DEV] SSLv3 POODLE
 + [DEV] FREAK Attack

### 2. How to Install?
git clone https://github.com/hahwul/a2sv.git<br>
cd a2sv<br>

A. run install script<br>

./install.sh<br>
<br>
or <br>
<br>
B. install python package <br>


### 3. How to Use?
usage: a2sv.py [-h] [-t T] [-p P] [-m M]

optional arguments:
  -h, --help  show this help message and exit
  -t T        Target URL/IP Address
  -p P        Custom Port / Default: 443
  -m M        Check Module

ex)
python a2sv.py -t 127.0.0.1
python a2sv.py -t 127.0.0.1 -m heartbleed
python a2sv.py -t 127.0.0.1 -p 8111

### 4. Support
Contact hahwul@gmail.com
