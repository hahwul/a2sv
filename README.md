
                        █████╗ ██████╗ ███████╗██╗   ██╗
                       ██╔══██╗╚════██╗██╔════╝██║   ██║
                       ███████║ █████╔╝███████╗██║   ██║
        .o oOOOOOOOo   ██╔══██║██╔═══╝ ╚════██║╚██╗ ██╔╝        OOOo
        Ob.OOOOOOOo O  ██║  ██║███████╗███████║ ╚████╔╝   .adOOOOOOO
        OboO'''''''''' ╚═╝  ╚═╝╚══════╝╚══════╝  ╚═══╝  ''''''''''OO
        OOP.oOOOOOOOOOOO 'POOOOOOOOOOOo.   `'OOOOOOOOOP,OOOOOOOOOOOB'
        `O'OOOO'     `OOOOo'OOOOOOOOOOO` .adOOOOOOOOO'oOOO'    `OOOOo
        .OOOO'            `OOOOOOOOOOOOOOOOOOOOOOOOOO'            `OO
        OOOOO                 ''OOOOOOOOOOOOOOOO'`                oOO
       oOOOOOba.                .adOOOOOOOOOOba               .adOOOOo.
      oOOOOOOOOOOOOOba.    .adOOOOOOOOOO@^OOOOOOOba.     .adOOOOOOOOOOOO
     OOOOOOOOOOOOOOOOO.OOOOOOOOOOOOOO'`  ''OOOOOOOOOOOOO.OOOOOOOOOOOOOO
     'OOOO'       'YOoOOOOMOIONODOO'`  .   ''OOROAOPOEOOOoOY'     'OOO'
        Y           'OOOOOOOOOOOOOO: .oOOo. :OOOOOOOOOOO?'         :`
        :            .oO%OOOOOOOOOOo.OOOOOO.oOOOOOOOOOOOO?         .
        .            oOOP'%OOOOOOOOoOOOOOOO?oOOOOO?OOOO'OOo
                     '%o  OOOO'%OOOO%'%OOOOO'OOOOOO'OOO':
                          `$'  `OOOO' `O'Y ' `OOOO'  o             .
        .                  .     OP'          : o     .
                                  :
                       [Auto Scanning to SSL Vulnerability]
                           [By Hahwul / www.hahwul.com]

________________________________________________
# A2SV(Auto Scanning to SSL Vulnerability v1.3.4)
## 1. A2SV?
Auto Scanning to SSL Vulnerability.<br>
HeartBleed, CCS Injection, SSLv3 POODLE, FREAK... etc <br>
<br>
A. Support Vulnerability<br>
> [CVE-2014-0160] CCS Injection<br>
> [CVE-2014-0224] HeartBleed<br>
> [CVE-2014-3566] SSLv3 POODLE<br>
> [CVE-2015-0204] FREAK Attack<br>
> [CVE-2015-4000] LOGJAM Attack<br>
 
B. Dev Plan<br>
> [DEV] DROWN Attack<br> 
> [PLAN] SSL ACCF<br>
 
## 2. How to Install?
A. Download(clone) & Unpack A2SV
> git clone https://github.com/hahwul/a2sv.git<br>
> cd a2sv<br>

B. Install Python Package / OpenSSL<br>
> pip install argparse<br>
> pip install netaddr<br>

> apt-get install openssl

C. Run A2SV<br>
> python a2sv.py -h

## 3. How to Use?
usage: a2sv.py [-h] [-t TARGET] [-p PORT] [-m MODULE] [-v]<br>
<br>
optional arguments:<br>
  -h, --help            show this help message and exit<br>
  -t TARGET, --target TARGET<br>
                        Target URL/IP Address<br>
  -p PORT, --port PORT  Custom Port / Default: 443<br>
  -m MODULE, --module MODULE<br>
                        Check Module<br>
  -u, --update          Update A2SV (GIT)<br>
  -v, --version         Show Version<br>
<br>
[Scan SSL Vulnerability]<br>
> python a2sv.py -t 127.0.0.1<br>
> python a2sv.py -t 127.0.0.1 -m heartbleed<br>
> python a2sv.py -t 127.0.0.1 -p 8111<br>

[Update A2SV]<br>
> python a2sv.py -u
> python a2sv.py --update

## 4. Support
Contact hahwul@gmail.com
<br>
## 5. Code Reference Site
> poodle : https://github.com/supersam654/Poodle-Checker<br>
> heartbleed : https://github.com/sensepost/heartbleed-poc<br>
> ccs injection : https://github.com/Tripwire/OpenSSL-CCS-Inject-Test<br>
> freak : https://gist.github.com/martinseener/d50473228719a9554e6a<br>


