<img src="https://cloud.githubusercontent.com/assets/13212227/26283701/dd5b48fe-3e67-11e7-8b54-96fb31c225b1.png">

## 1. A2SV?
Auto Scanning to SSL Vulnerability.<br>
HeartBleed, CCS Injection, SSLv3 POODLE, FREAK... etc <br>
<br>
A. Support Vulnerability<br>
> [CVE-2007-1858] Anonymous Cipher<br>
> [CVE-2012-4929] CRIME(SPDY)<br>
> [CVE-2014-0160] CCS Injection<br>
> [CVE-2014-0224] HeartBleed<br>
> [CVE-2014-3566] SSLv3 POODLE<br>
> [CVE-2015-0204] FREAK Attack<br>
> [CVE-2015-4000] LOGJAM Attack<br>
> [CVE-2016-0800] SSLv2 DROWN<br>
 
B. Dev Plan<br>
> [PLAN] SSL ACCF<br>
> [PLAN] SSL Information Analysis<br>
 
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

    usage: a2sv [-h] [-t TARGET] [-tf TARGETFILE] [-p PORT] [-m MODULE]
                [-d DISPLAY] [-u] [-v]

    optional arguments:
      -h, --help            show this help message and exit
      -t TARGET, --target TARGET
                            Target URL and IP Address
                             > e.g -t 127.0.0.1
      -tf TARGETFILE, --targetfile TARGETFILE
                            Target file(list) URL and IP Address
                             > e.g -tf ./target.list
      -p PORT, --port PORT  Custom Port / Default: 443
                             > e.g -p 8080
      -m MODULE, --module MODULE
                            Check SSL Vuln with one module
                            [anonymous]: Anonymous Cipher
                            [crime]: Crime(SPDY)
                            [heart]: HeartBleed
                            [ccs]: CCS Injection
                            [poodle]: SSLv3 POODLE
                            [freak]: OpenSSL FREAK
                            [logjam]: OpenSSL LOGJAM
                            [drown]: SSLv2 DROWN
      -d DISPLAY, --display DISPLAY
                            Display output
                            [Y,y] Show output
                            [N,n] Hide output
      -o OUT, --out OUT     Result write to file
                             > e.g -o /home/yourdir/result.txt
      -u, --update          Update A2SV (GIT)
      -v, --version         Show Version


[Scan SSL Vulnerability]<br>
> python a2sv.py -t 127.0.0.1<br>
> python a2sv.py -t 127.0.0.1 -m heartbleed<br>
> python a2sv.py -t 127.0.0.1 -d n<br>
> python a2sv.py -t 127.0.0.1 -p 8111<br>
> python a2sv.py -tf target_list.txt<br>

[Update A2SV]<br>
> python a2sv.py -u<br>
> python a2sv.py --update<br>

## 4. Support
Submit New Issue(github)<br>
Contact hahwul@gmail.com
<br>

## 5. Screen shot
<img src="https://cloud.githubusercontent.com/assets/13212227/26360322/c67cc642-4012-11e7-9db3-31f25a94222d.png">
<img src="https://cloud.githubusercontent.com/assets/13212227/26360319/c6381718-4012-11e7-895f-87e5f42a8269.png">

## 6. Code Reference Site
> poodle : https://github.com/supersam654/Poodle-Checker<br>
> heartbleed : https://github.com/sensepost/heartbleed-poc<br>
> ccs injection : https://github.com/Tripwire/OpenSSL-CCS-Inject-Test<br>
> freak : https://gist.github.com/martinseener/d50473228719a9554e6a<br>


