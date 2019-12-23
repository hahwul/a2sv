[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](https://opensource.org/licenses/MIT)
<img src="https://cloud.githubusercontent.com/assets/13212227/26283701/dd5b48fe-3e67-11e7-8b54-96fb31c225b1.png">

## 1. A2SV?
Auto Scanning to SSL Vulnerability.

HeartBleed, CCS Injection, SSLv3 POODLE, FREAK... etc 



A. Support Vulnerability
```
- CVE-2007-1858] Anonymous Cipher
- CVE-2012-4929] CRIME(SPDY)
- CVE-2014-0160] CCS Injection
- CVE-2014-0224] HeartBleed
- CVE-2014-3566] SSLv3 POODLE
- CVE-2015-0204] FREAK Attack
- CVE-2015-4000] LOGJAM Attack
- CVE-2016-0800] SSLv2 DROWN
```
 
B. Dev Plan
```
- PLAN] SSL ACCF
- PLAN] SSL Information Analysis
```
## 2. How to Install?
A. Download(clone) & Unpack A2SV
```
$ git clone https://github.com/hahwul/a2sv.git
$ cd a2sv
```
B. Install Python Package / OpenSSL

```
$ pip install argparse
$ pip install netaddr

$ apt-get install openssl
```
C. Run A2SV

```
$ python a2sv.py -h
```
## 3. How to Use?
```
usage: a2sv [-h] [-t TARGET] [-tf TARGETFILE] [-p PORT] [-m MODULE]
[-d DISPLAY] [-u] [-v]

optional arguments:
  -h, --helpshow this help message and exit
  -t TARGET, --target TARGET
Target URL and IP Address
 $ e.g -t 127.0.0.1
  -tf TARGETFILE, --targetfile TARGETFILE
Target file(list) URL and IP Address
 $ e.g -tf ./target.list
  -p PORT, --port PORT  Custom Port / Default: 443
 $ e.g -p 8080
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
  -o OUT, --out OUT Result write to file
 $ e.g -o /home/yourdir/result.txt
  -u, --update  Update A2SV (GIT)
  -v, --version Show Version

```
[Scan SSL Vulnerability]

```
$ python a2sv.py -t 127.0.0.1

$ python a2sv.py -t 127.0.0.1 -m heartbleed

$ python a2sv.py -t 127.0.0.1 -d n

$ python a2sv.py -t 127.0.0.1 -p 8111

$ python a2sv.py -tf target_list.txt

```
[Update A2SV]

```
$ python a2sv.py -u

$ python a2sv.py --update

```
## 4. Support
The answer is very slow because it's a project that I could't careful about.

## 5. Donate

I like coffee! I'm a coffee addict.<br>
<a href="https://www.paypal.me/hahwul"><img src="https://www.paypalobjects.com/digitalassets/c/website/logo/full-text/pp_fc_hl.svg" height="50px"></a>
<a href="https://www.buymeacoffee.com/hahwul"><img src="https://cdn.buymeacoffee.com/buttons/default-black.png" alt="Buy Me A Coffee" height="50px"></a>

## 6. Screen shot
<img src="https://cloud.githubusercontent.com/assets/13212227/26360322/c67cc642-4012-11e7-9db3-31f25a94222d.png">
<img src="https://cloud.githubusercontent.com/assets/13212227/26360319/c6381718-4012-11e7-895f-87e5f42a8269.png">

## 7. Code Reference Site
```
- poodle : https://github.com/supersam654/Poodle-Checker

- heartbleed : https://github.com/sensepost/heartbleed-poc

- ccs injection : https://github.com/Tripwire/OpenSSL-CCS-Inject-Test

- freak : https://gist.github.com/martinseener/d50473228719a9554e6a
