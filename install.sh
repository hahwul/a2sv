#/usr/bin/bash
echo 'Install a2sv'
echo ' -> install python package'
echo ' -> pip:argparse'
pip install argparse
echo ' -> pip:netaddr'
pip install netaddr
echo ' -> install openssl(apt)'
apt-get install openssl
echo ' -> set command'
MYPWD=`pwd`
echo '#/usr/bin/python
python '$MYPWD'/a2sv.py $*' >> /usr/bin/a2sv
echo 'Set Perm'
chmod 755 /usr/bin/a2sv
echo 'Finish. run a a2sv'
