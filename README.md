# HTTPS EPA Scan
Python script to scan webservers for their EPA settings. Based on [LdapRelayScan](https://raw.githubusercontent.com/zyn3rgy/LdapRelayScan).

## Installation
Ideally create a separete virtualenv
```
git clone https://github.com/Immortalem/HttpsEPAScan.git --recursive
cd HttpsEPAScan
mkvirtualenv
pip install -r requirements.txt
cd requests-ntlm
python3 setup.py install
```
Happy hacking.

## References
[LdapRelayScan](https://raw.githubusercontent.com/zyn3rgy/LdapRelayScan)
[Requests NTLM](https://github.com/requests/requests-ntlm)
