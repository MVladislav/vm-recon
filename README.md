# VM HACK

```sh
    MVladislav
```

---

- [VM HACK](#vm-hack)
  - [dependencies](#dependencies)
  - [install](#install)
    - [DEBUG](#debug)

---

A python wrapper to call recon services with predefined params.
_python with `setup.py` and `click` for **cli**_

## dependencies

- **[nmap](https://github.com/nmap/nmap.git)**
  > ```sh
  > $./configure && make && sudo make install
  > ```
- **[masscan](https://github.com/robertdavidgraham/masscan.git)**
  > ```sh
  > $make && sudo make install
  > ```
- **[gobuster](https://github.com/OJ/gobuster.git)**
  > ```sh
  > $go get && go build && go install
  > ```
- **[kiterunner](https://github.com/assetnote/kiterunner.git)**
  > ```sh
  > $sudo ln -s /opt/git/kiterunner/dist/kr /usr/local/bin/
  > ```
- **[whatweb](https://github.com/urbanadventurer/WhatWeb.git)**
  > ```sh
  > $sudo make install
  > ```
- **[gospider](https://github.com/jaeles-project/gospider.git)**
  > ```sh
  > $go get -u -v github.com/jaeles-project/gospider
  > ```
- **[hakrawler](https://github.com/hakluke/hakrawler.git)**
  > ```sh
  > $go get -u -v github.com/hakluke/hakrawler
  > ```
- **[emailfinder](https://github.com/Josue87/EmailFinder.git)**
  > ```sh
  > $pip3 install .
  > ```
- **[subfinder](https://github.com/projectdiscovery/subfinder.git)**
  > ```sh
  > $go get -u -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder
  > ```
- **[amass](https://github.com/OWASP/Amass.git)**
  > ```sh
  > $go get -u -v github.com/OWASP/Amass/v3/...
  > ```
- **[gau](https://github.com/lc/gau.git)**
  > ```sh
  > $go get -u -v github.com/lc/gau
  > ```
- **[wpscan](https://github.com/wpscanteam/wpscan.git)**
  > ```sh
  > $sudo gem install wpscan
  > ```
- **[checksec](https://github.com/slimm609/checksec.sh.git)**
  > ```sh
  > $sudo ln -s /opt/git/checksec/checksec /usr/local/bin/
  > ```
- **[nmap-converter.py](https://github.com/mrschyte/nmap-converter.git)**
  > ```sh
  > $sudo ln -s /opt/git/nmap-converter/nmap-converter.py /usr/local/bin/
  > ```
- **xsltproc**
  > ```sh
  > $sudo apt instal xsltproc
  > ```
- **dig**
  > ```sh
  > $sudo apt instal dnsutils
  > ```
- **host**
  > ```sh
  > $sudo apt instal dnsutils
  > ```
- **openssl**
  > ```sh
  > $sudo apt instal openssl libcurl4-openssl-dev
  > ```
- **[nmap-bootstrap-xsl](https://github.com/honze-net/nmap-bootstrap-xsl.git)**

## install

```sh
$pip3 install starlette && pip3 install .
```

### DEBUG

```sh
$python3 -m venv ./venv
$source venv/bin/activate
$pip3 install starlette && pip3 install --editable .
```
