#!/bin/bash

sudo mkdir -p /opt/git
sudo chown $USER:$USER /opt/git
chmod 740 /opt/git

git_clone() {
  git clone https://github.com/nmap/nmap.git /opt/git/nmap
  git clone https://github.com/robertdavidgraham/masscan.git /opt/git/masscan
  git clone https://github.com/OJ/gobuster.git /opt/git/gobuster
  git clone https://github.com/assetnote/kiterunner.git /opt/git/kiterunner
  git clone https://github.com/urbanadventurer/WhatWeb.git /opt/git/WhatWeb
  git clone https://github.com/Josue87/EmailFinder.git /opt/git/EmailFinder
  git clone https://github.com/slimm609/checksec.sh.git /opt/git/checksec
  git clone https://github.com/mrschyte/nmap-converter.git /opt/git/nmap-converter
  git clone https://github.com/honze-net/nmap-bootstrap-xsl.git /opt/git/nmap-bootstrap-xsl
}

install() {
  cd /opt/git/kiterunner || (echo "folder to cd in is missing" && exit 1)
  sudo ln -s /opt/git/kiterunner/dist/kr /usr/local/bin/

  cd /opt/git/checksec || (echo "folder to cd in is missing" && exit 1)
  sudo ln -s /opt/git/checksec/checksec /usr/local/bin/

  cd /opt/git/nmap-converter.py || (echo "folder to cd in is missing" && exit 1)
  sudo ln -s /opt/git/nmap-converter/nmap-converter.py /usr/local/bin/

  cd /opt/git/wpscan || (echo "folder to cd in is missing" && exit 1)
  sudo gem install wpscan

  cd /opt/git/nmap || (echo "folder to cd in is missing" && exit 1)
  ./configure && make && sudo make install

  cd /opt/git/masscan || (echo "folder to cd in is missing" && exit 1)
  make && sudo make install

  cd /opt/git/whatweb || (echo "folder to cd in is missing" && exit 1)
  sudo make install

  cd /opt/git/gobuster || (echo "folder to cd in is missing" && exit 1)
  go get && go build && go install

  cd /opt/git/emailfinder || (echo "folder to cd in is missing" && exit 1)
  pip3 install .

  go get -u -v github.com/jaeles-project/gospider
  go get -u -v github.com/hakluke/hakrawler
  go get -u -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder
  go get -u -v github.com/OWASP/Amass/v3/...
  go get -u -v github.com/lc/gau

  sudo apt instal xsltproc
  sudo apt instal dnsutils
  sudo apt instal openssl libcurl4-openssl-dev
}

git_clone() install() exit 0
