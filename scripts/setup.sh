#!/bin/bash -e

echo ''
printf "    __  ____    ____          ___      __ \n\
   /  |/  / |  / / /___ _____/ (_)____/ /___ __   __ \n\
  / /|_/ /| | / / / __ \`/ __  / / ___/ / __ \`/ | / / \n\
 / /  / / | |/ / / /_/ / /_/ / (__  ) / /_/ /| |/ / \n\
/_/  /_/  |___/_/\__,_/\__,_/_/____/_/\__,_/ |___/\n"
echo '**************** 4D 56 6C 61 64 69 73 6C 61 76 *****************'
echo '****************************************************************'
echo '* Copyright of MVladislav, 2021                                *'
echo '* https://mvladislav.online                                    *'
echo '* https://github.com/MVladislav                                *'
echo '****************************************************************'
echo '* PROD                                                         *'
echo '****************************************************************'
echo ''

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
echo ''
echo 'setup:: path:: to install without root'
echo '--> setup:: path:: go-bin'
# SETUP:: go-bin
# Install GO to /usr/local/go/bin
export PATH=$PATH:/usr/local/go/bin

echo '--> setup:: path:: go-path'
# SETUP:: go-path
# Install GO to ~/go
export GOPATH=$HOME/go
export PATH=$GOPATH/bin:$PATH

echo '--> setup:: path:: npm'
# SETUP:: npm
# Install NPM Gems to ~/.npm-packages
NPM_PACKAGES="${HOME}/.npm-packages"
export PATH="$PATH:$NPM_PACKAGES/bin"
# Preserve MANPATH if you already defined it somewhere in your config.
# Otherwise, fall back to `manpath` so we can inherit from `/etc/manpath`.
export MANPATH="${MANPATH-$(manpath)}:$NPM_PACKAGES/share/man"

echo '--> setup:: path:: ruby'
# SETUP:: ruby
# Install Ruby Gems to ~/gems
export GEM_HOME="$HOME/gems"
export PATH="$HOME/gems/bin:$PATH"

echo '--> setup:: path:: make'
export PREFIX="$HOME/.local"

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
echo ''
echo 'init:: create base folder struct'
vm_path=$HOME/.vm_recon
vm_path_git=$vm_path/git
vm_path_source=$vm_path/deb
vm_prefix=$HOME/.local
vm_run=$HOME/.local/bin
mkdir -p "$vm_path"
mkdir -p "$vm_path_git"
mkdir -p "$vm_path_source"
mkdir -p "$vm_prefix"
mkdir -p "$vm_run"

echo ''
echo 'inst:: dependencies...'

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
echo ''
echo 'inst:: apt:: services'

# get source git by call 'apt-get download <PKG>'
cmds_to_install=(
  'https://github.com/rfc1036/whois.git whois'
  'https://salsa.debian.org/debian/curl.git curl'
  'https://salsa.debian.org/debian/grep.git grep'
  'https://salsa.debian.org/debian/jq.git jq'
  'https://salsa.debian.org/debian/openssl.git openssl'
  'https://salsa.debian.org/dns-team/bind9.git dig'
  'https://salsa.debian.org/xml-sgml-team/libxslt.git xsltproc'
)

export DESTDIR="$HOME/.local"

for cmd_to_install in "${cmds_to_install[@]}"; do
  IFS=' ' read -r -a cmd_install <<<"$cmd_to_install"
  cloned_repo=$(basename "${cmd_install[0]}" .git)
  if ! command -v "${cmd_install[1]}" &>/dev/null; then
    cd "$vm_path_source"
    echo "--> inst:: ...:: ${cmd_install[0]}"
    git clone "${cmd_install[0]}"
    cd "$cloned_repo"

    if [ -f "$PWD/configure" ]; then
      ./configure --prefix "$HOME"
    elif [ -f "$PWD/Makefile" ]; then
      echo "Makefile exists."
      export DESTDIR=$HOME
      sed -i 's/prefix = \/usr/prefix = \/\.local/g' Makefile
    fi

    # if [ -f "$PWD/Makefile" ]; then
    #   make
    #   make install
    # fi
  else
    echo "--> inst:: ...:: ${cmd_install[1]} is always installed"
  fi
done

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
echo ''
echo 'inst:: pip3:: services'
pips_to_install=(
  sqlmap
  wfuzz
  pyyaml
  pymongo
  requests
  s3recon
  fierce
  dnspython
  argparse
  ndg-httpsclient
  python-masscan
  aiodns
  aiohttp
  aiosqlite
  plotly
  aiomultiprocess
  python-libnmap
  XlsxWriter
  pywhat
  pysmb
  impacket
  pypykatz
  updog
  emailfinder
)
for pip_to_install in "${pips_to_install[@]}"; do
  echo "--> inst:: ...:: ${pip_to_install}"
  pip3 install "$pip_to_install"
done

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
echo ''
echo 'inst:: gem:: services'
gems_to_install=(
  bundler
  rails
  winrm
  winrm-fs
  stringio
  highline
  inspec-bin
  snmp
  wpscan
  evil-winrm
)
for gem_to_install in "${gems_to_install[@]}"; do
  echo "--> inst:: ...:: ${gem_to_install}"
  gem install "$gem_to_install"
done

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
echo ''
echo 'inst:: go:: services'
gos_to_install=(
  github.com/projectdiscovery//cmd/
  github.com/jaeles-project/
  github.com/lc/gau
  github.com/projectdiscovery//v2/cmd/
  github.com/OWASP/Amass/v3/...
  github.com/OJ/gobuster/v3
)
for go_to_install in "${gos_to_install[@]}"; do
  echo "--> inst:: ...:: ${go_to_install}"
  go install "${go_to_install}@latest"
done

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
echo ''
echo 'inst:: npm:: services'
npms_to_install=(asar)
for npm_to_install in "${npms_to_install[@]}"; do
  echo "--> inst:: ...:: ${npm_to_install}"
  npm install -g "$npm_to_install"
done

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
clone_or_pull_and_cd() {
  git_link=$1
  repo_name=$(basename "$git_link" .git)
  echo ''
  echo "inst:: git:: $repo_name"
  cd "$vm_path_git"

  git clone "$git_link" 2>/dev/null || (
    cd "$repo_name"
    git pull
  )
  cd "$repo_name"
}

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
clone_or_pull_and_cd "git@github.com:nmap/nmap.git"
./configure --prefix "$vm_prefix"
make
make install

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
clone_or_pull_and_cd "git@github.com:mrschyte/nmap-converter.git"
ln -sf "$PWD/nmap-converter.py" "$vm_run/nmap-converter"

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
clone_or_pull_and_cd "https://github.com/slimm609/checksec.sh.git"
ln -sf "$PWD/checksec" "$vm_run/checksec"

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
clone_or_pull_and_cd "https://github.com/CiscoCXSecurity/enum4linux.git"
ln -sf "$PWD/enum4linux.pl" "$vm_run/enum4linux"

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
clone_or_pull_and_cd "https://github.com/assetnote/kiterunner.git"
make
cd dist
wget https://wordlists-cdn.assetnote.io/data/kiterunner/routes-large.kite.tar.gz
tar -xvf routes-large.kite.tar.gz
rm routes-large.kite.tar.gz
ln -sf "$PWD/kr" "$vm_run/kr"

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
clone_or_pull_and_cd "https://github.com/urbanadventurer/WhatWeb.git"
bundle update
bundle install
ln -sf "$PWD/whatweb" "$vm_run/whatweb"

echo ''
echo '#########################################################################'
echo ''

exit 0
