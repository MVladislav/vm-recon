# VM RECON

```sh
    MVladislav
```

---

- [VM RECON](#vm-recon)
  - [dependencies](#dependencies)
  - [setups](#setups)
    - [use install(ed) without root](#use-installed-without-root)
    - [nmap without root `(--privileged)`](#nmap-without-root---privileged)
  - [install](#install)
    - [DEBUG `(PREFERRED)`](#debug-preferred)
  - [code quality and git](#code-quality-and-git)
    - [pre-commit](#pre-commit)
    - [manual test run](#manual-test-run)

---

A python wrapper to call recon services with predefined params.
_python with `setup.py` and `click` for **cli**_

## dependencies

- **[nmap](https://github.com/nmap/nmap.git)**
- **[masscan](https://github.com/robertdavidgraham/masscan.git)**
- **[gobuster](https://github.com/OJ/gobuster.git)**
- **[kiterunner](https://github.com/assetnote/kiterunner.git)**
- **[whatweb](https://github.com/urbanadventurer/WhatWeb.git)**
- **[gospider](https://github.com/jaeles-project/gospider.git)**
- **[hakrawler](https://github.com/hakluke/hakrawler.git)**
- **[emailfinder](https://github.com/Josue87/EmailFinder.git)**
- **[subfinder](https://github.com/projectdiscovery/subfinder.git)**
- **[amass](https://github.com/OWASP/Amass.git)**
- **[gau](https://github.com/lc/gau.git)**
- **[wpscan](https://github.com/wpscanteam/wpscan.git)**
- **[checksec](https://github.com/slimm609/checksec.sh.git)**
- **[nmap-converter.py](https://github.com/mrschyte/nmap-converter.git)**
- **xsltproc**
- **dig**
- **host**
- **openssl**
- **[nmap-bootstrap-xsl](https://github.com/honze-net/nmap-bootstrap-xsl.git)**
- ...

## setups

on run `pip` `install`, it will run **setup script** under `./scripts`
which will install dependencies and useful tools for recon+

### use install(ed) without root

copy ... from `scripts/vm_recon_path.sh` into `~/.bashrc` or `~/.zshrc`

### nmap without root `(--privileged)`

```sh
$sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)
```

## install

```sh
$python3 -m pip install .
# $pip3 install .
```

### DEBUG `(PREFERRED)`

```sh
$mkdir -p "$HOME/.vm_recon"
$python3 -m venv "$HOME/.vm_recon/venv"
$source "$HOME/.vm_recon/venv/bin/activate"
$python3 -m pip install -v -e .
# $pip3 install -v --editable .
```

---

## code quality and git

### pre-commit

run:

```sh
$git config --local core.hooksPath .git/hooks
$pre-commit install
```

### manual test run

```sh
$mypy app
$flake8 app
$pytest --cov=tests
$tox
```
