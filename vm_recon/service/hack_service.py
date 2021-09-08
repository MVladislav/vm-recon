from pathlib import Path

import yaml

from ..cli import Context
from ..config import (SUBFINDER_CENSYS_SECRET, SUBFINDER_CENSYS_USERNAME,
                      SUBFINDER_SHODAN_API_KEY)
from ..utilities.utils import Utils

# ------------------------------------------------------------------------------
#
#
#
# ------------------------------------------------------------------------------


class HackService:

    def __init__(self, ctx: Context):
        self.ctx: Context = ctx
        self.utils: Utils = self.ctx.utils
        self.utils.logging.debug('hack-service is initiated')

    # --------------------------------------------------------------------------
    #
    #
    #
    # --------------------------------------------------------------------------

    def clone_page(self, host: str) -> None:
        service_name = 'RECON'
        self.utils.log_runBanner(service_name)
        path = self.utils.create_service_folder(f'page', host)
        self.utils.logging.debug(f'new folder created:: {path}')

        cmd_result = self.utils.run_command_output_loop(f'clone page {host}', [
            ['wget', '-r', '-nHp', host, '-P', path],
            ['tee', f'{path}/page_clone.log']
        ])

        self.utils.logging.info(f'[*] {service_name} Done! View the log reports under {path}/')

    # --------------------------------------------------------------------------
    #
    #
    #
    # --------------------------------------------------------------------------

    def recon(self, domain: str, org: str, mode: str = "gospider", threads: int = 10, depth: int = 2, ns: str = "1.1.1.1") -> None:
        service_name = 'RECON'
        self.utils.log_runBanner(service_name)
        path = self.utils.create_service_folder(f'scan/recon', domain)
        self.utils.logging.debug(f'new folder created:: {path}')

        sources = []
        if mode == 'subfinder' or mode == 'censys':
            self.utils.logging.debug('Create subfinder conf with keys...')
            subfinder_config_path = f'{self.utils.get_user_path()}/.config/subfinder'
            subfinder_config_file = 'config.yaml'

            # sources.append('bufferover')
            # sources.append('sitedossier')
            sources.append('censys')
            sources.append('shodan')
            # sources.append('Binaryedge')
            # sources.append('certspotter')
            # sources.append('Chaos')
            # sources.append('DnsDB')
            sources.append('github')
            # sources.append('Intelx')
            # sources.append('passivetotal')
            # sources.append('Recon.dev')
            # sources.append('Robtex')
            # sources.append('SecurityTrails')
            # sources.append('Spyse')
            # sources.append('Threatbook')
            sources.append('virustotal')
            # sources.append('Zoomeye')

            data = {
                'sources': sources,
                'all-sources': sources,
                'recursive': sources,
                'censys': [f'{SUBFINDER_CENSYS_USERNAME}:{SUBFINDER_CENSYS_SECRET}'],
                'shodan': [f'{SUBFINDER_SHODAN_API_KEY}'],
                # 'virustotal': [f'{TODO}'],
                # 'passivetotal': [f'{TODO},{TODO}'],
                # 'securitytrails': [f'{TODO}'],
                # 'binaryedge': [],
                # 'certspotter': [],
                # 'chaos': [],
                # 'dnsdb': [],
                # 'github': [],
                # 'intelx': [],
                # 'recon': [],
                # 'robtex': [],
                # 'spyse': [],
                # 'threatbook': [],
                # 'urlscan': [],
                # 'zoomeye': [],
            }
            Path(subfinder_config_path).mkdir(parents=True, exist_ok=True)
            with open(f'{subfinder_config_path}/{subfinder_config_file}', 'w') as file:
                yaml.dump(data, file)
                self.utils.logging.debug(f'... {subfinder_config_path}/{subfinder_config_file} ...')
                self.utils.logging.debug('... subfinder conf with keys created')

        options_1 = ['-t', str(threads), '--recursive', '-v', '-oJ', '-nW']
        options_2 = ['-t', str(threads), '--recursive', '-v', '-oJ', '-nW', '--sources', ",".join(sources)]

        if mode == "gospider":
            cmd_result = self.utils.run_command_output_loop(f'recon {mode}', [
                ['gospider', '-s', domain, '-o', f'{path}/gospider', '-c',
                    str(threads), '-d', str(depth), '--other-source', '--include-subs'],
                ['tee', f'{path}/gospider.log']
            ])
        elif mode == "hakrawler":
            cmd_result = self.utils.run_command_output_loop(f'recon {mode}', [
                ['echo', domain],
                # -h "Cookie: foo=bar;Authorization: token"
                ['hakrawler', '-d', str(depth), '-t', str(threads), '-insecure'],
                ['tee', f'{path}/hakrawler.log']
            ])
        elif mode == "emailfinder":
            cmd_result = self.utils.run_command_output_loop(f'recon {mode}', [
                ['emailfinder', '-d', domain],
                ['tee', f'{path}/emailfinder.log']
            ])
        elif mode == "subfinder":
            cmd_result = self.utils.run_command_output_loop(f'recon {mode}', [
                ['subfinder', '-d', domain, '-o', f'{path}/subfinder_rec', '-r', ns] + options_1,
                ['httpx'],
                ['tee', f'{path}/subfinder_rec.log']
            ])
        elif mode == "subfinder_api":
            cmd_result = self.utils.run_command_output_loop(f'recon {mode}', [
                ['subfinder', '-d', domain, '-o', f'{path}/subfinder_censys', '-r', ns] + options_2,
                ['tee', f'{path}/subfinder_censys.log']
            ])
        elif mode == "amass_whois":
            cmd_result = self.utils.run_command_output_loop(f'recon {mode}', [
                ['amass', 'intel', '-d', domain, '-whois', '-r', ns, '-o', f'{path}/amass_whois'],
                ['tee', f'{path}/amass_whois.log']
            ])
        elif mode == "amass_org":
            cmd_result = self.utils.run_command_output_loop(f'recon {mode}', [
                ['amass', 'intel', '-org', org, '-r', ns, '-o', f'{path}/amass_org'],
                ['tee', f'{path}/amass_org.log']
            ])
        elif mode == "passive":
            cmd_result = self.utils.run_command_output_loop(f'recon {mode}', [
                ['amass', 'enum', '-passive', '-d', domain, '-r', ns, '-o', f'{path}/amass_passive'],
                ['tee', f'{path}/amass_passive.log']
            ])
        elif mode == "active":
            cmd_result = self.utils.run_command_output_loop(f'recon {mode}', [
                ['amass', 'enum', '-active', '-src', '-ip', '-brute', '-min-for-recursive',
                    str(depth), '-d', domain, '-r', ns, '-o', f'{path}/amass_active'],
                ['tee', f'{path}/amass_active.log']
            ])
        elif mode == "gau":
            cmd_result = self.utils.run_command_output_loop(f'recon {mode}', [
                ['gau', '--subs', domain],
                ['cut', '-d', '/', '-f', '3'],
                ['sort', '-u'],
                ['tee', f'{path}/gau.log']
            ])

        self.utils.logging.info(f'[*] {service_name} Done! View the log reports under {path}/')

    # --------------------------------------------------------------------------
    #
    #
    #
    # --------------------------------------------------------------------------

    def dns(self, host: str, ns: str = "", record_type: str = "ANY", port: int = 53) -> None:
        service_name = 'DNS/DIG'
        self.utils.log_runBanner(service_name)
        path = self.utils.create_service_folder(f'scan/dig', host)
        self.utils.logging.debug(f'new folder created:: {path}')

        if ns and len(ns) > 0 and not ns.startswith("@"):
            ns = f"@{ns}"

        cmd_result = self.utils.run_command_output_loop('dig', [
            ['dig', "-p", str(port), ns, host, record_type],
            ['tee', f'{path}/dig_dns.log'],
        ])
        cmd_result = self.utils.run_command_output_loop('dig x', [
            ['dig', '-x', '-p', str(port), ns, host, record_type],
            ['tee', f'{path}/dig_dns_x.log'],
        ])
        cmd_result = self.utils.run_command_output_loop('dig spf', [
            ['dig', 'TXT', '-p', str(port), ns, host, record_type],
            ['tee', f'{path}/dig_dns_txt_spf.log'],
        ])
        cmd_result = self.utils.run_command_output_loop('dig dkmi', [
            ['dig', 'TXT', '-p', str(port), ns, f'dkmi._{host}', record_type],
            ['tee', f'{path}/dig_dns_txt_dkmi.log'],
        ])
        cmd_result = self.utils.run_command_output_loop('dig dmarc', [
            ['dig', 'TXT', '-p', str(port), ns, f'_dmarc.{host}', record_type],
            ['tee', f'{path}/dig_dns_txt_dmarc.log'],
        ])
        cmd_result = self.utils.run_command_output_loop('dig axfr', [
            ['dig', '+multi', 'AXFR', '-p', str(port), ns, host, record_type],
            ['tee', f'{path}/dig_dns_axfr_multi.log '],
        ])

        self.utils.logging.info(f'[*] {service_name} Done! View the log reports under {path}/')

        service_name = 'DNS/HOST'
        self.utils.log_runBanner(service_name)
        path = self.utils.create_service_folder(f'scan/host', host)
        self.utils.logging.debug(f'new folder created:: {path}')

        cmd_result = self.utils.run_command_output_loop('host', [
            ['host', '-aRR', host],
            ['tee', f'{path}/host.log'],
        ])

        self.utils.logging.info(f'[*] {service_name} Done! View the log reports under {path}/')

    def tls(self, domain: str) -> None:
        service_name = 'TLS'
        self.utils.log_runBanner(service_name)
        path = self.utils.create_service_folder(f'scan/tls', domain)
        self.utils.logging.debug(f'new folder created:: {path}')

        cmd_result = self.utils.run_command_output_loop('openssl [1/4]', [
            ['openssl', 's_client', '-connect', domain, '-showcerts'],
            ['tee', f'{path}/openssl_info_cert.log']
        ])
        cmd_result = self.utils.run_command_output_loop('openssl [2/4]', [
            ['openssl', 's_client', '-connect', domain],
            ['tee', f'{path}/openssl_info.log']
        ])
        cmd_result = self.utils.run_command_output_loop('openssl [3/4]', [
            ['openssl', 's_client', '-connect', domain, '</dev/null 2>/dev/null'],
            ['openssl', 'x509', '-noout', '-in', '/dev/stdin', '-text'],
            ['tee', f'{path}/openssl_text.log']
        ])
        cmd_result = self.utils.run_command_output_loop('openssl [4/4]', [
            ['openssl', 's_client', '-connect', domain, '</dev/null 2>/dev/null'],
            ['openssl', 'x509', '-fingerprint', '-noout', '-in', '/dev/stdin'],
            ['tee', f'{path}/openssl_fingerprint.log']
        ])

        self.utils.logging.info(f'[*] {service_name} Done! View the log reports under {path}/')

    # --------------------------------------------------------------------------
    #
    #
    #
    # --------------------------------------------------------------------------

    def nmap(self, host: str, udp: bool = True, ports=None,
             options: list = [], rate: int = 1000, path: str = None, silent: bool = False) -> None:
        service_name = 'NMAP'
        self.utils.log_runBanner(service_name)
        path = self.utils.create_service_folder(f'scan/namp', host) if path == None else path
        self.utils.logging.debug(f'new folder created:: {path}')

        host = host.split(" ")

        t_scan = 4
        if silent:
            rate = 100
            t_scan = 1
            for option in options:
                if "-T" in option:
                    option = f'-T{t_scan}'

        if ports == None:
            if udp:
                ports = self.utils.run_command_output_loop('nmap udp ports', [
                    ['sudo', 'nmap', '-sU', '-sT', '--max-retries=1', '-p-', f'--min-rate={rate}', f'-T{t_scan}'] + host,
                    ['grep', '^[0-9]'],
                    ['cut', '-d', '/', '-f', '1', ],
                    ['sort'],
                    ['uniq'],
                    ['tr', '\\n', ',', ],
                    ['sed', 's/,$//'],
                ])
            else:
                ports = self.utils.run_command_output_loop('nmap tcp ports', [
                    ['sudo', 'nmap', '-p-', f'--min-rate={rate}', f'-T{t_scan}'] + host,
                    ['grep', '^[0-9]'],
                    ['cut', '-d', '/', '-f', '1'],
                    ['sort'],
                    ['uniq'],
                    ['tr', '\\n', ','],
                    ['sed', 's/,$//'],
                ])

        if ports != None:
            cmd_result = self.utils.run_command_output_loop('nmap scan', [
                ['sudo', 'nmap', '-p', ports, '-oX', f'{path}/inital.xml', '-oN', f'{path}/inital.log'] + host + options
            ])

            cmd_result = self.utils.run_command_output_loop('nmap convert xls', [
                ['nmap-converter.py', f'{path}/inital.xml', '-o', f'{path}/inital.xls']
            ])
            cmd_result = self.utils.run_command_output_loop('nmap convert html', [
                ['xsltproc', f'{path}/inital.xml', '-o', f'{path}/inital.html']
            ])

            self.utils.logging.info(f'[*] {service_name} Done! View the log reports under {path}/')
        else:
            self.utils.logging.warning('[-] No ports found')

    def masscan(self, host: str, rate: int = 10000, options: list = []) -> None:
        service_name = 'MASSCAN'
        self.utils.log_runBanner(service_name)
        path = self.utils.create_service_folder(f'scan/masscan', host)
        self.utils.logging.debug(f'new folder created:: {path}')

        cmd_result = self.utils.run_command_output_loop('masscan', [
            ['sudo', 'masscan', host, '-oX', f'{path}/masscan.xml'] + options
        ])
        cmd_result = self.utils.run_command_output_loop('xsltproc', [
            ['xsltproc', '-o', f'{path}/final-masscan.html',
                '/opt/git/nmap-bootstrap-xsl/nmap-bootstrap.xsl', f'{path}/masscan.xml']
        ])
        ports = self.utils.run_command_output_loop('cat ports', [
            ['cat', f'{path}/masscan.xml'],
            ['grep', 'portid'],
            ['cut', '-d', '\"', '-f', '10'],
            ['sort', '-n'],
            ['uniq'],
            ['paste', '-sd,']
        ])

        if ports != None:
            self.utils.logging.info(f'[*] {service_name} Done! View the log reports under {path}/')
            n_options = ['-sV', '-O', f'-T{t_scan}', '-PE', '-Pn', '-n', '--open', '-vv']
            self.nmap(host=host, ports=ports, options=n_options, path=path)
        else:
            self.utils.logging.warning('[-] No ports found')

    def gobuster(self, host: str, type: str = 'dir', threads: int = 10,
                 w_list: str = None, options: list = [], exclude_length: int = None) -> None:
        service_name = 'GOBUSTER'
        self.utils.log_runBanner(service_name)
        path = self.utils.create_service_folder(f'scan/gobuster', host)
        self.utils.logging.debug(f'new folder created:: {path}')

        # wordlist = '/opt/git/SecLists/Discovery/Web-Content/big.txt' if w_list == None else w_list
        wordlist = '/opt/git/SecLists/Discovery/Web-Content/raft-medium-words.txt' if w_list == None else w_list

        if exclude_length != None:
            options + ['--exclude-length', exclude_length]

        if type == 'dir' or type == None:
            wordlist = '/opt/git/SecLists/Discovery/Web-Content/big.txt' if w_list == None else w_list
            cmd_result = self.utils.run_command_output_loop('gobuster dir', [
                ['gobuster', 'dir', '-u', host, '-w', wordlist, '-r', '-t',
                    str(threads), '-o', f'{path}/gobuster_dir'] + options,
                ['tee', f'{path}/gobuster_dir.log']
            ])
        elif type == 'vhost':
            wordlist = '/opt/git/SecLists/Discovery/DNS/subdomains-top1million-110000.txt' if w_list == None else w_list
            cmd_result = self.utils.run_command_output_loop('gobuster vhost', [
                ['gobuster', 'vhost', '-u', host, '-w', wordlist, '-r', '-t',
                    str(threads), '-o', f'{path}/gobuster_vhost'] + options,
                ['tee', f'{path}/gobuster_vhost.log']
            ])
        elif type == 'fuzz':
            # wordlist = '/opt/git/SecLists/Discovery/Web-Content/big.txt' if w_list == None else w_list
            # wordlist = '/opt/git/SecLists/Discovery/Web-Content/Apache.fuzz.txt' if w_list == None else w_list
            # wordlist = '/opt/git/SecLists/Discovery/Web-Content/ApacheTomcat.fuzz.txt' if w_list == None else w_list
            wordlist = '/opt/git/SecLists/Discovery/Web-Content/FatwireCMS.fuzz.txt' if w_list == None else w_list
            # wordlist = '/opt/git/SecLists/Discovery/Web-Content/CMS/wordpress.fuzz.txt' if w_list == None else w_list
            # wordlist = '/opt/git/SecLists/Discovery/Web-Content/CMS/wp-plugins.fuzz.txt' if w_list == None else w_list
            # wordlist = '/opt/git/SecLists/Discovery/Web-Content/CMS/wp-themes.fuzz.txt' if w_list == None else w_list
            cmd_result = self.utils.run_command_output_loop('gobuster fuzz', [
                ['gobuster', 'fuzz', '-u', host, '-w', wordlist, '-r', '-t',
                    str(threads), '-o', f'{path}/gobuster_fuzz'] + options,
                ['tee', f'{path}/gobuster_fuzz.log']
            ])
        elif type == 'dns':
            wordlist = '/opt/git/SecLists/Discovery/DNS/subdomains-top1million-110000.txt' if w_list == None else w_list
            cmd_result = self.utils.run_command_output_loop('gobuster dns', [
                ['gobuster', 'dns', '-d', host, '-w', wordlist, '-r', '-t',
                    str(threads), '-o', f'{path}/gobuster_dns'] + options,
                ['tee', f'{path}/gobuster_dns.log']
            ])
        elif type == 'bak':
            wordlist = '/opt/git/SecLists/Discovery/Web-Content/big.txt' if w_list == None else w_list
            cmd_result = self.utils.run_command_output_loop('gobuster bak', [
                ['gobuster', 'dir', '-u', host, '-w', wordlist, '-d', '-r',
                    '-t', str(threads), '-o', f'{path}/gobuster_back'] + options,
                ['tee', f'{path}/gobuster_back.log']
            ])
        else:
            self.utils.logging.warning(f'gobuster type "{type}" not defined')

        self.utils.logging.info(f'[*] {service_name} Done! View the log reports under {path}/')

    def kitrunner(self, host: str,  w_list: str = None) -> None:
        service_name = 'KITRUNNER'
        self.utils.log_runBanner(service_name)
        path = self.utils.create_service_folder(f'scan/kr', host)
        self.utils.logging.debug(f'new folder created:: {path}')

        wordlist = "/opt/git/kiterunner/routes.kite" if w_list == None else w_list
        max_connection_per_host = 10
        ignore_length = 34

        cmd_result = self.utils.run_command_output_loop('kitrunner', [
            ['kr', 'scan', host, '-w', wordlist, '-A=apiroutes-210228:20000', '-x',
                str(max_connection_per_host), f'--ignore-length={ignore_length}'],
            ['tee', f'{path}/kr_scan.log']
        ])

        self.utils.logging.info(f'[*] {service_name} Done! View the log reports under {path}/')

    # --------------------------------------------------------------------------
    #
    #
    #
    # --------------------------------------------------------------------------

    def smb(self, hosts: str, ports: str = '139,445'):
        service_name = 'SMB'
        self.utils.log_runBanner(service_name)

        for host in hosts.split(' '):
            for port in ports.split(','):
                path = self.utils.create_service_folder(f'scan/smb', host)
                self.utils.logging.debug(f'new folder created:: {path}')

                # SMBCLIENT ############################################################
                ########################################################################
                cmd_result = self.utils.run_command_output_loop('smbclient scan', [
                    ['smbclient', '-N', '-p', str(port).strip(), '-L', f'//{host}'],
                    ['tee', f'{path}/smbclient.log']
                ])

                print('')
                print('~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~')
                self.utils.logging.notice(f'use "smbclient //{host}/..." to check the results')
                self.utils.logging.notice('usefull commands "dir,get,put,..."')
                self.utils.logging.notice(f'usefull commands "smbget -R smb://{host}/..."')
                print('~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~')
                print('')

        self.utils.logging.info(f'[*] {service_name} Done! View the log reports under {path}/')

        # NMAP #################################################################
        ########################################################################
        path = self.utils.create_service_folder(f'scan/smb', hosts)
        smb_options = ['--script', 'smb-vuln-*,smb-os-discovery,smb-enum-shares.nse,smb-enum-users.nse']
        n_options = ['-sV', '-O', '-T4', '-PE', '-Pn', '-n', '--open', '-vv'] + smb_options
        self.nmap(host=hosts, ports=ports, udp=True, options=n_options, path=path, silent=False)

    def rpc(self, hosts: str, ports: str = '111'):
        service_name = 'RPC'
        self.utils.log_runBanner(service_name)
        path = self.utils.create_service_folder(f'scan/rpc', hosts)
        self.utils.logging.debug(f'new folder created:: {path}')

        # for host in hosts.split(' '):
        #     for port in ports.split(','):
        #         path = self.utils.create_service_folder(f'scan/smb', host)
        #         self.utils.logging.debug(f'new folder created:: {path}')

        #         # SMBCLIENT ############################################################
        #         ########################################################################
        #         cmd_result = self.utils.run_command_output_loop('smbclient scan', [
        #             ['smbclient', '-N', '-p', str(port).strip(), '-L', f'//{host}'],
        #             ['tee', f'{path}/smbclient.log']
        #         ])

        #         print('')
        #         print('~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~')
        #         self.utils.logging.notice(f'use "smbclient //{host}/..." to check the results')
        #         self.utils.logging.notice('usefull commands "dir,get,put,..."')
        #         print('~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~')
        #         print('')

        # self.utils.logging.info(f'[*] {service_name} Done! View the log reports under {path}/')

        # NMAP #################################################################
        ########################################################################
        rpc_options = ['--script', 'nfs-ls,nfs-statfs,nfs-showmount']
        n_options = ['-sV', '-O', '-T4', '-PE', '-Pn', '-n', '--open', '-vv'] + rpc_options
        self.nmap(host=hosts, ports=ports, udp=True, options=n_options, path=path, silent=False)

    # --------------------------------------------------------------------------
    #
    #
    #
    # --------------------------------------------------------------------------

    def whatweb(self, host: str, silent: int = 3) -> None:
        service_name = 'WHATWEB'
        self.utils.log_runBanner(service_name)
        path = self.utils.create_service_folder(f'scan/whatweb', host)
        self.utils.logging.debug(f'new folder created:: {path}')

        cmd_result = self.utils.run_command_output_loop('whatweb silent', [
            ['whatweb', host, '-a', str(silent), '-v',
             f'--log-verbose={path}/whatweb_v.log', f'--log-json={path}/whatweb_j.log']
        ])

        self.utils.logging.info(f'[*] {service_name} Done! View the log reports under {path}/')

    def wpscan(self, host: str, silent: bool = False) -> None:
        service_name = 'WPSCAN'
        self.utils.log_runBanner(service_name)
        path = self.utils.create_service_folder(f'scan/wpscan', host)
        self.utils.logging.debug(f'new folder created:: {path}')

        mode = ['--plugins-detection', 'aggressive'] if silent == False else ['--plugins-detection', 'passive']

        cmd_result = self.utils.run_command_output_loop(f'wpscan {mode}', [
            ['wpscan', '--url', host, '-e', 'ap', '-o', f'{path}/wpscan'] + mode,
            ['tee', f'{path}/wpscan.log']
        ])

        self.utils.logging.info(f'[*] {service_name} Done! View the log reports under {path}/')

    # --------------------------------------------------------------------------
    #
    #
    #
    # --------------------------------------------------------------------------

    def pwn(self, file: str) -> None:
        service_name = 'PWN'
        self.utils.log_runBanner(service_name)
        path = self.utils.create_service_folder(f'pwn/checks', file)
        self.utils.logging.debug(f'new folder created:: {path}')

        cmd_result = self.utils.run_command_output_loop(f'pwn file', [
            ['file', file],
            ['tee', f'{path}/file.log']
        ])
        cmd_result = self.utils.run_command_output_loop(f'pwn strings', [
            ['strings', '-n', '10', file],
            ['tee', f'{path}/strings.log']
        ])
        cmd_result = self.utils.run_command_output_loop(f'pwn checksec', [
            ['checksec', '--file', file],
            ['tee', f'{path}/checksec.log']
        ])

        self.utils.logging.info(f'[*] {service_name} Done! View the log reports under {path}/')

# ------------------------------------------------------------------------------
#
#
#
# ------------------------------------------------------------------------------
