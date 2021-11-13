import logging
import os
import sys
from pathlib import Path
from typing import Any, List, Union

import yaml

from ..utils.config import (SUBFINDER_CENSYS_SECRET, SUBFINDER_CENSYS_USERNAME,
                            SUBFINDER_SHODAN_API_KEY)
from ..utils.defaultLogBanner import log_runBanner
from ..utils.utils import Context, Utils

# from libnmap.objects.host import NmapHost
# from libnmap.objects.report import NmapReport
# from libnmap.parser import NmapParser, NmapParserException
# from libnmap.process import NmapProcess


default_split_by: str = ','

# ------------------------------------------------------------------------------
#
#
#
# ------------------------------------------------------------------------------


class HackService:

    def __init__(self, ctx: Context):
        '''
            hack service
        '''
        if ctx is not None and ctx.utils is not None:
            self.ctx: Context = ctx
            self.utils: Utils = ctx.utils
            logging.log(logging.DEBUG, 'hack-service is initiated')
        else:
            logging.log(logging.ERROR, 'context or utils are not set')
            sys.exit(1)

    # --------------------------------------------------------------------------
    #
    #
    #
    # --------------------------------------------------------------------------

    def clone_page(self, host: str, ssl_verify: bool = True) -> None:
        '''
            ...
        '''
        service_name = 'page cloner'
        log_runBanner(service_name)
        path = self.utils.create_service_folder(f'page', host)

        options = []
        if ssl_verify is False:
            options.append('--no-check-certificate')

        self.utils.run_command_output_loop(f'clone page {host}', [
            ['wget', '-r', '-nHp', host, '-P', path] + options,
            ['tee', f'{path}/page_clone.log']
        ])

        logging.log(logging.SUCCESS, f'[*] {service_name} Done! View the log reports under {path}/')

    # --------------------------------------------------------------------------
    #
    #
    #
    # --------------------------------------------------------------------------

    def recon(self, domain: str, org: str, mode: str = 'gospider', threads: int = 10, depth: int = 2, ns: str = '1.1.1.1') -> None:
        '''
            ...
        '''
        service_name = 'RECON'
        log_runBanner(service_name)
        path = self.utils.create_service_folder(f'scan/recon', domain)

        sources = []
        if mode == 'subfinder' or mode == 'censys':
            logging.log(logging.DEBUG, 'Create subfinder conf with keys...')
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
                logging.log(logging.DEBUG, f'... {subfinder_config_path}/{subfinder_config_file} ...')
                logging.log(logging.DEBUG, '... subfinder conf with keys created')

        options_1 = ['-t', str(threads), '--recursive', '-v', '-oJ', '-nW']
        options_2 = ['-t', str(threads), '--recursive', '-v', '-oJ', '-nW', '--sources', ','.join(sources)]

        if mode == 'gospider':
            self.utils.run_command_output_loop(f'recon {mode}', [
                ['gospider', '-s', domain, '-o', f'{path}/gospider', '-c',
                    str(threads), '-d', str(depth), '--other-source', '--include-subs'],
                ['tee', f'{path}/gospider.log']
            ])
        elif mode == 'hakrawler':
            self.utils.run_command_output_loop(f'recon {mode}', [
                ['echo', domain],
                # -h 'Cookie: foo=bar;Authorization: token'
                ['hakrawler', '-d', str(depth), '-t', str(threads), '-insecure'],
                ['tee', f'{path}/hakrawler.log']
            ])
        elif mode == 'emailfinder':
            self.utils.run_command_output_loop(f'recon {mode}', [
                ['emailfinder', '-d', domain],
                ['tee', f'{path}/emailfinder.log']
            ])
        elif mode == 'subfinder':
            self.utils.run_command_output_loop(f'recon {mode}', [
                ['subfinder', '-d', domain, '-o', f'{path}/subfinder_rec', '-r', ns] + options_1,
                ['httpx'],
                ['tee', f'{path}/subfinder_rec.log']
            ])
        elif mode == 'subfinder_api':
            self.utils.run_command_output_loop(f'recon {mode}', [
                ['subfinder', '-d', domain, '-o', f'{path}/subfinder_censys', '-r', ns] + options_2,
                ['tee', f'{path}/subfinder_censys.log']
            ])
        elif mode == 'amass_whois':
            self.utils.run_command_output_loop(f'recon {mode}', [
                ['amass', 'intel', '-d', domain, '-whois', '-r', ns, '-o', f'{path}/amass_whois'],
                ['tee', f'{path}/amass_whois.log']
            ])
        elif mode == 'amass_org':
            self.utils.run_command_output_loop(f'recon {mode}', [
                ['amass', 'intel', '-org', org, '-r', ns, '-o', f'{path}/amass_org'],
                ['tee', f'{path}/amass_org.log']
            ])
        elif mode == 'passive':
            self.utils.run_command_output_loop(f'recon {mode}', [
                ['amass', 'enum', '-passive', '-d', domain, '-r', ns, '-o', f'{path}/amass_passive'],
                ['tee', f'{path}/amass_passive.log']
            ])
        elif mode == 'active':
            self.utils.run_command_output_loop(f'recon {mode}', [
                ['amass', 'enum', '-active', '-src', '-ip', '-brute', '-min-for-recursive',
                    str(depth), '-d', domain, '-r', ns, '-o', f'{path}/amass_active'],
                ['tee', f'{path}/amass_active.log']
            ])
        elif mode == 'gau':
            self.utils.run_command_output_loop(f'recon {mode}', [
                ['gau', '--subs', domain],
                ['cut', '-d', '/', '-f', '3'],
                ['sort', '-u'],
                ['tee', f'{path}/gau.log']
            ])
        elif mode == 'theHarvester':
            sources = ['baidu', 'bufferoverun', 'crtsh', 'hackertarget', 'otx', 'projecdiscovery',
                       'rapiddns', 'sublist3r', 'threatcrowd', 'trello', 'urlscan', 'vhost', 'virustotal', 'zoomeye']
            for source in sources:
                self.utils.run_command_output_loop(f'recon {mode}', [
                    ['theHarvester', '-d', domain, '-b', source, '-f', f'theHarvester_{source}'],
                    ['jq', '-r', '.hosts[]', '2>/dev/null'],
                    ['cut', "-d':'", '-f', '1'],
                    ['sort', '-u'],
                    ['tee', f'{path}/theHarvester_{source}.log']
                ])

        logging.log(logging.SUCCESS, f'[*] {service_name} Done! View the log reports under {path}/')

    # --------------------------------------------------------------------------
    #
    #
    #
    # --------------------------------------------------------------------------

    def dns(self, host: str, ns: Union[str, None] = None, record_type: Union[str, None] = None, port: int = 53, is_subdomain: bool = False) -> None:
        '''
            ...
        '''
        service_name = 'DNS/DIG'
        log_runBanner(service_name)
        path = self.utils.create_service_folder(f'scan/dig', host)

        nameserver = []
        if ns is not None:
            if not ns.startswith('@'):
                ns = f'@{ns}'
            nameserver = [ns]

        mode_plus = ['+answer', '+nocomments', '+multi']  # '+noall',
        mode_subdomain = []
        if is_subdomain is True:
            mode_subdomain = ['a']
        mode_test_01 = ['', 'ANY', 'TXT', 'A', 'NS', 'MX', 'CNAME', 'AXFR', 'SOA']
        if record_type is not None:
            mode_test_01 = [record_type]
        mode_test_02 = ['', 'dkmi._', '_dmarc.']

        for test_01 in mode_test_01:
            for test_02 in mode_test_02:
                file_suffix_1 = f'_{test_01}' if test_01 and len(test_01) > 0 else ''
                file_suffix_2 = f'_{test_02}' if test_02 and len(test_02) > 0 else ''
                cur_record = [test_01] if test_01 and len(test_01) > 0 else []
                self.utils.run_command_output_loop('dig', [
                    ['dig'] + mode_subdomain + cur_record + mode_plus + ['-p', str(port)] + nameserver + [f'{test_02}{host}'],
                    ['tee', f'{path}/dig_dns{file_suffix_1}{file_suffix_2}.log'],
                ])

        logging.log(logging.SUCCESS, f'[*] {service_name} Done! View the log reports under {path}/')

        service_name = 'DNS/HOST'
        log_runBanner(service_name)
        path = self.utils.create_service_folder(f'scan/host', host)

        self.utils.run_command_output_loop('whois', [
            ['whois', host],
            ['tee', f'{path}/whois.log'],
        ])

        self.utils.run_command_output_loop('host', [
            ['host', '-aRR', host],
            ['tee', f'{path}/host.log'],
        ])

        logging.log(logging.SUCCESS, f'[*] {service_name} Done! View the log reports under {path}/')

    def domain(self, domain: str) -> None:
        '''
            ...
        '''
        service_name = 'DOMAIN'
        log_runBanner(service_name)
        path = self.utils.create_service_folder(f'scan/domain', domain)

        mode_types = ['subdomains', 'tlds', 'all']

        for types in mode_types:
            self.utils.run_command_output_loop('domain', [
                ['curl', '-s', f'https://sonar.omnisint.io/{types}/{domain}'],
                ['jq', '-r', '.[]'],
                ['sort', '-u'],
                ['tee', f'{path}/domain_{types}.log'],
            ])

    def tls(self, domain: str, port: int = 443) -> None:
        '''
            ...
        '''
        service_name = 'TLS'
        log_runBanner(service_name)
        path = self.utils.create_service_folder(f'scan/tls', domain)

        # TODO: check param domain for port or http
        create_domain = f'{domain}:{port}'

        self.utils.run_command_output_loop('openssl [1/5]', [
            ['openssl', 's_client', '-connect', create_domain, '-showcerts'],
            ['tee', f'{path}/openssl_info_cert.log']
        ])
        self.utils.run_command_output_loop('openssl [2/5]', [
            ['openssl', 's_client', '-connect', create_domain],
            ['tee', f'{path}/openssl_info.log']
        ])
        self.utils.run_command_output_loop('openssl [3/5]', [
            ['openssl', 's_client', '-connect', create_domain, '</dev/null 2>/dev/null'],
            ['openssl', 'x509', '-noout', '-in', '/dev/stdin', '-text'],
            ['tee', f'{path}/openssl_text.log']
        ])
        self.utils.run_command_output_loop('openssl [4/5]', [
            ['openssl', 's_client', '-connect', create_domain, '</dev/null 2>/dev/null'],
            ['openssl', 'x509', '-fingerprint', '-noout', '-in', '/dev/stdin'],
            ['tee', f'{path}/openssl_fingerprint.log']
        ])
        self.utils.run_command_output_loop('openssl [5/5]', [
            ['openssl', 's_client', '-ign_eof', '2>/dev/null', "<<<$'HEAD / HTTP/1.0\r\n\r'", '-connect', create_domain],
            ['openssl', 'x509', '-noout', '-text', '-in', '-'],
            ['grep', 'DNS'],
            ['sed', '-e', 's|DNS:|\n|g', '-e', 's|^\*.*||g'],
            ['tr', ' -d', ','],
            ['sort', '-u'],
            ['tee', f'{path}/openssl_fingerprint.log']
        ])

        self.utils.run_command_output_loop('cert/crt.sh', [
            ['curl', '-s', f'https://crt.sh/?q={domain}&output=json'],
            ['jq', '-r', '.[] | "\(.name_value)\n\(.common_name)"'],
            ['sort', '-u'],
            ['tee', f'{path}/cert_crt.sh.log']
        ])

        logging.log(logging.SUCCESS, f'[*] {service_name} Done! View the log reports under {path}/')

    # --------------------------------------------------------------------------
    #
    #
    #
    # --------------------------------------------------------------------------

    def nmap(self, host: str, udp: bool = True, port: Union[str, None] = None,
             options: List[Any] = [], rate: int = 10000,
             path: Union[str, None] = None, silent: bool = False) -> None:
        '''
            ...
        '''
        service_name = 'NMAP'
        log_runBanner(service_name)
        path = self.utils.create_service_folder(f'scan/nmap', host) if path is None else path

        hosts: Union[str, List[str], None] = host.split(' ')
        ports: Union[str, List[str], None] = None  # port

        port_range_scan = ['-p-']  # '-p-' | '-F-' | '--top-ports=1000'
        if port is not None:
            port_range_scan = ['-p', port]
        mode_decoy = []
        t_scan = 4
        if silent:
            mode_decoy = ['-D', 'RND:5']
            rate = 100
            t_scan = 1
            for option in options:
                if '-T' in option:
                    option = f'-T{t_scan}'

        # TODO: ...
        options_script_args = []
        if SUBFINDER_SHODAN_API_KEY is not None:
            options_script_args = ['--script-args', f'shodan-api.apikey={SUBFINDER_SHODAN_API_KEY}']

        options_privileged = ['--privileged']
        options_improve_scan = [f'--min-rate={rate}', f'-T{t_scan}']

        # nmap --privileged  -Pn -n -sn -PE
        options_host_scan = ['-Pn', '-n', '-sn', '-PE'] + options_improve_scan + mode_decoy

        # nmap --privileged -Pn -n --disable-arp-ping -p-
        options_port_scan = ['-Pn', '-n', '--disable-arp-ping'] + options_improve_scan + mode_decoy + port_range_scan
        options_port_udp_scan = options_port_scan + ['-sU', '-sT', '--max-retries=1']

        options_output_format = ['-oX', f'{path}/inital.xml', '-oA', f'{path}/inital']
        options_full_scan = ['--reason'] + options_improve_scan + mode_decoy + options_output_format + options

        # nmap_report_hosts = self.utils.nmap_process('nmap host up scan', hosts, options_host_scan)
        # hosts = [host.address for host in nmap_report_hosts.hosts if host.is_up()]
        # logging.log(logging.DEBUG, hosts)

        if isinstance(hosts, List):
            hosts = self.utils.run_command_output_loop('nmap host-up scan', [
                ['nmap'] + options_privileged + options_host_scan + hosts,
                ['grep', 'for'],
                ['cut', '-d', ' ', '-f5'],
                ['sort'],
                ['uniq'],
                ['tr', '\\n', ' '],
                ['sed', 's/ $//'],
            ])
        else:
            logging.log(logging.WARNING, 'host str was not parsed correct to list, check your typed host')
            hosts = None

        if hosts is not None:
            hosts = hosts.split(' ')
            # SAVE host to file
            with open(f'{path}/hosts.lst', 'w') as file:
                file.write('\n'.join(hosts))
            # RUN scan for ports, if not specified
            if ports is None:
                # if udp:
                #     nmap_report_ports = self.utils.nmap_process('nmap udp ports scan', hosts, options_port_udp_scan)
                # else:
                #     nmap_report_ports = self.utils.nmap_process('nmap tcp ports scan', hosts, options_port_scan)
                # ports_host_tmp = []
                # [ports_host_tmp.extend(host.get_ports()) for host in nmap_report_ports.hosts if host.is_up()]
                # ports = sorted(set((str(p[0]) for p in ports_host_tmp)))
                # logging.log(logging.DEBUG, ports)

                if udp:
                    ports = self.utils.run_command_output_loop('nmap udp ports scan', [
                        self.ctx.use_sudo + ['nmap'] + options_privileged + options_port_udp_scan + hosts,
                        ['grep', '^[0-9]'],
                        ['cut', '-d', '/', '-f', '1'],
                        ['sort'],
                        ['uniq'],
                        ['tr', '\\n', default_split_by],
                        ['sed', f's/{default_split_by}$//'],
                    ])
                else:
                    ports = self.utils.run_command_output_loop('nmap tcp ports scan', [
                        self.ctx.use_sudo + ['nmap'] + options_privileged + options_port_scan + hosts,
                        ['grep', '^[0-9]'],
                        ['cut', '-d', '/', '-f', '1'],
                        ['sort'],
                        ['uniq'],
                        ['tr', '\\n', default_split_by],
                        ['sed', f's/{default_split_by}$//'],
                    ])

            # --initial-rtt-timeout 50ms --max-rtt-timeout 100ms
            # nmap -T1 --min-rate=100 -O -n -sn -Pn -sA
            if isinstance(ports, str):
                ports = ports.split(default_split_by)
                # SAVE ports to file
                with open(f'{path}/ports.lst', 'w') as file:
                    file.write('\n'.join(ports))
                # RUN full scan for information's
                self.utils.run_command_output_loop('nmap scan', [
                    self.ctx.use_sudo + ['nmap'] + options_privileged + options_full_scan + ['-p', ','.join(ports)] + hosts
                ])
                # nmap_report = self.utils.nmap_process('nmap scan', hosts, options_full_scan+['-p', ','.join(ports)], safe_mode=False)

                if os.path.isfile(f'{path}/inital.xml'):
                    self.utils.run_command_output_loop('nmap convert xls', [
                        ['nmap-converter', f'{path}/inital.xml', '-o', f'{path}/inital.xls'],
                        ['tee', f'{path}/nmap.log']
                    ])
                    self.utils.run_command_output_loop('nmap convert html', [
                        ['xsltproc', f'{path}/inital.xml', '-o', f'{path}/inital.html']
                    ])

                    logging.log(logging.SUCCESS, f'[*] {service_name} Done! View the log reports under {path}/')
                else:
                    logging.log(logging.WARNING, '[-] Any error in full nmap scan')
            else:
                logging.log(logging.WARNING, '[-] No ports found')
        else:
            logging.log(logging.WARNING, '[-] No host are reachable')

    def masscan(self, host: str, rate: int = 10000, options: List[str] = []) -> None:
        '''
            ...
        '''
        service_name = 'MASSCAN'
        log_runBanner(service_name)
        path = self.utils.create_service_folder(f'scan/masscan', host)

        self.utils.run_command_output_loop('masscan', [
            self.ctx.use_sudo + ['masscan', host, '-oX', f'{path}/masscan.xml'] + options
        ])
        self.utils.run_command_output_loop('xsltproc', [
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

        if ports is not None:
            t_scan = 4
            logging.log(logging.SUCCESS, f'[*] {service_name} Done! View the log reports under {path}/')
            n_options = ['-sV', '-O', f'-T{t_scan}', '-PE', '-Pn', '-n', '--open', '-vv']
            self.nmap(host=host, port=ports, options=n_options, path=path, rate=rate)
        else:
            logging.log(logging.WARNING, '[-] No ports found')

    # TODO: add ffuf
    # ffuf -w ./vhosts -u http://10.129.42.195 -H "HOST: FUZZ.www.inlanefreight.htb"
    # ffuf -recursion -recursion-depth 1 -u http://192.168.10.10/FUZZ -w /opt/useful/SecLists/Discovery/Web-Content/raft-small-directories-lowercase.txt
    # cewl -m5 --lowercase -w wordlist.txt http://192.168.10.10
    # ffuf -w ./folders.txt:FOLDERS,./wordlist.txt:WORDLIST,./extensions.txt:EXTENSIONS -u http://192.168.10.10/FOLDERS/WORDLISTEXTENSIONS

    def gobuster(self, host: str, type: str = 'dir', threads: int = 10,
                 w_list: Union[str, None] = None,
                 options: List[str] = [], exclude_length: Union[int, None] = None) -> None:
        '''
            ...
        '''
        service_name = 'GOBUSTER'
        log_runBanner(service_name)
        path = self.utils.create_service_folder(f'scan/gobuster', host)

        # wordlist = f'{self.ctx.home_path}/.vm_recon/git/SecLists/Discovery/Web-Content/big.txt' if w_list is None else w_list
        wordlist = f'{self.ctx.home_path}/.vm_recon/git/SecLists/Discovery/Web-Content/raft-medium-words.txt' if w_list is None else w_list

        if exclude_length is not None:
            options + ['--exclude-length', str(exclude_length)]

        if type == 'dir' or type is None:
            wordlist = f'{self.ctx.home_path}/.vm_recon/git/SecLists/Discovery/Web-Content/big.txt' if w_list is None else w_list
            self.utils.run_command_output_loop('gobuster dir', [
                ['gobuster', 'dir', '-u', host, '-w', wordlist, '-r', '-t',
                    str(threads), '-o', f'{path}/gobuster_dir'] + options,
                ['tee', f'{path}/gobuster_dir.log']
            ])
        elif type == 'vhost':
            wordlist = f'{self.ctx.home_path}/.vm_recon/git/SecLists/Discovery/DNS/subdomains-top1million-110000.txt' if w_list is None else w_list
            self.utils.run_command_output_loop('gobuster vhost', [
                ['gobuster', 'vhost', '-u', host, '-w', wordlist, '-r', '-t',
                    str(threads), '-o', f'{path}/gobuster_vhost'] + options,
                ['tee', f'{path}/gobuster_vhost.log']
            ])
        elif type == 'fuzz':
            # wordlist = f'{self.ctx.home_path}/.vm_recon/git/SecLists/Discovery/Web-Content/big.txt' if w_list is None else w_list
            # wordlist = f'{self.ctx.home_path}/.vm_recon/git/SecLists/Discovery/Web-Content/Apache.fuzz.txt' if w_list is None else w_list
            # wordlist = f'{self.ctx.home_path}/.vm_recon/git/SecLists/Discovery/Web-Content/ApacheTomcat.fuzz.txt' if w_list is None else w_list
            wordlist = f'{self.ctx.home_path}/.vm_recon/git/SecLists/Discovery/Web-Content/FatwireCMS.fuzz.txt' if w_list is None else w_list
            # wordlist = f'{self.ctx.home_path}/.vm_recon/git/SecLists/Discovery/Web-Content/CMS/wordpress.fuzz.txt' if w_list is None else w_list
            # wordlist = f'{self.ctx.home_path}/.vm_recon/git/SecLists/Discovery/Web-Content/CMS/wp-plugins.fuzz.txt' if w_list is None else w_list
            # wordlist = f'{self.ctx.home_path}/.vm_recon/git/SecLists/Discovery/Web-Content/CMS/wp-themes.fuzz.txt' if w_list is None else w_list
            self.utils.run_command_output_loop('gobuster fuzz', [
                ['gobuster', 'fuzz', '-u', host, '-w', wordlist, '-r', '-t',
                    str(threads), '-o', f'{path}/gobuster_fuzz'] + options,
                ['tee', f'{path}/gobuster_fuzz.log']
            ])
        elif type == 'dns':
            wordlist = f'{self.ctx.home_path}/.vm_recon/git/SecLists/Discovery/DNS/subdomains-top1million-110000.txt' if w_list is None else w_list
            self.utils.run_command_output_loop('gobuster dns', [
                ['gobuster', 'dns', '-d', host, '-w', wordlist, '-r', '-t',
                    str(threads), '-o', f'{path}/gobuster_dns'] + options,
                ['tee', f'{path}/gobuster_dns.log']
            ])
        elif type == 'bak':
            wordlist = f'{self.ctx.home_path}/.vm_recon/git/SecLists/Discovery/Web-Content/big.txt' if w_list is None else w_list
            self.utils.run_command_output_loop('gobuster bak', [
                ['gobuster', 'dir', '-u', host, '-w', wordlist, '-d', '-r',
                    '-t', str(threads), '-o', f'{path}/gobuster_back'] + options,
                ['tee', f'{path}/gobuster_back.log']
            ])
        else:
            logging.log(logging.WARNING, f'gobuster type "{type}" not defined')

        logging.log(logging.SUCCESS, f'[*] {service_name} Done! View the log reports under {path}/')

    def kitrunner(self, host: str,  w_list: Union[str, None] = None) -> None:
        '''
            ...
        '''
        service_name = 'KITRUNNER'
        log_runBanner(service_name)
        path = self.utils.create_service_folder(f'scan/kr', host)

        wordlist = '/opt/git/kiterunner/routes.kite' if w_list is None else w_list
        max_connection_per_host = 10
        ignore_length = 34

        self.utils.run_command_output_loop('kitrunner', [
            ['kr', 'scan', host, '-w', wordlist, '-A=apiroutes-210228:20000', '-x',
                str(max_connection_per_host), f'--ignore-length={ignore_length}'],
            ['tee', f'{path}/kr_scan.log']
        ])

        logging.log(logging.SUCCESS, f'[*] {service_name} Done! View the log reports under {path}/')

    def sqlmap(self,
               host: str, data: Union[str, None] = None,
               cookie: Union[str, None] = None, method: str = 'POST', technique: str = 'U',
               dbms: Union[str, None] = None, dbs=False, tables=False,
               database_name: Union[str, None] = None, tables_name: Union[str, None] = None,
               random_agent=True, banner=True, parse_errors=True, dump=True, tamper: Union[str, None] = None,
               level: int = 5, risk: int = 3, threads: int = 10, verbose: int = 3) -> None:
        '''
            tamper:
                - between
                - charunicodeescape
            technique:
                - B: Boolean-based blind
                - E: Error-based
                - U: Union query-based
                - S: Stacked queries
                - T: Time-based blind
                - Q: Inline queries
        '''
        service_name = 'SQLMAP'
        log_runBanner(service_name)
        path = self.utils.create_service_folder(f'scan/sqlmap', host)

        database_name_l = ['-D', database_name] if database_name else []
        tables_name_l = ['-T', tables_name] if tables_name else []

        data = f'--data={data}' if data else ''
        cookie = f'--cookie={cookie}' if cookie else ''
        method = f'--method={method}' if method else ''
        technique = f'--technique={technique}' if technique else ''
        dbms = f'--dbms={dbms}' if dbms else ''
        dbs = '--dbs' if dbs else ''
        tables = '--tables' if tables else ''

        random_agent = '--random-agent' if random_agent else ''
        banner = '--banner' if banner else ''
        parse_errors = '--parse-errors' if parse_errors else ''
        dump = f'--dump' if dump else ''
        tamper = f'--tamper={tamper}' if tamper else ''

        self.utils.run_command_output_loop('sqlmap', [
            ['sqlmap', '-u', host, random_agent, banner, parse_errors, tamper,
                f'--level={level}', f'--risk={risk}', f'--threads={threads}', '-v', str(verbose),
             data, cookie, method, technique, dbms, dbs, tables, dump] + database_name_l + tables_name_l,
            ['tee', f'{path}/sqlmap.log']
        ])

        logging.log(logging.SUCCESS, f'[*] {service_name} Done! View the log reports under {path}/')

    # --------------------------------------------------------------------------
    #
    #
    #
    # --------------------------------------------------------------------------

    def smb(self, hosts: str, ports: str = '139;445') -> None:
        '''
            ...
        '''
        service_name = 'SMB'
        log_runBanner(service_name)

        for host in hosts.split(' '):
            for port in ports.split(default_split_by):
                path = self.utils.create_service_folder(f'scan/smb', host)

                # SMBCLIENT ############################################################
                ########################################################################
                self.utils.run_command_output_loop('smbclient scan', [
                    ['smbclient', '-N', '-p', str(port).strip(), '-L', f'//{host}'],
                    ['tee', f'{path}/smbclient.log']
                ])

                print('')
                print('~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~')
                logging.log(logging.NOTICE, f'use "smbclient -U anonymous //{host}/..." to check the results')
                logging.log(logging.NOTICE, 'usefull commands "dir,get,put,..."')
                logging.log(logging.NOTICE, f'usefull commands "smbget -R smb://{host}/..."')
                print('~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~')
                print('')

                # ENUM4LINUX ############################################################
                ########################################################################
                self.utils.run_command_output_loop('enum4linux scan', [
                    ['enum4linux', host],
                    ['tee', f'{path}/enum4linux.log']
                ])

                print('')
                print('~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~')
                logging.log(logging.NOTICE, f'use "smbmap -u \'...\' -p \'\' -R -H {host}" to check the results')
                print('~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~')
                print('')

        logging.log(logging.SUCCESS, f'[*] {service_name} Done! View the log reports under {path}/')

        # NMAP #################################################################
        ########################################################################
        path = self.utils.create_service_folder(f'scan/smb', hosts)
        smb_options = ['--script', 'smb-vuln-*,smb-os-discovery,smb-enum-shares.nse,smb-enum-users.nse']
        n_options = ['-sV', '-O', '-T4', '-PE', '-Pn', '-n', '--open', '-vv'] + smb_options
        self.nmap(host=hosts, port=ports, udp=True, options=n_options, path=path, silent=False)

    def rpc(self, hosts: str, ports: str = '111') -> None:
        '''
            ...
        '''
        service_name = 'RPC'
        log_runBanner(service_name)
        path = self.utils.create_service_folder(f'scan/rpc', hosts)

        # for host in hosts.split(' '):
        #     for port in ports.split(','):
        #         path = self.utils.create_service_folder(f'scan/smb', host)

        #         # SMBCLIENT ############################################################
        #         ########################################################################
        #         self.utils.run_command_output_loop('smbclient scan', [
        #             ['smbclient', '-N', '-p', str(port).strip(), '-L', f'//{host}'],
        #             ['tee', f'{path}/smbclient.log']
        #         ])

        #         print('')
        #         print('~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~')
        #         logging.log(logging.NOTICE, f'use "smbclient //{host}/..." to check the results')
        #         logging.log(logging.NOTICE, 'usefull commands "dir,get,put,..."')
        #         print('~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~')
        #         print('')

        # logging.log(logging.INFO,f'[*] {service_name} Done! View the log reports under {path}/')

        # NMAP #################################################################
        ########################################################################
        rpc_options = ['--script', 'nfs-ls,nfs-statfs,nfs-showmount']
        n_options = ['-sV', '-O', '-T4', '-PE', '-Pn', '-n', '--open', '-vv'] + rpc_options
        self.nmap(host=hosts, port=ports, udp=True, options=n_options, path=path, silent=False)

    # --------------------------------------------------------------------------
    #
    #
    #
    # --------------------------------------------------------------------------

    def whatweb(self, host: str, silent: int = 3) -> None:
        '''
            ...
        '''
        service_name = 'WHATWEB'
        log_runBanner(service_name)
        path = self.utils.create_service_folder(f'scan/whatweb', host)

        self.utils.run_command_output_loop('whatweb silent', [
            ['whatweb', host, '-a', str(silent), '-v',
             f'--log-verbose={path}/whatweb_v.log', f'--log-json={path}/whatweb_j.log']
        ])

        self.utils.run_command_output_loop('wafw00f', [
            ['wafw00f', '-v', host],
            ['tee', f'{path}/wafw00f.log']
        ])

        logging.log(logging.SUCCESS, f'[*] {service_name} Done! View the log reports under {path}/')

    def wpscan(self, host: str, silent: bool = False) -> None:
        '''
            ...
        '''
        service_name = 'WPSCAN'
        log_runBanner(service_name)
        path = self.utils.create_service_folder(f'scan/wpscan', host)

        mode = ['--plugins-detection', 'aggressive'] if silent == False else ['--plugins-detection', 'passive']
        options = ['--random-user-agent', '-e', 'ap']
        to_file = ['-o', f'{path}/wpscan']

        self.utils.run_command_output_loop(f'wpscan {mode}', [
            ['wpscan', '--url', host] + options + to_file + mode,
            ['tee', f'{path}/wpscan.log']
        ])

        logging.log(logging.SUCCESS, f'[*] {service_name} Done! View the log reports under {path}/')

    # --------------------------------------------------------------------------
    #
    #
    #
    # --------------------------------------------------------------------------

    def pwn(self, file: str) -> None:
        '''
            ...
        '''
        service_name = 'PWN'
        log_runBanner(service_name)
        path = self.utils.create_service_folder(f'pwn/checks', file)

        self.utils.run_command_output_loop(f'pwn file', [
            ['file', file],
            ['tee', f'{path}/file.log']
        ])
        self.utils.run_command_output_loop(f'pwn strings', [
            ['strings', '-n', '10', file],
            ['tee', f'{path}/strings.log']
        ])
        self.utils.run_command_output_loop(f'pwn checksec', [
            ['checksec', '--file', file],
            ['tee', f'{path}/checksec.log']
        ])

        logging.log(logging.SUCCESS, f'[*] {service_name} Done! View the log reports under {path}/')

# ------------------------------------------------------------------------------
#
#
#
# ------------------------------------------------------------------------------
