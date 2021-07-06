from vm_recon.cli import Context
from vm_recon.utilities.utils import Utils

# ------------------------------------------------------------------------------
#
#
#
# ------------------------------------------------------------------------------


class HackService:

    def __init__(self, ctx: Context):
        self.ctx: Context = ctx
        self.utils: Utils = self.ctx.utils
        self.utils.logging.debug("hack-service is initiated")

    # --------------------------------------------------------------------------
    #
    #
    #
    # --------------------------------------------------------------------------

    def recon(self, domain: str, org: str, mode: str = "gospider", threads: int = 10, depth: int = 2) -> None:
        self.utils.log_runBanner('RECON')
        path = self.utils.create_service_folder(f'{self.utils.slugify(domain)}/scan/recon')
        self.utils.logging.debug(f'new folder created:: {path}')

        wordlist = "wordlist.txt"
        options_1 = ['--silent', '-t', '200', '--recursive', '-vv']
        options_2 = ['-t', '100', '--recursive', '-b', '-w', wordlist, '--sources', 'censys', '--set-settings', 'CensysPages=2', '-vv']

        if mode == "gospider":
            cmd_result = self.utils.run_command_output_loop(f'recon {mode}', [
                ['gospider', '-s', domain, '-o', f'{path}/gospider', '-c', str(threads), '-d', str(depth), '--other-source', '--include-subs'],
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
                ['subfinder', '-d', domain, '-o', f'{path}/subfinder_rec'] + options_1,
                ['tee', f'{path}/subfinder_rec.log']
            ])
        elif mode == "censys":
            cmd_result = self.utils.run_command_output_loop(f'recon {mode}', [
                ['subfinder', '-d', domain, '-o', f'{path}/subfinder_censys'] + options_2,
                ['tee', f'{path}/subfinder_censys.log']
            ])
        elif mode == "amass_whois":
            cmd_result = self.utils.run_command_output_loop(f'recon {mode}', [
                ['amass', 'intel', '-d', domain, '-whois', '-o', f'{path}/amass_whois'],
                ['tee', f'{path}/amass_whois.log']
            ])
        elif mode == "amass_org":
            cmd_result = self.utils.run_command_output_loop(f'recon {mode}', [
                ['amass', 'intel', '-org', org, '-o', f'{path}/amass_org'],
                ['tee', f'{path}/amass_org.log']
            ])
        elif mode == "passive":
            cmd_result = self.utils.run_command_output_loop(f'recon {mode}', [
                ['amass', 'enum', '-passive', '-d', domain, '-o', f'{path}/amass_passive'],
                ['tee', f'{path}/amass_passive.log']
            ])
        elif mode == "active":
            cmd_result = self.utils.run_command_output_loop(f'recon {mode}', [
                ['amass', 'enum', '-active', '-src', '-ip', '-brute', '-min-for-recursive', '2', '-d', domain, '-o', f'{path}/amass_active'],
                ['tee', f'{path}/amass_active.log']
            ])
        elif mode == "gau":
            cmd_result = self.utils.run_command_output_loop(f'recon {mode}', [
                ['gau', '--subs', domain],
                ['cut', '-d', '/', '-f', '3'],
                ['sort', '-u'],
                ['tee', f'{path}/gau.log']
            ])

        self.utils.logging.info(f'[*] RECON Done! View the log reports under {path}/')

    # --------------------------------------------------------------------------
    #
    #
    #
    # --------------------------------------------------------------------------

    def dns(self, host: str, ns: str = "ANY") -> None:
        self.utils.log_runBanner('DNS/DIG')
        path = self.utils.create_service_folder(f'{self.utils.slugify(host)}/scan/dig')
        self.utils.logging.debug(f'new folder created:: {path}')

        cmd_result = self.utils.run_command_output_loop('dig', [
            ['dig', host, ns],
            ['tee', f'{path}/dig_dns.log'],
        ])
        cmd_result = self.utils.run_command_output_loop('dig x', [
            ['dig', '-x', host, ns],
            ['tee', f'{path}/dig_dns_x.log'],
        ])
        cmd_result = self.utils.run_command_output_loop('dig spf', [
            ['dig', 'TXT', host, ns],
            ['tee', f'{path}/dig_dns_txt_spf.log'],
        ])
        cmd_result = self.utils.run_command_output_loop('dig dkmi', [
            ['dig', 'TXT', f'dkmi._{host}', ns],
            ['tee', f'{path}/dig_dns_txt_dkmi.log'],
        ])
        cmd_result = self.utils.run_command_output_loop('dig dmarc', [
            ['dig', 'TXT', f'_dmarc.{host}', ns],
            ['tee', f'{path}/dig_dns_txt_dmarc.log'],
        ])
        cmd_result = self.utils.run_command_output_loop('dig axfr', [
            ['dig', '+multi', 'AXFR', ns, host],
            ['tee', f'{path}/dig_dns_axfr_multi.log '],
        ])

        self.utils.logging.info(f'[*] DNS/DIG Done! View the log reports under {path}/')

        self.utils.log_runBanner('DNS/HOST')
        path = self.utils.create_service_folder(f'{self.utils.slugify(host)}/scan/host')
        self.utils.logging.debug(f'new folder created:: {path}')

        cmd_result = self.utils.run_command_output_loop('host', [
            ['host', '-aRR', host],
            ['tee', f'{path}/host.log'],
        ])

        self.utils.logging.info(f'[*] DNS/HOST Done! View the log reports under {path}/')

    def tls(self, domain: str) -> None:
        self.utils.log_runBanner('TLS')
        path = self.utils.create_service_folder(f'{self.utils.slugify(domain)}/scan/tls')
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

        self.utils.logging.info(f'[*] TLS Done! View the log reports under {path}/')

    # --------------------------------------------------------------------------
    #
    #
    #
    # --------------------------------------------------------------------------

    def nmap(self, host: str, udp: bool = True, ports=None,
             options: list = None, rate: int = 1000, path: str = None) -> None:
        self.utils.log_runBanner('NMAP')
        path = self.utils.create_service_folder(f'{self.utils.slugify(host)}/scan/namp') if path == None else path
        self.utils.logging.debug(f'new folder created:: {path}')

        options_b = ['-sV', '-O', '-T4', '-PE', '-Pn', '-n', '--open', '-sC', '--script=vuln', '-vv'] if options == None else options

        if ports == None:
            if udp:
                ports = self.utils.run_command_output_loop('nmap udp ports', [
                    ['sudo', 'nmap', '-sU', '-p-', f'--min-rate={rate}', '-T4', host],
                    ['grep', '^[0-9]'],
                    ['cut', '-d', '/', '-f', '1', ],
                    ['tr', '\\n', ',', ],
                    ['sed', 's/,$//'],
                ])
            else:
                ports = self.utils.run_command_output_loop('nmap tcp ports', [
                    ['sudo', 'nmap', '-p-', f'--min-rate={rate}', '-T4', host],
                    ['grep', '^[0-9]'],
                    ['cut', '-d', '/', '-f', '1'],
                    ['tr', '\\n', ','],
                    ['sed', 's/,$//'],
                ])

        if ports != None:
            cmd_result = self.utils.run_command_output_loop('nmap scan', [
                ['sudo', 'nmap', host, '-p', ports, '-oX', f'{path}/inital.xml', '-oN', f'{path}/inital.log'] + options_b
            ])

            cmd_result = self.utils.run_command_output_loop('nmap convert xls', [
                ['nmap-converter.py', f'{path}/inital.xml', '-o', f'{path}/inital.xls']
            ])
            cmd_result = self.utils.run_command_output_loop('nmap convert html', [
                ['xsltproc', f'{path}/inital.xml', '-o', f'{path}/inital.html']
            ])

            self.utils.logging.info(f'[*] NMAP Done! View the HTML report at {path}/inital.html')
            self.utils.logging.info(f'[*] NMAP Done! View the XLS  report at {path}/inital.xls')
        else:
            self.utils.logging.warning('[-] No ports found')

    def masscan(self, host: str, rate: int = 10000, options: list = None) -> None:
        self.utils.log_runBanner('MASSCAN')
        path = self.utils.create_service_folder(f'{self.utils.slugify(host)}/scan/masscan')
        self.utils.logging.debug(f'new folder created:: {path}')

        options_b = ['-p1-65535', '--rate', str(rate), '--wait', '0', '--open', '-vv'] if options == None else options

        cmd_result = self.utils.run_command_output_loop('masscan', [
            ['sudo', 'masscan', host, '-oX', f'{path}/masscan.xml'] + options_b
        ])
        cmd_result = self.utils.run_command_output_loop('xsltproc', [
            ['xsltproc', '-o', f'{path}/final-masscan.html', '/opt/git/nmap-bootstrap-xsl/nmap-bootstrap.xsl', f'{path}/masscan.xml']
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
            self.utils.logging.info(f'[*] MASSCAN Done! View the log reports under {path}/')
            n_options = ['-sV', '-O', '-T4', '-PE', '-Pn', '-n', '--open', '-vv']
            self.nmap(host=host, ports=ports, options=n_options, path=path)
        else:
            self.utils.logging.warning('[-] No ports found')

    def gobuster(self, host: str, type: str = 'dir', threads: int = 10,
                 w_list: str = None, extras: list = None) -> None:
        self.utils.log_runBanner('GOBUSTER')
        path = self.utils.create_service_folder(f'{self.utils.slugify(host)}/scan/gobuster')
        self.utils.logging.debug(f'new folder created:: {path}')

        extras_b = ['-k', '-x', 'php,txt,html,js'] if extras == None else extras
        wordlist = '/opt/git/SecLists/Discovery/Web-Content/big.txt' if w_list == None else w_list

        if type == 'dir' or type == None:
            wordlist = '/opt/git/SecLists/Discovery/Web-Content/big.txt' if w_list == None else w_list
            cmd_result = self.utils.run_command_output_loop('gobuster dir', [
                ['gobuster', 'dir', '-u', host, '-w', wordlist, '-r', '-t', str(threads), '-o', f'{path}/gobuster_dir'] + extras_b,
                ['tee', f'{path}/gobuster_dir.log']
            ])
        elif type == 'vhost':
            wordlist = '/opt/git/SecLists/Discovery/DNS/subdomains-top1million-110000.txt' if w_list == None else w_list
            cmd_result = self.utils.run_command_output_loop('gobuster vhost', [
                ['gobuster', 'vhost', '-u', host, '-w', wordlist, '-r', '-t', str(threads), '-o', f'{path}/gobuster_vhost'] + extras_b,
                ['tee', f'{path}/gobuster_vhost.log']
            ])
        elif type == 'fuzz':
            wordlist = '/opt/git/SecLists/Discovery/Web-Content/CMS/wordpress.fuzz.txt' if w_list == None else w_list
            cmd_result = self.utils.run_command_output_loop('gobuster fuzz', [
                ['gobuster', 'fuzz', '-u', host, '-w', wordlist, '-r', '-t', str(threads), '-o', f'{path}/gobuster_fuzz'] + extras_b,
                ['tee', f'{path}/gobuster_fuzz.log']
            ])
        elif type == 'dns':
            wordlist = '/opt/git/SecLists/Discovery/DNS/subdomains-top1million-110000.txt' if w_list == None else w_list
            cmd_result = self.utils.run_command_output_loop('gobuster dns', [
                ['gobuster', 'dns', '-d', host, '-w', wordlist, '-r', '-t', str(threads), '-o', f'{path}/gobuster_dns'] + extras_b,
                ['tee', f'{path}/gobuster_dns.log']
            ])
        elif type == 'bak':
            wordlist = '/opt/git/SecLists/Discovery/Web-Content/big.txt' if w_list == None else w_list
            cmd_result = self.utils.run_command_output_loop('gobuster bak', [
                ['gobuster', 'dir', '-d', host, '-w', wordlist, '-d', '-r', '-t', str(threads), '-o', f'{path}/gobuster_back'] + extras_b,
                ['tee', f'{path}/gobuster_back.log']
            ])
        else:
            self.utils.logging.warning(f'gobuster type "{type}" not defined')

        self.utils.logging.info(f'[*] GOBUSTER Done! View the log reports under {path}/')

    def kitrunner(self, host: str,  w_list: str = None) -> None:
        self.utils.log_runBanner('KITRUNNER')
        path = self.utils.create_service_folder(f'{self.utils.slugify(host)}/scan/kr')
        self.utils.logging.debug(f'new folder created:: {path}')

        wordlist = "/opt/git/kiterunner/routes.kite" if w_list == None else w_list
        max_connection_per_host = 10
        ignore_length = 34

        cmd_result = self.utils.run_command_output_loop('kitrunner', [
            ['kr', 'scan', host, '-w', wordlist, '-A=apiroutes-210228:20000', '-x', str(max_connection_per_host), f'--ignore-length={ignore_length}'],
            ['tee', f'{path}/kr_scan.log']
        ])

        self.utils.logging.info(f'[*] KITRUNNER Done! View the log reports under {path}/')

    # --------------------------------------------------------------------------
    #
    #
    #
    # --------------------------------------------------------------------------

    def whatweb(self, host: str, silent: int = 3) -> None:
        self.utils.log_runBanner('WHATWEB')
        path = self.utils.create_service_folder(f'{self.utils.slugify(host)}/scan/whatweb')
        self.utils.logging.debug(f'new folder created:: {path}')

        cmd_result = self.utils.run_command_output_loop('whatweb silent', [
            ['whatweb', host, '-a', str(silent), '-v', f'--log-verbose={path}/whatweb_v.log', f'--log-json={path}/whatweb_j.log']
        ])

        self.utils.logging.info(f'[*] WHATWEB Done! View the log reports under {path}/')

    def wpscan(self, host: str, silent: bool = False) -> None:
        self.utils.log_runBanner('WPSCAN')
        path = self.utils.create_service_folder(f'{self.utils.slugify(host)}/scan/wpscan')
        self.utils.logging.debug(f'new folder created:: {path}')

        mode = "aggressive" if silent == False else "passive"

        cmd_result = self.utils.run_command_output_loop(f'wpscan {mode}', [
            ['wpscan', '--url', host, '-e', 'ap', '--plugins-detection', mode, '-o', f'{path}/wpscan'],
            ['tee', f'{path}/wpscan.log']
        ])

        self.utils.logging.info(f'[*] WPSCAN Done! View the log reports under {path}/')

    # --------------------------------------------------------------------------
    #
    #
    #
    # --------------------------------------------------------------------------

    def pwn(self, file: str) -> None:
        self.utils.log_runBanner('PWN')
        path = self.utils.create_service_folder(f'{self.utils.slugify(file)}/pwn')
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

        self.utils.logging.info(f'[*] PWN Done! View the log reports under {path}/')

# ------------------------------------------------------------------------------
#
#
#
# ------------------------------------------------------------------------------
