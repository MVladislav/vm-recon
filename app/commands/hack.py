import logging
import sys

import click

from ..service.hack_service import HackService
from ..utils.utilsHelper import Context, define_option_list, pass_context

default_split_by = ','


# ------------------------------------------------------------------------------
#
#
#
# ------------------------------------------------------------------------------
@click.group()
@pass_context
def cli(ctx: Context):
    '''
        A wrapper for recon services
        with predefined params
    '''
    ctx.service = HackService()


# ------------------------------------------------------------------------------
#
#
#
# ------------------------------------------------------------------------------
@cli.command()
@click.option('-d', '--host', type=str, help='host to scan for', required=True)
@click.option(
    '-s', '--ssl-verify', is_flag=True, help='if certificate should be checked [True]'
)
@pass_context
def clone_page(ctx: Context, host: str, ssl_verify: bool):
    '''
        page clone scan
    '''
    try:
        service: HackService = ctx.service
        service.clone_page(host=host, ssl_verify=not ssl_verify)
    except KeyboardInterrupt as k:
        logging.log(logging.DEBUG, f'process interupted! ({k})')
        sys.exit(5)
    except Exception as e:
        logging.log(logging.CRITICAL, e, exc_info=True)
        sys.exit(2)


# ------------------------------------------------------------------------------
#
#
#
# ------------------------------------------------------------------------------
@cli.command()
@click.option('-d', '--host', type=str, help='host to scan for', required=True)
@click.option(
    '-n', '--nameserver', type=str, help='define nameserver [None]', default=None
)
@click.option(
    '-t',
    '--record_type',
    type=click.Choice(['ANY', 'TXT', 'A', 'NS', 'MX', 'CNAME', 'AXFR', 'SOA']),
    help='define record type [None]',
    default=None,
)
@click.option('-p', '--port', type=int, help='define port [53]', default=53)
@click.option('-is', '--is_subdomain', is_flag=True, help='is host a subdomain [False]')
@pass_context
def dns(
    ctx: Context,
    host: str,
    nameserver: str,
    record_type: str,
    port: int,
    is_subdomain: bool,
):
    '''
        DNS scan
    '''
    try:
        service: HackService = ctx.service
        service.dns(
            host=host,
            ns=nameserver,
            record_type=record_type,
            port=port,
            is_subdomain=is_subdomain,
        )
    except KeyboardInterrupt as k:
        logging.log(logging.DEBUG, f'process interupted! ({k})')
        sys.exit(5)
    except Exception as e:
        logging.log(logging.CRITICAL, e, exc_info=True)
        sys.exit(2)


@cli.command()
@click.option('-d', '--domain', type=str, help='domain to scan for', required=True)
@pass_context
def domain(ctx: Context, domain: str):
    '''
        DOMAIN scan
    '''
    try:
        service: HackService = ctx.service
        service.domain(domain=domain)
    except KeyboardInterrupt as k:
        logging.log(logging.DEBUG, f'process interupted! ({k})')
        sys.exit(5)
    except Exception as e:
        logging.log(logging.CRITICAL, e, exc_info=True)
        sys.exit(2)


@cli.command()
@click.option('-d', '--domain', type=str, help='domain to scan for', required=True)
@pass_context
def tls(ctx: Context, domain):
    '''
        TLS scan
    '''
    try:
        service: HackService = ctx.service
        service.tls(domain=domain)
    except KeyboardInterrupt as k:
        logging.log(logging.DEBUG, f'process interupted! ({k})')
        sys.exit(5)
    except Exception as e:
        logging.log(logging.CRITICAL, e, exc_info=True)
        sys.exit(2)


# ------------------------------------------------------------------------------
#
#
#
# ------------------------------------------------------------------------------
@cli.command()
@click.option('-d', '--host', type=str, help='host to scan for', required=True)
@click.option(
    '-p',
    '--ports',
    type=str,
    help=f'define ports (separate by "{default_split_by}") [None]',
    default=None,
)
@click.option('-udp', is_flag=True, help='enables udp port scan instead of tcp')
@click.option(
    '-o', '--options', type=str, help=f'options to scan with [see help]', default=None
)
@click.option(
    '-oa',
    '--options_append',
    is_flag=True,
    help='append new options to existing option list',
)
@click.option(
    '-r', '--rate', type=int, help='rate to scan ports for [10000]', default=10000
)
@click.option(
    '-sm', '--silent-mode', type=int, help='value to use in -T* [4]', default=4
)
@click.option('-s', '--silent', is_flag=True, help='scan silent with predefined mode')
@pass_context
def nmap(
    ctx: Context, host, ports, udp, options, options_append, rate, silent_mode, silent
):
    '''
        NMAP scan\n
        options:\n
            -sS -sV -O -T{silent-mode} -PE --open -sC --script=vuln --script=discovery -vv
        HINT:\n
            - Try also with:\n
                - -oa -o "--script-args=newtargets"\n

    '''
    service: HackService = ctx.service
    try:
        defaults = [
            '-sS',
            '-sV',
            '-O',
            f'-T{silent_mode}',
            '-PE',
            '--open',
            '-sC',
            '--script=vuln',
            '--script=discovery',
            '-vv',
        ]
        options = define_option_list(
            options=options,
            default_options=defaults,
            options_append=options_append,
            # default_split_by=default_split_by,
        )
        service.nmap(
            host=host, port=ports, udp=udp, options=options, rate=rate, silent=silent
        )
    except KeyboardInterrupt as k:
        logging.log(logging.DEBUG, f'process interupted! ({k})')
        sys.exit(5)
    except Exception as e:
        logging.log(logging.CRITICAL, e, exc_info=True)
        sys.exit(2)


@cli.command()
@click.option('-d', '--host', type=str, help='host to scan for', required=True)
@click.option(
    '-m',
    '--mode',
    type=click.Choice(['dir', 'vhost', 'fuzz', 'dns', 'bak']),
    help='type to scan for [dir]',
    default='dir',
)
@click.option('-t', '--threads', type=int, help='threads to use [10]', default=10)
@click.option('-w', '--wordlist', type=str, help='wordlist to use')
@click.option(
    '-o', '--options', type=str, help='options to scan with [see help]', default=None
)
@click.option(
    '-oa',
    '--options_append',
    is_flag=True,
    help='append new options to existing option list',
)
@pass_context
def gobuster(ctx: Context, host, mode, threads, wordlist, options, options_append):
    '''
        GOBUSTER scan\n
        options:\n
            -k -r --random-agent
        HINT:\n
            - FUZZ:\n
                - write host with "FUZZ" in it\n
            - WORDLIST:\n
                - -w "~/.vm_recon/git/SecLists/Discovery/Web-Content/raft-medium-words.txt"\n
                - -w "~/.vm_recon/git/SecLists/Discovery/Web-Content/big.txt"\n
                - -w "~/.vm_recon/git/SecLists/Discovery/Web-Content/Apache.fuzz.txt"\n
                - -w "~/.vm_recon/git/SecLists/Discovery/Web-Content/big.txt"\n
                - -w "~/.vm_recon/git/SecLists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt"\n
                - -w "~/.vm_recon/git/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt"\n
                - -w "~/.vm_recon/git/SecLists/Fuzzing/big-list-of-naughty-strings.txt"\n
            - Try also with:\n
                - -oa -o "-x php,txt,html,js,log,bak"\n
                - -oa -o "-f"\n
                - -oa -o "-c "\n
                - -oa -o "--exclude-length 15349"
    '''
    service: HackService = ctx.service
    try:
        defaults = ['-k', '-r', '--random-agent']
        options = define_option_list(
            options=options,
            default_options=defaults,
            options_append=options_append,
            # default_split_by=default_split_by,
        )
        service.gobuster(
            host=host, type=mode, threads=threads, w_list=wordlist, options=options
        )
    except KeyboardInterrupt as k:
        logging.log(logging.DEBUG, f'process interupted! ({k})')
        sys.exit(5)
    except Exception as e:
        logging.log(logging.CRITICAL, e, exc_info=True)
        sys.exit(2)


@cli.command()
@click.option('-d', '--host', type=str, help='host to scan for', required=True)
@click.option('-w', '--wordlist', type=str, help='wordlist to use')
@pass_context
def kitrunner(ctx: Context, host, wordlist):
    '''
        KITRUNNER scan
    '''
    service: HackService = ctx.service
    try:
        service.kitrunner(host=host, w_list=wordlist)
    except KeyboardInterrupt as k:
        logging.log(logging.DEBUG, f'process interupted! ({k})')
        sys.exit(5)
    except Exception as e:
        logging.log(logging.CRITICAL, e, exc_info=True)
        sys.exit(2)


@cli.command()
@click.option('-d', '--host', type=str, help='host to scan for', required=True)
@click.option('-m', '--method', type=str, help='method', required=True, default='POST')
@click.option(
    '-dt', '--data', type=str, help='data to send', required=False, default=None
)
@click.option(
    '-c', '--cookie', type=str, help='cookie to send', required=False, default=None
)
@click.option(
    '-db', '--dbms', type=str, help='which dbms', required=False, default=None
)
@click.option(
    '-dbs', '--scan-databases', type=str, help='scan databases', required=True
)
@click.option('-t', '--scan-tables', type=str, help='scan tables', required=True)
@pass_context
def sqlmap(ctx: Context, host, method, data, cookie, dbms, scan_databases, scan_tables):
    '''
        SQLMAP scan
        HINT:
            - after scan sqlmap saves tmp file, to start new fresh scan remove it
            -
    '''
    service: HackService = ctx.service
    try:
        technique = 'U'
        database_name = None
        tables_name = None
        tamper = None
        level = 5
        risk = 3
        threads = 10
        verbose = 3
        random_agent = True
        banner = True
        parse_errors = True
        dump = True
        service.sqlmap(
            host=host,
            data=data,
            cookie=cookie,
            method=method,
            technique=technique,
            dbms=dbms,
            dbs=scan_databases,
            tables=scan_tables,
            database_name=database_name,
            tables_name=tables_name,
            random_agent=random_agent,
            banner=banner,
            parse_errors=parse_errors,
            dump=dump,
            tamper=tamper,
            level=level,
            risk=risk,
            threads=threads,
            verbose=verbose,
        )
    except KeyboardInterrupt as k:
        logging.log(logging.DEBUG, f'process interupted! ({k})')
        sys.exit(5)
    except Exception as e:
        logging.log(logging.CRITICAL, e, exc_info=True)
        sys.exit(2)


# ------------------------------------------------------------------------------
#
#
#
# ------------------------------------------------------------------------------
@cli.command()
@click.option(
    '-d',
    '--hosts',
    type=str,
    help='host to scan for (multiple split by "space")',
    required=True,
)
@click.option(
    '-p',
    '--ports',
    type=str,
    help='ports to use for scan (multiple split by ",")',
    required=False,
    default='139,445',
)
@pass_context
def smb(ctx: Context, hosts, ports):
    '''
        SMB scan
    '''
    service: HackService = ctx.service
    try:
        service.smb(hosts=hosts, ports=ports)
    except KeyboardInterrupt as k:
        logging.log(logging.DEBUG, f'process interupted! ({k})')
        sys.exit(5)
    except Exception as e:
        logging.log(logging.CRITICAL, e, exc_info=True)
        sys.exit(2)


@cli.command()
@click.option(
    '-d',
    '--hosts',
    type=str,
    help='host to scan for (multiple split by "space")',
    required=True,
)
@click.option(
    '-p',
    '--ports',
    type=str,
    help='ports to use for scan (multiple split by ",")',
    required=False,
    default='111',
)
@pass_context
def rpc(ctx: Context, hosts, ports):
    '''
        RPC scan
    '''
    service: HackService = ctx.service
    try:
        service.rpc(hosts=hosts, ports=ports)
    except KeyboardInterrupt as k:
        logging.log(logging.DEBUG, f'process interupted! ({k})')
        sys.exit(5)
    except Exception as e:
        logging.log(logging.CRITICAL, e, exc_info=True)
        sys.exit(2)


# ------------------------------------------------------------------------------
#
#
#
# ------------------------------------------------------------------------------
@cli.command()
@click.option('-d', '--host', type=str, help='host to scan for', required=True)
@click.option(
    '-s',
    '--silent',
    type=click.Choice(['1', '2', '3']),
    help='silent mode [3]',
    default='3',
)
@pass_context
def whatweb(ctx: Context, host, silent):
    '''
        WHATWEB scan
    '''
    try:
        service: HackService = ctx.service
        service.whatweb(host=host, silent=silent)
    except KeyboardInterrupt as k:
        logging.log(logging.DEBUG, f'process interupted! ({k})')
        sys.exit(5)
    except Exception as e:
        logging.log(logging.CRITICAL, e, exc_info=True)
        sys.exit(2)


@cli.command()
@click.option('-d', '--host', type=str, help='host to scan for', required=True)
@click.option('-s', '--silent', is_flag=True, help='silent mode')
@pass_context
def wpscan(ctx: Context, host, silent):
    '''
        WPSCAN scan
    '''
    try:
        service: HackService = ctx.service
        service.wpscan(host=host, silent=silent)
    except KeyboardInterrupt as k:
        logging.log(logging.DEBUG, f'process interupted! ({k})')
        sys.exit(5)
    except Exception as e:
        logging.log(logging.CRITICAL, e, exc_info=True)
        sys.exit(2)


@cli.command()
@click.option('-u', '--username', type=str, help='username to search for')
@click.option('-e', '--email', type=str, help='email to search for')
@pass_context
def accounting(ctx: Context, username: str, email: str):
    '''
        ACCOUNTING scan
    '''
    try:
        service: HackService = ctx.service
        service.accounting(username=username, email=email)
    except KeyboardInterrupt as k:
        logging.log(logging.DEBUG, f'process interupted! ({k})')
        sys.exit(5)
    except Exception as e:
        logging.log(logging.CRITICAL, e, exc_info=True)
        sys.exit(2)


# ------------------------------------------------------------------------------
#
#
#
# ------------------------------------------------------------------------------
@cli.command()
@click.option('-d', '--domain', type=str, help='domain to scan for')
@click.option('-o', '--org', type=str, help='org to scan for')
@click.option(
    '-n',
    '--nameserver',
    type=str,
    help='the DNS server to use [1.1.1.1]',
    default='1.1.1.1',
)
@click.option(
    '-m',
    '--mode',
    type=click.Choice(
        [
            'gospider',
            'hakrawler',
            'subfinder',
            'subfinder_api',
            'amass_whois',
            'amass_org',
            'passive',
            'active',
            'gau',
            'theHarvester',
        ]
    ),
    help='recon tool to use [gospider]',
    default='gospider',
)
@click.option('-t', '--threads', type=int, help='threads to use [10]', default=10)
@click.option('-dp', '--depth', type=int, help='depth to scan for [2]', default=2)
@pass_context
def recon(ctx: Context, domain, org, mode, threads, depth, nameserver):
    '''
        RECON scan\n
        HINT:\n
            - in some cases, the domain, need a http:// or https://
    '''
    service: HackService = ctx.service
    try:
        service.recon(
            domain=domain,
            org=org,
            mode=mode,
            threads=threads,
            depth=depth,
            ns=nameserver,
        )
    except KeyboardInterrupt as k:
        logging.log(logging.DEBUG, f'process interupted! ({k})')
        sys.exit(5)
    except Exception as e:
        logging.log(logging.CRITICAL, e, exc_info=True)
        sys.exit(2)


# ------------------------------------------------------------------------------
#
#
#
# ------------------------------------------------------------------------------
@cli.command()
@click.option(
    '-f', '--file', type=click.Path(writable=True), help='file to check', required=True
)
@pass_context
def pwn(ctx: Context, file):
    '''
        pwn scan
    '''
    try:
        service: HackService = ctx.service
        service.pwn(file=file)
    except KeyboardInterrupt as k:
        logging.log(logging.DEBUG, f'process interupted! ({k})')
        sys.exit(5)
    except Exception as e:
        logging.log(logging.CRITICAL, e, exc_info=True)
        sys.exit(2)
