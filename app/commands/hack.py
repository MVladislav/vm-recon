import logging
import sys

import click

from ..main import Context, pass_context
from ..service.hack_service import HackService

default_split_by = ';'

# ------------------------------------------------------------------------------
#
#
#
# ------------------------------------------------------------------------------


@click.group(invoke_without_command=True)
@pass_context
def cli(ctx: Context):
    '''
        A wrapper for hacking/recon services
        with predefined params
    '''
    ctx.hack = HackService(ctx)

# ------------------------------------------------------------------------------
#
#
#
# ------------------------------------------------------------------------------


@cli.command()
@click.option('-d', '--host', type=str, help='host to scan for', required=True)
@click.option('-n', '--nameserver', type=str, help='define nameserver [""]', default="")
@click.option('-t', '--record_type', type=str, help='define record type [ANY]', default="ANY")
@click.option('-p', '--port', type=int, help='define port [53]', default=53)
@pass_context
def dns(ctx: Context, host, nameserver, record_type, port):
    '''DNS scan'''
    hack: HackService = ctx.hack
    try:
        hack.dns(host=host, ns=nameserver, record_type=record_type, port=port)
    except KeyboardInterrupt as k:
        logging.log(logging.DEBUG, f"process interupted! ({k})")
        sys.exit(5)
    except Exception as e:
        logging.log(logging.CRITICAL, e)
        sys.exit(2)


@cli.command()
@click.option('-d', '--domain', type=str, help='domain to scan for', required=True)
@pass_context
def tls(ctx: Context, domain):
    '''TLS scan'''
    hack: HackService = ctx.hack
    try:
        hack.tls(domain=domain)
    except KeyboardInterrupt as k:
        logging.log(logging.DEBUG, f"process interupted! ({k})")
        sys.exit(5)
    except Exception as e:
        logging.log(logging.CRITICAL, e)
        sys.exit(2)

# ------------------------------------------------------------------------------
#
#
#
# ------------------------------------------------------------------------------


@cli.command()
@click.option('-d', '--host', type=str, help='host to scan for', required=True)
@click.option('-udp', is_flag=True, help='enables udp port scan instead of tcp')
@click.option('-o', '--options', type=str, help=f'options to scan with (seperated by "{default_split_by}") [None]', default=None)
@click.option('-oa', '--options_append', is_flag=True, help='append new options to existing option list')
@click.option('-r', '--rate', type=int, help='rate to scan ports for [1000]', default=1000)
@click.option('-sm', '--silent-mode', type=int, help='value to use in -T* [4]', default=4)
@click.option('-s', '--silent', is_flag=True, help='scan silent with predefined mode')
@pass_context
def nmap(ctx: Context, host, udp, options, options_append, rate, silent_mode, silent):
    '''NMAP scan'''
    hack: HackService = ctx.hack
    try:

        if options != None and not options_append:
            options = options.split(default_split_by)
        elif options != None and options_append:
            options = ['-sS', '-sV', '-O', f'-T{silent_mode}', '-PE', '--open', '-sC',
                       '--script=vuln', '--script=discovery', '-vv'] + options.split(default_split_by)
        else:
            options = ['-sS', '-sV', '-O', f'-T{silent_mode}', '-PE',
                       '--open', '-sC', '--script=vuln', '--script=discovery', '-vv']

        hack.nmap(host=host, udp=udp, options=options, rate=rate, silent=silent)
    except KeyboardInterrupt as k:
        logging.log(logging.DEBUG, f"process interupted! ({k})")
        sys.exit(5)
    except Exception as e:
        logging.log(logging.CRITICAL, e)
        sys.exit(2)


@cli.command()
@click.option('-d', '--host', type=str, help='host to scan for', required=True)
@click.option('-m', '--mode', type=click.Choice(['dir', 'vhost', 'fuzz', 'dns', 'bak']), help='type to scan for [dir]', default='dir')
@click.option('-t', '--threads', type=int, help='threads to use [10]', default=10)
@click.option('-w', '--wordlist', type=str, help='wordlist to use')
@click.option('-o', '--options', type=str, help=f'options to scan with (seperated by "{default_split_by}") ["-k", "-r", "--random-agent"]', default=None)
@click.option('-oa', '--options_append', is_flag=True, help='append new options to existing option list')
@pass_context
def gobuster(ctx: Context, host, mode, threads, wordlist, options, options_append):
    '''
        GOBUSTER scan\n
        HINT:\n
            - FUZZ: write host with "FUZZ" in it\n
            - WORDLIST:\n
                - /opt/git/SecLists/Discovery/Web-Content/raft-medium-words.txt\n
                - /opt/git/SecLists/Discovery/Web-Content/big.txt\n
                - /opt/git/SecLists/Discovery/Web-Content/Apache.fuzz.txt\n
                - /opt/git/SecLists/Discovery/Web-Content/big.txt\n
                - /opt/git/SecLists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt\n
                - /opt/git/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt\n
                - /opt/git/SecLists/Fuzzing/big-list-of-naughty-strings.txt\n
            - Try also with:\n
                - "-x;php,txt,html,js,log,bak"\n
                - "-f"\n
                - "-c;..."\n
                - "--exclude-length;15349"
    '''
    hack: HackService = ctx.hack
    try:
        # '-x', 'php,txt,html,js',

        if options != None and not options_append:
            options = options.split(default_split_by)
        elif options != None and options_append:
            options = ['-k', '-r', '--random-agent'] + options.split(default_split_by)
        else:
            options = ['-k', '-r', '--random-agent']

        hack.gobuster(host=host, type=mode, threads=threads, w_list=wordlist, options=options)
    except KeyboardInterrupt as k:
        logging.log(logging.DEBUG, f"process interupted! ({k})")
        sys.exit(5)
    except Exception as e:
        logging.log(logging.CRITICAL, e)
        sys.exit(2)


@cli.command()
@click.option('-d', '--host', type=str, help='host to scan for', required=True)
@click.option('-w', '--wordlist', type=str, help='wordlist to use')
@pass_context
def kitrunner(ctx: Context, host, wordlist):
    '''KITRUNNER scan'''
    hack: HackService = ctx.hack
    try:
        hack.kitrunner(host=host, w_list=wordlist)
    except KeyboardInterrupt as k:
        logging.log(logging.DEBUG, f"process interupted! ({k})")
        sys.exit(5)
    except Exception as e:
        logging.log(logging.CRITICAL, e)
        sys.exit(2)

# ------------------------------------------------------------------------------
#
#
#
# ------------------------------------------------------------------------------


@cli.command()
@click.option('-d', '--hosts', type=str, help='host to scan for (multiple split by "space")', required=True)
@click.option('-p', '--ports', type=str, help='ports to use for scan (multiple split by ",")', required=False, default='139,445')
@pass_context
def smb(ctx: Context, hosts, ports):
    '''SMB scan'''
    hack: HackService = ctx.hack
    try:
        hack.smb(hosts=hosts, ports=ports)
    except KeyboardInterrupt as k:
        logging.log(logging.DEBUG, f"process interupted! ({k})")
        sys.exit(5)
    except Exception as e:
        logging.log(logging.CRITICAL, e)
        sys.exit(2)


@cli.command()
@click.option('-d', '--hosts', type=str, help='host to scan for (multiple split by "space")', required=True)
@click.option('-p', '--ports', type=str, help='ports to use for scan (multiple split by ",")', required=False, default='111')
@pass_context
def rpc(ctx: Context, hosts, ports):
    '''RPC scan'''
    hack: HackService = ctx.hack
    try:
        hack.rpc(hosts=hosts, ports=ports)
    except KeyboardInterrupt as k:
        logging.log(logging.DEBUG, f"process interupted! ({k})")
        sys.exit(5)
    except Exception as e:
        logging.log(logging.CRITICAL, e)
        sys.exit(2)

# ------------------------------------------------------------------------------
#
#
#
# ------------------------------------------------------------------------------


@cli.command()
@click.option('-d', '--host', type=str, help='host to scan for', required=True)
@click.option('-s', '--silent', type=click.Choice(['1', '2', '3']), help='silent mode [3]', default="3")
@pass_context
def whatweb(ctx: Context, host, silent):
    '''WHATWEB scan'''
    hack: HackService = ctx.hack
    try:
        hack.whatweb(host=host, silent=silent)
    except KeyboardInterrupt as k:
        logging.log(logging.DEBUG, f"process interupted! ({k})")
        sys.exit(5)
    except Exception as e:
        logging.log(logging.CRITICAL, e)
        sys.exit(2)


@cli.command()
@click.option('-d', '--host', type=str, help='host to scan for', required=True)
@click.option('-s', '--silent', is_flag=True, help='silent mode')
@pass_context
def wpscan(ctx: Context, host, silent):
    '''WPSCAN scan'''
    hack: HackService = ctx.hack
    try:
        hack.wpscan(host=host, silent=silent)
    except KeyboardInterrupt as k:
        logging.log(logging.DEBUG, f"process interupted! ({k})")
        sys.exit(5)
    except Exception as e:
        logging.log(logging.CRITICAL, e)
        sys.exit(2)

# ------------------------------------------------------------------------------
#
#
#
# ------------------------------------------------------------------------------


@cli.command()
@click.option('-d', '--domain', type=str, help='domain to scan for', required=True)
@click.option('-o', '--org', type=str, help='org to scan for', required=True)
@click.option('-n', '--nameserver', type=str, help='the DNS server to use [1.1.1.1]', default="1.1.1.1")
@click.option('-m', '--mode', type=click.Choice(
    ['gospider', 'hakrawler', 'emailfinder', 'subfinder', 'subfinder_api', 'amass_whois', 'amass_org', 'passive', 'active', 'gau']),
    help='recon tool to use (gospider)', default="gospider")
@click.option('-t', '--threads', type=int, help='threads to use [10]', default=10)
@click.option('-dp', '--depth', type=int, help='depth to scan for [2]', default=2)
@pass_context
def recon(ctx: Context, domain, org, mode, threads, depth, nameserver):
    '''
        RECON scan\n
        HINT:\n
            - in some cases, the domain, need a http:// or https://
    '''
    hack: HackService = ctx.hack
    try:
        hack.recon(domain=domain, org=org, mode=mode, threads=threads, depth=depth, ns=nameserver)
    except KeyboardInterrupt as k:
        logging.log(logging.DEBUG, f"process interupted! ({k})")
        sys.exit(5)
    except Exception as e:
        logging.log(logging.CRITICAL, e)
        sys.exit(2)

# ------------------------------------------------------------------------------
#
#
#
# ------------------------------------------------------------------------------


@cli.command()
@click.option('-f', '--file', type=click.Path(writable=True), help='file to check', required=True)
@pass_context
def pwd(ctx: Context, file):
    '''PWD scan'''
    hack: HackService = ctx.hack
    try:
        hack.pwd(file=file)
    except KeyboardInterrupt as k:
        logging.log(logging.DEBUG, f"process interupted! ({k})")
        sys.exit(5)
    except Exception as e:
        logging.log(logging.CRITICAL, e)
        sys.exit(2)