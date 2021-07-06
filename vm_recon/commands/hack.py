import sys

import click
from vm_recon.cli import pass_context
from vm_recon.service.hack_service import HackService

# ------------------------------------------------------------------------------
#
#
#
# ------------------------------------------------------------------------------


@click.group(invoke_without_command=True)
@pass_context
def cli(ctx):
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
@click.option('-ns', '--ns', type=str, help='define nameserver')
@pass_context
def dns(ctx, host, ns):
    '''DNS scan'''
    hack: HackService = ctx.hack
    try:
        if ns != None:
            hack.dns(host=host, ns=ns)
        else:
            hack.dns(host=host)
    except KeyboardInterrupt as k:
        hack.utils.logging.debug(f"process interupted! ({k})")
        sys.exit(5)
    except Exception as e:
        hack.utils.logging.exception(e)
        sys.exit(2)


@cli.command()
@click.option('-d', '--domain', type=str, help='domain to scan for', required=True)
@pass_context
def tls(ctx, domain):
    '''TLS scan'''
    hack: HackService = ctx.hack
    try:
        hack.tls(domain=domain)
    except KeyboardInterrupt as k:
        hack.utils.logging.debug(f"process interupted! ({k})")
        sys.exit(5)
    except Exception as e:
        hack.utils.logging.exception(e)
        sys.exit(2)

# ------------------------------------------------------------------------------
#
#
#
# ------------------------------------------------------------------------------


@cli.command()
@click.option('-d', '--host', type=str, help='host to scan for', required=True)
@click.option('-udp', is_flag=True, help='enables udp port scan instead of tcp')
@click.option('-o', '--options', type=str, help='options to scan with (comma seperated)', default=None)
@click.option('-oa', '--options_append', is_flag=True, help='append new options to existing option list')
@click.option('-r', '--rate', type=int, help='rate to scan ports for', default=1000)
@pass_context
def nmap(ctx, host, udp, options, options_append, rate):
    '''NMAP scan'''
    hack: HackService = ctx.hack
    try:
        if options != None and not options_append:
            options = options.split(',')
        elif options != None and options_append:
            options = ['-sV', '-O', '-T4', '-PE', '-Pn', '-n', '--open', '-sC', '--script=vuln', '-vv'] + options.split(',')
        else:
            options = ['-sV', '-O', '-T4', '-PE', '-Pn', '-n', '--open', '-sC', '--script=vuln', '-vv']

        hack.nmap(host=host, udp=udp, options=options, rate=rate)
    except KeyboardInterrupt as k:
        hack.utils.logging.debug(f"process interupted! ({k})")
        sys.exit(5)
    except Exception as e:
        hack.utils.logging.exception(e)
        sys.exit(2)


@cli.command()
@click.option('-d', '--host', type=str, help='host to scan for', required=True)
@click.option('-m', '--mode', type=click.Choice(['dir', 'vhost', 'fuzz', 'dns', 'bak']), help='type to scan for', default='dir')
@click.option('-t', '--threads', type=int, help='thrads to use', default=10)
@click.option('-w', '--wordlist', type=str, help='wordlist to use')
@pass_context
def gobuster(ctx, host, mode, threads, wordlist):
    '''GOBUSTER scan'''
    hack: HackService = ctx.hack
    try:
        hack.gobuster(host=host, type=mode, threads=threads, w_list=wordlist)
    except KeyboardInterrupt as k:
        hack.utils.logging.debug(f"process interupted! ({k})")
        sys.exit(5)
    except Exception as e:
        hack.utils.logging.exception(e)
        sys.exit(2)


@cli.command()
@click.option('-d', '--host', type=str, help='host to scan for', required=True)
@click.option('-w', '--wordlist', type=str, help='wordlist to use')
@pass_context
def kitrunner(ctx, host, type, thread, wordlist):
    '''KITRUNNER scan'''
    hack: HackService = ctx.hack
    try:
        hack.kitrunner(host=host, w_list=wordlist)
    except KeyboardInterrupt as k:
        hack.utils.logging.debug(f"process interupted! ({k})")
        sys.exit(5)
    except Exception as e:
        hack.utils.logging.exception(e)
        sys.exit(2)

# ------------------------------------------------------------------------------
#
#
#
# ------------------------------------------------------------------------------


@cli.command()
@click.option('-d', '--host', type=str, help='host to scan for', required=True)
@click.option('-s', '--silent', type=click.Choice(['1', '2', '3']), help='silent mode', default="3")
@pass_context
def whatweb(ctx, host, silent):
    '''WHATWEB scan'''
    hack: HackService = ctx.hack
    try:
        hack.whatweb(host=host, silent=silent)
    except KeyboardInterrupt as k:
        hack.utils.logging.debug(f"process interupted! ({k})")
        sys.exit(5)
    except Exception as e:
        hack.utils.logging.exception(e)
        sys.exit(2)


@cli.command()
@click.option('-d', '--host', type=str, help='host to scan for', required=True)
@click.option('-s', '-silent', is_flag=True, help='silent mode')
@pass_context
def wpscan(ctx, host, silent):
    '''WPSCAN scan'''
    hack: HackService = ctx.hack
    try:
        hack.wpscan(host=host, silent=silent)
    except KeyboardInterrupt as k:
        hack.utils.logging.debug(f"process interupted! ({k})")
        sys.exit(5)
    except Exception as e:
        hack.utils.logging.exception(e)
        sys.exit(2)

# ------------------------------------------------------------------------------
#
#
#
# ------------------------------------------------------------------------------


@cli.command()
@click.option('-d', '--domain', type=str, help='domain to scan for', required=True)
@click.option('-o', '--org', type=str, help='org to scan for', required=True)
@click.option('-m', '--mode', type=click.Choice(
    ['gospider', 'hakrawler', 'emailfinder', 'subfinder', 'censys', 'amass_whois', 'amass_org', 'passive', 'active', 'gau']),
    help='recon tool to use', default="gospider")
@click.option('-t', '--threads', type=int, help='threads to use', default=10)
@click.option('-dp', '--depth', type=int, help='depth to scan for', default=2)
@pass_context
def recon(ctx, domain, org, mode, threads, depth):
    '''RECON scan'''
    hack: HackService = ctx.hack
    try:
        hack.recon(domain=domain, org=org, mode=mode, threads=threads, depth=depth)
    except KeyboardInterrupt as k:
        hack.utils.logging.debug(f"process interupted! ({k})")
        sys.exit(5)
    except Exception as e:
        hack.utils.logging.exception(e)
        sys.exit(2)

# ------------------------------------------------------------------------------
#
#
#
# ------------------------------------------------------------------------------


@cli.command()
@click.option('-f', '--file', type=click.Path(writable=True), help='file to check', required=True)
@pass_context
def pwd(ctx, file):
    '''PWD scan'''
    hack: HackService = ctx.hack
    try:
        hack.pwd(file=file)
    except KeyboardInterrupt as k:
        hack.utils.logging.debug(f"process interupted! ({k})")
        sys.exit(5)
    except Exception as e:
        hack.utils.logging.exception(e)
        sys.exit(2)
