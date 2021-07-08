import sys

import click

from ..cli import Context, pass_context
from ..service.hack_service import HackService

# ------------------------------------------------------------------------------
#
#
#
# ------------------------------------------------------------------------------


@click.group(invoke_without_command=True)
@pass_context
def cli(ctx: Context):
    '''
        A wrapper for infra structure scanning
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
@click.option('-udp', is_flag=True, help='enables udp port scan instead of tcp')
@click.option('-o', '--options', type=str, help='options to scan with (comma seperated)', default=None)
@click.option('-oa', '--options_append', is_flag=True, help='append new options to existing option list')
@click.option('-r', '--rate', type=int, help='rate to scan ports for', default=1000)
@click.pass_context
def nmap(ctx: Context, host, udp, options, options_append, rate):
    '''NMAP scan'''
    hack: HackService = ctx.obj.hack
    try:
        if options != None and not options_append:
            options = options.split(',')
        elif options != None and options_append:
            options = ['-O', '-T4', '-PE', '-Pn', '-n', '--open', '-vv'] + options.split(',')
        else:
            options = ['-O', '-T4', '-PE', '-Pn', '-n', '--open', '-vv']

        hack.nmap(host=host, udp=udp, options=options, rate=rate)
    except KeyboardInterrupt as k:
        hack.utils.logging.debug(f"process interupted! ({k})")
        sys.exit(5)
    except Exception as e:
        hack.utils.logging.exception(e)
        sys.exit(2)


@cli.command()
@click.option('-d', '--host', type=str, help='host to scan for', required=True)
@click.option('-r', '--rate', type=int, help='rate to use', default=10000)
@click.pass_context
def masscan(ctx: Context, host, rate):
    '''MASSCAN scan'''
    hack: HackService = ctx.obj.hack
    try:
        hack.masscan(host=host, rate=rate)
    except KeyboardInterrupt as k:
        hack.utils.logging.debug(f"process interupted! ({k})")
        sys.exit(5)
    except Exception as e:
        hack.utils.logging.exception(e)
        sys.exit(2)
