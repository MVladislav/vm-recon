import logging
import sys

import click

from ..service.hack_service import HackService
from ..utils.utils import Context, pass_context

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
    if ctx.utils is not None:
        ctx.service = HackService(ctx)
    else:
        logging.log(logging.ERROR, f'utils are not set')
        sys.exit(1)

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
def nmap(ctx: Context, host, udp, options, options_append, rate):
    '''NMAP scan'''
    service: HackService = ctx.service
    try:
        if options != None and not options_append:
            options = options.split(',')
        elif options != None and options_append:
            options = ['-O', '-T4', '-PE', '--open', '-vv'] + options.split(',')
        else:
            options = ['-O', '-T4', '-PE', '--open', '-vv']

        service.nmap(host=host, udp=udp, options=options, rate=rate)
    except KeyboardInterrupt as k:
        logging.log(logging.DEBUG, f"process interupted! ({k})")
        sys.exit(5)
    except Exception as e:
        logging.log(logging.CRITICAL, e)
        sys.exit(2)


@cli.command()
@click.option('-d', '--host', type=str, help='host to scan for', required=True)
@click.option('-o', '--options', type=str, help='options to scan with (comma seperated)', default=None)
@click.option('-oa', '--options_append', is_flag=True, help='append new options to existing option list')
@click.option('-r', '--rate', type=int, help='rate to use', default=10000)
@pass_context
def masscan(ctx: Context, host, options, options_append, rate):
    '''MASSCAN scan'''
    service: HackService = ctx.service
    try:
        if options != None and not options_append:
            options = options.split(',')
        elif options != None and options_append:
            options = ['-p1-65535', '--rate', str(rate), '--wait', '0', '--open', '-vv'] + options.split(',')
        else:
            options = ['-p1-65535', '--rate', str(rate), '--wait', '0', '--open', '-vv']

        service.masscan(host=host, rate=rate, options=options)
    except KeyboardInterrupt as k:
        logging.log(logging.DEBUG, f"process interupted! ({k})")
        sys.exit(5)
    except Exception as e:
        logging.log(logging.CRITICAL, e)
        sys.exit(2)
