import logging
import sys

import click

from ..service.wifi_service import WiFiService
from ..utils.utilsHelper import Context, pass_context


# ------------------------------------------------------------------------------
#
#
#
# ------------------------------------------------------------------------------
@click.group(invoke_without_command=True)
@pass_context
def cli(ctx: Context):
    '''
        A wrapper for wifi services
        with predefined params
    '''
    ctx.service = WiFiService()




# ------------------------------------------------------------------------------
#
#
#
# ------------------------------------------------------------------------------
@cli.command()
@click.option(
    '-n', '--net', type=str, help='network range like 192.168.0.0/24', required=True
)
@pass_context
def scapy_arp(ctx: Context, net: str):
    '''
        Scapy ARP
    '''
    try:
        service: WiFiService = ctx.service
        service.scapy_arp(net)
    except KeyboardInterrupt as k:
        logging.log(logging.DEBUG, f"process interupted! ({k})")
        sys.exit(5)
    except Exception as e:
        logging.log(logging.CRITICAL, e, exc_info=True)
        sys.exit(2)
