import logging
import sys

import click

from ..service.tool_service import DownloadWhat, ToolService
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
        A wrapper for tool services
        with predefined params
    '''
    if ctx.utils is not None:
        ctx.service = ToolService(ctx)
    else:
        logging.log(logging.ERROR, f'utils are not set')
        sys.exit(1)
# ------------------------------------------------------------------------------
#
#
#
# ------------------------------------------------------------------------------


@cli.command()
@click.option('-w', '--what', type=click.Choice(list(map(str, DownloadWhat))), help='download a tool', required=True)
@pass_context
def wget(ctx: Context, what):
    '''DOWNLOAD'''
    service: ToolService = ctx.service
    try:
        service.download(what=what)
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
@click.option('-p', '--port', type=int, help='port to open on')
@pass_context
def nc(ctx: Context, port):
    '''NC LISTENER'''
    service: ToolService = ctx.service
    try:
        if port != None:
            service.nc(port=port)
        else:
            service.nc()
    except KeyboardInterrupt as k:
        logging.log(logging.DEBUG, f"process interupted! ({k})")
        sys.exit(5)
    except Exception as e:
        logging.log(logging.CRITICAL, e)
        sys.exit(2)


@cli.command()
@click.option('-d', '--host', type=str, help='host for self-inject')
@click.option('-p', '--port', type=int, help='port for listen on and self-inject')
@pass_context
def pwncat(ctx: Context, host, port):
    '''PWNCAT LISTENER'''
    service: ToolService = ctx.service
    try:
        if host != None and port != None:
            service.pwncat(host=host, port=port)
        elif host != None:
            service.pwncat(host=host)
        elif port != None:
            service.pwncat(port=port)
        else:
            service.pwncat()
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
@click.option('-d', '--host', type=str, help='LHOST to connect back', required=True)
@click.option('-p', '--port', type=int, help='LPORT to connect back', required=True)
@click.option('-f', '--format', type=click.Choice(['dll', 'exe']), help='what file type to create [dll]', default='dll')
@pass_context
def msfvenom(ctx: Context, host, port, format):
    '''MSFVENOM creator'''
    service: ToolService = ctx.service
    try:
        service.msfvenom(host=host, port=port, format=format)
    except KeyboardInterrupt as k:
        logging.log(logging.DEBUG, f"process interupted! ({k})")
        sys.exit(5)
    except Exception as e:
        logging.log(logging.CRITICAL, e)
        sys.exit(2)
