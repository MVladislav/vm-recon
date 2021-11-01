import logging
import sys

import click

from ..utils.utils import Context, pass_context
from ..service.tool_service import DownloadWhat, ToolService

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
    ctx.hack = ToolService(ctx)
# ------------------------------------------------------------------------------
#
#
#
# ------------------------------------------------------------------------------


@cli.command()
@click.option('-w', '--what', type=click.Choice(list(map(str, DownloadWhat))), help='download a tool', required=True)
@click.pass_context
def wget(ctx: Context, what):
    '''DOWNLOAD'''
    hack: ToolService = ctx.obj.hack
    try:
        hack.download(what=what)
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
@click.pass_context
def nc(ctx: Context, port):
    '''NC LISTENER'''
    hack: ToolService = ctx.obj.hack
    try:
        if port != None:
            hack.nc(port=port)
        else:
            hack.nc()
    except KeyboardInterrupt as k:
        logging.log(logging.DEBUG, f"process interupted! ({k})")
        sys.exit(5)
    except Exception as e:
        logging.log(logging.CRITICAL, e)
        sys.exit(2)


@cli.command()
@click.option('-d', '--host', type=str, help='host for self-inject')
@click.option('-p', '--port', type=int, help='port for listen on and self-inject')
@click.pass_context
def pwncat(ctx: Context, host, port):
    '''PWNCAT LISTENER'''
    hack: ToolService = ctx.obj.hack
    try:
        if host != None and port != None:
            hack.pwncat(host=host, port=port)
        elif host != None:
            hack.pwncat(host=host)
        elif port != None:
            hack.pwncat(port=port)
        else:
            hack.pwncat()
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
@click.pass_context
def msfvenom(ctx: Context, host, port, format):
    '''MSFVENOM creator'''
    hack: ToolService = ctx.obj.hack
    try:
        hack.msfvenom(host=host, port=port, format=format)
    except KeyboardInterrupt as k:
        logging.log(logging.DEBUG, f"process interupted! ({k})")
        sys.exit(5)
    except Exception as e:
        logging.log(logging.CRITICAL, e)
        sys.exit(2)
