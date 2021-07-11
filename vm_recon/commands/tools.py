import sys

import click

from ..cli import Context, pass_context
from ..service.tool_service import ToolService

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
@click.option('-p', '--port', type=int, help='port to open on', required=True)
@click.pass_context
def nc(ctx: Context, port):
    '''NC LISTENER'''
    hack: ToolService = ctx.obj.hack
    try:
        hack.nc(port=port)
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
        hack.utils.logging.debug(f"process interupted! ({k})")
        sys.exit(5)
    except Exception as e:
        hack.utils.logging.exception(e)
        sys.exit(2)
