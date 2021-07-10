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
@click.pass_context
def nc(ctx: Context):
    '''TEST scan'''
    hack: ToolService = ctx.obj.hack
    try:
        hack.nc()
    except KeyboardInterrupt as k:
        hack.utils.logging.debug(f"process interupted! ({k})")
        sys.exit(5)
    except Exception as e:
        hack.utils.logging.exception(e)
        sys.exit(2)
