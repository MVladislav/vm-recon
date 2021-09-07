import sys

import click

from ..cli import Context, pass_context
from ..service.wifi_service import WiFiService

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
    ctx.hack = WiFiService(ctx)

# ------------------------------------------------------------------------------
#
#
#
# ------------------------------------------------------------------------------


@cli.command()
@click.pass_context
def test(ctx: Context):
    '''TEST scan'''
    hack: WiFiService = ctx.obj.hack
    try:
        pass
        hack.utils.logging.debug(hack.find_nic())
        # hack.<...>
    except KeyboardInterrupt as k:
        hack.utils.logging.debug(f"process interupted! ({k})")
        sys.exit(5)
    except Exception as e:
        hack.utils.logging.exception(e)
        sys.exit(2)
