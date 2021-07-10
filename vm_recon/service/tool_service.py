import re

from ..cli import Context
from ..utilities.utils import Utils

# ------------------------------------------------------------------------------
#
#
#
# ------------------------------------------------------------------------------


class ToolService:

    # --------------------------------------------------------------------------
    #
    #
    #
    # --------------------------------------------------------------------------

    def __init__(self, ctx: Context):
        self.ctx: Context = ctx
        self.utils: Utils = self.ctx.utils
        self.utils.logging.debug('tool-service is initiated')

    # --------------------------------------------------------------------------
    #
    #
    #
    # --------------------------------------------------------------------------

    def nc(self, port: int = 9001):
        self.utils.log_runBanner('NC')
        path = self.utils.create_service_folder('tool/nc')
        self.utils.logging.debug(f'new folder created:: {path}')

        cmd_result = self.utils.run_command_output_loop(f'nc listening...', [
            ['nc', '-lvnp', port],
            ['tee', f'{path}/nc.log']
        ])

    # --------------------------------------------------------------------------
    #
    #
    #
    # --------------------------------------------------------------------------
