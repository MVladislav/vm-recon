from pathlib import Path

import yaml

from ..cli import Context
from ..utilities.utils import Utils

# ------------------------------------------------------------------------------
#
#
#
# ------------------------------------------------------------------------------


class ForensicService:

    def __init__(self, ctx: Context):
        self.ctx: Context = ctx
        self.utils: Utils = self.ctx.utils
        self.utils.logging.debug('forensic-service is initiated')

    # --------------------------------------------------------------------------
    #
    #
    #
    # --------------------------------------------------------------------------

    def capinfos(self, file: str) -> None:
        service_name = 'CAPINFO'
        self.utils.log_runBanner(service_name)
        path = self.utils.create_service_folder(f'page', file)
        self.utils.logging.debug(f'new folder created:: {path}')

        cmd_result = self.utils.run_command_output_loop(f'capinfos {file}', [
            ['capinfos', file],
            ['tee', f'{path}/capinfos.log']
        ])

        self.utils.logging.info(f'[*] {service_name} Done! View the log reports under {path}/')

    def tshark(self, file: str) -> None:
        service_name = 'CAPINFO'
        self.utils.log_runBanner(service_name)
        path = self.utils.create_service_folder(f'page', file)
        self.utils.logging.debug(f'new folder created:: {path}')

        # list infos
        # tshark -n -r <.pcap> -z <BLABLA | io,phs> -q
        # get icmp
        # tshark -n -r <.pcap> -Y '(icmp.type == 8) && (icmp.code == 0)'
        # tshark -n -r <.pcap> -Y '(icmp[0] == 8) and (icmp[1] == 0)'
        # display readable time
        # tshark -n -r <.pcap> -Y '(icmp[0] == 8) and (icmp[1] == 0)' -t ad # ad => local time
        # tshark -n -r <.pcap> -Y '(icmp[0] == 8) and (icmp[1] == 0)' -t ud # ud => utc time
        # get source and target ip
        # tshark -n -r <.pcap> -Y '(icmp[0] == 8) and (icmp[1] == 0)' -t ad | awk --field-seperator ' ' '{ print $4 }' | sort | uniq --count
        # tshark -n -r <.pcap> -Y '(icmp[0] == 8) and (icmp[1] == 0)' -t ad | awk --field-seperator ' ' '{ print $6 }' | sort | uniq --count

        # tshark -n -r <.pcap> -Y '(icmp[0] == 8) and (icmp[1] == 0) and (dst.ip == ...)' -T fields -e ip.dst | sort | uniq --sort
        # tshark -n -r <.pcap> -Y '(icmp[0] == 8) and (icmp[1] == 0) and (dst.ip == ...)' -T fields -e ip.srt | sort | uniq --sort

        # tshark -n -r <.pcap> -Y '(icmp)' -T fields -e frame.time -e ip.src -e ip.dst -e icmp.type -e icmp.code
        # tshark -n -r <.pcap> -Y '(icmp)' -T fields -e frame.time -e ip.src -e ip.dst -e icmp.type -e icmp.code -E header=y -E seperator=, > export.csv

        cmd_result = self.utils.run_command_output_loop(f'tshark {file}', [
            ['tshark', file],
            ['tee', f'{path}/tshark.log']
        ])

        self.utils.logging.info(f'[*] {service_name} Done! View the log reports under {path}/')


# ------------------------------------------------------------------------------
#
#
#
# ------------------------------------------------------------------------------
