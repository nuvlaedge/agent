# -*- coding: utf-8 -*-
""" NuvlaEdge IP address monitoring class.

This class is devoted to finding and reporting IP addresses of the Host,
Docker Container, and VPN along with their corresponding interface names.
It also reports and handles the IP geolocation system.

"""
import json
import os
import time
from typing import List, NoReturn, Dict, Union

import requests
from docker import errors as docker_err
from docker.models.containers import Container
from nuvlaedge.common.constant_files import FILE_NAMES

from agent.common import nuvlaedge_common, util
from agent.monitor.data.network_data import NetworkingData, NetworkInterface, IP
from agent.monitor import Monitor
from ..components import monitor


@monitor('network_monitor')
class NetworkMonitor(Monitor):
    """
    Handles the retrieval of IP networking data.
    """
    _REMOTE_IPV4_API: str = "https://api.ipify.org?format=json"
    _AUXILIARY_DOCKER_IMAGE: str = "sixsq/iproute2:latest"
    _IP_COMMAND_ARGS: str = '-j route'
    _PUBLIC_IP_UPDATE_RATE: int = 3600
    _NUVLAEDGE_COMPONENT_LABEL_KEY: str = util.base_label

    def __init__(self, name: str, telemetry, enable_monitor=True):

        super().__init__(self.__class__.__name__, NetworkingData,
                         enable_monitor=enable_monitor)

        # List of network interfaces
        self.updaters: List = [self.set_public_data,
                               self.set_local_data,
                               self.set_swarm_data,
                               self.set_vpn_data]

        self.host_fs: str = telemetry.hostfs
        self.first_net_stats: Dict = {}
        self.previous_net_stats_file: str = telemetry.previous_net_stats_file

        self.runtime_client: nuvlaedge_common.ContainerRuntimeClient = telemetry.container_runtime


        self.engine_project_name: str = self.get_engine_project_name()
        self.logger.info(f'Running network monitor for project '
                         f'{self.engine_project_name}')
        self.iproute_container_name: str = f'{self.engine_project_name}-iproute'

        self.last_public_ip: float = 0.0

        # Initialize the corresponding data on the EdgeStatus class
        if not telemetry.edge_status.iface_data:
            telemetry.edge_status.iface_data = self.data

    def get_engine_project_name(self) -> str:
        return self.runtime_client.get_nuvlaedge_project_name(util.default_project_name)

    def set_public_data(self) -> NoReturn:
        """
        Reads the IP from the GeoLocation systems.
        """
        if time.time() - self.last_public_ip < self._PUBLIC_IP_UPDATE_RATE:
            return
        try:
            it_v4_response: requests.Response = requests.get(
                self._REMOTE_IPV4_API, timeout=5)

            if it_v4_response.status_code == 200:
                self.data.ips.public = \
                    json.loads(it_v4_response.content.decode("utf-8")).get("ip")
                self.last_public_ip = time.time()

        except requests.Timeout as ex:
            reason: str = f'Connection to server timed out: {ex}'
            self.logger.error(f'Cannot retrieve public IP. {reason}')
        except Exception as e:
            self.logger.error(f'Cannot retrieve public IP: {e}')

    def parse_host_ip_json(self, iface_data: Dict) -> Union[NetworkInterface, None]:
        """
        Receives a dict with the information of a host interface and returns a
        BaseModel data class of NetworkInterface.

        @param iface_data: Single interface data entry.
        @return: NetworkInterface class
        """
        try:
            is_default_gw = iface_data.get('dst', '') == 'default'
            return NetworkInterface(iface_name=iface_data['dev'],
                                    ips=[IP(address=iface_data['prefsrc'])],
                                    default_gw=is_default_gw)
        except KeyError as err:
            self.logger.warning(f'Interface key not found {err}')
            return None

    def is_already_registered(self, it_route: Dict) -> bool:
        it_name = it_route.get('dev', '')
        it_ip = IP(address=it_route.get('prefsrc', ''))
        return it_name in self.data.interfaces.keys() \
               and it_ip in self.data.interfaces[it_name].ips

    def is_skip_route(self, it_route: Dict) -> bool:
        """
        Assess whether the IP route is a loopback or the interface is already
        registered

        Args:
            it_route: single IP route report in

        Returns:
            True if the route is to be skipped
        """
        is_loop: bool = it_route.get('dst', '127.').startswith('127.')
        is_already_registered: bool = self.is_already_registered(it_route)
        not_complete: bool = 'prefsrc' not in it_route

        return is_loop or is_already_registered or not_complete

    def _gather_host_ip_route(self) -> str:
        """
        Gathers a json type string containing the host local network routing if
        the container run is run successfully
        Returns:
            str as the output of the command (can be empty).
        """
        self.runtime_client.container_remove(self.iproute_container_name)
        return self.runtime_client \
            .container_run_command(self._AUXILIARY_DOCKER_IMAGE,
                                   self.iproute_container_name,
                                   args=self._IP_COMMAND_ARGS,
                                   network='host')

    def read_traffic_data(self) -> List:
        """ Gets the list of net ifaces and corresponding rxbytes and txbytes

            :returns [{"interface": "iface1", "bytes-transmitted": X,
            "bytes-received": Y}, {"interface": "iface2", ...}]
        """

        sysfs_net = f"{self.host_fs}/sys/class/net"

        try:
            ifaces = os.listdir(sysfs_net)
        except FileNotFoundError:
            self.logger.warning("Cannot find network information for this device")
            return []

        previous_net_stats = {}
        try:
            with open(self.previous_net_stats_file, encoding='UTF-8') as pns:
                previous_net_stats = json.loads(pns.read())
        except (FileNotFoundError, json.decoder.JSONDecodeError):
            pass

        net_stats = []
        for interface in ifaces:
            stats = f"{sysfs_net}/{interface}/statistics"
            try:
                with open(f"{stats}/rx_bytes", encoding='UTF-8') as rx_file:
                    rx_bytes = int(rx_file.read())
                with open(f"{stats}/tx_bytes", encoding='UTF-8') as tx_file:
                    tx_bytes = int(tx_file.read())
            except (FileNotFoundError, NotADirectoryError):
                self.logger.warning(
                    f"Cannot calculate net usage for interface {interface}")
                continue

            # we compute the net stats since the beginning of the NB lifetime
            # and our counters reset on every NB restart
            if interface in self.first_net_stats:
                if rx_bytes < self.first_net_stats[interface].get('bytes-received', 0) \
                        or tx_bytes < \
                        self.first_net_stats[interface].get('bytes-transmitted', 0):

                    # then the system counters were reset
                    self.logger.warning(f'Host network counters seem to have '
                                        f'been reset for network interface {interface}')

                    if interface in previous_net_stats:
                        # in this case, because the numbers no longer correlate,
                        # we need to add up to the previous reported value
                        rx_bytes_report = previous_net_stats[interface].get(
                            'bytes-received', 0) + rx_bytes
                        tx_bytes_report = previous_net_stats[interface].get(
                            'bytes-transmitted', 0) + tx_bytes
                    else:
                        rx_bytes_report = rx_bytes
                        tx_bytes_report = tx_bytes

                    self.first_net_stats[interface] = {
                        "bytes-transmitted": tx_bytes,
                        "bytes-received": rx_bytes,
                        "bytes-transmitted-carry": previous_net_stats.get(interface,
                                                                          {}).get(
                            'bytes-transmitted', 0),
                        "bytes-received-carry": previous_net_stats.get(interface, {}).get(
                            'bytes-received', 0),
                    }
                else:
                    # then counters are still going. In this case we just need to do
                    #
                    # current - first + carry
                    rx_bytes_report = rx_bytes - \
                                      self.first_net_stats[interface].get(
                                          'bytes-received', 0) + \
                                      self.first_net_stats[interface].get(
                                          'bytes-received-carry', 0)
                    tx_bytes_report = \
                        tx_bytes - \
                        self.first_net_stats[interface].get('bytes-transmitted', 0) + \
                        self.first_net_stats[interface].get('bytes-transmitted-carry', 0)

            else:
                rx_bytes_report = previous_net_stats.get(interface, {}).get(
                    'bytes-received', 0)
                tx_bytes_report = previous_net_stats.get(interface, {}).get(
                    'bytes-transmitted', 0)

                self.first_net_stats[interface] = {
                    "bytes-transmitted": tx_bytes,
                    "bytes-received": rx_bytes,
                    "bytes-transmitted-carry": tx_bytes_report,
                    "bytes-received-carry": rx_bytes_report
                }

            previous_net_stats[interface] = {
                "bytes-transmitted": tx_bytes_report,
                "bytes-received": rx_bytes_report
            }

            net_stats.append({
                "interface": interface,
                "bytes-transmitted": tx_bytes_report,
                "bytes-received": rx_bytes_report
            })

        util.atomic_write(self.previous_net_stats_file,
                          json.dumps(previous_net_stats), encoding='UTF-8')

        return net_stats

    def set_local_data(self) -> NoReturn:
        """
        Runs the auxiliary container that reads the host network interfaces and parses the
        output return
        """
        ip_route: str = self._gather_host_ip_route()

        if not ip_route:
            return

        # Gather default Gateway
        readable_route: List = []

        try:
            readable_route = json.loads(ip_route)
        except json.decoder.JSONDecodeError as ex:
            self.logger.warning(f'Failed parsing IP info: {ex}')

        if readable_route:
            for route in readable_route:
                it_name = route.get('dev')
                it_ip = route.get('prefsrc')

                # Handle special cases
                if route.get('dst', 'not_def') == 'default':
                    self.data.default_gw = it_name

                if self.is_skip_route(route):
                    continue

                # Create new interface data structure
                it_iface: NetworkInterface
                if it_name in self.data.interfaces:
                    it_iface = self.data.interfaces[it_name]
                else:
                    it_iface = self.parse_host_ip_json(route)
                    self.data.interfaces[it_name] = it_iface

                if it_iface and it_name and it_ip:
                    if it_name == self.data.default_gw:
                        it_iface.default_gw = True

                        if self.data.ips.local != it_ip:
                            self.data.ips.local = it_ip

                    ip_address = IP(address=it_ip)
                    if ip_address not in self.data.interfaces[it_name].ips:
                        self.data.interfaces[it_name].ips.append(ip_address)

        # Update traffic data
        it_traffic: List = self.read_traffic_data()

        for iface_traffic in it_traffic:
            it_name: str = iface_traffic.get("interface")
            if it_name in self.data.interfaces.keys():
                self.data.interfaces[it_name].tx_bytes = \
                    iface_traffic.get('bytes-transmitted', '')
                self.data.interfaces[it_name].rx_bytes = \
                    iface_traffic.get('bytes-received', '')

    def set_vpn_data(self) -> NoReturn:
        """ Discovers the NuvlaEdge VPN IP  """

        # Check if file exists and not empty
        if FILE_NAMES.VPN_IP_FILE.exists() and \
                FILE_NAMES.VPN_IP_FILE.stat().st_size != 0:
            with FILE_NAMES.VPN_IP_FILE.open() as file:
                it_line = file.read()
                ip_address: str = str(it_line.splitlines()[0])

            if self.data.ips.vpn != ip_address:
                self.data.ips.vpn = ip_address

        else:
            self.logger.warning("Cannot infer the NuvlaEdge VPN IP!")

    def set_swarm_data(self) -> NoReturn:
        """ Discovers the host SWARM IP address """
        it_ip: str = self.runtime_client.get_api_ip_port()[0]

        if self.data.ips.swarm != it_ip:
            self.data.ips.swarm = it_ip

    def update_data(self) -> NoReturn:
        """
        Iterates over the different interfaces and gathers the data
        """
        for updater in self.updaters:
            updater()

    def populate_nb_report(self, nuvla_report: Dict):
        """
                Network report structure:
                network: {
                    default_gw: str,
                    ips: {
                        local: str,
                        public: str,
                        swarm: str,
                        vpn: str
                        }
                    interfaces: [
                        {
                            "interface": iface_name
                            "ips": [{
                                "address": "ip_Add"
                            }]
                        }
                    ]
                }
                """
        # Until server is adapted, we only return a single IP address as
        #  a string following the next priority.
        # 1.- VPN
        # 2.- Default Local Gateway
        # 3.- Public
        # 4.- Swarm
        if not nuvla_report.get('resources'):
            nuvla_report['resources'] = {}

        it_traffic: List = [x.dict(by_alias=True, exclude={'ips', 'default_gw'})
                            for _, x in self.data.interfaces.items()]

        it_report = self.data.dict(by_alias=True, exclude={'interfaces'}, exclude_none=True)
        it_report['interfaces'] = [{'interface': name,
                                    'ips': [ip.dict() for ip in obj.ips]}
                                   for name, obj in self.data.interfaces.items()]

        nuvla_report['network'] = it_report

        if it_traffic:
            nuvla_report['resources']['net-stats'] = it_traffic

        if self.data.ips.vpn:
            nuvla_report['ip'] = str(self.data.ips.vpn)
            return str(self.data.ips.vpn)

        if self.data.ips.local:
            nuvla_report['ip'] = str(self.data.ips.local)
            return str(self.data.ips.local)

        if self.data.ips.public:
            nuvla_report['ip'] = str(self.data.ips.public)
            return str(self.data.ips.public)

        if self.data.ips.swarm:
            nuvla_report['ip'] = str(self.data.ips.swarm)
            return str(self.data.ips.swarm)

        return None
