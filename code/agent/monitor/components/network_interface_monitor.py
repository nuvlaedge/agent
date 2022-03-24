# -*- coding: utf-8 -*-
""" NuvlaBox IP address monitoring class.

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

from agent.common.NuvlaBoxCommon import ContainerRuntimeClient
from agent.monitor.data.network_data import NetworkingData, NetworkInterface
from agent.monitor.edge_status import EdgeStatus
from agent.monitor.monitor import Monitor


class NetworkIfaceMonitor(Monitor):
    """
    Handles the retrieval of IP networking data.
    """
    _REMOTE_IPV4_API: str = "https://api.ipify.org?format=json"
    _AUXILIARY_DOCKER_IMAGE: str = "sixsq/iproute2:latest"
    _IP_COMMAND: str = '-j route'

    def __init__(self, vpn_ip_file: str, runtime_client: ContainerRuntimeClient,
                 status: EdgeStatus):

        super().__init__(self.__class__.__name__, NetworkingData, enable_monitor=True)

        # List of network interfaces
        self.updaters: List = [self.set_public_data,
                               self.set_local_data,
                               self.set_swarm_data,
                               self.set_vpn_data]
        self.vpn_ip_file: str = vpn_ip_file
        self.runtime_client: ContainerRuntimeClient = runtime_client

        # Initialize the corresponding data on the EdgeStatus class
        if not status.iface_data:
            status.iface_data = self.data

    def set_public_data(self) -> NoReturn:
        """
        Reads the IP from the GeoLocation systems.
        """
        try:
            it_v4_response: requests.Response = requests.get(
                self._REMOTE_IPV4_API)

            if it_v4_response.status_code == 200:
                self.data.public.ip = \
                    json.loads(it_v4_response.content.decode("utf-8")).get("ip")

        except requests.Timeout as ex:
            reason: str = f'Connection to server timed out: {ex}'
            self.logger.error(f'Cannot retrieve public IP. {reason}')

        # TODO: Future feature, to include IPv6
        # it_v6_response: requests.Response =
        # requests.get("https://api64.ipify.org?format=json")
        # Future feature, to include IPv6
        # if it_v6_response.status_code == 200:
        #     self.custom_data.public.ip_v6 =
        #     json.loads(it_v6_response.content.decode("utf-8")).get("ip")

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
                                    ip=iface_data['prefsrc'],
                                    default_gw=is_default_gw)

        except KeyError as err:
            self.logger.warning(f'Interface key not found {err}')
            return None

    def is_skip_route(self, it_route: Dict) -> bool:
        """
        Assess whether the IP route is a loopback or the interface is already
        registered

        Args:
            it_route: single IP route report in

        Returns:
            True if the route is to be skipped
        """
        return it_route.get('dst', '127.').startswith('127.') or \
               it_route.get('dev', '') in self.data.local.keys()

    def gather_host_ip_route(self) -> Union[str, None]:
        """
        Gathers a json type string containing the host local network routing if
        the container run is run successfully
        Returns:
            str if succeeds. None otherwise
        """
        try:
            return self.runtime_client.client.containers.run(
                self._AUXILIARY_DOCKER_IMAGE,
                name="ip_aux_tools",
                command=self._IP_COMMAND,
                remove=True,
                network="host"
            ).decode("utf-8")

        except (docker_err.ImageNotFound,
                docker_err.ContainerError,
                docker_err.APIError) as ex:
            self.logger.warning(f'Local interface data auxiliary container '
                                f'not run: {ex.explanation}')
            return None

    def set_local_data(self) -> NoReturn:
        """
        Runs the auxiliary container that reads the host network interfaces and parses the
        output return
        """
        ip_route: str = self.gather_host_ip_route()

        # Gather default Gateway
        readable_route: List = []
        try:
            readable_route = json.loads(ip_route)
        except json.decoder.JSONDecodeError as ex:
            self.logger.warning(f'Failed parsing IP info: {ex}')

        if readable_route:
            for route in readable_route:
                # Handle special cases
                if self.is_skip_route(route):
                    continue
                # Create new interface data structure
                it_iface: NetworkInterface = self.parse_host_ip_json(route)
                if it_iface:
                    self.data.local[it_iface.iface_name] = it_iface

    def set_vpn_data(self) -> NoReturn:
        """ Discovers the NuvlaBox VPN IP  """

        # Check if file exists and not empty
        if os.path.exists(self.vpn_ip_file) and \
                os.stat(self.vpn_ip_file).st_size != 0:
            with open(self.vpn_ip_file, 'r', encoding='UTF-8') as file:
                it_line = file.read()
                ip_address: str = str(it_line.splitlines()[0])

            self.data.vpn = NetworkInterface(iface_name="vpn", ip=ip_address)
        else:
            self.logger.warning("Cannot infer the NuvlaBox VPN IP!")

    def set_swarm_data(self) -> NoReturn:
        """ Discovers the host SWARM IP address """
        it_ip: str = self.runtime_client.get_api_ip_port()[0]
        self.data.swarm = None
        if it_ip:
            self.data.swarm = NetworkInterface(
                iface_name="swarm",
                ip=it_ip)

    def update_data(self) -> NoReturn:
        self.logger.info("Updating IP data")
        t_time = time.time()
        for updater in self.updaters:
            try:
                updater()
            except Exception as ex:
                self.logger.warning(f'Address seeking for {updater} interface'
                                    f' raised error: {ex}')
        self.logger.info(f'IP gathering time: {time.time() - t_time}')

    def get_data(self):
        # TODO: Until server is adapted, we only return a single IP address as
        #       a string following the next priority.
        # 1.- VPN
        # 2.- Default Local Gateway
        # 3.- Public
        # 4.- Swarm

        if self.data.vpn:
            return str(self.data.vpn.ip)

        if self.data.local:
            for _, iface_data in self.data.local.items():
                if iface_data.default_gw:
                    return str(iface_data.ip)

        if self.data.public.ip:
            return str(self.data.public.ip)

        if self.data.swarm:
            return str(self.data.swarm.ip)

        return None
