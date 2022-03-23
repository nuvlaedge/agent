# -*- coding: utf-8 -*-
""" NuvlaBox IP address monitoring class.

This class is devoted to finding and reporting IP addresses of the Host,
Docker Container, and VPN along with their corresponding interface names.
It also reports and handles the IP geolocation system.

"""
import os
import time
import json
import requests

from docker import errors
from pydantic import BaseModel, IPvAnyAddress
from agent.monitor.Monitor import Monitor, BaseDataStructure
from typing import Union, List, NoReturn, Dict
from agent.common.NuvlaBoxCommon import ContainerRuntimeClient


class NetworkInterface(BaseModel):
    """
    Pydantic BaseModel definition for Network interfaces. This includes public,
    vpn, and swarm addresses.
    """

    iface_name: Union[str, None]
    ip: Union[IPvAnyAddress, None]
    default_gw: bool = False
    # TODO: Future feature, to include IPv6
    # ip_v6: Union[IPvAnyAddress, None]


class NetworkTelemetryStructure(BaseDataStructure):
    """
    Base model to gather all the IP addresses in the NuvlaEdge device
        public: Public IPv4 and IPv6 addresses
        local: Host device local interfaces and its corresponding IP addresses
        vpn: VPN IPv4 address provided by OpenVpn server (If present)
        swarm: SWARM node IP address (If present)
    """
    public: NetworkInterface = NetworkInterface(iface_name="public")
    local: Dict[str, NetworkInterface] = {}
    vpn: Union[NetworkInterface, None]
    swarm: Union[NetworkInterface, None]


class IPAddressTelemetry(Monitor):
    """
    Handles the retrieval of IP networking data.
    """

    def __init__(self, vpn_ip_file: str,
                 runtime_client: ContainerRuntimeClient):

        self.custom_data: NetworkTelemetryStructure = \
            NetworkTelemetryStructure(telemetry_name=self.__class__.__name__)
        super().__init__(self.__class__.__name__, self.custom_data)
        self.updaters: List = [self.set_public_data,
                               self.set_local_data,
                               self.set_swarm_data,
                               self.set_vpn_data]
        self.vpn_ip_file: str = vpn_ip_file
        self.runtime_client: ContainerRuntimeClient = runtime_client
        self.main_remote_api: str = "https://api.ipify.org?format=json"

    def set_public_data(self) -> NoReturn:
        """
        Reads the IP from the GeoLocation systems.
        """
        try:
            it_v4_response: requests.Response = requests.get(
                self.main_remote_api)

            if it_v4_response.status_code == 200:
                self.custom_data.public.ip = \
                    json.loads(it_v4_response.content.decode("utf-8")).get("ip")

        except requests.Timeout as errorTimed:
            reason = f'Connection to server timed out: {errorTimed}'
            self.log.error(f'Cannot retrieve public IP. {reason}')

        # TODO: Future feature, to include IPv6
        # it_v6_response: requests.Response = requests.get("https://api64.ipify.org?format=json")
        # Future feature, to include IPv6
        # if it_v6_response.status_code == 200:
        #     self.custom_data.public.ip_v6 = json.loads(it_v6_response.content.decode("utf-8")).get("ip")

    def parse_host_ip_json(self, iface_data: Dict) -> NetworkInterface:
        """
        Receives a dict with the information of a host interface and returns a
        BaseModel data class of NetworkInterface.

        @param iface_data: Single interface data entry.
        @return: NetworkInterface class
        """
        try:
            is_default_gw = True if iface_data.get('dst', '') == 'default' else False
            return NetworkInterface(iface_name=iface_data['dev'],
                                    ip=iface_data['prefsrc'],
                                    default_gw=is_default_gw)
        except KeyError as err:
            self.log.warning(f'Interface key not found {err}')

    def set_local_data(self) -> NoReturn:
        """
        Runs the auxiliary container that reads the host network interfaces and parses the
        output return
        """

        def is_skip_route(r):
            return r.get('dst', '127.').startswith('127.') or \
                    r.get('dev', '') in self.custom_data.local.keys()

        ip_route: str = ""
        try:
            ip_route = self.runtime_client.client.containers.run(
                'sixsq/iproute2:latest',
                name="ip_aux_tools",
                command="-j route",
                remove=True,
                network="host"
            ).decode("utf-8")

        except errors.NotFound as imageNotFound:
            self.log.warning(
                f'Auxiliary IP reading image not found: {imageNotFound.explanation}')

        except errors.ContainerError as containerError:
            self.log.warning(f'Container run error: {containerError}')

        except errors.APIError as dockerApiError:
            self.log.warning(f'Docker API error: {dockerApiError}')

        # Gather default Gateway
        readable_route: List = []
        try:
            readable_route = json.loads(ip_route)
        except json.decoder.JSONDecodeError as jsonError:
            self.log.warning(f'Failed parsing IP info: {jsonError}')

        if readable_route:
            for route in readable_route:

                # Handle special cases
                if is_skip_route(route):
                    continue

                # Create new interface data structure
                it_iface: NetworkInterface = self.parse_host_ip_json(route)
                if it_iface:
                    self.custom_data.local[it_iface.iface_name] = it_iface

    def set_vpn_data(self) -> NoReturn:
        """ Discovers the NuvlaBox VPN IP  """

        # Check if file exists and not empty
        if os.path.exists(self.vpn_ip_file) and \
                os.stat(self.vpn_ip_file).st_size != 0:
            with open(self.vpn_ip_file, 'r') as file:
                it_line = file.read()
                ip = str(it_line.splitlines()[0])
            self.custom_data.vpn = NetworkInterface(iface_name="vpn", ip=ip)
        else:
            self.log.warning("Cannot infer the NuvlaBox VPN IP!")

    def set_swarm_data(self) -> NoReturn:
        """ Discovers the host SWARM IP address """
        it_ip: str = self.runtime_client.get_api_ip_port()[0]
        self.custom_data.swarm = None
        if it_ip:
            self.custom_data.swarm = NetworkInterface(
                iface_name="swarm",
                ip=it_ip)

    def update_data(self) -> NoReturn:
        self.log.info("Updating IP data")
        t_time = time.time()
        for updater in self.updaters:
            try:
                updater()
            except Exception as ex:
                # TODO: add proper logging
                self.log.error(ex)
        self.log.info(f'IP gathering time: {time.time() - t_time}')

        self.data = self.custom_data.copy(deep=True)

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
            for k, v in self.data.local.items():
                if v.default_gw:
                    return str(v.ip)

        if self.data.public.ip:
            return str(self.data.public.ip)

        if self.data.swarm:
            return str(self.data.swarm.ip)
