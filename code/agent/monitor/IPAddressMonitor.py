#!/usr/bin/env python
# -*- coding: utf-8 -*-
""" Nuvlabox IP address monitoring class

This class is devoted to finding and reporting IP addresses of the Host, Docker Container and VPN and its
corresponding interface name. It will also report and handle the IP geolocation system

"""
import time
import json
import docker
import requests

from docker import errors
from os import path, stat
from pydantic import BaseModel, IPvAnyAddress
from agent.monitor.Monitor import Monitor, BaseDataStructure
from typing import Union, List, NoReturn, Dict
from agent.common.NuvlaBoxCommon import ContainerRuntimeClient


class NetworkInterface(BaseModel):
    iface_name: Union[str, None]
    ip: Union[IPvAnyAddress, None]
    ip_v6: Union[IPvAnyAddress, None]
    default: bool = False


class NetworkTelemetryStructure(BaseDataStructure):
    public: NetworkInterface = NetworkInterface(iface_name="public")
    local: Union[Dict[str, NetworkInterface], None] = {}
    vpn: Union[NetworkInterface, None]
    swarm: Union[NetworkInterface, None]


class IPAddressTelemetry(Monitor):
    """
    Handles the retrieval of IP networking data
    """

    def __init__(self, vpn_ip_file: str, local_ip_file: str,
                 runtime_client: ContainerRuntimeClient):
        self.custom_data: NetworkTelemetryStructure = NetworkTelemetryStructure(telemetry_name=self.__class__.__name__)
        super().__init__(self.__class__.__name__, self.custom_data)
        self.updaters: List = [self.set_public_data, self.set_local_data, self.set_swarm_data]
        self.vpn_ip_file: str = vpn_ip_file
        self.local_ip_file: str = local_ip_file
        self.runtime_client: ContainerRuntimeClient = runtime_client
        # self.runtime_client = docker.from_env()

    def set_public_data(self) -> NoReturn:
        """
        Reads the IP from the GeoLocation systems
        """
        it_v4_response: requests.Response = requests.get("https://api.ipify.org?format=json")
        it_v6_response: requests.Response = requests.get("https://api64.ipify.org?format=json")

        self.log.error("{} -- {}".format(it_v4_response.status_code,
                                         it_v6_response.status_code))

        if it_v4_response.status_code == 200:
            self.custom_data.public.ip = json.loads(it_v4_response.content.decode("utf-8")).get("ip")

        if it_v6_response.status_code == 200:
            self.custom_data.public.ip_v6 = json.loads(it_v6_response.content.decode("utf-8")).get("ip")

    @staticmethod
    def parse_host_ip_json(iface_data: Dict) -> NetworkInterface:
        """
        Receives a dict with the information of a host interface and returns a BaseModel data class
        of NetworkInterface

        @param iface_data: Single interface data entry.
        @return: NetworkInterface class
        """
        it_ifname: str = iface_data.get("ifname", "")
        # self.log.error(iface_data)
        address_info: List = iface_data.get("addr_info", [])
        if address_info:
            it_local_addr: str = iface_data.get("addr_info", [])[0].get("local", "")

            if address_info[0].get('family', "inet") == "inet":
                return NetworkInterface(iface_name=it_ifname, ip=it_local_addr)
            else:
                return NetworkInterface(iface_name=it_ifname, ip_v6=it_local_addr)

    def set_local_data(self) -> NoReturn:
        """
        Runs the auxiliary container that reads the host network interfaces and parses the
        output return
        """
        # TODO: Run container and read output return
        t_time = time.time()
        ip_info: str = ""
        try:
            ip_info = self.runtime_client.client.containers.run(
                'sixsq/iproute2:0.0.1',
                remove=True,
                command="-j a",
                network="host"
            ).decode("utf-8")

        except errors.NotFound as imageNotFound:
            self.log.warning("Auxiliary IP reading image not found with error {}".format(imageNotFound.explanation))

        readable_info: List = []
        try:
            readable_info = json.loads(ip_info)
        except json.decoder.JSONDecodeError as jsonError:
            self.log.warning("Error parsing IP info {} -- {}".format(ip_info, jsonError))

        for j in readable_info:
            it_ifname_data: NetworkInterface = self.parse_host_ip_json(j)
            if it_ifname_data:
                self.custom_data.local[it_ifname_data.iface_name] = it_ifname_data

        print(time.time() - t_time)
        ...

    def set_vpn_data(self) -> NoReturn:
        """ Discovers the NuvlaBox VPN IP  """

        if path.exists(self.vpn_ip_file) and stat(self.vpn_ip_file).st_size != 0:
            ip = str(open(self.vpn_ip_file).read().splitlines()[0])
            self.custom_data.vpn.append(NetworkInterface(iface_name="vpn",
                                                         ip=ip))
        else:
            self.log.warning("Cannot infer the NuvlaBox VPN IP!")

    def set_swarm_data(self) -> NoReturn:
        """ Discovers the host SWARM IP address """
        # self.custom_data.swarm.append(NetworkInterface(iface_name="swarm",
        #                                                ip=self.runtime_client.get_api_ip_port()[0]))

    def update_data(self) -> NoReturn:
        self.log.info("Updating IP data")
        [i() for i in self.updaters]
        self.data = self.custom_data.copy(deep=True)


# x = IPAddressTelemetry()
# t = time.time()
# x.update_data()
# print(time.time() - t)
# print(x.data.public)
# for k, v in x.data.local.items():
#     print(k, v)
# print(x.data.vpn)
