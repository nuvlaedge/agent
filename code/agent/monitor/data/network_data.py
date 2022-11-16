# -*- coding: utf-8 -*-

""" NuvlaBox Edge Networking data structure

Gathers all the requirements for status reporting
"""
from typing import Union, Dict, List, Optional

from pydantic import Field

from agent.monitor import BaseDataStructure


class IP(BaseDataStructure, allow_mutation=False):
    """
    address: IP addresses
    """
    address: str = ''

    def __hash__(self):
        return hash(self.address)


class NetworkInterface(BaseDataStructure):
    """
    Pydantic BaseModel definition for Network interfaces. This includes public,
    vpn, and swarm addresses.
        iface_name: network interface name
        ips: List of IP addresses
        default_gw: flag indicating whether the interface is the default for the host
        device or not
    """

    iface_name: Union[str, None] = Field(alias='interface')
    ips: List[IP] = Field([])
    default_gw: bool = Field(False, alias='default-gw')

    # Interface data traffic control
    tx_bytes: Union[int, None] = Field(0, alias='bytes-transmitted')
    rx_bytes: Union[int, None] = Field(0, alias='bytes-received')


class IPAddresses(BaseDataStructure):
    """
    public: Public IPv4 and IPv6 addresses
    local: Host device local interface and its corresponding IP addresses
    vpn: VPN IPv4 address provided by OpenVpn server (If present)
    swarm: SWARM node IP address (If present)
    """
    public: str = ''
    swarm: str = ''
    vpn: str = ''
    local: str = ''


class NetworkingData(BaseDataStructure):
    """
    Base model to gather all the IP addresses in the NuvlaEdge device

    """
    default_gw: Optional[str]
    interfaces: Dict[str, NetworkInterface] = {}
    ips: IPAddresses = IPAddresses()
