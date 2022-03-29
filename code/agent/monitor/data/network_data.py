# -*- coding: utf-8 -*-

""" NuvlaBox Edge Networking data structure

Gathers all the requirements for status reporting
"""
from typing import Union, Dict

from pydantic import Field

from agent.monitor import BaseDataStructure


class NetworkInterface(BaseDataStructure):
    """
    Pydantic BaseModel definition for Network interfaces. This includes public,
    vpn, and swarm addresses.
        iface_name: network interface name
        ip: IPv4 address
        default_gw: flag indicating whether the interface is the default for the host
        device or not
    """

    iface_name: Union[str, None] = Field(alias='interface')
    ip: Union[str, None]
    default_gw: bool = Field(False, alias='default-gw')
    # TODO: Future feature, to include IPv6
    # ip_v6: Union[IPvAnyAddress, None]

    # Interface data traffic control
    tx_bytes: Union[int, None] = Field(alias='bytes-transmitted')
    rx_bytes: Union[int, None] = Field(alias='bytes-received')


class NetworkingData(BaseDataStructure):
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
