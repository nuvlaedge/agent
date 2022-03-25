""" NuvlaBox Edge Status

Gathers all the requiremets for status reporting
"""
from typing import Union

import pydantic

from agent.monitor.data import network_data, nuvlaedge_data


class EdgeStatus(pydantic.BaseModel):
    """
    Pydantic class to gather together all the information on the NuvlaEdge device
    """
    # General NuvlaEdge data information
    nuvlaedge_info: Union[nuvlaedge_data.NuvlaEdgeData, None]

    # Networking data report
    iface_data: Union[network_data.NetworkingData, None]
