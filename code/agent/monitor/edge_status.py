""" NuvlaBox Edge Status

Gathers all the requiremets for status reporting
"""
from typing import Union

import pydantic

from agent.monitor.data import network_data


class EdgeStatus(pydantic.BaseModel):
    """
    Pydantic class to gather together all the information on the NuvlaEdge device
    """
    id: Union[str, None]

    iface_data: Union[network_data.NetworkingData, None]
