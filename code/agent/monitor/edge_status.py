""" NuvlaBox Edge Status

Gathers all the requiremets for status reporting
"""
from typing import Union

from pydantic import BaseModel

from agent.monitor.data import network_data


class EdgeStatus(BaseModel):

    id: Union[str, None]

    iface_data: Union[network_data.NetworkingData, None]
