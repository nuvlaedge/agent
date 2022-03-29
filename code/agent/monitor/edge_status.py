""" NuvlaBox Edge Status

Gathers all the requiremets for status reporting
"""
from typing import Union

import pydantic

from agent.monitor.data import (network_data, nuvlaedge_data, resources_data,
                                orchestrator_data, temperature_data, geolocation_data,
                                vulnerabilities_data, power_data)


class EdgeStatus(pydantic.BaseModel):
    """
    Pydantic class to gather together all the information on the NuvlaEdge device
    """
    # General NuvlaEdge data information
    nuvlaedge_info: Union[nuvlaedge_data.NuvlaEdgeData, None]

    # Networking data report
    iface_data: Union[network_data.NetworkingData, None]

    # Resource utilization report
    resources: Union[resources_data.ResourcesData, None]

    # Temperature status report
    temperatures: Union[temperature_data.TemperatureData, None]

    # Deployed container stats
    container_stats: Union[orchestrator_data.DeploymentData, None]

    # Geolocation data
    inferred_location: Union[geolocation_data.GeoLocationData, None]

    # Vulnerabilities data
    vulnerabilities: Union[vulnerabilities_data.VulnerabilitiesData, None]

    power: Union[power_data.PowerData, None]