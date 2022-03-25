"""
    NuvlaEdge data structures module
"""
from typing import Union, List

from pydantic import Field

from agent.monitor import BaseDataStructure


class InstallationParametersData(BaseDataStructure):
    """ Provides a standard structure for installation parameters data """

    project_name: Union[str, None] = Field(alias='project-name')
    environment: Union[List[str], None]


class NuvlaEdgeData(BaseDataStructure):
    """ Provides a standard structure for generic NuvlaEdge data """

    # Node unique ID provided by Nuvla
    id: Union[str, None]

    nuvlaedge_engine_version: Union[str, None] = Field(alias='nuvlabox-engine-version')
    installation_home: Union[str, None] = Field(alias='host-user-home')

    # Host node information
    operating_system: Union[str, None] = Field(alias='operating-system')
    architecture: Union[str, None]
    hostname: Union[str, None]
    last_boot: Union[str, None] = Field(alias='last-boot')
    container_plugins: Union[List[str], None] = Field(alias='container-plugins')

    installation_parameters: Union[InstallationParametersData, None] \
        = Field(alias='installation-parameters')

    components: Union[List[str], None]
