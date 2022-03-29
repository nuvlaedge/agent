"""
Gathers the base NuvlaEdge base information
"""
from typing import Dict
import datetime
import psutil


import agent.common.NuvlaBoxCommon as NuvlaCommon
from agent.monitor import Monitor
from agent.monitor.data.nuvlaedge_data import NuvlaEdgeData as NuvlaInfo
from agent.monitor.data.nuvlaedge_data import InstallationParametersData
from ..components import monitor


@monitor('configuration_monitor')
class ConfigurationMonitor(Monitor):
    """ NuvlaEdge information monitor class. """
    def __init__(self, name: str, telemetry,
                 enable_monitor: bool = True):
        super().__init__(name, NuvlaInfo, enable_monitor)

        self.runtime_client: NuvlaCommon.ContainerRuntimeClient = \
            telemetry.container_runtime
        self.ne_id: str = telemetry.nb_status_id
        self.ne_engine_version: str = telemetry.nuvlabox_engine_version
        self.installation_home: str = telemetry.installation_home

        if not telemetry.edge_status.nuvlaedge_info:
            telemetry.edge_status.nuvlaedge_info = self.data

    def update_data(self):
        """
        Updates NuvlaEdge configuration parameters including installation and Nuvla
        information. Also, the components of the NuvlaEdge deployment
        """
        # Update static information
        self.data.id = self.ne_id
        self.data.nuvlaedge_engine_version = self.ne_engine_version
        self.data.installation_home = self.installation_home

        node_info = self.runtime_client.get_node_info()
        self.data.operating_system = self.runtime_client.get_host_os()
        self.data.architecture = self.runtime_client.get_host_architecture(node_info)
        self.data.hostname = self.runtime_client.get_hostname(node_info)
        self.data.last_boot = datetime.datetime.fromtimestamp(psutil.boot_time()).\
            strftime("%Y-%m-%dT%H:%M:%SZ")
        self.data.container_plugins = self.runtime_client.get_container_plugins()

        # installation parameters
        if not self.data.installation_parameters:
            self.data.installation_parameters = InstallationParametersData()
        filter_label = "nuvlabox.component=True"

        self.data.installation_parameters = \
            InstallationParametersData.parse_obj(
                self.runtime_client.get_installation_parameters(filter_label))

        # Components running in the current NuvlaEdge deployment
        self.data.components = self.runtime_client.get_all_nuvlabox_components()

    def populate_nb_report(self, nuvla_report: Dict):
        nuvla_report.update(self.data.dict(by_alias=True, exclude_none=True))
