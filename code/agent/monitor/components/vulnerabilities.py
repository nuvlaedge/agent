"""
    VulnerabilitiesMonitor.py
"""
import os
import json
from typing import Dict, Union

from agent.monitor import Monitor
from agent.monitor.components import monitor
from agent.monitor.data.vulnerabilities_data import (VulnerabilitiesData,
                                                     VulnerabilitiesSummary)


@monitor('vulnerabilities_monitor')
class VulnerabilitiesMonitor(Monitor):
    """ Vulnerabilities monitor class """
    def __init__(self, name: str, telemetry, enable_monitor: bool):
        super().__init__(name, VulnerabilitiesData, enable_monitor)

        self.vulnerabilities_file: str = telemetry.vulnerabilities_file

        if not telemetry.edge_status.vulnerabilities:
            telemetry.edge_status.vulnerabilities = self.data

    def retrieve_security_vulnerabilities(self) -> Union[Dict, None]:
        """ Reads vulnerabilities from the security scans, from a file in the shared volume

            :return: contents of the file
        """
        if os.path.exists(self.vulnerabilities_file):
            with open(self.vulnerabilities_file, encoding='UTF-8') as issues_file:
                return json.loads(issues_file.read())
        else:
            return None

    def update_data(self):
        vulnerabilities = self.retrieve_security_vulnerabilities()

        if vulnerabilities:
            it_summary: VulnerabilitiesSummary = VulnerabilitiesSummary()

            scores = list(filter((-1).__ne__, map(
                lambda v: v.get('vulnerability-score', -1), vulnerabilities)))
            it_summary.total = len(vulnerabilities)

            it_summary.affected_products = list(set(map(
                lambda v: v.get('product', 'unknown'), vulnerabilities)))

            if len(scores) > 0:
                it_summary.average_score = round(sum(scores) / len(scores), 2)

            self.data.summary = it_summary
            self.data.items = sorted(
                vulnerabilities,
                key=lambda v: v.get('vulnerability-score', 0), reverse=True)[0:100]

    def populate_nb_report(self, nuvla_report: Dict):
        if self.data.summary and self.data.items:
            nuvla_report['vulnerabilities'] = self.data.dict(by_alias=True)
