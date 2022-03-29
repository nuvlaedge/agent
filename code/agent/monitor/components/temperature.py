"""
Temperature monitor class
"""
import os
from typing import Dict, List, Union, Tuple

import psutil

from agent.monitor import Monitor
from agent.monitor.data.temperature_data import TemperatureData, TemperatureZone
from ..components import monitor


@monitor('temperature_monitor')
class TemperatureMonitor(Monitor):
    """
    Reads and updates the host node temperature available data
    """
    def __init__(self, name: str, telemetry, enable_monitor: bool = True):
        super().__init__(name, TemperatureData, enable_monitor)

        self.host_fs: str = telemetry.hostfs
        self.thermal_fs_path = f'{self.host_fs}/sys/devices/virtual/thermal'

        if not telemetry.edge_status.temperatures:
            telemetry.edge_status.temperatures = self.data

    def update_temperature_entry(self, zone_name: str, temp_value: float):
        """
        Updates the Pydantic structure if exists, creates it otherwise
        Args:
            zone_name: Name of the zone to be updated
            temp_value: Tempearture tu be updated
        """
        if zone_name in self.data.temperatures:
            self.data.temperatures[zone_name] = temp_value
        else:
            self.data.temperatures[zone_name] = TemperatureZone(thermal_zone=zone_name,
                                                                value=temp_value)

    def update_temperatures_with_psutil(self):
        """
        Updates class variable data using psutil package
        Returns:

        """
        ps_temp: Dict = psutil.sensors_temperatures()
        for name, value in ps_temp.items():
            self.update_temperature_entry(name, value.current)

    def read_temperature_file(self,zone_path, temp_path) -> \
            Tuple[Union[str, None], Union[float, None]]:
        """
        Reads files, extract temperature/thermal values and returns them

        :param zone_path: path to thermal_zone_file
        :param temp_path: path to temperature_file
        :return: (metric_basename, temperature_value)
        """
        with open(zone_path, encoding='UTF-8') as zone_file:
            try:
                metric_name = zone_file.read().split()[0]
            except IndexError:
                self.logger.warning(f'Cannot read thermal zone at {zone_path}')
                metric_name = None

        with open(temp_path, encoding='UTF-8') as temp_file:
            try:
                temp_value = temp_file.read().split()[0]
            except IndexError:
                self.logger.warning(f'Cannot read temperature at {temp_path}')
                temp_value = None

        return metric_name, temp_value

    def update_temperatures_with_file(self):
        """
        Updates class variable data reading the temperatures file of the system
        """
        temperature_dirs: List = os.listdir(self.thermal_fs_path)
        temperature_dirs = \
            list(filter(lambda x: x.startswith('thermal'), temperature_dirs))

        for sub_dir in temperature_dirs:
            zone_path = f'{self.thermal_fs_path}/{sub_dir}/type'
            temp_path = f'{self.thermal_fs_path}/{sub_dir}/temp'

            if not os.path.exists(zone_path) or not os.path.exists(temp_path):
                self.logger.warning(f'Thermal zone (at {zone_path}) and '
                                    f'temperature (at {temp_path}) values do '
                                    f'not complement each other')
                continue

            zone_name, temp_value = self.read_temperature_file(zone_path, temp_path)

            if not zone_name or not temp_value:
                self.logger.warning(f'Thermal zone {zone_path} or temperature '
                                    f'{temp_path} value is missing')
                continue

            try:
                self.update_temperature_entry(zone_name, float(temp_value)/1000)

            except (ValueError, TypeError) as ex:
                self.logger.warning(f'Cannot convert temperature at '
                                    f'{temp_path}. Reason: {str(ex)}')

    def update_data(self):

        if not os.path.exists(self.thermal_fs_path):
            if hasattr(psutil, 'sensors_temperature'):
                self.update_temperatures_with_psutil()
        else:
            self.update_temperatures_with_file()

    def populate_nb_report(self, nuvla_report: Dict):
        # nuvla_report['temperatures'] = \
        #     [x.dict(by_alias=True) for x in self.data.temperatures.values()]
        ...
