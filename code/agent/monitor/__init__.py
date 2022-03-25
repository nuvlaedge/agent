"""
Implementation of the Monitor and BaseDataStructure to be extended by every
component and data structure
"""
import logging
from abc import ABC, abstractmethod
from typing import Type, Dict

from pydantic import BaseModel


class Monitor(ABC):
    """
    Serves as a base class to facilitate and structure the telemetry gathering
    along the device.
    """
    def __init__(self, name: str, data_type: Type, enable_monitor: bool):
        self.name: str = name
        self.data: data_type = data_type(telemetry_name=name)

        # Logging system
        self.logger: logging.Logger = logging.getLogger(name)

        # Enable flag
        self._enabled_monitor: bool = enable_monitor

    @property
    def enabled_monitor(self):
        """
        Getter for monitor flag

        Returns: bool

        """
        return self._enabled_monitor

    @enabled_monitor.setter
    def enabled_monitor(self, flag: bool):
        """
        Setter for monitor flag
        Args:
            flag: bool
        """
        self._enabled_monitor = flag

    @abstractmethod
    def update_data(self):
        """
        General updater of the data attribute. To be implemented by class
        extension.
        """
        ...

    @abstractmethod
    def populate_nb_report(self, nuvla_report: Dict):
        """
            This method fills the nuvla report dictionary with the data corresponding
            to the given monitor class following the current structure of NuvlaAPI
        Args:
            nuvla_report: dictionary to fill with the data structure report
        """
        ...


class BaseDataStructure(BaseModel):
    """
    Base data structure for providing a common configuration for all the
    structures.
    """

    class Config:
        """ Configuration class for base telemetry data """
        allow_population_by_field_name = True
