#!/usr/bin/env python
# -*- coding: utf-8 -*-
""" Nuvlabox monitoring parent abstract class

"""
import logging
from typing import Type
from abc import ABC, abstractmethod

from pydantic import BaseModel


class BaseDataStructure(BaseModel):
    """ Base data structure for providing a common configuration for all the strucures """

    class Config:
        allow_population_by_field_name = True


class Monitor(ABC):
    """
    Serves as a base class to facilitate and structure the telemetry gathering along the
    device
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
        return self._enabled_monitor

    @enabled_monitor.setter
    def enabled_monitor(self, value: bool):
        self._enabled_monitor = value

    @abstractmethod
    def update_data(self):
        ...

    @abstractmethod
    def get_data(self):
        ...
