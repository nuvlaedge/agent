#!/usr/bin/env python
# -*- coding: utf-8 -*-
""" Nuvlabox monitoring parent abstract class

"""
import logging
from pydantic import BaseModel
from abc import ABC, abstractmethod


class BaseDataStructure(BaseModel):
    telemetry_name: str


class Monitor(ABC):
    """
    Serves as a base class to facilitate and structure the telemetry gathering along the device
    """
    def __init__(self, name: str, data: BaseDataStructure):
        self.name: str = name
        self.data: BaseDataStructure = data

        self.log: logging.Logger = logging.getLogger(name)

    @abstractmethod
    def update_data(self):
        ...
