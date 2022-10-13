"""

"""
from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class Ports(BaseModel):
    host_ip: str = Field(..., alias='HostIp')
    host_port: str = Field(..., alias='HostPort')

    class Config:
        allow_population_by_field_name = True


class NetworkConfig(BaseModel):
    Aliases: Optional[List[str]]
    IPAddress: str
    Gateway: str


class WorkerConfig(BaseModel):
    worker_id: str
    container_id: str
    container_name: str
    project_name: str
    networks: Dict[str, NetworkConfig] = {}
    ports: Dict[str, Ports] = {}
