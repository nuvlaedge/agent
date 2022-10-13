"""

"""
from typing import Dict, List, Optional

from pydantic import BaseModel


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
