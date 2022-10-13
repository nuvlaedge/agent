"""
Agent initial settings definition
"""

from pydantic import BaseSettings, Field


class InitialSettings(BaseSettings):
    """
    Agent Microservice initial settings from compose
    """
    NUVLAEDGE_API_KEY: str = ''
    NUVLAEDGE_API_SECRET: str = ''
    NUVLAEDGE_UUID: str
    NUVLA_ENDPOINT: str = Field('nuvla.io', env='NUVLA_ENDPOINT')
    NUVLA_ENDPOINT_INSECURE: bool = Field(False, env='NUVLA_ENDPOINT_INSECURE')

    NUVLAEDGE_ENGINE_VERSION: str = Field(..., env='NUVLAEDGE_ENGINE_VERSION')
    NUVLAEDGE_IMMUTABLE_SSH_PUB_KEY: str = Field('',
                                                 env='NUVLAEDGE_IMMUTABLE_SSH_PUB_KEY')
    HOST_HOME: str = Field(..., env='HOST_HOME')
    VPN_INTERFACE_NAME: str = Field('vpn', env='VPN_INTERFACE_NAME')
    NUVLAEDGE_LOG_LEVEL: bool = False
    AGENT_API_SERVER_PORT: int = Field(5000, env='AGENT_API_SERVER_PORT')

    class Config:
        fields = {
            'NUVLAEDGE_UUID': {
                'env': ['NUVLAEDGE_UUID', 'NUVLABOX_UUID']
            },
            'NUVLAEDGE_API_KEY': {
                'env': ['NUVLAEDGE_API_KEY', 'NUVLABOX_API_KEY']
            },
            'NUVLAEDGE_API_SECRET': {
                'env': ['NUVLAEDGE_API_SECRET', 'NUVLABOX_API_SECRET']
            },
            'NUVLAEDGE_LOG_LEVEL': {
                'env': ['NUVLAEDGE_LOG_LEVEL', 'NUVLABOX_LOG_LEVEL']
            }
        }


