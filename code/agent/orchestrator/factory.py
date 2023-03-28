import os

from agent.orchestrator.docker import DockerClient
from agent.orchestrator.kubernetes import KubernetesClient

if os.getenv('KUBERNETES_SERVICE_HOST'):
    ORCHESTRATOR = KubernetesClient.NAME
    ORCHESTRATOR_COE = KubernetesClient.NAME_COE
else:
    ORCHESTRATOR = DockerClient.NAME
    ORCHESTRATOR_COE = DockerClient.NAME_COE


HOSTSFS = "/rootfs"


def orchestrator_name():
    return ORCHESTRATOR


def get_coe_client(installation_home, hostfs=HOSTSFS):
    """
    Returns COE client based on the underlying orchestrator.

    :return: instance of a ContainerRuntimeClient
    """
    if orchestrator_name() == KubernetesClient.NAME:
        return KubernetesClient(hostfs, installation_home)
    elif orchestrator_name() == DockerClient.NAME:
        return DockerClient(hostfs, installation_home)
    else:
        raise NotImplementedError(f'COE client of type {ORCHESTRATOR} is not known.')
