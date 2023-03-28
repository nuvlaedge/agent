from mock import Mock
import unittest

# from kubernetes import config as k8s_config

import agent.orchestrator.factory as orch_factory
from agent.orchestrator.factory import get_coe_client
from agent.orchestrator.docker import DockerClient
from agent.orchestrator.kubernetes import KubernetesClient
from agent.orchestrator.kubernetes import config as k8s_config


class TestOrchestratorFactory(unittest.TestCase):

    def test_get_coe_client_docker(self):

        orch_factory.orchestrator_name = Mock()
        orch_factory.orchestrator_name.return_value = DockerClient.NAME
        assert isinstance(get_coe_client('foo', 'bar'), DockerClient)

    def test_get_coe_client_kubernetes(self):

        orch_factory.orchestrator_name = Mock()
        orch_factory.orchestrator_name.return_value = KubernetesClient.NAME
        k8s_config.load_incluster_config = Mock()
        assert isinstance(get_coe_client('foo', 'bar'), KubernetesClient)
