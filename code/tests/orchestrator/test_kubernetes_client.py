#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import mock
import os
import sys
import unittest


import kubernetes

import tests.utils.fake as fake
from agent.common import nuvlaedge_common
from agent.orchestrator.kubernetes import KubernetesClient


class ContainerRuntimeKubernetesTestCase(unittest.TestCase):
    def setUp(self) -> None:
        os.environ.setdefault('KUBERNETES_SERVICE_HOST', 'force-k8s-coe')

        with mock.patch.dict(sys.modules):
            # sys.modules.clear()
            if 'agent.common.NuvlaEdgeCommon' in sys.modules:
                del sys.modules['agent.common.NuvlaEdgeCommon']

        self.nuvlaedge_common = nuvlaedge_common
        self.nuvlaedge_common.ORCHESTRATOR = 'kubernetes'
        self.hostfs = '/fake-rootfs'
        self.host_home = '/home/fakeUser'
        os.environ.setdefault('MY_HOST_NODE_NAME', 'fake-host-node-name')
        os.environ.setdefault('NUVLAEDGE_JOB_ENGINE_LITE_IMAGE','fake-job-lite-image')
        with mock.patch('kubernetes.client.CoreV1Api') as mock_k8s_client_CoreV1Api:
            with mock.patch('kubernetes.client.AppsV1Api') as mock_k8s_client_AppsV1Api:
                with mock.patch('kubernetes.config.load_incluster_config') as mock_k8s_config:
                    mock_k8s_client_CoreV1Api.return_value = mock.MagicMock()
                    mock_k8s_client_AppsV1Api.return_value = mock.MagicMock()
                    mock_k8s_config.return_value = True
                    self.obj = KubernetesClient()
        logging.disable(logging.CRITICAL)

    def tearDown(self):
        logging.disable(logging.NOTSET)

    def test_init(self):
        # the K8s coe should be set
        self.assertEqual(self.nuvlaedge_common.ORCHESTRATOR, 'kubernetes',
                             'Unable to set Kubernetes as the COE')
        # client should be set as well
        self.assertIsNotNone(self.obj.client,
                             'Unable to set Kubernetes client')
        self.assertIsNotNone(self.obj.client_apps,
                             'Unable to set Kubernetes client for apps')

        # the base class should also have been set
        self.assertEqual(self.obj.job_engine_lite_component, "nuvlaedge-job-engine-lite",
                         'Base class of the ContainerRuntime was not properly initialized')

    def test_get_node_info(self, ):
        # if MY_HOST_NODE_NAME is setup, then return the node's info
        self.obj.client.read_node.return_value = {}
        self.assertIsInstance(self.obj.get_node_info(), dict,
                              'Expecting node_info as a dict, but got something else instead')
        # otherwise, return None
        self.obj.host_node_name = None
        self.assertIsNone(self.obj.get_node_info(),
                          'Without a MY_HOST_NODE_NAME, node_info should be None, but got something else instead')

    @mock.patch('agent.orchestrator.kubernetes.KubernetesClient.get_node_info')
    def test_get_host_os(self, mock_get_node_info):
        # if get_node_info returns something valid, we get a valid string out of it
        node = fake.mock_kubernetes_node()
        mock_get_node_info.return_value = node
        self.assertIsInstance(self.obj.get_host_os(), str,
                              'Host OS should be a string')
        self.assertEqual(self.obj.get_host_os(),
                         f"{node.status.node_info.os_image} {node.status.node_info.kernel_version}",
                         'Did not get the expected host OS value')

        # otherwise, we get None
        mock_get_node_info.return_value = None
        self.assertIsNone(self.obj.get_host_os(),
                          'Host OS should be None cause Node is not defined')

    def test_get_join_tokens(self):
        # NOTE: nothing to test for the KubernetesClient
        self.assertEqual(self.obj.get_join_tokens(), (),
                         'Kubernetes tokens are now being returned, so this test needs to be updated')

    def test_list_nodes(self):
        self.obj.client.list_node.return_value.items = [fake.mock_kubernetes_node()]
        self.assertIsInstance(self.obj.list_nodes(), list,
                              'List nodes should returns its items, a list, but got something else instead')
        self.obj.client.list_node.assert_called_once()

    @mock.patch('agent.orchestrator.kubernetes.KubernetesClient.list_nodes')
    @mock.patch('agent.orchestrator.kubernetes.KubernetesClient.get_cluster_id')
    @mock.patch('agent.orchestrator.kubernetes.KubernetesClient.get_node_info')
    def test_get_cluster_info(self, mock_get_node_info, mock_cluster_id, mock_list_nodes):
        me = fake.mock_kubernetes_node(uid='myself-fake-id')
        mock_cluster_id.return_value = 'fake-id'
        mock_get_node_info.return_value = me
        mock_list_nodes.return_value = [me, fake.mock_kubernetes_node()]

        expected_fields = ['cluster-id', 'cluster-orchestrator', 'cluster-managers', 'cluster-workers']
        # if all goes well, we should get the above keys
        self.assertEqual(sorted(expected_fields), sorted(list(self.obj.get_cluster_info().keys())),
                         'The expected cluster keys were not given back while getting cluster info')

        # as is, we should expect 2 workers and 0 managers
        self.assertEqual(len(self.obj.get_cluster_info()['cluster-workers']), 2,
                         'Expecting 2 k8s workers but got something else')
        self.assertEqual(len(self.obj.get_cluster_info()['cluster-managers']), 0,
                         'Expecting no k8s manager but got something else')

        # COE should also match with class' COE
        self.assertEqual(self.obj.get_cluster_info()['cluster-orchestrator'], self.obj.ORCHESTRATOR_COE,
                         'Got the wrong cluster-orchestrator')

        # but if one of the nodes is a master, then we should get 1 worker and 1 manager
        me.metadata.labels = {'node-role.kubernetes.io/master': ''}
        mock_get_node_info.return_value = me
        mock_list_nodes.return_value = [me, fake.mock_kubernetes_node()]
        self.assertEqual(len(self.obj.get_cluster_info()['cluster-workers']), 1,
                         'Expecting 1 k8s workers but got something else')
        self.assertEqual(len(self.obj.get_cluster_info()['cluster-managers']), 1,
                         'Expecting 1 k8s manager but got something else')
        self.assertEqual(self.obj.get_cluster_info()['cluster-managers'][0], me.metadata.name,
                         'Expecting 2 k8s workers but got something else')

    def test_get_api_ip_port(self):
        endpoint = fake.mock_kubernetes_endpoint('not-kubernetes')
        self.obj.client.list_endpoints_for_all_namespaces.return_value.items = [endpoint, endpoint]
        # if the host_node_ip is already defined, then it is straighforward and we get it plus the default port
        self.obj.host_node_ip = '0.0.0.0'
        self.assertEqual(self.obj.get_api_ip_port(), ('0.0.0.0', 6443),
                         'Failed to return k8s API IP and port')

        # otherwise, it looks up k8s endpoints
        self.obj.host_node_ip = None

        # if there are no kubernetes endpoints, then return None,None
        self.assertEqual(self.obj.get_api_ip_port(), (None, None),
                         'Returned API IP and port even though there are no Kubernetes endpoints')

        # even if there are k8s endpoints...if either the IP or port are undefined, return None,None
        endpoint_k8s = fake.mock_kubernetes_endpoint('kubernetes')
        endpoint_k8s.subsets[0].ports[0].protocol = None
        self.obj.client.list_endpoints_for_all_namespaces.return_value.items = [endpoint_k8s, endpoint]
        # if there are no kubernetes endpoints, then return None,None
        self.assertEqual(self.obj.get_api_ip_port(), (None, None),
                         'Got k8s API ip/port even though the endpoint port protocol is not TCP')

        # only if the k8s endpoint has all parameters, we get a valid IP and port
        endpoint_k8s = fake.mock_kubernetes_endpoint('kubernetes')
        self.obj.client.list_endpoints_for_all_namespaces.return_value.items = [endpoint_k8s, endpoint]
        self.assertIsNotNone(self.obj.get_api_ip_port()[0],
                             'Should have gotten an API IP but got None')
        self.assertIsNotNone(self.obj.get_api_ip_port()[1],
                             'Should have gotten an API port but got None')

    def test_has_pull_job_capability(self):
        # if the job-lite variable does not exist (is not set), we get False, otherwise, we get True
        self.assertTrue(self.obj.has_pull_job_capability(),
                        'Should have found the job-lite image name from env, but has not')

        backup = self.obj.job_engine_lite_image = None
        self.obj.job_engine_lite_image = None
        self.assertFalse(self.obj.has_pull_job_capability(),
                         'job_engine_lite_image is not set, so we should have received False...')

        self.obj.job_engine_lite_image = backup # restore var

    def test_cast_dict_to_list(self):
        # 1st level casting only
        ref = {'a': 1.1, 'b': None, 'c': 'string'}
        exp_out = ['a=1.1', 'b', 'c=string']
        self.assertEqual(self.obj.cast_dict_to_list(ref), exp_out,
                         'Unable to convert dict to list')

    @mock.patch('agent.orchestrator.kubernetes.KubernetesClient.get_node_info')
    def test_get_node_labels(self, mock_get_node_info):
        node = fake.mock_kubernetes_node()
        node.metadata.labels = {} # no labels are set by default
        mock_get_node_info.return_value = node
        self.assertEqual(self.obj.get_node_labels(), [],
                         'Unable to get k8s empty node labels')

        node.metadata.labels = {'fake-label': 'fake-value'}
        mock_get_node_info.return_value = node
        self.assertEqual(self.obj.get_node_labels(), ['fake-label=fake-value'],
                         'Unable to get k8s node labels')

    def test_is_vpn_client_running(self):
        pod = fake.mock_kubernetes_pod()
        # if there are no pods with the vpn-client label, we get False
        self.obj.client.list_pod_for_all_namespaces.return_value.items = []
        self.assertFalse(self.obj.is_vpn_client_running(),
                         'Saying VPN client is running even though it is not')

        # but if there are matching pods, returns False if no containers match the vpn-client name, True otherwise
        self.obj.client.list_pod_for_all_namespaces.return_value.items = [pod, pod]
        self.assertFalse(self.obj.is_vpn_client_running(),
                         'Says VPN client is running when none of the pods are from the VPN component')

        vpn_pod = fake.mock_kubernetes_pod()
        vpn_pod.status.container_statuses[0].name = self.obj.vpn_client_component
        self.obj.client.list_pod_for_all_namespaces.return_value.items = [pod, vpn_pod]
        self.assertTrue(self.obj.is_vpn_client_running(),
                        'Says VPN client is not running, but it is')

    def test_install_ssh_key(self):
        # if there's an error while looking for an existing SSH installer pod, an exception is raised
        self.obj.client.read_namespaced_pod.side_effect = kubernetes.client.exceptions.ApiException()
        self.assertRaises(kubernetes.client.exceptions.ApiException, self.obj.install_ssh_key, '', '')

        # if the pod already exists, and is running, then we need to wait, and we get False
        self.obj.client.read_namespaced_pod.reset_mock(side_effect=True)
        self.obj.client.read_namespaced_pod.return_value = fake.mock_kubernetes_pod()
        self.assertFalse(self.obj.install_ssh_key('', ''),
                         'Failed to verify that an SSH installer is already running')

        # otherwise, it deletes the finished previous installer and installs a new key
        self.obj.client.read_namespaced_pod.return_value = fake.mock_kubernetes_pod(phase='terminated')
        self.obj.client.delete_namespaced_pod.return_value = True
        self.obj.client.create_namespaced_pod.return_value = True
        self.assertTrue(self.obj.install_ssh_key('', ''),
                        'Failed to install SSH key')
        self.obj.client.create_namespaced_pod.assert_called_once()
        self.obj.client.delete_namespaced_pod.assert_called_once()

        # also, if the initial check for an existing container returns 404, we continue
        self.obj.client.read_namespaced_pod.side_effect = kubernetes.client.exceptions.ApiException(status=404)
        self.assertTrue(self.obj.install_ssh_key('', ''),
                        'Failed to install SSH key')
        self.obj.client.delete_namespaced_pod.assert_called_once()
        self.assertEqual(self.obj.client.create_namespaced_pod.call_count, 2,
                         'Upon a 404, the SSH installer was not deployed as expected')

    def test_is_nuvla_job_running(self):
        self.obj.client.delete_namespaced_pod.reset_mock()
        # if there's an error while looking for pod, we default to True
        self.obj.client.read_namespaced_pod.side_effect = kubernetes.client.exceptions.ApiException()
        self.assertTrue(self.obj.is_nuvla_job_running('', ''),
                        'Says Nuvla job is not running even though it cannot be sure of that')

        # if 404, then False
        self.obj.client.read_namespaced_pod.side_effect = kubernetes.client.exceptions.ApiException(status=404)
        self.assertFalse(self.obj.is_nuvla_job_running('', ''),
                         'Says Nuvla job is running, when respective pod could not be found')

        # if found, we continue to see its state
        self.obj.client.read_namespaced_pod.reset_mock(side_effect=True)
        self.obj.client.read_namespaced_pod.return_value = fake.mock_kubernetes_pod(phase='running')
        self.assertTrue(self.obj.is_nuvla_job_running('', ''),
                        'Nuvla job is running, but got the opposite message')

        self.obj.client.read_namespaced_pod.return_value = fake.mock_kubernetes_pod(phase='pending')
        self.assertFalse(self.obj.is_nuvla_job_running('', ''),
                         'Says Nuvla job is running, when in fact it is pending')

        # for any other state, delete the pod and return False
        self.obj.client.read_namespaced_pod.return_value = fake.mock_kubernetes_pod(phase='succeeded')
        self.obj.client.delete_namespaced_pod.return_value = True
        self.assertFalse(self.obj.is_nuvla_job_running('', ''),
                         'Says Nuvla job is running, even though it should have been deleted')
        self.obj.client.delete_namespaced_pod.assert_called_once()

        # if deletion fails, return True
        self.obj.client.delete_namespaced_pod.side_effect = kubernetes.client.exceptions.ApiException()
        self.assertTrue(self.obj.is_nuvla_job_running('', ''),
                        'Dunno if job pod is running, but saying that is is not')

    def test_launch_job(self):
        # no returns. The only test is to make sure there are no exceptions and that the job pod is launched
        self.obj.client.create_namespaced_pod.reset_mock()
        self.obj.client.create_namespaced_pod.return_value = True
        self.assertIsNone(self.obj.launch_job('', '', ''),
                          'Unable to launch new job')
        self.obj.client.create_namespaced_pod.assert_called_once()

    @mock.patch('kubernetes.client.CustomObjectsApi.list_cluster_custom_object')
    @mock.patch('agent.orchestrator.kubernetes.KubernetesClient.get_node_info')
    def test_collect_container_metrics(self, mock_get_node_info, mock_pod_metrics):
        pod_list = mock.MagicMock()
        pod_list.items = [fake.mock_kubernetes_pod("pod-1"), fake.mock_kubernetes_pod("pod-2")]
        self.obj.client.list_pod_for_all_namespaces.return_value = pod_list
        mock_get_node_info.return_value.status.return_value.capacity = {
            'cpu': 1,
            'memory': '1Ki'
        }

        # if there are no pod to collect metrics from, return []
        mock_pod_metrics.return_value = {
            'items': []
        }
        self.assertEqual(self.obj.collect_container_metrics(), [],
                         'Returned container metrics when no pods are running')

        # if there are pod metrics, they must all match with the list of pods
        new_pod = fake.mock_kubernetes_pod_metrics('wrong-name')
        mock_pod_metrics.return_value = {
            'items': [new_pod]
        }
        self.assertEqual(self.obj.collect_container_metrics(), [],
                         'Returned container metrics when there is a mismatch between existing pods and metrics')

        # if pod metrics match the list of pods, then we should get a non-empty list, with cpu and mem values/container
        mock_pod_metrics.return_value = {
            'items': [fake.mock_kubernetes_pod_metrics("pod-1"), fake.mock_kubernetes_pod_metrics("pod-2")]
        }
        self.assertIsInstance(self.obj.collect_container_metrics(), list,
                              'Expecting list of pod container metrics, but got something else')

        expected_field = ['container-status', 'name', 'id', 'cpu-percent', 'mem-percent']
        self.assertEqual(sorted(expected_field), sorted(list(self.obj.collect_container_metrics()[0].keys())),
                         'Missing container metrics keys')
        self.assertEqual(len(self.obj.collect_container_metrics()), 2,
                         'Expecting metrics for 2 containers, but got something else')

    def test_get_installation_parameters(self):
        self.obj.client_apps.list_namespaced_deployment.return_value.items = []
        # if no apps, return empty environment and just the project name
        expected_output = {
            'project-name': self.obj.namespace,
            'environment': []
        }
        self.assertEqual(self.obj.get_installation_parameters(''), expected_output,
                         'Got the wrong installation parameters when there are no deployments to list')

        # when there are deployments, get the env vars from them, skipping templated env vars
        self.obj.client_apps.list_namespaced_deployment.return_value.items = [
            fake.mock_kubernetes_deployment(),
            fake.mock_kubernetes_deployment()
        ]
        self.assertGreater(len(self.obj.get_installation_parameters('')['environment']), 0,
                           'Expecting installation environment variables to be reported')

    def test_read_system_issues(self):
        # NOT IMPLEMENTED, so just return two []
        self.assertEqual(self.obj.read_system_issues(''), ([], []),
                         'System errors are no longer empty by default')

    def test_get_node_id(self):
        name = 'fake-name'
        node_info = fake.mock_kubernetes_node(name)
        # should always return the ID value indicated in the passed argument
        self.assertTrue(self.obj.get_node_id(node_info).startswith(name),
                        'Returned Node name does not match the real one')

    def test_get_cluster_id(self):
        node_info = fake.mock_kubernetes_node()
        # should always return the ID value indicated in the passed argument

        # if Node does not have cluster name, then return the default one passed as an arg
        default_cluster_name = 'fake-cluster'
        self.assertEqual(self.obj.get_cluster_id(node_info, default_cluster_name=default_cluster_name),
                         default_cluster_name,
                         'Returned Cluster name does not match the default one')

        # but if Node has it, take it from there
        cluster_name = 'new-cluster-name'
        node_info.metadata.cluster_name = cluster_name
        self.assertEqual(self.obj.get_cluster_id(node_info, default_cluster_name=default_cluster_name),
                         cluster_name,
                         'Returned Cluster name does not match the real one')

    @mock.patch('agent.orchestrator.kubernetes.KubernetesClient.list_nodes')
    def test_get_cluster_managers(self, mock_list_nodes):
        mock_list_nodes.return_value = [fake.mock_kubernetes_node(), fake.mock_kubernetes_node()]
        # if there are no managers, then return an empty list
        self.assertEqual(self.obj.get_cluster_managers(), [],
                         'There are no manager but got something else than an empty list')

        # if there's one manager, than get only the one's name
        manager = fake.mock_kubernetes_node("manager")
        manager.metadata.labels = {'node-role.kubernetes.io/master': ''}
        mock_list_nodes.return_value = [fake.mock_kubernetes_node(), fake.mock_kubernetes_node(), manager]
        self.assertEqual(self.obj.get_cluster_managers(), [manager.metadata.name],
                         'There is one manager (called "manager"), but got some other list of managers')

        # for multiple manager, get them all
        mock_list_nodes.return_value = [fake.mock_kubernetes_node(), fake.mock_kubernetes_node(), manager, manager]
        self.assertEqual(len(self.obj.get_cluster_managers()), 2,
                         'There are 2 managers, but got a different number')

    def test_get_host_architecture(self):
        node_info = fake.mock_kubernetes_node()
        # simple attribute lookup
        self.assertEqual(self.obj.get_host_architecture(node_info), node_info.status.node_info.architecture,
                         'Host architecture does not match the real one')

    def test_get_hostname(self):
        # always gives back the class attribute
        self.assertEqual(self.obj.get_hostname(), self.obj.host_node_name,
                         'Failed to get hostname')

        # even if an arg is provided
        node = fake.mock_kubernetes_node()
        self.assertEqual(self.obj.get_hostname(node_info=node), self.obj.host_node_name,
                         'Failed to get hostname when the node is given as an arg')

    @mock.patch('agent.orchestrator.kubernetes.KubernetesClient.get_node_info')
    def test_get_kubelet_version(self, mock_get_node_info):
        node = fake.mock_kubernetes_node()
        mock_get_node_info.return_value = node
        # simple node attr lookup
        self.assertEqual(self.obj.get_kubelet_version(), node.status.node_info.kubelet_version,
                         f'Expecting Kubelet version {node.status.node_info.kubelet_version} but got something else')

    def test_get_cluster_join_address(self):
        # NOT IMPLEMENTED
        self.assertIsNone(self.obj.get_cluster_join_address('fake-id'),
                          'Got something out of a function which is not implemented')

    def test_is_node_active(self):
        node = fake.mock_kubernetes_node()
        # if node is ready, should return its name
        self.assertEqual(self.obj.is_node_active(node), node.metadata.name,
                         'Saying node is not active when it is, and failed to give back its name')

        # otherwise, always returns None
        node = fake.mock_kubernetes_node(ready=False)
        self.assertIsNone(self.obj.is_node_active(node),
                          'Saying node is active when it is not')

    def test_get_container_plugins(self):
        # NOT IMPLEMENTED
        self.assertEqual(self.obj.get_container_plugins(), [],
                         'Received plugins for K8s even though method is not implemented')

    def test_define_nuvla_infra_service(self):
        # if api endpoint is not passed, get nothing in return
        self.assertEqual(self.obj.define_nuvla_infra_service('', []), {},
                         'Got an infrastructure service even though API endpoint is not defined')

        # otherwise, build the IS
        # if there are no keys, they are not passed
        api_endpoint = 'fake.endpoint'
        self.assertEqual(self.obj.define_nuvla_infra_service(api_endpoint, []), {'kubernetes-endpoint': api_endpoint},
                         'Returned IS does not match the provided API endpoint')

        # and if there are keys, return everything
        expected_fields = ["kubernetes-endpoint", "kubernetes-client-ca",
                           "kubernetes-client-cert", "kubernetes-client-key"]

        self.assertEqual(sorted(expected_fields),
                         sorted(list(self.obj.define_nuvla_infra_service(api_endpoint, "ca", "cert", "key").keys())),
                         'Unable to define IS')

    def test_get_partial_decommission_attributes(self):
        # NOT IMPLEMENTED
        self.assertEqual(self.obj.get_partial_decommission_attributes(), [],
                         'Received partial decommissioning attrs for K8s even though method is not implemented')

    def test_infer_if_additional_coe_exists(self):
        # NOT IMPLEMENTED
        self.assertEqual(self.obj.infer_if_additional_coe_exists(), {},
                         'Received additional COE even though method is not implemented for K8s')
