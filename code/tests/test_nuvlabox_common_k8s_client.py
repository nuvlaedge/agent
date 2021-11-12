#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import json
import os
import subprocess
import kubernetes
import logging
import mock
import requests
import unittest
import tests.utils.fake as fake
import yaml

os.environ.setdefault('KUBERNETES_SERVICE_HOST','force-k8s-coe')
import agent.common.NuvlaBoxCommon as NuvlaBoxCommon


class ContainerRuntimeKubernetesTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.hostfs = '/fake-rootfs'
        self.host_home = '/home/fakeUser'
        os.environ.setdefault('MY_HOST_NODE_NAME', 'fake-host-node-name')
        os.environ.setdefault('NUVLABOX_JOB_ENGINE_LITE_IMAGE','fake-job-lite-image')
        with mock.patch('agent.common.NuvlaBoxCommon.client.CoreV1Api') as mock_k8s_client_CoreV1Api:
            with mock.patch('agent.common.NuvlaBoxCommon.client.AppsV1Api') as mock_k8s_client_AppsV1Api:
                with mock.patch('agent.common.NuvlaBoxCommon.config') as mock_k8s_config:
                    mock_k8s_client_CoreV1Api.return_value = mock.MagicMock()
                    mock_k8s_client_AppsV1Api.return_value = mock.MagicMock()
                    mock_k8s_config.return_value = True
                    self.obj = NuvlaBoxCommon.KubernetesClient(self.hostfs, self.host_home)
        logging.disable(logging.CRITICAL)

    def tearDown(self):
        logging.disable(logging.NOTSET)

    def test_init(self):
        # the K8s coe should be set
        self.assertEqual(NuvlaBoxCommon.ORCHESTRATOR, 'kubernetes',
                             'Unable to set Kubernetes as the COE')
        # client should be set as well
        self.assertIsNotNone(self.obj.client,
                             'Unable to set Kubernetes client')
        self.assertIsNotNone(self.obj.client_apps,
                             'Unable to set Kubernetes client for apps')

        # the base class should also have been set
        self.assertEqual(self.obj.job_engine_lite_component, "nuvlabox-job-engine-lite",
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

    @mock.patch('agent.common.NuvlaBoxCommon.KubernetesClient.get_node_info')
    def test_get_host_os(self, mock_get_node_info):
        # if get_node_info returns something valid, we get a valid string out of it
        node = fake.MockKubernetesNode()
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
        self.obj.client.list_node.return_value.items = [fake.MockKubernetesNode()]
        self.assertIsInstance(self.obj.list_nodes(), list,
                              'List nodes should returns its items, a list, but got something else instead')
        self.obj.client.list_node.assert_called_once()

    @mock.patch('agent.common.NuvlaBoxCommon.KubernetesClient.list_nodes')
    @mock.patch('agent.common.NuvlaBoxCommon.KubernetesClient.get_cluster_id')
    @mock.patch('agent.common.NuvlaBoxCommon.KubernetesClient.get_node_info')
    def test_get_cluster_info(self, mock_get_node_info, mock_cluster_id, mock_list_nodes):
        me = fake.MockKubernetesNode(uid='myself-fake-id')
        mock_cluster_id.return_value = 'fake-id'
        mock_get_node_info.return_value = me
        mock_list_nodes.return_value = [me, fake.MockKubernetesNode()]

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
        self.assertEqual(self.obj.get_cluster_info()['cluster-orchestrator'], NuvlaBoxCommon.ORCHESTRATOR_COE,
                         'Got the wrong cluster-orchestrator')

        # but if one of the nodes is a master, then we should get 1 worker and 1 manager
        me.metadata.labels = {'node-role.kubernetes.io/master': ''}
        mock_get_node_info.return_value = me
        mock_list_nodes.return_value = [me, fake.MockKubernetesNode()]
        self.assertEqual(len(self.obj.get_cluster_info()['cluster-workers']), 1,
                         'Expecting 1 k8s workers but got something else')
        self.assertEqual(len(self.obj.get_cluster_info()['cluster-managers']), 1,
                         'Expecting 1 k8s manager but got something else')
        self.assertEqual(self.obj.get_cluster_info()['cluster-managers'][0], me.metadata.name,
                         'Expecting 2 k8s workers but got something else')

    def test_get_api_ip_port(self):
        endpoint = fake.MockKubernetesEndpoint('not-kubernetes')
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
        endpoint_k8s = fake.MockKubernetesEndpoint('kubernetes')
        endpoint_k8s.subsets[0].ports[0].protocol = None
        self.obj.client.list_endpoints_for_all_namespaces.return_value.items = [endpoint_k8s, endpoint]
        # if there are no kubernetes endpoints, then return None,None
        self.assertEqual(self.obj.get_api_ip_port(), (None, None),
                         'Got k8s API ip/port even though the endpoint port protocol is not TCP')

        # only if the k8s endpoint has all parameters, we get a valid IP and port
        endpoint_k8s = fake.MockKubernetesEndpoint('kubernetes')
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

    @mock.patch('agent.common.NuvlaBoxCommon.KubernetesClient.get_node_info')
    def test_get_node_labels(self, mock_get_node_info):
        node = fake.MockKubernetesNode()
        node.metadata.labels = {} # no labels are set by default
        mock_get_node_info.return_value = node
        self.assertEqual(self.obj.get_node_labels(), [],
                         'Unable to get k8s empty node labels')

        node.metadata.labels = {'fake-label': 'fake-value'}
        mock_get_node_info.return_value = node
        self.assertEqual(self.obj.get_node_labels(), ['fake-label=fake-value'],
                         'Unable to get k8s node labels')

    def test_is_vpn_client_running(self):
        pod = fake.MockKubernetesPod()
        # if there are no pods with the vpn-client label, we get False
        self.obj.client.list_pod_for_all_namespaces.return_value.items = []
        self.assertFalse(self.obj.is_vpn_client_running(),
                         'Saying VPN client is running even though it is not')

        # but if there are matching pods, returns False if no containers match the vpn-client name, True otherwise
        self.obj.client.list_pod_for_all_namespaces.return_value.items = [pod, pod]
        self.assertFalse(self.obj.is_vpn_client_running(),
                         'Says VPN client is running when none of the pods are from the VPN component')

        vpn_pod = fake.MockKubernetesPod()
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
        self.obj.client.read_namespaced_pod.return_value = fake.MockKubernetesPod()
        self.assertFalse(self.obj.install_ssh_key('', ''),
                         'Failed to verify that an SSH installer is already running')

        # otherwise, it deletes the finished previous installer and installs a new key
        self.obj.client.read_namespaced_pod.return_value = fake.MockKubernetesPod(phase='terminated')
        self.obj.client.delete_namespaced_pod.return_value = True
        self.obj.client.create_namespaced_pod.return_value = True
        self.assertTrue(self.obj.install_ssh_key('', ''),
                        'Failed to install SSH key')
        self.obj.client.delete_namespaced_pod.assert_called_once()
        self.obj.client.create_namespaced_pod.assert_called_once()

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
        self.obj.client.read_namespaced_pod.return_value = fake.MockKubernetesPod(phase='running')
        self.assertTrue(self.obj.is_nuvla_job_running('', ''),
                        'Nuvla job is running, but got the opposite message')

        self.obj.client.read_namespaced_pod.return_value = fake.MockKubernetesPod(phase='pending')
        self.assertFalse(self.obj.is_nuvla_job_running('', ''),
                         'Says Nuvla job is running, when in fact it is pending')

        # for any other state, delete the pod and return False
        self.obj.client.read_namespaced_pod.return_value = fake.MockKubernetesPod(phase='succeeded')
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
    @mock.patch('agent.common.NuvlaBoxCommon.KubernetesClient.get_node_info')
    def test_collect_container_metrics(self, mock_get_node_info, mock_pod_metrics):
        pod_list = mock.MagicMock()
        pod_list.items = [fake.MockKubernetesPod("pod-1"), fake.MockKubernetesPod("pod-2")]
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
        new_pod = fake.MockKubernetesPodMetrics('wrong-name')
        mock_pod_metrics.return_value = {
            'items': [new_pod]
        }
        self.assertEqual(self.obj.collect_container_metrics(), [],
                         'Returned container metrics when there is a mismatch between existing pods and metrics')

        # if pod metrics match the list of pods, then we should get a non-empty list, with cpu and mem values/container
        mock_pod_metrics.return_value = {
            'items': [fake.MockKubernetesPodMetrics("pod-1"), fake.MockKubernetesPodMetrics("pod-2")]
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
            fake.MockKubernetesDeployment(),
            fake.MockKubernetesDeployment()
        ]
        self.assertGreater(len(self.obj.get_installation_parameters('')['environment']), 0,
                           'Expecting installation environment variables to be reported')

    def test_read_system_issues(self):
        # NOT IMPLEMENTED, so just return two []
        self.assertEqual(self.obj.read_system_issues(''), ([], []),
                         'System errors are no longer empty by default')

    def test_get_node_id(self):
        name = 'fake-name'
        node_info = fake.MockKubernetesNode(name)
        # should always return the ID value indicated in the passed argument
        self.assertTrue(self.obj.get_node_id(node_info).startswith(name),
                        'Returned Node name does not match the real one')

    def test_get_cluster_id(self):
        node_info = fake.MockKubernetesNode()
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

    # @mock.patch('agent.common.NuvlaBoxCommon.DockerClient.get_node_info')
    # def test_get_cluster_managers(self, mock_get_node):
    #     node_info = {
    #         'Swarm': {
    #             'RemoteManagers': [{'NodeID': 'manager-1'}, {'NodeID': 'manager-2'}]
    #         }
    #     }
    #     mock_get_node.return_value = node_info
    #     # if all is good, we should get the managers IDs
    #     self.assertEqual(self.obj.get_cluster_managers(),
    #                      list(map(lambda x: x['NodeID'], node_info['Swarm']['RemoteManagers'])),
    #                      'Did not get the expected cluster managers IDs')
    #
    #     # but if there are none, we get an empty list
    #     mock_get_node.return_value = {}
    #     self.assertEqual(self.obj.get_cluster_managers(), [],
    #                      'Did not get the expected cluster managers IDs')
   #
   #  def test_get_host_architecture(self):
   #      node_info = {
   #          'Architecture': 'fake-arch'
   #      }
   #      # simple attribute lookup
   #      self.assertEqual(self.obj.get_host_architecture(node_info), node_info['Architecture'],
   #                       'Host architecture does not match the real one')
   #
   #  def test_get_hostname(self):
   #      node_info = {
   #          'Name': 'fake-name'
   #      }
   #      # simple attribute lookup
   #      self.assertEqual(self.obj.get_hostname(node_info), node_info['Name'],
   #                       'Hostname does not match the real one')
   #
   #  @mock.patch('agent.common.NuvlaBoxCommon.DockerClient.get_node_info')
   #  def test_get_cluster_join_address(self, mock_get_node):
   #      node_id = 'fake-node-id'
   #      node_info = {
   #          'Swarm': {
   #              'RemoteManagers': [{'NodeID': node_id, 'Addr': 'good-addr'},
   #                                 {'NodeID': 'manager-2', 'Addr': 'bad-addr'}]
   #          }
   #      }
   #      # if this node's ID is in the managers list, return its addr
   #      mock_get_node.return_value = node_info
   #      self.assertEqual(self.obj.get_cluster_join_address(node_id), node_info['Swarm']['RemoteManagers'][0]['Addr'],
   #                       'Unable to report the right cluster manager address')
   #
   #      # if the Addr attribute is not set, then we should get None
   #      node_info['Swarm']['RemoteManagers'][0].pop('Addr')
   #      mock_get_node.return_value = node_info
   #      self.assertIsNone(self.obj.get_cluster_join_address(node_id),
   #                        'Returned a join address where there should not be one')
   #
   #      # same result if this node ID is not in the list of managers
   #      self.assertIsNone(self.obj.get_cluster_join_address('some-other-fake-node-id'),
   #                        'Returned a join address when this node is not a manager')
   #
   #  def test_is_node_active(self):
   #      node = fake.MockDockerNode()
   #      # if node is ready, should return its ID (in this case a random number)
   #      self.assertIsNotNone(self.obj.is_node_active(node),
   #                           'Saying node is not active when it is')
   #
   #      # otherwise, always returns None
   #      node = fake.MockDockerNode(state='pending')
   #      self.assertIsNone(self.obj.is_node_active(node),
   #                        'Saying node is active when it is not')
   #
   #  @mock.patch('docker.models.plugins.PluginCollection.list')
   #  def test_get_container_plugins(self, mock_plugins):
   #      plugin_obj = mock.MagicMock()
   #      plugin_obj.enabled = True
   #      plugin_obj.name = 'docker.plugin.fake'
   #
   #      mock_plugins.return_value = [plugin_obj, plugin_obj]
   #      # if there are enabled plugins, we expect a list with their names
   #      self.assertEqual(self.obj.get_container_plugins(), ['docker.plugin.fake', 'docker.plugin.fake'],
   #                       'Unable to retrieve container plugins')
   #
   #      # if there are no plugins, we get an empty list
   #      mock_plugins.return_value = []
   #      self.assertEqual(self.obj.get_container_plugins(), [],
   #                       'Returned container plugins when there are none')
   #
   #      # same for plugins that are not active
   #      plugin_obj.enabled = False
   #      mock_plugins.return_value = [plugin_obj, plugin_obj]
   #      self.assertEqual(self.obj.get_container_plugins(), [],
   #                       'Returned container plugins when none are active')
   #
   #  @mock.patch('agent.common.NuvlaBoxCommon.DockerClient.infer_if_additional_coe_exists')
   #  def test_define_nuvla_infra_service(self, mock_infer_extra_coe):
   #      mock_infer_extra_coe.return_value = {}
   #      # if the api_endpoint is not set, the infra is not set either
   #      self.assertEqual(self.obj.define_nuvla_infra_service('', []), {},
   #                       'Returned a valid infra service when there is no API endpoint')
   #
   #      # otherwise, destructs the TLS keys and gives back the commissioning payload for the IS
   #      is_keys = ["swarm-client-ca", "swarm-client-cert", "swarm-client-key", "swarm-endpoint"]
   #      self.assertTrue(set(is_keys).issubset(self.obj.define_nuvla_infra_service('valid-api-endpoint',
   #                                                                                ['ca', 'cert', 'key'])),
   #                      'Failed to setup Swarm infrastructure service payload for commissioning')
   #
   #      # if there are no TLS keys, they are not included in the IS payload
   #      mock_infer_extra_coe.return_value = {}
   #      self.assertEqual(self.obj.define_nuvla_infra_service('valid-api-endpoint', []),
   #                       {'swarm-endpoint': 'valid-api-endpoint'},
   #                       'Returned more IS keys than just the expected API endpoint')
   #
   #      # the result should not be affected by the inference of the extra COE throwing an exeception
   #      mock_infer_extra_coe.side_effect = ConnectionError
   #      self.assertEqual(self.obj.define_nuvla_infra_service('valid-api-endpoint', []),
   #                       {'swarm-endpoint': 'valid-api-endpoint'},
   #                       'Infra service definition was affected by k8s discovery function exception')
   #
   #      # and if there's an extra k8s infra, it should be appended to the final infra
   #      mock_infer_extra_coe.reset_mock(side_effect=True)
   #      mock_infer_extra_coe.return_value = {'k8s-stuff': True}
   #      self.assertIn('k8s-stuff', self.obj.define_nuvla_infra_service('valid-api-endpoint', ['ca', 'cert', 'key']),
   #                    'Additional COE was not added to infrastructure service payload')
   #      self.assertEqual(len(self.obj.define_nuvla_infra_service('valid-api-endpoint', ['ca', 'cert', 'key']).keys()),
   #                       5,
   #                       'Unexpected number of infrastructure service fields')
   #
   #  def test_get_partial_decommission_attributes(self):
   #      # returns a constant, so let's just make sure that all return list items start with 'swarm'
   #      self.assertTrue(all(x.startswith('swarm') for x in self.obj.get_partial_decommission_attributes()),
   #                      'Received partial decommissioning attributes that are not Swarm related')
   #
   #  @mock.patch('yaml.safe_load')
   #  @mock.patch('os.path.isfile')
   #  def test_is_k3s_running(self, mock_isfile, mock_yaml):
   #      # if k3s_addr is not set, we get {}
   #      self.assertEqual(self.obj.is_k3s_running(''), {},
   #                       'Received k3s details even though no address was provided')
   #
   #      # same if the k3s config file cannot be found
   #      mock_isfile.return_value = False
   #      self.assertEqual(self.obj.is_k3s_running('1.1.1.1'), {},
   #                       'Received k3s details even though k3s config file does not exist')
   #
   #      mock_isfile.return_value = True
   #      # same again if the k3s config is malformed
   #      mock_yaml.side_effect = yaml.YAMLError
   #      with mock.patch("agent.common.NuvlaBoxCommon.open", mock.mock_open(read_data='{"notyaml": True}')):
   #          self.assertEqual(self.obj.is_k3s_running('1.1.1.1'), {},
   #                           'Received k3s details even though the k3s config file is malformed')
   #
   #      mock_yaml.reset_mock(side_effect=True)
   #      ca = b'ca'
   #      cert = b'cert'
   #      key = b'key'
   #      kubeconfig = {
   #          'clusters': [
   #              {
   #                  'cluster': {
   #                      'server': 'https://fake-server:6443',
   #                      'certificate-authority-data': base64.b64encode(ca),
   #                  }
   #              }
   #          ]
   #      }
   #      mock_yaml.return_value = kubeconfig
   #
   #      # if k3s config can be read, but there's an exception while retrieving the values from it, we again get {}
   #      # let's force a KeyError by omitting the users from the k3s config
   #      with mock.patch("agent.common.NuvlaBoxCommon.open", mock.mock_open(read_data='{"notyaml": True}')):
   #          self.assertEqual(self.obj.is_k3s_running('1.1.1.1'), {},
   #                           'Received k3s details even though the k3s config cannot be parsed')
   #
   #      kubeconfig['users'] = [
   #          {
   #              'user': {
   #                  'client-certificate-data': base64.b64encode(cert),
   #                  'client-key-data': base64.b64encode(key)
   #              }
   #          }
   #      ]
   #      mock_yaml.return_value = kubeconfig
   #
   #      # and now, with the kubeconfig complete and parsable, we should get all the expected k8s keys
   #      is_keys = ["kubernetes-client-ca", "kubernetes-client-cert", "kubernetes-client-key", "kubernetes-endpoint"]
   #      with mock.patch("agent.common.NuvlaBoxCommon.open", mock.mock_open(read_data='{"notyaml": True}')):
   #          self.assertTrue(set(is_keys).issubset(list(self.obj.is_k3s_running('1.1.1.1').keys())),
   #                          'Received k3s details even though the k3s config cannot be parsed')
   #
   #  @mock.patch('agent.common.NuvlaBoxCommon.run')
   #  @mock.patch('agent.common.NuvlaBoxCommon.DockerClient.is_k3s_running')
   #  def test_infer_if_additional_coe_exists(self, mock_k3s, mock_run):
   #      # if we timeout GREPing for a k8s process, we get {}
   #      mock_run.side_effect = subprocess.TimeoutExpired('', 0)
   #      self.assertEqual(self.obj.infer_if_additional_coe_exists(), {},
   #                       'Got additional COE details even though the PID check failed')
   #
   #      mock_run.assert_called_once()
   #      mock_k3s.assert_not_called()
   #
   #      # or if the grep result is empty/None, we try to get k3s
   #      grep = mock.MagicMock()
   #      grep.stdout = ''
   #      mock_run.return_value = grep
   #      mock_run.reset_mock(side_effect=True)
   #
   #      mock_k3s.return_value = {'fake-k3s': True}
   #      self.assertEqual(self.obj.infer_if_additional_coe_exists(), {'fake-k3s': True},
   #                       'Failed to get additional k3s IS when kube-apiserver PID does not exist')
   #      mock_k3s.assert_called_once_with(None)
   #
   #      # and we get {} again if also the k3s discovery raises an exception
   #      mock_k3s.side_effect = TimeoutError
   #      self.assertEqual(self.obj.infer_if_additional_coe_exists(), {},
   #                       'Got additional COE details even though there is not Kubernetes installation available')
   #
   #      # if we get a kube PID though, then we try to infer its args to build the IS payload
   #      grep.stdout = '/fake/proc/pid/comm:foo'
   #      mock_run.return_value = grep
   #
   #      k8s_process = 'exec\x00--arg1=1\n--arg2=2\x00--arg3=3\x00'
   #      # if an exception is thrown while opening the process cmdline file, we get {}
   #      with mock.patch("agent.common.NuvlaBoxCommon.open", mock.mock_open(read_data=k8s_process)) as mock_open:
   #          mock_open.side_effect = FileNotFoundError
   #          self.assertEqual(self.obj.infer_if_additional_coe_exists(), {},
   #                           'Got additional COE details even though the k8s process cmdline file does not exist')
   #
   #      # if the file exists, we read it but if it hasn't the right keywords, we get {} again
   #      with mock.patch("agent.common.NuvlaBoxCommon.open", mock.mock_open(read_data=k8s_process)):
   #          self.assertEqual(self.obj.infer_if_additional_coe_exists(), {},
   #                           'Got additional COE details even though the k8s process cmdline is missing the right args')
   #
   #      # finally, if the cmdline args are all there, we should get the whole kubernetes IS payload
   #      k8s_cmdline_keys = ["advertise-address", "secure-port", "client-ca-file",
   #                          "kubelet-client-certificate", "kubelet-client-key"]
   #
   #      k8s_process = 'exec\n--' + '=fake_value\x00--'.join(k8s_cmdline_keys) + '=1\n'
   #      is_fields = ['kubernetes-endpoint', 'kubernetes-client-ca', 'kubernetes-client-cert', 'kubernetes-client-key']
   #      with mock.patch("agent.common.NuvlaBoxCommon.open", mock.mock_open(read_data=k8s_process)):
   #          self.assertTrue(set(is_fields).issubset(list(self.obj.infer_if_additional_coe_exists().keys())),
   #                          'Got unexpected K8s COE IS fields')
