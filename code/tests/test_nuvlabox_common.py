#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import docker
import logging
import mock
import requests
import unittest
import tests.utils.fake as fake
import agent.common.NuvlaBoxCommon as NuvlaBoxCommon


class ContainerRuntimeDockerTestCase(unittest.TestCase):

    def setUp(self) -> None:
        self.hostfs = '/fake-rootfs'
        self.host_home = '/home/fakeUser'
        self.obj = NuvlaBoxCommon.DockerClient(self.hostfs, self.host_home)
        self.local_docker_client = docker.from_env()
        self.fake_swarm_tokens = {
            'JoinTokens': {
                'Manager': 'token-manager',
                'Worker': 'token-worker'
            }
        }
        self.job_engine_lite_component = 'fake-job-lite'
        logging.disable(logging.CRITICAL)

    def tearDown(self):
        self.obj.client.close()
        self.local_docker_client.close()
        logging.disable(logging.NOTSET)

    def test_init(self):
        # the Docker client should be set
        self.assertIsInstance(self.obj.client.version(), dict,
                              'Unable to load Docker client')
        self.assertIn('ID', self.obj.client.info(),
                      'Unable to retrieve Docker info')

        # the base class should also have been set
        self.assertEqual(self.obj.job_engine_lite_component, "nuvlabox-job-engine-lite",
                         'Base class of the ContainerRuntime was not properly initialized')

    def test_get_node_info(self):
        self.assertIn('ID', self.obj.get_node_info(),
                      'Unable to retrieve Docker info')

        self.assertIsInstance(self.obj.get_node_info(), dict,
                              'Docker info should be returned as a dict')

        self.assertEqual(self.obj.get_node_info().keys(), self.local_docker_client.info().keys(),
                         'Get node info return a different value than the real Docker info')

    def test_get_host_os(self):
        self.assertIsInstance(self.obj.get_host_os(), str,
                              'Host OS should be a string')

    @mock.patch('docker.api.swarm.SwarmApiMixin.inspect_swarm')
    def test_get_join_tokens(self, mock_docker):
        # if there are no tokens (Swarm is off), we should get an empty tuple
        mock_docker.return_value = {}
        self.assertEqual(self.obj.get_join_tokens(), (),
                         'Returned Swarm tokens even though Swarm is NOT enabled')

        # otherwise, the tokens should be received
        mock_docker.return_value = self.fake_swarm_tokens
        self.assertEqual(self.obj.get_join_tokens(),
                         (self.fake_swarm_tokens['JoinTokens']['Manager'],
                          self.fake_swarm_tokens['JoinTokens']['Worker']),
                         'Did not get the expected Swarm tokens')

        # is there's a Docker error, we should get an empty tuple
        mock_docker.side_effect = docker.errors.APIError("fake", response=requests.Response())
        self.assertEqual(self.obj.get_join_tokens(), (),
                         'Returned Swarm tokens even though Docker threw an exception')

    @mock.patch('docker.models.nodes.NodeCollection.list')
    def test_list_nodes(self, mock_docker):
        # a filter should be accepted as an arg
        fake_filter = {'test': 'foo'}
        mock_docker.return_value = []
        self.assertEqual(self.obj.list_nodes(optional_filter=fake_filter), [],
                         'Listing Docker nodes when there are none')
        mock_docker.assert_called_once_with(filters=fake_filter)

        # make sure the returned list is consistent with what's provided by Docker
        mock_docker.return_value = [1, 2, 3]
        self.assertEqual(len(self.obj.list_nodes()), 3,
                         'Number of Docker nodes does not match with true value')

        # and when Docker throws an error, this shall too
        mock_docker.side_effect = docker.errors.APIError("", response=requests.Response())
        self.assertRaises(docker.errors.APIError, self.obj.list_nodes)

    @mock.patch('agent.common.NuvlaBoxCommon.DockerClient.list_nodes')
    @mock.patch('agent.common.NuvlaBoxCommon.DockerClient.get_node_info')
    def test_get_cluster_info(self, mock_get_node_info, mock_list_nodes):
        # if Swarm is not enabled, we should get an empty dict
        mock_get_node_info.return_value = {'Swarm': {}}
        self.assertEqual(self.obj.get_cluster_info(), {},
                         'Returned cluster info when there is no cluster')

        # if not a Swarm manager, then again {} is returned
        mock_get_node_info.return_value = {'Swarm': {'ControlAvailable': ''}}
        self.assertEqual(self.obj.get_cluster_info(), {},
                         'Returned cluster info when node is not a manager')

        # if nodes exist...

        mock_get_node_info.return_value = {
            'Swarm': {
                'ControlAvailable': True
            },
            'Cluster': {
                'ID': 'fake-id'
            }
        }

        # if all nodes are ready, we get them all back
        mock_list_nodes.return_value = [fake.MockDockerNode(), fake.MockDockerNode()]
        self.assertIn('cluster-id', self.obj.get_cluster_info(),
                      'Expecting cluster-id in cluster info')
        self.assertEqual(len(self.obj.get_cluster_info()['cluster-managers']), 2,
                         'Expecting 2 cluster nodes, but got something else')
        self.assertEqual(len(self.obj.get_cluster_info().keys()), 4,
                         'Expecting 4 keys to define cluster, but got something else')

        # if not all nodes are ready, then we just get the ones which are ready
        mock_list_nodes.return_value = [fake.MockDockerNode(), fake.MockDockerNode(state='not-ready')]
        self.assertIn('cluster-orchestrator', self.obj.get_cluster_info(),
                      'Expecting cluster-orchestrator in cluster info')
        self.assertIn(self.obj.get_cluster_info()['cluster-orchestrator'].lower(), ['docker', 'swarm'],
                      'Expecting Docker-based COE but got a different orchestrator')
        self.assertEqual(len(self.obj.get_cluster_info()['cluster-workers']), 1,
                         'Expecting 1 worker in cluster info, but got something else')

    @mock.patch('agent.common.NuvlaBoxCommon.DockerClient.get_node_info')
    def test_get_api_ip_port(self, mock_get_nodes_info):
        # if Swarm info has an address, we should just get that back with port 5000
        node_addr = '1.2.3.4'
        mock_get_nodes_info.return_value = {
            'Swarm': {
                'NodeAddr': node_addr
            }
        }

        self.assertEqual(self.obj.get_api_ip_port(), (node_addr, 5000),
                         'Expected default Swarm NodeAddr with port 5000, but got something else instead')

        # otherwise, we try to read the machine IP from the disk
        mock_get_nodes_info.return_value = {'Swarm': {}}
        # if there's a valid IP in this file, we return it
        tcp_file = '''sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode                                                     
   6: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 51149 1 ffffffc1c9be2e80 100 0 0 10 0                     
   7: 0100007F:13D8 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 58062 1 ffffffc1dea25d00 100 0 0 10 0                     
   8: 2D28A8C0:0016 652AA8C0:D6C9 01 00000024:00000000 01:00000015 00000000     0        0 3610139 4 ffffffc10cd3f440 22 4 29 10 -1                  
   9: 0100007F:ECA0 0100007F:13D8 06 00000000:00000000 03:00000577 00000000     0        0 0 3 ffffffc0d1887ef0
   '''
        with mock.patch("agent.common.NuvlaBoxCommon.open", mock.mock_open(read_data=tcp_file)):
            self.assertEqual(self.obj.get_api_ip_port(), ('192.168.40.45', 5000),
                             'Could not get valid IP from filesystem')

        # if there's no valid IP in this file, then we return 127.0.0.1
        tcp_file = '''sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode                                                     
   0: 0100007F:0B83 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 22975 1 ffffffc1dea20000 100 0 0 10 0                     
   1: 00000000:1388 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 46922 1 ffffffc1c9be1740 100 0 0 10 0
   '''
        with mock.patch("agent.common.NuvlaBoxCommon.open", mock.mock_open(read_data=tcp_file)):
            self.assertEqual(self.obj.get_api_ip_port(), ('127.0.0.1', 5000),
                             'Could not get default IP from filesystem')

    @mock.patch('docker.models.containers.ContainerCollection.get')
    def test_has_pull_job_capability(self, mock_containers_get):
        # if the job-lite does not exist, we get False
        mock_containers_get.side_effect = docker.errors.NotFound
        self.assertFalse(self.obj.has_pull_job_capability(),
                         'Job lite can not be found but returned True anyway')

        # same for any other exception
        mock_containers_get.side_effect = EOFError
        self.assertFalse(self.obj.has_pull_job_capability(),
                         'Error occurred but returned True anyway')

        # otherwise, we infer its Docker image
        mock_containers_get.reset_mock(side_effect=True)

        mock_containers_get.return_value = fake.MockContainer(status='running')

        # if the container is running, we return false
        self.assertFalse(self.obj.has_pull_job_capability(),
                         'Returned True even when job-lite container is not paused')

        # the container is supposed to be paused
        mock_containers_get.return_value = fake.MockContainer()
        self.assertTrue(self.obj.has_pull_job_capability(),
                        'Should have found the job-lite component, but has not')
        self.assertEqual(self.obj.job_engine_lite_image, 'fake-image',
                         'Set the wrong job-lite Docker image')

    @mock.patch('agent.common.NuvlaBoxCommon.DockerClient.cast_dict_to_list')
    @mock.patch('docker.api.swarm.SwarmApiMixin.inspect_node')
    @mock.patch('agent.common.NuvlaBoxCommon.DockerClient.get_node_info')
    def test_get_node_labels(self, mock_get_node_info, mock_inspect_node, mock_cast_dict_to_list):
        # errors while inspecting node should cause it to return empty list
        mock_inspect_node.side_effect = KeyError
        node = {
            'Swarm': {
                'NodeID': 'fake-id'
            }
        }
        mock_get_node_info.return_value = node
        err = 'Exception not caught while getting node labels'
        self.assertEqual(self.obj.get_node_labels(), [],
                         err)

        mock_inspect_node.reset_mock(side_effect=True)
        mock_get_node_info.side_effect = docker.errors.NullResource
        self.assertEqual(self.obj.get_node_labels(), [],
                         err)

        mock_get_node_info.reset_mock(side_effect=True)
        labels = [1, 2]
        mock_inspect_node.return_value = {
            'Spec': {
                'Labels': labels
            }
        }
        mock_cast_dict_to_list.return_value = labels
        self.assertEqual(self.obj.get_node_labels(), labels,
                         'Unable to get node labels')
        mock_cast_dict_to_list.assert_called_once_with(labels)

    @mock.patch('docker.models.containers.ContainerCollection.get')
    def test_is_vpn_client_running(self, mock_containers_get):
        mock_containers_get.return_value = fake.MockContainer(status='running')
        # if vpn is running, returns True
        self.assertTrue(self.obj.is_vpn_client_running(),
                        'Says vpn-client is not running when it is')

        # False otherwise
        mock_containers_get.return_value = fake.MockContainer(status='paused')
        self.assertFalse(self.obj.is_vpn_client_running(),
                         'Says vpn-client is running, but it is not')



# class NuvlaBoxCommonTestCase(unittest.TestCase):
#
#     def setUp(self):
#         Activate.__bases__ = (Fake.imitate(NuvlaBoxCommon),)
#         self.shared_volume = "mock/path"
#         self.obj = Activate(self.shared_volume)
#         self.api_key_content = '{"api-key": "mock-key", "secret-key": "mock-secret"}'
#         self.obj.activation_flag = 'mock-activation-file'
#         self.obj.nuvlabox_id = "nuvlabox/fake-id"
#         self.obj.nuvla_endpoint = "https://fake-nuvla.io"
#         self.obj.data_volume = self.shared_volume
#         self.obj.context = 'path/to/fake/context/file'
#         logging.disable(logging.CRITICAL)
#
#     def tearDown(self):
#         logging.disable(logging.NOTSET)
#
#     @staticmethod
#     def set_nuvla_api(api_keys):
#         """ Fake the initialization of the Nuvla Api instance """
#         api = FakeNuvlaApi(api_keys)
#         return api
#
#     def test_instantiation(self):
#         self.assertTrue(self.obj.user_info == {}, "Failed to instantiate Activate class instance")
#
#     @mock.patch.object(Activate, 'read_json_file')
#     @mock.patch.object(Activate, 'write_json_to_file')
#     @mock.patch.object(Activate, 'get_api_keys')
#     @mock.patch.object(Activate, 'get_operational_status')
#     def test_activation_is_possible(self, mock_get_op_status, mock_get_api_keys, mock_write_file, mock_read_file):
#         # activation is not possible because NuvlaBox is not ready/operational
#         mock_get_op_status.return_value = 'UNKNOWN'
#         self.assertEqual(self.obj.activation_is_possible(), (False, {}),
#                          'Activation unable to cope with UNKNOWN operational status')
#
#         mock_get_op_status.return_value = 'OPERATIONAL'
#         # if there's no file and no env, then activation should go through
#         mock_get_api_keys.return_value = (None, None)
#         mock_read_file.side_effect = FileNotFoundError
#         self.assertEqual(self.obj.activation_is_possible(), (True, {}),
#                          'Activation not possible when it should be')
#
#         # activation is not possible, because even though files does not exist, API keys are in env
#         mock_write_file.return_value = True
#         mock_get_api_keys.return_value = (json.loads(self.api_key_content)['api-key'],
#                                           json.loads(self.api_key_content)['secret-key'])
#         self.assertEqual(self.obj.activation_is_possible(), (False, json.loads(self.api_key_content)),
#                          'Cannot read existing activation file with API key credentials')
#         self.assertTrue(mock_write_file.called,
#                         'Could not save API keys from env into file')
#
#         # activation is not possible because NuvlaBox has already been activated - there's a file
#         mock_read_file.reset_mock(return_value=True, side_effect=True)
#         mock_read_file.return_value = json.loads(self.api_key_content)
#         # with mock.patch("agent.Activate.open", mock.mock_open(read_data=self.api_key_content)):
#         self.assertEqual(self.obj.activation_is_possible(), (False, json.loads(self.api_key_content)),
#                          'Cannot read existing activation file with API key credentials')
#
#     @mock.patch.object(Activate, 'shell_execute')
#     @mock.patch.object(Activate, 'write_json_to_file')
#     @mock.patch.object(Activate, 'api')
#     def test_activate(self, mock_api, mock_write_file, mock_shell_exec):
#         # successful activation will return the API keys for the NuvlaBox
#         mock_api.return_value = self.set_nuvla_api(json.loads(self.api_key_content))
#         mock_write_file.return_value = True
#         self.assertEqual(self.obj.activate(), json.loads(self.api_key_content),
#                          'Unable to activate the NuvlaBox')
#         # and because it was successful, the API keys have been written to a file
#         mock_write_file.assert_called_once_with(self.obj.activation_flag, json.loads(self.api_key_content))
#
#         # if there's an SSLError while activating, then systemd-timesyncd should take place
#         mock_shell_exec.return_value = True
#         mock_api.side_effect = requests.exceptions.SSLError
#         self.assertRaises(requests.exceptions.SSLError, self.obj.activate)
#         self.assertTrue(mock_shell_exec.called,
#                         'requests.exceptions.SSLError was not caught during NuvlaBox activation')
#         # there hasn't been a new attempt to write the api keys into the file
#         mock_write_file.assert_called_once_with(self.obj.activation_flag, json.loads(self.api_key_content))
#
#         # if there's a connection error, then an exception must be thrown
#         mock_api.side_effect = requests.exceptions.ConnectionError
#         self.assertRaises(requests.exceptions.ConnectionError, self.obj.activate)
#         # ensure neither the write function nor the shell_exec have been called a second time
#         mock_shell_exec.assert_called_once()
#         mock_write_file.assert_called_once_with(self.obj.activation_flag, json.loads(self.api_key_content))
#
#     @mock.patch.object(Activate, 'write_json_to_file')
#     @mock.patch.object(Activate, 'read_json_file')
#     def test_create_nb_document(self, mock_read_json_file, mock_write_to_file):
#         # if context file does not exist, the old NB resource should be empty
#         mock_read_json_file.side_effect = FileNotFoundError
#         mock_write_to_file.return_value = None
#         self.assertEqual(self.obj.create_nb_document_file({'foo': 'bar'}), {},
#                          'Returned an old NuvlaBox resource when there should not be one')
#         mock_read_json_file.assert_called_once()
#         mock_write_to_file.assert_called_once()
#
#         # if there is a context file already, its content will be returned as the old NuvlaBox resource context
#         old_nuvlabox_context = {'id': 'nuvlabox/fake-old'}
#         mock_read_json_file.reset_mock(side_effect=True)
#         mock_write_to_file.reset_mock()
#         mock_read_json_file.return_value = old_nuvlabox_context
#         self.assertEqual(self.obj.create_nb_document_file({'foo': 'bar'}), old_nuvlabox_context,
#                          'Unable to get old NuvlaBox context when creating new NB document')
#         mock_write_to_file.assert_called_once()
#
#     @mock.patch.object(Activate, 'commission_vpn')
#     def test_vpn_commission_if_needed(self, mock_commission_vpn):
#         old_nuvlabox_resource = {'id': self.obj.nuvlabox_id}
#         new_nuvlabox_resource = {**old_nuvlabox_resource, **{'vpn-server-id': 'infrastructure-servive/fake-vpn'}}
#
#         mock_commission_vpn.return_value = None
#
#         # if 'vpn-server-id' has not changed, then VPN commissioning will not be invoked
#         self.obj.vpn_commission_if_needed(old_nuvlabox_resource, old_nuvlabox_resource)
#         mock_commission_vpn.assert_not_called()
#
#         # but if 'vpn-server-id' changes, then VPN commissioning takes place
#         self.obj.vpn_commission_if_needed(new_nuvlabox_resource, old_nuvlabox_resource)
#         mock_commission_vpn.assert_called_once()
#
#     @mock.patch.object(Activate, 'api')
#     def test_get_nuvlabox_info(self, mock_api):
#         mock_api.return_value = self.set_nuvla_api(json.loads(self.api_key_content))
#
#         # Nuvla should return the NuvlaBox resource
#         returned_nuvlabox_resource = self.obj.get_nuvlabox_info()
#         self.assertIsInstance(returned_nuvlabox_resource, dict)
#         self.assertEqual(self.obj.nuvlabox_id, returned_nuvlabox_resource.get('id'),
#                          'Did not get the expected NuvlaBox resource')
#         mock_api.assert_called_once()
#
#     @mock.patch.object(Activate, 'create_nb_document_file')
#     @mock.patch.object(Activate, 'get_nuvlabox_info')
#     @mock.patch.object(Activate, 'authenticate')
#     def test_update_nuvlabox_resource(self, mock_authenticate, mock_get_nuvlabox_info, mock_create_nb_doc):
#         self.obj.user_info = json.loads(self.api_key_content)
#         mock_authenticate.return_value = self.set_nuvla_api(self.obj.user_info)
#         old_nuvlabox_resource = {'id': self.obj.nuvlabox_id}
#         new_nuvlabox_resource = {**old_nuvlabox_resource, **{'new-attr': True}}
#         mock_get_nuvlabox_info.return_value = new_nuvlabox_resource
#         mock_create_nb_doc.return_value = old_nuvlabox_resource
#
#         # when called, it shall get the NB resource from Nuvla,
#         # overwrite the existing NB doc,
#         # and return both old and new NB resources
#         self.assertEqual(self.obj.update_nuvlabox_resource(), (new_nuvlabox_resource, old_nuvlabox_resource),
#                          'Failed to update NuvlaBox resource: unexpected "new" and "old" NB resources')
